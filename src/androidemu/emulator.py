import verboselogs

from unicorn import (
    Uc,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_ARCH_ARM64,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC
)
from unicorn.arm_const import (
    UC_ARM_REG_SP,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1
)
from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_CPACR_EL1,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1
)

from androidemu import pcb
from androidemu.utils.assembler import asm_thumb
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.cpu.syscall_hooks import SyscallHooks
from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules
from androidemu.java.helpers.native_method import native_write_args
from androidemu.java.java_classloader import JavaClassLoader
from androidemu.java.java_vm import JavaVM
from androidemu.native.symbol_hooks import SymbolHooks
from androidemu.native.memory_syscall_handler import MemorySyscallHandler
from androidemu.native.memory_map import MemoryMap
from androidemu.vfs.file_system import VirtualFileSystem
from androidemu.vfs.virtual_file import VirtualFile
from androidemu.utils import misc_utils
from androidemu.scheduler import Scheduler
from androidemu.config import Config
from androidemu.environment import Environment
from androidemu.const.emu_const import (
    MAP_ALLOC_BASE,
    MAP_ALLOC_SIZE,
    BRIDGE_MEMORY_BASE,
    BRIDGE_MEMORY_SIZE,
    JMETHOD_ID_BASE,
    STACK_ADDR,
    STACK_SIZE,
    Arch
)
from androidemu.java.classes import get_java_classes

logger = verboselogs.VerboseLogger(__name__)


class EmulatorException(Exception):
    pass


class EmulatorStopped(EmulatorException):
    pass


class Emulator:
    def __init__(
        self,
        vfs_root="vfs",
        config: Config = None,
        environment: Environment = None,
        vfp_inst_set=True,
        arch=Arch.ARM32,
        muti_task=False,
    ):
        if not config:
            logger.warning('Config is not set. Will use default config.')

        if not environment:
            logger.warning('Environment is not set. Will use default environment.')

        self.config = config or Config()
        self.environment = environment or Environment()

        self._arch = arch
        self._support_muti_task = muti_task
        self._pcb = pcb.Pcb()

        logger.info("process pid:%d", self._pcb.get_pid())

        if arch == Arch.ARM32:
            self._ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                self._enable_vfp32()

            sp_reg = UC_ARM_REG_SP
            self.call_native = self._call_native32
            self.call_native_return_2reg = self._call_native_return_2reg32

        elif arch == Arch.ARM64:
            self._ptr_sz = 8
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            if vfp_inst_set:
                self._enable_vfp64()

            sp_reg = UC_ARM64_REG_SP
            self.call_native = self._call_native64
            self.call_native_return_2reg = self._call_native_return_2reg64

        else:
            raise ValueError("emulator arch=%d not support" % arch)

        self._vfs_root = vfs_root

        if arch == Arch.ARM32:
            self.system_properties = {
                "libc.debug.malloc.options": "",
                "ro.build.version.sdk": "19",
                "ro.build.version.release": "4.4.4",
                "persist.sys.dalvik.vm.lib": "libdvm.so",
                "ro.product.cpu.abi": "armeabi-v7a",
                "ro.product.cpu.abi2": "armeabi",
                "ro.product.manufacturer": "LGE",
                "ro.product.manufacturer": "LGE",
                "ro.debuggable": "0",
                "ro.product.model": "AOSP on HammerHead",
                "ro.hardware": "hammerhead",
                "ro.product.board": "hammerhead",
                "ro.product.device": "hammerhead",
                "ro.build.host": "833d1eed3ea3",
                "ro.build.type": "user",
                "ro.secure": "1",
                "wifi.interface": "wlan0",
                "ro.product.brand": "Android",
            }

        else:
            self.system_properties = {
                "libc.debug.malloc.options": "",
                "ro.build.version.sdk": "23",
                "ro.build.version.release": "6.0.1",
                "persist.sys.dalvik.vm.lib2": "libart.so",
                "ro.product.cpu.abi": "arm64-v8a",
                "ro.product.manufacturer": "LGE",
                "ro.product.manufacturer": "LGE",
                "ro.debuggable": "0",
                "ro.product.model": "AOSP on HammerHead",
                "ro.hardware": "hammerhead",
                "ro.product.board": "hammerhead",
                "ro.product.device": "hammerhead",
                "ro.build.host": "833d1eed3ea3",
                "ro.build.type": "user",
                "ro.secure": "1",
                "wifi.interface": "wlan0",
                "ro.product.brand": "Android",
            }

        self.memory = MemoryMap(self.mu, MAP_ALLOC_BASE, MAP_ALLOC_BASE + MAP_ALLOC_SIZE)

        # Stack.
        self.memory.map(STACK_ADDR, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.mu.reg_write(sp_reg, STACK_ADDR + STACK_SIZE)

        self._scheduler = Scheduler(self)

        # CPU
        self._syscall_handler = SyscallHandlers(self)

        # Hooker
        self.memory.map(BRIDGE_MEMORY_BASE, BRIDGE_MEMORY_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._hooker = Hooker(self, BRIDGE_MEMORY_BASE, BRIDGE_MEMORY_SIZE)

        # syscalls
        self._mem_handler = MemorySyscallHandler(self, self.memory, self._syscall_handler)
        self._syscall_hooks = SyscallHooks(self, self._syscall_handler)
        self.vfs = VirtualFileSystem(self, vfs_root, self.config, self._syscall_handler, self.memory)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)

        # linker
        self.modules = Modules(self, self._vfs_root)
        # Native
        self._sym_hooks = SymbolHooks(self, self.modules, self._hooker, self._vfs_root)

        self.memory.map(
            JMETHOD_ID_BASE,
            0x2000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )

    def stop(self):
        self._scheduler.stop()
        self.mu.emu_stop()
        raise EmulatorStopped()

    def get_pc(self):
        if self.get_arch() == Arch.ARM32:
            return self.mu.reg_read(UC_ARM_REG_PC)
        else:
            return self.mu.reg_read(UC_ARM64_REG_PC)

    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    # arm32 64 fp https://www.raspberrypi.org/forums/viewtopic.php?t=259802
    # https://www.cnblogs.com/pengdonglin137/p/3727583.html
    def _enable_vfp32(self):
        address = 0x1000
        mem_size = 0x1000
        
        code_bytes = asm_thumb([
            'MRC p15, #0, r1, c1, c0, #2',
            'ORR r1, r1, #(0xf << 20)',
            'MCR p15, #0, r1, c1, c0, #2',
            'isb',
            'MOV r0,#0x40000000',
            'FMXR FPEXC, r0',
            'vpush {d8}'
        ])

        try:
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)

    # arm64
    """
    mrs    x1, cpacr_el1
    mov    x0, #(3 << 20)
    orr    x0, x1, x0
    msr    cpacr_el1, x0
    """

    def _enable_vfp64(self):
        # arm64 enable vfp
        x = 0
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000  # set FPEN bit
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)

    def add_default_classes(self):
        for clz in get_java_classes():
            self.java_classloader.add_class(clz)

        # also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)

    def get_vfs_root(self):
        return self._vfs_root

    def load_library(self, filename, do_init=True, call_entry_point=False):
        return self.modules.load_module(filename, do_init, call_entry_point)

    def call_symbol(self, module, symbol_name, *argv):
        symbol_addr = module.find_symbol(symbol_name)

        if symbol_addr is None:
            logger.error(
                "Unable to find symbol '%s' in module '%s'."
                % (symbol_name, module.filename)
            )
            return

        return self.call_native(symbol_addr, *argv)

    def _call_native32(self, addr, *argv):
        assert addr is not None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self._scheduler.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM_REG_R0)
        return res

    def _call_native64(self, addr, *argv):
        assert addr is not None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self._scheduler.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM64_REG_X0)
        return res

    def _call_native_return_2reg32(self, addr, *argv):
        res = self._call_native32(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res

    def _call_native_return_2reg64(self, addr, *argv):
        res = self._call_native64(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM64_REG_X1)

        return (res_high << 64) | res

    def get_arch(self):
        return self._arch

    def get_ptr_size(self):
        return self._ptr_sz

    def get_pcb(self):
        return self._pcb

    def get_schduler(self):
        return self._scheduler

    def get_muti_task_support(self):
        return self._support_muti_task
