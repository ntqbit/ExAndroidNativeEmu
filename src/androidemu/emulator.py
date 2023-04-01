import verboselogs
import os
import time
import importlib
import inspect
import pkgutil
import sys
import os.path

from random import randint

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from androidemu import config
from androidemu import pcb
from androidemu.const import emu_const
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

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.constant_values import JAVA_NULL

import androidemu.java.classes.application
import androidemu.java.classes.debug
import androidemu.java.classes.array
import androidemu.java.classes.okhttp
import androidemu.java.classes.asset_manager
import androidemu.java.classes.uri
import androidemu.java.classes.constructor
import androidemu.java.classes.proxy
import androidemu.java.classes.contentresolver
import androidemu.java.classes.system
import androidemu.java.classes.package_manager
import androidemu.java.classes.clazz
import androidemu.java.classes.list
import androidemu.java.classes.environment
import androidemu.java.classes.intent
import androidemu.java.classes.java_set
import androidemu.java.classes.file
import androidemu.java.classes.object
import androidemu.java.classes.executable
import androidemu.java.classes.types
import androidemu.java.classes.shared_preferences
import androidemu.java.classes.dexfile
import androidemu.java.classes.context
import androidemu.java.classes.network_interface
import androidemu.java.classes.method
import androidemu.java.classes.map
import androidemu.java.classes.wifi
import androidemu.java.classes.field
import androidemu.java.classes.string
import androidemu.java.classes.activity_thread
import androidemu.java.classes.settings
import androidemu.java.classes.bundle

logger = verboselogs.VerboseLogger(__name__)


class Emulator:
    # https://github.com/unicorn-engine/unicorn/blob/8c6cbe3f3cabed57b23b721c29f937dd5baafc90/tests/regress/arm_fp_vfp_disabled.py#L15
    # 关于arm32 64 fp https://www.raspberrypi.org/forums/viewtopic.php?t=259802
    # https://www.cnblogs.com/pengdonglin137/p/3727583.html
    def _enable_vfp32(self):
        # MRC p15, #0, r1, c1, c0, #2
        # ORR r1, r1, #(0xf << 20)
        # MCR p15, #0, r1, c1, c0, #2
        # MOV r1, #0
        # MCR p15, #0, r1, c7, c5, #4
        # MOV r0,#0x40000000
        # FMXR FPEXC, r0
        code = '11EE501F'
        code += '41F47001'
        code += '01EE501F'
        code += '4FF00001'
        code += '07EE951F'
        code += '4FF08040'
        code += 'E8EE100A'
        # vpush {d8}
        code += '2ded028b'

        address = 0x1000
        mem_size = 0x1000
        code_bytes = bytes.fromhex(code)

        try:
            self.mu.mem_map(address, mem_size)
            self.mu.mem_write(address, code_bytes)
            self.mu.reg_write(UC_ARM_REG_SP, address + mem_size)

            self.mu.emu_start(address | 1, address + len(code_bytes))
        finally:
            self.mu.mem_unmap(address, mem_size)

    # arm64
    '''
    mrs    x1, cpacr_el1
    mov    x0, #(3 << 20)
    orr    x0, x1, x0
    msr    cpacr_el1, x0
    '''

    def _enable_vfp64(self):
        # arm64 enable vfp
        x = 0
        x = self.mu.reg_read(UC_ARM64_REG_CPACR_EL1)
        x |= 0x300000  # set FPEN bit
        self.mu.reg_write(UC_ARM64_REG_CPACR_EL1, x)

    def _add_classes(self):
        defualt_classes = [
            androidemu.java.classes.application.Application,
            androidemu.java.classes.debug.Debug,
            androidemu.java.classes.array.Array,
            androidemu.java.classes.array.ByteArray,
            androidemu.java.classes.array.ObjectArray,
            androidemu.java.classes.array.ClassArray,
            androidemu.java.classes.array.StringArray,
            androidemu.java.classes.okhttp.Buffer,
            androidemu.java.classes.okhttp.ResponseBody,
            androidemu.java.classes.okhttp.Builder,
            androidemu.java.classes.okhttp.HttpUrl,
            androidemu.java.classes.okhttp.RequestBody,
            androidemu.java.classes.okhttp.Headers,
            androidemu.java.classes.okhttp.Request,
            androidemu.java.classes.okhttp.Response,
            androidemu.java.classes.okhttp.Chain,
            androidemu.java.classes.asset_manager.AssetManager,
            androidemu.java.classes.uri.Uri,
            androidemu.java.classes.constructor.Constructor,
            androidemu.java.classes.proxy.Proxy,
            androidemu.java.classes.contentresolver.ContentResolver,
            androidemu.java.classes.system.System,
            androidemu.java.classes.package_manager.Signature,
            androidemu.java.classes.package_manager.ApplicationInfo,
            androidemu.java.classes.package_manager.PackageInfo,
            androidemu.java.classes.package_manager.PackageManager,
            androidemu.java.classes.clazz.Class,
            androidemu.java.classes.list.List,
            androidemu.java.classes.environment.Environment,
            androidemu.java.classes.intent.IntentFilter,
            androidemu.java.classes.intent.Intent,
            androidemu.java.classes.java_set.Set,
            androidemu.java.classes.file.File,
            androidemu.java.classes.object.Object,
            androidemu.java.classes.executable.Executable,
            androidemu.java.classes.types.Boolean,
            androidemu.java.classes.types.Integer,
            androidemu.java.classes.types.Long,
            androidemu.java.classes.types.Float,
            androidemu.java.classes.shared_preferences.Editor,
            androidemu.java.classes.shared_preferences.SharedPreferences,
            androidemu.java.classes.dexfile.DexFile,
            androidemu.java.classes.context.Context,
            androidemu.java.classes.context.ContextImpl,
            androidemu.java.classes.context.ContextWrapper,
            androidemu.java.classes.network_interface.NetworkInterface,
            androidemu.java.classes.method.Method,
            androidemu.java.classes.map.HashMap,
            androidemu.java.classes.wifi.WifiInfo,
            androidemu.java.classes.wifi.WifiConfiguration,
            androidemu.java.classes.wifi.DhcpInfo,
            androidemu.java.classes.wifi.WifiManager,
            androidemu.java.classes.wifi.TelephonyManager,
            androidemu.java.classes.wifi.RequestBuilder,
            androidemu.java.classes.wifi.NetworkInfo,
            androidemu.java.classes.wifi.ConnectivityManager,
            androidemu.java.classes.field.AccessibleObject,
            androidemu.java.classes.field.Field,
            androidemu.java.classes.string.String,
            androidemu.java.classes.activity_thread.AccessibilityManager,
            androidemu.java.classes.activity_thread.AccessibilityInteractionController,
            androidemu.java.classes.activity_thread.Window,
            androidemu.java.classes.activity_thread.ViewRootImpl,
            androidemu.java.classes.activity_thread.AttachInfo,
            androidemu.java.classes.activity_thread.View,
            androidemu.java.classes.activity_thread.Activity,
            androidemu.java.classes.activity_thread.ActivityClientRecord,
            androidemu.java.classes.activity_thread.ArrayMap,
            androidemu.java.classes.activity_thread.ActivityManager,
            androidemu.java.classes.activity_thread.IActivityManager,
            androidemu.java.classes.activity_thread.ActivityManagerNative,
            androidemu.java.classes.activity_thread.Instrumentation,
            androidemu.java.classes.activity_thread.IInterface,
            androidemu.java.classes.activity_thread.IPackageManager,
            androidemu.java.classes.activity_thread.ActivityThread,
            androidemu.java.classes.settings.Secure,
            androidemu.java.classes.settings.Settings,
            androidemu.java.classes.bundle.Bundle
        ]

        for clz in defualt_classes:
            self.java_classloader.add_class(clz)

        # also add classloader as java class
        self.java_classloader.add_class(JavaClassLoader)

    """
    :type mu Uc
    :type modules Modules
    :type memory Memory
    """

    def __init__(
            self,
            vfs_root="vfs",
            config_path="emu_cfg/default.json",
            vfp_inst_set=True,
            arch=emu_const.Arch.ARM32,
            muti_task=False):
        # Unicorn.
        sys.stdout = sys.stderr
        # 由于这里的stream只能改一次，为避免与fork之后的子进程写到stdout混合，将这些log写到stderr
        # FIXME:解除这种特殊的依赖
        self.config = config.Config(config_path)
        self._arch = arch
        self._support_muti_task = muti_task
        self._pcb = pcb.Pcb()

        logger.info("process pid:%d" % self._pcb.get_pid())

        sp_reg = 0
        if arch == emu_const.Arch.ARM32:
            self._ptr_sz = 4
            self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            if vfp_inst_set:
                self._enable_vfp32()

            sp_reg = UC_ARM_REG_SP
            self.call_native = self._call_native32
            self.call_native_return_2reg = self._call_native_return_2reg32

        elif arch == emu_const.Arch.ARM64:
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

        # 注意，原有缺陷，原来linker初始化没有完成init_tls部分，导致libc初始化有访问空指针而无法正常完成
        # 而这里直接将0映射空间，,强行运行过去，因为R1刚好为0,否则会报memory unmap异常
        # 最新版本已经解决这个问题，无需再这么映射
        #self.mu.mem_map(0x0, 0x00001000, UC_PROT_READ | UC_PROT_WRITE)

        # Android 4.4
        if arch == emu_const.Arch.ARM32:
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
            # FIXME 这里arm64用 6.0，应该arm32也统一使用6.0
            # Android 6.0
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

        self.memory = MemoryMap(
            self.mu,
            config.MAP_ALLOC_BASE,
            config.MAP_ALLOC_BASE +
            config.MAP_ALLOC_SIZE)

        # Stack.
        addr = self.memory.map(
            config.STACK_ADDR,
            config.STACK_SIZE,
            UC_PROT_READ | UC_PROT_WRITE)
        self.mu.reg_write(sp_reg, config.STACK_ADDR + config.STACK_SIZE)
        #sp = self.mu.reg_read(sp_reg)
        #print ("stack addr %x"%sp)

        self._sch = Scheduler(self)
        # CPU
        self._syscall_handler = SyscallHandlers(self.mu, self._sch, self.get_arch())

        # Hooker
        self.memory.map(
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self._hooker = Hooker(
            self,
            config.BRIDGE_MEMORY_BASE,
            config.BRIDGE_MEMORY_SIZE)

        # syscalls
        self._mem_handler = MemorySyscallHandler(self, self.memory, self._syscall_handler)
        self._syscall_hooks = SyscallHooks(self, self.config, self._syscall_handler)
        self._vfs = VirtualFileSystem(
            self,
            vfs_root,
            self.config,
            self._syscall_handler,
            self.memory)

        # JavaVM
        self.java_classloader = JavaClassLoader()
        self.java_vm = JavaVM(self, self.java_classloader, self._hooker)

        # linker
        self.modules = Modules(self, self._vfs_root)
        # Native
        self._sym_hooks = SymbolHooks(
            self, self.modules, self._hooker, self._vfs_root)

        self._add_classes()

        # Hack 为jmethod_id指向的内存分配一块空间，抖音会将jmethodID强转，为的是绕过去
        self.memory.map(
            config.JMETHOD_ID_BASE,
            0x2000,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        if arch == emu_const.Arch.ARM32:
            # 映射常用的文件，cpu一些原子操作的函数实现地方
            # path = "%s/system/lib/vectors" % vfs_root
            # vf = VirtualFile(
            #     "[vectors]", misc_utils.platform_open(
            #         path, os.O_RDONLY), path)
            # self.memory.map(
            #     0xffff0000,
            #     0x1000,
            #     UC_PROT_EXEC | UC_PROT_READ,
            #     vf,
            #     0)

            # 映射app_process，android系统基本特征
            path = "%s/system/bin/app_process32" % vfs_root
            sz = os.path.getsize(path)
            vf = VirtualFile(
                "/system/bin/app_process32",
                misc_utils.platform_open(
                    path,
                    os.O_RDONLY),
                path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ)
            self.mu.mem_write(0xab006000, vf.descriptor.read())
            self.memory.set_file_map(0xab006000, sz, vf, 0)

        else:
            # 映射app_process，android系统基本特征
            path = "%s/system/bin/app_process64" % vfs_root
            sz = os.path.getsize(path)
            vf = VirtualFile(
                "/system/bin/app_process64",
                misc_utils.platform_open(
                    path,
                    os.O_RDONLY),
                path)
            self.memory.map(0xab006000, sz, UC_PROT_EXEC | UC_PROT_READ)
            self.memory.set_file_map(0xab006000, sz, vf, 0)

    def get_vfs_root(self):
        return self._vfs_root

    def load_library(self, filename, do_init=True):
        libmod = self.modules.load_module(filename, True)
        return libmod

    def call_symbol(self, module, symbol_name, *argv):
        symbol_addr = module.find_symbol(symbol_name)

        if symbol_addr is None:
            logger.error(
                'Unable to find symbol \'%s\' in module \'%s\'.' %
                (symbol_name, module.filename))
            return

        return self.call_native(symbol_addr, *argv)

    def _call_native32(self, addr, *argv):
        assert addr is not None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self._sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM_REG_R0)
        return res

    def _call_native64(self, addr, *argv):
        assert addr is not None, "call addr is None, make sure your jni native function has registered by RegisterNative!"
        native_write_args(self, *argv)
        self._sch.exec(addr)
        # Read result from locals if jni.
        res = self.mu.reg_read(UC_ARM64_REG_X0)
        return res

    # 返回值8个字节,用两个寄存器保存

    def _call_native_return_2reg32(self, addr, *argv):
        res = self._call_native32(addr, *argv)

        res_high = self.mu.reg_read(UC_ARM_REG_R1)

        return (res_high << 32) | res

    # 返回值16个字节,用两个寄存器保存

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
        return self._sch

    def get_muti_task_support(self):
        return self._support_muti_task
