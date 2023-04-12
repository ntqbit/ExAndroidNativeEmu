import verboselogs

from unicorn import (
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_HOOK_CODE
)
from unicorn.arm_const import (
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_CPSR,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC
)
from unicorn.arm64_const import (
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_PC
)

from androidemu.const.emu_const import Arch
from androidemu.java.helpers.native_method import native_read_args_in_hook_code
from androidemu.utils.assembler import asm, asm64

logger = verboselogs.VerboseLogger(__name__)


def is_thumb(cpsr):
    return (cpsr & (1 << 5)) != 0


def set_thumb(cpsr):
    return cpsr | (1 << 5)


def clear_thumb(cpsr):
    return cpsr & (~(1 << 5))


def standlize_addr(addr):
    return addr & (~1)


class FuncHooker:
    # 32 layout
    """
    funAddr
    ldr lr, [pc, #0x0]
    bx lr
    original lr
    """
    # 64 layout
    """
    funcAddr
    #ldr x30, #0x8
    #br x30
    original lr
    """

    def _hook_stub(self, mu, address, size, user_data):
        try:
            address = standlize_addr(address)
            fun_entry_addr = address - self._emu.get_ptr_size()
            fun_entry_bytes = mu.mem_read(
                fun_entry_addr, self._emu.get_ptr_size()
            )
            fun_entry = int.from_bytes(
                fun_entry_bytes, "little", signed=False
            )
            if fun_entry in self._hook_params:
                hook_param = self._hook_params[fun_entry]
                cb_after = hook_param[2]
                r0 = 0
                r1 = 0
                if self._arch == Arch.ARM32:
                    r0 = mu.reg_read(UC_ARM_REG_R0)
                    r1 = mu.reg_read(UC_ARM_REG_R1)

                else:
                    r0 = mu.reg_read(UC_ARM64_REG_X0)
                    r1 = mu.reg_read(UC_ARM64_REG_X1)

                cb_after(self._emu, r0, r1)

        except Exception:
            mu.emu_stop()
            logger.exception("Caught an exception in __hook_stub:")
            raise

    def __init__(self, emu):
        self._emu = emu
        self._arch = self._emu.get_arch()
        self._hook_params = {}
        HOOK_STUB_MEMORY_SIZE = 0x00100000
        self._stub_off = self._emu.memory.map(
            0,
            HOOK_STUB_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
        )
        self._emu.mu.hook_add(
            UC_HOOK_CODE,
            self._hook_stub,
            None,
            self._stub_off,
            self._stub_off + HOOK_STUB_MEMORY_SIZE,
        )

    def _hook_func_head(self, mu, address, size, user_data):
        try:
            address = standlize_addr(address)
            if address not in self._hook_params:
                return

            logger.debug("trigger hook on 0x%08X", address)
            hook_param = self._hook_params[address]
            nargs = hook_param[0]
            args = native_read_args_in_hook_code(self._emu, nargs)
            if hook_param[1]:
                is_handled = hook_param[1](self._emu, *args)
                if is_handled:
                    # 如果逻辑已经被处理，则直接返回
                    if self._arch == Arch.ARM32:
                        cpsr = mu.reg_read(mu, UC_ARM_REG_CPSR)
                        lr = self._emu.reg_read(UC_ARM_REG_LR)
                        # same as BX LR
                        if lr & 1:
                            # thumb set TF
                            cpsr = set_thumb(cpsr)
                        else:
                            # arm clear TF
                            cpsr = clear_thumb(cpsr)
                        mu.reg_write(UC_ARM_REG_CPSR, cpsr)
                        mu.reg_write(UC_ARM_REG_PC, lr)
                    else:
                        lr = self._emu.reg_read(UC_ARM64_REG_X30)
                        mu.reg_write(UC_ARM64_REG_PC, lr)
                    return

            if hook_param[2]:
                if self._arch == Arch.ARM32:
                    mu.mem_write(
                        self._stub_off,
                        address.to_bytes(4, "little", signed=False),
                    )  # 写入函数地址
                    self._stub_off += 4

                    new_lr = self._stub_off
                    # 跳板跳回原返回地址
                    mu.mem_write(
                        self._stub_off, asm('ldr lr, [pc, #0x0]')
                    )
                    self._stub_off += 4
                    mu.mem_write(self._stub_off, asm('bx lr'))
                    self._stub_off += 4
                    lr = mu.reg_read(UC_ARM_REG_LR)
                    mu.mem_write(
                        self._stub_off,
                        lr.to_bytes(4, "little", signed=False),
                    )
                    self._stub_off += 4
                    mu.reg_write(UC_ARM_REG_LR, new_lr)
                else:
                    mu.mem_write(
                        self._stub_off,
                        address.to_bytes(8, "little", signed=False),
                    )
                    self._stub_off += 8

                    new_lr = self._stub_off
                    mu.mem_write(
                        self._stub_off, asm64('ldr x30, #0x8')
                    )
                    self._stub_off += 4
                    mu.mem_write(self._stub_off, asm64('br x30'))
                    self._stub_off += 4

                    lr = mu.reg_read(UC_ARM64_REG_X30)
                    mu.mem_write(
                        self._stub_off,
                        lr.to_bytes(8, "little", signed=False),
                    )
                    self._stub_off += 8
                    mu.reg_write(UC_ARM64_REG_X30, new_lr)

        except Exception:
            mu.emu_stop()
            logger.exception("Caught an exception in __hook_func_head:")
            raise

    def fun_hook(self, fun_addr, nargs, cb_before, cb_after):
        fun_addr = standlize_addr(fun_addr)
        mu = self._emu.mu
        mu.hook_add(
            UC_HOOK_CODE, self._hook_func_head, None, fun_addr, fun_addr + 4
        )
        self._hook_params[fun_addr] = (nargs, cb_before, cb_after)
