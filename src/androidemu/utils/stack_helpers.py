from unicorn.arm_const import UC_ARM_REG_SP
from unicorn.arm64_const import UC_ARM64_REG_SP

from androidemu.const.emu_const import Arch
from androidemu.utils import memory_helpers


class StackHelper:
    def __init__(self, emu):
        self._emu = emu
        arch = emu.get_arch()
        if arch == Arch.ARM32:
            sp_reg = UC_ARM_REG_SP

        elif arch == Arch.ARM64:
            sp_reg = UC_ARM64_REG_SP

        sp = emu.mu.reg_read(sp_reg)
        self._sp = sp
        self._sp_reg = sp_reg

    def reserve(self, nptr):
        self._sp -= nptr * self._emu.get_ptr_size()
        return self._sp

    def write_val(self, value):
        ptr_sz = self._emu.get_ptr_size()
        self._sp -= ptr_sz
        memory_helpers.write_ptrs_sz(self._emu.mu, self._sp, value, ptr_sz)
        return self._sp

    def write_utf8(self, str_val):
        value_utf8 = str_val.encode(encoding="utf-8") + b"\x00"
        n = len(value_utf8)
        self._sp -= n
        self._emu.mu.mem_write(self._sp, value_utf8)
        return self._sp

    def commit(self):
        if self._emu.get_arch() == Arch.ARM32:
            self._sp = self._sp & (~7)
        elif self._emu.get_arch() == Arch.ARM64:
            self._sp = self._sp & (~15)

        self._emu.mu.reg_write(self._sp_reg, self._sp)

    def get_sp(self):
        return self._sp
