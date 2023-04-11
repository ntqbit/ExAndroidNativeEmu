from unicorn.arm_const import UC_ARM_REG_SP
from unicorn.arm64_const import UC_ARM64_REG_SP

from androidemu.const.emu_const import Arch
from androidemu.utils import memory_helpers


class StackHelper:
    def __init__(self, emu):
        self._emu = emu

        if emu.get_arch() == Arch.ARM32:
            sp_reg = UC_ARM_REG_SP
        else:
            sp_reg = UC_ARM64_REG_SP

        self._sp = emu.mu.reg_read(sp_reg)
        self._sp_reg = sp_reg

    def get_sp(self):
        return self._sp

    def reserve(self, nptr: int):
        return self.reserve_bytes(nptr * self._emu.get_ptr_size())

    def reserve_bytes(self, size: int):
        self._sp -= size
        return self._sp

    def write_val(self, value):
        ptr_sz = self._emu.get_ptr_size()
        self._sp -= ptr_sz
        memory_helpers.write_ptrs_sz(self._emu.mu, self._sp, value, ptr_sz)
        return self._sp

    def write_utf8(self, value: str):
        return self.write_bytes(value.encode(encoding="utf-8") + b"\x00")

    def write_bytes(self, value: bytes):
        self._sp -= len(value)
        self._emu.mu.mem_write(self._sp, value)
        return self._sp

    def align(self):
        if self._emu.get_arch() == Arch.ARM32:
            self._sp = self._sp & (~7)
        elif self._emu.get_arch() == Arch.ARM64:
            self._sp = self._sp & (~15)

    def commit(self):
        self.align()
        self._emu.mu.reg_write(self._sp_reg, self._sp)
