import sys
import os
from androidemu.utils.debug_utils import *


class MemoryMonitor:
    def __init__(self, emu):
        self._emu = emu
        self._has_writed = set()
        self._read_not_writed = set()

    def feed_write(self, pc, address, size):
        #data = self._emu.mu.mem_read(address, size)
        for addr in range(address, address + size):
            self._has_writed.add(addr)

    def feed_read(self, pc, address, size):
        for addr in range(address, address + size):
            if addr not in self._has_writed:
                self._read_not_writed.add((addr, pc))

    def dump_read_no_write(self, f):
        name_read = "unknown"
        name_pc = "unknown"
        base_read = 0
        base_pc = 0
        li = sorted(self._read_not_writed)
        for item in li:
            addr = item[0]
            pc = item[1]
            moudle_mem = get_module_by_addr(self._emu, addr)
            if moudle_mem is not None:
                name_read = os.path.basename(moudle_mem.filename)
                base_read = moudle_mem.base

            else:
                name_read = "unknown"
                base_read = 0

            moudle_pc = get_module_by_addr(self._emu, pc)

            if moudle_pc is not None:
                name_pc = os.path.basename(moudle_pc.filename)
                base_pc = moudle_pc.base

            else:
                name_pc = "unknown"
                base_pc = 0

            line = "[0x%08X(%s) 0x%08X(%s)]\n" % (
                addr - base_read, name_read, pc - base_pc, name_pc)
            f.write(line)
