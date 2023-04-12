import verboselogs

from unicorn import UC_HOOK_INTR, UC_ARCH_ARM, UC_ARCH_ARM64, UC_QUERY_ARCH
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm64_const import UC_ARM64_REG_PC

from androidemu.utils.misc_utils import format_addr

logger = verboselogs.VerboseLogger(__name__)


class InterruptHandler:
    def __init__(self, emu):
        self._emu = emu
        self._emu.mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        try:
            if intno in self._handlers:
                self._handlers[intno](uc)
            else:                
                arch = self._emu.mu.query(UC_QUERY_ARCH)
                if arch == UC_ARCH_ARM:
                    pc = self._emu.mu.reg_read(UC_ARM_REG_PC)
                elif arch == UC_ARCH_ARM64:
                    pc = self._emu.mu.reg_read(UC_ARM64_REG_PC)
                else:
                    raise NotImplementedError()

                logger.error("Unhandled interrupt %d at %s, stopping emulation", intno, format_addr(self._emu, pc))
                self._emu.mu.emu_stop()
                raise RuntimeError('Unhandled interrupt')
        except Exception:
            logger.exception("Caught an exception in _hook_interrupt intno: %d", intno)
            self._emu.mu.emu_stop()
            raise

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
