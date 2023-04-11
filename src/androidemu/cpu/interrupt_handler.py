import verboselogs

from unicorn import UC_HOOK_INTR, UC_ARCH_ARM, UC_ARCH_ARM64, UC_QUERY_ARCH
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm64_const import UC_ARM64_REG_PC

logger = verboselogs.VerboseLogger(__name__)


class InterruptHandler:
    def __init__(self, mu):
        self._mu = mu
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)
        self._handlers = dict()

    def _hook_interrupt(self, uc, intno, data):
        try:
            if intno in self._handlers:
                self._handlers[intno](uc)
            else:
                pc = 0
                arch = self._mu.query(UC_QUERY_ARCH)
                if arch == UC_ARCH_ARM:
                    pc = self._mu.reg_read(UC_ARM_REG_PC)
                elif arch == UC_ARCH_ARM64:
                    pc = self._mu.reg_read(UC_ARM64_REG_PC)

                logger.error("Unhandled interrupt %d at %x, stopping emulation", intno, pc)
                self._mu.emu_stop()
                raise RuntimeError('Unhandled interrupt')
        except Exception:
            logger.exception("Caught an exception in _hook_interrupt intno: %d", intno)
            self._mu.emu_stop()
            raise

    def set_handler(self, intno, handler):
        self._handlers[intno] = handler
