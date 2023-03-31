import verboselogs

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_LR, UC_ARM_REG_PC
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X6, UC_ARM64_REG_X8, UC_ARM64_REG_LR, UC_ARM64_REG_PC

from androidemu.cpu.interrupt_handler import InterruptHandler
from androidemu.cpu.syscall_handler import SyscallHandler
from androidemu.const import emu_const

logger = verboselogs.VerboseLogger(__name__)


class SyscallHandlers:
    """
    :type interrupt_handler InterruptHandler
    """

    def __init__(self, mu, schduler, arch):
        self._handlers = dict()
        self._sch = schduler
        self._interrupt_handler = InterruptHandler(mu)

        if arch == emu_const.ARCH_ARM32:
            self._interrupt_handler.set_handler(2, self._handle_syscall)
        else:
            # arm64
            self._interrupt_handler.set_handler(2, self._handle_syscall64)

    def set_handler(self, idx, name, arg_count, callback):
        self._handlers[idx] = SyscallHandler(idx, name, arg_count, callback)

    def _handle_syscall(self, mu):
        idx = mu.reg_read(UC_ARM_REG_R7)
        lr = mu.reg_read(UC_ARM_REG_LR)
        tid = self._sch.get_current_tid()

        logger.debug("%d syscall %d lr=0x%08X", tid, idx, lr)

        args = [
            mu.reg_read(reg_idx) for reg_idx in range(
                UC_ARM_REG_R0,
                UC_ARM_REG_R6 + 1)]
        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[:handler.arg_count]
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])

            logger.debug("%d Executing syscall %s(%s) at 0x%08X",
                         tid, handler.name, args_formatted, mu.reg_read(UC_ARM_REG_PC))

            try:
                result = handler.callback(mu, *args)
            except BaseException:
                logger.exception("%d An error occured during in %x syscall hander, stopping emulation",
                                 tid, idx)
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM_REG_R0, result)
        else:
            args_formatted = ", ".join(["0x%08X" % arg for arg in args])
            error = "%d Unhandled syscall 0x%x (%u) at 0x%x, args(%s) stopping emulation" % (
                tid, idx, idx, mu.reg_read(UC_ARM_REG_PC), args_formatted)

            logger.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)

    def _handle_syscall64(self, mu):
        idx = mu.reg_read(UC_ARM64_REG_X8)
        lr = mu.reg_read(UC_ARM64_REG_LR)
        tid = self._sch.get_current_tid()

        logger.debug("%d syscall %d lr=0x%016X", tid, idx, lr)
        args = [
            mu.reg_read(reg_idx) for reg_idx in range(
                UC_ARM64_REG_X0,
                UC_ARM64_REG_X6 + 1)]

        if idx in self._handlers:
            handler = self._handlers[idx]
            args = args[:handler.arg_count]
            args_formatted = ", ".join(["0x%016X" % arg for arg in args])
            logger.debug(
                "%d Executing syscall %s(%s) at 0x%016X" %
                (tid, handler.name, args_formatted, mu.reg_read(UC_ARM64_REG_PC)))
            try:
                result = handler.callback(mu, *args)
            except BaseException:
                logger.exception(
                    "%d An error occured during in %x syscall hander, stopping emulation" %
                    (tid, idx))
                mu.emu_stop()
                raise

            if result is not None:
                mu.reg_write(UC_ARM64_REG_X0, result)
        else:
            args_formatted = ", ".join(["0x%016X" % arg for arg in args])
            error = "%d Unhandled syscall 0x%x (%u) at 0x%x, args(%s) stopping emulation" % (
                tid, idx, idx, mu.reg_read(UC_ARM64_REG_PC), args_formatted)

            logger.exception(error)
            mu.emu_stop()
            raise RuntimeError(error)
