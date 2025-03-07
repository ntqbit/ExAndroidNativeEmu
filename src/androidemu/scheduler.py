
import time

from collections import deque

import verboselogs

from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import (
    UC_ARM_REG_LR,
    UC_ARM_REG_SP,
    UC_ARM_REG_R0,
    UC_ARM_REG_PC,
    UC_ARM_REG_C13_C0_3,
    UC_ARM_REG_CPSR
)
from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_X30
)

from androidemu.const.emu_const import STOP_MEMORY_BASE, STOP_MEMORY_SIZE, Arch

from androidemu.utils.misc_utils import format_addr


logger = verboselogs.VerboseLogger(__name__)


class Task:
    def __init__(self):
        self.entry = 0
        self.context = None
        self.tid = 0
        self.init_stack_ptr = 0
        self.tls_ptr = 0
        self.is_init = True
        self.is_main = False
        self.is_exit = False
        # the time ts for prev halt, in ms
        self.halt_ts = -1
        # the timeout for blocking -1 is infinte
        self.blocking_timeout = -1


class Scheduler:
    def __init__(self, emu):
        self._emu = emu
        self._mu = self._emu.mu
        self._pid = self._emu.get_pcb().get_pid()
        self._next_sub_tid = self._pid + 1
        self._tasks_queue = deque()
        self._tasks_map = {}
        self._defer_task_map = {}
        self._tid_2_remove = set()
        self._cur_tid = 0
        self._stopped = False

        self._emu.memory.map(
            STOP_MEMORY_BASE,
            STOP_MEMORY_SIZE,
            UC_PROT_READ | UC_PROT_EXEC,
        )
        self._stop_pos = STOP_MEMORY_BASE

        # blocking futex ptr to thread lists,
        # 记录在futex中等待的任务id
        self._futex_blocking_map = {}
        # just record all blocking tid
        self._blocking_set = set()

    def stop(self):
        self._stopped = True

    def _get_pc(self):
        if self._emu.get_arch() == Arch.ARM32:
            pc = self._emu.mu.reg_read(UC_ARM_REG_PC)
            return pc
        else:
            return self._emu.mu.reg_read(UC_ARM64_REG_PC)

    def _clear_reg0(self):

        if self._emu.get_arch() == Arch.ARM32:
            self._mu.reg_write(UC_ARM_REG_R0, 0)
        else:
            self._mu.reg_write(UC_ARM64_REG_X0, 0)

    def _set_sp(self, sp):
        if self._emu.get_arch() == Arch.ARM32:
            self._emu.mu.reg_write(UC_ARM_REG_SP, sp)
        else:
            self._emu.mu.reg_write(UC_ARM64_REG_SP, sp)

    def _set_tls(self, tls_ptr):
        if self._emu.get_arch() == Arch.ARM32:
            self._emu.mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            self._emu.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)

    def _get_interrupted_entry(self):
        pc = self._get_pc()
        if self._emu.get_arch() == Arch.ARM32:
            cpsr = self._emu.mu.reg_read(UC_ARM_REG_CPSR)
            if cpsr & (1 << 5):
                pc = pc | 1

        return pc

    def _create_task(self, tid, stack_ptr, context, is_main, tls_ptr):
        t = Task()
        t.tid = tid
        t.init_stack_ptr = stack_ptr
        t.context = context
        t.is_main = is_main
        t.tls_ptr = tls_ptr
        return t

    def _set_main_task(self):
        tid = self._emu.get_pcb().get_pid()
        if tid in self._tasks_map:
            raise RuntimeError(f"set_main_task fail for main task {tid} exist")

        t = self._create_task(tid, 0, None, True, 0)
        self._tasks_map[tid] = t
        self._tasks_queue.append(tid)

    def sleep(self, ms):
        tid = self._cur_tid
        self._blocking_set.add(tid)
        self._tasks_map[tid].blocking_timeout = ms
        self.yield_task()

    def futex_wait(self, futex_ptr, timeout=-1):
        block_set = None
        if futex_ptr in self._futex_blocking_map:
            block_set = self._futex_blocking_map[futex_ptr]

        else:
            block_set = set()
            self._futex_blocking_map[futex_ptr] = block_set

        tid = self.get_current_tid()
        block_set.add(tid)
        self._blocking_set.add(tid)
        self._tasks_map[tid].blocking_timeout = timeout

        # handle out control flow
        self.yield_task()

    def futex_wake(self, futex_ptr):
        cur_tid = self.get_current_tid()

        if futex_ptr in self._futex_blocking_map:
            block_set = self._futex_blocking_map[futex_ptr]
            if len(block_set) > 0:
                tid = block_set.pop()
                self._blocking_set.remove(tid)
                logger.debug(
                    "%d futex_wake tid %d waiting in futex_ptr 0x%08X is unblocked"
                    % (cur_tid, tid, futex_ptr)
                )
                return True
            else:
                logger.info(
                    "%d futex_wake unblock nobody waiting in futex ptr 0x%08X"
                    % (cur_tid, futex_ptr)
                )
                return False

        else:
            logger.info(
                "%d futex_wake unblock nobody waiting in futex ptr 0x%08X"
                % (cur_tid, futex_ptr)
            )
            return False

    # 创建子线程任务

    def add_sub_task(self, stack_ptr, tls_ptr=0):
        tid = self._next_sub_tid
        ctx = self._emu.mu.context_save()
        t = self._create_task(tid, stack_ptr, ctx, False, tls_ptr)
        self._defer_task_map[tid] = t
        self._next_sub_tid = self._next_sub_tid + 1
        return tid

    def get_current_tid(self):
        return self._cur_tid

    # yield the task.

    def yield_task(self):
        logger.debug("tid %d yield", self._cur_tid)
        self._emu.mu.emu_stop()

    def exit_current_task(self):
        self._tasks_map[self._cur_tid].is_exit = True
        self._tid_2_remove.add(self._cur_tid)
        self.yield_task()

    # @params entry the main_thread entry_point

    def exec(self, main_entry, clear_task_when_return=True):
        self._set_main_task()
        if self._emu.get_arch() == Arch.ARM32:
            self._emu.mu.reg_write(UC_ARM_REG_LR, self._stop_pos)
        else:
            self._emu.mu.reg_write(UC_ARM64_REG_X30, self._stop_pos)

        while True:
            for tid in self._tasks_queue:
                task = self._tasks_map[tid]
                if tid in self._blocking_set:
                    # 处理block
                    if len(self._tasks_queue) == 1:
                        if task.blocking_timeout < 0:
                            raise RuntimeError("only one task %d exists, but blocking infinity dead lock bug!" % tid)
                        else:
                            logger.debug(
                                "only on task %d block with timeout %d ms do sleep"
                                % (tid, task.blocking_timeout)
                            )
                            time.sleep(task.blocking_timeout / 1000)
                            self._blocking_set.remove(tid)

                    else:
                        if task.blocking_timeout > 0:
                            now = int(time.time() * 1000)
                            if now - task.halt_ts < task.blocking_timeout:
                                logger.debug(
                                    "%d is blocking skip scheduling ts has block %d ms timeout %d ms"
                                    % (
                                        tid,
                                        now - task.halt_ts,
                                        task.blocking_timeout,
                                    )
                                )
                                continue
                            else:
                                logger.debug("%d is wait up for timeout", tid)
                                task.blocking_timeout = -1
                                self._blocking_set.remove(tid)
                        else:
                            logger.debug("%d is blocking skip scheduling", tid)
                            continue

                logger.debug("%d scheduling enter ", tid)

                self._cur_tid = tid
                # run
                start_pos = 0
                if task.is_main:
                    if task.is_init:
                        start_pos = main_entry
                        task.is_init = False

                    else:
                        self._emu.mu.context_restore(task.context)
                        start_pos = self._get_interrupted_entry()

                else:
                    self._emu.mu.context_restore(task.context)
                    start_pos = self._get_interrupted_entry()

                    if task.is_init:
                        self._set_sp(task.init_stack_ptr)
                        if task.tls_ptr:
                            self._set_tls(task.tls_ptr)

                        self._clear_reg0()
                        task.is_init = False

                logger.debug(
                    "scheduler starting at %s. stop pos: %s",
                    format_addr(self._emu, start_pos),
                    format_addr(self._emu, self._stop_pos),
                )

                self._emu.mu.emu_start(start_pos, self._stop_pos, 0, 0)
                task.halt_ts = int(time.time() * 1000)
                # after run
                ctx = self._emu.mu.context_save()
                task.context = ctx

                if self._stopped:
                    self._stopped = False
                    return

                if self._get_pc() == self._stop_pos or task.is_exit:
                    self._tid_2_remove.add(self._cur_tid)
                    logger.debug("%d scheduling exit", tid)

                else:
                    logger.debug("%d scheduling paused", tid)

            for tid in self._tid_2_remove:
                self._tasks_map.pop(tid)
                # FIXME slow delete, try to optimize
                self._tasks_queue.remove(tid)

            self._tid_2_remove.clear()

            for tid_defer in self._defer_task_map:
                self._tasks_map[tid_defer] = self._defer_task_map[tid_defer]
                self._tasks_queue.append(tid_defer)

            self._defer_task_map.clear()

            if self._pid not in self._tasks_map:
                logger.debug("main_thead tid [%d] exit exec return", self._pid)

                if clear_task_when_return:
                    # clear all unfinished task
                    self._tasks_map.clear()
                    break
