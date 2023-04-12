import sys

import verboselogs

from androidemu.vfs.virtual_file import VirtualFile

logger = verboselogs.VerboseLogger(__name__)


DEFAULT_PID = 400

class Pcb:
    def __init__(self, pid=DEFAULT_PID):
        self._pid = DEFAULT_PID
        self._fds = {}
        self._fds[sys.stdin.fileno()] = VirtualFile(
            "stdin", sys.stdin.fileno()
        )
        self._fds[sys.stdout.fileno()] = VirtualFile(
            "stdout", sys.stdout.fileno()
        )
        self._fds[sys.stderr.fileno()] = VirtualFile(
            "stderr", sys.stderr.fileno()
        )

    def get_pid(self):
        return self._pid

    def add_fd(self, name, name_in_system, fd):
        logger.debug('add_fd: [name=%s,name_in_system=%s,fd=%d]', name, name_in_system, fd)
        self._fds[fd] = VirtualFile(name, fd, name_in_system=name_in_system)
        return fd

    def get_fd_detail(self, fd):
        if fd not in self._fds:
            return None
        return self._fds[fd]

    def has_fd(self, fd):
        return fd in self._fds

    def remove_fd(self, fd):
        logger.debug('remove_fd: [fd=%d]', fd)
        self._fds.pop(fd)
