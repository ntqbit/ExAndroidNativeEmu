import sys

from typing import List


class Logger:
    def write(self, message: str):
        raise NotImplementedError

    def flush(self):
        raise NotImplementedError


class GroupLogger(Logger):
    def __init__(self, loggers: List[Logger]):
        self._loggers = loggers

    def write(self, message: str):
        for logger in self._loggers:
            logger.write(message)

    def flush(self):
        for logger in self._loggers:
            logger.flush()


class FileLogger(Logger):
    def __init__(self, file):
        self._file = file

    def write(self, message: str):
        self._file.write(message)

    def flush(self):
        pass


class StdOutLogger(FileLogger):
    def __init__(self):
        super().__init__(sys.stdout)


class StdErrLogger(FileLogger):
    def __init__(self):
        super().__init__(sys.stderr)
