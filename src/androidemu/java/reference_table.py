import verboselogs

from androidemu.java.jni_ref import *


logger = verboselogs.VerboseLogger(__name__)


class ReferenceTable:
    """
    :type _table dict[int, jobject|None]
    """

    def __init__(self, start=1, max_entries=1024):
        self._table = dict()
        self._start = start
        self._size = max_entries

    def set(self, index, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError('Expected a jobject.')

        if index not in self._table:
            raise ValueError('Expected a index.')

        self._table[index] = newobj
        logger.debug('reference: set: %s = %d', newobj, index)

    def add(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError('Expected a jobject.')

        # Search a free index.
        index = self._start
        while index in self._table:
            index += 1

        # Add to table.
        self._table[index] = obj
        logger.debug('reference: add: %s = %d', obj, index)

        return index

    def remove(self, index):
        assert index != 0 and index is not None

        logger.debug('reference: remove: %s = %d', self._table[index], index)
        self._table[index] = None
        return True

    def get(self, index):
        if index not in self._table:
            logger.debug('reference: get: not found %d', index)
            return None

        r = self._table[index]
        logger.debug('reference: get: %s = %d', r, index)
        return r

    def in_range(self, idx):
        return self._start <= idx < self._start + self._size

    def clear(self):
        logger.debug('reference: cleanup')
        self._table.clear()
