import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def


logger = verboselogs.VerboseLogger(__name__)


class Enumeration(metaclass=JavaClassDef, jvm_name='java/util/Enumeration'):
    def __init__(self, iterable):
        self._iter = iterable
        self._next = None

    @java_method_def('hasMoreElements', '()Z', args_list=[])
    def hasMoreElements(self, emu):
        return self._get_next() is not None

    @java_method_def('nextElement', '()Ljava/lang/Object;', args_list=[])
    def nextElement(self, emu):
        return self._get_next()

    def _get_next(self):
        try:
            self._next = next(self._iter)
        except StopIteration:
            self._next = None

        return self._next
