import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def


logger = verboselogs.VerboseLogger(__name__)


class Iterator(metaclass=JavaClassDef, jvm_name='java/util/Iterator'):
    def __init__(self):
        pass

    @java_method_def('hasNext', '()Z')
    def hasNext(self, emu):
        return False


class TreeSet(metaclass=JavaClassDef, jvm_name='java/util/TreeSet'):
    def __init__(self):
        pass

    @java_method_def('<init>', '()V')
    def ctor(self, emu):
        pass

    @java_method_def('iterator', '()Ljava/util/Iterator;')
    def iterator(self, emu):
        return Iterator()
