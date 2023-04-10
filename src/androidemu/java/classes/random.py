import random
import verboselogs

from androidemu.java import JavaClassDef, java_method_def

logger = verboselogs.VerboseLogger(__name__)


class Random(metaclass=JavaClassDef, jvm_name='java/util/Random'):
    def __init__(self):
        pass

    @java_method_def('<init>', '()V', args_list=[])
    def ctor(self, emu):
        pass

    @java_method_def('nextLong', '()J')
    def nextLong(self, emu):
        return random.randint(0, 10**6)
