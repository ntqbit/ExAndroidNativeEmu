import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def
from androidemu.java.classes.exceptions import Throwable

logger = verboselogs.VerboseLogger(__name__)


class Log(metaclass=JavaClassDef, jvm_name='android/util/Log'):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def('getStackTraceString', '(Ljava/lang/Throwable;)Ljava/lang/String;', args_list=['jthrowable'])
    def getStackTraceString(emu, throwable: Throwable):
        return throwable.toString(emu)
