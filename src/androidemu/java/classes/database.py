import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def


logger = verboselogs.VerboseLogger(__name__)


class Cursor(metaclass=JavaClassDef, jvm_name='android/database/Cursor'):
    def __init__(self):
        pass
