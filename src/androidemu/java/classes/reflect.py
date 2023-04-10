import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def


logger = verboselogs.VerboseLogger(__name__)


PUBLIC = 1 << 0
PRIVATE = 1 << 1
PROTECTED = 1 << 2
STATIC = 1 << 3
FINAL = 1 << 4
SYNCHRONIZED = 1 << 5
VOLATILE = 1 << 6
TRANSIENT = 1 << 7
NATIVE = 1 << 8
INTERFACE = 1 << 9
ABSTRACT = 1 << 10
STRICT = 1 << 11


class Modifier(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Modifier',
               jvm_fields=[
                   JavaFieldDef('PUBLIC', 'I', True, PUBLIC),
                   JavaFieldDef('PRIVATE', 'I', True, PRIVATE),
                   JavaFieldDef('PROTECTED', 'I', True, PROTECTED),
                   JavaFieldDef('STATIC', 'I', True, STATIC),
                   JavaFieldDef('FINAL', 'I', True, FINAL),
                   JavaFieldDef('SYNCHRONIZED', 'I', True, SYNCHRONIZED),
                   JavaFieldDef('VOLATILE', 'I', True, VOLATILE),
                   JavaFieldDef('TRANSIENT', 'I', True, TRANSIENT),
                   JavaFieldDef('NATIVE', 'I', True, NATIVE),
                   JavaFieldDef('INTERFACE', 'I', True, INTERFACE),
                   JavaFieldDef('ABSTRACT', 'I', True, ABSTRACT),
                   JavaFieldDef('STRICT', 'I', True, STRICT)
               ]):
    def __init__(self):
        pass
