import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def
from androidemu.java.const import (
    MODIFIER_PUBLIC,
    MODIFIER_PRIVATE,
    MODIFIER_PROTECTED,
    MODIFIER_STATIC,
    MODIFIER_FINAL,
    MODIFIER_SYNCHRONIZED,
    MODIFIER_VOLATILE,
    MODIFIER_TRANSIENT,
    MODIFIER_NATIVE,
    MODIFIER_INTERFACE,
    MODIFIER_ABSTRACT,
    MODIFIER_STRICT
)


logger = verboselogs.VerboseLogger(__name__)


class Modifier(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Modifier',
               jvm_fields=[
                   JavaFieldDef('PUBLIC', 'I', True, MODIFIER_PUBLIC),
                   JavaFieldDef('PRIVATE', 'I', True, MODIFIER_PRIVATE),
                   JavaFieldDef('PROTECTED', 'I', True, MODIFIER_PROTECTED),
                   JavaFieldDef('STATIC', 'I', True, MODIFIER_STATIC),
                   JavaFieldDef('FINAL', 'I', True, MODIFIER_FINAL),
                   JavaFieldDef('SYNCHRONIZED', 'I', True, MODIFIER_SYNCHRONIZED),
                   JavaFieldDef('VOLATILE', 'I', True, MODIFIER_VOLATILE),
                   JavaFieldDef('TRANSIENT', 'I', True, MODIFIER_TRANSIENT),
                   JavaFieldDef('NATIVE', 'I', True, MODIFIER_NATIVE),
                   JavaFieldDef('INTERFACE', 'I', True, MODIFIER_INTERFACE),
                   JavaFieldDef('ABSTRACT', 'I', True, MODIFIER_ABSTRACT),
                   JavaFieldDef('STRICT', 'I', True, MODIFIER_STRICT)
               ]):
    def __init__(self):
        pass
