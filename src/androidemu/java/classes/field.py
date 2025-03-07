import verboselogs

from androidemu.java import JavaClassDef, java_method_def

logger = verboselogs.VerboseLogger(__name__)


class AccessibleObject(
    metaclass=JavaClassDef, jvm_name="java/lang/reflect/AccessibleObject"
):
    def __init__(self):
        pass

    @java_method_def(
        name="setAccessible",
        args_list=["jboolean"],
        signature="(Z)V",
        native=False,
    )
    def setAccessible(self, emu, access):
        logger.debug("AccessibleObject setAccessible call skip")


class Field(
    AccessibleObject,
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Field",
    jvm_super=AccessibleObject,
):
    def __init__(self, pydeclaringClass: JavaClassDef, fieldName: str):
        super().__init__()
        self._fieldName = fieldName
        self.declaringClass = pydeclaringClass

    @java_method_def(
        name="get",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, obj):
        logger.debug("Field.get(%r)" % obj)

        v = getattr(obj, self._fieldName)
        return v
