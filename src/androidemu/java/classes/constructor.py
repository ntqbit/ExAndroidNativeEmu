from androidemu.java.classes.executable import Executable
from androidemu.java import JavaClassDef, JavaMethodDef, JavaFieldDef


class Constructor(
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Constructor",
    jvm_fields=[
        JavaFieldDef("slot", "I", ignore=True),
        JavaFieldDef("declaringClass", "Ljava/lang/Class;"),
    ],
    jvm_super=Executable,
):
    def __init__(self, clazz: JavaClassDef, method: JavaMethodDef):
        self._clazz = clazz
        self._method = method
        self.slot = method.jvm_id
        self.declaringClass = self._clazz
        self.accessFlags = method.modifier
