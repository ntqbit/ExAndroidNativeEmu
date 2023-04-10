from androidemu.java import JavaClassDef, JavaFieldDef


class Executable(
    metaclass=JavaClassDef,
    jvm_name="java/lang/reflect/Executable",
    jvm_fields=[JavaFieldDef("accessFlags", "I")],
):
    def __init__(self):
        pass
