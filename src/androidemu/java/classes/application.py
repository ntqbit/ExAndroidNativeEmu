from androidemu.java import JavaClassDef

from androidemu.java.classes.context import ContextWrapper


class Application(
    ContextWrapper,
    metaclass=JavaClassDef,
    jvm_name="android/app/Application",
    jvm_super=ContextWrapper,
):
    def __init__(self):
        pass
