from androidemu.java import JavaClassDef, java_method_def


class DexFile(metaclass=JavaClassDef, jvm_name="dalvik/system/DexFile"):
    def __init__(self):
        pass

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, *args, **kwargs):
        return DexFile()
