from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.file import File


class Environment(metaclass=JavaClassDef, jvm_name="android/os/Environment"):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getExternalStorageDirectory",
        signature="()Ljava/io/File;",
        native=False,
    )
    def getExternalStorageDirectory(emu):
        return File("/sdcard/")
