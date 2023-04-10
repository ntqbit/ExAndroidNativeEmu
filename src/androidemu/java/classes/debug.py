from androidemu.java import JavaClassDef, java_method_def


class Debug(metaclass=JavaClassDef, jvm_name="android/os/Debug"):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name="isDebuggerConnected", signature="()Z", native=False)
    def isDebuggerConnected(emu):
        return False
