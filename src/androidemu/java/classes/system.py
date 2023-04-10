import time

from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.string import String


class System(metaclass=JavaClassDef, jvm_name="java/lang/System"):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getProperty",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/String;"
    )
    def getProperty(mu, s1):
        key = s1.get_py_string()
        if key == "java.vm.version":
            return String("1.6.0")

        return String("")

    @staticmethod
    @java_method_def('currentTimeMillis', '()J')
    def currentTimeMillis(emu):
        return round(time.time() * 1000)
