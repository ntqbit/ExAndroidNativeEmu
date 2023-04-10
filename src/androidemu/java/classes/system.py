import time

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *
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
