from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *
from androidemu.java.classes.string import String


class Bundle(metaclass=JavaClassDef, jvm_name="android/os/Bundle"):
    def __init__(self, py_map={}):
        self._pymap = py_map

    def __repr__(self):
        return f"Bundle({self._pymap})"

    @java_method_def(
        "getString",
        "(Ljava/lang/String;)Ljava/lang/String;",
        args_list=["jstring"],
    )
    def getString(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self._pymap:
            return String(self._pymap[pykey])
        else:
            return JAVA_NULL

    @java_method_def(
        "getInt",
        "(Ljava/lang/String;I)I",
        args_list=["jstring", "jint"],
    )
    def getInt(self, emu, k: String, default):
        pykey = k.get_py_string()
        if pykey in self._pymap:
            return int(self._pymap[pykey])
        else:
            return default

    @java_method_def(
        "getBoolean",
        "(Ljava/lang/String;)Z",
        args_list=["jstring"]
    )
    def getBoolean(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self._pymap:
            return bool(self._pymap[pykey])
        else:
            return JAVA_NULL
