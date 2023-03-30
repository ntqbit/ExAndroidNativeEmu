from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *
from androidemu.java.classes.string import String


class Bundle(metaclass=JavaClassDef, jvm_name='android/os/Bundle'):

    def __init__(self, py_map={}):
        self._pymap = py_map

    def __repr__(self):
        return f'Bundle({self._pymap})'

    @java_method_def(name='getString',
                     args_list=["jstring"],
                     signature='(Ljava/lang/String;)Ljava/lang/String;',
                     native=False)
    def getString(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self._pymap:
            return String(self._pymap[pykey])
        else:
            # attention do not return None, return None means no return value
            # in function, return JAVA_NULL means the return value is NULL
            return JAVA_NULL

    @java_method_def(name='getBoolean',
                     args_list=["jstring"],
                     signature='(Ljava/lang/String;)Z',
                     native=False)
    def getBoolean(self, emu, k):
        pykey = k.get_py_string()
        if pykey in self._pymap:
            return bool(self._pymap[pykey])
        else:
            # attention do not return None, return None means no return value
            # in function, return JAVA_NULL means the return value is NULL
            return JAVA_NULL
