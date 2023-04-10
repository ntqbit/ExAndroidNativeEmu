import sys

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String
from androidemu.utils import debug_utils


class Boolean(metaclass=JavaClassDef, jvm_name="java/lang/Boolean"):
    def __init__(self, value=False):
        self._value = value

    @java_method_def(name="booleanValue", signature="()Z", native=False)
    def booleanValue(self, emu):
        return self._value

    def __repr__(self):
        return "true" if self._value else "false"

    @java_method_def(
        name="getClass", signature="()Ljava/lang/Class;", native=False
    )
    def getClass(self, emu):
        return self.class_object


class Integer(metaclass=JavaClassDef, jvm_name="java/lang/Integer"):
    def __init__(self, value=0):
        self._value = value

    @java_method_def(
        name="<init>", args_list=["jint"], signature="(I)V", native=False
    )
    def ctor(self, emu, value):
        self._value = value

    @java_method_def(name="intValue", signature="()I", native=False)
    def intValue(self, emu):
        return self._value

    def __repr__(self):
        return f"Int({self._value})"

    # TODO: 在继承多态机制完善后移动到Object类上

    @java_method_def(
        name="getClass", signature="()Ljava/lang/Class;", native=False
    )
    def getClass(self, emu):
        return self.class_object


class Long(metaclass=JavaClassDef, jvm_name="java/lang/Long"):
    def __init__(self, value=0):
        self._value = value

    @java_method_def(
        name="<init>", args_list=["jlong"], signature="(J)V", native=False
    )
    def ctor(self, emu, lvalue):

        self._value = lvalue

    @java_method_def(name="longValue", signature="()J", native=False)
    def longValue(self, emu):
        return self._value

    def __repr__(self):
        return f"Long({self._value})"

    @java_method_def(name="getClass", signature="()Ljava/lang/Class;", native=False)
    def getClass(self, emu):
        return self.class_object

    @java_method_def('toString', signature='()Ljava/lang/String;')
    def toString(self, emu):
        return String(str(self._value))

    def get_py_value(self):
        return self._value


class Float(metaclass=JavaClassDef, jvm_name="java/lang/Float"):
    def __init__(self, value=0.0):
        self._value = value

    def __repr__(self):
        return f"Float({self._value})"

    # #TODO: 在继承多态机制完善后移动到Object类上

    @java_method_def(
        name="getClass", signature="()Ljava/lang/Class;", native=False
    )
    def getClass(self, emu):
        return self.class_object
