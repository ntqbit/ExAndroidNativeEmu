from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *


class List(metaclass=JavaClassDef, jvm_name="java/util/List"):
    def __init__(self, pylist):
        self._pylist = pylist

    def __repr__(self):
        return f"List({self._pylist})"

    def __len__(self):
        return len(self._pylist)

    def __getitem__(self, index):
        return self._pylist[index]

    def __setitem__(self, index, value):
        self._pylist[index] = value

    @java_method_def(
        name="get",
        args_list=["jint"],
        signature="(I)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, index):
        if index < len(self._pylist):
            return self._pylist[index]
        return JAVA_NULL

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self._pylist)

    @java_method_def(name="isEmpty", signature="()Z", native=False)
    def isEmpty(self, emu):
        return len(self._pylist) == 0
