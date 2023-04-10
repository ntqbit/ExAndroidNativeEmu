from androidemu.java import JavaClassDef
from androidemu.java.const import *
from androidemu.java.classes.array import *


class Set(metaclass=JavaClassDef, jvm_name="java/util/Set"):
    def __init__(self, pyset):
        self._pyset = pyset

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self._pyset = set()

    def __len__(self):
        return len(self._pyset)

    def __getitem__(self, key):
        return self._pyset[key]

    """
    @java_method_def(name='get', args_list=["jobject"], signature='(Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key):
        if key in self._pyset:
            return self._pyset[key]
        return JAVA_NULL



    @java_method_def(name='put', args_list=["jobject", "jobject"], signature='(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;', native=False)
    def get(self, emu, key, value):
        prev = JAVA_NULL
        if key in self._pyset:
            prev = self._pyset[key]

        self._pyset[key] = value
        return prev

    """

    @java_method_def(
        name="toArray", signature="()[Ljava/lang/Object;", native=False
    )
    def toArray(self, emu):
        return Array(list(self._pyset))

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self._pyset)
