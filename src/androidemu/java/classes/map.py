from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.const import *
from androidemu.java.classes.java_set import Set


class HashMap(metaclass=JavaClassDef, jvm_name="java/util/HashMap"):
    def __init__(self, pydict={}):
        self._pydict = pydict

    def __repr__(self):
        return f"HashMap({self._pydict})"

    @java_method_def(name="<init>", signature="()V", native=False)
    def ctor(self, emu):
        self._pydict = {}

    @java_method_def(name="<init>", signature="(I)V", native=False)
    def ctor2(self, emu):
        self._pydict = {}

    def __len__(self):
        return len(self._pydict)

    def __getitem__(self, key):
        return self._pydict[key]

    def __setitem__(self, key, value):
        self._pydict[key] = value

    @java_method_def(
        name="get",
        args_list=["jobject"],
        signature="(Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def get(self, emu, key):
        if key in self._pydict:
            return self._pydict[key]
        return JAVA_NULL

    @java_method_def(
        name="put",
        args_list=["jobject", "jobject"],
        signature="(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def put(self, emu, key, value):
        prev = JAVA_NULL
        if key in self._pydict:
            prev = self._pydict[key]

        self._pydict[key] = value
        return prev

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self._pydict)

    @java_method_def(
        name="keySet", signature="()Ljava/util/Set;", native=False
    )
    def keySet(self, emu):
        # FIXME 由于不支持子类函数覆盖父类，所以暂时以Set返回
        jset = Set(set(self._pydict.keys()))
        return jset
