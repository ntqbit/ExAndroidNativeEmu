from androidemu.java import JavaClassDef, java_method_def
from androidemu.utils.repr import short_bytes_repr


class Array(metaclass=JavaClassDef, jvm_name="java/lang/reflect/Array"):
    def __init__(self, pyitems):
        self._pyitems = pyitems

    def get_py_items(self):
        return self._pyitems

    def __len__(self):
        return len(self._pyitems)

    def __getitem__(self, index):
        return self._pyitems[index]

    def __setitem__(self, index, value):
        self._pyitems[index] = value

    def __repr__(self):
        return f"Array({self._pyitems})"

    @staticmethod
    @java_method_def(
        name="set",
        signature="(Ljava/lang/Object;I)Ljava/lang/Object;",
        native=False,
    )
    def set(emu, obj, index):
        raise NotImplementedError()


class ByteArray(Array, metaclass=JavaClassDef, jvm_name="[B", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f"ByteArray({short_bytes_repr(self._pyitems)})"


class ObjectArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/Object;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f"ObjectArray({self._pyitems})"


class ClassArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/Class;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f"ClassArray({self._pyitems})"


class StringArray(
    Array,
    metaclass=JavaClassDef,
    jvm_name="[Ljava/lang/String;",
    jvm_super=Array,
):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f"StringArray({self._pyitems})"
