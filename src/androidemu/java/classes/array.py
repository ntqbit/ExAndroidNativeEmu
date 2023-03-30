from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef


class Array(metaclass=JavaClassDef, jvm_name='java/lang/reflect/Array'):

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
    @java_method_def(name='set',
                     signature='(Ljava/lang/Object;I)Ljava/lang/Object;',
                     native=False)
    def set(emu, obj, index):
        raise NotImplementedError()

    # #TODO: 在继承多态机制完善后移动到Object类上

    @java_method_def(name='getClass',
                     signature='()Ljava/lang/Class;',
                     native=False)
    def getClass(self, emu):
        return self.class_object


# 外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ByteArray(Array, metaclass=JavaClassDef, jvm_name="[B", jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        b = self._pyitems
        if len(b) > 20:
            b = b[:18] + '..'

        return f'ByteArray({b})'


# 外面用到，因为与Array jvm name不同，所以暂时手动定义，与Array作用一样
class ObjectArray(
        Array,
        metaclass=JavaClassDef,
        jvm_name="[Ljava/lang/Object;",
        jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f'ObjectArray({self._pyitems})'


class ClassArray(
        Array,
        metaclass=JavaClassDef,
        jvm_name="[Ljava/lang/Class;",
        jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f'ClassArray({self._pyitems})'


class StringArray(
        Array,
        metaclass=JavaClassDef,
        jvm_name="[Ljava/lang/String;",
        jvm_super=Array):
    def __init__(self, item_list):
        Array.__init__(self, item_list)

    def __repr__(self):
        return f'StringArray({self._pyitems})'
