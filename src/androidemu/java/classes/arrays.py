from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.list import List
from androidemu.java.classes.array import Array


class Arrays(
    metaclass=JavaClassDef, jvm_name="java/util/Arrays"
):
    def __init__(self):
        pass

    @java_method_def('asList', '([Ljava/lang/Object;)Ljava/util/List;', args_list=['jobject'])
    @staticmethod
    def asList(emu, objs: Array):
        return List(objs.get_py_items())
