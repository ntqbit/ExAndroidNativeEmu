from androidemu.java import JavaClassDef

from androidemu.java.classes.clazz import Class


class JavaClassLoader(metaclass=JavaClassDef, jvm_name="java/lang/ClassLoader"):

    def __init__(self):
        self._class_by_id = dict()
        self._class_by_name = dict()

    def add_class(self, clazz):
        if not isinstance(clazz, JavaClassDef):
            raise ValueError("Expected a JavaClassDef.")

        if clazz.jvm_name in self._class_by_name:
            raise KeyError(f"The class '{clazz.jvm_name}' is already registered.")

        if clazz.class_object is None:
            clazz.class_object = Class(clazz, self)

        self._class_by_id[clazz.jvm_id] = clazz
        self._class_by_name[clazz.jvm_name] = clazz

    def find_class_by_id(self, jvm_id):
        if jvm_id not in self._class_by_id:
            return None

        return self._class_by_id[jvm_id]

    def find_class_by_name(self, name):
        if name not in self._class_by_name:
            return None

        return self._class_by_name[name]
