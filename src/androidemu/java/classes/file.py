from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String


class File(metaclass=JavaClassDef, jvm_name='java/io/File'):

    def __init__(self, path):
        assert isinstance(path, str)
        self._path = path

    @java_method_def(name='getPath',
                     signature='()Ljava/lang/String;',
                     native=False)
    def getPath(self, emu):
        return String(self._path)

    @java_method_def(name='getAbsolutePath',
                     signature='()Ljava/lang/String;',
                     native=False)
    def getAbsolutePath(self, emu):
        raise NotImplementedError()
        # FIXME return abspath...
        return String(self._path)
