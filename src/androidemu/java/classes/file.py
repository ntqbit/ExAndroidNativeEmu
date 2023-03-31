import verboselogs

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.string import String

logger = verboselogs.VerboseLogger(__name__)


class File(metaclass=JavaClassDef, jvm_name='java/io/File'):

    def __init__(self, path):
        assert isinstance(path, str)
        self._path = path

    def __repr__(self):
        return f'File("{self._path}")'

    @java_method_def(name='getPath',
                     signature='()Ljava/lang/String;',
                     native=False)
    def getPath(self, emu):
        logger.debug('File.getPath: [path=%s]', self._path)
        return String(self._path)

    @java_method_def(name='getAbsolutePath',
                     signature='()Ljava/lang/String;',
                     native=False)
    def getAbsolutePath(self, emu):
        raise NotImplementedError()
        # FIXME return abspath...
        return String(self._path)
