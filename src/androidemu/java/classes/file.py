import verboselogs

from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.string import String

logger = verboselogs.VerboseLogger(__name__)


class File(metaclass=JavaClassDef, jvm_name="java/io/File"):
    def __init__(self, path):
        assert isinstance(path, str)
        self._path = path

    def __repr__(self):
        return f'File("{self._path}")'

    @java_method_def(
        "getPath", "()Ljava/lang/String;", native=False
    )
    def getPath(self, emu):
        logger.debug("File.getPath: [path=%s]", self._path)
        return String(self._path)

    @java_method_def(
        "getAbsolutePath", "()Ljava/lang/String;", native=False
    )
    def getAbsolutePath(self, emu):
        logger.debug("File.getAbsolutePath: [path=%s]", self._path)
        return String(self._path)

    @java_method_def(
        "toString", "()Ljava/lang/String;", native=False
    )
    def toString(self, emu):
        logger.debug("File.toString: [path=%s]", self._path)
        return String(self._path)
