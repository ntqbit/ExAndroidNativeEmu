from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.array import ByteArray, StringArray


class StringBuilder(metaclass=JavaClassDef, jvm_name='java/lang/StringBuilder'):
    def __init__(self):
        pass

    @java_method_def('<init>', '()V')
    def ctor(self, emu):
        pass


class String(metaclass=JavaClassDef, jvm_name="java/lang/String"):
    def __init__(self, pystr=""):
        if not isinstance(pystr, str):
            raise ValueError(f'Java String class got {type(pystr)} instead of str.')

        self._str = pystr

    def __repr__(self):
        return f'String("{self._str}")'

    def get_py_string(self):
        return self._str

    @java_method_def(
        name="<init>",
        args_list=["jobject", "jstring"],
        signature="([BLjava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, barr, charset):
        pyarr = barr.get_py_items()
        pystr = charset.get_py_string()
        self._str = pyarr.decode(pystr)

    @java_method_def(
        name="getBytes",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)[B",
        native=False,
    )
    def getBytes(self, emu, charset):
        pycharset = charset.get_py_string()
        barr = bytearray(self._str, pycharset)
        arr = ByteArray(barr)
        return arr

    @java_method_def('split', '(Ljava/lang/String;)[Ljava/lang/String;', args_list=['jstring'])
    def split(self, emu, separator: 'String'):
        return StringArray([String(s) for s in self._str.split(separator.get_py_string())])
