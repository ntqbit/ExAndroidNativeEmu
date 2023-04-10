from androidemu.java import JavaClassDef, java_method_def


class Uri(metaclass=JavaClassDef, jvm_name="android/net/Uri"):
    def __init__(self, pystr):
        self._uri = pystr

    def get_py_string(self):
        return self._uri

    def __repr__(self):
        return f"Uri({self._uri})"

    @staticmethod
    @java_method_def(
        name="parse",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Landroid/net/Uri;",
        native=False,
    )
    def parse(emu, uri):
        pystr_uri = uri.get_py_string()
        uri = Uri(pystr_uri)
        return uri
