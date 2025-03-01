import xml.dom.minidom


from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.string import String

class Editor(
    metaclass=JavaClassDef, jvm_name="android/content/SharedPreferences$Editor"
):
    def __init__(self):
        pass

    @java_method_def(
        name="putString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def putString(self, emu, skey, svalue):
        raise NotImplementedError()

    @java_method_def(name="commit", signature="()Z", native=False)
    def commit(self, emu):
        raise NotImplementedError()


class SharedPreferences(
    metaclass=JavaClassDef, jvm_name="android/content/SharedPreferences"
):
    def __init__(self, emu, path):
        real_path = emu.vfs.translate_path(path)
        self._xml_tree = xml.dom.minidom.parse(real_path)
        self._editor = Editor()
        self._string_values = {}
        root = self._xml_tree.documentElement
        string_node = root.getElementsByTagName("string")

        for node in string_node:
            if node.hasAttribute("name"):
                k = node.getAttribute("name")
                v = str(node.childNodes[0].data)
                self._string_values[k] = String(v)

    @java_method_def(
        name="edit",
        signature="()Landroid/content/SharedPreferences$Editor;",
        native=False,
    )
    def edit(self, emu):
        return self._editor

    @java_method_def(
        name="getString",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        native=False,
    )
    def getString(self, emu, skey, sdefault):
        pyKey = skey.get_py_string()
        if pyKey in self._string_values:
            return self._string_values[pyKey]

        else:
            return sdefault
