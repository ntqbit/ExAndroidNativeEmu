from androidemu.java.classes.bundle import Bundle
from androidemu.java import JavaClassDef, java_method_def

from androidemu.java.classes.string import String
from androidemu.java.classes.array import ByteArray


class IntentFilter(
    metaclass=JavaClassDef, jvm_name="android/content/IntentFilter"
):
    def __init__(self):
        pass

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def init(self, emu, str):
        pass


class Intent(metaclass=JavaClassDef, jvm_name="android/content/Intent"):
    def __init__(self):
        self._action = None
        self._package_name = None
        self._extra = {}

    @java_method_def('<init>', '(Ljava/lang/String;)V', args_list=['jstring'])
    def ctor(self, emu, action: String):
        self._action = action

    @java_method_def('setPackage', '(Ljava/lang/String;)Landroid/content/Intent;', args_list=['jstring'])
    def setPackage(self, emu, package_name: String):
        self._package_name = package_name.get_py_string()
        return self

    @java_method_def('putExtra', '(Ljava/lang/String;[B)Landroid/content/Intent;', args_list=['jstring', 'jobject'])
    def putExtra(self, emu, name: String, value: ByteArray):
        self._extra[name.get_py_string()] = value.get_py_items()
        return self

    @java_method_def(
        name="getExtras", signature="()Landroid/os/Bundle;", native=False
    )
    def getExtras(self, emu):
        return Bundle()
