from androidemu.java import JavaClassDef, java_method_def
from androidemu.java.classes.array import Array


class NetworkInterface(
    metaclass=JavaClassDef, jvm_name="java/net/NetworkInterface"
):
    def __init__(self, pyname):
        self._name = pyname

    @staticmethod
    @java_method_def(
        name="getByName",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/net/NetworkInterface;",
        native=False,
    )
    def getByName(emu, s1):
        pyname = s1.get_py_string()
        return NetworkInterface(pyname)

    @java_method_def(name="getHardwareAddress", signature="()[B", native=False)
    def getHardwareAddress(self, emu):
        mac = emu.environment.get_mac_address()
        barr = bytearray(mac)
        arr = Array(barr)
        return arr
