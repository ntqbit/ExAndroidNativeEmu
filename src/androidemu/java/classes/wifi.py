from androidemu.java import JavaClassDef, java_method_def, JavaFieldDef
from androidemu.java.classes.list import List
from androidemu.java.classes.string import String


class WifiInfo(metaclass=JavaClassDef, jvm_name="android/net/wifi/WifiInfo"):
    def __init__(self):
        pass

    @java_method_def(
        name="getMacAddress", signature="()Ljava/lang/String;", native=False
    )
    def getMacAddress(self, emu, *args, **kwargs):
        # TODO read from config
        mac = emu.config.get("mac")
        s = "%02x:%02x:%02x:%02x:%02x:%02x" % (
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5],
        )
        return String(s)

    @java_method_def(
        name="getBSSID", signature="()Ljava/lang/String;", native=False
    )
    def getBSSID(self, *args, **kwargs):
        # TODO 从WifiConfiguration 获取
        return String("")

    @java_method_def(
        name="getSSID", signature="()Ljava/lang/String;", native=False
    )
    def getSSID(self, *args, **kwargs):
        # TODO 从WifiConfiguration 获取
        return String("")


class WifiConfiguration(
    metaclass=JavaClassDef,
    jvm_name="android/net/wifi/WifiConfiguration",
    jvm_fields=[
        JavaFieldDef("SSID", "Ljava/lang/String;"),
        JavaFieldDef("hiddenSSID", "Z"),
        JavaFieldDef("BSSID", "Ljava/lang/String;"),
        JavaFieldDef("FQDN", "Ljava/lang/String;"),
        JavaFieldDef("networkId", "I"),
        JavaFieldDef("priority", "I"),
        JavaFieldDef("providerFriendlyName", "Ljava/lang/String;"),
    ],
):
    def __init__(self):
        self.SSID = String("")
        self.BSSID = String("")
        self.FQDN = String("")
        self.hiddenSSID = False
        self.networkId = 0
        self.priority = 0
        self.providerFriendlyName = String("hello")


class DhcpInfo(
    metaclass=JavaClassDef,
    jvm_name="android/net/DhcpInfo",
    jvm_fields=[
        JavaFieldDef("gateway", "I", False),
    ],
):
    def __init__(self):
        self.gateway = 0


class WifiManager(
    metaclass=JavaClassDef, jvm_name="android/net/wifi/WifiManager"
):
    def __init__(self):
        self._list = List([])
        self._dhcpInfo = DhcpInfo()

    @java_method_def(
        name="getConfiguredNetworks",
        signature="()Ljava/util/List;",
        native=False,
    )
    def getConfiguredNetworks(self, emu):
        return self._list

    @java_method_def(
        name="getDhcpInfo", signature="()Landroid/net/DhcpInfo;", native=False
    )
    def getDhcpInfo(self, emu):
        return self._dhcpInfo

    @java_method_def(
        name="getDeviceId", signature="()Ljava/lang/String;", native=False
    )
    def getDeviceId(self, *args, **kwargs):
        # TODO read from config
        return String("12345678")

    @java_method_def(
        name="getSubscriberId", signature="()Ljava/lang/String;", native=False
    )
    def getSubscriberId(self, *args, **kwargs):
        # TODO read from config
        return String("12345678")

    @java_method_def(
        name="getConnectionInfo",
        signature="()Landroid/net/wifi/WifiInfo;",
        native=False,
    )
    def getConnectionInfo(self, *args, **kwargs):
        # TODO read from config
        return WifiInfo()

    @java_method_def(
        name="getActiveNetworkInfo",
        signature="()Landroid/net/NetworkInfo;",
        native=False,
    )
    def getActiveNetworkInfo(self, *args, **kwargs):
        # TODO read from config
        return NetworkInfo()


class TelephonyManager(
    metaclass=JavaClassDef, jvm_name="android/telephony/TelephonyManager"
):
    def __init__(self):
        pass

    @java_method_def(
        name="getDeviceId", signature="()Ljava/lang/String;", native=False
    )
    def getDeviceId(self, *args, **kwargs):
        # IMEI
        # FIXME 读配置文件
        imei = "353627071193539"
        return String(imei)

    @java_method_def(
        name="getSubscriberId", signature="()Ljava/lang/String;", native=False
    )
    def getSubscriberId(self, *args, **kwargs):
        # IMEI
        # FIXME 读配置文件
        imsi = "00000000000000"
        return String(imsi)


class RequestBuilder(
    metaclass=JavaClassDef, jvm_name="android/net/NetworkRequest$Builder"
):
    def __init__(self):
        pass

    @java_method_def(name="<init>", signature="()V", native=False)
    def init(self, *args, **kwargs):
        return RequestBuilder()

    @java_method_def(
        name="addTransportType",
        signature="(I)Landroid/net/NetworkRequest$Builder;",
        native=False,
    )
    def addTransportType(self, emu, i):
        raise NotImplementedError()
        #return RequestBuilder()


class NetworkInfo(metaclass=JavaClassDef, jvm_name="android/net/NetworkInfo"):
    def __init__(self):
        pass


class ConnectivityManager(
    metaclass=JavaClassDef, jvm_name="android/net/ConnectivityManager"
):
    def __init__(self):
        pass

    @java_method_def(
        name="getActiveNetworkInfo",
        signature="()Landroid/net/NetworkInfo;",
        native=False,
    )
    def getActiveNetworkInfo(self, *args, **kwargs):
        return NetworkInfo()
