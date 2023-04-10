import time
import verboselogs

from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def
from androidemu.java.classes.string import String
from androidemu.java.classes.array import ObjectArray, ByteArray

logger = verboselogs.VerboseLogger(__name__)


class Signature(metaclass=JavaClassDef, jvm_name="android/content/pm/Signature"):
    def __init__(self, signature: bytes):
        self._signature = signature

    def __repr__(self):
        return f"Signature(sign={self._signature.hex()})"

    @java_method_def(name="toByteArray", signature="()[B", native=False)
    def toByteArray(self, emu):
        return ByteArray(self._signature)

    @java_method_def(
        name="toCharsString", signature="()Ljava/lang/String;", native=False
    )
    def toCharsString(self, emu):
        return String(self._signature.hex())


class ApplicationInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/ApplicationInfo",
    jvm_fields=[
        JavaFieldDef("sourceDir", "Ljava/lang/String;"),
        JavaFieldDef("dataDir", "Ljava/lang/String;"),
        JavaFieldDef("nativeLibraryDir", "Ljava/lang/String;"),
        JavaFieldDef("flags", "I"),
    ],
):
    def __init__(self, package_name, flags):
        self._package_name = package_name
        self.sourceDir = String("/data/app/%s-1.apk" % package_name)
        self.dataDir = String("/data/data/%s" % package_name)
        self.nativeLibraryDir = String("/data/data/%s" % package_name)
        self.flags = flags

    def __repr__(self):
        return f'ApplicationInfo(package_name={self._package_name},flags={self.flags})'


class PackageInfo(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/PackageInfo",
    jvm_fields=[
        JavaFieldDef("packageName", "Ljava/lang/String;"),
        JavaFieldDef("applicationInfo", "Landroid/content/pm/ApplicationInfo;"),
        JavaFieldDef("firstInstallTime", "J"),
        JavaFieldDef("lastUpdateTime", "J"),
        JavaFieldDef("signatures", "[Landroid/content/pm/Signature;"),
        JavaFieldDef("versionCode", "I"),
    ],
):
    def __init__(self, package_name, signatures, version_code, flags):
        self.packageName = package_name
        self.applicationInfo = ApplicationInfo(package_name, flags)
        self.firstInstallTime = int(time.time())
        self.lastUpdateTime = self.firstInstallTime
        self.versionCode = version_code

        self.signatures = ObjectArray([Signature(sign) for sign in signatures])

    def __repr__(self):
        return f'PackageInfo(package_name={self.packageName})'


class PackageManager(
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/PackageManager",
    jvm_fields=[
        JavaFieldDef("GET_SIGNATURES", "I", True, 64),
        JavaFieldDef('FEATURE_STRONGBOX_KEYSTORE', 'Ljava/lang/String;',
                     True, String('android.hardware.strongbox_keystore'))
    ],
):
    GET_SIGNATURES = 64
    ALL_FLAGS = GET_SIGNATURES

    def __init__(self):
        pass

    @java_method_def(
        name="getPackageInfo",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        native=False,
    )
    def getPackageInfo(self, emu, package_name: String, flags):
        package = self._get_package(emu, package_name.get_py_string())

        if flags & ~PackageManager.ALL_FLAGS:
            raise RuntimeError(f'Invalid flags to getPackageInfo: {flags}')

        sign_hex = []

        if flags & PackageManager.GET_SIGNATURES:
            sign_hex = [sign.getBytes() for sign in package.get_signatures()]

        version_code = package.get_version_code()

        return PackageInfo(package_name, sign_hex, version_code, flags)

    @java_method_def('getInstallerPackageName', '(Ljava/lang/String;)Ljava/lang/String;', args_list=['jstring'])
    def getInstallerPackageName(self, emu, package_name: String):
        package = self._get_package(emu, package_name.get_py_string())
        return String(package.get_installer_package_name())

    @java_method_def('hasSystemFeature', '(Ljava/lang/String;)Z', args_list=['jstring'])
    def hasSystemFeature(self, emu, feature_name: String):
        return False

    @java_method_def(
        name="checkPermission",
        args_list=["jstring", "jstring"],
        signature="(Ljava/lang/String;Ljava/lang/String;)I",
        native=False,
    )
    def checkPermission(self, *args, **kwargs):
        logger.debug('Checking permission')
        return 0

    def _get_package(self, emu, package_name: str):
        package = emu.environment.find_package_by_name(package_name)
        if not package:
            raise RuntimeError(f'Package {package_name} not found.')
        return package
