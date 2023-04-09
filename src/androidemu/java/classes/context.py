from androidemu import config
from androidemu.java.classes.file import File
from androidemu.java.classes.string import String
from androidemu.java.classes.contentresolver import ContentResolver
from androidemu.java.classes.wifi import (
    TelephonyManager,
    WifiManager,
    ConnectivityManager,
)
from androidemu.java.classes.shared_preferences import *
from androidemu.java.classes.asset_manager import *
from androidemu.java.classes.package_manager import *
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef


class Context(
    metaclass=JavaClassDef,
    jvm_name="android/content/Context",
    jvm_fields=[
        JavaFieldDef(
            "WIFI_SERVICE", "Ljava/lang/String;", True, String("wifi")
        ),
        JavaFieldDef(
            "TELEPHONY_SERVICE", "Ljava/lang/String;", True, String("phone")
        ),
        JavaFieldDef(
            "CONNECTIVITY_SERVICE",
            "Ljava/lang/String;",
            True,
            String("connectivity"),
        ),
    ],
):
    def __init__(self):
        pass

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getFilesDir", signature="()Ljava/io/File;", native=False
    )
    def getFilesDir(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getCacheDir", signature="()Ljava/io/File;", native=False
    )
    def getCacheDir(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        raise RuntimeError("pure virtual function call")

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        raise RuntimeError("pure virtual function call")


class ContextImpl(
    Context,
    metaclass=JavaClassDef,
    jvm_name="android/app/ContextImpl",
    jvm_super=Context,
):
    def __init__(self, package_name):
        Context.__init__(self)

        self._package_name = String(package_name)
        self._package_manager = PackageManager()
        self._content_resolver = ContentResolver()
        self._asset_mgr = None
        self._sp_map = {}

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        return self._package_manager

    @java_method_def(
        name="getAssets",
        signature="()Landroid/content/res/AssetManager;",
        native=False,
    )
    def getAssets(self, emu):
        if not self._asset_mgr:
            # 调用getAssets才初始化assert_manager
            # 因为不是每个so模拟执行都需要打开apk
            pyapk_path = self._package_manager.getPackageInfo(
                emu, self._package_name, 0
            ).applicationInfo.sourceDir.get_py_string()
            self._asset_mgr = AssetManager(emu, pyapk_path)

        return self._asset_mgr

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        return self._content_resolver

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        print(s1)
        stype = s1.get_py_string()
        if stype == "phone":
            return TelephonyManager()

        elif stype == "wifi":
            return WifiManager()

        elif stype == "connectivity":
            return ConnectivityManager()

        raise NotImplementedError()

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        pkgMgr = self._package_manager
        pkgInfo = pkgMgr.getPackageInfo(emu, self._package_name, 0)
        return pkgInfo.applicationInfo

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        return self._package_name

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        return 0  # PERMISSION_GRANTED

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        return 0  # PERMISSION_GRANTED

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        pkgName = emu.environment.get_package_name()
        path = "/data/app/%s-1.apk" % (pkgName,)
        return String(path)

    @java_method_def(
        name="getFilesDir", signature="()Ljava/io/File;", native=False
    )
    def getFilesDir(self, emu):
        pkgName = emu.environment.get_package_name()
        fdir = "/data/data/%s/files" % (pkgName,)
        return File(fdir)

    @java_method_def(
        name="getCacheDir", signature="()Ljava/io/File;", native=False
    )
    def getCacheDir(self, emu):
        pkgName = emu.environment.get_package_name()
        return File("/data/user/0/%s/cache" % pkgName)

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        pkgName = emu.environment.get_package_name()
        pyName = name.get_py_string()
        if pyName in self._sp_map:
            return self._sp_map[pyName]

        else:
            path = "/data/data/%s/shared_prefs/%s.xml" % (pkgName, pyName)
            sp = SharedPreferences(emu, path)
            self._sp_map[pyName] = sp
            return sp


class ContextWrapper(
    Context,
    metaclass=JavaClassDef,
    jvm_name="android/content/ContextWrapper",
    jvm_super=Context,
):
    def __init__(self):
        Context.__init__(self)
        self._impl = None

    def attachBaseContext(self, ctx_impl):
        self._impl = ctx_impl

    @java_method_def(
        name="getPackageManager",
        signature="()Landroid/content/pm/PackageManager;",
        native=False,
    )
    def getPackageManager(self, emu):
        return self._impl.getPackageManager(emu)

    @java_method_def(
        name="getAssets",
        signature="()Landroid/content/res/AssetManager;",
        native=False,
    )
    def getAssets(self, emu):
        return self._impl.getAssets(emu)

    @java_method_def(
        name="getContentResolver",
        signature="()Landroid/content/ContentResolver;",
        native=False,
    )
    def getContentResolver(self, emu):
        return self._impl.getContentResolver(emu)

    @java_method_def(
        name="getSystemService",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu, s1):
        return self._impl.getSystemService(emu, s1)

    @java_method_def(
        name="getApplicationInfo",
        signature="()Landroid/content/pm/ApplicationInfo;",
        native=False,
    )
    def getApplicationInfo(self, emu):
        return self._impl.getApplicationInfo(emu)

    @java_method_def(
        name="getPackageName", signature="()Ljava/lang/String;", native=False
    )
    def getPackageName(self, emu):
        return self._impl.getPackageName(emu)

    @java_method_def(
        name="checkSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkSelfPermission(self, emu):
        return self._impl.checkSelfPermission(emu)

    @java_method_def(
        name="checkCallingOrSelfPermission",
        signature="(Ljava/lang/String;)I",
        native=False,
    )
    def checkCallingOrSelfPermission(self, emu):
        return self._impl.checkCallingOrSelfPermission(emu)

    @java_method_def(
        name="getPackageCodePath",
        signature="()Ljava/lang/String;",
        native=False,
    )
    def getPackageCodePath(self, emu):
        return self._impl.getPackageCodePath(emu)

    @java_method_def(
        name="getFilesDir", signature="()Ljava/io/File;", native=False
    )
    def getFilesDir(self, emu):
        return self._impl.getFilesDir(emu)

    @java_method_def(
        name="getCacheDir", signature="()Ljava/io/File;", native=False
    )
    def getCacheDir(self, emu):
        return self._impl.getCacheDir(emu)

    @java_method_def(
        name="getSharedPreferences",
        args_list=["jstring", "jint"],
        signature="(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        native=False,
    )
    def getSharedPreferences(self, emu, name, mode):
        return self._impl.getSharedPreferences(emu, name, mode)
