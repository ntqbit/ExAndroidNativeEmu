import androidemu.java.classes.application
import androidemu.java.classes.debug
import androidemu.java.classes.array
import androidemu.java.classes.okhttp
import androidemu.java.classes.asset_manager
import androidemu.java.classes.uri
import androidemu.java.classes.constructor
import androidemu.java.classes.proxy
import androidemu.java.classes.contentresolver
import androidemu.java.classes.system
import androidemu.java.classes.package_manager
import androidemu.java.classes.clazz
import androidemu.java.classes.list
import androidemu.java.classes.environment
import androidemu.java.classes.intent
import androidemu.java.classes.java_set
import androidemu.java.classes.file
import androidemu.java.classes.object
import androidemu.java.classes.executable
import androidemu.java.classes.types
import androidemu.java.classes.shared_preferences
import androidemu.java.classes.dexfile
import androidemu.java.classes.context
import androidemu.java.classes.network_interface
import androidemu.java.classes.method
import androidemu.java.classes.map
import androidemu.java.classes.wifi
import androidemu.java.classes.field
import androidemu.java.classes.string
import androidemu.java.classes.activity_thread
import androidemu.java.classes.settings
import androidemu.java.classes.bundle
import androidemu.java.classes.arrays
import androidemu.java.classes.display
import androidemu.java.classes.security
import androidemu.java.classes.enumeration
import androidemu.java.classes.random
import androidemu.java.classes.exceptions
import androidemu.java.classes.log
import androidemu.java.classes.database
import androidemu.java.classes.sqlite
import androidemu.java.classes.reflect

from .list import List
from .string import String
from .context import Context, ContentResolver, ContextImpl, ContextWrapper
from .array import ByteArray, StringArray, Array, ObjectArray, ClassArray
from .arrays import Arrays
from .file import File


def get_java_classes():
    return [
        androidemu.java.classes.application.Application,
        androidemu.java.classes.debug.Debug,
        androidemu.java.classes.array.Array,
        androidemu.java.classes.array.ByteArray,
        androidemu.java.classes.array.ObjectArray,
        androidemu.java.classes.array.ClassArray,
        androidemu.java.classes.array.StringArray,
        androidemu.java.classes.okhttp.Buffer,
        androidemu.java.classes.okhttp.ResponseBody,
        androidemu.java.classes.okhttp.Builder,
        androidemu.java.classes.okhttp.HttpUrl,
        androidemu.java.classes.okhttp.RequestBody,
        androidemu.java.classes.okhttp.Headers,
        androidemu.java.classes.okhttp.Request,
        androidemu.java.classes.okhttp.Response,
        androidemu.java.classes.okhttp.Chain,
        androidemu.java.classes.asset_manager.AssetManager,
        androidemu.java.classes.uri.Uri,
        androidemu.java.classes.constructor.Constructor,
        androidemu.java.classes.proxy.Proxy,
        androidemu.java.classes.contentresolver.ContentResolver,
        androidemu.java.classes.system.System,
        androidemu.java.classes.package_manager.Signature,
        androidemu.java.classes.package_manager.ApplicationInfo,
        androidemu.java.classes.package_manager.PackageInfo,
        androidemu.java.classes.package_manager.PackageManager,
        androidemu.java.classes.clazz.Class,
        androidemu.java.classes.list.List,
        androidemu.java.classes.environment.Environment,
        androidemu.java.classes.intent.IntentFilter,
        androidemu.java.classes.intent.Intent,
        androidemu.java.classes.java_set.Set,
        androidemu.java.classes.file.File,
        androidemu.java.classes.object.Object,
        androidemu.java.classes.executable.Executable,
        androidemu.java.classes.types.Boolean,
        androidemu.java.classes.types.Integer,
        androidemu.java.classes.types.Long,
        androidemu.java.classes.types.Float,
        androidemu.java.classes.shared_preferences.Editor,
        androidemu.java.classes.shared_preferences.SharedPreferences,
        androidemu.java.classes.dexfile.DexFile,
        androidemu.java.classes.context.Context,
        androidemu.java.classes.context.ContextImpl,
        androidemu.java.classes.context.ContextWrapper,
        androidemu.java.classes.context.ComponentName,
        androidemu.java.classes.network_interface.NetworkInterface,
        androidemu.java.classes.method.Method,
        androidemu.java.classes.map.HashMap,
        androidemu.java.classes.wifi.WifiInfo,
        androidemu.java.classes.wifi.WifiConfiguration,
        androidemu.java.classes.wifi.DhcpInfo,
        androidemu.java.classes.wifi.WifiManager,
        androidemu.java.classes.wifi.TelephonyManager,
        androidemu.java.classes.wifi.RequestBuilder,
        androidemu.java.classes.wifi.NetworkInfo,
        androidemu.java.classes.wifi.ConnectivityManager,
        androidemu.java.classes.field.AccessibleObject,
        androidemu.java.classes.field.Field,
        androidemu.java.classes.string.String,
        androidemu.java.classes.string.StringBuilder,
        androidemu.java.classes.activity_thread.AccessibilityManager,
        androidemu.java.classes.activity_thread.AccessibilityInteractionController,
        androidemu.java.classes.activity_thread.Window,
        androidemu.java.classes.activity_thread.ViewRootImpl,
        androidemu.java.classes.activity_thread.AttachInfo,
        androidemu.java.classes.activity_thread.View,
        androidemu.java.classes.activity_thread.Activity,
        androidemu.java.classes.activity_thread.ActivityClientRecord,
        androidemu.java.classes.activity_thread.ArrayMap,
        androidemu.java.classes.activity_thread.ActivityManager,
        androidemu.java.classes.activity_thread.IActivityManager,
        androidemu.java.classes.activity_thread.ActivityManagerNative,
        androidemu.java.classes.activity_thread.Instrumentation,
        androidemu.java.classes.activity_thread.IInterface,
        androidemu.java.classes.activity_thread.IPackageManager,
        androidemu.java.classes.activity_thread.ActivityThread,
        androidemu.java.classes.settings.Secure,
        androidemu.java.classes.settings.Settings,
        androidemu.java.classes.bundle.Bundle,
        androidemu.java.classes.arrays.Arrays,
        androidemu.java.classes.display.DisplayManager,
        androidemu.java.classes.display.Display,
        androidemu.java.classes.security.KeyStore,
        androidemu.java.classes.security.KeyProperties,
        androidemu.java.classes.security.ECGenParameterSpec,
        androidemu.java.classes.security.KeyGenParameterSpec,
        androidemu.java.classes.security.KeyGenParameterSpec_Builder,
        androidemu.java.classes.security.KeyPairGenerator,
        androidemu.java.classes.security.KeyPair,
        androidemu.java.classes.enumeration.Enumeration,
        androidemu.java.classes.random.Random,
        androidemu.java.classes.exceptions.Throwable,
        androidemu.java.classes.exceptions.Exception,
        androidemu.java.classes.exceptions.RuntimeException,
        androidemu.java.classes.exceptions.UnsupportedOperationException,
        androidemu.java.classes.exceptions.KeyStoreException,
        androidemu.java.classes.log.Log,
        androidemu.java.classes.sqlite.SQLiteDatabase,
        androidemu.java.classes.sqlite.SQLiteDatabase_CursorFactory,
        androidemu.java.classes.sqlite.SQLiteCursor,
        androidemu.java.classes.database.Cursor,
        androidemu.java.classes.reflect.Modifier,
    ]
