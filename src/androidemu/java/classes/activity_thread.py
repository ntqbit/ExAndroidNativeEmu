from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def
from androidemu.java.classes.context import ContextImpl
from androidemu.java.const import *
from androidemu.java.classes.application import Application


class AccessibilityManager(
    metaclass=JavaClassDef,
    jvm_name="android/view/accessibility/AccessibilityManager",
):
    def __init__(self):
        pass

    @java_method_def(
        name="getEnabledAccessibilityServiceList",
        args_list=["jint"],
        signature="(I)Ljava/util/List;",
        native=False,
    )
    def getEnabledAccessibilityServiceList(self, emu, i):
        raise NotImplementedError()


class AccessibilityInteractionController(
    metaclass=JavaClassDef,
    jvm_name="android/view/AccessibilityInteractionController",
):
    def __init__(self):
        pass


class Window(metaclass=JavaClassDef, jvm_name="android/view/Window"):
    def __init__(self):
        self._dec_view = View()

    @java_method_def(
        name="getDecorView", signature="()Landroid/view/View;", native=False
    )
    def getDecorView(self, emu):
        return self._dec_view


class ViewRootImpl(
    metaclass=JavaClassDef,
    jvm_name="android/view/ViewRootImpl",
    jvm_fields=[
        JavaFieldDef(
            "mAccessibilityInteractionController",
            "android/view/AccessibilityInteractionController"
        )
    ],
):
    def __init__(self):
        self.mAccessibilityInteractionController = (
            AccessibilityInteractionController()
        )


class AttachInfo(
    metaclass=JavaClassDef,
    jvm_name="android/view/View$AttachInfo",
    jvm_fields=[
        JavaFieldDef("mViewRootImpl", "android/view/ViewRootImpl")
    ],
):
    def __init__(self, view_root_impl):
        self.mViewRootImpl = view_root_impl


class View(
    metaclass=JavaClassDef,
    jvm_name="android/view/View",
    jvm_fields=[JavaFieldDef("", "android/view/View$AttachInfo")],
):
    def __init__(self):
        self.mAttachInfo = AttachInfo(ViewRootImpl())


class Activity(metaclass=JavaClassDef, jvm_name="android/app/Activity"):
    def __init__(self):
        self._window = Window()

    @java_method_def(
        name="getWindow", signature="()Landroid/view/Window;", native=False
    )
    def getWindow(self, emu):
        return self._window

    # 这应该是Context的方法

    @java_method_def(
        name="getSystemService",
        signature="(Ljava/lang/String;)Ljava/lang/Object;",
        native=False,
    )
    def getSystemService(self, emu):
        raise NotImplementedError()


class ActivityClientRecord(
    metaclass=JavaClassDef,
    jvm_name="android/app/ActivityThread$ActivityClientRecord",
    jvm_fields=[
        JavaFieldDef("paused", "Z"),
        JavaFieldDef("activity", "Landroid/app/Activity;"),
    ],
):
    def __init__(self):
        self.paused = False
        self.activity = Activity()


class ArrayMap(metaclass=JavaClassDef, jvm_name="android/util/ArrayMap"):
    def __init__(self, arr):
        self._array = arr

    @java_method_def(name="size", signature="()I", native=False)
    def size(self, emu):
        return len(self._array)

    @java_method_def(
        name="valueAt",
        args_list=["jint"],
        signature="(I)Ljava/lang/Object;",
        native=False,
    )
    def valueAt(self, emu, id):
        return self._array[id]


class ActivityManager(
    metaclass=JavaClassDef, jvm_name="android/app/ActivityManager"
):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(name="isUserAMonkey", signature="()Z", native=False)
    def isUserAMonkey(emu):
        return False


class IActivityManager(
    metaclass=JavaClassDef, jvm_name="android/app/IActivityManager"
):
    def __init__(self):
        pass


class ActivityManagerNative(
    metaclass=JavaClassDef, jvm_name="android/app/ActivityManagerNative"
):
    def __init__(self):
        pass

    @staticmethod
    @java_method_def(
        name="getDefault",
        signature="()android/app/IActivityManager;",
        native=False,
    )
    def getDefault(emu):
        return IActivityManager()


class Instrumentation(
    metaclass=JavaClassDef, jvm_name="android/app/Instrumentation"
):
    def __init__(self):
        pass


class IInterface(metaclass=JavaClassDef, jvm_name="android/os/IInterface"):
    def __init__(self):
        pass


class IPackageManager(
    IInterface,
    metaclass=JavaClassDef,
    jvm_name="android/content/pm/IPackageManager",
    jvm_super=IInterface,
):
    def __init__(self):
        pass


class ActivityThread(
    metaclass=JavaClassDef,
    jvm_name="android/app/ActivityThread",
    jvm_fields=[
        JavaFieldDef("mActivities", "Landroid/util/ArrayMap;"),
        JavaFieldDef(
            "sPackageManager",
            "Landroid/content/pm/IPackageManager;",
            True,
            IPackageManager(),
        ),
    ],
):

    s_am = {}

    def __init__(self, package_name):
        self._ctx_impl = ContextImpl(package_name)
        self.app = Application()
        self.app.attachBaseContext(self._ctx_impl)
        self.mActivities = ArrayMap([ActivityClientRecord()])
        self.mInstrumentation = Instrumentation()
        # self.mActivities = ArrayMap([])

    @staticmethod
    @java_method_def(
        name="currentActivityThread",
        signature="()Landroid/app/ActivityThread;",
        native=False,
    )
    def currentActivityThread(emu: 'Emulator'):
        package_name = emu.environment.get_process_name()
        if package_name not in ActivityThread.s_am:
            ActivityThread.s_am[package_name] = ActivityThread(package_name)

        return ActivityThread.s_am[package_name]

    @staticmethod
    @java_method_def(
        name="currentApplication",
        signature="()Landroid/app/Application;",
        native=False,
    )
    def currentApplication(emu):
        am = ActivityThread.currentActivityThread(emu)
        return am.app

    @java_method_def(
        name="getSystemContext",
        signature="()Landroid/app/ContextImpl;",
        native=False,
    )
    def getSystemContext(self, emu):
        return self._ctx_impl
