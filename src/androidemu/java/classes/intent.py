from androidemu.java.classes.bundle import Bundle
from androidemu.java import JavaClassDef, java_method_def, JavaFieldDef

from androidemu.java.classes.string import String
from androidemu.java.classes.array import ByteArray

BATTERY_STATUS_UNKNOWN = 1
BATTERY_STATUS_CHARGING = 2
BATTERY_STATUS_DISCHARGING = 3
BATTERY_STATUS_NOT_CHARGING = 4
BATTERY_STATUS_FULL = 5


class IntentFilter(
    metaclass=JavaClassDef, jvm_name="android/content/IntentFilter"
):
    def __init__(self):
        self._action = None

    def get_action(self):
        return self._action

    @java_method_def(
        name="<init>",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)V",
        native=False,
    )
    def ctor(self, emu, action):
        self._action = action


class Intent(
        metaclass=JavaClassDef,
        jvm_name="android/content/Intent",
        jvm_fields=[
            JavaFieldDef('ACTION_BATTERY_CHANGED', 'Ljava/lang/String;', True,
                         String('android.intent.action.BATTERY_CHANGED'))
        ]
):
    def __init__(self, intent_filter: IntentFilter = None):
        self._action = None
        self._package_name = None
        self._intent_filter = intent_filter
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

    @java_method_def('getIntExtra', '(Ljava/lang/String;I)I', args_list=['jstring', 'jint'])
    def getIntExtra(self, emu, name, default_value):
        if self._intent_filter:
            action = self._intent_filter.get_action()
            if action == 'android.intent.action.BATTERY_CHANGED':
                if name == 'level':
                    # TODO: do not hard code
                    return 84
                elif name == 'scale':
                    return 100
                elif name == 'status':
                    return BATTERY_STATUS_DISCHARGING
                elif name == 'plugged':
                    return 0

        return default_value
