from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def


STATE_UNKNOWN = 0
STATE_OFF = 1
STATE_ON = 2
STATE_DOZE = 3
STATE_DOZE_SUSPEND = 4
STATE_VR = 5
STATE_ON_SUSPEND = 6


class Display(metaclass=JavaClassDef, jvm_name='android/view/Display',
              jvm_fields=[
                  JavaFieldDef('DEFAULT_DISPLAY', 'I', True, 0),
                  JavaFieldDef('STATE_UNKNOWN', 'I', True, STATE_UNKNOWN),
                  JavaFieldDef('STATE_OFF', 'I', True, STATE_OFF),
                  JavaFieldDef('STATE_ON', 'I', True, STATE_ON),
                  JavaFieldDef('STATE_DOZE', 'I', True, STATE_DOZE),
                  JavaFieldDef('STATE_DOZE_SUSPEND', 'I', True, STATE_DOZE_SUSPEND),
                  JavaFieldDef('STATE_VR', 'I', True, STATE_VR),
                  JavaFieldDef('STATE_ON_SUSPEND', 'I', True, STATE_ON_SUSPEND)
              ]):
    def __init__(self, display_id):
        self._display_id = display_id

    @java_method_def('getState', '()I')
    def getState(self, emu):
        return STATE_ON


class DisplayManager(metaclass=JavaClassDef, jvm_name="android/hardware/display/DisplayManager"):
    def __init__(self):
        pass

    @java_method_def('getDisplay', '(I)Landroid/view/Display;', args_list=['jint'])
    def getDisplay(self, emu, display_id):
        return Display(display_id)
