import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def

from androidemu.java.classes.string import String


logger = verboselogs.VerboseLogger(__name__)


class BatteryManager(
    metaclass=JavaClassDef,
    jvm_name='android/os/BatteryManager',
    jvm_fields=[
        JavaFieldDef('EXTRA_STATUS', 'Ljava/lang/String;', True, String('status')),
        JavaFieldDef('EXTRA_LEVEL', 'Ljava/lang/String;', True, String('level')),
        JavaFieldDef('EXTRA_SCALE', 'Ljava/lang/String;', True, String('scale')),
        JavaFieldDef('EXTRA_PLUGGED', 'Ljava/lang/String;', True, String('plugged')),
    ]
):
    def __init__(self, iterable):
        self._iter = iterable
        self._next = None

    @java_method_def('hasMoreElements', '()Z', args_list=[])
    def hasMoreElements(self, emu):
        return self._get_next() is not None

    @java_method_def('nextElement', '()Ljava/lang/Object;', args_list=[])
    def nextElement(self, emu):
        return self._get_next()

    def _get_next(self):
        try:
            self._next = next(self._iter)
        except StopIteration:
            self._next = None

        return self._next
