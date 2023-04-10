import verboselogs

from androidemu.java import JavaClassDef, JavaFieldDef, java_method_def

from androidemu.java.classes.string import String

logger = verboselogs.VerboseLogger(__name__)


class Throwable(metaclass=JavaClassDef, jvm_name='java/lang/Throwable'):
    def __init__(self, msg: str = None):
        self._msg = msg

    @java_method_def('getMessage', '()Ljava/lang/String;')
    def getMessage(self, emu):
        return String(self._msg)

    @java_method_def('getCause', '()Ljava/lang/Throwable;')
    def getCause(self, emu):
        return self

    @java_method_def('toString', '()Ljava/lang/String;')
    def toString(self, emu):
        s = self.__class__.__name__

        if self._msg:
            return String(f'{s}: {self._msg}')
        else:
            return String(s)


class Exception(Throwable,
                metaclass=JavaClassDef,
                jvm_name='java/lang/Exception'):
    def __init__(self, msg: str = None):
        super().__init__(msg)


class RuntimeException(Exception,
                       metaclass=JavaClassDef,
                       jvm_name='java/lang/RuntimeException'):
    def __init__(self, msg: str = None):
        super().__init__(msg)


class UnsupportedOperationException(RuntimeException,
                                    metaclass=JavaClassDef,
                                    jvm_name='java/lang/UnsupportedOperationException'):
    def __init__(self, msg: str = None):
        super().__init__(msg)


class KeyStoreException(RuntimeException,
                        metaclass=JavaClassDef,
                        jvm_name='android/security/KeyStoreException'):
    def __init__(self, msg: str = None):
        super().__init__(msg)
