from androidemu.java.classes.activity_thread import (
    ActivityThread,
    ActivityManagerNative,
)
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *
from androidemu.java.classes.string import *
from androidemu.java.classes.method import *
from androidemu.java.classes.field import *

import io


class Class(metaclass=JavaClassDef, jvm_name="java/lang/Class"):
    _basic_types = ["Z", "B", "C", "D", "F", "I", "J", "S"]

    def __init__(self, pyclazz, class_loader):
        self.class_loader = class_loader
        self._pyclazz = pyclazz
        self._descriptor_represent = pyclazz.jvm_name

    def __repr__(self):
        return f"Class({self._descriptor_represent})"

    @java_method_def(
        name="getClassLoader",
        signature="()Ljava/lang/ClassLoader;",
        native=False,
    )
    def getClassLoader(self, emu):
        return self.class_loader

    @staticmethod
    @java_method_def(
        name="forName",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/Class;",
        native=False,
    )
    def forName(emu, name):
        clz_name = name.get_py_string()
        if clz_name == "android.app.ActivityThread":
            return Class(ActivityThread, emu.java_classloader)
        elif clz_name == "android.app.ActivityManagerNative":
            return Class(ActivityManagerNative, emu.java_classloader)
        else:
            raise NotImplementedError()

    # FIXME -

    @java_method_def(
        name="getMethod",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        native=False,
    )
    def getMethod(self, emu, name, parameterTypes):
        return self.getDeclaredMethod(emu, name, parameterTypes)

    @java_method_def(
        name="getName", signature="()Ljava/lang/String;", native=False
    )
    def getName(self, emu):
        name = self._descriptor_represent
        assert name is not None

        name = name.replace("/", ".")
        return String(name)

    @java_method_def(
        name="getCanonicalName", signature="()Ljava/lang/String;", native=False
    )
    def getCanonicalName(self, emu):
        name = self.getName(emu).get_py_string()

        if name[0] == "[":
            dims = 0
            for ch in name:
                if ch == "[":
                    dims += 1

                else:
                    break

            # 去除[
            name = name[dims:]
            if name[0] == "L":
                # 去除类型前的L
                name = name[1:]

            for i in range(dims):
                name = name + "[]"

        # $->.
        name = name.replace("$", ".")
        return String(name)

    def get_jni_descriptor(self):
        return self._descriptor_represent

    def get_py_clazz(self):
        return self._pyclazz

    @java_method_def(
        name="getDeclaredField",
        args_list=["jstring"],
        signature="(Ljava/lang/String;)Ljava/lang/reflect/Field;",
        native=False,
    )
    def getDeclaredField(self, emu, name):
        logger.debug("getDeclaredField %s" % name)
        reflected_field = Field(self._pyclazz, name.get_py_string())
        return reflected_field

    @java_method_def(
        name="getDeclaredMethod",
        args_list=["jstring", "jobject"],
        signature="(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        native=False,
    )
    def getDeclaredMethod(self, emu, name, parameterTypes):
        logger.debug(
            "getDeclaredMethod name:[%r] parameterTypes:[%r]"
            % (name, parameterTypes)
        )
        sbuf = io.StringIO()
        sbuf.write("(")
        for item in parameterTypes:
            desc = item.get_jni_descriptor()
            if desc[0] == "[" or desc in Class._basic_types:
                sbuf.write(desc)

            else:
                sbuf.write("L")
                sbuf.write(desc)
                sbuf.write(";")

        sbuf.write(")")

        signature_no_ret = sbuf.getvalue()
        pyname = name.get_py_string()
        pymethod = self._pyclazz.find_method_sig_with_no_ret(
            pyname, signature_no_ret
        )
        if pymethod is None:
            assert False, "getDeclaredMethod not found..."
            return JAVA_NULL

        reflected_method = Method(self._pyclazz, pymethod)
        logger.debug("getDeclaredMethod return %r" % reflected_method)
        return reflected_method
