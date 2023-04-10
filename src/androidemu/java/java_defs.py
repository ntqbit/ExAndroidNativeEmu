import inspect
import sys

import verboselogs

from androidemu.java.jvm_id_counter import (
    next_cls_id,
    next_field_id,
    next_method_id
)
from androidemu.java.jni_ref import jobject, jclass
from androidemu.const.emu_const import Arch
from androidemu.java.const import JAVA_NULL

logger = verboselogs.VerboseLogger(__name__)


class JavaClassDef(type):
    def __init__(
        cls,
        name,
        base,
        ns,
        jvm_name=None,
        jvm_fields=None,
        jvm_ignore=False,
        jvm_super=None,
    ):
        cls.jvm_id = next_cls_id()
        cls.jvm_name = jvm_name
        cls.jvm_methods = dict()
        cls.jvm_fields = dict()
        cls.jvm_ignore = jvm_ignore
        cls.jvm_super = jvm_super
        cls.class_object = java_method_def('getClass', '()Ljava/lang/Class;')(JavaClassDef._getClass)

        # Register all defined Java methods.
        for func in inspect.getmembers(cls, predicate=inspect.isfunction):
            if hasattr(func[1], "jvm_method"):
                method = func[1].jvm_method
                cls.jvm_methods[method.jvm_id] = method

        # Register all defined Java fields.
        if jvm_fields is not None:
            for jvm_field in jvm_fields:
                cls.jvm_fields[jvm_field.jvm_id] = jvm_field

        type.__init__(cls, name, base, ns)

    def __new__(cls, name, base, ns, **kargs):
        return type.__new__(cls, name, base, ns)

    def _getClass(self, emu):
        return self.class_object

    def register_native(cls, name, signature, ptr_func):
        found = False
        found_method = None

        # Search for a defined jvm method.
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                method.native_addr = ptr_func
                found = True
                found_method = method
                break

        if not found:
            x = (
                "Register native ('%s', '%s', '0x%08X') failed on class %s."
                % (name, signature, ptr_func, cls.__name__)
            )
            logger.warning(x)
            return
            # raise RuntimeError("Register native ('%s', '%s') failed on class %s." % (name, signature, cls.__name__))
        logger.debug(
            "Registered native function ('%s', '%s', ''0x%08X'') to %s.%s"
            % (name, signature, ptr_func, cls.__name__, found_method.func_name)
        )

    def find_method(cls, name, signature):
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature == signature:
                return method

        if cls.jvm_super is not None:
            return cls.jvm_super.find_method(name, signature)

        return None

    # 用于支持java反射，java反射签名都没有返回值
    # @param signature_no_ret something like (ILjava/lang/String;) 注意，没有返回值

    def find_method_sig_with_no_ret(cls, name, signature_no_ret):
        assert (
            signature_no_ret[0] == "("
            and signature_no_ret[len(signature_no_ret) - 1] == ")"
        ), "signature_no_ret error"
        for method in cls.jvm_methods.values():
            if method.name == name and method.signature.startswith(
                signature_no_ret
            ):
                return method

        if cls.jvm_super is not None:
            return cls.jvm_super.find_method_sig_with_no_ret(
                name, signature_no_ret
            )

        return None

    def find_method_by_id(cls, jvm_id):
        if jvm_id in cls.jvm_methods:
            return cls.jvm_methods[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_method_by_id(jvm_id)

        return None

    def find_field(cls, name, signature, is_static):
        for field in cls.jvm_fields.values():
            if (
                field.name == name
                and field.signature == signature
                and field.is_static == is_static
            ):
                return field

        if cls.jvm_super is not None:
            return cls.jvm_super.find_field(name, signature, is_static)

        return None

    def find_field_by_id(cls, jvm_id):
        if jvm_id in cls.jvm_fields:
            return cls.jvm_fields[jvm_id]
        if cls.jvm_super is not None:
            return cls.jvm_super.find_field_by_id(jvm_id)

        return None


class JavaMethodDef:
    def __init__(
        self,
        func_name,
        func,
        name,
        signature,
        native,
        args_list=None,
        modifier=None,
        ignore=None,
    ):
        self.jvm_id = next_method_id()
        self.func_name = func_name
        self.func = func
        self.name = name
        self.signature = signature
        self.native = native
        self.native_addr = None
        self.args_list = args_list
        self.modifier = modifier
        self.ignore = ignore


def java_method_def(
    name, signature, native=False, args_list=None, modifier=None, ignore=False
):
    def java_method_def_real(func):
        def native_wrapper(*args, **kwargs):
            clz = args[0].__class__
            emulator = None
            extra_args = None
            first_obj = 0xFA

            if isinstance(clz, JavaClassDef):
                emulator = args[1]
                extra_args = args[2:]

                first_obj = emulator.java_vm.jni_env.add_local_reference(
                    jobject(args[0])
                )
            else:
                emulator = args[0]
                extra_args = args[1:]
                vals = vars(sys.modules[func.__module__])
                sa = func.__qualname__.split(".")
                for attr in sa[:-1]:
                    vals = vals[attr]

                pyclazz = vals
                if not isinstance(pyclazz, JavaClassDef):
                    raise RuntimeError(f"Error class {clz.__name__} is not register as jvm class")

                jvm_clazz = pyclazz.class_object
                first_obj = emulator.java_vm.jni_env.add_local_reference(
                    jclass(jvm_clazz)
                )

            brace_index = signature.find(")")
            if brace_index == -1:
                raise RuntimeError(f"native_wrapper invalid function signature {signature}")

            return_index = brace_index + 1
            return_ch = signature[return_index]
            res = None
            arch = emulator.get_arch()
            if return_ch in ("J", "D") and arch == Arch.ARM32:
                res = emulator.call_native_return_2reg(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,  # this object or this class
                    # method has been declared in
                    *extra_args  # Extra args.
                )
            else:
                res = emulator.call_native(
                    native_wrapper.jvm_method.native_addr,
                    emulator.java_vm.jni_env.address_ptr,  # JNIEnv*
                    first_obj,  # this object or this class
                    # method has been declared in
                    *extra_args  # Extra args.
                )

            r = None
            if return_ch in ("[", "L"):
                result_idx = res
                result = emulator.java_vm.jni_env.get_local_reference(
                    result_idx
                )
                if result is None:
                    r = JAVA_NULL
                else:
                    r = result.value

            else:
                r = res

            emulator.java_vm.jni_env.clear_locals()
            return r

        def normal_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return result

        wrapper = native_wrapper if native else normal_wrapper
        wrapper.jvm_method = JavaMethodDef(
            func.__name__,
            wrapper,
            name,
            signature,
            native,
            args_list=args_list,
            modifier=modifier,
            ignore=ignore,
        )
        return wrapper

    return java_method_def_real


class JavaFieldDef:
    def __init__(self, name, signature, is_static=False, static_value=None, ignore=False):
        self.jvm_id = next_field_id()
        self.name = name
        self.signature = signature
        self.is_static = is_static
        self.static_value = static_value
        self.ignore = ignore

        if self.is_static and self.static_value is None:
            raise ValueError("Static value may not be None for a static field.")
