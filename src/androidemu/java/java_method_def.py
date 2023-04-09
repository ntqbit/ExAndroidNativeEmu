from androidemu.java.jvm_id_counter import *
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.jni_ref import *
from androidemu.const import emu_const

import sys

from androidemu.java.constant_values import JAVA_NULL


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
                    raise RuntimeError(
                        "Error class %s is not register as jvm class" % clsname
                    )

                jvm_clazz = pyclazz.class_object
                first_obj = emulator.java_vm.jni_env.add_local_reference(
                    jclass(jvm_clazz)
                )

            brace_index = signature.find(")")
            if brace_index == -1:
                raise RuntimeError(
                    "native_wrapper invalid function signature %s" % signature
                )

            return_index = brace_index + 1
            return_ch = signature[return_index]
            res = None
            arch = emulator.get_arch()
            if return_ch in ("J", "D") and arch == emu_const.Arch.ARM32:
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
                # 基本类型的话直接返回
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
