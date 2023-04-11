import sys

import verboselogs

from unicorn import (
    UC_PROT_READ,
    UC_PROT_WRITE
)

from androidemu.hooker import Hooker
from androidemu.java.classes.constructor import Constructor
from androidemu.java.classes.method import Method
from androidemu.java import JavaClassDef
from androidemu.java.helpers.native_method import (
    create_native_method_wrapper,
    native_translate_arg,
)
from androidemu.java.jni_ref import jclass, jobject, jthrowable
from androidemu.java.reference_table import ReferenceTable
from androidemu.java.classes.string import String
from androidemu.java.classes.array import Array
from androidemu.java.const import JAVA_NULL, MODIFIER_STATIC
from androidemu.java.jni_const import JNI_TRUE, JNI_FALSE, JNI_OK
from androidemu.utils import memory_helpers, debug_utils
from androidemu.utils.repr import short_bytes_repr
from androidemu.const.emu_const import Arch
from androidemu.java.jni_functions import JNI_FUNCTIONS
from androidemu.logging import JNICALL

logger = verboselogs.VerboseLogger(__name__)


# This class attempts to mimic the JNINativeInterface table.
class JNIEnv:
    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """

    def __init__(self, emu, java_vm, class_loader, hooker):
        self._emu = emu
        self._java_vm = java_vm
        self._class_loader = class_loader
        self._locals = ReferenceTable(start=1, max_entries=2048)
        self._globals = ReferenceTable(start=4096, max_entries=512000)

        arch = emu.get_arch()
        if arch == Arch.ARM32:
            self._read_args = self._read_args32
            self._read_args_v = self._read_args_v32
        elif arch == Arch.ARM64:
            self._read_args = self._read_args64
            self._read_args_v = self._read_args_v64
        else:
            raise NotImplementedError("unsupport arch %d" % arch)

        (self.address_ptr, self.address) = hooker.write_function_table(
            self._get_jni_hooking_table()
        )

    def _get_jni_hooking_table(self):
        JNI_CALLBACKS = {
            "GetVersion": self.get_version,
            "DefineClass": self.define_class,
            "FindClass": self.find_class,
            "FromReflectedMethod": self.from_reflected_method,
            "FromReflectedField": self.from_reflected_field,
            "ToReflectedMethod": self.to_reflected_method,
            "GetSuperclass": self.get_superclass,
            "IsAssignableFrom": self.is_assignable_from,
            "ToReflectedField": self.to_reflected_field,
            "Throw": self.throw,
            "ThrowNew": self.throw_new,
            "ExceptionOccurred": self.exception_occurred,
            "ExceptionDescribe": self.exception_describe,
            "ExceptionClear": self.exception_clear,
            "FatalError": self.fatal_error,
            "PushLocalFrame": self.push_local_frame,
            "PopLocalFrame": self.pop_local_frame,
            "NewGlobalRef": self.new_global_ref,
            "DeleteGlobalRef": self.delete_global_ref,
            "DeleteLocalRef": self.delete_local_ref,
            "IsSameObject": self.is_same_object,
            "NewLocalRef": self.new_local_ref,
            "EnsureLocalCapacity": self.ensure_local_capacity,
            "AllocObject": self.alloc_object,
            "NewObject": self.new_object,
            "NewObjectV": self.new_object_v,
            "NewObjectA": self.new_object_a,
            "GetObjectClass": self.get_object_class,
            "IsInstanceOf": self.is_instance_of,
            "GetMethodID": self.get_method_id,
            "CallObjectMethod": self.call_object_method,
            "CallObjectMethodV": self.call_object_method_v,
            "CallObjectMethodA": self.call_object_method_a,
            "CallBooleanMethod": self.call_boolean_method,
            "CallBooleanMethodV": self.call_boolean_method_v,
            "CallBooleanMethodA": self.call_boolean_method_a,
            "CallByteMethod": self.call_byte_method,
            "CallByteMethodV": self.call_byte_method_v,
            "CallByteMethodA": self.call_byte_method_a,
            "CallCharMethod": self.call_char_method,
            "CallCharMethodV": self.call_char_method_v,
            "CallCharMethodA": self.call_char_method_a,
            "CallShortMethod": self.call_short_method,
            "CallShortMethodV": self.call_short_method_v,
            "CallShortMethodA": self.call_short_method_a,
            "CallIntMethod": self.call_int_method,
            "CallIntMethodV": self.call_int_method_v,
            "CallIntMethodA": self.call_int_method_a,
            "CallLongMethod": self.call_long_method,
            "CallLongMethodV": self.call_long_method_v,
            "CallLongMethodA": self.call_long_method_a,
            "CallFloatMethod": self.call_float_method,
            "CallFloatMethodV": self.call_float_method_v,
            "CallFloatMethodA": self.call_float_method_a,
            "CallDoubleMethod": self.call_double_method,
            "CallDoubleMethodV": self.call_double_method_v,
            "CallDoubleMethodA": self.call_double_method_a,
            "CallVoidMethod": self.call_void_method,
            "CallVoidMethodV": self.call_void_method_v,
            "CallVoidMethodA": self.call_void_method_a,
            "CallNonvirtualObjectMethod": self.call_nonvirtual_object_method,
            "CallNonvirtualObjectMethodV": self.call_nonvirtual_object_method_v,
            "CallNonvirtualObjectMethodA": self.call_nonvirtual_object_method_a,
            "CallNonvirtualBooleanMethod": self.call_nonvirtual_boolean_method,
            "CallNonvirtualBooleanMethodV": self.call_nonvirtual_boolean_method_v,
            "CallNonvirtualBooleanMethodA": self.call_nonvirtual_boolean_method_a,
            "CallNonvirtualByteMethod": self.call_nonvirtual_byte_method,
            "CallNonvirtualByteMethodV": self.call_nonvirtual_byte_method_v,
            "CallNonvirtualByteMethodA": self.call_nonvirtual_byte_method_a,
            "CallNonvirtualCharMethod": self.call_nonvirtual_char_method,
            "CallNonvirtualCharMethodV": self.call_nonvirtual_char_method_v,
            "CallNonvirtualCharMethodA": self.call_nonvirtual_char_method_a,
            "CallNonvirtualShortMethod": self.call_nonvirtual_short_method,
            "CallNonvirtualShortMethodV": self.call_nonvirtual_short_method_v,
            "CallNonvirtualShortMethodA": self.call_nonvirtual_short_method_a,
            "CallNonvirtualIntMethod": self.call_nonvirtual_int_method,
            "CallNonvirtualIntMethodV": self.call_nonvirtual_int_method_v,
            "CallNonvirtualIntMethodA": self.call_nonvirtual_int_method_a,
            "CallNonvirtualLongMethod": self.call_nonvirtual_long_method,
            "CallNonvirtualLongMethodV": self.call_nonvirtual_long_method_v,
            "CallNonvirtualLongMethodA": self.call_nonvirtual_long_method_a,
            "CallNonvirtualFloatMethod": self.call_nonvirtual_float_method,
            "CallNonvirtualFloatMethodV": self.call_nonvirtual_float_method_v,
            "CallNonvirtualFloatMethodA": self.call_nonvirtual_float_method_a,
            "CallNonvirtualDoubleMethod": self.call_nonvirtual_double_method,
            "CallNonvirtualDoubleMethodV": self.call_nonvirtual_double_method_v,
            "CallNonvirtualDoubleMethodA": self.call_nonvirtual_double_method_a,
            "CallNonvirtualVoidMethod": self.call_nonvirtual_void_method,
            "CallNonvirtualVoidMethodV": self.call_nonvirtual_void_method_v,
            "CallNonvirtualVoidMethodA": self.call_nonvirtual_void_method_a,
            "GetFieldID": self.get_field_id,
            "GetObjectField": self.get_object_field,
            "GetBooleanField": self.get_boolean_field,
            "GetByteField": self.get_byte_field,
            "GetCharField": self.get_char_field,
            "GetShortField": self.get_short_field,
            "GetIntField": self.get_int_field,
            "GetLongField": self.get_long_field,
            "GetFloatField": self.get_float_field,
            "GetDoubleField": self.get_double_field,
            "SetObjectField": self.set_object_field,
            "SetBooleanField": self.set_boolean_field,
            "SetByteField": self.set_byte_field,
            "SetCharField": self.set_char_field,
            "SetShortField": self.set_short_field,
            "SetIntField": self.set_int_field,
            "SetLongField": self.set_long_field,
            "SetFloatField": self.set_float_field,
            "SetDoubleField": self.set_double_field,
            "GetStaticMethodID": self.get_static_method_id,
            "CallStaticObjectMethod": self.call_static_object_method,
            "CallStaticObjectMethodV": self.call_static_object_method_v,
            "CallStaticObjectMethodA": self.call_static_object_method_a,
            "CallStaticBooleanMethod": self.call_static_boolean_method,
            "CallStaticBooleanMethodV": self.call_static_boolean_method_v,
            "CallStaticBooleanMethodA": self.call_static_boolean_method_a,
            "CallStaticByteMethod": self.call_static_byte_method,
            "CallStaticByteMethodV": self.call_static_byte_method_v,
            "CallStaticByteMethodA": self.call_static_byte_method_a,
            "CallStaticCharMethod": self.call_static_char_method,
            "CallStaticCharMethodV": self.call_static_char_method_v,
            "CallStaticCharMethodA": self.call_static_char_method_a,
            "CallStaticShortMethod": self.call_static_short_method,
            "CallStaticShortMethodV": self.call_static_short_method_v,
            "CallStaticShortMethodA": self.call_static_short_method_a,
            "CallStaticIntMethod": self.call_static_int_method,
            "CallStaticIntMethodV": self.call_static_int_method_v,
            "CallStaticIntMethodA": self.call_static_int_method_a,
            "CallStaticLongMethod": self.call_static_long_method,
            "CallStaticLongMethodV": self.call_static_long_method_v,
            "CallStaticLongMethodA": self.call_static_long_method_a,
            "CallStaticFloatMethod": self.call_static_float_method,
            "CallStaticFloatMethodV": self.call_static_float_method_v,
            "CallStaticFloatMethodA": self.call_static_float_method_a,
            "CallStaticDoubleMethod": self.call_static_double_method,
            "CallStaticDoubleMethodV": self.call_static_double_method_v,
            "CallStaticDoubleMethodA": self.call_static_double_method_a,
            "CallStaticVoidMethod": self.call_static_void_method,
            "CallStaticVoidMethodV": self.call_static_void_method_v,
            "CallStaticVoidMethodA": self.call_static_void_method_a,
            "GetStaticFieldID": self.get_static_field_id,
            "GetStaticObjectField": self.get_static_object_field,
            "GetStaticBooleanField": self.get_static_boolean_field,
            "GetStaticByteField": self.get_static_byte_field,
            "GetStaticCharField": self.get_static_char_field,
            "GetStaticShortField": self.get_static_short_field,
            "GetStaticIntField": self.get_static_int_field,
            "GetStaticLongField": self.get_static_long_field,
            "GetStaticFloatField": self.get_static_float_field,
            "GetStaticDoubleField": self.get_static_double_field,
            "SetStaticObjectField": self.set_static_object_field,
            "SetStaticBooleanField": self.set_static_boolean_field,
            "SetStaticByteField": self.set_static_byte_field,
            "SetStaticCharField": self.set_static_char_field,
            "SetStaticShortField": self.set_static_short_field,
            "SetStaticIntField": self.set_static_int_field,
            "SetStaticLongField": self.set_static_long_field,
            "SetStaticFloatField": self.set_static_float_field,
            "SetStaticDoubleField": self.set_static_double_field,
            "NewString": self.new_string,
            "GetStringLength": self.get_string_length,
            "GetStringChars": self.get_string_chars,
            "ReleaseStringChars": self.release_string_chars,
            "NewStringUTF": self.new_string_utf,
            "GetStringUTFLength": self.get_string_utf_length,
            "GetStringUTFChars": self.get_string_utf_chars,
            "ReleaseStringUTFChars": self.release_string_utf_chars,
            "GetArrayLength": self.get_array_length,
            "NewObjectArray": self.new_object_array,
            "GetObjectArrayElement": self.get_object_array_element,
            "SetObjectArrayElement": self.set_object_array_element,
            "NewBooleanArray": self.new_boolean_array,
            "NewByteArray": self.new_byte_array,
            "NewCharArray": self.new_char_array,
            "NewShortArray": self.new_short_array,
            "NewIntArray": self.new_int_array,
            "NewLongArray": self.new_long_array,
            "NewFloatArray": self.new_float_array,
            "NewDoubleArray": self.new_double_array,
            "GetBooleanArrayElements": self.get_boolean_array_elements,
            "GetByteArrayElements": self.get_byte_array_elements,
            "GetCharArrayElements": self.get_char_array_elements,
            "GetShortArrayElements": self.get_short_array_elements,
            "GetIntArrayElements": self.get_int_array_elements,
            "GetLongArrayElements": self.get_long_array_elements,
            "GetFloatArrayElements": self.get_float_array_elements,
            "GetDoubleArrayElements": self.get_double_array_elements,
            "ReleaseBooleanArrayElements": self.release_boolean_array_elements,
            "ReleaseByteArrayElements": self.release_byte_array_elements,
            "ReleaseCharArrayElements": self.release_char_array_elements,
            "ReleaseShortArrayElements": self.release_short_array_elements,
            "ReleaseIntArrayElements": self.release_int_array_elements,
            "ReleaseLongArrayElements": self.release_long_array_elements,
            "ReleaseFloatArrayElements": self.release_float_array_elements,
            "ReleaseDoubleArrayElements": self.release_double_array_elements,
            "GetBooleanArrayRegion": self.get_boolean_array_region,
            "GetByteArrayRegion": self.get_byte_array_region,
            "GetCharArrayRegion": self.get_char_array_region,
            "GetShortArrayRegion": self.get_short_array_region,
            "GetIntArrayRegion": self.get_int_array_region,
            "GetLongArrayRegion": self.get_long_array_region,
            "GetFloatArrayRegion": self.get_float_array_region,
            "GetDoubleArrayRegion": self.get_double_array_region,
            "SetBooleanArrayRegion": self.set_boolean_array_region,
            "SetByteArrayRegion": self.set_byte_array_region,
            "SetCharArrayRegion": self.set_char_array_region,
            "SetShortArrayRegion": self.set_short_array_region,
            "SetIntArrayRegion": self.set_int_array_region,
            "SetLongArrayRegion": self.set_long_array_region,
            "SetFloatArrayRegion": self.set_float_array_region,
            "SetDoubleArrayRegion": self.set_double_array_region,
            "RegisterNatives": self.register_natives,
            "UnregisterNatives": self.unregister_natives,
            "MonitorEnter": self.monitor_enter,
            "MonitorExit": self.monitor_exit,
            "GetJavaVM": self.get_java_vm,
            "GetStringRegion": self.get_string_region,
            "GetStringUTFRegion": self.get_string_utf_region,
            "GetPrimitiveArrayCritical": self.get_primitive_array_critical,
            "ReleasePrimitiveArrayCritical": self.release_primitive_array_critical,
            "GetStringCritical": self.get_string_critical,
            "ReleaseStringCritical": self.release_string_critical,
            "NewWeakGlobalRef": self.new_weak_global_ref,
            "DeleteWeakGlobalRef": self.delete_weak_global_ref,
            "ExceptionCheck": self.exception_check,
            "NewDirectByteBuffer": self.new_direct_byte_buffer,
            "GetDirectBufferAddress": self.get_direct_buffer_address,
            "GetDirectBufferCapacity": self.get_direct_buffer_capacity,
            "GetObjectRefType": self.get_object_ref_type,
        }

        def map_var_type(var, var_type):
            if var_type == "JNIEnv*":
                return None

            if var_type == "jmethodID":
                return var  # TODO: impl

            if var_type in ["jobject", "jclass", "jthrowable"]:
                return f"ref<{var},{repr(self.get_reference(var))}>"

            if var_type == "jstring":
                return (
                    "'" + self.get_reference(var).value.get_py_string() + "'"
                )

            if var_type in "char*":
                return "'" + memory_helpers.read_utf8(self._emu.mu, var) + "'"

            return var

        def get_args_log(args, func_args):
            mapped_to_text = [
                (func_arg["name"], map_var_type(arg, func_arg["type"]))
                for arg, func_arg in zip(args, func_args)
            ]

            args_filtered_none = filter(
                lambda x: x[1] is not None, mapped_to_text
            )

            args_with_names = [
                f"{name}:{mapped_text}"
                for name, mapped_text in args_filtered_none
            ]

            return ",".join(args_with_names)

        def create_wrapper(func, callback):
            def wrapper(mu, *args):
                log_text = f"JNIEnv->{func['name']}({get_args_log(args, func['args'])})"

                try:
                    ret = callback(mu, *args)

                    if ret is not None:
                        ret = native_translate_arg(self._emu, ret)

                        if func["ret"] != "void":
                            log_text += f' = {map_var_type(ret, func["ret"])}'
                except Exception as e:
                    log_text += f". Thrown {e.__class__.__name__}({str(e)})."
                    logger.log(JNICALL, log_text)
                    raise

                logger.log(JNICALL, log_text)
                return ret

            return create_native_method_wrapper(wrapper, len(func["args"]))

        return {
            func["id"]: create_wrapper(func, JNI_CALLBACKS[func["name"]])
            for func in JNI_FUNCTIONS
        }

    def get_reference(self, idx):
        if idx == 0:
            return None

        if self._locals.in_range(idx):
            return self._locals.get(idx)

        if self._globals.in_range(idx):
            return self._globals.get(idx)

        raise RuntimeError("Invalid get_reference(%d)" % idx)

    def add_local_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        index = self._locals.add(obj)
        return index

    def set_local_reference(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError("Expected a jobject.")

        self._locals.set(idx, newobj)

    def get_local_reference(self, idx):
        r = self._locals.get(idx)
        return r

    def delete_local_reference(self, obj):
        return self._locals.remove(obj)

    def clear_locals(self):
        self._locals.clear()

    def add_global_reference(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        return self._globals.add(obj)

    def get_global_reference(self, idx):
        return self._globals.get(idx)

    def delete_global_reference(self, obj):
        return self._globals.remove(obj)

    # args is a tuple or list

    def _read_args32(self, mu, args, args_type_list):
        if args_type_list is None:
            logger.warning('Argument type list is not defined')
            return []

        result = []
        args_index = 0
        n = len(args_type_list)
        nargs = len(args)
        args_list_index = 0

        while args_list_index < n:
            arg_name = args_type_list[args_list_index]
            if args_index == 0 and arg_name in ("jlong", "jdouble"):
                args_index = args_index + 1
                continue

            v = args[args_index]
            if arg_name in ("jint", "jchar", "jbyte", "jboolean"):
                result.append(v)

            elif arg_name in ("jlong", "jdouble"):
                args_index = args_index + 1
                if args_index >= nargs:
                    raise RuntimeError(
                        "read_args get long on args_type_list, but args len is not enough to read high bytes"
                    )

                vh = args[args_index]
                value = (vh << 32) | v
                result.append(value)

            elif arg_name in ("jstring", "jobject", "jthrowable"):
                ref = v
                jobj = self.get_reference(ref)

                if jobj is None:
                    obj = None
                else:
                    obj = jobj.value

                result.append(obj)
            else:
                raise NotImplementedError(f"Unknown arg name {arg_name}")

            args_index = args_index + 1
            args_list_index = args_list_index + 1

        return result

    def _read_args64(self, mu, args, args_type_list):
        if args_type_list is None:
            logger.warning('Argument type list is not defined')
            return []

        result = []
        n = len(args_type_list)
        nargs = len(args)

        for args_index in nargs:
            arg_name = args_type_list[args_index]
            v = args[args_index]
            if arg_name in (
                "jint",
                "jchar",
                "jbyte",
                "jboolean",
                "jlong",
                "jdouble",
            ):
                result.append(v)

            elif arg_name in ("jstring", "jobject", "jthrowable"):
                ref = v
                jobj = self.get_reference(ref)
                if jobj is None:
                    obj = None
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError("Unknown arg name %s" % arg_name)

        return result

    def _read_args_v32(self, mu, args_ptr, args_type_list):
        result = []

        if args_type_list is None:
            logger.warning('Argument type list is not defined')
            return result

        for arg_name in args_type_list:
            v = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder="little")

            if arg_name in ("jint", "jchar", "jbyte", "jboolean"):
                result.append(v)
            elif arg_name in ("jlong", "jdouble"):
                args_ptr = args_ptr + 4
                vh = int.from_bytes(
                    mu.mem_read(args_ptr, 4), byteorder="little"
                )
                value = (vh << 32) | v
                result.append(value)

            elif arg_name in ("jstring", "jobject", "jthrowable"):
                ref = v
                jobj = self.get_reference(ref)

                if jobj is None:
                    obj = None
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError("Unknown arg name %s" % arg_name)

            args_ptr = args_ptr + 4

        return result

    def _read_args_v64(self, mu, args_ptr, args_type_list):
        result = []
        if args_type_list is None:
            logger.warning('Argument type list is not defined')
            return result

        ptr_size = self._emu.get_ptr_size()
        for arg_name in args_type_list:
            v = int.from_bytes(
                mu.mem_read(args_ptr, ptr_size), byteorder="little"
            )
            if arg_name in (
                "jint",
                "jchar",
                "jbyte",
                "jboolean",
                "jlong",
                "jdouble",
            ):
                result.append(v)

            elif arg_name in ("jstring", "jobject", "jthrowable"):
                ref = v
                jobj = self.get_reference(ref)
                if jobj is None:
                    obj = None
                else:
                    obj = jobj.value
                result.append(obj)
            else:
                raise NotImplementedError("Unknown arg name %s" % arg_name)

            args_ptr = args_ptr + ptr_size

        return result

    def _read_args_a(self, mu, args_ptr, args_type_list):
        assert self._emu.get_arch() == Arch.ARM32

        result = []

        if args_type_list is None:
            logger.warning('Argument type list is not defined')
            return result

        for arg_name in args_type_list:
            if arg_name in ('jchar', 'jbyte', 'jboolean'):
                result.append(int.from_bytes(mu.mem_read(args_ptr, 1), byteorder="little"))
            if arg_name == 'jint':
                result.append(int.from_bytes(mu.mem_read(args_ptr, 4), byteorder="little"))
            elif arg_name in ("jlong", "jdouble"):
                result.append(int.from_bytes(mu.mem_read(args_ptr, 8), byteorder="little"))
            elif arg_name in ("jstring", "jobject", "jthrowable"):
                ref = int.from_bytes(mu.mem_read(args_ptr, 4), byteorder="little")
                jobj = self.get_reference(ref)

                if jobj is None:
                    obj = None
                else:
                    obj = jobj.value

                result.append(obj)
            else:
                raise NotImplementedError(f"Unknown arg name {arg_name}")

            args_ptr = args_ptr + 8

        return result

    # arg_type = 0 tuple or list, 1 arg_v, 2 array

    def _read_args_common(self, mu, args, args_type_list, arg_type):
        if arg_type == 0:
            return self._read_args(mu, args, args_type_list)
        elif arg_type == 1:
            return self._read_args_v(mu, args, args_type_list)
        elif arg_type == 2:
            return self._read_args_a(mu, args, args_type_list)
        else:
            raise RuntimeError("arg_type %d not support" % arg_type)

    @staticmethod
    def jobject_to_pyobject(obj):
        if isinstance(obj, jobject):
            return obj.value
        else:
            raise RuntimeError("jobject_to_pyobject unknown obj type %r" % obj)

    def get_version(self, mu, env):
        logger.debug("JNIEnv->GetVersion() was called")
        return 65542

    def define_class(self, mu, env):
        raise NotImplementedError()

    def find_class(self, mu, env, name_ptr):
        """
        Returns a class object from a fully-qualified name, or NULL if the class cannot be found.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug("JNIEnv->FindClass(%s) was called", name)

        pyclazz = self._class_loader.find_class_by_name(name)
        if pyclazz is None:
            raise RuntimeError(f"Could not find class '{name}' for JNIEnv.")

        if pyclazz.jvm_ignore:
            logger.debug("FindClass %s return 0 because of ignored")
            return JAVA_NULL

        return self.add_local_reference(jclass(pyclazz.class_object))

    def from_reflected_method(self, mu, env):
        raise NotImplementedError()

    def from_reflected_field(self, mu, env):
        raise NotImplementedError()

    def to_reflected_method(self, mu, env, class_idx, method_id, is_static):
        """
        Converts a method ID derived from cls to a java.lang.reflect.Method or java.lang.reflect.Constructor object.
        isStatic must be set to JNI_TRUE if the method ID refers to a static field, and JNI_FALSE otherwise.

        Throws OutOfMemoryError and returns 0 if fails.
        """
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError(
                "Could not find method ('%u') in class %s."
                % (method_id, pyclazz.jvm_name)
            )

        if method.modifier & MODIFIER_STATIC:
            mu.mem_write(
                is_static, int(JNI_TRUE).to_bytes(4, byteorder="little")
            )
        else:
            mu.mem_write(
                is_static, int(JNI_FALSE).to_bytes(4, byteorder="little")
            )

        logger.debug(
            "JNIEnv->ToReflectedMethod(%s, %s, %u) was called"
            % (pyclazz.jvm_name, method.name, is_static)
        )

        if method.name == "<init>" and method.signature.endswith("V"):
            return Constructor(pyclazz, method)
        else:
            return Method(pyclazz, method)

    def get_superclass(self, mu, env, clazz_idx):
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")

        # Create class instance.
        class_obj = jclazz.value
        pyclass = class_obj.get_py_clazz()

        logger.debug("JNIEnv->GetSuperClass (%s) is called" % pyclass.jvm_name)

        pyclazz_super = pyclass.jvm_super
        if not pyclazz_super:
            raise RuntimeError(
                "super class for %s is None you should at least inherit Object"
            )

        logger.debug(
            "JNIEnv->GetSuperClass (%s) return (%s)"
            % (pyclass.jvm_name, pyclazz_super.jvm_name)
        )
        clazz_super_object = pyclazz_super.class_object
        return self.add_local_reference(jclass(clazz_super_object))

    def is_assignable_from(self, mu, env, clazz_idx1, clazz_idx2):
        jclazz1 = self.get_reference(clazz_idx1)
        jclazz2 = self.get_reference(clazz_idx2)
        # Create class instance.
        class_obj1 = jclazz1.value
        pyclass1 = class_obj1.get_py_clazz()

        class_obj2 = jclazz2.value
        pyclass2 = class_obj2.get_py_clazz()

        logger.debug(
            "JNIEnv->IsAssignableFrom (%s,%s) is called"
            % (pyclass1.jvm_name, pyclass2.jvm_name)
        )
        r = JNI_FALSE
        jvm_super = pyclass1.jvm_super
        while jvm_super is not None:
            if jvm_super == pyclass2:
                r = JNI_TRUE
                break

            jvm_super = jvm_super.jvm_super

        logger.debug(
            "JNIEnv->IsAssignableFrom (%s,%s) return (%d)"
            % (pyclass1.jvm_name, pyclass2.jvm_name, r)
        )
        return r

    def to_reflected_field(self, mu, env):
        raise NotImplementedError()

    def throw(self, mu, env, obj_idx):
        obj = self.get_reference(obj_idx)
        logger.debug('Thrown an exception: %s', obj)

        if not isinstance(obj, jthrowable):
            raise ValueError("Expected a jthrowable.")

        self._java_vm.set_exception(obj)
        return 0

    def throw_new(self, mu, env, clazz_idx, msg_idx):
        logger.debug('Thrown an exception')

        clazz = self.get_reference(clazz_idx)
        msg_obj = self.get_reference(msg_idx)
        logger.debug('Thrown a new exception: %s,%s', clazz, msg_obj)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        if not isinstance(msg_obj, jobject):
            raise ValueError('Expected a jobject.')

        if msg_obj.value == JAVA_NULL:
            msg = None
        else:
            msg = msg_obj.value.get_py_string()

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()
        obj = jthrowable(pyclazz(msg))

        self._java_vm.set_exception(obj)
        return 0

    def exception_occurred(self, mu, env):
        exc = self._java_vm.get_exception()
        if not exc:
            return JAVA_NULL

        return self.add_local_reference(exc)

    def exception_describe(self, mu, env):
        raise NotImplementedError()

    def exception_clear(self, mu, env):
        """
        Clears any exception that is currently being thrown.
        If no exception is currently being thrown, this routine has no effect.
        """
        self._java_vm.clear_exception()

    def fatal_error(self, mu, env):
        raise NotImplementedError()

    def push_local_frame(self, mu, env):
        raise NotImplementedError()

    def pop_local_frame(self, mu, env):
        raise NotImplementedError()

    def new_global_ref(self, mu, env, jobj):
        """
        Creates a new global reference to the object referred to by the obj argument. The obj argument may be a
        global or local reference. Global references must be explicitly disposed of by calling DeleteGlobalRef().
        """
        logger.debug("JNIEnv->NewGlobalRef(%d) was called", jobj)

        if jobj == 0:
            return 0

        obj = self.get_reference(jobj)

        if obj is None:
            # TODO: Implement global > global support (?)
            raise NotImplementedError("Invalid local reference obj.")

        return self.add_global_reference(obj)

    def delete_global_ref(self, mu, env, idx):
        """
        Deletes the global reference pointed to by globalRef.
        """
        logger.debug("JNIEnv->DeleteGlobalRef(%d) was called" % idx)

        if idx == 0:
            return None

        self.delete_global_reference(idx)

    def delete_local_ref(self, mu, env, idx):
        """
        Deletes the local reference pointed to by localRef.
        """
        logger.debug("JNIEnv->DeleteLocalRef(%d) was called" % idx)

        if idx == 0:
            return None

        self.delete_local_reference(idx)

    def is_same_object(self, mu, env, ref1, ref2):
        """
        Returns JNI_TRUE if ref1 and ref2 refer to the same Java object, or are both NULL; otherwise, returns JNI_FALSE.
        """
        logger.debug("JNIEnv->IsSameObject(%d, %d) was called" % (ref1, ref2))

        if ref1 == 0 and ref2 == 0:
            return JNI_TRUE

        if ref1 == 0 or ref2 == 0:
            return JNI_FALSE

        obj1 = self.get_reference(ref1)
        obj2 = self.get_reference(ref2)
        pyobj1 = self.jobject_to_pyobject(obj1)
        pyobj2 = self.jobject_to_pyobject(obj2)

        if pyobj1 is pyobj2:
            return JNI_TRUE

        return JNI_FALSE

    def new_local_ref(self, mu, env, ref):
        """
        Creates a new local reference that refers to the same object as ref.
        The given ref may be a global or local reference. Returns NULL if ref refers to null.
        """
        logger.debug("JNIEnv->NewLocalRef(%d) was called" % ref)

        obj = self.get_reference(ref)

        if obj is None:
            return 0

        return self.add_local_reference(obj)

    def ensure_local_capacity(self, mu, env):
        return JNI_OK

    def alloc_object(self, mu, env):
        raise NotImplementedError()

    def _new_object(self, mu, env, clazz_idx, method_id, args, args_type):
        # Get class reference.
        jclazz = self.get_reference(clazz_idx)
        if not isinstance(jclazz, jclass):
            raise ValueError("Expected a jclass.")

        # Create class instance.
        class_obj = jclazz.value

        pyclazz = class_obj.get_py_clazz()

        obj = pyclazz()

        # Get constructor method.
        method = pyclazz.find_method_by_id(method_id)
        if method.name != "<init>" or not method.signature.endswith("V"):
            raise ValueError("Class constructor has the wrong name or does not return void.")

        # Parse arguments.
        constructor_args = self._read_args_common(mu, args, method.args_list, args_type)

        logger.debug("JNIEnv->NewObjectX(%s, %s, %s) was called", pyclazz.jvm_name, method.name, constructor_args)

        # Execute function.
        method.func(obj, self._emu, *constructor_args)

        return self.add_local_reference(jobject(obj))

    def new_object(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._new_object(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def new_object_v(self, mu, env, clazz_idx, method_id, args_v):
        return self._new_object(mu, env, clazz_idx, method_id, args_v, 1)

    def new_object_a(self, mu, env, clazz_idx, method_id, args_v):
        return self._new_object(mu, env, clazz_idx, method_id, args_v, 2)

    def get_object_class(self, mu, env, obj_idx):

        obj = self.get_reference(obj_idx)
        if obj is None:
            raise RuntimeError(
                "get_object_class can not get class for object id %d for JNIEnv."
                % obj_idx
            )

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        logger.debug("JNIEnv->GetObjectClass(%r) was called", pyobj)

        pyclazz = pyobj.__class__

        jvm_clazz = pyclazz.class_object
        return self.add_local_reference(jclass(jvm_clazz))

    def is_instance_of(self, mu, env, obj_idx, class_idx):
        """
        Tests whether an object is an instance of a class.
        Returns JNI_TRUE if obj can be cast to clazz; otherwise, returns JNI_FALSE. A NULL object can be cast to any class.
        """
        obj = self.get_reference(obj_idx)
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        clazz = self.get_reference(class_idx)
        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        # TODO: Casting check (?)

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        return JNI_TRUE if pyobj.jvm_id == pyclazz.jvm_id else JNI_FALSE

    def get_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for an instance (nonstatic) method of a class or interface. The method may be defined
        in one of the clazz’s superclasses and inherited by clazz. The method is determined by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)
        logger.debug(
            "JNIEnv->GetMethodId(%d, %s, %s) was called"
            % (clazz_idx, name, sig)
        )

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        logger.debug("get_method_id type %s" % (pyclazz))
        method = pyclazz.find_method(name, sig)

        if method is None:
            raise RuntimeError(
                "Could not find method ('%s', '%s') in class %s."
                % (name, sig, pyclazz.jvm_name)
            )

        logger.debug(
            "JNIEnv->GetMethodId(%d, %s, %s) return 0x%08X"
            % (clazz_idx, name, sig, method.jvm_id)
        )
        return method.jvm_id

    def _call_xxx_method(self, mu, env, obj_idx, method_id, args, args_type, is_wide=False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = JNIEnv.jobject_to_pyobject(obj)

        method = pyobj.__class__.find_method_by_id(method_id)
        if method is None:
            raise RuntimeError("Could not find method %d in object %s by id." % (method_id, pyobj.jvm_name))

        sig = method.signature
        name = method.name

        real_method = pyobj.__class__.find_method(name, sig)

        constructor_args = self._read_args_common(mu, args, method.args_list, args_type)

        logger.log(JNICALL, "JNIEnv->CallXXXMethodX(%s, %s <%s>, %s) was called" %
                   (pyobj.jvm_name, method.name, method.signature, constructor_args))

        v = real_method.func(pyobj, self._emu, *constructor_args)

        if is_wide:
            rhigh = v >> 32
            rlow = v & 0xFFFFFFFF
            return (rlow, rhigh)

        return v

    def call_object_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_object_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_object_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_boolean_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_boolean_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_boolean_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_byte_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_byte_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_byte_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_char_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_char_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_char_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_short_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_short_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_short_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_int_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_int_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_int_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_long_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0, True)

    def call_long_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1, True)

    def call_long_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_float_method(self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_float_method_v(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_float_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_double_method(
        self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4
    ):
        raise NotImplementedError()
        # return self._call_xxx_method(mu, env, obj_idx, method_id, (arg1,
        # arg2, arg3, arg4), 0)

    def call_double_method_v(self, mu, env, obj_idx, method_id, args):
        raise NotImplementedError()
        # return self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_double_method_a(self, mu, env):
        raise NotImplementedError()

    def call_void_method(
        self, mu, env, obj_idx, method_id, arg1, arg2, arg3, arg4
    ):
        self._call_xxx_method(
            mu, env, obj_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_void_method_a(self, mu, env, obj_idx, method_id, args):
        return self._call_xxx_method(mu, env, obj_idx, method_id, args, 2)

    def call_void_method_v(self, mu, env, obj_idx, method_id, args):
        self._call_xxx_method(mu, env, obj_idx, method_id, args, 1)

    def call_nonvirtual_object_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_object_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_object_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_boolean_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_boolean_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_byte_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_byte_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_byte_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_char_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_char_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_char_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_short_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_short_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_short_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_int_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_int_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_int_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_long_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_long_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_long_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_float_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_float_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_float_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_double_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_double_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_double_method_a(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_void_method(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_void_method_v(self, mu, env):
        raise NotImplementedError()

    def call_nonvirtual_void_method_a(self, mu, env):
        raise NotImplementedError()

    def get_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for an instance (nonstatic) field of a class. The field is specified by its name and
        signature. The Get<type>Field and Set<type>Field families of accessor functions use field IDs to retrieve
        object fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug(
            "JNIEnv->GetFieldId(%d, %s, %s) was called"
            % (clazz_idx, name, sig)
        )

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, False)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find field ('%s', '%s') in class %s."
                % (name, sig, pyclazz.jvm_name)
            )

        if field.ignore:
            return 0

        return field.jvm_id

    def _get_xxx_field(self, mu, env, obj_idx, field_id, is_wide=False):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find field %d in object %s by id."
                % (field_id, pyobj.jvm_name)
            )

        logger.debug(
            "JNIEnv->GetXXXField(%s, %s <%s>) was called"
            % (pyobj.jvm_name, field.name, field.signature)
        )
        v = getattr(pyobj, field.name)
        if not is_wide:
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0xFFFFFFFF
            return (rlow, rhigh)

    def get_object_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_boolean_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_byte_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_char_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_short_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_int_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_long_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id, True)

    def get_float_field(self, mu, env, obj_idx, field_id):
        return self._get_xxx_field(mu, env, obj_idx, field_id)

    def get_double_field(self, mu, env, obj_idx, field_id):
        raise NotImplementedError()

    def _set_xxx_field(
        self, mu, env, obj_idx, field_id, value, is_obj_value=False
    ):
        obj = self.get_reference(obj_idx)

        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        field = pyobj.__class__.find_field_by_id(field_id)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find field %d in object %s by id."
                % (field_id, pyobj.jvm_name)
            )

        logger.debug(
            "JNIEnv->SetXXXField(%s, %s <%s>, %r) was called"
            % (pyobj.jvm_name, field.name, field.signature, value)
        )

        v = None
        if is_obj_value:
            value_idx = value
            value_obj = self.get_reference(value_idx)
            v = JNIEnv.jobject_to_pyobject(value_obj)

        else:
            v = value

        setattr(pyobj, field.name, v)

    def set_object_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value, True)

    def set_boolean_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_byte_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_char_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_short_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_int_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_long_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_float_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def set_double_field(self, mu, env, obj_idx, field_id, value):
        self._set_xxx_field(mu, env, obj_idx, field_id, value)

    def get_static_method_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the method ID for a static method of a class. The method is specified by its name and signature.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)
        clazz = self.get_reference(clazz_idx)

        logger.debug(
            "JNIEnv->GetStaticMethodId(%d, %s, %s) was called"
            % (clazz_idx, name, sig)
        )

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()
        method = pyclazz.find_method(name, sig)

        if method is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static method ('%s', '%s') in class %s."
                % (name, sig, pyclazz.jvm_name)
            )

        if method.ignore:
            return 0
        logger.debug(
            "JNIEnv->GetStaticMethodId(%d, %s, %s) return 0x%08X"
            % (clazz_idx, name, sig, method.jvm_id)
        )

        return method.jvm_id

    def _call_static_xxx_method(self, mu, env, clazz_idx, method_id, args, args_type, is_wide=False):
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        method = pyclazz.find_method_by_id(method_id)

        if method is None:
            raise RuntimeError("Could not find method %d in class %s by id." % (method_id, pyclazz.jvm_name))

        constructor_args = self._read_args_common(mu, args, method.args_list, args_type)

        logger.log(JNICALL, "JNIEnv->CallStaticXXXMethodX(%s, %s <%s>, %r) was called",
                   pyclazz.jvm_name, method.name, method.signature, constructor_args)

        v = method.func(self._emu, *constructor_args)

        if not is_wide:
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0xFFFFFFFF
            return (rlow, rhigh)

    def call_static_object_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_static_object_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    def call_static_object_method_a(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    def call_static_boolean_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_boolean_method_v(
        self, mu, env, clazz_idx, method_id, args
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1
        )

    def call_static_boolean_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_byte_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_byte_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1
        )

    def call_static_byte_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_char_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_char_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1
        )

    def call_static_char_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_short_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_short_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1
        )

    def call_static_short_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_int_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_int_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, args, 1
        )

    def call_static_int_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_long_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0, True)

    def call_static_long_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1, True)

    def call_static_long_method_a(self, mu, env,  clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2, True)

    def call_static_float_method(self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0)

    def call_static_float_method_v(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    def call_static_float_method_a(self, mu, env, clazz_idx, method_id, args):
        return self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 2)

    def call_static_double_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        raise NotImplementedError()
        # return self._call_static_xxx_method(mu, env, clazz_idx, method_id,
        # (arg1, arg2, arg3, arg4), 0)

    def call_static_double_method_v(self, mu, env, clazz_idx, method_id, args):
        raise NotImplementedError()
        # return self._call_static_xxx_method(mu, env, clazz_idx, method_id,
        # args, 1)

    def call_static_double_method_a(self, mu, env):
        raise NotImplementedError()

    def call_static_void_method(
        self, mu, env, clazz_idx, method_id, arg1, arg2, arg3, arg4
    ):
        self._call_static_xxx_method(
            mu, env, clazz_idx, method_id, (arg1, arg2, arg3, arg4), 0
        )

    def call_static_void_method_v(self, mu, env, clazz_idx, method_id, args):
        self._call_static_xxx_method(mu, env, clazz_idx, method_id, args, 1)

    def call_static_void_method_a(self, mu, env):
        raise NotImplementedError()

    def get_static_field_id(self, mu, env, clazz_idx, name_ptr, sig_ptr):
        """
        Returns the field ID for a static field of a class. The field is specified by its name and signature. The
        GetStatic<type>Field and SetStatic<type>Field families of accessor functions use field IDs to retrieve static
        fields.
        """
        name = memory_helpers.read_utf8(mu, name_ptr)
        sig = memory_helpers.read_utf8(mu, sig_ptr)

        logger.debug(
            "JNIEnv->GetStaticFieldId(%d, %s, %s) was called"
            % (clazz_idx, name, sig)
        )

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field(name, sig, True)

        if field is None:
            # TODO: Proper Java error?
            raise RuntimeError(
                "Could not find static field ('%s', '%s') in class %s."
                % (name, sig, pyclazz.jvm_name)
            )

        if field.ignore:
            return 0

        return field.jvm_id

    def _get_static_xxx_field(
        self, mu, env, clazz_idx, field_id, is_wide=False
    ):

        logger.debug(
            "JNIEnv->GetStaticXXXField(%d, %d) was called"
            % (clazz_idx, field_id)
        )

        clazz = self.get_reference(clazz_idx)

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)

        r = field.static_value
        logger.debug("JNIEnv->GetStaticXXXField return %r" % r)
        v = field.static_value

        if not is_wide:
            return v
        else:
            rhigh = v >> 32
            rlow = v & 0xFFFFFFFF
            return (rlow, rhigh)

    def get_static_object_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_boolean_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_byte_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_char_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_short_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_int_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_long_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id, True)

    def get_static_float_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id)

    def get_static_double_field(self, mu, env, clazz_idx, field_id):
        return self._get_static_xxx_field(mu, env, clazz_idx, field_id, True)

    def set_static_object_field(self, mu, env):
        raise NotImplementedError()

    def set_static_boolean_field(self, mu, env):
        raise NotImplementedError()

    def set_static_byte_field(self, mu, env):
        raise NotImplementedError()

    def set_static_char_field(self, mu, env):
        raise NotImplementedError()

    def set_static_short_field(self, mu, env):
        raise NotImplementedError()

    def set_static_int_field(self, mu, env):
        raise NotImplementedError()

    def set_static_long_field(
        self, mu, env, clazz_idx, field_id, _, value_l, value_h
    ):
        # 注意，由于刚好第四个参数是8个字节，arm32不会使用R3作为寄存器传递参数了，而是跳过R3直接使用栈，
        value = value_h << 32 | value_l
        logger.info(
            "JNIEnv->set_static_long_field (%u, %u, 0x%016X)"
            % (clazz_idx, field_id, value)
        )
        clazz = self.get_reference(clazz_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        field = pyclazz.find_field_by_id(field_id)
        # FIXME: 对field支持还不完善，非stativ value无法设置，需要改进
        field.static_value = value

    def set_static_float_field(self, mu, env):
        raise NotImplementedError()

    def set_static_double_field(self, mu, env):
        raise NotImplementedError()

    def new_string(self, mu, env):
        raise NotImplementedError()

    def get_string_length(self, mu, env):
        raise NotImplementedError()

    def get_string_chars(self, mu, env):
        raise NotImplementedError()

    def release_string_chars(self, mu, env):
        raise NotImplementedError()

    def new_string_utf(self, mu, env, utf8_ptr):
        logger.debug("JNIEnv->NewStringUtf(%x) was called" % utf8_ptr)
        pystr = memory_helpers.read_utf8(mu, utf8_ptr)
        logger.debug("JNIEnv->NewStringUtf(%s) was called" % pystr)
        string = String(pystr)
        idx = self.add_local_reference(jobject(string))
        logger.debug("JNIEnv->NewStringUtf(%s) return id(%d)" % (pystr, idx))
        return idx

    def get_string_utf_length(self, mu, env, string):

        str_ref = self.get_reference(string)
        str_obj = str_ref.value
        if str_obj == JAVA_NULL:
            return 0

        str_val = str_obj.get_py_string()
        return len(str_val)

    def get_string_utf_chars(self, mu, env, string, is_copy_ptr):
        logger.debug(
            "JNIEnv->GetStringUtfChars(%u, %x) was called"
            % (string, is_copy_ptr)
        )

        str_ref = self.get_reference(string)
        str_obj = str_ref.value
        if str_obj == JAVA_NULL:
            return JAVA_NULL

        str_val = str_obj.get_py_string()
        # FIXME use malloc
        str_ptr = self._emu.memory.map(
            0, len(str_val) + 1, UC_PROT_READ | UC_PROT_WRITE
        )

        if is_copy_ptr != 0:
            # TODO 观察行为,真机总是返回true,但是根据文档,返回false应该也没问题
            # https://stackoverflow.com/questions/30992989/is-iscopy-field-always-necessary-in-android
            mu.mem_write(is_copy_ptr, int(0).to_bytes(1, byteorder="little"))

        memory_helpers.write_utf8(mu, str_ptr, str_val)

        return str_ptr

    def release_string_utf_chars(self, mu, env, string, utf8_ptr):

        pystr = memory_helpers.read_utf8(mu, utf8_ptr)
        logger.debug(
            "JNIEnv->ReleaseStringUtfChars(%u, %s) was called"
            % (string, pystr)
        )
        if utf8_ptr != 0:
            self._emu.memory.unmap(utf8_ptr, len(pystr) + 1)

    def get_array_length(self, mu, env, array):
        logger.debug("JNIEnv->GetArrayLength(%u) was called" % array)

        obj = self.get_reference(array)

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        return len(pyobj)

    def new_object_array(self, mu, env, size, class_idx, obj_init):
        logger.debug(
            "JNIEnv->NewObjectArray(%d, %u, %r) was called"
            % (size, class_idx, obj_init)
        )
        clazz = self.get_reference(class_idx)

        if not isinstance(clazz, jclass):
            raise ValueError("Expected a jclass.")

        class_obj = clazz.value

        pyclazz = class_obj.get_py_clazz()

        arr_item_cls_name = pyclazz.jvm_name

        pyarr = []
        for i in range(0, size):
            pyarr.append(JAVA_NULL)

        if obj_init != JAVA_NULL:
            obj = self.get_reference(obj_init)
            pyobj = self.jobject_to_pyobject(obj)
            pyarr[0] = pyobj

        new_jvm_name = ""
        # FIXME check if is array
        if arr_item_cls_name[0] == "[":
            new_jvm_name = "[%s" % arr_item_cls_name

        else:
            new_jvm_name = "[L%s;" % arr_item_cls_name

        pyarray_clazz = self._class_loader.find_class_by_name(new_jvm_name)
        if pyarray_clazz is None:
            raise RuntimeError(
                "NewObjectArray Array Class %s not found" % new_jvm_name
            )

        arr = pyarray_clazz(pyarr)
        return self.add_local_reference(jobject(arr))

    def get_object_array_element(self, mu, env, array_idx, item_idx):
        logger.debug(
            "JNIEnv->GetObjectArrayElement(%u, %u) was called"
            % (array_idx, item_idx)
        )

        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        pyobj_item = array_pyobj[item_idx]
        if pyobj_item == JAVA_NULL:
            return JAVA_NULL
        return self.add_local_reference(jobject(pyobj_item))

    def set_object_array_element(self, mu, env, array_idx, index, obj_idx):
        logger.debug(
            "JNIEnv->SetObjectArrayElement(%u, %u, %u) was called"
            % (array_idx, index, obj_idx)
        )
        array_obj = self.get_reference(array_idx)

        array_pyobj = JNIEnv.jobject_to_pyobject(array_obj)
        obj = self.get_reference(obj_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        array_pyobj[index] = pyobj

    def new_boolean_array(self, mu, env):
        raise NotImplementedError()

    def new_byte_array(self, mu, env, bytelen):
        logger.debug("JNIEnv->NewByteArray(%u) was called" % bytelen)
        barr = bytearray([0] * bytelen)
        arr = Array(barr)
        return self.add_local_reference(jobject(arr))

    def new_char_array(self, mu, env):
        raise NotImplementedError()

    def new_short_array(self, mu, env):
        raise NotImplementedError()

    def new_int_array(self, mu, env):
        raise NotImplementedError()

    def new_long_array(self, mu, env):
        raise NotImplementedError()

    def new_float_array(self, mu, env):
        raise NotImplementedError()

    def new_double_array(self, mu, env):
        raise NotImplementedError()

    def get_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_byte_array_elements(self, mu, env, array_idx, is_copy_ptr):
        logger.debug(
            "JNIEnv->get_byte_array_elements(%u, %u) was called"
            % (array_idx, is_copy_ptr)
        )

        if is_copy_ptr != 0:
            raise NotImplementedError()

        obj = self.get_reference(array_idx)
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        items = pyobj.get_py_items()
        items_len = len(items)
        extra_n = 4
        # FIXME use malloc
        buf = self._emu.memory.map(
            0, extra_n + items_len, UC_PROT_READ | UC_PROT_WRITE
        )

        logger.debug(f"=> {short_bytes_repr(items)}")

        # 协议约定前四个字节必定是长度
        mu.mem_write(buf, items_len.to_bytes(extra_n, "little"))
        b = bytes(items)
        mu.mem_write(buf + extra_n, b)
        return buf + extra_n

    def get_char_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_short_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_int_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_long_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_float_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_double_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_boolean_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_byte_array_elements(self, mu, env, array_idx, elems, mode):
        if elems == JAVA_NULL:
            return

        # 前四个字节必为长度
        logger.debug(
            "JNIEnv->ReleaseByteArrayElements(%u, %u, %u) was called"
            % (array_idx, elems, mode)
        )
        true_buf = elems - 4
        b = mu.mem_read(true_buf, 4)
        elems_sz = int.from_bytes(b, byteorder="little", signed=False)
        self._emu.memory.unmap(true_buf, elems_sz + 4)

    def release_char_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_short_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_int_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_long_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_float_array_elements(self, mu, env):
        raise NotImplementedError()

    def release_double_array_elements(self, mu, env):
        raise NotImplementedError()

    def get_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    def get_byte_array_region(
        self, mu, env, array_idx, start, len_in, buf_ptr
    ):
        logger.debug(
            "JNIEnv->GetByteArrayRegion(%u, %u, %u, 0x%x) was called"
            % (array_idx, start, len_in, buf_ptr)
        )

        obj = self.get_reference(array_idx)
        """
        if not isinstance(obj, jbyteArray):
            raise ValueError('Expected a jbyteArray.')
        """
        pyobj = JNIEnv.jobject_to_pyobject(obj)
        barr = pyobj.get_py_items()
        mu.mem_write(buf_ptr, bytes(barr[start: start + len_in]))

        return None

    def get_char_array_region(self, mu, env):
        raise NotImplementedError()

    def get_short_array_region(self, mu, env):
        raise NotImplementedError()

    def get_int_array_region(self, mu, env):
        raise NotImplementedError()

    def get_long_array_region(self, mu, env):
        raise NotImplementedError()

    def get_float_array_region(self, mu, env):
        raise NotImplementedError()

    def get_double_array_region(self, mu, env):
        raise NotImplementedError()

    def set_boolean_array_region(self, mu, env):
        raise NotImplementedError()

    def set_byte_array_region(
        self, mu, env, arrayJREF, startIndex, length, bufAddress
    ):
        string = memory_helpers.read_byte_array(mu, bufAddress, length)
        logger.debug("JNIEnv->SetByteArrayRegion was called")
        arr = Array(string)
        self.set_local_reference(arrayJREF, jobject(arr))

    def set_char_array_region(self, mu, env):
        raise NotImplementedError()

    def set_short_array_region(self, mu, env):
        raise NotImplementedError()

    def set_int_array_region(self, mu, env):
        raise NotImplementedError()

    def set_long_array_region(self, mu, env):
        raise NotImplementedError()

    def set_float_array_region(self, mu, env):
        raise NotImplementedError()

    def set_double_array_region(self, mu, env):
        raise NotImplementedError()

    def register_natives(self, mu, env, clazz_id, methods, methods_count):
        logger.debug(
            "JNIEnv->RegisterNatives(%d, 0x%08X, %d) was called"
            % (clazz_id, methods, methods_count)
        )

        clazz = self.get_reference(clazz_id)

        if not isinstance(clazz, jclass):
            raise ValueError(
                "Expected a jclass but type %r value %r getted."
                % (type(clazz), clazz)
            )

        class_obj = clazz.value
        pyclazz = class_obj.get_py_clazz()
        ptr_sz = self._emu.get_ptr_size()

        for i in range(0, methods_count):
            ptr_name = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods, ptr_sz
            )
            ptr_sign = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods + ptr_sz, ptr_sz
            )
            ptr_func = memory_helpers.read_ptr_sz(
                mu, (i * 3 * ptr_sz) + methods + 2 * ptr_sz, ptr_sz
            )

            name = memory_helpers.read_utf8(mu, ptr_name)
            signature = memory_helpers.read_utf8(mu, ptr_sign)

            pyclazz.register_native(name, signature, ptr_func)

        return JNI_OK

    def unregister_natives(self, mu, env):
        raise NotImplementedError()

    def monitor_enter(self, mu, env):
        raise NotImplementedError()

    def monitor_exit(self, mu, env):
        raise NotImplementedError()

    def get_java_vm(self, mu, env, vm):
        logger.debug("JNIEnv->GetJavaVM(0x%08x) was called" % vm)

        mu.mem_write(
            vm, self._emu.java_vm.address_ptr.to_bytes(4, byteorder="little")
        )

        return JNI_OK

    def get_string_region(self, mu, env):
        raise NotImplementedError()

    def get_string_utf_region(self, mu, env):
        raise NotImplementedError()

    def get_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    def release_primitive_array_critical(self, mu, env):
        raise NotImplementedError()

    def get_string_critical(self, mu, env):
        raise NotImplementedError()

    def release_string_critical(self, mu, env):
        raise NotImplementedError()

    def new_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    def delete_weak_global_ref(self, mu, env):
        raise NotImplementedError()

    def exception_check(self, mu, env):
        """
        Returns JNI_TRUE when there is a pending exception; otherwise, returns JNI_FALSE.
        """
        return JNI_TRUE if self._java_vm.get_exception() else JNI_FALSE

    def new_direct_byte_buffer(self, mu, env):
        raise NotImplementedError()

    def get_direct_buffer_address(self, mu, env):
        raise NotImplementedError()

    def get_direct_buffer_capacity(self, mu, env):
        raise NotImplementedError()

    def get_object_ref_type(self, mu, env):
        raise NotImplementedError()
