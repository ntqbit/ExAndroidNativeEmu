import verboselogs

from androidemu.java.helpers.native_method import native_method
from androidemu.java.jni_const import JNI_OK
from androidemu.java.jni_env import JNIEnv
from androidemu.java.jni_ref import jthrowable

logger = verboselogs.VerboseLogger(__name__)


# https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html
# This class attempts to mimic the JNIInvokeInterface table.
class JavaVM:
    """
    :type class_loader JavaClassLoader
    :type hooker Hooker
    """

    def __init__(self, emu, class_loader, hooker):
        (self.address_ptr, self.address) = hooker.write_function_table(
            {
                3: self.destroy_java_vm,
                4: self.attach_current_thread,
                5: self.detach_current_thread,
                6: self.get_env,
                7: self.attach_current_thread,
            }
        )

        self.jni_env = JNIEnv(emu, self, class_loader, hooker)
        self._exception = None
        self._emu = emu

    def throw(self, exception):
        self._exception = jthrowable(exception)

    def get_exception(self):
        return self._exception

    def set_exception(self, exception):
        self._exception = exception

    def clear_exception(self):
        self._exception = None

    @native_method
    def destroy_java_vm(self, mu):
        raise NotImplementedError()

    @native_method
    def attach_current_thread(self, mu, java_vm, env_ptr, thr_args):
        logger.debug(
            "JavaVM->AttachCurrentThread(0x%08x, 0x%08x, 0x%08x)"
            % (java_vm, env_ptr, thr_args)
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self._emu.get_ptr_size(), "little"
            ),
        )
        return JNI_OK

    @native_method
    def detach_current_thread(self, mu, java_vm):
        # TODO: NooOO idea.
        logger.debug("JavaVM->DetachCurrentThread(0x%08x)", java_vm)
        return JNI_OK

    @native_method
    def get_env(self, mu, java_vm, env_ptr, version):
        logger.debug(
            "JavaVM->GetEnv(0x%08x, 0x%08x, 0x%08x)"
            % (java_vm, env_ptr, version)
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self._emu.get_ptr_size(), "little"
            ),
        )
        return JNI_OK

    @native_method
    def attach_current_thread_as_daemon(self, mu, java_vm, env_ptr, thr_args):
        logger.debug(
            "JavaVM->AttachCurrentThreadAsDaemon(0x%08x, 0x%08x, 0x%08x)"
            % (java_vm, env_ptr, thr_args)
        )
        mu.mem_write(
            env_ptr,
            self.jni_env.address_ptr.to_bytes(
                self._emu.get_ptr_size(), "little"
            ),
        )
        return JNI_OK
