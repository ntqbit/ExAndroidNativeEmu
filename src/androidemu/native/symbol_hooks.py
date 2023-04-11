import random

import verboselogs

from androidemu.java.helpers.native_method import native_method
from androidemu.const.emu_const import Arch
from androidemu.native.asset_mgr_hooks import AssetManagerHooks
from androidemu.utils import memory_helpers

from unicorn.unicorn_const import UC_PROT_READ, UC_PROT_WRITE

logger = verboselogs.VerboseLogger(__name__)


class SymbolHooks:
    def __init__(self, emu, modules, hooker, vfs_root):
        self._emu = emu
        self._modules = modules
        self._vfs_root = vfs_root
        self._thread_id = 32145

        modules.add_symbol_hook("__system_property_get", hooker.write_function(self.system_property_get))
        modules.add_symbol_hook("dlopen", hooker.write_function(self.dlopen))
        modules.add_symbol_hook("dlclose", hooker.write_function(self.dlclose))
        modules.add_symbol_hook("dladdr", hooker.write_function(self.dladdr))
        modules.add_symbol_hook("dlsym", hooker.write_function(self.dlsym))
        modules.add_symbol_hook("dl_unwind_find_exidx", hooker.write_function(self.dl_unwind_find_exidx))

        if not emu.get_muti_task_support():
            modules.add_symbol_hook("pthread_create", hooker.write_function(self.pthread_create))
            modules.add_symbol_hook("pthread_join", hooker.write_function(self.pthread_join))
            modules.add_symbol_hook("pthread_detach", hooker.write_function(self.pthread_detach))

        modules.add_symbol_hook("rand", hooker.write_function(self.rand))
        modules.add_symbol_hook("newlocale", hooker.write_function(self.newlocale))

        modules.add_symbol_hook("abort", hooker.write_function(self.abort))
        modules.add_symbol_hook("dlerror", hooker.write_function(self.nop("dlerror")))

        asset_hooks = AssetManagerHooks(emu, modules, hooker, vfs_root)
        asset_hooks.register()

    @native_method
    def system_property_get(self, mu, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.debug("Called __system_property_get(%s, 0x%x)", name, buf_ptr)

        if name in self._emu.system_properties:
            p = self._emu.system_properties[name]
            nread = len(p)
            memory_helpers.write_utf8(mu, buf_ptr, p)
            return nread
        else:
            logger.error("%s was not found in system_properties dictionary.", name)

        return 0

    @native_method
    def dlopen(self, mu, path_str):
        path = memory_helpers.read_utf8(mu, path_str)
        logger.debug("Called dlopen(%s)", path)

        r = 0
        if path.find("/") < 0:
            for mod in self._modules._modules:
                if mod.filename.find(path) > -1:
                    r = mod.soinfo_ptr
                    logger.debug("Called dlopen(%s) return 0x%08x", path, r)
                    return r

        # redirect path on matter what path in vm runing
        fullpath = self._modules.find_so_on_disk(path)
        if fullpath is not None:
            mod = self._emu.load_library(fullpath)
            r = mod.soinfo_ptr
        else:
            # raise RuntimeError("dlopen %s not found"%path)
            logger.warning("dlopen %s not found", path)
            r = 0

        logger.debug("Called dlopen(%s) return 0x%08x", path, r)
        return r

    @native_method
    def dlclose(self, mu, handle):
        """
        The function dlclose() decrements the reference count on the dynamic library handle handle.
        If the reference count drops to zero and no other loaded libraries use symbols in it, then the dynamic library is unloaded.
        """
        logger.debug("Called dlclose(0x%x)", handle)
        return 0

    @native_method
    def dladdr(self, mu, addr, info_ptr):
        logger.debug("Called dladdr(0x%x, 0x%x)", addr, info_ptr)

        for mod in self._modules._modules:
            if mod.base <= addr < mod.base + mod.size:
                # FIXME: memory leak
                dli_fname = self._emu.memory.map(
                    0, len(mod.filename) + 1, UC_PROT_READ | UC_PROT_WRITE
                )
                memory_helpers.write_utf8(mu, dli_fname, mod.filename)
                memory_helpers.write_ptrs_sz(
                    mu,
                    info_ptr,
                    [dli_fname, mod.base, 0, 0],
                    self._emu.get_ptr_size(),
                )
                logger.debug("Called dladdr ok return path=%s base=0x%08x", mod.filename, mod.base)
                logger.warning(
                    "dladdr has memory leak, dli_fname can not free"
                )
                return 1

        logger.debug("Called dladdr not found: %s, 0x%X", mod.filename, mod.base)
        return 0

    @native_method
    def dlsym(self, mu, handle, symbol):
        symbol_str = memory_helpers.read_utf8(mu, symbol)
        logger.debug("Called dlsym(0x%x, %s)", handle, symbol_str)

        global_handle = 0xFFFFFFFF
        if self._emu.get_arch() == Arch.ARM64:
            global_handle = 0

        if handle == global_handle:
            sym = self._modules.find_symbol_str(symbol_str)
        else:
            soinfo = handle
            base = -1

            if self._emu.get_arch() == Arch.ARM64:
                base = memory_helpers.read_ptr_sz(
                    mu, soinfo + 152, self._emu.get_ptr_size()
                )
            else:
                # soinfo+140 offset of load base in soinfo on android 4.4
                base = memory_helpers.read_ptr_sz(
                    mu, soinfo + 140, self._emu.get_ptr_size()
                )

            module = self._modules.find_module(base)

            if module is None:
                raise Exception(f"Module not found for address 0x{symbol:x}")

            sym = module.find_symbol(symbol_str)

        if sym is None:
            r = 0
        else:
            r = sym

        logger.debug("Called dlsym(0x%x, %s) return 0x%08X", handle, symbol_str, r)
        return r

    @native_method
    def abort(self, mu):
        raise RuntimeError("abort called")
        self._emu.emu_stop()

    @native_method
    def dl_unwind_find_exidx(self, mu, pc, pcount_ptr):
        return 0

    @native_method
    def pthread_create(self, mu, pthread_t_ptr, attr, start_routine, arg):
        logger.warning("pthread_create called start_routine [0x%08X]", start_routine)

        mu.mem_write(
            pthread_t_ptr,
            int(self._thread_id).to_bytes(
                self._emu.get_ptr_size(), byteorder="little"
            ),
        )
        self._thread_id = self._thread_id + 1
        return 0

    @native_method
    def pthread_join(self, mu, pthread_t, retval):
        return 0

    @native_method
    def pthread_detach(self, mu, pthread_t):
        return 0

    @native_method
    def rand(self, mu):
        logger.info("rand call")
        r = random.randint(0, 0xFFFFFFFF)
        return r

    @native_method
    def newlocale(self, mu):
        logger.info("newlocale call return 0 skip")
        return 0

    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError(f"Symbol hook not implemented: {name}")

        return nop_inside
