import verboselogs
import os
import sys
from androidemu.hooker import Hooker
from androidemu.internal.modules import Modules

from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers, misc_utils
from androidemu.java.jni_env import JNIEnv
from unicorn import *

logger = verboselogs.VerboseLogger(__name__)


class AssetManagerHooks:
    def __init__(self, emu, modules, hooker, vfs_root):
        self._emu = emu
        self._modules = modules
        self._vfs_root = vfs_root
        self._hooker = hooker
        self._local_ptr_off = 0x98765432
        self._local_ptr_map = {}

        self._local_asset_ptr_off = 0x87654321
        self._local_asset_ptr_map = {}

    def register(self):
        self._modules.add_symbol_hook(
            "AAssetManager_fromJava",
            self._hooker.write_function(self._AAssetManager_fromJava),
        )
        self._modules.add_symbol_hook(
            "AAssetManager_open",
            self._hooker.write_function(self._AAssetManager_open),
        )
        self._modules.add_symbol_hook(
            "AAsset_close", self._hooker.write_function(self._AAsset_close)
        )
        self._modules.add_symbol_hook(
            "AAsset_read", self._hooker.write_function(self._AAsset_read)
        )
        self._modules.add_symbol_hook(
            "AAsset_getLength",
            self._hooker.write_function(self._AAsset_getLength),
        )

    @native_method
    def _AAssetManager_fromJava(self, uc, env_ptr, jobj_mgr_idx):
        logger.debug(
            "AAssetManager_fromJava call [0x%08X], [%d]"
            % (env_ptr, jobj_mgr_idx)
        )
        env_obj = self._emu.java_vm.jni_env
        assert (
            env_obj.address_ptr == env_ptr
        ), "ERROR input env_ptr != main_thread ptr, impossible for single thread program"

        obj = env_obj.get_reference(jobj_mgr_idx)

        pyobj = JNIEnv.jobject_to_pyobject(obj)
        zipf = pyobj.get_zip_file()
        self._local_ptr_map[self._local_ptr_off] = zipf
        r = self._local_ptr_off
        self._local_ptr_off = self._local_ptr_off + 1
        return r

    @native_method
    def _AAssetManager_open(self, uc, amgr_ptr, filename_ptr, mode):

        filename = memory_helpers.read_utf8(uc, filename_ptr)
        logger.debug(
            "AAssetManager_open call [0x%08X], [%s]" % (amgr_ptr, filename)
        )
        zipf = self._local_ptr_map[amgr_ptr]
        real_filename = "assets/%s" % filename
        zf = zipf.open(real_filename, mode="r")
        self._local_asset_ptr_map[self._local_asset_ptr_off] = (
            zf,
            real_filename,
            zipf,
        )
        r = self._local_asset_ptr_off
        self._local_asset_ptr_off = self._local_asset_ptr_off + 1

        return r

    @native_method
    def _AAsset_close(self, uc, asset_ptr):
        logger.debug("AAssetManager_close call [0x%08X]" % (asset_ptr,))
        asset_sa = self._local_asset_ptr_map.pop(asset_ptr)
        asset_obj = asset_sa[0]
        asset_obj.close()

    @native_method
    def _AAsset_read(self, uc, asset_ptr, buf_ptr, count):
        asset_sa = self._local_asset_ptr_map[asset_ptr]
        asset_obj = asset_sa[0]
        b = asset_obj.read(count)
        if b is None:
            # logger.error("AAsset_read return None...")
            raise RuntimeError("AAsset_read return None...")
            return -1

        n = len(b)
        uc.mem_write(buf_ptr, b)

        logger.debug(
            "AAsset_read call [0x%08X] [0x%08X] [%d] return [%d]"
            % (asset_ptr, buf_ptr, count, n)
        )
        return n

    @native_method
    def _AAsset_getLength(self, uc, asset_ptr):
        logger.debug("AAssetManager_getLength call [0x%08X]" % (asset_ptr))
        asset_sa = self._local_asset_ptr_map[asset_ptr]
        asset_filename = asset_sa[1]
        zipf = asset_sa[2]
        info = zipf.getinfo(asset_filename)
        n = info.file_size
        return n
