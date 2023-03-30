from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_field_def import JavaFieldDef
from androidemu.java.java_method_def import java_method_def, JavaMethodDef
from androidemu.java.constant_values import *
from androidemu.utils import misc_utils
from androidemu.java.classes.string import String

import zipfile


class AssetManager(
        metaclass=JavaClassDef,
        jvm_name='android/content/res/AssetManager'):
    def __init__(self, emu, pyapk_path):
        self._py_apk_path = pyapk_path
        vfs_root = emu.get_vfs_root()
        real_apk_path = misc_utils.vfs_path_to_system_path(
            vfs_root, pyapk_path)
        self._zip_file = zipfile.ZipFile(real_apk_path, 'r')
        # print(111)

    def get_zip_file(self):
        return self._zip_file
