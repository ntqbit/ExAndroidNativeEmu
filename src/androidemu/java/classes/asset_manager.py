import zipfile

from androidemu.java.java_class_def import JavaClassDef


class AssetManager(
    metaclass=JavaClassDef, jvm_name="android/content/res/AssetManager"
):
    def __init__(self, emu, pyapk_path):
        self._py_apk_path = pyapk_path
        real_apk_path = emu.vfs.translate_path(pyapk_path)
        self._zip_file = zipfile.ZipFile(real_apk_path, "r")

    def get_zip_file(self):
        return self._zip_file
