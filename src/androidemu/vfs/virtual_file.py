class VirtualFile:
    def __init__(self, name, file_descriptor, name_in_system=None):
        self._name = name
        self._name_in_system = name_in_system
        self._descriptor = file_descriptor

    def __repr__(self):
        return f"VirtualFile(name={self._name},name_in_system={self._name_in_system},descriptor={self._descriptor})"

    def get_name(self):
        return self._name

    def get_name_in_system(self):
        return self._name_in_system

    def get_descriptor(self):
        return self._descriptor
