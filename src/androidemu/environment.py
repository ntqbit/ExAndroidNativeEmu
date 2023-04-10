from typing import Dict, List, Optional


class AndroidPackageSignature:
    def __init__(self, sig_bytes):
        self._bytes = sig_bytes

    def getBytes(self) -> bytes:
        return self._bytes


class AndroidPackage:
    def __init__(self,
                 package_name: str = None,
                 version_code: int = 0,
                 version_name: str = None,
                 signatures: List[AndroidPackageSignature] = [],
                 installer_package_name: str = None
                 ):
        self.package_name = package_name
        self.version_code = version_code
        self.version_name = version_name
        self.signatures = signatures
        self.installer_package_name = installer_package_name

    def get_version_code(self) -> int:
        return self.version_code

    def get_package_name(self) -> str:
        return self.package_name

    def get_signatures(self) -> List[AndroidPackageSignature]:
        return self.signatures

    def get_installer_package_name(self) -> str:
        return self.installer_package_name


class Environment:
    def __init__(self):
        self.package_name = None
        self.packages: Dict[str, AndroidPackage] = {}
        self.uid = 1

    def add_package(self, package: AndroidPackage):
        self.packages[package.get_package_name()] = package

    def get_package_name(self):
        return self.package_name

    def get_process_name(self):
        return self.package_name

    def find_package_by_name(self, package_name: str) -> Optional[AndroidPackage]:
        return self.packages.get(package_name)

    def get_uid(self):
        return self.uid
