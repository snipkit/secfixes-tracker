import os
import logging
from ctypes import cdll, c_char_p, c_int

VersionUnknown = 0
VersionEqual = 1
VersionLess = 2
VersionGreater = 4
VersionFuzzy = 8

logger = logging.getLogger("APKVersion")
logging.basicConfig(level=logging.WARNING)

def _load_libapk():
    lib_path = os.getenv("APK_LIB_PATH")
    lib_names = [lib_path] if lib_path else [
        'libapk.so.2.14.0',
        'libapk.so.2',
        'libapk.so',
    ]
    for name in lib_names:
        if name is None:
            continue
        try:
            lib = cdll.LoadLibrary(name)
            lib.apk_version_compare.argtypes = [c_char_p, c_char_p]
            lib.apk_version_compare.restype = c_int
            logger.info(f"Loaded libapk from {name}")
            return lib
        except OSError:
            logger.debug(f"Failed to load {name}")
    logger.warning(f"Could not find libapk library ({lib_names}).")
    return None

libapk = _load_libapk()

class APKVersionError(Exception):
    pass

def _compare(ver1: str, ver2: str, ops: int, fuzzy: bool = False) -> bool:
    if libapk is None:
        raise APKVersionError("libapk is not loaded. Cannot compare versions.")
    result = libapk.apk_version_compare(ver1.encode('ascii'), ver2.encode('ascii'))
    return (result & ops) != 0 if fuzzy else (result & ops) == ops

class APKVersion:
    def __init__(self, version: str):
        if not isinstance(version, str):
            raise TypeError("version must be a string")
        self.version = version

    def __repr__(self):
        return f"<APKVersion {self.version}>"

    def _ensure_version(self, other):
        if isinstance(other, APKVersion):
            return other.version
        elif isinstance(other, str):
            return other
        else:
            raise TypeError(f"Cannot compare APKVersion with {type(other)}")

    def __eq__(self, other):
        try:
            other_version = self._ensure_version(other)
            return _compare(self.version, other_version, VersionEqual)
        except APKVersionError:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        other_version = self._ensure_version(other)
        return _compare(self.version, other_version, VersionLess)

    def __le__(self, other):
        other_version = self._ensure_version(other)
        return _compare(self.version, other_version, VersionLess | VersionEqual, fuzzy=True)

    def __gt__(self, other):
        other_version = self._ensure_version(other)
        return _compare(self.version, other_version, VersionGreater)

    def __ge__(self, other):
        other_version = self._ensure_version(other)
        return _compare(self.version, other_version, VersionGreater | VersionEqual, fuzzy=True)
