from typing import List, Union

from keystone import (
    Ks,
    KS_ARCH_ARM,
    KS_ARCH_ARM64,
    KS_MODE_ARM,
    KS_MODE_THUMB,
    KS_MODE_LITTLE_ENDIAN
)

ks_arm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
ks_arm64 = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)


def asm(instr: Union[str, List[str]], address=0) -> bytes:
    return _asm(ks_arm, instr, address)


def asm_thumb(instr: Union[str, List[str]], address=0) -> bytes:
    return _asm(ks_thumb, instr, address)


def asm64(instr: Union[str, List[str]], address=0) -> bytes:
    return _asm(ks_arm64, instr, address)


def _asm(ks: Ks, instr: Union[str, List[str]], address=0) -> bytes:
    if isinstance(instr, list):
        instr = '\n'.join(instr)

    assert isinstance(instr, str)

    return ks.asm(instr, address, True)[0]
