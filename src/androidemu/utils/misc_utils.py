import os
import platform

import verboselogs

from unicorn.unicorn_const import (
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_PROT_ALL,
)
from unicorn.arm_const import UC_ARM_REG_C13_C0_3
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0

from androidemu.const.emu_const import Arch

logger = verboselogs.VerboseLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


def format_addr(emu, address):
    map_file = emu.memory.get_map_file(address)
    if map_file:
        file_name = map_file['vf'].get_name()
        addr_name = os.path.basename(file_name)
        rva = address - map_file['start']
        return f'0x{address:08X} ({addr_name}!0x{rva:X})'

    return f'0x{address:08X}'


def vfs_path_to_system_path(vfs_root, path):
    if os.name == "nt":
        path = path.replace(":", "_")

    fullpath = "%s/%s" % (vfs_root, path)
    return fullpath


def system_path_to_vfs_path(vfs_root, path):
    return "/" + os.path.relpath(path, vfs_root)


PF_R = 0x4  # Readable
PF_W = 0x2  # Writable
PF_X = 0x1  # Executable


def get_segment_protection(prot_in):
    prot = UC_PROT_NONE

    if prot_in & PF_R != 0:
        prot |= UC_PROT_READ

    if prot_in & PF_W != 0:
        prot |= UC_PROT_WRITE

    if prot_in & PF_X != 0:
        prot |= UC_PROT_EXEC

    if prot == UC_PROT_NONE:
        return UC_PROT_ALL

    return prot


def platform_open(fd, flag):
    if IS_WINDOWS:
        flag = flag | getattr(os, 'O_BINARY')

    return os.open(fd, flag)


def get_bionic_tls_address(emu) -> int:
    if emu.get_arch() == Arch.ARM32:
        return emu.mu.reg_read(UC_ARM_REG_C13_C0_3)
    else:
        return emu.mu.reg_read(UC_ARM64_REG_TPIDR_EL0)


def get_bionic_tls_slot(emu, slot: int) -> int:
    tls_ptr = get_bionic_tls_address(emu)

    if emu.get_arch() == Arch.ARM32:
        wordsize = 4
    else:
        wordsize = 8

    return int.from_bytes(emu.mu.mem_read(tls_ptr + wordsize * slot, wordsize), 'little')


MIN_TLS_SLOT = 0

TLS_SLOT_SELF = 0
TLS_SLOT_THREAD_ID = 1
TLS_SLOT_APP = 2
TLS_SLOT_OPENGL = 3
TLS_SLOT_OPENGL_API = 4
TLS_SLOT_STACK_GUARD = 5
TLS_SLOT_SANITIZER = 6
TLS_SLOT_ART_THREAD_SELF = 7
TLS_SLOT_DTV = 8
TLS_SLOT_BIONIC_TLS = 9
MAX_TLS_SLOT = 9


# Gets pthread_internal_t bionic structure address
def get_pthread_internal_addr(emu) -> int:
    return get_bionic_tls_slot(emu, TLS_SLOT_THREAD_ID)


def get_errno_address(emu) -> int:
    if emu.get_arch() == Arch.ARM32:
        errno_value_offset = 0x298
    else:
        # Just find the offset of `errno_value` field in pthread_internal_t structure.
        raise NotImplementedError()

    return get_pthread_internal_addr(emu) + errno_value_offset


def get_errno(emu) -> int:
    errno_value_address = get_errno_address(emu)
    return int.from_bytes(emu.mu.mem_read(errno_value_address, 4), 'little')


def set_errno(emu, errno: int):
    errno_value_address = get_errno_address(emu)
    emu.mu.mem_write(errno_value_address, errno.to_bytes(4, 'little'))
