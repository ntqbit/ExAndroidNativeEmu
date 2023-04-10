import os
import platform

from unicorn.unicorn_const import (
    UC_PROT_NONE,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_PROT_ALL,
)
from unicorn.arm_const import UC_ARM_REG_C13_C0_3
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0

from androidemu.const import emu_const


IS_WINDOWS = platform.system() == "Windows"


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


def set_errno(emu, errno):
    mu = emu.mu
    if emu.get_arch() == emu_const.Arch.ARM32:
        err_ptr = mu.reg_reg(UC_ARM_REG_C13_C0_3) + 8
        mu.mem_write(err_ptr, int(errno).to_bytes(4, byteorder="little"))

    else:
        err_ptr = mu.reg_write(UC_ARM64_REG_TPIDR_EL0) + 16
        # errno 是int，只写四个字节
        mu.mem_write(err_ptr, int(errno).to_bytes(4, byteorder="little"))
