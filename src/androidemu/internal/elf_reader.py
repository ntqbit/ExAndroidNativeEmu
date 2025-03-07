import struct
import os

import verboselogs

from androidemu.utils import memory_helpers

logger = verboselogs.VerboseLogger(__name__)

PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6


DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 0x0C
DT_INIT_ARRAY = 0x19
DT_FINI_ARRAY = 0x1A
DT_INIT_ARRAYSZ = 0x1B
DT_FINI_ARRAYSZ = 0x1C
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_RELRSZ = 35
DT_RELR = 36
DT_RELRENT = 37
DT_GNU_HASH = 0x6FFFFEF5
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7FFFFFFF
DT_ANDROID_RELR = 0x6fffe000
DT_ANDROID_RELRSZ = 0x6fffe001
DT_ANDROID_RELRENT = 0x6fffe003
DT_ANDROID_RELRCOUNT = 0x6fffe005

SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHN_LOPROC = 0xFF00
SHN_HIPROC = 0xFF1F
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_HIRESERVE = 0xFFFF
SHN_MIPS_ACCOMON = 0xFF00

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4


class ELFReader:
    @staticmethod
    def _elf32_r_sym(x):
        return x >> 8

    @staticmethod
    def _elf32_r_type(x):
        return x & 0xFF

    @staticmethod
    def _elf64_r_sym(x):
        return x >> 32

    @staticmethod
    def _elf64_r_type(x):
        return x & 0xFFFFFFFF

    # define ELF_ST_BIND(x)	((x) >> 4)
    # define ELF_ST_TYPE(x)	(((unsigned int) x) & 0xf)

    @staticmethod
    def __elf_st_bind(x):
        return x >> 4

    @staticmethod
    def __elf_st_type(x):
        return x & 0xF

    @staticmethod
    def check_elf32(filename):
        with open(filename, "rb") as f:
            f.seek(0x4, os.SEEK_SET)
            buf = f.read(1)
            return buf[0] == 1

    def _st_name_to_name(self, st_name):
        assert (
            st_name < self._dyn_str_sz
        ), "__st_name_to_name st_name %d out of range %d" % (
            st_name,
            self._dyn_str_sz,
        )
        endId = self._dyn_str_buf.find(b"\x00", st_name)
        r = self._dyn_str_buf[st_name:endId]
        name = r.decode("utf-8")
        return name

    def __init__(self, filename):

        with open(filename, "rb") as f:
            is_elf32 = ELFReader.check_elf32(filename)
            self._is_elf32 = is_elf32

            if is_elf32:
                ehdr_sz = 52
                phdr_sz = 32
                elf_dyn_sz = 8
                elf_sym_sz = 16
                elf_rel_sz = 8
                elf_r_sym = ELFReader._elf32_r_sym
                elf_r_type = ELFReader._elf32_r_type
                edhr_pattern = "<16sHHIIIIIHHHHHH"
                phdr_pattern = "<IIIIIIII"
                dyn_pattern = "<II"
                sym_pattern = "<IIIccH"
                rel_pattern = "<II"
            else:
                ehdr_sz = 64
                phdr_sz = 56
                elf_dyn_sz = 16
                elf_sym_sz = 24
                elf_rel_sz = 24
                elf_r_sym = ELFReader._elf64_r_sym
                elf_r_type = ELFReader._elf64_r_type
                edhr_pattern = "<16sHHIQQQIHHHHHH"
                phdr_pattern = "<IIQQQQQQ"
                dyn_pattern = "<QQ"
                sym_pattern = "<IccHQQ"
                rel_pattern = "<QQq"

            self._filename = filename
            self._init_array_addr = 0
            self._init_array_size = 0
            self._init_addr = 0
            self._nbucket = 0
            self._nchain = 0
            self._bucket_addr = 0
            self._chain_addr = 0
            self._plt_got_addr = 0

            self._phdrs = []
            self._loads = []
            self._so_needed = []
            self._dynsymols = []
            self._rels = {}
            self._file = f
            ehdr_bytes = f.read(ehdr_sz)
            (
                _,
                _,
                _,
                _,
                self._entry_point,
                phoff,
                _,
                _,
                _,
                phdr_ent_size,
                phdr_num,
                _,
                _,
                _,
            ) = struct.unpack(edhr_pattern, ehdr_bytes)

            self._phoff = phoff
            self._phdr_num = phdr_num
            self._phdr_entry_size = phdr_ent_size
            f.seek(phoff, 0)

            dyn_off = 0
            dyn_addr = 0
            self._sz = 0
            for i in range(0, phdr_num):
                phdr_bytes = f.read(phdr_sz)
                # 32与64的phdr结构体顺序有区别
                if is_elf32:
                    (
                        p_type,
                        p_offset,
                        p_vaddr,
                        p_paddr,
                        p_filesz,
                        p_memsz,
                        p_flags,
                        p_align,
                    ) = struct.unpack(phdr_pattern, phdr_bytes)
                else:  # 64
                    (
                        p_type,
                        p_flags,
                        p_offset,
                        p_vaddr,
                        p_paddr,
                        p_filesz,
                        p_memsz,
                        p_align,
                    ) = struct.unpack(phdr_pattern, phdr_bytes)

                phdr = {
                    "p_type": p_type,
                    "p_offset": p_offset,
                    "p_vaddr": p_vaddr,
                    "p_paddr": p_paddr,
                    "p_filesz": p_filesz,
                    "p_memsz": p_memsz,
                    "p_flags": p_flags,
                    "p_align": p_align,
                }
                self._phdrs.append(phdr)
                if p_type == PT_DYNAMIC:
                    dyn_off = p_offset
                    dyn_addr = p_vaddr

                elif p_type == PT_LOAD:
                    self._loads.append(phdr)

                self._sz += p_memsz

            assert dyn_off > 0, "error no dynamic in this elf."
            self._dyn_addr = dyn_addr
            f.seek(dyn_off, 0)
            dyn_str_addr = 0
            dyn_str_sz = 0
            self._dyn_str_buf = b""
            dyn_sym_addr = 0
            nsymbol = -1
            rel_addr = 0
            rel_count = 0
            relr_addr = 0
            relr_size = 0
            elf_relr_ent_sz = 0
            relplt_addr = 0
            relplt_count = 0
            dt_needed = []

            bias = self._loads[0]["p_vaddr"] - self._loads[0]["p_offset"]
            while True:
                dyn_item_bytes = f.read(elf_dyn_sz)
                d_tag, d_val_ptr = struct.unpack(dyn_pattern, dyn_item_bytes)
                if d_tag == DT_NULL:
                    break

                # REL
                if d_tag == DT_RELA:
                    assert not is_elf32, "get DT_RELA when parsing elf64 impossible in android"
                    rel_addr = d_val_ptr
                elif d_tag == DT_RELASZ:
                    rel_count = int(d_val_ptr / elf_rel_sz)

                # REL
                elif d_tag == DT_REL:
                    assert is_elf32, "get DT_REL when parsing elf32 impossible in android"
                    rel_addr = d_val_ptr
                elif d_tag == DT_RELSZ:
                    rel_count = int(d_val_ptr / elf_rel_sz)

                # RELR
                elif d_tag in (DT_RELR, DT_ANDROID_RELR):
                    relr_addr = d_val_ptr
                elif d_tag in (DT_RELRSZ, DT_ANDROID_RELRSZ):
                    relr_size = d_val_ptr
                elif d_tag in (DT_RELRENT, DT_ANDROID_RELRENT):
                    elf_relr_ent_sz = d_val_ptr

                # JMPREL
                elif d_tag == DT_JMPREL:
                    relplt_addr = d_val_ptr
                elif d_tag == DT_PLTRELSZ:
                    relplt_count = int(d_val_ptr / elf_rel_sz)

                elif d_tag == DT_SYMTAB:
                    dyn_sym_addr = d_val_ptr

                elif d_tag == DT_STRTAB:
                    dyn_str_addr = d_val_ptr

                elif d_tag == DT_STRSZ:
                    dyn_str_sz = d_val_ptr

                elif d_tag == DT_HASH:
                    n = f.tell()
                    f.seek(d_val_ptr - bias, 0)
                    hash_heads = f.read(8)
                    f.seek(n, 0)
                    self._nbucket, self._nchain = struct.unpack("<II", hash_heads)
                    self._bucket_addr = d_val_ptr + 8
                    self._chain_addr = d_val_ptr + 8 + self._nbucket * 4
                    nsymbol = self._nchain

                elif d_tag == DT_GNU_HASH:
                    # https://flapenguin.me/elf-dt-gnu-hash
                    ori = f.tell()
                    f.seek(d_val_ptr - bias, 0)
                    hash_heads = f.read(16)
                    f.seek(ori, 0)
                    (
                        gnu_nbucket_,
                        symoffset,
                        gnu_maskwords_,
                        gnu_shift2_,
                    ) = struct.unpack("<IIII", hash_heads)
                    gnu_bloom_filter_ = d_val_ptr - bias + 16
                    if is_elf32:
                        gnu_bucket_ = gnu_bloom_filter_ + 4 * gnu_maskwords_
                    else:
                        gnu_bucket_ = gnu_bloom_filter_ + 8 * gnu_maskwords_

                    gnu_chain_ = gnu_bucket_ + 4 * gnu_nbucket_ - 4 * symoffset

                    # https://flapenguin.me/elf-dt-gnu-hash
                    maxbucket_symidx = 0
                    for bucket_id in range(0, gnu_nbucket_):
                        f.seek(gnu_bucket_ + 4 * bucket_id, 0)
                        nbytes = f.read(4)
                        symidx = int.from_bytes(nbytes, "little")
                        if symidx > maxbucket_symidx:
                            maxbucket_symidx = symidx

                    max_symid = maxbucket_symidx
                    while True:
                        f.seek(gnu_chain_ + 4 * max_symid, 0)
                        cbytes = f.read(4)
                        c = int.from_bytes(cbytes, "little")

                        if (c & 1) == 1:
                            break

                        max_symid = max_symid + 1

                    nsymbol = max_symid + 1
                    f.seek(ori, 0)

                elif d_tag == DT_INIT:
                    self._init_addr = d_val_ptr
                elif d_tag == DT_INIT_ARRAY:
                    self._init_array_addr = d_val_ptr
                elif d_tag == DT_INIT_ARRAYSZ:
                    self._init_array_size = d_val_ptr

                elif d_tag == DT_NEEDED:
                    dt_needed.append(d_val_ptr)

                elif d_tag == DT_PLTGOT:
                    self._plt_got_addr = d_val_ptr
                elif d_tag == DT_SONAME:
                    pass
                elif d_tag == DT_FLAGS:
                    pass
                elif d_tag == DT_FLAGS_1:
                    pass
                elif d_tag == DT_PLTREL:
                    pass
                elif d_tag == DT_SYMENT:
                    pass
                else:
                    logger.warning('Unsupported d_tag %d (0x%X) while loading library: %s', d_tag, d_tag, filename)

            assert nsymbol > -1, "can not detect nsymbol by DT_HASH or DT_GNU_HASH, make sure their exist in so"
            self._dyn_str_addr = dyn_str_addr
            self._dyn_str_addr = dyn_sym_addr

            self._dyn_str_sz = dyn_str_sz

            self._pltrel_addr = relplt_addr
            self._pltrel_count = relplt_count

            self._rel_addr = rel_addr
            self._rel_count = rel_count

            f.seek(dyn_str_addr - bias)
            self._dyn_str_buf = f.read(dyn_str_sz)

            f.seek(dyn_sym_addr - bias, 0)
            for i in range(0, nsymbol):
                sym_bytes = f.read(elf_sym_sz)
                if is_elf32:
                    (
                        st_name,
                        st_value,
                        st_size,
                        st_info,
                        st_other,
                        st_shndx,
                    ) = struct.unpack(sym_pattern, sym_bytes)
                else:
                    (
                        st_name,
                        st_info,
                        st_other,
                        st_shndx,
                        st_value,
                        st_size,
                    ) = struct.unpack(sym_pattern, sym_bytes)

                int_st_info = int.from_bytes(
                    st_info, "little", signed=False
                )
                st_info_bind = ELFReader.__elf_st_bind(int_st_info)
                st_info_type = ELFReader.__elf_st_type(int_st_info)
                name = ""
                try:
                    name = self._st_name_to_name(st_name)
                except UnicodeDecodeError as e:
                    logger.warning(
                        "warning can not decode sym index %d at off 0x%08x skip"
                        % (i, st_name)
                    )

                d = {
                    "name": name,
                    "st_name": st_name,
                    "st_value": st_value,
                    "st_size": st_size,
                    "st_info": st_info,
                    "st_other": st_other,
                    "st_shndx": st_shndx,
                    "st_info_bind": st_info_bind,
                    "st_info_type": st_info_type,
                }
                self._dynsymols.append(d)

            # Read reloactions
            rel_table = []
            if rel_count > 0:
                # rel不一定有
                f.seek(rel_addr - bias, 0)

                for i in range(0, rel_count):
                    rel_item_bytes = f.read(elf_rel_sz)
                    d = {}
                    if is_elf32:
                        r_offset, r_info = struct.unpack(
                            rel_pattern, rel_item_bytes
                        )
                    else:
                        # 64 rela
                        r_offset, r_info, r_addend = struct.unpack(
                            rel_pattern, rel_item_bytes
                        )

                    r_info_sym = elf_r_sym(r_info)
                    r_info_type = elf_r_type(r_info)
                    d = {
                        "r_offset": r_offset,
                        "r_info": r_info,
                        "r_info_type": r_info_type,
                        "r_info_sym": r_info_sym,
                    }
                    if not is_elf32:
                        d["r_addend"] = r_addend
                    rel_table.append(d)

            self._rels["dynrel"] = rel_table

            # RELR
            relr_table = []

            if relr_size > 0:
                f.seek(relr_addr - bias, 0)
                relocations = f.read(relr_size)
                relr_table = [
                    int.from_bytes(relocations[i * elf_relr_ent_sz:(i + 1) * elf_relr_ent_sz], 'little')
                    for i in range(relr_size // elf_relr_ent_sz)
                ]

            self._rels["relr"] = relr_table

            relplt_table = []
            if relplt_count > 0:
                f.seek(relplt_addr - bias, 0)
                for i in range(0, relplt_count):
                    rel_item_bytes = f.read(elf_rel_sz)
                    if is_elf32:
                        r_offset, r_info = struct.unpack(
                            rel_pattern, rel_item_bytes
                        )
                    else:
                        # 64 rela
                        r_offset, r_info, r_addend = struct.unpack(
                            rel_pattern, rel_item_bytes
                        )

                    r_info_sym = elf_r_sym(r_info)
                    r_info_type = elf_r_type(r_info)
                    d = {
                        "r_offset": r_offset,
                        "r_info": r_info,
                        "r_info_type": r_info_type,
                        "r_info_sym": r_info_sym,
                    }
                    # rela多了一个字段
                    if not is_elf32:
                        d["r_addend"] = r_addend
                    relplt_table.append(d)

                self._rels["relplt"] = relplt_table
                for str_off in dt_needed:
                    endId = self._dyn_str_buf.find(b"\x00", str_off)
                    so_name = self._dyn_str_buf[str_off:endId]
                    self._so_needed.append(so_name.decode("utf-8"))

    def get_load(self):
        return self._loads

    def get_symbols(self):
        return self._dynsymols

    def get_rels(self):
        return self._rels

    def is_elf32(self):
        return self._is_elf32

    def get_dyn_string_by_rel_sym(self, rel_sym):
        nsym = len(self._dynsymols)
        assert rel_sym < nsym
        sym = self._dynsymols[rel_sym]
        st_name = sym["st_name"]
        r = self._st_name_to_name(st_name)
        return r

    def get_init_array(self):
        return self._init_array_addr, self._init_array_size

    def get_init(self):
        return self._init_addr

    def get_entry_point(self):
        return self._entry_point

    def get_so_need(self):
        return self._so_needed

    def get_phdr_addr(self):
        return self._phoff

    def get_phdr_num(self):
        return self._phdr_num

    def get_phdr_entry_size(self):
        return self._phdr_entry_size

    def _write_soinfo32(self, mu, load_base, load_bias, info_base):
        # android 4.4.4 soinfo

        # 在虚拟机中构造一个soinfo结构
        assert len(self._filename) < 128

        # name
        memory_helpers.write_utf8(mu, info_base + 0, self._filename)
        # phdr
        mu.mem_write(
            info_base + 128,
            int(load_base + self._phoff).to_bytes(4, "little"),
        )
        # phnum
        mu.mem_write(
            info_base + 132,
            int(self._phdr_num).to_bytes(4, "little"),
        )
        # entry
        mu.mem_write(info_base + 136, int(self._entry_point).to_bytes(4, "little"))
        # base
        mu.mem_write(
            info_base + 140, int(load_base).to_bytes(4, "little")
        )
        # size
        mu.mem_write(
            info_base + 144, int(self._sz).to_bytes(4, "little")
        )
        # unused1
        mu.mem_write(info_base + 148, int(0).to_bytes(4, "little"))
        # dynamic
        mu.mem_write(
            info_base + 152,
            int(load_base + self._dyn_addr).to_bytes(4, "little"),
        )
        # unused2
        mu.mem_write(info_base + 156, int(0).to_bytes(4, "little"))
        # unused3
        mu.mem_write(info_base + 160, int(0).to_bytes(4, "little"))
        # next
        mu.mem_write(info_base + 164, int(0).to_bytes(4, "little"))
        # flags
        mu.mem_write(info_base + 168, int(0).to_bytes(4, "little"))
        # strtab
        mu.mem_write(
            info_base + 172,
            int(load_base + self._dyn_str_addr).to_bytes(
                4, "little"
            ),
        )
        # symtab
        mu.mem_write(
            info_base + 176,
            int(load_base + self._dyn_str_addr).to_bytes(
                4, "little"
            ),
        )
        # nbucket
        mu.mem_write(
            info_base + 180, int(self._nbucket).to_bytes(4, "little")
        )
        # nchain
        mu.mem_write(
            info_base + 184, int(self._nchain).to_bytes(4, "little")
        )

        # bucket
        mu.mem_write(
            info_base + 188,
            int(load_base + self._bucket_addr).to_bytes(4, "little"),
        )
        # nchain
        mu.mem_write(
            info_base + 192,
            int(load_base + self._chain_addr).to_bytes(4, "little"),
        )

        # plt_got
        mu.mem_write(
            info_base + 196,
            int(load_base + self._plt_got_addr).to_bytes(
                4, "little"
            ),
        )

        # plt_rel
        mu.mem_write(
            info_base + 200,
            int(load_base + self._pltrel_addr).to_bytes(4, "little"),
        )
        # plt_rel_count
        mu.mem_write(
            info_base + 204,
            int(self._pltrel_count).to_bytes(4, "little"),
        )

        # rel
        mu.mem_write(
            info_base + 208,
            int(load_base + self._rel_addr).to_bytes(4, "little"),
        )
        # rel_count
        mu.mem_write(
            info_base + 212,
            int(self._rel_count).to_bytes(4, "little"),
        )

        # preinit_array
        mu.mem_write(info_base + 216, int(0).to_bytes(4, "little"))
        # preinit_array_count
        mu.mem_write(info_base + 220, int(0).to_bytes(4, "little"))

        # init_array
        mu.mem_write(
            info_base + 224,
            int(load_base + self._init_array_addr).to_bytes(
                4, "little"
            ),
        )
        # init_array_count
        mu.mem_write(
            info_base + 228,
            int(self._init_array_size / 4).to_bytes(4, "little"),
        )

        # finit_array
        mu.mem_write(info_base + 232, int(0).to_bytes(4, "little"))
        # finit_array_count
        mu.mem_write(info_base + 236, int(0).to_bytes(4, "little"))

        # init_func
        mu.mem_write(
            info_base + 240,
            int(load_base + self._init_addr).to_bytes(4, "little"),
        )
        # fini_func
        mu.mem_write(info_base + 244, int(0).to_bytes(4, "little"))

        # ARM_exidx
        mu.mem_write(info_base + 248, int(0).to_bytes(4, "little"))
        # ARM_exidx_count
        mu.mem_write(info_base + 252, int(0).to_bytes(4, "little"))

        # ref_count
        mu.mem_write(info_base + 256, int(1).to_bytes(4, "little"))

        # link_map
        mu.mem_write(info_base + 260, int(0).to_bytes(20, "little"))

        # constructors_called
        mu.mem_write(info_base + 280, int(1).to_bytes(4, "little"))

        # Elf32_Addr load_bias
        load_bias = load_base - (
            self._loads[0]["p_vaddr"] - self._loads[0]["p_offset"]
        )
        mu.mem_write(
            info_base + 284, int(load_bias).to_bytes(4, "little")
        )

        soinfo_sz = 288
        return soinfo_sz

    def _write_soinfo64(self, mu, load_base, load_bias, info_base):
        # 在虚拟机中构造一个soinfo结构
        assert len(self._filename) < 128

        # name
        memory_helpers.write_utf8(mu, info_base + 0, self._filename)
        off = 128
        # phdr
        mu.mem_write(
            info_base + off,
            int(load_base + self._phoff).to_bytes(8, "little"),
        )
        off += 8
        # phnum
        mu.mem_write(
            info_base + off,
            int(self._phdr_num).to_bytes(8, "little"),
        )
        off += 8

        # entry
        mu.mem_write(info_base + off, int(self._entry_point).to_bytes(8, "little"))
        off += 8

        # base
        mu.mem_write(
            info_base + off, int(load_base).to_bytes(8, "little")
        )
        off += 8

        # size
        mu.mem_write(
            info_base + off, int(self._sz).to_bytes(8, "little")
        )
        off += 8

        # unused1
        mu.mem_write(
            info_base + off, int(0).to_bytes(8, "little")
        )  # unsed uint32  占用8因为内存对齐
        off += 8

        # dynamic
        mu.mem_write(
            info_base + off,
            int(load_base + self._dyn_addr).to_bytes(8, "little"),
        )
        off += 8

        # unused2
        mu.mem_write(info_base + off, int(0).to_bytes(4, "little"))
        off += 4
        # unused3
        mu.mem_write(info_base + off, int(0).to_bytes(4, "little"))
        off += 4
        # next
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8
        # flags
        mu.mem_write(
            info_base + off, int(0).to_bytes(8, "little")
        )  # 内存对齐
        off += 8

        # strtab
        mu.mem_write(
            info_base + off,
            int(load_base + self._dyn_str_addr).to_bytes(
                8, "little"
            ),
        )
        off += 8

        # symtab
        mu.mem_write(
            info_base + off,
            int(load_base + self._dyn_str_addr).to_bytes(
                8, "little"
            ),
        )
        off += 8

        # nbucket
        mu.mem_write(
            info_base + off, int(self._nbucket).to_bytes(4, "little")
        )
        off += 8
        # nchain
        mu.mem_write(
            info_base + off, int(self._nchain).to_bytes(4, "little")
        )
        off += 8

        # bucket
        mu.mem_write(
            info_base + off,
            int(load_base + self._bucket_addr).to_bytes(4, "little"),
        )
        off += 8
        # nchain
        mu.mem_write(
            info_base + off,
            int(load_base + self._chain_addr).to_bytes(4, "little"),
        )
        off += 8

        # plt_rela
        mu.mem_write(
            info_base + off,
            int(load_base + self._pltrel_addr).to_bytes(8, "little"),
        )
        off += 8
        # plt_rela_count
        mu.mem_write(
            info_base + off,
            int(self._pltrel_count).to_bytes(8, "little"),
        )
        off += 8

        # rela
        mu.mem_write(
            info_base + off,
            int(load_base + self._rel_addr).to_bytes(8, "little"),
        )
        off += 8

        # rela_count
        mu.mem_write(
            info_base + off,
            int(self._rel_count).to_bytes(8, "little"),
        )
        off += 8

        # preinit_array
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8
        # preinit_array_count
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8

        # init_array
        mu.mem_write(
            info_base + off,
            int(load_base + self._init_array_addr).to_bytes(
                8, "little"
            ),
        )
        off += 8
        # init_array_count
        mu.mem_write(
            info_base + off,
            int(self._init_array_size / 8).to_bytes(8, "little"),
        )
        off += 8

        # finit_array
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8
        # finit_array_count
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8

        # init_func
        mu.mem_write(
            info_base + off,
            int(load_base + self._init_addr).to_bytes(8, "little"),
        )
        off += 8
        # fini_func
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8

        # ARM_exidx
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8
        # ARM_exidx_count
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8

        # ref_count
        mu.mem_write(info_base + off, int(1).to_bytes(4, "little"))
        off += 8

        # link_map
        mu.mem_write(info_base + off, int(0).to_bytes(40, "little"))
        off += 40

        # constructors_called
        mu.mem_write(info_base + off, int(1).to_bytes(8, "little"))
        off += 8

        # Elf64_Addr load_bias
        mu.mem_write(
            info_base + off, int(load_bias).to_bytes(8, "little")
        )
        off += 8

        # has_DT_SYMBOLIC
        mu.mem_write(info_base + off, int(0).to_bytes(8, "little"))
        off += 8

        soinfo_sz = off
        return soinfo_sz

    def write_soinfo(self, mu, load_base, load_bias, info_base):
        if self.is_elf32():
            return self._write_soinfo32(mu, load_base, load_bias, info_base)

        else:
            return self._write_soinfo64(mu, load_base, load_bias, info_base)
