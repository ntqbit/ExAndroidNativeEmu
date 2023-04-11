import os
import random

from typing import List, Tuple, Dict

import verboselogs

from unicorn import UC_PROT_ALL, UC_PROT_WRITE, UC_PROT_READ
from unicorn.arm_const import UC_ARM_REG_C13_C0_3, UC_ARM_REG_SP
from unicorn.arm64_const import UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_SP

from androidemu.internal import arm
from androidemu.utils.misc_utils import get_segment_protection
from androidemu.native.memory_map import PAGE_SIZE
from androidemu.utils.alignment import page_start, page_end
from androidemu.utils.stack_helpers import StackHelper
from androidemu.internal.module import Module
from androidemu.const.emu_const import Arch
from androidemu.utils import memory_helpers, misc_utils
from androidemu.vfs.virtual_file import VirtualFile
from androidemu.internal import elf_reader
from androidemu.const import linux
from androidemu.const.emu_const import BASE_ADDR, TLS_BASE, TLS_SIZE


logger = verboselogs.VerboseLogger(__name__)


class Modules:
    def __init__(self, emu, vfs_root):
        self._emu = emu
        self._modules: List[Module] = list()
        self._symbol_hooks = dict()
        self._counter_memory = BASE_ADDR
        soinfo_area_sz = 0x40000
        self._soinfo_area_base = emu.memory.map(0, soinfo_area_sz, UC_PROT_WRITE | UC_PROT_READ)
        self._errno_ptr = 0
        self._linker: Module = None
        self._argv = None
        self._envp = None
        self._auxv = None

    def get_modules(self):
        return self._modules

    def _init_args(self, linker_base, phdr_addr, phdr_num, phdr_ent_size, entry_point):
        self._argv = ["app_process32"]

        self._envp = {
            "ANDROID_DATA": "/data",
            "MKSH": "/system/bin/sh",
            "HOME": "/data",
            "USER": "shell",
            "ANDROID_ROOT": "/system",
            "SHELL": "/system/bin/sh",
            "ANDROID_BOOTLOGO": "1",
            "TMPDIR": "/data/local/tmp",
            "ANDROID_ASSETS": "/system/app",
            "HOSTNAME": "bullhead",
            "EXTERNAL_STORAGE": "/sdcard",
            "ANDROID_STORAGE": "/storage",
        }

        # Used a list of tuples instead of dict.
        # Because in python before version 3.7 dictionaries had no speicific order.
        # But here it is required for auxv AT_NULL at the end of the list.
        self._auxv = [
            (linux.AT_SYSINFO_EHDR, 0),  # vdso (Virtual Dynamic Shared Object)
            (linux.AT_HWCAP, 0x37B0D6),
            (linux.AT_PAGESZ, PAGE_SIZE),
            (linux.AT_CLKTCK, 0x64),
            (linux.AT_PHDR, phdr_addr),  # app_process32 phdr
            (linux.AT_PHENT, phdr_ent_size),
            (linux.AT_PHNUM, phdr_num),
            (linux.AT_BASE, linker_base),  # linker base address
            (linux.AT_FLAGS, 0x0),
            (linux.AT_ENTRY, entry_point),  # somewhere in app_process32
            (linux.AT_UID, 0x0),
            (linux.AT_EUID, 0x0),
            (linux.AT_GID, 0x0),
            (linux.AT_EGID, 0x0),
            (linux.AT_SECURE, 0x0),
            #(linux.AT_RANDOM, random.randbytes(16)),
            (linux.AT_HWCAP2, 0x1F),
            #(linux.AT_EXECFN, '/dev/fd/4'),
            #(linux.AT_PLATFORM, 'v8l')
        ]

    def _load_linker(self, base_address, base: elf_reader.ELFReader):
        self._linker = self.load_module(
            self._emu.vfs.translate_path('/system/bin/linker'),
            do_init=False, call_entry_point=True, is_linker=True,
            base_address=base_address,
            base=base
        )

        self._tls_init()

    def _write_raw_args(self, argv: List[str], envp: Dict[str, str], auxv: List[Tuple[int, int]]):
        raw_args_parts = []

        if self._emu.get_arch() == Arch.ARM32:
            wordsize = 4
            sp_reg = UC_ARM_REG_SP
        else:
            wordsize = 8
            sp_reg = UC_ARM64_REG_SP

        argc = len(argv)
        env_count = len(envp)

        argc_size = wordsize
        argv_size = wordsize * argc
        null_size = wordsize
        envp_size = wordsize * env_count
        auxv_size = len(auxv) * wordsize * 2

        argv_data_size = sum(len(arg) + 1 for arg in argv)
        envp_data_size = sum(len(arg) + 1 for arg in envp)

        total_size_unaligned = argc_size + argv_size + null_size + envp_size + \
            null_size + auxv_size + argv_data_size + envp_data_size
        total_size = total_size_unaligned | (wordsize - 1)

        sp_addr = self._emu.mu.reg_read(sp_reg) - total_size
        self._emu.mu.reg_write(sp_reg, sp_addr)

        argc_addr = sp_addr
        argv_addr = argc_addr + argc_size
        envp_addr = argv_addr + argv_size + null_size
        auxv_addr = envp_addr + envp_size + null_size
        data_addr = auxv_addr + auxv_size

        current_data_addr = data_addr

        raw_args_parts.append(argc.to_bytes(wordsize, 'little'))

        # Write argv
        for arg in argv:
            raw_args_parts.append(current_data_addr.to_bytes(wordsize, 'little'))
            current_data_addr += memory_helpers.write_utf8(self._emu.mu, current_data_addr, arg)

        raw_args_parts.append(int(0).to_bytes(wordsize, 'little'))

        # Write envp
        for env in envp:
            raw_args_parts.append(current_data_addr.to_bytes(wordsize, 'little'))
            current_data_addr += memory_helpers.write_utf8(self._emu.mu, current_data_addr, env)

        raw_args_parts.append(int(0).to_bytes(wordsize, 'little'))

        # Write auxv
        raw_args_parts += [
            key.to_bytes(wordsize, 'little') + val.to_bytes(wordsize, 'little')
            for key, val in auxv
        ]

        a = b''.join(raw_args_parts)
        assert len(a) == data_addr - sp_addr
        self._emu.mu.mem_write(sp_addr, a)

    def _tls_init(self):
        sp_helpers = StackHelper(self._emu)

        pthread_internal_nptr = 0x400
        thread_internal_ptr = sp_helpers.reserve(pthread_internal_nptr)

        stack_guard_ptr = sp_helpers.write_val(0x1000)

        argvs_ptrs = []
        for arg in self._argv:
            argvs_ptrs.append(sp_helpers.write_utf8(arg))

        env_ptrs = []
        for k, val in self._envp.items():
            env_str = f'{k}={val}'
            env_ptr = sp_helpers.write_utf8(env_str)
            env_ptrs.append(env_ptr)

        sp_helpers.commit()
        ptr_sz = self._emu.get_ptr_size()

        # auxv

        auxv_base = sp_helpers.reserve(0x100)
        auxv_offset = auxv_base
        for auxv_key, auxv_val in self._auxv:
            memory_helpers.write_ptrs_sz(self._emu.mu, auxv_offset, auxv_key, ptr_sz)
            memory_helpers.write_ptrs_sz(self._emu.mu, auxv_offset + ptr_sz, auxv_val, ptr_sz)
            auxv_offset += 2 * ptr_sz

        # auvx数组0结尾
        memory_helpers.write_ptrs_sz(self._emu.mu, auxv_offset, 0, 2 * ptr_sz)

        env_base = sp_helpers.reserve(len(env_ptrs) + 1)
        env_offset = env_base
        # envp
        for env_ptr in env_ptrs:
            memory_helpers.write_ptrs_sz(
                self._emu.mu, env_offset, env_ptr, ptr_sz
            )
            env_offset += ptr_sz

        # 0结尾
        memory_helpers.write_ptrs_sz(self._emu.mu, env_offset, 0, ptr_sz)

        nargc = len(self._argv)
        argv_base = sp_helpers.reserve(nargc + 1)
        argv_offset = argv_base
        # argv
        for argv_ptr in argvs_ptrs:
            memory_helpers.write_ptrs_sz(
                self._emu.mu, argv_offset, argv_ptr, ptr_sz
            )
            argv_offset += ptr_sz

        # 0结尾
        memory_helpers.write_ptrs_sz(self._emu.mu, argv_offset, 0, ptr_sz)

        # KernelArgumentBlock
        # int argc;
        # char** argv;
        # char** envp;
        # Elf32_auxv_t* auxv;
        # abort_msg_t** abort_message_ptr;
        kernel_args_base = sp_helpers.reserve(5)
        memory_helpers.write_ptrs_sz(self._emu.mu, kernel_args_base, nargc, ptr_sz)
        memory_helpers.write_ptrs_sz(self._emu.mu, kernel_args_base + ptr_sz, argv_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self._emu.mu, kernel_args_base + 2 * ptr_sz, env_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self._emu.mu, kernel_args_base + 3 * ptr_sz, auxv_base, ptr_sz)
        memory_helpers.write_ptrs_sz(self._emu.mu, kernel_args_base + 4 * ptr_sz, 0, ptr_sz)

        # tls单独一个区域，不放在stack中
        self._emu.mu.mem_map(TLS_BASE, TLS_SIZE, UC_PROT_WRITE | UC_PROT_READ)
        tls_ptr = TLS_BASE
        mu = self._emu.mu
        # TLS_SLOT_SELF
        memory_helpers.write_ptrs_sz(mu, tls_ptr, tls_ptr, ptr_sz)
        # TLS_SLOT_THREAD_ID
        memory_helpers.write_ptrs_sz(mu, tls_ptr + ptr_sz, thread_internal_ptr, ptr_sz)
        # TLS_SLOT_ERRNO
        self._errno_ptr = tls_ptr + 2 * ptr_sz
        # TLS_SLOT_BIONIC_PREINIT
        memory_helpers.write_ptrs_sz(mu, tls_ptr + 3 * ptr_sz, kernel_args_base, ptr_sz)
        arch = self._emu.get_arch()

        if arch == Arch.ARM32:
            mu.reg_write(UC_ARM_REG_C13_C0_3, tls_ptr)
        else:
            mu.reg_write(UC_ARM64_REG_TPIDR_EL0, tls_ptr)

        sp_helpers.commit()

    def _get_ld_library_path(self):
        if self._emu.get_arch() == Arch.ARM32:
            return ["/system/lib/"]
        else:
            return ["/system/lib64/"]

    def find_so_on_disk(self, so_path):
        if os.path.isabs(so_path):
            return self._emu.vfs.translate_path(so_path)
        else:
            ld_library_path = self._get_ld_library_path()
            so_name = so_path
            for lib_path in ld_library_path:
                lib_full_path = "%s/%s" % (lib_path, so_name)
                vfs_lib_path = self._emu.vfs.translate_path(lib_full_path)
                if os.path.exists(vfs_lib_path):
                    return vfs_lib_path

        return None

    def add_symbol_hook(self, symbol_name, addr):
        self._symbol_hooks[symbol_name] = addr

    def find_symbol(self, addr):
        for module in self._modules:
            if addr in module.symbol_lookup:
                return module.symbol_lookup[addr]
        return None, None

    def find_symbol_str(self, symbol_str):
        for module in self._modules:
            sym = module.find_symbol(symbol_str)
            if sym is not None:
                return sym
        return None

    def find_module(self, addr):
        for module in self._modules:
            if module.base == addr:
                return module
        return None

    def find_module_by_name(self, filename):
        absp1 = os.path.abspath(filename)
        for m in self._modules:
            absm = os.path.abspath(m.filename)
            if absp1 == absm:
                return m

    def mem_reserve(self, start, end):
        size_aligned = page_end(end) - page_start(start)
        ret = self._counter_memory
        self._counter_memory += size_aligned
        return ret

    def load_module(self, filename, do_init=True, call_entry_point=False,
                    is_linker=False, base_address=None, base: elf_reader.ELFReader = None):
        m = self.find_module_by_name(filename)
        if m is not None:
            return m

        logger.verbose("Loading module '%s'.", filename)

        # do sth like linker
        reader = elf_reader.ELFReader(filename)

        if self._emu.get_arch() == Arch.ARM32 and not reader.is_elf32():
            raise RuntimeError(f"arch is ARCH_ARM32 but so {filename} is not elf32")
        elif self._emu.get_arch() == Arch.ARM64 and reader.is_elf32():
            raise RuntimeError(f"arch is ARCH_ARM64 but so {filename} is elf32")

        if self._emu.get_arch() == Arch.ARM32:
            wordsize = 4
        else:
            wordsize = 8

        # Parse program header (Execution view).

        # - LOAD (determinate what parts of the ELF file get mapped into memory)
        load_segments = reader.get_load()

        # Find bounds of the load segments.
        bound_low = 0xFFFFFFFFFFFFFFFF
        bound_high = 0
        for segment in load_segments:
            p_memsz = segment["p_memsz"]
            if p_memsz == 0:
                continue
            p_vaddr = segment["p_vaddr"]
            if bound_low > p_vaddr:
                bound_low = p_vaddr
            high = p_vaddr + p_memsz

            if bound_high < high:
                bound_high = high

        # Retrieve a base address for this module.
        load_base = self.mem_reserve(bound_low, bound_high)
        load_bias = load_base - bound_low

        vf = VirtualFile(
            self._emu.vfs.translate_path(filename),
            misc_utils.platform_open(filename, os.O_RDONLY),
            filename,
        )
        for segment in load_segments:
            p_flags = segment["p_flags"]
            prot = get_segment_protection(p_flags)
            prot = prot if prot != 0 else UC_PROT_ALL

            p_vaddr = segment["p_vaddr"]
            seg_start = load_bias + p_vaddr
            seg_page_start = page_start(seg_start)
            p_offset = segment["p_offset"]
            file_start = p_offset
            p_filesz = segment["p_filesz"]
            file_end = file_start + p_filesz
            file_page_start = page_start(file_start)
            file_length = file_end - file_page_start

            if file_length == 0:
                continue

            if file_length <= 0:
                logger.error("File length must be greater than zero. [p_filesz=%d,file_end=%d,file_page_start=%d,file_length=%d]",
                             p_filesz, file_end, file_page_start, file_length)
                logger.debug("Segment: %s", segment)
                logger.debug("Load segments: %s", load_segments)
                raise RuntimeError("File length must be greater than zero.")

            self._emu.memory.map(seg_page_start, file_length, prot, vf, file_page_start)

            p_memsz = segment["p_memsz"]
            seg_end = seg_start + p_memsz
            seg_page_end = page_end(seg_end)

            seg_file_end = seg_start + p_filesz

            seg_file_end = page_end(seg_file_end)

            if seg_page_end > seg_file_end:
                self._emu.memory.map(seg_file_end, seg_page_end - seg_file_end,
                                     prot, vf, file_page_start + file_length)

        # TODO: refactor
        if is_linker:
            self._init_args(load_base, base_address + base.get_phdr_addr(), base_address + base.get_phdr_num(),
                            base_address + base.get_phdr_entry_size(), base_address + base.get_entry_point())
        elif not self._linker:
            self._load_linker(load_base, reader)

        so_needed = reader.get_so_need()
        for so_name in so_needed:
            path = self.find_so_on_disk(so_name)
            if path is None:
                logger.warning("%s needed by %s do not exist in vfs %s", so_name, filename, self._emu.get_vfs_root())
                continue

            self.load_module(path)

        # Resolve all symbols.
        symbols_resolved = dict()

        symbols = reader.get_symbols()
        for symbol in symbols:
            symbol_address = self._elf_get_symval(load_bias, symbol)
            if symbol_address is not None:
                name = symbol["name"]
                symbols_resolved[name] = symbol_address

        # Relocate.
        if is_linker:
            logger.debug('R_ARM_IRELATIVE relocation skipped in linker')
        else:
            rels = reader.get_rels()

            for rel_name, rel_tbl in rels.items():
                def apply_relative_relocation(offset):
                    rel_addr = load_bias + offset
                    value_orig_bytes = self._emu.mu.mem_read(rel_addr, wordsize)
                    value_orig = int.from_bytes(value_orig_bytes, byteorder="little")
                    value = load_bias + value_orig
                    self._emu.mu.mem_write(rel_addr, value.to_bytes(wordsize, byteorder="little"))

                if rel_name == 'relr':
                    # https://android.googlesource.com/platform/bionic/+/master/linker/linker.cpp#2727

                    base = 0

                    for rel in rel_tbl:
                        if rel & 1:
                            # bitmap encoding
                            offset = base

                            while rel:
                                rel >>= 1

                                if rel & 1:
                                    apply_relative_relocation(offset)

                                offset += wordsize

                            base += (8 * wordsize - 1) * wordsize
                        else:
                            apply_relative_relocation(rel)
                            base = rel + wordsize

                else:
                    for rel in rel_tbl:
                        r_info_sym = rel["r_info_sym"]
                        sym = symbols[r_info_sym]
                        sym_value = sym["st_value"]

                        # Location where relocation should happen
                        offset = rel["r_offset"]
                        rel_addr = load_bias + offset
                        rel_info_type = rel["r_info_type"]

                        sym_name = reader.get_dyn_string_by_rel_sym(r_info_sym)
                        if rel_info_type == arm.R_ARM_ABS32:
                            if sym_name in symbols_resolved:
                                sym_addr = symbols_resolved[sym_name]

                                value_orig_bytes = self._emu.mu.mem_read(rel_addr, 4)
                                value_orig = int.from_bytes(value_orig_bytes, byteorder="little")

                                # R_ARM_ABS32 how to relocate see android linker source code
                                # *reinterpret_cast<Elf32_Addr*>(reloc) += sym_addr;
                                value = sym_addr + value_orig
                                # Write the new value
                                # print(value)
                                self._emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder="little"))

                        elif rel_info_type in (arm.R_AARCH64_ABS64, arm.R_AARCH64_ABS32):
                            if sym_name in symbols_resolved:
                                sym_addr = symbols_resolved[sym_name]

                                value_orig_bytes = self._emu.mu.mem_read(rel_addr, 8)
                                value_orig = int.from_bytes(
                                    value_orig_bytes, byteorder="little"
                                )
                                addend = rel["r_addend"]

                                value = sym_addr + value_orig + addend
                                # Write the new value
                                # print(value)
                                self._emu.mu.mem_write(
                                    rel_addr, value.to_bytes(8, byteorder="little")
                                )

                        elif rel_info_type in (arm.R_ARM_GLOB_DAT, arm.R_ARM_JUMP_SLOT):
                            # Resolve the symbol.
                            # R_ARM_GLOB_DAT，R_ARM_JUMP_SLOT how to relocate see android linker source code
                            # *reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
                            if sym_name in symbols_resolved:
                                value = symbols_resolved[sym_name]

                                # Write the new value
                                self._emu.mu.mem_write(rel_addr, value.to_bytes(4, byteorder="little"))

                        elif rel_info_type in (arm.R_AARCH64_GLOB_DAT, arm.R_AARCH64_JUMP_SLOT):
                            # Resolve the symbol.
                            # R_ARM_GLOB_DAT，R_ARM_JUMP_SLOT how to relocate see android linker source code
                            # *reinterpret_cast<Elf32_Addr*>(reloc) = sym_addr;
                            if sym_name in symbols_resolved:
                                value = symbols_resolved[sym_name]
                                addend = rel["r_addend"]
                                # Write the new value
                                self._emu.mu.mem_write(rel_addr, (value + addend).to_bytes(8, byteorder="little"))

                        elif rel_info_type == arm.R_ARM_RELATIVE:
                            apply_relative_relocation(offset)
                        elif rel_info_type == arm.R_AARCH64_RELATIVE:
                            if sym_value == 0:
                                addend = rel["r_addend"]
                                # Create the new value
                                value = load_bias + addend

                                # print(value)
                                # Write the new value
                                self._emu.mu.mem_write(rel_addr, value.to_bytes(8, byteorder="little"))
                            else:
                                raise NotImplementedError()  # impossible
                        elif rel_info_type == arm.R_ARM_TLS_TPOFF32:
                            logger.warning("reltype R_ARM_TLS_TPOFF32 skipped: [symname=%s]", sym_name)
                        elif rel_info_type == arm.R_ARM_IRELATIVE:
                            if self._emu.get_arch() != Arch.ARM32:
                                raise NotImplementedError()

                            value_orig_bytes = self._emu.mu.mem_read(rel_addr, wordsize)
                            value_orig = int.from_bytes(value_orig_bytes, byteorder="little")

                            result = self._emu.call_native(load_bias + value_orig)
                            self._emu.mu.mem_write(rel_addr, result.to_bytes(wordsize, byteorder="little"))
                        else:
                            logger.error("Unhandled relocation type %i. symname=%s", rel_info_type, sym_name)
                            raise NotImplementedError(f"Unhandled relocation type {rel_info_type}.")

        # Find init array.
        init_array_addr, init_array_size = reader.get_init_array()
        init_array = []
        init_addr = reader.get_init()

        if init_addr != 0:
            init_array.append(load_bias + init_addr)

        init_item_sz = 4
        if not reader.is_elf32():
            init_item_sz = 8

        for _ in range(int(init_array_size / init_item_sz)):
            b = self._emu.mu.mem_read(load_bias + init_array_addr, init_item_sz)
            fun_ptr = int.from_bytes(b, byteorder="little", signed=False)
            if fun_ptr != 0:
                init_array.append(fun_ptr)

            init_array_addr += init_item_sz

        write_sz = reader.write_soinfo(
            self._emu.mu, load_base, load_bias, self._soinfo_area_base
        )

        entry_point = reader.get_entry_point()
        if entry_point:
            entry_point = entry_point + load_bias

        # Store information about loaded module.
        module = Module(
            filename,
            load_base,
            bound_high - bound_low,
            symbols_resolved,
            init_array,
            entry_point,
            self._soinfo_area_base,
        )
        self._modules.append(module)

        self._soinfo_area_base += write_sz

        if do_init:
            logger.debug("calling module init: [filename=%s,load_base=0x%X]", filename, load_base)
            module.call_init(self._emu)

        if call_entry_point:
            envp_list = [f'{key}={val}' for key, val in self._envp.items()]
            self._write_raw_args(self._argv, envp_list, self._auxv)
            module.call_entry_point(self._emu)

        logger.info("finish load lib %s base 0x%08X", filename, load_base)
        return module

    def _elf_get_symval(self, load_bias, symbol):
        # logger.debug('Getting symbal: %s', symbol)

        name = symbol["name"]
        if name in self._symbol_hooks:
            return self._symbol_hooks[name]

        if symbol["st_shndx"] == elf_reader.SHN_UNDEF:
            # External symbol, lookup value.
            target = self._elf_lookup_symbol(name)
            if target is None:
                # Extern symbol not found
                if symbol["st_info_bind"] == elf_reader.STB_WEAK:
                    # Weak symbol initialized as 0
                    return 0
                else:
                    if name:
                        logger.error('=> Undefined external symbol: "%s"', name)
                    return None
            else:
                return target
        elif symbol["st_shndx"] == elf_reader.SHN_ABS:
            # Absolute symbol.
            return load_bias + symbol["st_value"]
        else:
            # Internally defined symbol.
            return load_bias + symbol["st_value"]

    def _elf_lookup_symbol(self, name):
        for module in self._modules:
            if name in module.symbols:
                addr = module.symbols[name]
                if addr != 0:
                    return addr

        return None
