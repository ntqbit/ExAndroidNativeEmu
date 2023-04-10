from unicorn import UC_HOOK_CODE
from androidemu.const import emu_const

import verboselogs

logger = verboselogs.VerboseLogger(__name__)

# Utility class to create a bridge between ARM and Python.


class Hooker:
    """
    :type emu androidemu.emulator.Emulator
    """

    def __init__(self, emu, base_addr, size):
        self._emu = emu
        self._size = size
        self._current_id = 0xFF00
        self._hooks = dict()
        _hook_start = base_addr + emu.get_ptr_size()
        self._hook_current = _hook_start
        self._emu.mu.hook_add(UC_HOOK_CODE, self._hook, None, _hook_start, _hook_start + size)

    def _get_next_id(self):
        idx = self._current_id
        self._current_id += 1
        return idx

    def write_function(self, func):
        # Get the hook id.
        hook_id = self._get_next_id()
        self._hooks[hook_id] = func
        # the the hook_id to header
        self._emu.mu.mem_write(
            self._hook_current,
            int(hook_id).to_bytes(4, byteorder="little", signed=False),
        )
        self._hook_current += 4

        hook_addr = self._hook_current
        if self._emu.get_arch() == emu_const.Arch.ARM32:
            # Create the ARM assembly code.
            self._emu.mu.mem_write(
                self._hook_current, b"\x1E\xFF\x2F\xE1"
            )  # bx lr
            self._hook_current += 4
        else:
            self._emu.mu.mem_write(
                self._hook_current, b"\xC0\x03\x5F\xD6"
            )  # ret
            self._hook_current += 4

        return hook_addr

    def write_function_table(self, table):
        if not isinstance(table, dict):
            raise ValueError("Expected a dictionary for the function table.")

        index_max = int(max(table, key=int)) + 1

        # First, we write every function and store its result address.
        hook_map = dict()

        for index, func in table.items():
            hook_map[index] = self.write_function(func)

        # Then we write the function table.
        table_bytes = b""
        table_address = self._hook_current
        ptr_size = self._emu.get_ptr_size()
        for index in range(0, index_max):
            address = hook_map[index] if index in hook_map else 0
            table_bytes += int(address).to_bytes(
                ptr_size, byteorder="little"
            )

        self._emu.mu.mem_write(table_address, table_bytes)
        self._hook_current += len(table_bytes)

        ptr_address = self._hook_current
        self._emu.mu.mem_write(
            ptr_address, table_address.to_bytes(ptr_size, byteorder="little")
        )
        self._hook_current += ptr_size

        return ptr_address, table_address

    def _hook(self, mu, address, size, user_data):
        hook_id_ptr = address - 4
        hook_id_bytes = mu.mem_read(hook_id_ptr, 4)
        hook_id = int.from_bytes(hook_id_bytes, byteorder="little", signed=False)

        hook_func = self._hooks[hook_id]

        # Call hook.
        try:
            hook_func(self._emu)
        except Exception:
            mu.emu_stop()
            logger.exception("Caught an exception in _hook:")
            raise
