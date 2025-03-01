import verboselogs

logger = verboselogs.VerboseLogger(__name__)


class Module:
    """
    :type filename str
    :type base int
    :type size int
    """

    def __init__(
        self, filename, address, size, symbols_resolved, init_array, entry_point, soinfo_ptr
    ):
        self.filename = filename
        self.base = address
        self.size = size
        self.symbols = symbols_resolved
        self.symbol_lookup = dict()
        self.init_array = list(init_array)
        self._entry_point = entry_point
        self.soinfo_ptr = soinfo_ptr

        for symbol_name in self.symbols:
            logger.notice('Module %s symbol %s: 0x%X', filename, symbol_name, self.symbols[symbol_name])

        # Create fast lookup.
        for symbol_name in self.symbols:
            addr = self.symbols[symbol_name]
            if addr != 0:
                self.symbol_lookup[addr] = symbol_name

    def find_symbol(self, name):
        if name in self.symbols:
            return self.symbols[name]
        return None

    def is_symbol_addr(self, addr):
        if addr in self.symbol_lookup:
            return self.symbol_lookup[addr]
        elif addr + 1 in self.symbol_lookup:
            return self.symbol_lookup[addr + 1]
        else:
            return None

    def call_init(self, emu):
        for fun_addr in self.init_array:
            logger.debug("Calling Init_array %s function: 0x%08X ", self.filename, fun_addr)
            emu.call_native(fun_addr)

    def call_entry_point(self, emu):
        if self._entry_point:
            logger.debug("Calling entry point of %s. Function: 0x%08X ", self.filename, self._entry_point)
            emu.call_native(self._entry_point)
        else:
            logger.debug("No entry point in library %s", self.filename)
