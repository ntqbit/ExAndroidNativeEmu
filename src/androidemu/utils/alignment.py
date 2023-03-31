PAGE_SIZE = 0x1000


def page_start(addr, page_size=PAGE_SIZE):
    return addr & ~(page_size - 1)


def page_end(addr, page_size=PAGE_SIZE):
    return page_start(addr + (page_size - 1))
