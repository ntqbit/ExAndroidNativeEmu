def short_bytes_repr(b):
    if len(b) <= 20:
        return b.hex()
    else:
        return b[:19].hex() + ".."
