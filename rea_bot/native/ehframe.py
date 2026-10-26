"""ELF .eh_frame function bounds. Sizes are the FDE address ranges, which survive a stripped symbol table."""
import struct


def _uleb(buf, i):
    n = s = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << s
        if b < 128:
            return n, i
        s += 7
    raise ValueError("Truncated ULEB128.")


def _sleb(buf, i):
    n = s = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << s
        s += 7
        if b < 128:
            if s < 64 and (b & 0x40):
                n |= (-1) << s
            return n, i
    raise ValueError("Truncated SLEB128.")


def _encoded(buf, i, enc, sec_va, ptr_size):
    """Read one DWARF exception-header value. PC-relative values are resolved."""
    if enc == 0xFF:
        return None, i
    start = i
    fmt = enc & 0x0F
    if fmt == 0x00:
        if ptr_size == 8:
            val = struct.unpack_from("<Q", buf, i)[0]
            i += 8
        else:
            val = struct.unpack_from("<I", buf, i)[0]
            i += 4
    elif fmt == 0x01:
        val, i = _uleb(buf, i)
    elif fmt == 0x02:
        val = struct.unpack_from("<H", buf, i)[0]
        i += 2
    elif fmt == 0x03:
        val = struct.unpack_from("<I", buf, i)[0]
        i += 4
    elif fmt == 0x04:
        val = struct.unpack_from("<Q", buf, i)[0]
        i += 8
    elif fmt == 0x09:
        val, i = _sleb(buf, i)
    elif fmt == 0x0A:
        val = struct.unpack_from("<h", buf, i)[0]
        i += 2
    elif fmt == 0x0B:
        val = struct.unpack_from("<i", buf, i)[0]
        i += 4
    elif fmt == 0x0C:
        val = struct.unpack_from("<q", buf, i)[0]
        i += 8
    else:
        raise ValueError("Unsupported EH pointer encoding %s." % hex(enc))
    app = enc & 0x70
    if app == 0x10:
        val = (sec_va + start + val) & ((1 << (ptr_size * 8)) - 1)
    elif app not in (0x00,):
        raise ValueError("Unsupported EH pointer application %s." % hex(app))
    return val, i


def functions(data, sec_va, ptr_size=8):
    """Return [(pc, size), ...] from an ELF .eh_frame section."""
    cies = {}
    found = []
    off = 0
    while off + 4 <= len(data):
        length = struct.unpack_from("<I", data, off)[0]
        if length == 0:
            break
        rec = off
        off += 4
        if length == 0xFFFFFFFF:
            length = struct.unpack_from("<Q", data, off)[0]
            off += 8
            id_size = 8
        else:
            id_size = 4
        end = off + length
        if end > len(data):
            break
        cie_id = struct.unpack_from("<I" if id_size == 4 else "<Q", data, off)[0]
        id_at = off
        off += id_size
        if cie_id == 0:
            version = data[off]
            off += 1
            aug_at = off
            while off < end and data[off] != 0:
                off += 1
            aug = data[aug_at:off].decode("ascii", "replace")
            off += 1
            if aug == "eh":
                off += ptr_size
            _, off = _uleb(data, off)
            _, off = _sleb(data, off)
            if version == 1:
                off += 1
            else:
                _, off = _uleb(data, off)
            fde_enc = 0x00
            if aug.startswith("z"):
                _, off = _uleb(data, off)
                for ch in aug[1:]:
                    if ch == "R":
                        fde_enc = data[off]
                        off += 1
                    elif ch == "P":
                        penc = data[off]
                        off += 1
                        _, off = _encoded(data, off, penc, sec_va, ptr_size)
                    elif ch == "L":
                        off += 1
                    else:
                        break
            cies[rec] = fde_enc
        else:
            cie_pos = id_at - cie_id
            enc = cies.get(cie_pos, 0x1B)
            pc, off = _encoded(data, off, enc, sec_va, ptr_size)
            size, off = _encoded(data, off, enc & 0x0F, sec_va, ptr_size)
            if pc and size and size < 16 * 1024 * 1024:
                found.append((int(pc), int(size)))
        off = end
    return found
