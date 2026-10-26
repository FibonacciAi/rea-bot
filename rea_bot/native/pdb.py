"""CodeView records plus portable PDB and classic MSF PDB readers.

Portable PDBs yield document basenames and local-variable names. Classic MSF
PDBs yield the GUID, age and structure, class, union and enum names from the
type stream. The assembly is not executed.
"""
import struct
import uuid
from pathlib import Path

_MSF = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
_LEAVES = {0x1505: "struct", 0x1504: "class", 0x1506: "union", 0x1507: "enum"}
_TABLES = {
    0x30: "Document", 0x31: "MethodDebugInformation", 0x32: "LocalScope", 0x33: "LocalVariable",
    0x34: "LocalConstant", 0x35: "ImportScope", 0x36: "StateMachineMethod", 0x37: "CustomDebugInformation",
}


def codeview(binary):
    """The RSDS record LIEF already parsed off a PE debug directory."""
    try:
        entries = list(getattr(binary, "debug", []) or [])
    except Exception:
        return None
    for entry in entries:
        if "CODEVIEW" not in str(getattr(entry, "type", "")).upper():
            continue
        filename = str(getattr(entry, "filename", "") or "")
        guid = getattr(entry, "guid", None)
        age = getattr(entry, "age", None)
        if not filename and not guid:
            continue
        return {"guid": str(guid) if guid else None, "age": int(age) if isinstance(age, int) else None,
                "file": Path(filename.replace("\\", "/")).name}
    return None


def locate(pe_path, info):
    pe_path = Path(pe_path)
    candidates = [pe_path.with_suffix(".pdb")]
    if info and info.get("file"):
        candidates.append(pe_path.parent / info["file"])
    seen = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        if cand.is_file():
            return cand
    return None


def parse(path, limit=16):
    data = Path(path).read_bytes()
    if data[:4] == b"BSJB":
        return _portable(data, limit)
    if data.startswith(_MSF):
        return _msf(data, limit)
    raise ValueError("Not a portable PDB or an MSF 7.00 PDB.")


def _cstr(buf, off):
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    if end < 0:
        end = min(len(buf), off + 240)
    return buf[off:end].decode("utf-8", "replace")


def _base(name):
    text = name.replace("\\", "/").rstrip("/")
    if not text:
        return ""
    return text.split("/")[-1][:120]


def _compressed(buf, index):
    if index >= len(buf):
        return 0, index
    first = buf[index]
    if first < 0x80:
        return first, index + 1
    if first < 0xC0 and index + 1 < len(buf):
        return ((first & 0x3F) << 8) | buf[index + 1], index + 2
    if index + 3 < len(buf):
        return ((first & 0x1F) << 24) | (buf[index + 1] << 16) | (buf[index + 2] << 8) | buf[index + 3], index + 4
    return 0, len(buf)


def _document_name(blob, offset):
    if offset <= 0 or offset >= len(blob):
        return ""
    size, index = _compressed(blob, offset)
    if size <= 0 or index + size > len(blob):
        return ""
    raw = blob[index:index + size]
    if not raw:
        return ""
    sep = "" if raw[0] == 0 else chr(raw[0])
    pos = 1
    parts = []
    while pos < len(raw) and len(parts) < 32:
        part, pos = _compressed(raw, pos)
        if part <= 0 or part >= len(blob):
            parts.append("")
            continue
        plen, pindex = _compressed(blob, part)
        parts.append(blob[pindex:pindex + plen].decode("utf-8", "replace"))
    return _base(sep.join(parts))


def _portable(data, limit):
    if len(data) < 32 or data[:4] != b"BSJB":
        raise ValueError("Not a portable PDB.")
    _sig, _major, _minor, _res, length = struct.unpack_from("<IHHII", data, 0)
    off = (16 + length + 3) & ~3
    _flags, nstreams = struct.unpack_from("<HH", data, off)
    off += 4
    streams = {}
    for _ in range(nstreams):
        start, size = struct.unpack_from("<II", data, off)
        off += 8
        end = data.index(b"\x00", off)
        name = data[off:end].decode("utf-8", "replace")
        off = (end + 1 + 3) & ~3
        streams[name] = data[start:start + size]
    tilde = streams.get("#~", b"")
    strings = streams.get("#Strings", b"")
    blobs = streams.get("#Blob", b"")
    if len(tilde) < 24:
        raise ValueError("Portable PDB metadata stream is truncated.")
    heaps = tilde[6]
    string_w = 4 if heaps & 1 else 2
    guid_w = 4 if heaps & 2 else 2
    blob_w = 4 if heaps & 4 else 2
    valid = struct.unpack_from("<Q", tilde, 8)[0]
    bits = [i for i in range(64) if valid & (1 << i)]
    rows = {}
    cursor = 24
    for bit in bits:
        rows[bit], = struct.unpack_from("<I", tilde, cursor)
        cursor += 4

    def index_width(table):
        return 4 if rows.get(table, 0) >= 65536 else 2

    def take(buf, pos, width):
        if width == 2:
            return struct.unpack_from("<H", buf, pos)[0], pos + 2
        return struct.unpack_from("<I", buf, pos)[0], pos + 4

    # Row widths for the portable tables that are actually present. A wider
    # coded index is only needed for CustomDebugInformation, which we count
    # and do not walk.
    widths = {}
    for bit in bits:
        if bit == 0x30:
            widths[bit] = blob_w + guid_w + blob_w + guid_w
        elif bit == 0x31:
            widths[bit] = index_width(0x30) + blob_w
        elif bit == 0x32:
            widths[bit] = index_width(0x06) + index_width(0x35) + index_width(0x33) + index_width(0x34) + 8
        elif bit == 0x33:
            widths[bit] = 4 + string_w
        elif bit == 0x34:
            widths[bit] = string_w + blob_w
        elif bit == 0x35:
            widths[bit] = index_width(0x35) + blob_w
        elif bit == 0x36:
            widths[bit] = index_width(0x06) * 2
        elif bit == 0x37:
            widths[bit] = None
        else:
            widths[bit] = None
    pos = cursor
    documents = []
    locals_ = []
    for bit in bits:
        count = rows[bit]
        width = widths.get(bit)
        if width is None:
            break
        body = tilde[pos:pos + count * width]
        pos += count * width
        if bit == 0x30:
            row_at = 0
            for _ in range(count):
                name_i, row_at = take(body, row_at, blob_w)
                _, row_at = take(body, row_at, guid_w)
                _, row_at = take(body, row_at, blob_w)
                _, row_at = take(body, row_at, guid_w)
                label = _document_name(blobs, name_i)
                if label:
                    documents.append(label)
        elif bit == 0x33:
            row_at = 0
            for _ in range(min(count, 4000)):
                _, row_at = take(body, row_at, 2)
                _, row_at = take(body, row_at, 2)
                name_i, row_at = take(body, row_at, string_w)
                label = _cstr(strings, name_i)
                if label:
                    locals_.append(label[:80])
            # Skip the unread tail of a truncated walk.
            row_at = count * width
    catalog = {_TABLES.get(bit, "table_%02x" % bit): rows[bit] for bit in bits}
    return {"format": "portable-pdb", "tables": catalog, "documents": rows.get(0x30, 0),
            "document_names": documents[:limit], "local_variables": rows.get(0x33, 0),
            "local_names": locals_[:limit], "locals_recovered": len(locals_)}


def _skip_numeric(body, off):
    if off + 2 > len(body):
        return off
    leaf = struct.unpack_from("<H", body, off)[0]
    if leaf < 0x8000:
        return off + 2
    extra = {0x8000: 0, 0x8001: 0, 0x8002: 1, 0x8003: 2, 0x8004: 2, 0x8005: 4, 0x8006: 4, 0x8007: 4,
             0x8008: 4, 0x8009: 8, 0x800A: 8}.get(leaf)
    if extra is None:
        return off + 2
    return off + 2 + extra


def _tpi(blob, limit):
    if len(blob) < 28:
        return {"records": 0, "names": []}
    _version, header_size, begin, end, rec_bytes = struct.unpack_from("<IIIII", blob, 0)
    if header_size < 28 or header_size > len(blob):
        return {"records": 0, "names": []}
    data = blob[header_size:header_size + min(rec_bytes, len(blob) - header_size)]
    names = []
    count = 0
    index = 0
    while index + 4 <= len(data) and count < 8000:
        length = struct.unpack_from("<H", data, index)[0]
        if length < 2 or index + 2 + length > len(data):
            break
        leaf = struct.unpack_from("<H", data, index + 2)[0]
        body = data[index + 4:index + 2 + length]
        count += 1
        if leaf in _LEAVES and len(body) >= 16:
            cursor = _skip_numeric(body, 16)
            text = _cstr(body, cursor)
            if text:
                names.append({"kind": _LEAVES[leaf], "name": text[:80]})
        index += 2 + length
    return {"records": max(count, max(0, end - begin)), "names": names[:limit]}


def _msf(data, limit):
    if len(data) < 56 or not data.startswith(_MSF):
        raise ValueError("Not an MSF 7.00 PDB.")
    block_size, _free, num_blocks, dir_bytes, _reserved, map_addr = struct.unpack_from("<IIIIII", data, 32)
    if block_size not in {512, 1024, 2048, 4096} or dir_bytes <= 0 or dir_bytes > 8_000_000:
        raise ValueError("Unexpected MSF directory.")
    if num_blocks * block_size < len(data) - block_size or map_addr >= num_blocks:
        raise ValueError("MSF block map is out of range.")

    def piece(indices, size):
        out = bytearray()
        for number in indices:
            start = number * block_size
            out += data[start:start + block_size]
        return bytes(out[:size])

    map_count = (dir_bytes + block_size - 1) // block_size
    map_off = map_addr * block_size
    map_index = list(struct.unpack_from("<%dI" % map_count, data, map_off))
    directory = piece(map_index, dir_bytes)
    nstreams = struct.unpack_from("<I", directory, 0)[0]
    if nstreams > 100000:
        raise ValueError("MSF stream count is not plausible.")
    sizes = list(struct.unpack_from("<%dI" % nstreams, directory, 4))
    cursor = 4 + 4 * nstreams
    streams = []
    for size in sizes:
        if size in {0xFFFFFFFF, 0}:
            streams.append(b"")
            continue
        blocks = (size + block_size - 1) // block_size
        indices = list(struct.unpack_from("<%dI" % blocks, directory, cursor))
        cursor += 4 * blocks
        streams.append(piece(indices, size))
    info = streams[1] if len(streams) > 1 else b""
    if len(info) < 28:
        raise ValueError("PDB info stream is truncated.")
    version, _signature, age = struct.unpack_from("<III", info, 0)
    guid = str(uuid.UUID(bytes_le=info[12:28]))
    types = _tpi(streams[2], limit) if len(streams) > 2 else {"records": 0, "names": []}
    return {"format": "msf", "msf_version": version, "age": age, "guid": guid,
            "type_records": types["records"], "type_names": types["names"]}
