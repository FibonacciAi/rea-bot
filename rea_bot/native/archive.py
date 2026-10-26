"""Recursive unpacking for zip, tar, gzip, bzip2, xz, ar/deb, Electron asar, CAB, MSI and NSIS.

Members are written under the destination. Paths that escape the destination, symlinks,
and special files are refused. Nothing inside an archive is executed.
"""
import bz2
import gzip
import io
import json
import lzma
import struct
import zlib
import tarfile
import zipfile
from pathlib import Path

MAX_FILES = 2000
MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 4
_NEST = {".zip", ".jar", ".nupkg", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".deb", ".asar", ".a", ".msi", ".cab"}


def _safe_name(name):
    raw = name.replace("\\", "/").strip()
    if not raw or raw.startswith("/") or raw.startswith("../") or "/../" in "/" + raw or raw == "..":
        raise ValueError("Archive member escapes the destination.")
    parts = [p for p in raw.split("/") if p not in {"", "."}]
    if any(p == ".." for p in parts):
        raise ValueError("Archive member escapes the destination.")
    if not parts:
        raise ValueError("Archive member has an empty name.")
    return "/".join(parts)


def _write(dest, name, data, budget):
    rel = _safe_name(name)
    if budget["files"] >= MAX_FILES or budget["bytes"] + len(data) > MAX_BYTES:
        budget["truncated"] = True
        return None
    path = dest / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    budget["files"] += 1
    budget["bytes"] += len(data)
    return path


def _asar_header(data):
    if len(data) < 16 or data[:4] != b"\x04\x00\x00\x00":
        raise ValueError("Not an asar archive.")
    header_size = struct.unpack_from("<I", data, 4)[0]
    if 8 + header_size > len(data):
        raise ValueError("Truncated asar header.")
    payload_size = struct.unpack_from("<I", data, 8)[0]
    if 12 + payload_size > 8 + header_size:
        raise ValueError("Truncated asar pickle.")
    strlen = struct.unpack_from("<I", data, 12)[0]
    raw = data[16:16 + strlen]
    header = json.loads(raw)
    return header, 8 + header_size


def unpack_asar(data, dest, budget):
    header, base = _asar_header(data)
    files = []

    def walk(node, prefix):
        for name, info in (node.get("files") or {}).items():
            rel = prefix + name
            if "files" in info:
                walk(info, rel + "/")
            elif "offset" in info and not info.get("unpacked"):
                start = base + int(info["offset"])
                size = int(info["size"])
                files.append((rel, data[start:start + size]))
    walk(header, "")
    written = []
    for name, blob in files:
        path = _write(dest, name, blob, budget)
        if path:
            written.append(str(path.relative_to(dest)))
    return written


def pack_asar(members):
    """Build an asar the Electron reader accepts. `members` is a list of (relative path, bytes)."""
    header = {"files": {}}
    blob = bytearray()
    for rel, content in members:
        node = header["files"]
        parts = _safe_name(rel).split("/")
        for part in parts[:-1]:
            node = node.setdefault(part, {"files": {}})["files"]
        node[parts[-1]] = {"size": len(content), "offset": str(len(blob))}
        blob.extend(content)
    raw = json.dumps(header, separators=(",", ":")).encode()
    pad = (4 - (len(raw) % 4)) % 4
    payload = struct.pack("<I", len(raw)) + raw + b"\x00" * pad
    header_buf = struct.pack("<I", len(payload)) + payload
    size_buf = struct.pack("<II", 4, len(header_buf))
    return size_buf + header_buf + bytes(blob)


def _ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Not an ar archive.")
    off = 8
    out = []
    while off + 60 <= len(data):
        header = data[off:off + 60]
        if header[58:60] != b"`\n":
            break
        name = header[:16].decode("ascii", "replace").strip()
        size = int(header[48:58].decode("ascii").strip() or "0")
        off += 60
        blob = data[off:off + size]
        off += size + (size & 1)
        if name.startswith("#1/"):
            n = int(name[3:])
            name = blob[:n].decode("ascii", "replace").strip("\x00")
            blob = blob[n:]
        out.append((name, blob))
    return out


def _inflate(blob):
    """NSIS and MSZIP both store raw deflate. LZMA is the other NSIS method."""
    try:
        return zlib.decompress(blob, -15)
    except zlib.error:
        pass
    if len(blob) >= 5:
        props = blob[0]
        dict_size = struct.unpack_from("<I", blob, 1)[0]
        if 0 < dict_size <= 64 * 1024 * 1024 and props < 225:
            lc = props % 9
            rest = props // 9
            pb = rest // 5
            lp = rest % 5
            if lc <= 8 and lp <= 4 and pb <= 4:
                try:
                    return lzma.decompress(blob[5:], format=lzma.FORMAT_RAW, filters=[{
                        "id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}])
                except lzma.LZMAError:
                    pass
    raise ValueError("Compressed installer block was not deflate or LZMA.")


def _nsis_chunks(buf):
    out = []
    index = 0
    while index + 4 <= len(buf):
        word = struct.unpack_from("<I", buf, index)[0]
        index += 4
        if word == 0:
            break
        size = word & 0x7FFFFFFF
        if size == 0 or index + size > len(buf):
            # A trailing CRC does not start another block.
            return out or None
        raw = buf[index:index + size]
        index += size
        out.append(raw if word < 0x80000000 else _inflate(raw))
    return out


def _utf16(buf, off):
    if off < 0 or off + 2 > len(buf):
        return ""
    chars = []
    while off + 1 < len(buf) and len(chars) < 180:
        code = struct.unpack_from("<H", buf, off)[0]
        if code == 0:
            break
        if code < 32 or code == 127:
            return ""
        chars.append(chr(code))
        off += 2
    return "".join(chars)


def _filename(text):
    if not text or len(text) > 160:
        return ""
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in text):
        return ""
    if any(ch in text for ch in " :*\"<>|"):
        return ""
    if "." not in text.strip("."):
        return ""
    return text.replace("\\", "/")


def _nsis_files(header, payloads):
    """Pair EW_EXTRACTFILE entries (opcode 20 in a standard NSIS 3 build) with data blocks."""
    bases = []
    count = min(len(header) // 4, 80)
    for value in struct.unpack_from("<%dI" % count, header):
        if 0 < value < len(header) and value % 2 == 0:
            bases.append(value)
    best = {}
    for index in range(0, len(header) - 28, 4):
        which, _flag, name_off, data_index = struct.unpack_from("<IIII", header, index)
        if which != 20 or data_index >= len(payloads) or name_off > 100000:
            continue
        for base in bases:
            at = base + name_off * 2
            if at >= 2 and struct.unpack_from("<H", header, at - 2)[0] != 0:
                continue
            label = _filename(_utf16(header, at))
            if not label:
                continue
            # Prefer the longer real filename when several dword alignments match opcode 20.
            if data_index not in best or len(label) > len(best[data_index][0]):
                best[data_index] = (label, payloads[data_index])
            break
    if best:
        return [best[i] for i in sorted(best)]
    return [("file-%d.bin" % i, blob) for i, blob in enumerate(payloads)]


def _nsis_members(data):
    sig = struct.pack("<I", 0xDEADBEEF)
    magic = struct.pack("<III", 0x6C6C754E, 0x74666F73, 0x74736E49)
    start = 0
    while True:
        found = data.find(sig, start)
        if found < 4:
            break
        if data[found + 4:found + 16] != magic:
            start = found + 1
            continue
        pos = found - 4
        header_len, following = struct.unpack_from("<II", data, pos + 20)
        if following < 28 or following > len(data) or header_len > 8_000_000:
            start = found + 1
            continue
        layouts = []
        if pos == len(data) - following:
            layouts.append(data[pos + 28:])
        if pos + 28 >= following:
            layouts.append(data[pos + 28 - following:pos])
        for blob in layouts:
            try:
                chunks = _nsis_chunks(blob)
            except ValueError:
                chunks = None
            if not chunks:
                continue
            if len(chunks[0]) == header_len and len(chunks) > 1:
                return _nsis_files(chunks[0], chunks[1:])
            if len(chunks) == 1 and len(chunks[0]) > header_len:
                return _nsis_files(chunks[0][:header_len], [chunks[0][header_len:]])
        start = found + 1
    raise ValueError("Not an NSIS installer.")


def _cab_members(data):
    if len(data) < 36 or data[:4] != b"MSCF":
        raise ValueError("Not a cabinet.")
    _reserved, size, _res2, files_off, _res3 = struct.unpack_from("<IIIII", data, 4)
    nfolders, nfiles, flags, _setid, _index = struct.unpack_from("<HHHHH", data, 26)
    if size > len(data) + 16 or nfolders < 1 or nfiles < 1 or nfolders > 1000 or nfiles > MAX_FILES:
        raise ValueError("Cabinet header is not plausible.")
    off = 36
    if flags & 0x0004:
        if off + 4 > len(data):
            raise ValueError("Cabinet reserve header is truncated.")
        cb_header, cb_folder, cb_data = struct.unpack_from("<HHH", data, off)
        off += 4 + cb_header
    else:
        cb_folder = cb_data = 0
    folders = []
    for _ in range(nfolders):
        coff, count, method = struct.unpack_from("<IHH", data, off)
        off += 8 + cb_folder
        if method not in {0, 1}:
            raise ValueError("Cabinet compression %d is not stored or MSZIP." % method)
        folders.append((coff, count, method))
    if files_off > len(data):
        raise ValueError("Cabinet file table is out of range.")
    cursor = files_off
    files = []
    for _ in range(nfiles):
        cb_file, uoff, folder, _date, _time, _attr = struct.unpack_from("<IIHHHH", data, cursor)
        cursor += 16
        end = data.find(b"\x00", cursor)
        if end < 0:
            raise ValueError("Cabinet file name is truncated.")
        name = data[cursor:end].decode("utf-8", "replace")
        cursor = end + 1
        files.append((name, cb_file, uoff, folder))
    return _cab_read(data, folders, files, cb_data)


def _cab_read(data, folders, files, cb_data):
    inflated = []
    for coff, count, method in folders:
        blob = bytearray()
        at = coff
        for _ in range(count):
            if at + 8 > len(data):
                raise ValueError("Cabinet data block is truncated.")
            _sum, cb_comp, cb_uncomp = struct.unpack_from("<IHH", data, at)
            at += 8
            raw = data[at + cb_data:at + cb_data + cb_comp]
            at += cb_data + cb_comp
            if method == 0:
                blob += raw
            else:
                if raw[:2] != b"CK":
                    raise ValueError("MSZIP block is missing its CK header.")
                blob += zlib.decompress(raw[2:], -15)
        inflated.append(bytes(blob))
    out = []
    for name, cb_file, uoff, folder in files:
        if folder >= len(inflated):
            continue
        out.append((name, inflated[folder][uoff:uoff + cb_file]))
    return out


def _msi_members(data):
    from .runtime import activate
    activate()
    try:
        import olefile
    except ImportError as err:
        raise ValueError("MSI unpacking needs the pinned olefile wheel from native setup.") from err
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as err:
        raise ValueError("Not an MSI compound file.") from err
    out = []
    try:
        for stream in ole.listdir():
            label = "/".join(part for part in stream if part)
            if not label or label.startswith("\x05"):
                continue
            blob = ole.openstream(stream).read()
            cab_at = blob.find(b"MSCF")
            if 0 <= cab_at < 4096:
                for name, content in _cab_members(blob[cab_at:]):
                    out.append((name, content))
                continue
            printable = bool(label) and all(32 <= ord(ch) < 127 or ch in "/\\" for ch in label)
            if printable and blob.strip(b"\x00"):
                out.append((label, blob))
    finally:
        ole.close()
    if not out:
        raise ValueError("MSI contained no extractable streams.")
    return out


def _is_nsis(data):
    tail = data[-1_000_000:]
    return b"NullsoftInst" in tail and b"\xef\xbe\xad\xde" in tail


def _kind(name, data):
    low = name.lower()
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or low.endswith(".msi"):
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return "msi"
    if data[:4] == b"MSCF" or low.endswith(".cab"):
        if data[:4] == b"MSCF":
            return "cab"
    if data[:2] == b"MZ" and _is_nsis(data):
        return "nsis"
    if low.endswith(".asar") or (len(data) > 4 and data[:4] == b"\x04\x00\x00\x00" and low.endswith(".asar")):
        return "asar"
    if data.startswith(b"!<arch>\n") or low.endswith(".deb") or low.endswith(".a"):
        return "ar"
    if low.endswith(".zip") or low.endswith(".jar") or low.endswith(".nupkg") or low.endswith(".whl") or data[:2] == b"PK":
        return "zip"
    if low.endswith(".tar") or data[257:262] == b"ustar":
        return "tar"
    if low.endswith(".tgz") or low.endswith(".tar.gz") or data[:2] == b"\x1f\x8b":
        return "gz"
    if low.endswith(".bz2") or data[:3] == b"BZh":
        return "bz2"
    if low.endswith(".xz") or data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    return None


def _children(kind, name, data):
    if kind == "asar":
        return None  # handled separately
    if kind == "ar":
        return _ar_members(data)
    if kind == "zip":
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.flag_bits & 0x1:
                    continue
                out.append((info.filename, zf.read(info)))
        return out
    if kind == "gz":
        inner = gzip.decompress(data)
        base = name[:-3] if name.endswith(".gz") else name + ".out"
        if base.endswith(".tgz"):
            base = name[:-4] + ".tar"
        return [(base, inner)]
    if kind == "bz2":
        return [(name[:-4] if name.endswith(".bz2") else name + ".out", bz2.decompress(data))]
    if kind == "xz":
        return [(name[:-3] if name.endswith(".xz") else name + ".out", lzma.decompress(data))]
    if kind == "cab":
        return _cab_members(data)
    if kind == "msi":
        return _msi_members(data)
    if kind == "nsis":
        return _nsis_members(data)
    if kind == "tar":
        out = []
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for member in tf.getmembers():
                if not member.isfile() or member.issym() or member.islnk():
                    if member.issym() or member.islnk():
                        raise ValueError("Refusing a symlink in a tar archive.")
                    continue
                extracted = tf.extractfile(member)
                if extracted:
                    out.append((member.name, extracted.read()))
        return out
    return []


def unpack(path, dest, depth=0, budget=None):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    budget = budget or {"files": 0, "bytes": 0, "truncated": False, "archives": []}
    data = Path(path).read_bytes()
    kind = _kind(Path(path).name, data)
    if kind is None:
        raise ValueError("Unsupported archive.")
    budget["archives"].append({"name": Path(path).name, "kind": kind, "bytes": len(data)})
    if kind == "asar":
        written = unpack_asar(data, dest, budget)
    else:
        written = []
        for name, blob in _children(kind, Path(path).name, data):
            path_out = _write(dest, name, blob, budget)
            if path_out:
                written.append(str(path_out.relative_to(dest)))
    nested = []
    if depth + 1 < MAX_DEPTH:
        for rel in list(written):
            child = dest / rel
            if not child.is_file():
                continue
            head = child.read_bytes()[:8]
            if _kind(child.name, head) or child.suffix.lower() in _NEST:
                try:
                    sub = child.read_bytes()
                    if _kind(child.name, sub) is None:
                        continue
                    subdest = dest / (rel + ".unpacked")
                    unpack(child, subdest, depth + 1, budget)
                    nested.append(rel)
                except ValueError:
                    continue
    return {"kind": kind, "files": written, "nested": nested, "file_count": budget["files"],
            "bytes": budget["bytes"], "truncated": budget["truncated"], "archives": budget["archives"],
            "scripts_executed": False,
            "limitations": ["Archives are unpacked only. Members are not executed.",
                            "Symlinks and encrypted zip members are refused.",
                            "MSI cabinets are stored or MSZIP. NSIS blocks are raw deflate or LZMA. Quantum and LZX cabinets are refused.",
                            "Caps: %d files, %d bytes, depth %d." % (MAX_FILES, MAX_BYTES, MAX_DEPTH)]}
