"""Recursive unpacking for zip, tar, gzip, bzip2, xz, ar/deb and Electron asar.

Members are written under the destination. Paths that escape the destination, symlinks,
and special files are refused. Nothing inside an archive is executed.
"""
import bz2
import gzip
import io
import json
import lzma
import struct
import tarfile
import zipfile
from pathlib import Path

MAX_FILES = 2000
MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 4
_NEST = {".zip", ".jar", ".nupkg", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".deb", ".asar", ".a"}


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


def _kind(name, data):
    low = name.lower()
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
                            "Caps: %d files, %d bytes, depth %d." % (MAX_FILES, MAX_BYTES, MAX_DEPTH)]}
