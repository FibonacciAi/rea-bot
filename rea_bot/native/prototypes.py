"""Calling conventions and a small prototype catalog Lostwax owns.

Names and types here are the ones we apply when a binary has no DWARF and no PDB.
They are not a copy of any system header. Nothing is executed.
"""
import re

# Integer argument registers, in order. Stack arguments follow these.
REGS = {
    "sysv": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "win64": ["rcx", "rdx", "r8", "r9"],
    "aapcs64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
}

# Caller-saved registers that a call may overwrite. Callee-saved registers stay.
CLOBBER = {
    "sysv": ["rax", "eax", "rcx", "ecx", "rdx", "edx", "rsi", "esi", "rdi", "edi",
             "r8", "r8d", "r9", "r9d", "r10", "r10d", "r11", "r11d"],
    "win64": ["rax", "eax", "rcx", "ecx", "rdx", "edx", "r8", "r8d", "r9", "r9d",
              "r10", "r10d", "r11", "r11d"],
    "aapcs64": ["x%d" % i for i in range(19)] + ["w%d" % i for i in range(19)],
}

# name -> (return type, [(type, parameter name), ...])
# A trailing None marks a variadic function; the fixed parameters are the list.
_CATALOG = {
    "getopt": ("int", [("int", "argc"), ("char **", "argv"), ("char *", "optstring")]),
    "getopt_long": ("int", [("int", "argc"), ("char **", "argv"), ("char *", "optstring"),
                            ("void *", "longopts"), ("int *", "longindex")]),
    "getopt_long_only": ("int", [("int", "argc"), ("char **", "argv"), ("char *", "optstring"),
                                 ("void *", "longopts"), ("int *", "longindex")]),
    "printf": ("int", [("char *", "format")], True),
    "fprintf": ("int", [("void *", "stream"), ("char *", "format")], True),
    "sprintf": ("int", [("char *", "buf"), ("char *", "format")], True),
    "snprintf": ("int", [("char *", "buf"), ("int", "len"), ("char *", "format")], True),
    "puts": ("int", [("char *", "s")]),
    "fputs": ("int", [("char *", "s"), ("void *", "stream")]),
    "malloc": ("void *", [("int", "size")]),
    "calloc": ("void *", [("int", "count"), ("int", "size")]),
    "realloc": ("void *", [("void *", "ptr"), ("int", "size")]),
    "free": ("void", [("void *", "ptr")]),
    "memcpy": ("void *", [("void *", "dest"), ("void *", "src"), ("int", "n")]),
    "memmove": ("void *", [("void *", "dest"), ("void *", "src"), ("int", "n")]),
    "memset": ("void *", [("void *", "dest"), ("int", "c"), ("int", "n")]),
    "memcmp": ("int", [("void *", "a"), ("void *", "b"), ("int", "n")]),
    "strlen": ("int", [("char *", "s")]),
    "strcmp": ("int", [("char *", "a"), ("char *", "b")]),
    "strncmp": ("int", [("char *", "a"), ("char *", "b"), ("int", "n")]),
    "strcpy": ("char *", [("char *", "dest"), ("char *", "src")]),
    "strncpy": ("char *", [("char *", "dest"), ("char *", "src"), ("int", "n")]),
    "strdup": ("char *", [("char *", "s")]),
    "strchr": ("char *", [("char *", "s"), ("int", "c")]),
    "strrchr": ("char *", [("char *", "s"), ("int", "c")]),
    "strstr": ("char *", [("char *", "haystack"), ("char *", "needle")]),
    "open": ("int", [("char *", "path"), ("int", "flags")], True),
    "close": ("int", [("int", "fd")]),
    "read": ("int", [("int", "fd"), ("void *", "buf"), ("int", "count")]),
    "write": ("int", [("int", "fd"), ("void *", "buf"), ("int", "count")]),
    "lseek": ("int", [("int", "fd"), ("int", "offset"), ("int", "whence")]),
    "stat": ("int", [("char *", "path"), ("void *", "buf")]),
    "fstat": ("int", [("int", "fd"), ("void *", "buf")]),
    "lstat": ("int", [("char *", "path"), ("void *", "buf")]),
    "fopen": ("void *", [("char *", "path"), ("char *", "mode")]),
    "fclose": ("int", [("void *", "stream")]),
    "fread": ("int", [("void *", "buf"), ("int", "size"), ("int", "count"), ("void *", "stream")]),
    "fwrite": ("int", [("void *", "buf"), ("int", "size"), ("int", "count"), ("void *", "stream")]),
    "exit": ("void", [("int", "status")]),
    "_exit": ("void", [("int", "status")]),
    "abort": ("void", []),
    "__errno_location": ("int *", []),
    "__libc_start_main": ("int", [("void *", "main"), ("int", "argc"), ("char **", "argv")]),
    "getenv": ("char *", [("char *", "name")]),
    "setlocale": ("char *", [("int", "category"), ("char *", "locale")]),
    "bindtextdomain": ("char *", [("char *", "domain"), ("char *", "dir")]),
    "textdomain": ("char *", [("char *", "domain")]),
    "malloc_usable_size": ("int", [("void *", "ptr")]),
    "CloseHandle": ("int", [("void *", "handle")]),
    "ReadFile": ("int", [("void *", "handle"), ("void *", "buf"), ("int", "len"), ("int *", "read"), ("void *", "overlapped")]),
    "WriteFile": ("int", [("void *", "handle"), ("void *", "buf"), ("int", "len"), ("int *", "written"), ("void *", "overlapped")]),
    "GetLastError": ("int", []),
    "CreateFileA": ("void *", [("char *", "name"), ("int", "access"), ("int", "share"), ("void *", "security"),
                               ("int", "disposition"), ("int", "flags"), ("void *", "template")]),
    "CreateFileW": ("void *", [("void *", "name"), ("int", "access"), ("int", "share"), ("void *", "security"),
                               ("int", "disposition"), ("int", "flags"), ("void *", "template")]),
}

ARGC_CALLEES = {"getopt", "getopt_long", "getopt_long_only"}


def normalize(name):
    """Import and PLT names, without a leading underscore or a version suffix."""
    text = str(name or "").strip()
    if not text:
        return ""
    text = text.split("@")[0]
    if text.startswith("__") and text[2:] in _CATALOG:
        return text
    if text.startswith("_") and text[1:] in _CATALOG:
        text = text[1:]
    return text


def lookup(name):
    key = normalize(name)
    row = _CATALOG.get(key)
    if not row:
        return None
    varargs = False
    if len(row) == 3:
        ret, params, varargs = row
    else:
        ret, params = row
    return {"name": key, "return": ret, "params": list(params), "varargs": bool(varargs)}


def convention_for(arch, binary_format):
    fmt = str(binary_format or "")
    if arch == "x86-64" and "PE" in fmt:
        return "win64"
    if arch == "x86-64":
        return "sysv"
    if arch == "arm64":
        return "aapcs64"
    return ""


def usage_signature(callee_names, existing=None):
    """argc/argv when a function calls getopt and DWARF did not already name the parameters."""
    existing = existing or {}
    if existing.get("source") == "dwarf":
        return existing
    names = {normalize(name) for name in callee_names or [] if name}
    if not names & ARGC_CALLEES:
        return existing
    out = dict(existing)
    out["args"] = ["int argc", "char **argv"]
    out["nargs"] = 2
    out["returns"] = existing.get("returns") if existing.get("returns") not in {None, "", "unknown", "gpr0"} else "int"
    out["source"] = "usage"
    out["name"] = existing.get("name") or "main"
    return out


def extern_prototypes(imports):
    """Catalog rows for import names present in one binary."""
    found = []
    seen = set()
    for name in imports or []:
        text = name.get("name") if isinstance(name, dict) else name
        proto = lookup(text)
        if not proto or proto["name"] in seen:
            continue
        seen.add(proto["name"])
        found.append(proto)
    return found


def signature_line(proto):
    if not proto:
        return ""
    args = ["%s %s" % pair for pair in proto["params"]]
    if proto.get("varargs"):
        args.append("...")
    return "%s %s(%s)" % (proto["return"], proto["name"], ", ".join(args))


def readable_name(token):
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(token or "")))
