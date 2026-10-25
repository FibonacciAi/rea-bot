"""Opt-in Ghidra 12.1.4 backend. Lostwax drives analyzeHeadless itself.

The pinned release is downloaded only by `ghidra setup --apply` after the
approve token. Every existing tree entry must match the locally available,
SHA-pinned release archive. The target is imported for static analysis and is not executed.
REA is not on this path.
"""
from contextlib import contextmanager
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from .. import runner

PIN = json.loads((Path(__file__).resolve().parent / "ghidra_pin.json").read_text())
APPROVE = PIN["approve"]
SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"
_NAME = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]{0,180}")
_SYNTHETIC = re.compile(r"sub_[0-9a-fA-F]+")
MAX_BINARIES = 2
MAX_REPORT_BYTES = 128 * 1024 * 1024


def ghidra_home():
    return Path(os.environ.get("REA_BOT_GHIDRA_HOME") or "/workspace/.rea-bot-ghidra")


def _java_home():
    env = os.environ.get("JAVA_HOME")
    if env:
        if not Path(env).is_absolute():
            return None
        java = Path(env) / "bin" / "java"
    else:
        java = shutil.which("java")
    if not java:
        return None
    java = Path(java).resolve()
    home = java.parent.parent
    if java.name == "java" and java.parent.name == "bin" and java.is_file() and os.access(java, os.X_OK):
        return str(home)
    return None


def _environment(cwd, java_home):
    # Do not inherit JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS, CLASSPATH, loader hooks,
    # credentials, or user configuration. Ghidra and the probe use this same Java.
    cwd = str(cwd)
    return {"PATH": str(Path(java_home) / "bin") + os.pathsep + os.defpath,
            "JAVA_HOME": str(java_home), "HOME": cwd, "TMPDIR": cwd,
            "XDG_CONFIG_HOME": cwd, "XDG_CACHE_HOME": cwd,
            "JAVA_TOOL_OPTIONS": '-Duser.home="' + cwd.replace('\\', '\\\\').replace('"', '\\"') + '"',
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def _java_version():
    home = _java_home()
    if home is None:
        return None
    java = str(Path(home) / "bin" / "java")
    with tempfile.TemporaryDirectory(prefix="lostwax-java-") as tmp:
        proc = runner._capture_command([java, "-version"], b"", 15, tmp,
                                       environment=_environment(tmp, home))
    if not proc["ok"] or proc.get("exit_code") != 0:
        return None
    text = proc.get("stderr_tail", "") + proc.get("raw_stdout", b"").decode("utf-8", "replace")
    match = re.search(r'version "(\d+)', text)
    if not match:
        return None
    line = next((line for line in text.splitlines() if re.search(r'version "\d+', line)), "")
    return {"major": int(match.group(1)), "line": line,
            "home": home, "executable": java}


def _digest(handle):
    result = hashlib.sha256()
    while True:
        chunk = handle.read(1 << 20)
        if not chunk:
            return result.hexdigest()
        result.update(chunk)


@contextmanager
def _trusted_archive(archive):
    # Hash and read the same open file, so renaming the path cannot substitute bytes.
    with Path(archive).open("rb") as handle:
        if _digest(handle) != PIN["sha256"]:
            raise ValueError("Ghidra zip failed SHA-256 verification.")
        handle.seek(0)
        with zipfile.ZipFile(handle) as package:
            yield package


def _archive_manifest(archive):
    """Trusted, complete byte manifest; never accept an unsigned on-disk receipt."""
    with _trusted_archive(archive) as package:
        return _package_manifest(package)


def _package_manifest(package):
    top = "ghidra_%s_PUBLIC" % PIN["version"]
    manifest, seen = {"": ("dir", None)}, set()
    for info in package.infolist():
        name = info.filename
        parts = PurePosixPath(name).parts
        mode = stat.S_IFMT(info.external_attr >> 16)
        if (not name or name != info.orig_filename or "\x00" in name or "\\" in name or
                name.startswith("/") or any(p in (".", "..") or ":" in p for p in parts) or
                not parts or parts[0] != top or "/".join(parts) + ("/" if info.is_dir() else "") != name or
                mode not in (0, stat.S_IFREG, stat.S_IFDIR) or
                (mode == stat.S_IFDIR and not info.is_dir()) or
                (info.is_dir() and (mode == stat.S_IFREG or info.file_size)) or info.flag_bits & 1):
            raise ValueError("Ghidra zip contains an unsafe or malformed entry.")
        rel = "/".join(parts[1:])
        if rel in seen or (not rel and not info.is_dir()):
            raise ValueError("Ghidra zip contains a duplicate or malformed entry.")
        seen.add(rel)
        for index in range(1, len(parts) - 1):
            parent = "/".join(parts[1:index + 1])
            if parent in manifest and manifest[parent][0] != "dir":
                raise ValueError("Ghidra zip contains conflicting entries.")
            manifest[parent] = ("dir", None)
        if info.is_dir():
            kind = ("dir", None)
        else:
            with package.open(info) as handle:
                kind = ("file", _digest(handle))
        if rel in manifest and manifest[rel] != kind:
            raise ValueError("Ghidra zip contains conflicting entries.")
        manifest[rel] = kind
    if (manifest.get("support/analyzeHeadless", (None,))[0] != "file" or
            manifest.get(PIN["properties_rel"]) != ("file", PIN["properties_sha256"])):
        raise ValueError("Ghidra zip does not contain the pinned release files.")
    return manifest


def _tree_manifest(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Ghidra tree must be a directory without symlinks.")
    manifest = {"": ("dir", None)}
    def fail(error):
        raise error
    for current, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in dirs + files:
            path = Path(current) / name
            mode = path.lstat().st_mode
            rel = path.relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                manifest[rel] = ("dir", None)
            elif stat.S_ISREG(mode):
                with path.open("rb") as handle:
                    manifest[rel] = ("file", _digest(handle))
            else:
                raise ValueError("Ghidra tree contains a symlink or special file.")
    return manifest


def _verified(root):
    root = Path(root)
    archives = (ghidra_home() / "cache" / PIN["filename"], root.parent / PIN["filename"])
    for archive in dict.fromkeys(archives):
        try:
            manifest = _archive_manifest(archive)
            if _tree_manifest(root) != manifest:
                return None
            if PIN["version_line"] not in (root / PIN["properties_rel"]).read_text(errors="replace"):
                return None
            return root.resolve()
        except (OSError, ValueError, zipfile.BadZipFile):
            continue
    return None


def resolve_install():
    """Return the pinned Ghidra root, or None. A wrong GHIDRA_INSTALL_DIR does not fall through."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        return _verified(env)
    home = ghidra_home()
    for candidate in (home / ("ghidra_%s_PUBLIC" % PIN["version"]), home):
        found = _verified(candidate)
        if found is not None:
            return found
    return None


def _problems(java, install):
    found = []
    if java is None:
        found.append("Java %s was not found at the selected JAVA_HOME or PATH. The pinned Ghidra build needs it." % PIN["java_major"])
    elif java["major"] != PIN["java_major"]:
        found.append("Java %s was found (%s). The pinned Ghidra build needs Java %s." % (
            java["major"], java["line"], PIN["java_major"]))
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and install is None:
        found.append("GHIDRA_INSTALL_DIR is not the verified Ghidra %s release. The complete tree must match the SHA-pinned local zip in the ghidra home cache or beside the tree." % PIN["version"])
    elif install is None:
        found.append("Ghidra %s is not installed. Run `rea-bot ghidra setup`, then "
                     "`rea-bot ghidra setup --apply --approve-source %s`, or set GHIDRA_INSTALL_DIR to a complete tree with its SHA-pinned zip cached locally."
                     % (PIN["version"], APPROVE))
    return found


def problems():
    return _problems(_java_version(), resolve_install())


def plan():
    return {"engine": "lostwax-ghidra@" + PIN["version"], "home": str(ghidra_home()),
            "version": PIN["version"], "sha256": PIN["sha256"], "url": PIN["url"], "approve": APPROVE,
            "java_major": PIN["java_major"],
            "effects": "Downloads the pinned Ghidra zip, checks SHA-256, and extracts it under the ghidra home. "
                       "Existing trees require an exact complete byte match to that locally retained zip. "
                       "Does not install Java. Does not execute a target. Not part of the default install."}


def status():
    info = plan()
    java = _java_version()
    install = resolve_install()
    info["java"] = None if java is None else java
    info["install"] = None if install is None else str(install)
    info["problems"] = _problems(java, install)
    info["ready"] = not info["problems"]
    info["applied"] = install is not None
    return info


def _download(url, dest, digest):
    digest = digest.lower()
    hasher = hashlib.sha256()
    tmp = dest.with_suffix(dest.suffix + ".partial")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, tmp.open("wb") as handle:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                hasher.update(chunk)
                handle.write(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("Ghidra zip failed SHA-256 verification.")
        tmp.replace(dest)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _extract(archive, dest):
    dest = Path(dest)
    root = dest.resolve()
    with _trusted_archive(archive) as package:
        _package_manifest(package)
        for info in package.infolist():
            target = dest / info.filename
            if dest.is_symlink() or any(p.is_symlink() for p in (target, *target.parents) if p == dest or dest in p.parents):
                raise ValueError("Ghidra extraction destination contains a symlink.")
            target = target.resolve()
            if target != root and root not in target.parents:
                raise ValueError("Ghidra zip contains an unsafe path.")
        package.extractall(dest)


def setup(apply=False, approve=None):
    info = status()
    if not apply:
        info["applied"] = info["ready"]
        info["next"] = None if info["ready"] else "Re-run with --apply --approve-source " + APPROVE + " after approval."
        return info
    if approve != APPROVE:
        raise ValueError("--apply needs --approve-source " + APPROVE + ".")
    java = _java_version()
    if java is None or java["major"] != PIN["java_major"]:
        raise ValueError(problems()[0])
    if os.environ.get("GHIDRA_INSTALL_DIR") and resolve_install() is None:
        raise ValueError(problems()[0])
    if resolve_install() is not None and not os.environ.get("GHIDRA_INSTALL_DIR"):
        info["applied"] = True
        info["ready"] = True
        info["problems"] = []
        return info
    if resolve_install() is not None:
        info["applied"] = True
        return info
    home = ghidra_home()
    cache = home / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / PIN["filename"]
    if not archive.is_file() or runner.sha256_file(archive) != PIN["sha256"]:
        _download(PIN["url"], archive, PIN["sha256"])
    _extract(archive, home)
    install = resolve_install()
    if install is None:
        raise ValueError("The extracted tree did not completely match the pinned Ghidra %s zip." % PIN["version"])
    receipt = {"version": PIN["version"], "approve": APPROVE, "sha256": PIN["sha256"],
               "properties_sha256": PIN["properties_sha256"], "install": str(install), "java_major": java["major"]}
    (home / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return status()


def _typed_arg(text):
    """Split `char **argv` into the type and the parameter name. Stars stay on the type."""
    raw = str(text or "").strip()
    match = re.search(r"[A-Za-z_][A-Za-z0-9_]*$", raw)
    if not match:
        return "", ""
    pname = _token(match.group(0))
    ptype = raw[:match.start()].strip()
    return pname, ptype


def _token(text):
    match = _NAME.search(str(text or ""))
    if not match:
        return ""
    token = match.group(0)
    if _SYNTHETIC.fullmatch(token):
        return ""
    return token


def hints_from(report):
    """Names, DWARF signatures and decompile hints from a native binary report."""
    names = {}
    signatures = {}
    hints = []
    base = int(str(report.get("imagebase") or "0x0"), 16)
    for func in report.get("functions_detail") or []:
        addr = int(func["address"], 16)
        token = _token(func.get("name"))
        if token and token not in {"entry"}:
            names.setdefault(addr, token)
        elif token == "entry":
            names.setdefault(addr, "entry")
        signature = func.get("signature") or {}
        if signature.get("source") in {"dwarf", "usage"}:
            signatures[addr] = signature
            hints.append(addr)
        if token in {"main", "add", "_start", "entry"}:
            hints.append(addr)
        for callee in func.get("callees") or []:
            if callee.get("kind") == "import" and callee.get("address"):
                slot = int(callee["address"], 16)
                imported = _token(callee.get("name"))
                if imported:
                    names.setdefault(slot, imported)
    entry = report.get("entrypoint")
    if entry:
        hints.append(int(entry, 16))
    sample = (report.get("decompiler") or {}).get("sample_name")
    for func in report.get("functions_detail") or []:
        if sample and func.get("name") == sample:
            hints.append(int(func["address"], 16))
    ordered = []
    seen = set()
    for addr in hints:
        if addr not in seen:
            seen.add(addr)
            ordered.append(addr)
    return base, names, signatures, ordered[:24]


def externs_from(report):
    """Catalog prototypes for import names on a native report."""
    from .prototypes import extern_prototypes
    return extern_prototypes(report.get("imports") or [])


def _config_field(value):
    text = str(value)
    if len(text) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError("Unsafe control character or oversized field in Ghidra configuration metadata.")
    return text


def _config_line(*fields):
    return "\t".join(_config_field(field) for field in fields)


def _config(path, source_base, names, signatures, hints, limit, decomp_timeout, externs=None):
    lines = [_config_line("out", path), _config_line("source_base", "%x" % source_base),
             _config_line("limit", "%d" % limit), _config_line("decomp_timeout", "%d" % decomp_timeout)]
    for addr, name in list(names.items())[:16000]:
        token = _token(_config_field(name))
        if token:
            lines.append(_config_line("name", "%x" % addr, token))
    for addr, signature in signatures.items():
        for index, arg in enumerate(signature.get("args") or []):
            pname, ptype = _typed_arg(_config_field(arg))
            if pname:
                lines.append(_config_line("param", "%x" % addr, str(index), ptype, pname))
        returns = _config_field(signature.get("returns") or "")
        if returns and returns != "unknown":
            lines.append(_config_line("ret", "%x" % addr, returns))
    for proto in list(externs or [])[:500]:
        fields = ["extern", proto["name"], proto["return"]]
        for typ, pname in proto["params"]:
            if '|' in _config_field(typ) or '|' in _config_field(pname):
                raise ValueError("Unsafe parameter separator in Ghidra external prototype.")
            fields.append("%s|%s" % (typ, pname))
        if proto.get("varargs"):
            fields.append("...|")
        lines.append(_config_line(*fields))
    hinted = hints if int(limit) <= 0 else hints[:limit]
    for addr in hinted:
        lines.append(_config_line("hint", "%x" % addr))
    return "\n".join(lines) + "\n"


def _log_tail(path):
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 1500))
            text = handle.read(1500).decode("utf-8", "replace")
    except OSError:
        return ""
    return text[-1500:]


def _read_report(path):
    # Refuse known oversize files before allocating a buffer or parsing JSON.
    # Retain the bounded read as protection against growth after stat.
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Ghidra report exceeded %s bytes." % MAX_REPORT_BYTES)
    with path.open("rb") as handle:
        raw = handle.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Ghidra report exceeded %s bytes." % MAX_REPORT_BYTES)
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Ghidra report must be a JSON object.")
    return payload


def decompile(path, source_base=0, names=None, signatures=None, hints=None, analysis_timeout=480,
              decomp_timeout=60, limit=16, externs=None):
    """Import one file in headless Ghidra and return functions plus C. Does not execute the file."""
    java = _java_version()
    root = resolve_install()
    blocked = _problems(java, root)
    if blocked:
        raise ValueError(" ".join(blocked))
    headless = root / "support" / "analyzeHeadless"
    names = names or {}
    signatures = signatures or {}
    hints = hints or []
    # Zero retains upstream's all-internal-function selection. Wall time and
    # retained report size remain bounded; selection is not a completion claim.
    limit = max(0, min(int(limit), 100000))
    analysis_timeout = max(1, min(int(analysis_timeout), 7200))
    decomp_timeout = max(1, min(int(decomp_timeout), 300))
    started = time.perf_counter()
    path = Path(path).resolve()
    with tempfile.TemporaryDirectory(prefix="lostwax-ghidra-") as tmp:
        tmp = Path(tmp)
        project = tmp / "project"
        project.mkdir()
        config = tmp / "config.txt"
        output = tmp / "out.json"
        log = tmp / "analyze.log"
        home = tmp / "home"
        home.mkdir()
        config.write_text(_config(output, int(source_base), names, signatures, hints, limit, decomp_timeout, externs))
        cmd = [str(headless), str(project), "Lostwax", "-import", str(path), "-scriptPath", str(SCRIPT_DIR),
               "-postScript", "LostwaxDecompile.java", str(config), "-deleteProject",
               "-analysisTimeoutPerFile", str(int(analysis_timeout)), "-log", str(log)]
        if not os.access(headless, os.X_OK):
            shell = shutil.which("bash", path=os.defpath)
            if not shell:
                raise ValueError("bash is required to launch the verified analyzeHeadless script.")
            cmd.insert(0, shell)
        per_function = 7200 if limit == 0 else decomp_timeout * max(limit, 1)
        budget = min(14400, analysis_timeout + per_function + 180)
        proc = runner._capture_command(cmd, b"", budget, str(tmp),
                                       environment=_environment(home, java["home"]))
        if not proc["ok"]:
            raise ValueError("Ghidra analysis failed: %s. The target was not executed." % proc["error"])
        if proc.get("exit_code") != 0:
            detail = proc.get("stderr_tail") or proc.get("raw_stdout", b"").decode("utf-8", "replace") or _log_tail(log)
            raise ValueError("Ghidra analysis failed (exit %s). The target was not executed. %s" % (
                proc.get("exit_code"), detail[-1500:]))
        if not output.is_file():
            detail = (proc.get("stderr_tail") or proc.get("raw_stdout", b"").decode("utf-8", "replace") or _log_tail(log))[-1500:]
            raise ValueError("Ghidra did not write a decompiler report (exit %s). The target was not executed. %s" % (
                proc.get("exit_code"), detail))
        try:
            payload = _read_report(output)
        except ValueError as err:
            raise ValueError("Ghidra wrote an invalid report: %s The target was not executed." % err) from err
    payload["version"] = PIN["version"]
    payload["install"] = str(root)
    payload["seconds"] = round(time.perf_counter() - started, 2)
    payload["scripts_executed"] = False  # Target scripts were not executed.
    payload["target_executed"] = False
    payload["analysis_script_executed"] = True
    payload["requested_limit"] = limit
    payload["requested_scope"] = "all-internal" if limit == 0 else "bounded-selection"
    payload["process_budget_seconds"] = budget
    payload["decomp_timeout_seconds"] = decomp_timeout
    payload.update(_coverage(payload))
    payload["note"] = "analyzeHeadless imported the file for static analysis. The target was not executed."
    return payload


def _coverage(result):
    """Count successful bodies separately from attempts, failures and truncation."""
    rows = [row for row in result.get("decompiled") or [] if isinstance(row, dict)]
    completed = [row for row in rows if row.get("decompile_completed") is True and str(row.get("c") or "").strip()]
    full = [row for row in completed if not row.get("c_truncated")]
    def addresses(items):
        found = set()
        for row in items:
            try:
                found.add(int(row["address"], 16))
            except (KeyError, TypeError, ValueError):
                continue
        return found
    full_addresses = addresses(full)
    internal = addresses(row for row in result.get("functions") or []
                         if isinstance(row, dict) and row.get("external") is False)
    return {"attempted_count": len(rows), "completed_count": len(addresses(completed)),
            "decompiled_count": len(full_addresses), "failed_count": len(rows) - len(completed),
            "truncated_count": sum(bool(row.get("c_truncated")) for row in completed),
            "all_functions_complete": bool(internal) and result.get("requested_scope") == "all-internal" and
                result.get("internal") == len(internal) and internal == full_addresses and len(rows) == len(internal)}


def _source_address(ghidra_addr, ghidra_base, source_base, known):
    shifted = ghidra_addr - ghidra_base + source_base
    if shifted in known:
        return shifted
    if ghidra_addr in known:
        return ghidra_addr
    return shifted


def _markers(text):
    body = text or ""
    return {"has_left": "left" in body, "has_right": "right" in body,
            "has_getopt_long": "getopt_long" in body, "has_return": "return" in body,
            "chars": len(body)}


def merge(report, result, source_base=0):
    """Attach a Ghidra result to a native report. Native CFG and import edges stay in place."""
    known = set()
    for func in report.get("functions_detail") or []:
        try:
            known.add(int(func["address"], 16))
        except (TypeError, ValueError):
            continue
    ghidra_base = int(str(result.get("imagebase") or "0"), 16)
    functions = []
    matched = 0
    for item in result.get("functions") or []:
        try:
            ghidra_addr = int(item["address"], 16)
        except (TypeError, ValueError, KeyError):
            continue
        source = _source_address(ghidra_addr, ghidra_base, int(source_base), known)
        if source in known:
            matched += 1
        functions.append({"address": item.get("address"), "source_address": hex(source), "name": item.get("name") or "",
                          "external": bool(item.get("external")), "signature": item.get("signature") or ""})
    decompiled = []
    for item in result.get("decompiled") or []:
        try:
            ghidra_addr = int(item["address"], 16)
        except (TypeError, ValueError, KeyError):
            continue
        source = _source_address(ghidra_addr, ghidra_base, int(source_base), known)
        code = item.get("c") or ""
        calls = []
        for callee in item.get("calls") or []:
            try:
                callee_addr = int(callee.get("address") or "0", 16)
            except ValueError:
                callee_addr = 0
            calls.append({"name": callee.get("name") or "", "address": callee.get("address"),
                          "source_address": hex(_source_address(callee_addr, ghidra_base, int(source_base), known))})
        decompiled.append({"address": item.get("address"), "source_address": hex(source), "name": item.get("name") or "",
                           "signature": item.get("signature") or "", "decompile_completed": bool(item.get("decompile_completed")),
                           "c_truncated": bool(item.get("c_truncated")),
                           "c": code, "calls": calls, "markers": _markers(code)})
    sample = _pick_sample([row for row in decompiled if row["decompile_completed"] and row["c"] and not row["c_truncated"]])
    lines = []
    signature = ""
    if sample:
        raw_lines = (sample.get("c") or "").splitlines()
        content = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith(("/*", "*", "//"))]
        signature = content[0][:240] if content else (sample.get("signature") or "")
        lines = [line[:200] for line in raw_lines if line.strip()][:30]
    report["ghidra_functions"] = functions
    report["ghidra_decompiled"] = decompiled
    report["ghidra"] = {"backend": "ghidra", "version": result.get("version") or PIN["version"],
                        "language": result.get("language"), "compiler": result.get("compiler"),
                        "imagebase": result.get("imagebase"), "functions": len(functions),
                        "internal": result.get("internal"), "external": result.get("external"),
                        "names_applied": result.get("names_applied", 0), "params_applied": result.get("params_applied", 0),
                        **_coverage(result), "matched_native": matched,
                        "requested_scope": result.get("requested_scope", "unknown"),
                        "requested_limit": result.get("requested_limit"),
                        "process_budget_seconds": result.get("process_budget_seconds"),
                        "sample_name": sample.get("name") if sample else "",
                        "sample_signature": signature, "sample": lines,
                        "sample_markers": sample.get("markers") if sample else {},
                        "seconds": result.get("seconds"), "scripts_executed": False,
                        "note": result.get("note")}
    native = report.setdefault("decompiler", {})
    native["ghidra_functions"] = len(functions)
    native["ghidra_decompiled"] = report["ghidra"]["decompiled_count"]
    return report


def _pick_sample(decompiled):
    def rank(item):
        name = item.get("name") or ""
        score = 0
        if name == "add":
            score += 50
        if name == "main":
            score += 40
        if name in {"entry", "_start"}:
            score += 10
        if item.get("decompile_completed"):
            score += 5
        score += min(len(item.get("c") or "") // 40, 20)
        return score
    if not decompiled:
        return None
    return max(decompiled, key=rank)
