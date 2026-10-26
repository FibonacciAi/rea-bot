"""Opt-in Ghidra 12.1.4 backend. Lostwax drives analyzeHeadless itself.

The pinned release is downloaded only by `ghidra setup --apply` after the
approve token. An existing tree is accepted only when its application.properties
matches the pin. The target is imported for static analysis and is not executed.
REA is not on this path.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

PIN = json.loads((Path(__file__).resolve().parent / "ghidra_pin.json").read_text())
APPROVE = PIN["approve"]
SCRIPT_DIR = Path(__file__).resolve().parent / "ghidra"
_NAME = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]{0,180}")
_SYNTHETIC = re.compile(r"sub_[0-9a-fA-F]+")
MAX_BINARIES = 2


def ghidra_home():
    return Path(os.environ.get("REA_BOT_GHIDRA_HOME") or "/workspace/.rea-bot-ghidra")


def _java_home():
    env = os.environ.get("JAVA_HOME")
    if env and (Path(env) / "bin" / "java").is_file():
        return env
    java = shutil.which("java")
    if not java:
        return None
    home = Path(os.path.realpath(java)).resolve().parent.parent
    if (home / "bin" / "java").is_file():
        return str(home)
    return None


def _java_version():
    java = shutil.which("java")
    if not java:
        return None
    try:
        proc = subprocess.run([java, "-version"], text=True, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stderr or "") + (proc.stdout or "")
    match = re.search(r'version "(\d+)', text)
    if not match:
        return None
    return {"major": int(match.group(1)), "line": text.splitlines()[0] if text.splitlines() else ""}


def _verified(root):
    root = Path(root)
    headless = root / "support" / "analyzeHeadless"
    props_path = root / PIN["properties_rel"]
    if not headless.is_file() or not props_path.is_file():
        return None
    raw = props_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PIN["properties_sha256"]:
        return None
    if PIN["version_line"] not in raw.decode("utf-8", "replace"):
        return None
    return root


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


def problems():
    found = []
    java = _java_version()
    if java is None:
        found.append("Java %s was not found on PATH. The pinned Ghidra build needs it." % PIN["java_major"])
    elif java["major"] != PIN["java_major"]:
        found.append("Java %s was found (%s). The pinned Ghidra build needs Java %s." % (
            java["major"], java["line"], PIN["java_major"]))
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env and resolve_install() is None:
        found.append("GHIDRA_INSTALL_DIR is not the pinned Ghidra %s release. application.properties must match the pin." % PIN["version"])
    elif resolve_install() is None:
        found.append("Ghidra %s is not installed. Run `rea-bot ghidra setup`, then "
                     "`rea-bot ghidra setup --apply --approve-source %s`, or set GHIDRA_INSTALL_DIR to an extracted tree of that release."
                     % (PIN["version"], APPROVE))
    return found


def plan():
    return {"engine": "lostwax-ghidra@" + PIN["version"], "home": str(ghidra_home()),
            "version": PIN["version"], "sha256": PIN["sha256"], "url": PIN["url"], "approve": APPROVE,
            "java_major": PIN["java_major"],
            "effects": "Downloads the pinned Ghidra zip, checks SHA-256, and extracts it under the ghidra home. "
                       "Does not install Java. Does not execute a target. Not part of the default install."}


def status():
    info = plan()
    java = _java_version()
    install = resolve_install()
    info["java"] = None if java is None else java
    info["install"] = None if install is None else str(install)
    info["problems"] = problems()
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
    root = dest.resolve()
    with zipfile.ZipFile(archive) as package:
        for info in package.infolist():
            name = info.filename
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("Ghidra zip contains an unsafe path.")
            target = (dest / name).resolve()
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
    if not archive.is_file() or hashlib.sha256(archive.read_bytes()).hexdigest() != PIN["sha256"]:
        _download(PIN["url"], archive, PIN["sha256"])
    _extract(archive, home)
    install = resolve_install()
    if install is None:
        raise ValueError("The pinned zip extracted, but application.properties did not match Ghidra %s." % PIN["version"])
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


def _config(path, source_base, names, signatures, hints, limit, decomp_timeout, externs=None):
    lines = ["out\t" + str(path), "source_base\t%x" % source_base, "limit\t%d" % limit,
             "decomp_timeout\t%d" % decomp_timeout]
    for addr, name in list(names.items())[:16000]:
        token = _token(name)
        if token:
            lines.append("name\t%x\t%s" % (addr, token))
    for addr, signature in signatures.items():
        for index, arg in enumerate(signature.get("args") or []):
            pname, ptype = _typed_arg(arg)
            if pname:
                lines.append("param\t%x\t%d\t%s\t%s" % (addr, index, ptype, pname))
        returns = str(signature.get("returns") or "")
        if returns and returns != "unknown":
            lines.append("ret\t%x\t%s" % (addr, returns))
    for proto in list(externs or [])[:500]:
        fields = ["extern", proto["name"], proto["return"]]
        for typ, pname in proto["params"]:
            fields.append("%s|%s" % (typ, pname))
        if proto.get("varargs"):
            fields.append("...|")
        lines.append("\t".join(fields))
    # limit <= 0 decompiles every internal function, so a hint list is not a cap.
    hinted = hints if int(limit) <= 0 else hints[:limit]
    for addr in hinted:
        lines.append("hint\t%x" % addr)
    return "\n".join(lines) + "\n"


def _log_tail(path):
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return ""
    return text[-1500:]


def decompile(path, source_base=0, names=None, signatures=None, hints=None, analysis_timeout=480,
              decomp_timeout=60, limit=16, externs=None):
    """Import one file in headless Ghidra and return functions plus C. Does not execute the file.

    limit <= 0 decompiles every non-external function. A positive limit is how many
    functions to decompile, not a sample cap of 32.
    """
    blocked = problems()
    if blocked:
        raise ValueError(" ".join(blocked))
    root = resolve_install()
    headless = root / "support" / "analyzeHeadless"
    names = names or {}
    signatures = signatures or {}
    hints = hints or []
    limit = int(limit)
    if limit < 0:
        limit = 0
    else:
        limit = min(limit, 100000)
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="lostwax-ghidra-") as tmp:
        tmp = Path(tmp)
        project = tmp / "project"
        project.mkdir()
        config = tmp / "config.txt"
        output = tmp / "out.json"
        log = tmp / "analyze.log"
        config.write_text(_config(output, int(source_base), names, signatures, hints, limit,
                                  int(decomp_timeout), externs))
        cmd = [str(headless), str(project), "Lostwax", "-import", str(path), "-scriptPath", str(SCRIPT_DIR),
               "-postScript", "LostwaxDecompile.java", str(config), "-deleteProject",
               "-analysisTimeoutPerFile", str(int(analysis_timeout)), "-log", str(log)]
        if not os.access(headless, os.X_OK):
            cmd.insert(0, "bash")
        env = os.environ.copy()
        home = _java_home()
        if home:
            env["JAVA_HOME"] = home
        per_function = 7200 if limit == 0 else int(decomp_timeout) * max(limit, 1)
        budget = int(analysis_timeout) + per_function + 180
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=budget, env=env, cwd=str(tmp))
        except subprocess.TimeoutExpired as err:
            raise ValueError("Ghidra analysis timed out after %s seconds. The target was not executed." % budget) from err
        if not output.is_file():
            detail = (proc.stderr or proc.stdout or _log_tail(log))[-1500:]
            raise ValueError("Ghidra did not write a decompiler report (exit %s). The target was not executed. %s" % (
                proc.returncode, detail))
        try:
            payload = json.loads(output.read_text())
        except ValueError as err:
            raise ValueError("Ghidra wrote a report that is not JSON. The target was not executed.") from err
    payload["version"] = PIN["version"]
    payload["install"] = str(root)
    payload["seconds"] = round(time.perf_counter() - started, 2)
    payload["scripts_executed"] = False
    payload["note"] = "analyzeHeadless imported the file for static analysis. The target was not executed."
    return payload


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
                           "c": code, "calls": calls, "markers": _markers(code)})
    sample = _pick_sample(decompiled)
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
                        "decompiled_count": len(decompiled), "matched_native": matched,
                        "sample_name": sample.get("name") if sample else "",
                        "sample_signature": signature, "sample": lines,
                        "sample_markers": sample.get("markers") if sample else {},
                        "seconds": result.get("seconds"), "scripts_executed": False,
                        "note": result.get("note")}
    native = report.setdefault("decompiler", {})
    native["ghidra_functions"] = len(functions)
    native["ghidra_decompiled"] = len(decompiled)
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
