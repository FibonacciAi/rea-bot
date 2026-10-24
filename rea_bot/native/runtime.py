"""Pinned opt-in install for the native engine. Wheels only, hashes checked, no install scripts."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request

from .. import ROOT

PINS = json.loads((Path(__file__).resolve().parent / "pins.json").read_text())
APPROVE = PINS["approve"]


def native_home():
    return Path(os.environ.get("REA_BOT_NATIVE_HOME") or "/workspace/.rea-bot-native")


def _python_ok():
    return sys.version_info[:2] >= tuple(PINS["python_min"])


def _machine():
    m = platform.machine().lower()
    if m in {"amd64", "x86_64"}:
        return "x86_64"
    if m in {"arm64", "aarch64"}:
        return "aarch64"
    return m


def _select(package):
    machine = _machine()
    chosen = None
    for wheel in package["wheels"]:
        if wheel["machine"] in {machine, "any"}:
            if wheel["machine"] == "any" and chosen and chosen["machine"] == machine:
                continue
            chosen = wheel
            if wheel["machine"] == machine:
                break
    if not chosen:
        raise ValueError("No pinned wheel for %s on %s." % (package["name"], machine))
    return chosen


def plan():
    home = native_home()
    wheels = []
    for package in PINS["packages"]:
        wheel = _select(package)
        wheels.append({"name": package["name"], "version": package["version"], "sha256": wheel["sha256"], "url": wheel["url"]})
    return {"engine": "lostwax-native@" + PINS["version"], "home": str(home), "python": list(sys.version_info[:3]),
            "python_ok": _python_ok(), "machine": _machine(), "wheels": wheels,
            "effects": "Downloads pinned wheels into the native home and installs them with pip --no-deps. No setup scripts. Nothing is installed system-wide.",
            "approve": APPROVE}


def _download(url, digest):
    raw = urllib.request.urlopen(url, timeout=180).read()
    got = hashlib.sha256(raw).hexdigest()
    if got != digest:
        raise ValueError("Wheel failed SHA-256 verification.")
    return raw


def setup(apply=False, approve=None):
    info = plan()
    if not info["python_ok"]:
        info["blocked"] = "The native binary backend needs Python >= %s." % ".".join(str(x) for x in PINS["python_min"])
        return info
    if not apply:
        info["applied"] = False
        info["next"] = "Re-run with --apply --approve-source " + APPROVE + " after approval."
        return info
    if approve != APPROVE:
        raise ValueError("--apply needs --approve-source " + APPROVE + ".")
    home = native_home()
    cache = home / "wheels"
    cache.mkdir(parents=True, exist_ok=True)
    paths = []
    for package in PINS["packages"]:
        wheel = _select(package)
        name = wheel["url"].rstrip("/").split("/")[-1]
        path = cache / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != wheel["sha256"]:
            path.write_bytes(_download(wheel["url"], wheel["sha256"]))
        paths.append(str(path))
    pip = [sys.executable, "-m", "pip", "install", "--target", str(home), "--no-deps", "--upgrade", "--no-index", *paths]
    # --no-index refuses URLs; the files are local wheels.
    proc = subprocess.run(pip, text=True, capture_output=True, timeout=180)
    if proc.returncode != 0:
        raise ValueError("Native wheel install failed: " + (proc.stderr or proc.stdout)[-800:])
    receipt = {"version": PINS["version"], "approve": APPROVE, "packages": [
        {"name": p["name"], "version": p["version"], "sha256": _select(p)["sha256"]} for p in PINS["packages"]],
               "python": list(sys.version_info[:3]), "machine": _machine()}
    (home / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    info["applied"] = True
    info["imports"] = imports()
    return info


def activate():
    home = native_home()
    if home.is_dir() and str(home) not in sys.path:
        sys.path.insert(0, str(home))
    return home


def imports():
    activate()
    found = {}
    for name in ("capstone", "lief", "wasmtime", "dnfile", "pefile"):
        try:
            __import__(name)
            found[name] = True
        except Exception:
            found[name] = False
    receipt = native_home() / "receipt.json"
    found["ready"] = all(found[name] for name in ("capstone", "lief", "wasmtime", "dnfile"))
    found["receipt"] = receipt.is_file()
    return found


def status():
    info = plan()
    info["imports"] = imports()
    info["ready"] = bool(info["imports"]["ready"] and info["imports"]["receipt"])
    info["next"] = None if info["ready"] else "rea-bot native setup, then --apply --approve-source " + APPROVE
    return info
