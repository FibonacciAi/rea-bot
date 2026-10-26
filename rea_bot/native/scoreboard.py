"""Function-by-function readability totals.

`with_stubs` counts every function that has text, including PLT stubs and named
GOT slots. `without_stubs` drops origins `plt` and `import`, which is the
like-for-like view against a decompiler that is scored on its code functions.
Nothing is executed.
"""
import re

from .decompile import readability

_STUBS = {"plt", "import"}


def function_row(func):
    """One native function: address, name, origin, and readability counts."""
    text = "\n".join(func.get("pseudocode") or [])
    metrics = readability(text)
    address = str(func.get("address") or "")
    return {
        "address": address,
        "name": func.get("name") or "",
        "origin": func.get("origin") or "",
        "lines": metrics["lines"],
        "gotos": metrics["gotos"],
        "unnamed": metrics["unnamed"],
        "addresses": metrics["addresses"],
        "if1": len(re.findall(r"\bif \(1\)", text)),
    }


def summarize(functions):
    """Totals with PLT/GOT stubs and without them. `functions` are detail rows or precomputed rows."""
    rows = []
    for func in functions or []:
        if "gotos" in func and "pseudocode" not in func:
            rows.append(dict(func))
        else:
            if not (func.get("pseudocode") or []):
                continue
            rows.append(function_row(func))
    return {"with_stubs": _totals(rows), "without_stubs": _totals(
        [row for row in rows if row.get("origin") not in _STUBS]), "functions": rows}


def _totals(rows):
    out = {"functions": len(rows), "lines": 0, "gotos": 0, "unnamed": 0, "addresses": 0, "if1": 0,
           "over_20": 0}
    for row in rows:
        out["lines"] += int(row.get("lines") or 0)
        out["gotos"] += int(row.get("gotos") or 0)
        out["unnamed"] += int(row.get("unnamed") or 0)
        out["addresses"] += int(row.get("addresses") or 0)
        out["if1"] += int(row.get("if1") or 0)
        if int(row.get("gotos") or 0) > 20:
            out["over_20"] += 1
    count = out["functions"] or 1
    out["gotos_per_function"] = round(out["gotos"] / count, 3) if out["functions"] else 0
    return out


def ghidra_rows(decompiled, source_of):
    """Readability rows for headless Ghidra.

    `source_of(address, name)` returns 'stub' or 'code'. A one-argument
    callable is still accepted.
    """
    rows = []
    for item in decompiled or []:
        text = item.get("c") or ""
        if not text:
            continue
        metrics = readability(text)
        source = str(item.get("source_address") or item.get("address") or "")
        name = item.get("name") or ""
        try:
            kind = source_of(source, name)
        except TypeError:
            kind = source_of(source)
        rows.append({
            "address": source,
            "ghidra_address": item.get("address") or "",
            "name": item.get("name") or "",
            "origin": "plt" if kind == "stub" else "code",
            "lines": metrics["lines"],
            "gotos": metrics["gotos"],
            "unnamed": metrics["unnamed"],
            "addresses": metrics["addresses"],
            "if1": len(re.findall(r"\bif \(1\)", text)),
        })
    return rows


def worse_than(native_rows, ghidra_rows_list):
    """Native functions with more gotos than the Ghidra function at the same address.

    The comparison is per function. A native function Ghidra did not decompile is
    not a loss. Ties are not listed.
    """
    other = {}
    for row in ghidra_rows_list or []:
        key = _addr_key(row.get("address"))
        if key is None:
            continue
        other[key] = row
    losses = []
    for row in native_rows or []:
        key = _addr_key(row.get("address"))
        match = other.get(key)
        if not match:
            continue
        delta = int(row.get("gotos") or 0) - int(match.get("gotos") or 0)
        if delta > 0:
            losses.append({
                "address": row.get("address"),
                "name": row.get("name") or "",
                "native_gotos": int(row.get("gotos") or 0),
                "ghidra_gotos": int(match.get("gotos") or 0),
                "ghidra_name": match.get("name") or "",
                "delta": delta,
            })
    losses.sort(key=lambda item: (-item["delta"], -item["native_gotos"]))
    return losses


def _addr_key(value):
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None
