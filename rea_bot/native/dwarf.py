"""DWARF subprogram and parameter names. Types come from the DIE tree, not from guessing."""
from pathlib import Path


def _name(die):
    attr = die.attributes.get("DW_AT_name")
    if attr is None:
        return ""
    value = attr.value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _ref(die, attr):
    found = die.attributes.get(attr)
    if found is None:
        return None
    return int(found.value)


def _type_name(die_map, offset, depth=0):
    if offset is None or depth > 6:
        return ""
    die = die_map.get(offset)
    if die is None:
        return ""
    tag = die.tag
    name = _name(die)
    if tag in {"DW_TAG_base_type", "DW_TAG_unspecified_type", "DW_TAG_enumeration_type", "DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"}:
        return name or tag.replace("DW_TAG_", "")
    if tag == "DW_TAG_typedef":
        return name or _type_name(die_map, _ref(die, "DW_AT_type"), depth + 1)
    if tag in {"DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"}:
        return _type_name(die_map, _ref(die, "DW_AT_type"), depth + 1)
    if tag == "DW_TAG_pointer_type":
        inner = _type_name(die_map, _ref(die, "DW_AT_type"), depth + 1)
        return (inner + "*") if inner else "pointer"
    if tag == "DW_TAG_array_type":
        inner = _type_name(die_map, _ref(die, "DW_AT_type"), depth + 1)
        return (inner + "[]") if inner else "array"
    if tag == "DW_TAG_subroutine_type":
        return name or "function"
    return name


def _addr(die):
    low = die.attributes.get("DW_AT_low_pc")
    if low is None:
        return None
    value = int(low.value)
    return value or None


def recover(path):
    """Return subprogram records keyed by low_pc, or None when DWARF support is absent."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"available": False}
    path = Path(path)
    try:
        handle = path.open("rb")
    except OSError:
        return None
    with handle:
        try:
            elf = ELFFile(handle)
        except Exception:
            return None
        if not elf.has_dwarf_info():
            return {"available": True, "subprograms": 0, "with_parameters": 0, "by_address": {}}
        try:
            dwarf = elf.get_dwarf_info()
        except Exception:
            return {"available": True, "subprograms": 0, "with_parameters": 0, "by_address": {}}
        by_address = {}
        named_params = 0
        for cu in dwarf.iter_CUs():
            dies = {}
            for die in cu.iter_DIEs():
                dies[die.offset] = die
            for die in dies.values():
                if die.tag != "DW_TAG_subprogram":
                    continue
                addr = _addr(die)
                if not addr:
                    continue
                params = []
                for child in die.iter_children():
                    if child.tag != "DW_TAG_formal_parameter":
                        continue
                    pname = _name(child) or "arg%d" % len(params)
                    ptype = _type_name(dies, _ref(child, "DW_AT_type"))
                    params.append({"name": pname, "type": ptype})
                ret = _type_name(dies, _ref(die, "DW_AT_type"))
                if any(item["name"] and not item["name"].startswith("arg") for item in params):
                    named_params += 1
                by_address[addr] = {"name": _name(die), "params": params, "return": ret}
        return {"available": True, "subprograms": len(by_address), "with_parameters": named_params, "by_address": by_address}
