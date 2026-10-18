"""Search reconstruction; compatibility measured only on the 14 owned cases.

Independently implemented from the MIT fixture's observable contract.
Python's Unicode lowercase tables may differ from Node's on untested inputs.
"""

# Explicit ECMAScript WhiteSpace and LineTerminator characters. In particular,
# include BOM; exclude NEL, U+001C and zero-width space. Plain strip() differs.
_TRIM = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def search(items: list[str], query: str) -> list[str]:
    """Return matching original items in order, retaining duplicates and case."""
    needle = query.strip(_TRIM).lower()
    if not needle:
        return []
    return [item for item in items if needle in item.lower()]
