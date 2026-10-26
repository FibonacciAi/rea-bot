"""Same slice as rebuild.py, but a year is 365 days. Year inputs disagree with ms 2.1.3."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rebuild as fixed

fixed._Y = fixed._D * 365


def convert(val, long=False):
    return fixed.convert(val, long=long)
