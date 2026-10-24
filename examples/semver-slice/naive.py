"""Echoes a dotted triple and ignores increment flags. Leading zeros are normalized, which the original rejects."""
import re
import sys

found = None
for arg in sys.argv[1:]:
    if re.fullmatch(r'\d+\.\d+\.\d+', arg):
        found = arg
if not found:
    raise SystemExit(1)
sys.stdout.write('.'.join(str(int(part)) for part in found.split('.')) + '\n')
