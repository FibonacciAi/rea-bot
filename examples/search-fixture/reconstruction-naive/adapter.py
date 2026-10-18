"""Deliberately naive reconstruction (Python str.strip) used to show that rea-bot catches real mismatches."""
import json
import sys

sys.dont_write_bytecode = True
case = json.load(sys.stdin)
needle = case['query'].strip().lower()
json.dump([] if not needle else [i for i in case['items'] if needle in i.lower()], sys.stdout, ensure_ascii=False)
