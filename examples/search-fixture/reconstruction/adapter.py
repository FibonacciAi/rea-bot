"""rea-bot adapter for the Python reconstruction: JSON case on stdin -> JSON result on stdout."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from search import search  # noqa: E402

case = json.load(sys.stdin)
json.dump(search(case['items'], case['query']), sys.stdout, ensure_ascii=False)
