"""Lostwax (code id rea-bot): evidence-backed understand / rebuild / prove workflow for Grok Bot."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
VERSION = json.loads((ROOT / '.cursor-plugin' / 'plugin.json').read_text())['version']
