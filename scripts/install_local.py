#!/usr/bin/env python3
"""Install rea-bot into this box's skill library as user skills. Dry run by default; --apply to do it.

What --apply does (and nothing else):
  1. copies this plugin folder to DEST (default /workspace/plugins/rea-bot); refuses if DEST exists
  2. writes two user skills into WORKFLOWS (default /home/box/agent-data/workflows):
       rea-bot-rebuild/SKILL.md, rea-bot-parity-recheck/SKILL.md
     with PLUGIN resolved to DEST; refuses if either folder exists
It does not touch settings, MCP registration, other skills, or the network.
Uninstall: delete DEST and the two workflow folders.
/workspace and /home/box are Grok Bot box defaults; override them with --dest and --workflows.
"""
import argparse
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SKILLS = {'rebuild': 'rea-bot-rebuild', 'parity-recheck': 'rea-bot-parity-recheck'}


def plan(dest, workflows):
    return {'copy_plugin': {'from': str(ROOT), 'to': str(dest)},
            'write_skills': [str(workflows / name / 'SKILL.md') for name in SKILLS.values()],
            'untouched': ['settings.json', 'MCP servers', 'other skills', 'network'],
            'uninstall': ['rm -r ' + str(dest)] + ['rm -r ' + str(workflows / n) for n in SKILLS.values()]}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--dest', default='/workspace/plugins/rea-bot')
    p.add_argument('--workflows', default='/home/box/agent-data/workflows')
    p.add_argument('--apply', action='store_true')
    a = p.parse_args()
    dest, workflows = Path(a.dest), Path(a.workflows)
    out = plan(dest, workflows)
    if not a.apply:
        print(json.dumps({**out, 'applied': False}, indent=2))
        return
    targets = [dest] + [workflows / n for n in SKILLS.values()]
    clash = [str(t) for t in targets if t.exists()]
    if clash:
        raise SystemExit('Refusing to overwrite: ' + ', '.join(clash))
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.git'))
    for folder, name in SKILLS.items():
        text = (dest / 'skills' / folder / 'SKILL.md').read_text()
        text = text.replace('`PLUGIN` below is the folder two levels above this file (it contains `bin/rea-bot`).',
                            '`PLUGIN` below is `' + str(dest) + '`.')
        text = text.replace('`PLUGIN` is the folder two levels above this file.', '`PLUGIN` is `' + str(dest) + '`.')
        (workflows / name).mkdir(parents=True)
        (workflows / name / 'SKILL.md').write_text(text)
    print(json.dumps({**out, 'applied': True}, indent=2))


if __name__ == '__main__':
    main()
