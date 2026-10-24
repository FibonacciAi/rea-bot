"""Generate a JSON stdin/stdout adapter for one JS or Python export. Does not run it.

Call convention for each case input:
  {"args": [...], "kwargs": {...}}  ->  JS calls fn(...args, kwargsObject) when kwargs is present;
                                         Python calls fn(*args, **kwargs).
  {"param": ...} with --params a,b  ->  fn(input[a], input[b]) on both sides.
  anything else                     ->  fn(input).

JavaScript `undefined` is written as JSON null. A thrown error is a nonzero exit.
"""
import hashlib
import json
from pathlib import Path

from . import workbench
from .scope import local_root, resolve_inside

_JS = '''import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { pathToFileURL } from 'url';

const entry = %(entry)s;
const symbol = %(symbol)s;
const params = %(params)s;
const format = %(fmt)s;
const mod = format === 'esm'
  ? await import(pathToFileURL(entry).href)
  : createRequire(import.meta.url)(entry);

function resolve(mod, symbol) {
  if (symbol === 'default' || symbol === 'module.exports') {
    if (typeof mod === 'function') return mod;
    if (mod && typeof mod.default === 'function') return mod.default;
  }
  return mod ? mod[symbol] : undefined;
}

const fn = resolve(mod, symbol);
if (typeof fn !== 'function') {
  console.error('Export is not a function: ' + symbol);
  process.exit(1);
}
const input = JSON.parse(readFileSync(0, 'utf8') || 'null');
let result;
if (input && typeof input === 'object' && !Array.isArray(input) && Object.prototype.hasOwnProperty.call(input, 'args')) {
  const args = Array.isArray(input.args) ? input.args.slice() : [];
  if (input.kwargs && typeof input.kwargs === 'object') args.push(input.kwargs);
  result = fn(...args);
} else if (params.length && input && typeof input === 'object' && !Array.isArray(input)) {
  result = fn(...params.map((name) => input[name]));
} else {
  result = fn(input);
}
process.stdout.write(typeof result === 'undefined' ? 'null' : JSON.stringify(result));
'''

_PY = '''import importlib.util
import json
import sys

ENTRY = %(entry)s
SYMBOL = %(symbol)s
PARAMS = %(params)s


def main():
    spec = importlib.util.spec_from_file_location('lostwax_target', ENTRY)
    if spec is None or spec.loader is None:
        raise RuntimeError('Could not load the entry.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, SYMBOL)
    data = json.load(sys.stdin)
    if isinstance(data, dict) and 'args' in data:
        result = fn(*(data.get('args') or []), **(data.get('kwargs') or {}))
    elif PARAMS and isinstance(data, dict):
        result = fn(*(data.get(name) for name in PARAMS))
    else:
        result = fn(data)
    json.dump(result, sys.stdout, ensure_ascii=False, allow_nan=False)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
'''


def _language(path):
    suf = path.suffix.lower()
    if suf == '.py':
        return 'py'
    if suf in {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'}:
        return 'js'
    raise ValueError('Harness supports JavaScript and Python entries.')


def _js_format(path, root):
    if path.suffix.lower() == '.mjs':
        return 'esm'
    if path.suffix.lower() == '.cjs':
        return 'cjs'
    cur = path.parent
    while True:
        pkg = cur / 'package.json'
        if pkg.is_file() and not pkg.is_symlink():
            try:
                data = json.loads(pkg.read_text()[:65536])
            except (OSError, ValueError):
                data = {}
            if data.get('type') == 'module':
                return 'esm'
            break
        if cur == root or cur == cur.parent:
            break
        cur = cur.parent
    head = path.read_text(errors='replace')[:20000]
    if re_export(head):
        return 'esm'
    return 'cjs'


def re_export(text):
    import re
    return re.search(r'(?m)^\s*export\s+', text) is not None


def _params(value):
    if value is None or value == '':
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.split(',') if p.strip()]
    elif isinstance(value, list):
        parts = value
    else:
        raise ValueError('params must be a comma-separated string or a list of names.')
    if len(parts) > 16 or any(not isinstance(p, str) or not p.isidentifier() for p in parts):
        raise ValueError('Each param must be an identifier (at most 16).')
    return parts


def resolve_entry(root, entry):
    """Relative entries stay inside the target. Absolute entries are an explicit rebuild outside it."""
    if isinstance(entry, str) and Path(entry).is_absolute():
        path = Path(entry).resolve()
        if path.is_symlink() or not path.is_file():
            raise ValueError('Entry must be a regular file.')
        if any(workbench.secret_name(part) or part in workbench.PRIVATE_PARTS or part.startswith('.') for part in path.parts):
            raise ValueError('Hidden and credential paths cannot be wrapped.')
        return path
    return resolve_inside(root, entry)


def generate(run, entry, symbol, out, params=None, language=None):
    if not isinstance(symbol, str) or not symbol.strip():
        raise ValueError('Pass the export name to wrap. Use default for module.exports.')
    root = local_root(run)
    path = resolve_entry(root, entry)
    lang = language or _language(path)
    if lang not in ('js', 'py'):
        raise ValueError('language must be js or py.')
    names = _params(params)
    destination = Path(out)
    if not destination.is_absolute():
        destination = Path.cwd() / destination
    destination = destination.resolve()
    root_resolved = root.resolve()
    if destination == root_resolved or root_resolved in destination.parents:
        raise ValueError('Write the harness outside the target tree so it does not change the pin.')
    if lang == 'js' and destination.suffix != '.mjs':
        raise ValueError('JavaScript harnesses must use a .mjs path so Node treats them as modules.')
    if lang == 'py' and destination.suffix != '.py':
        raise ValueError('Python harnesses must use a .py path.')
    if destination.exists() and not destination.is_file():
        raise ValueError('Harness output path is not a file.')
    if lang == 'js':
        fmt = _js_format(path, root)
        body = _JS % {'entry': json.dumps(str(path)), 'symbol': json.dumps(symbol),
                      'params': json.dumps(names), 'fmt': json.dumps(fmt)}
    else:
        fmt = 'python'
        body = _PY % {'entry': json.dumps(str(path)), 'symbol': json.dumps(symbol), 'params': json.dumps(names)}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body)
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    try:
        shown = str(path.relative_to(root))
    except ValueError:
        shown = str(path)
    return {'run': run.id, 'out': str(destination), 'sha256': digest, 'language': lang, 'format': fmt,
            'entry': shown, 'symbol': symbol, 'params': names,
            'undefined_json': 'null' if lang == 'js' else None,
            'call': 'args/kwargs, or named params when --params is set',
            'note': 'The harness is not executed here. Run it through rea-bot diff. Review the file before approving an original pin.'}
