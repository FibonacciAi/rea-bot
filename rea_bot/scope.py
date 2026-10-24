"""Static scope of one file: symbol names and line ranges. Does not execute the target or return its source."""
import hashlib
import re
from pathlib import Path

from . import report as report_mod
from . import store, workbench
from .htmltext import html_text

SCAN_BYTES = 256 * 1024
HASH_BYTES = 2 * 1024 * 1024
TEXT_PREVIEW = 2000

_JS_EXPORT_FN = re.compile(r'^export\s+(?:async\s+)?function\s+(\w+)', re.M)
_JS_EXPORT_CLASS = re.compile(r'^export\s+class\s+(\w+)', re.M)
_JS_EXPORT_CONST = re.compile(r'^export\s+(?:const|let|var)\s+(\w+)', re.M)
_JS_DEFAULT_FN = re.compile(r'^export\s+default\s+(?:async\s+)?function\s+(\w+)?', re.M)
_JS_CJS_DEFAULT = re.compile(r'^module\.exports\s*=\s*(?:async\s+)?function\b', re.M)
_JS_CJS_NAMED = re.compile(r'^(?:module\.)?exports\.(\w+)\s*=', re.M)
_JS_FN = re.compile(r'^(?:async\s+)?function\s+(\w+)\s*\(', re.M)
_PY = re.compile(r'^(?:async\s+def|def|class)\s+(\w+)', re.M)
_GO = re.compile(r'^func\s+(?:\([^)\n]*\)\s*)?(\w+)\s*\(', re.M)
_RUST = re.compile(r'^pub(?:\([^)\n]*\))?\s+(?:async\s+)?fn\s+(\w+)', re.M)

_LANG = {
    '.py': 'python', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript', '.go': 'go', '.rs': 'rust', '.html': 'html', '.htm': 'html',
}


def local_root(run):
    acquired = (run.meta.get('acquired') or {}).get('path')
    if acquired:
        root = Path(acquired)
    else:
        target = run.meta['target']
        root = Path(target)
        if not root.is_absolute() or not root.exists():
            raise ValueError('Target is not on disk. Run: rea-bot acquire ' + run.id)
        if root.is_file():
            root = root.parent
    if not root.is_dir():
        raise ValueError('No directory to scope.')
    return root.resolve()


def resolve_inside(root, rel):
    if not isinstance(rel, str) or not rel.strip() or rel.startswith('/') or '\\' in rel:
        raise ValueError('Pass a relative path inside the target.')
    root = root.resolve()
    path = Path(rel)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Pass a relative path inside the target.')
    candidate = (root / path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError('Path escapes the target root.')
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError('Scope path must be a regular file inside the target.')
    rel_parts = candidate.relative_to(root).parts
    if any(part in workbench.SKIP or part in workbench.PRIVATE_PARTS or workbench.secret_name(part) or part.startswith('.')
           for part in rel_parts):
        raise ValueError('Hidden, vendor and credential paths are excluded from scope.')
    return candidate


def _line_of(text, index):
    return text.count('\n', 0, index) + 1


def _signature(lines, line):
    if line < 1 or line > len(lines):
        return ''
    return lines[line - 1].strip()[:180]


def _brace_end(lines, start_line):
    """Best-effort end line. Braces inside strings can fool it; the range is a hint."""
    depth = 0
    seen = False
    start = start_line - 1
    limit = min(len(lines), start + 400)
    for i in range(start, limit):
        for ch in lines[i]:
            if ch == '{':
                depth += 1
                seen = True
            elif ch == '}':
                depth -= 1
                if seen and depth <= 0:
                    return i + 1, True
    return start_line, False


def _add(found, names, name, kind, line, lines, ranged=False):
    if not name or name in names or len(found) >= 80:
        return
    names.add(name)
    end, approx = (line, False)
    if ranged:
        end, approx = _brace_end(lines, line)
    found.append({'name': name, 'kind': kind, 'line': line, 'end_line': end,
                  'signature': _signature(lines, line), 'approximate_range': approx})


def _symbols(language, text):
    lines = text.splitlines() or ['']
    found, names = [], set()
    patterns = []
    if language in ('javascript', 'typescript'):
        patterns = [
            (_JS_EXPORT_FN, 'export-function', True),
            (_JS_EXPORT_CLASS, 'export-class', True),
            (_JS_EXPORT_CONST, 'export-binding', False),
            (_JS_CJS_NAMED, 'cjs-export', False),
        ]
        for match in _JS_CJS_DEFAULT.finditer(text):
            _add(found, names, 'default', 'cjs-default', _line_of(text, match.start()), lines, True)
        for match in _JS_DEFAULT_FN.finditer(text):
            _add(found, names, match.group(1) or 'default', 'export-default', _line_of(text, match.start()), lines, True)
    elif language == 'python':
        patterns = [(_PY, 'python', False)]
    elif language == 'go':
        patterns = [(_GO, 'function', True)]
    elif language == 'rust':
        patterns = [(_RUST, 'function', True)]
    for regex, kind, ranged in patterns:
        for match in regex.finditer(text):
            _add(found, names, match.group(1), kind, _line_of(text, match.start()), lines, ranged)
    if language in ('javascript', 'typescript'):
        for match in _JS_FN.finditer(text):
            _add(found, names, match.group(1), 'function', _line_of(text, match.start()), lines, True)
    if language == 'python':
        # End a top-level block at the next top-level symbol.
        ordered = sorted(found, key=lambda row: row['line'])
        for i, row in enumerate(ordered):
            nxt = ordered[i + 1]['line'] - 1 if i + 1 < len(ordered) else len(lines)
            row['end_line'] = max(row['line'], nxt)
            row['approximate_range'] = True
    return found


def scope_run(run, rel, symbol=None):
    root = local_root(run)
    path = resolve_inside(root, rel)
    size = path.stat().st_size
    raw = path.read_bytes()[:SCAN_BYTES + 1]
    truncated = len(raw) > SCAN_BYTES or size > SCAN_BYTES
    raw = raw[:SCAN_BYTES]
    if b'\x00' in raw:
        raise ValueError('Scope only reads text files.')
    text = raw.decode('utf-8', 'replace')
    language = _LANG.get(path.suffix.lower(), 'text')
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if size <= HASH_BYTES else None
    symbols = _symbols(language, text) if language != 'html' else []
    if symbol:
        symbols = [row for row in symbols if row['name'] == symbol]
        if not symbols:
            raise ValueError('No symbol named ' + symbol + ' in the scanned portion of ' + rel)
    rel_path = str(path.relative_to(root))
    out = {
        'run': run.id, 'root': str(root), 'path': rel_path, 'language': language,
        'bytes': size, 'sha256': digest, 'scan_truncated': truncated,
        'symbols': symbols,
        'limitations': [
            'Names and line ranges come from a static scan. They are not a behavior proof.',
            'Ranges are approximate when braces or indentation are ambiguous.',
            'At most 80 symbols and the first 256 KiB are scanned. Source text is not returned.',
        ],
    }
    if language == 'html':
        visible = html_text(text)
        out['visible_text_sha256'] = hashlib.sha256(visible.encode()).hexdigest()
        out['visible_text'] = visible if len(visible) <= TEXT_PREVIEW else None
        out['visible_text_preview'] = visible[:180]
        out['limitations'].append('HTML visible text skips script and style. Page scripts are not executed.')
    store.write_json(run.dir / 'scope.json', out)
    (run.dir / 'SCOPE.md').write_text(report_mod.scope_md(out))
    run.update_meta(status='scoped')
    return {k: out[k] for k in ('run', 'path', 'language', 'bytes', 'sha256', 'scan_truncated', 'symbols', 'limitations')
            if k in out} | ({'visible_text_preview': out['visible_text_preview']} if 'visible_text_preview' in out else {}) | {
                'scope_file': str(run.dir / 'scope.json'), 'scope_md': str(run.dir / 'SCOPE.md')}
