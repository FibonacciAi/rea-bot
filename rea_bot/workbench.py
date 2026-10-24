"""Static, dependency-free workbench: routing, bounded inventory, specification and parity accounting.

Ported from REA Native 0.1.7 (MIT) with bot-oriented fixes:
- symlinked *ancestors* (e.g. a symlinked agent-data folder, macOS /tmp) no longer block a real target;
  the selected path itself must not be a symlink, and exclusions apply to the resolved path too;
- inventory reports total files seen, an extension histogram and declared entrypoints;
- parity results carry an attestation level (runner-attested vs caller-supplied).
Nothing here executes a target, installs dependencies, or uses the network.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit, unquote

MAX_FILES = 256
MAX_BYTES = 65536
MAX_REQUEST = 2 * 1024 * 1024
STATES = ['observed-static', 'observed-runtime', 'source-derived', 'inferred', 'unknown']
SKIP = {'.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '__pycache__',
        '.aws', '.ssh', '.codex', '.agents', 'vendor', 'dist', 'build'}
PRIVATE_PARTS = {'.ssh', '.aws', '.codex', '.agents', '.gnupg', '.docker', '.kube'}
TEXT = {'.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.rs', '.go', '.c',
        '.h', '.cpp', '.swift', '.java', '.cs', '.json', '.md', '.html', '.css',
        '.toml', '.yaml', '.yml'}
ARCHIVES = {'.zip', '.apk', '.ipa', '.msix', '.appx', '.dmg', '.tgz', '.gz', '.tar'}
GITHUB_PAGES = {'topics', 'collections', 'marketplace', 'explore', 'settings',
                'login', 'features', 'sponsors', 'orgs', 'users', 'search'}
BINARY_MAGIC = (b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe',
                b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf',
                b'\xbf\xba\xfe\xca')
ENGINE_ROUTES = {'javascript-application', 'electron-asar'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_digest(obj):
    return digest(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())


def npm_identity(package, version=None):
    return {'package': package, 'version_hint': version,
            'version_pinned': bool(version and re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', version)),
            'integrity_verified': False}


def secret_name(name):
    n = name.lower()
    return n.startswith('.env') or n in {'.npmrc', '.pypirc', '.netrc', 'credentials', 'credentials.json',
            'auth.json', 'config.json', 'id_rsa', 'id_ed25519', 'secrets.json', 'box-secrets.json',
            'host-secrets.json'} or n.endswith(('.pem', '.key', '.p12', '.pfx', '.keystore'))


def _private(parts):
    return any(secret_name(x) or x in PRIVATE_PARTS for x in parts)


def local_path(value):
    p = Path(value).expanduser()
    if not p.is_absolute():
        raise ValueError('Use an absolute local path, or an HTTPS URL / npm: identifier.')
    if p.is_symlink():
        raise ValueError('The selected path is a symlink; supply the real authorized path.')
    if not p.exists():
        raise ValueError('The selected local target does not exist.')
    real = p.resolve(strict=True)
    if not (real.is_dir() or stat.S_ISREG(real.stat().st_mode)):
        raise ValueError('Only regular files and directories are supported; no devices, sockets or FIFOs.')
    if _private(p.parts) or _private(real.parts):
        raise ValueError('Credential and agent-private paths are excluded.')
    return p


def route_target(target):
    if not isinstance(target, str) or not target.strip() or len(target) > 4096 or '\x00' in target:
        raise ValueError('Supply one nonempty target, at most 4096 characters.')
    target = target.strip()
    out = {'target': target, 'execution': 'none',
           'cost': 'Bounded static inspection first; no paid tools or target execution.',
           'limitations': [], 'next': 'Continue with the rea-bot rebuild skill in this session.'}
    if target.startswith('npm:'):
        match = re.fullmatch(r'npm:((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)(?:@([a-zA-Z0-9.+_-]+))?', target)
        if not match:
            raise ValueError('Use npm:package@version or npm:@scope/package@version.')
        out.update(kind='npm-package', first_tools=['rea-bot acquire (registry tarball, sha512 check, no lifecycle scripts)', 'inspect', 'scope', 'engine:analyze_javascript_application'],
                   package_identity=npm_identity(*match.groups()),
                   acquisition='rea-bot acquire resolves an exact version, checks registry integrity, and extracts the tarball without lifecycle scripts or dependency installs.')
    elif '://' in target:
        u = urlsplit(target)
        if u.scheme != 'https' or not u.hostname or u.username or u.password:
            raise ValueError('Only credential-free HTTPS URLs are accepted.')
        if u.query or u.fragment:
            raise ValueError('Remove query strings/fragments; they can contain private tokens. Describe the feature separately.')
        parts = [unquote(x) for x in u.path.strip('/').split('/') if x]
        github_repository = u.hostname == 'github.com' and len(parts) >= 2 and parts[0].lower() not in GITHUB_PAGES
        if github_repository or u.path.endswith('.git') or (u.hostname in {'gitlab.com', 'bitbucket.org'} and len(parts) >= 2):
            out.update(kind='git-repository', first_tools=['rea-bot acquire (one commit, hooks and submodules off)', 'inspect', 'scope'],
                       acquisition='rea-bot acquire fetches one resolved commit with hooks disabled, no submodules, no LFS smudge, and no target execution.')
            if github_repository:
                owner, repository = parts[:2]
                repository = repository.removesuffix('.git')
                if (not re.fullmatch(r'[A-Za-z0-9_.-]+', owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+', repository)
                        or owner in {'.', '..'} or repository in {'.', '..'}):
                    raise ValueError('Use an unambiguous GitHub owner/repository URL.')
                out['repository_url'] = 'https://github.com/' + owner + '/' + repository
                out['revision_pinned'] = False
                if len(parts) > 3 and parts[2] in {'tree', 'blob', 'commit'}:
                    out['revision_hint'] = parts[3]
                    out['path_hint'] = '/'.join(parts[4:]) or None
                    out['revision_pinned'] = bool(re.fullmatch(r'[0-9a-fA-F]{40}', parts[3]))
                    if not out['revision_pinned']:
                        out['limitations'].append('Resolve branch/tag names with git ls-remote before acquisition; slash-containing refs can overlap the path. Do not silently use the default branch instead.')
        elif ((u.hostname in {'npmjs.com', 'www.npmjs.com'} and len(parts) > 1 and parts[0] == 'package')
                or (u.hostname == 'registry.npmjs.org' and parts)):
            out.update(kind='npm-package', first_tools=['rea-bot acquire (registry tarball, sha512 check, no lifecycle scripts)', 'inspect', 'scope', 'engine:analyze_javascript_application'],
                       acquisition='rea-bot acquire resolves an exact version, checks registry integrity, and extracts the tarball without lifecycle scripts or dependency installs.')
            if parts and parts[0] == 'package':
                tail = parts[1:]
                length = 2 if tail and tail[0].startswith('@') else 1
                package = '/'.join(tail[:length])
                version = tail[length + 1] if len(tail) > length + 1 and tail[length] == 'v' else None
                if re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+', package):
                    out['package_identity'] = npm_identity(package, version)
        else:
            out.update(kind='website', first_tools=['rea-bot acquire (static HTML and same-origin assets)', 'inspect', 'scope'],
                       acquisition='rea-bot acquire saves the HTML document and a few same-origin static assets. It does not run page scripts.')
            out['limitations'].append('A URL alone does not authorize logins, credential use, form submission, or running target scripts.')
            out['limitations'].append('rea-bot acquire does not execute page scripts, so client-rendered text is not in the saved copy.')
    else:
        p = local_path(target)
        real = p.resolve()
        if real.is_dir():
            if real.suffix.lower() == '.app':
                kind, tools = 'apple-app', ['inspect', 'engine:open_binary', 'engine:inspect_artifact']
            elif (real / '.git').exists():
                kind, tools = 'source-repository', ['inspect', 'source reading with Read/rg']
            elif (real / 'package.json').is_file():
                kind, tools = 'javascript-application', ['inspect', 'scope', 'engine:analyze_javascript_application']
            elif (real / 'pyproject.toml').is_file() or (real / 'setup.py').is_file() or (real / 'setup.cfg').is_file():
                kind, tools = 'python-package', ['inspect', 'scope', 'source reading with Read/rg']
            elif (real / 'go.mod').is_file():
                kind, tools = 'go-module', ['inspect', 'scope', 'source reading with Read/rg']
            elif (real / 'Cargo.toml').is_file():
                kind, tools = 'rust-crate', ['inspect', 'scope', 'source reading with Read/rg']
            else:
                kind, tools = 'source-directory', ['inspect', 'scope', 'source reading with Read/rg']
        elif real.suffix.lower() == '.asar':
            kind, tools = 'electron-asar', ['engine:analyze_javascript_application']
        elif real.suffix.lower() in ARCHIVES:
            kind, tools = 'package-archive', ['inspect', 'engine:open_binary', 'engine:inspect_artifact']
        else:
            with real.open('rb') as f:
                head = f.read(16)
            kind, tools = 'file', ['inspect']
            java_class = (head.startswith(b'\xca\xfe\xba\xbe') and len(head) >= 10
                          and int.from_bytes(head[4:6], 'big') in {0, 1, 2, 3, 65535}
                          and 45 <= int.from_bytes(head[6:8], 'big') <= 100
                          and int.from_bytes(head[8:10], 'big') > 0)
            if java_class:
                kind, tools = 'jvm-class', ['inspect', 'source/artifact tools']
                out['limitations'].append('Java class header observed; no Mach-O provider is selected. A JVM provider is a separate prerequisite.')
            elif head.startswith(BINARY_MAGIC):
                kind, tools = 'native-or-managed-binary', ['inspect', 'engine:open_binary']
            elif head.startswith(b'\x00asm'):
                kind, tools = 'wasm', ['inspect', 'engine:inspect_wasm_artifact']
            elif real.suffix.lower() in TEXT:
                kind, tools = 'source-file', ['inspect', 'source reading with Read/rg']
        out.update(kind=kind, first_tools=tools, acquisition='Read the explicitly selected local target only.')
        if real != p:
            out['resolved_path'] = str(real)
    out['engine_evidence_required'] = out['kind'] in ENGINE_ROUTES
    out['policy'] = {'execute_target': False, 'install_target_dependencies': False, 'publish': False,
                     'new_credentials': False, 'engine_provider_install': False}
    return out


def _entrypoints(data):
    found = {}
    for key in ('main', 'module', 'browser', 'types'):
        if isinstance(data.get(key), str):
            found[key] = data[key]
    if isinstance(data.get('bin'), str):
        found['bin'] = data['bin']
    elif isinstance(data.get('bin'), dict):
        found['bin'] = sorted(k for k in data['bin'] if isinstance(k, str))[:32]
    exp = data.get('exports')
    if isinstance(exp, str):
        found['exports'] = exp
    elif isinstance(exp, dict):
        found['exports'] = sorted(k for k in exp if isinstance(k, str))[:32]
    return found


def inspect_local(target):
    p = local_path(target)
    real = p.resolve()
    records, skipped, candidates = [], [], []
    ext_counts, total_seen, truncated = {}, 0, False
    if real.is_dir():
        for root, dirs, files in os.walk(real, followlinks=False):
            kept = []
            for d in sorted(dirs):
                if d in SKIP or d.startswith('.') or Path(root, d).is_symlink():
                    skipped.append(str(Path(root, d).relative_to(real)) + '/')
                else:
                    kept.append(d)
            dirs[:] = kept
            for name in sorted(files):
                q = Path(root, name)
                if q.is_symlink() or secret_name(name) or name.startswith('.'):
                    skipped.append(str(q.relative_to(real)))
                    continue
                total_seen += 1
                ext = q.suffix.lower() or '(none)'
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
                if len(candidates) < MAX_FILES:
                    candidates.append(q)
                else:
                    truncated = True
    else:
        candidates, total_seen = [real], 1
        ext_counts[real.suffix.lower() or '(none)'] = 1
    entrypoints = {}
    for q in candidates:
        if not q.is_file():
            continue
        size = q.stat().st_size
        with q.open('rb') as f:
            raw = f.read(MAX_BYTES + 1)
        complete = len(raw) <= MAX_BYTES
        raw = raw[:MAX_BYTES]
        rel = str(q.relative_to(real)) if real.is_dir() else real.name
        row = {'path': rel, 'size': size, 'sample_sha256': digest(raw), 'complete_file': complete,
               'evidence_id': 'static:' + digest(raw + rel.encode())[:24],
               'state': 'observed-static', 'execution': 'none'}
        if q.suffix.lower() in TEXT and b'\x00' not in raw:
            text = raw.decode('utf-8', errors='replace')
            row['line_count_in_sample'] = len(text.splitlines())
            if q.name == 'package.json':
                try:
                    data = json.loads(text)
                    row['package'] = {k: data[k] for k in ['name', 'version', 'license', 'type'] if isinstance(data.get(k), str)}
                    row['script_names'] = list(data.get('scripts', {})) if isinstance(data.get('scripts'), dict) else []
                    eps = _entrypoints(data)
                    if eps:
                        row['entrypoints'] = eps
                        entrypoints[rel] = eps
                except (ValueError, TypeError, AttributeError):
                    row['parse_error'] = 'Invalid or incomplete JSON; no metadata inferred.'
        records.append(row)
    return {'target': str(p), 'kind': route_target(str(p))['kind'], 'execution': 'none',
            'records': records, 'excluded': skipped[:MAX_FILES], 'excluded_count': len(skipped),
            'extension_histogram': dict(sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            'declared_entrypoints': entrypoints,
            'coverage': {'files_seen': total_seen, 'files_recorded': len(records), 'file_limit': MAX_FILES,
                         'bytes_per_file': MAX_BYTES, 'truncated': truncated, 'complete_repository': False},
            'limitations': ['Static inventory does not establish runtime behavior, global completeness, or feature parity.',
                            'Hidden paths, dependency/build/vendor directories and sensitive names are excluded. No source content is returned.',
                            'sample_sha256 is a full-file digest only when complete_file is true.']}


def prepare_build(target, evidence, features, improvements=None):
    """Validate a finite evidence-linked specification (unchanged contract from REA Native 0.1.7)."""
    if not isinstance(evidence, list) or not evidence or len(evidence) > 256:
        raise ValueError('Provide 1-256 evidence records from actual inspection.')
    refs = {}
    for e in evidence:
        if not isinstance(e, dict) or not isinstance(e.get('id'), str) or not e['id'] or e['id'] in refs:
            raise ValueError('Evidence requires unique nonempty id values.')
        if e.get('state') not in STATES:
            raise ValueError('Evidence state must distinguish observation, derivation, inference and unknown.')
        if not isinstance(e.get('locator'), str) or not e['locator'] or not isinstance(e.get('summary'), str):
            raise ValueError('Evidence needs a real locator and summary.')
        refs[e['id']] = e
    if not isinstance(features, list) or not features or len(features) > 100:
        raise ValueError('Provide 1-100 scoped features.')
    ids = set()
    for f in features:
        if not isinstance(f, dict) or not isinstance(f.get('id'), str) or not f['id'] or f['id'] in ids:
            raise ValueError('Features require unique nonempty ids.')
        ids.add(f['id'])
        for k in ['name', 'interface', 'behavior', 'test']:
            if not isinstance(f.get(k), str) or not f[k].strip():
                raise ValueError('Each feature needs name, interface, behavior and a reproducible test.')
        if f.get('state') not in STATES:
            raise ValueError('Each feature needs its claim state.')
        linked = f.get('evidence_ids')
        if not isinstance(linked, list) or not linked or any(not isinstance(x, str) or x not in refs for x in linked):
            raise ValueError('Every feature must link existing evidence IDs.')
        if f['state'].startswith('observed') and any(refs[x]['state'] not in ['observed-static', 'observed-runtime'] for x in linked):
            raise ValueError('An observed feature cannot be supported only by inference or unknown evidence.')
        if f['state'] == 'observed-runtime' and not any(refs[x]['state'] == 'observed-runtime' for x in linked):
            raise ValueError('Runtime claims require actual runtime evidence.')
    if improvements is None:
        improvements = []
    if not isinstance(improvements, list) or len(improvements) > 50:
        raise ValueError('Improvements must be a list of at most 50 ranked proposals.')
    for x in improvements:
        if not isinstance(x, dict) or not all(isinstance(x.get(k), str) and x[k] for k in ['proposal', 'benefit', 'cost', 'risk', 'validation']):
            raise ValueError('Each improvement needs proposal, benefit, cost, risk and validation.')
        if type(x.get('rank')) is not int or x['rank'] < 1:
            raise ValueError('Each improvement needs a positive integer rank.')
    spec = {'schema_version': 1, 'target': route_target(target), 'evidence': evidence,
            'capability_matrix': features, 'ranked_improvements': sorted(improvements, key=lambda x: x['rank']),
            'parity': {'state': 'unmeasured', 'scope': 'Only the declared finite feature set; unknowns remain unknown.'}}
    spec['spec_sha256'] = canonical_digest(spec)
    return spec


def verify_spec(spec):
    if not isinstance(spec, dict):
        raise ValueError('Supply the exact specification object.')
    canonical = {k: v for k, v in spec.items() if k != 'spec_sha256'}
    if spec.get('spec_sha256') != canonical_digest(canonical):
        raise ValueError('The specification was changed or its digest is missing. Reuse the saved specification by its spec_sha256; do not rebuild it by hand.')
    return spec['spec_sha256']


def assess_parity(specification, results):
    verify_spec(specification)
    fs = specification.get('capability_matrix', [])
    if not fs or not isinstance(results, list):
        raise ValueError('Supply the actual specification and finite test results.')
    expected = {f['id'] for f in fs}
    rows = {}
    for r in results:
        if not isinstance(r, dict) or r.get('feature_id') not in expected or r['feature_id'] in rows:
            raise ValueError('Results must reference unique declared feature IDs.')
        if r.get('status') not in ['passed', 'failed', 'blocked', 'not-run']:
            raise ValueError('Result status must be passed, failed, blocked or not-run.')
        if r['status'] in ['passed', 'failed'] and (not isinstance(r.get('test_evidence'), str) or not r['test_evidence']):
            raise ValueError('Executed test results require a real test-log locator.')
        if r['status'] == 'passed' and not r.get('original_evidence'):
            raise ValueError('Parity passes require original behavior evidence as well as reconstruction results.')
        if r['status'] == 'passed' and r.get('original_evidence_state') != 'observed-runtime':
            raise ValueError('Parity passes require observed-runtime original evidence. Source-derived checks alone are not runtime parity; report blocked or not-run.')
        if r.get('attestation') not in (None, 'caller-supplied', 'runner-attested'):
            raise ValueError('attestation must be caller-supplied or runner-attested.')
        rows[r['feature_id']] = {**r, 'attestation': r.get('attestation') or 'caller-supplied'}
    counts = {k: sum(r['status'] == k for r in rows.values()) for k in ['passed', 'failed', 'blocked', 'not-run']}
    counts['not-run'] += len(expected - rows.keys())
    attested = sum(r['status'] == 'passed' and r['attestation'] == 'runner-attested' for r in rows.values())
    return {'spec_sha256': specification['spec_sha256'], 'counts': counts, 'declared_features': len(expected),
            'measured_pass_fraction': counts['passed'] / len(expected),
            'runner_attested_passes': attested,
            'caller_supplied_passes': counts['passed'] - attested,
            'rows': [rows[k] for k in sorted(rows)],
            'scope': 'Finite declared features only. runner-attested rows were executed by rea-bot diff and their logs are digest-pinned; caller-supplied rows are accounted, not verified.',
            'global_parity': 'unknown', 'missing_feature_ids': sorted(expected - rows.keys())}
