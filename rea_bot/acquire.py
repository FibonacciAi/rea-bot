"""Fetch one remote target into the run folder. Nothing acquired is executed.

npm: download the registry tarball, check the published SHA-512 integrity, extract without
lifecycle scripts. Git: resolve one commit, fetch it with hooks, submodules and LFS smudge
disabled. Website: save the HTML document and a few same-origin static assets. Page scripts
are not run. Private, loopback and link-local addresses are refused.
"""
import hashlib
import io
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from .htmltext import html_text
from . import store

TARBALL_LIMIT = 32 * 1024 * 1024
META_LIMIT = 4 * 1024 * 1024
PAGE_LIMIT = 1 * 1024 * 1024
ASSET_LIMIT = 1 * 1024 * 1024
SITE_LIMIT = 8 * 1024 * 1024
ASSET_CAP = 16
GIT_FILE_CAP = 4000
GIT_BYTE_CAP = 30 * 1024 * 1024
NPM_FILE_CAP = 2000
ASSET_SUFFIXES = {'.css', '.js', '.mjs', '.html', '.svg'}
ASSET_TYPES = {'text/css', 'text/javascript', 'application/javascript', 'application/x-javascript',
               'text/plain', 'image/svg+xml', 'text/html', 'application/xhtml+xml'}
HTML_TYPES = {'text/html', 'application/xhtml+xml'}


def _blocked(ip):
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified)


def assert_public_https(url):
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('Only credential-free HTTPS URLs can be acquired.')
    if parts.port not in (None, 443):
        raise ValueError('Acquire only uses the default HTTPS port.')
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _blocked(literal):
            raise ValueError('Refusing a non-public address.')
        return url
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError('Could not resolve ' + host) from exc
    if not infos:
        raise ValueError('Could not resolve ' + host)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _blocked(ip):
            raise ValueError('Refusing a non-public address for ' + host)
    return url


def fetch(url, limit, hops=5):
    assert_public_https(url)

    class _Stop(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_Stop)
    request = urllib.request.Request(url, headers={'User-Agent': 'rea-bot', 'Accept': 'application/json, */*'})
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308) and hops:
            location = exc.headers.get('Location')
            if not location:
                raise ValueError('Redirect had no Location header.')
            return fetch(urljoin(url, location), limit, hops - 1)
        raise ValueError('Download failed with HTTP %s.' % exc.code) from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        raise ValueError('Download failed: ' + exc.__class__.__name__) from exc
    chunks, total = [], 0
    while True:
        block = response.read(65536)
        if not block:
            break
        total += len(block)
        if total > limit:
            raise ValueError('Download exceeded the size limit.')
        chunks.append(block)
    return {'url': url, 'data': b''.join(chunks), 'content_type': response.headers.get('content-type', '')}


def check_sha512_integrity(raw, integrity):
    if not isinstance(integrity, str) or not integrity.startswith('sha512-'):
        raise ValueError('Only sha512 integrity values from the registry are accepted.')
    import base64
    actual = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()
    if actual != integrity:
        raise ValueError('Tarball failed the registry integrity check; nothing extracted.')
    return actual


def _member_path(name):
    rel = Path(name)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ValueError('Archive path is not allowed.')
    return rel


def safe_extract_tarball(raw, dest, max_files=NPM_FILE_CAP, max_bytes=TARBALL_LIMIT):
    dest = Path(dest)
    if dest.exists():
        raise ValueError('Extract destination already exists.')
    dest.mkdir(parents=True)
    files = 0
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
            for member in tar.getmembers():
                rel = _member_path(member.name)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ValueError('Refusing a special archive member.')
                out = dest.joinpath(*rel.parts)
                if member.isdir():
                    out.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError('Refusing an unsupported archive member.')
                files += 1
                if files > max_files or member.size > max_bytes or total + max(member.size, 0) > max_bytes:
                    raise ValueError('Archive exceeds the size limit.')
                handle = tar.extractfile(member)
                if handle is None:
                    raise ValueError('Archive member could not be read.')
                blob = handle.read(member.size + 1)
                if len(blob) != member.size:
                    raise ValueError('Archive member size did not match its header.')
                total += len(blob)
                if total > max_bytes:
                    raise ValueError('Archive exceeds the size limit.')
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(blob)
        for path in dest.rglob('*'):
            if path.is_symlink():
                raise ValueError('Refusing a symlink in the extracted tree.')
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return {'files': files, 'bytes': total}


def _registry_name(name):
    if name.startswith('@'):
        scope, pkg = name[1:].split('/', 1)
        return '@' + scope + '%2f' + pkg
    return name


def _content_type(value):
    return (value or '').split(';', 1)[0].strip().lower()


def _package_hint(root):
    path = root / 'package.json'
    if not path.is_file():
        nested = root / 'package' / 'package.json'
        path = nested if nested.is_file() else None
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text()[:65536])
    except (OSError, ValueError):
        return {}
    hint = {}
    for key in ('name', 'version', 'main', 'module', 'type'):
        if isinstance(data.get(key), str):
            hint[key] = data[key]
    scripts = data.get('scripts')
    if isinstance(scripts, dict):
        hint['script_names'] = sorted(k for k in scripts if isinstance(k, str))[:32]
    bin_field = data.get('bin')
    if isinstance(bin_field, str):
        hint['bin'] = bin_field
    elif isinstance(bin_field, dict):
        hint['bin'] = {k: bin_field[k] for k in list(bin_field)[:16] if isinstance(k, str) and isinstance(bin_field[k], str)}
    return hint


def _finish(run, receipt):
    route = dict(run.meta['route'])
    if receipt['kind'] == 'npm-package' and isinstance(route.get('package_identity'), dict):
        route['package_identity'] = dict(route['package_identity'], integrity_verified=True,
                                          version_hint=receipt['version'], version_pinned=True)
    if receipt['kind'] == 'git-repository':
        route['revision_hint'] = receipt['commit']
        route['revision_pinned'] = True
    run.update_meta(route=route, acquired=receipt, status='acquired')
    return receipt


def _source_dir(run):
    dest = run.dir / 'source'
    if dest.exists():
        raise ValueError('This run already has acquired source. Remove it yourself to acquire again.')
    return dest


def acquire_npm(run, route, fetch_fn=None):
    fetch_fn = fetch_fn or fetch
    ident = route.get('package_identity') or {}
    name = ident.get('package')
    if not isinstance(name, str) or not name:
        raise ValueError('This npm route has no package name.')
    version = ident.get('version_hint')
    pinned = bool(ident.get('version_pinned'))
    if version and not pinned:
        import re
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9._-]*', version):
            raise ValueError('Pin an exact version. Dist-tags such as latest are resolved; ranges are not.')
    selector = version or 'latest'
    meta_url = 'https://registry.npmjs.org/' + _registry_name(name) + '/' + selector
    meta = json.loads(fetch_fn(meta_url, META_LIMIT)['data'].decode('utf-8'))
    import re
    if not isinstance(meta, dict) or meta.get('name') != name or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', str(meta.get('version') or '')):
        raise ValueError('Registry response did not name an exact version of this package.')
    dist = meta.get('dist') if isinstance(meta.get('dist'), dict) else {}
    integrity, tarball = dist.get('integrity'), dist.get('tarball')
    if not isinstance(tarball, str) or not isinstance(integrity, str):
        raise ValueError('Registry response has no integrity or tarball.')
    assert_public_https(tarball)
    raw = fetch_fn(tarball, TARBALL_LIMIT)['data']
    check_sha512_integrity(raw, integrity)
    dest = _source_dir(run)
    tmp = run.dir / '.acquire-tmp'
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        stats = safe_extract_tarball(raw, tmp)
        os.replace(tmp, dest)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
        raise
    hint = _package_hint(dest)
    receipt = {'kind': 'npm-package', 'path': str(dest), 'package': name, 'version': meta['version'],
               'requested': selector, 'integrity': integrity, 'tarball': tarball,
               'tarball_sha256': hashlib.sha256(raw).hexdigest(), 'files': stats['files'], 'bytes': stats['bytes'],
               'scripts_executed': False, 'package_hint': hint,
               'note': 'Tarball verified and extracted. Lifecycle scripts were not run. Dependencies were not installed.'}
    return _finish(run, receipt)


def _git_env(home):
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL') if k in os.environ}
    env.update({'HOME': str(home), 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
                'GIT_TERMINAL_PROMPT': '0', 'GIT_LFS_SKIP_SMUDGE': '1', 'GCM_INTERACTIVE': 'Never'})
    return env


def _git(args, cwd, env, timeout=180):
    proc = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.file.allow=never',
                           '-c', 'advice.detachedHead=false', *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout or '').strip().splitlines()
        raise ValueError('git failed: ' + (lines[-1] if lines else 'exit %s' % proc.returncode))
    return proc.stdout


def _resolve_commit(url, hint, pinned, env):
    import re
    if hint and re.fullmatch(r'[0-9a-fA-F]{40}', hint):
        return hint.lower()
    ref = hint or 'HEAD'
    candidates = ['HEAD'] if ref == 'HEAD' else ['refs/heads/' + ref, 'refs/tags/' + ref, 'refs/tags/' + ref + '^{}']
    for candidate in candidates:
        out = _git(['ls-remote', url, candidate], None, env, timeout=60)
        for line in out.splitlines():
            sha = line.split()[0] if line.split() else ''
            if re.fullmatch(r'[0-9a-fA-F]{40}', sha):
                return sha.lower()
    raise ValueError('Could not resolve a commit. Pass a branch, tag or 40-character commit.')


def _tree_stats(root):
    files = total = 0
    for path in root.rglob('*'):
        if '.git' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('Acquired tree contains a symlink.')
        if path.is_file():
            files += 1
            total += path.stat().st_size
            if files > GIT_FILE_CAP or total > GIT_BYTE_CAP:
                raise ValueError('Repository checkout exceeds the size limit.')
    return files, total


def _repo_url(route):
    if route.get('repository_url'):
        return route['repository_url']
    parts = urlsplit(route['target'])
    segments = [unquote(p) for p in parts.path.split('/') if p]
    if parts.scheme != 'https' or len(segments) < 2:
        raise ValueError('Pass the repository root URL (https://host/owner/name).')
    name = segments[1].removesuffix('.git')
    return parts.scheme + '://' + parts.hostname + '/' + segments[0] + '/' + name


def acquire_git(run, route):
    if shutil.which('git') is None:
        raise ValueError('git is not on PATH.')
    url = _repo_url(route)
    assert_public_https(url)
    dest = _source_dir(run)
    home = run.dir / '.git-home'
    home.mkdir(exist_ok=True)
    env = _git_env(home)
    sha = _resolve_commit(url, route.get('revision_hint'), route.get('revision_pinned'), env)
    try:
        dest.mkdir()
        _git(['init', '-q'], dest, env)
        _git(['remote', 'add', 'origin', url], dest, env)
        _git(['fetch', '--depth', '1', '--no-tags', 'origin', sha], dest, env)
        _git(['checkout', '-q', '--detach', 'FETCH_HEAD'], dest, env)
        got = _git(['rev-parse', 'HEAD'], dest, env).strip()
        if got != sha:
            raise ValueError('Checkout did not land on the resolved commit.')
        files, total = _tree_stats(dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    receipt = {'kind': 'git-repository', 'path': str(dest), 'url': url, 'commit': sha,
               'revision_requested': route.get('revision_hint'), 'revision_pinned': True,
               'path_hint': route.get('path_hint'), 'files': files, 'bytes': total,
               'hooks': 'disabled', 'submodules': 'not checked out', 'lfs': 'smudge skipped',
               'scripts_executed': False,
               'note': 'One commit was fetched. Hooks, submodules and git-lfs smudge were not run.'}
    return _finish(run, receipt)


def _asset_rels(page, base_url):
    from html.parser import HTMLParser

    class Links(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.found = []

        def handle_starttag(self, tag, attrs):
            attr = {k.lower(): v for k, v in attrs if k}
            if tag in {'script', 'img', 'source', 'video', 'audio'} and attr.get('src'):
                self.found.append(attr['src'])
            elif tag == 'link' and attr.get('href'):
                self.found.append(attr['href'])

    parser = Links()
    parser.feed(page.decode('utf-8', 'replace'))
    parser.close()
    base = urlsplit(base_url)
    rels = []
    for link in parser.found:
        if not isinstance(link, str) or link.startswith(('data:', 'javascript:', 'mailto:', '//')):
            continue
        joined = urlsplit(urljoin(base_url, link))
        if joined.scheme != 'https' or joined.hostname != base.hostname or joined.port not in (None, 443):
            continue
        if joined.query or joined.fragment or joined.username:
            continue
        suffix = Path(unquote(joined.path)).suffix.lower()
        if suffix not in ASSET_SUFFIXES:
            continue
        parts = [p for p in Path(unquote(joined.path)).parts if p not in ('/', '')]
        if not parts or '..' in parts or parts[0] == '..':
            continue
        rel = Path(*[p for p in parts if p != '/'])
        if str(rel) in ('index.html', '') or any(p.startswith('.') for p in rel.parts):
            continue
        rels.append((str(rel), joined.geturl()))
    unique = []
    seen = set()
    for item in rels:
        if item[0] not in seen:
            seen.add(item[0])
            unique.append(item)
    return unique[:ASSET_CAP]


def acquire_website(run, route, fetch_fn=None):
    fetch_fn = fetch_fn or fetch
    page = fetch_fn(route['target'], PAGE_LIMIT)
    if _content_type(page['content_type']) not in HTML_TYPES:
        raise ValueError('Website acquire expected an HTML document.')
    dest = _source_dir(run)
    tmp = run.dir / '.acquire-tmp'
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    saved = []
    total = 0
    try:
        (tmp / 'index.html').write_bytes(page['data'])
        total += len(page['data'])
        saved.append({'path': 'index.html', 'bytes': len(page['data']),
                      'sha256': hashlib.sha256(page['data']).hexdigest(), 'content_type': _content_type(page['content_type'])})
        skipped = []
        for rel, url in _asset_rels(page['data'], page['url']):
            if total >= SITE_LIMIT:
                skipped.append(rel)
                continue
            try:
                asset = fetch_fn(url, min(ASSET_LIMIT, SITE_LIMIT - total))
            except ValueError:
                skipped.append(rel)
                continue
            if _content_type(asset['content_type']) not in ASSET_TYPES:
                skipped.append(rel)
                continue
            target = tmp / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(asset['data'])
            total += len(asset['data'])
            saved.append({'path': rel, 'bytes': len(asset['data']),
                          'sha256': hashlib.sha256(asset['data']).hexdigest(),
                          'content_type': _content_type(asset['content_type'])})
        os.replace(tmp, dest)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
        raise
    visible = html_text(page['data'])
    receipt = {'kind': 'website', 'path': str(dest), 'url': page['url'], 'requested': route['target'],
               'files': len(saved), 'saved': saved, 'bytes': total, 'scripts_executed': False, 'skipped_assets': skipped,
               'visible_text_sha256': hashlib.sha256(visible.encode()).hexdigest(),
               'note': 'Static bytes only. JavaScript in the page was not executed, so client-rendered text is not in this copy.'}
    return _finish(run, receipt)


def acquire_run(run, fetch_fn=None):
    route = run.meta['route']
    kind = route.get('kind')
    if kind == 'npm-package':
        return acquire_npm(run, route, fetch_fn)
    if kind == 'git-repository':
        return acquire_git(run, route)
    if kind == 'website':
        return acquire_website(run, route, fetch_fn)
    if kind in {'source-directory', 'source-repository', 'source-file', 'javascript-application',
                'python-package', 'go-module', 'rust-crate', 'file'}:
        raise ValueError('Target is already local: ' + route.get('target', ''))
    raise ValueError('Acquire supports npm packages, git repositories and HTTPS websites. This route is ' + str(kind) + '.')
