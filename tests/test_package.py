"""Package shape: Cursor/Agent plugin manifest, skills, MCP config, engine pins, hygiene."""
import hashlib
import json
import re
import unittest

from tests.helpers import ROOT

# Hygiene list stored as SHA-256 digests only, so the terms themselves never ship.
# BANNED_TOKENS: digests of whole lowercase [a-z0-9]+ words. BANNED_SUBSTRINGS: (byte length, digest) of substrings.
BANNED_TOKENS = {
    '123d3ee19f254eeccbac647c94b39b1b1ac7c960e3d4df524eb60736a7d1f9c7',
    '12d25bbbfd9345aa8a961c7c123c25da1746a5b47d29adb3b6969c451d22f55e',
    '1fc148378903a6bb31270127289d272ef49d83b401c6fe9b8737e1b42885d08d',
    '2141d3eba0694334109e5fd149a4654ebe6ddb564045326dfdcbf788fe8ebf15',
    '29d242f5a98383039f9cadfbbf80bb1d697c8e0ad99ef47c716176c99b754bb2',
    '75f7313c20144e39edcf57a14733d074aee0c482320d5178ee0ef2f2608c2996',
    'a5a650816f407fbe43c8c649da480cf3b2d6df4b6612c97d3c788d1a81daaf52',
    'a66d93a7976497e4c0ef0f06e03bcd94416ce8841cb6016a044c9201053b6996',
    'a705401d0ab055c99fef9b9f59b1623638d4c620a414fe0f1d86ffc18a784cf7',
    'ab3352e20607e076e2cb2cdf77d1c7e0e9ee9c54cb282e59a671f5f98585a9bd',
    'ba89e17d42ffd1e80890bf04809c94daf2ecff8f4dd52311f5fc329728ac4eb5',
    'c8be11d0de96a595ddd2a59005513a3bd2992e2a1d0911379a2929d7e23df0ad',
    'fac19268939aa53b818ced06ac58b782bb9de9aba17d7bccf1ffad3dcbbb4fb5',
}
BANNED_SUBSTRINGS = {
    (4, '1fc148378903a6bb31270127289d272ef49d83b401c6fe9b8737e1b42885d08d'),
    (6, 'c8be11d0de96a595ddd2a59005513a3bd2992e2a1d0911379a2929d7e23df0ad'),
    (6, 'eb1eaccd43bc4f375ea775e287dd8a5433463323ec5f7ea504f19c2b4fa1eaf9'),
    (7, '3e44fb009899c0f900c1e74cd803b171d70a5d799d2cc933898d78e8d5fc17ca'),
    (7, 'fac19268939aa53b818ced06ac58b782bb9de9aba17d7bccf1ffad3dcbbb4fb5'),
    (8, '29d242f5a98383039f9cadfbbf80bb1d697c8e0ad99ef47c716176c99b754bb2'),
    (8, 'ab3352e20607e076e2cb2cdf77d1c7e0e9ee9c54cb282e59a671f5f98585a9bd'),
    (10, 'ba89e17d42ffd1e80890bf04809c94daf2ecff8f4dd52311f5fc329728ac4eb5'),
    (11, '123d3ee19f254eeccbac647c94b39b1b1ac7c960e3d4df524eb60736a7d1f9c7'),
    (11, '2141d3eba0694334109e5fd149a4654ebe6ddb564045326dfdcbf788fe8ebf15'),
    (12, 'a705401d0ab055c99fef9b9f59b1623638d4c620a414fe0f1d86ffc18a784cf7'),
    (14, 'f3c7e6be96e2b0e23b3d08e422f2bf92709e8bb321d945e6e2fe7a85075d207a'),
    (16, 'd76ba0f2df3c2a945ffec4a6ebbd03a4961d9e9d0297109afa1d0ab870f590ae'),
    (19, '97b8d6d82317ad329f09b168ad9e313c81d05557f0c2e981b4bf59b9fa5cf56d'),
}


class Package(unittest.TestCase):
    def test_manifest(self):
        m = json.loads((ROOT / '.cursor-plugin' / 'plugin.json').read_text())
        self.assertTrue(re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', m['name']))
        self.assertEqual(m['name'], 'rea-bot')
        self.assertTrue(re.fullmatch(r'\d+\.\d+\.\d+', m['version']))
        self.assertTrue((ROOT / m['logo']).is_file())
        self.assertTrue((ROOT / m['mcpServers']).is_file())
        self.assertTrue((ROOT / m['skills']).is_dir())
        mk = json.loads((ROOT / '.cursor-plugin' / 'marketplace.json').read_text())
        self.assertEqual(mk['metadata']['version'], m['version'])

    def test_mcp_uses_cursor_plugin_root(self):
        cfg = json.loads((ROOT / 'mcp.json').read_text())['mcpServers']['rea-bot']
        self.assertEqual(cfg['args'], ['${CURSOR_PLUGIN_ROOT}/server/mcp_server.py'])
        self.assertNotIn('${PLUGIN_ROOT}', json.dumps(cfg))
        self.assertTrue((ROOT / 'server' / 'mcp_server.py').is_file())

    def test_skills_frontmatter(self):
        skills = sorted((ROOT / 'skills').glob('*/SKILL.md'))
        self.assertGreaterEqual(len(skills), 2)
        for s in skills:
            text = s.read_text()
            m = re.match(r'---\nname: ([a-z0-9-]+)\ndescription: (.+?)\n---\n', text, re.S)
            self.assertTrue(m, s)
            self.assertTrue(m.group(1).startswith('rea-bot'))
            self.assertLessEqual(len(m.group(2)), 1024)

    def test_engine_pins_consistent(self):
        up = json.loads((ROOT / 'engine' / 'UPSTREAM.json').read_text())
        self.assertEqual((up['version'], up['commit']), ('6.5.0', '3b79af28e80785afce9f5998d8f03289402a1847'))
        integrity = json.loads((ROOT / 'engine' / 'vendor-integrity.json').read_text())
        self.assertEqual(len(integrity), 1651)
        import hashlib
        self.assertEqual(hashlib.sha256((ROOT / 'engine' / 'package-lock.json').read_bytes()).hexdigest(), integrity['package-lock.json'])

    def test_hygiene(self):
        lengths = sorted({n for n, _ in BANNED_SUBSTRINGS})
        for p in ROOT.rglob('*'):
            if {'.git', '__pycache__', '.rea-bot-engine', '.rea-bot-native'} & set(p.parts):
                continue
            if p.is_symlink():
                self.fail('symlink packaged: ' + str(p))
            if not p.is_file() or p.suffix in {'.png', '.pyc'} or p.parent.name == 'engine':
                continue
            raw = p.read_bytes().lower()
            for word in set(re.findall(rb'[a-z0-9]+', raw)):
                self.assertNotIn(hashlib.sha256(word).hexdigest(), BANNED_TOKENS, str(p) + ': banned word')
            for n in lengths:
                for i in range(len(raw) - n + 1):
                    if (n, hashlib.sha256(raw[i:i + n]).hexdigest()) in BANNED_SUBSTRINGS:
                        self.fail(str(p) + ': banned term at byte ' + str(i))
