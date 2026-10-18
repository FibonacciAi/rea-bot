"""MCP stdio protocol and full flow through tool calls."""
import json
import os
import shutil
import subprocess
import sys
import unittest

from tests.helpers import EXAMPLE, ROOT, TempHome
from rea_bot import runner


class Mcp(TempHome):
    def rpc(self, messages):
        env = dict(os.environ)
        p = subprocess.run([sys.executable, str(ROOT / 'server' / 'mcp_server.py')], input='\n'.join(json.dumps(m) for m in messages) + '\n',
                           capture_output=True, text=True, timeout=120, env=env)
        return [json.loads(line) for line in p.stdout.splitlines()]

    def call(self, i, name, args):
        return {'jsonrpc': '2.0', 'id': i, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}}

    def test_catalog_is_compact_and_contract_enforced(self):
        out = self.rpc([{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
                        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                        self.call(3, 'rea_route', {'target': 'https://example.org', 'extra': 1}),
                        {'jsonrpc': '2.0', 'id': 4, 'method': 'nope'}, 'garbage'])
        self.assertEqual(out[0]['result']['serverInfo']['name'], 'rea-bot')
        self.assertEqual(len(out[1]['result']['tools']), 12)
        self.assertTrue(out[2]['result']['isError'])
        self.assertEqual(out[3]['error']['code'], -32601)
        self.assertEqual(out[4]['error']['code'], -32600)

    @unittest.skipUnless(shutil.which('node'), 'node required')
    def test_full_flow_over_mcp(self):
        build = json.loads((EXAMPLE / 'build.json').read_text())
        pin = runner.sha256_path(EXAMPLE / 'original')
        out = self.rpc([
            self.call(1, 'rea_new_run', {'target': str(EXAMPLE / 'original'), 'run_id': 'mcp-demo'}),
            self.call(2, 'rea_inspect', {'run_id': 'mcp-demo'}),
            self.call(3, 'rea_prepare', {'run_id': 'mcp-demo', 'build': build, 'engine_waiver': 'mcp test'}),
            self.call(4, 'rea_diff', {'run_id': 'mcp-demo', 'cases_file': str(EXAMPLE / 'cases.json'),
                                      'reconstruction': ['python3', str(EXAMPLE / 'reconstruction' / 'adapter.py')],
                                      'original': ['node', str(EXAMPLE / 'original' / 'adapter.mjs')],
                                      'original_pin': str(EXAMPLE / 'original'), 'approve_original': pin}),
            self.call(5, 'rea_parity', {'run_id': 'mcp-demo'})])
        for m in out:
            self.assertFalse(m['result'].get('isError'), m)
        self.assertEqual(out[3]['result']['structuredContent']['matches'], 14)
        self.assertEqual(out[4]['result']['structuredContent']['runner_attested_passes'], 4)
