"""rea-bot command line. Every command prints one JSON object."""
import argparse
import json
import sys

from . import api, engine


def main(argv=None):
    p = argparse.ArgumentParser(prog='rea-bot', description='Understand, rebuild and prove a target on the box.')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('status')
    sub.add_parser('runs')
    a = sub.add_parser('route'); a.add_argument('target')
    a = sub.add_parser('pin', help='SHA-256 of a reviewed file or folder, for --approve-original'); a.add_argument('path')
    a = sub.add_parser('new'); a.add_argument('target'); a.add_argument('--id'); a.add_argument('--note')
    a = sub.add_parser('inspect'); a.add_argument('run'); a.add_argument('--target')
    a = sub.add_parser('prepare'); a.add_argument('run'); a.add_argument('--input', required=True, help='JSON with evidence, features, improvements')
    a.add_argument('--engine-waiver', help='Reason the REA engine could not be used (recorded in SPEC.md)')
    a = sub.add_parser('diff'); a.add_argument('run'); a.add_argument('--cases', required=True)
    a.add_argument('--reconstruction', required=True, help='argv string, e.g. "python3 adapter.py"')
    a.add_argument('--original'); a.add_argument('--original-pin'); a.add_argument('--approve-original')
    a.add_argument('--timeout', type=float, default=10); a.add_argument('--spec')
    a = sub.add_parser('parity'); a.add_argument('run'); a.add_argument('--results'); a.add_argument('--spec')
    a = sub.add_parser('recheck'); a.add_argument('run'); a.add_argument('--rerun', action='store_true')
    a = sub.add_parser('certify'); a.add_argument('run')
    e = sub.add_parser('engine').add_subparsers(dest='ecmd', required=True)
    e.add_parser('status')
    x = e.add_parser('stage-node'); x.add_argument('--apply', action='store_true')
    x = e.add_parser('setup'); x.add_argument('--node'); x.add_argument('--apply', action='store_true')
    x.add_argument('--approve-source'); x.add_argument('--tarball')
    x = e.add_parser('tools'); x.add_argument('--match'); x.add_argument('--schema', action='store_true')
    x = e.add_parser('call'); x.add_argument('run'); x.add_argument('--calls', required=True, help='JSON file: [{"tool":..., "arguments":{...}}]')
    args = p.parse_args(argv)
    try:
        if args.cmd == 'status': out = api.status()
        elif args.cmd == 'runs': out = api.runs()
        elif args.cmd == 'route': out = api.route(args.target)
        elif args.cmd == 'pin': out = {'path': args.path, 'sha256': __import__('rea_bot.runner', fromlist=['x']).sha256_path(args.path)}
        elif args.cmd == 'new': out = api.new(args.target, args.id, args.note)
        elif args.cmd == 'inspect': out = api.inspect(args.run, args.target)
        elif args.cmd == 'prepare': out = api.prepare(args.run, args.input, args.engine_waiver)
        elif args.cmd == 'diff': out = api.diff(args.run, args.cases, args.reconstruction, args.original, args.original_pin,
                                                args.approve_original, args.timeout, args.spec)
        elif args.cmd == 'parity': out = api.parity(args.run, args.results, args.spec)
        elif args.cmd == 'recheck': out = api.recheck(args.run, args.rerun)
        elif args.cmd == 'certify': out = api.certify(args.run)
        elif args.ecmd == 'status': out = engine.status()
        elif args.ecmd == 'stage-node': out = engine.stage_node(args.apply)
        elif args.ecmd == 'setup': out = engine.setup(args.node, args.approve_source, args.apply, args.tarball)
        elif args.ecmd == 'tools':
            tools = engine.list_tools(args.match)
            out = tools if args.schema else {'count': len(tools), 'tools': [t['name'] for t in tools]}
        elif args.ecmd == 'call':
            with open(args.calls) as f:
                out = engine.call_batch(args.run, json.load(f))
    except (ValueError, OSError, KeyError, TypeError) as err:
        print(json.dumps({'error': str(err)}, ensure_ascii=False))
        return 2
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
