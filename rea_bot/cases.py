"""Expand a small, seeded case specification into a concrete cases file.

Grids are cartesian products. Samples use random.Random(seed), so the same spec always
yields the same cases. This is not a coverage proof; it only makes the declared inputs
repeatable.
"""
import itertools
import random


def _assign(obj, path, value):
    parts = path.split('.')
    if not parts or any(not part for part in parts):
        raise ValueError('Case paths must be dotted names such as args.0.')
    cur = obj
    for i, part in enumerate(parts[:-1]):
        nxt = parts[i + 1]
        if part.isdigit():
            raise ValueError('A numeric path segment can only be last: ' + path)
        if not isinstance(cur, dict):
            raise ValueError('Path does not match the base object: ' + path)
        if part not in cur or not isinstance(cur[part], (dict, list)):
            cur[part] = [] if nxt.isdigit() else {}
        cur = cur[part]
    last = parts[-1]
    if last.isdigit():
        if not isinstance(cur, list):
            raise ValueError('Numeric path does not land on a list: ' + path)
        idx = int(last)
        if idx > 64:
            raise ValueError('List indexes in a case path stop at 64.')
        while len(cur) <= idx:
            cur.append(None)
        cur[idx] = value
    else:
        if not isinstance(cur, dict):
            raise ValueError('Path does not match the base object: ' + path)
        cur[last] = value


def _sample(rng, rule):
    if not isinstance(rule, dict):
        raise ValueError('Each sample field needs an object rule.')
    kind = rule.get('type')
    if kind == 'choice':
        values = rule.get('values')
        if not isinstance(values, list) or not values or len(values) > 100:
            raise ValueError('choice samples need 1-100 values.')
        return rng.choice(values)
    if kind == 'int':
        lo, hi = rule.get('min'), rule.get('max')
        if type(lo) is not int or type(hi) is not int or lo > hi or hi - lo > 1_000_000:
            raise ValueError('int samples need integer min and max, spanning at most 1000000.')
        return rng.randint(lo, hi)
    raise ValueError('Sample type must be choice or int.')


def expand(spec):
    if not isinstance(spec, dict):
        raise ValueError('Case spec must be an object.')
    feature = spec.get('feature_id')
    if not isinstance(feature, str) or not feature.strip():
        raise ValueError('Case spec needs a feature_id.')
    prefix = spec.get('id_prefix') or feature
    if not isinstance(prefix, str) or not prefix.strip():
        raise ValueError('id_prefix must be a nonempty string.')
    base = spec.get('base') if spec.get('base') is not None else {}
    if not isinstance(base, dict):
        raise ValueError('base must be an object.')
    grid = spec.get('grid') or {}
    if not isinstance(grid, dict) or len(grid) > 8:
        raise ValueError('grid supports at most 8 fields.')
    keys = list(grid)
    columns = []
    total = 1
    for key in keys:
        values = grid[key]
        if not isinstance(values, list) or not values or len(values) > 50:
            raise ValueError('Each grid field needs 1-50 values.')
        total *= len(values)
        if total > 500:
            raise ValueError('Grid expansion stops at 500 cases.')
        columns.append(values)
    rows = []
    combos = itertools.product(*columns) if columns else [()]
    for combo in combos:
        row = json_copy(base)
        for key, value in zip(keys, combo):
            _assign(row, key, value)
        rows.append(row)
    sample = spec.get('sample')
    if sample:
        if not isinstance(sample, dict):
            raise ValueError('sample must be an object.')
        count = sample.get('count', 0)
        if type(count) is not int or count < 0 or count > 100:
            raise ValueError('sample count must be an integer from 0 to 100.')
        seed = sample.get('seed', 0)
        if type(seed) is not int:
            raise ValueError('sample seed must be an integer.')
        fields = sample.get('fields') or {}
        if not isinstance(fields, dict) or not fields:
            raise ValueError('sample needs at least one field.')
        rng = random.Random(seed)
        for _ in range(count):
            row = json_copy(base)
            for key, rule in fields.items():
                _assign(row, key, _sample(rng, rule))
            rows.append(row)
    if not rows or len(rows) > 500:
        raise ValueError('Expansion must yield 1-500 cases.')
    cases = []
    for i, row in enumerate(rows, 1):
        cases.append({'id': '%s-%03d' % (prefix, i), 'feature_id': feature, 'input': row})
    return cases


def json_copy(value):
    import json
    return json.loads(json.dumps(value))
