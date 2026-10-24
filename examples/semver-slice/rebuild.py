"""Finite semver CLI slice: one X.Y.Z argument, optional major/minor/patch increment.

Leading zeros are rejected. This is not a full semver implementation.
"""
import re
import sys

_VER = re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')


def main(argv):
    inc = None
    versions = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ('-i', '--inc'):
            if index + 1 >= len(argv):
                return 1, ''
            inc = argv[index + 1]
            index += 2
            continue
        if arg == '--':
            versions.extend(argv[index + 1:])
            break
        if arg.startswith('-'):
            return 1, ''
        versions.append(arg)
        index += 1
    if len(versions) != 1 or inc not in (None, 'major', 'minor', 'patch'):
        return 1, ''
    match = _VER.fullmatch(versions[0])
    if not match:
        return 1, ''
    major, minor, patch = (int(part) for part in match.groups())
    if inc == 'major':
        major, minor, patch = major + 1, 0, 0
    elif inc == 'minor':
        minor, patch = minor + 1, 0
    elif inc == 'patch':
        patch += 1
    return 0, '%d.%d.%d\n' % (major, minor, patch)


if __name__ == '__main__':
    code, out = main(sys.argv[1:])
    sys.stdout.write(out)
    raise SystemExit(code)
