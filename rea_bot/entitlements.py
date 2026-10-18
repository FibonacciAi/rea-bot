"""Certificate bookkeeping. Lostwax is free and open source (MIT). No accounts, keys or payments.

`certify` issues a portable, digest-pinned parity certificate. Certificates are always free and unlimited.
This module only counts certificates issued on this box (for the status report); it never charges,
signs or contacts a server.
"""

from . import store


def _path():
    return store.home() / '.entitlements.json'


def state():
    data = store.read_json(_path(), {'certificates_issued': 0})
    return {'plan': 'free', 'certificates_issued': data['certificates_issued'], 'certificates': 'free, unlimited'}


def consume_certificate():
    data = store.read_json(_path(), {'certificates_issued': 0})
    data['certificates_issued'] += 1
    store.write_json(_path(), data)
    return True, state()
