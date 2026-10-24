"""Lostwax native analysis engine.

Optional, pinned, and off by default. The core plugin does not import capstone, LIEF,
wasmtime, or dnfile until `rea-bot native setup --apply` has verified those wheels.
REA stays available through `rea-bot engine`.
"""
