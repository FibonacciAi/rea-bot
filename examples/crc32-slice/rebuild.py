"""IEEE CRC-32 of UTF-8 bytes. Polynomial must be 3988292384.

Reads one JSON object {"bytes": str, "polynomial": int} and writes an 8-digit hex JSON string.
"""
import json
import sys
import zlib

IEEE = 3988292384


def main():
    data = json.load(sys.stdin)
    if int(data["polynomial"]) != IEEE:
        raise SystemExit("only the IEEE polynomial is implemented")
    digest = zlib.crc32(data["bytes"].encode("utf-8")) & 0xFFFFFFFF
    json.dump("%08x" % digest, sys.stdout)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
