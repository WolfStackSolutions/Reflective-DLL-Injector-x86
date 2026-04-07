#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Convert PE to XOR-encrypted C byte array")
    parser.add_argument("input", type=str, help="Input PE filename")
    parser.add_argument("--out", "-o", default="output.txt", type=str, help="Output filename (default: output.txt)")
    parser.add_argument("--key", "-k", default="00", type=str,
                        help="XOR key as hex string (default: 00 = no encryption). E.g. 123456789ABCDEF0")

    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        key = bytes.fromhex(args.key)
        if len(key) == 0:
            raise ValueError
    except ValueError:
        print(f"Error: invalid hex key '{args.key}'. Example: 123456789ABCDEF0", file=sys.stderr)
        sys.exit(1)

    raw = path.read_bytes()
    if len(raw) < 2 or raw[:2] != b"MZ":
        print("Warning: file does not appear to be a valid PE (no MZ header)", file=sys.stderr)

    key_len = len(key)
    with open(args.out, "w") as out:
        for i, byte in enumerate(raw):
            encrypted = byte ^ key[i % key_len]
            out.write(f"0x{encrypted:02X}")
            if i < len(raw) - 1:
                out.write(", ")
            if (i + 1) % 16 == 0:
                out.write("\n")

    print(f"Done: {len(raw)} bytes -> {args.out} (key: {key.hex().upper()}, {len(key)} bytes)")

if __name__ == "__main__":
    main()
