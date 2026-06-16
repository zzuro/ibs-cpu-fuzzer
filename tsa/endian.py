#!/usr/bin/env python3
import sys, re

s = " ".join(sys.argv[1:])
hexstr = re.sub(r"[^0-9a-fA-F]", "", s)

if len(hexstr) % 2:
    raise SystemExit("error: odd number of hex digits")

out = bytes.fromhex(hexstr)[::-1]
print(out.hex(" "))
print("0x" + out.hex())