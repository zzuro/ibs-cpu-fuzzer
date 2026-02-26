import sys
import math
import os

with open(sys.argv[1], 'ab') as f:
    f.seek(0, os.SEEK_END)
    length = f.tell()

    if length % 16 == 0:
        # Perfect, nothing to do
        pass
    else:
        f.write(b'\x90'*(length%16))
