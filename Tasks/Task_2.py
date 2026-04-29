import sys
import os
import random
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Task_1')))

from Task_1 import sha256

def spmac(k: bytearray, u: bytearray) -> str:
    k.extend(u)
    return sha256(k)

if __name__ == "__main__":
    key = bytearray(b'0\x01')
    msg = bytearray(b'0\x21')
    print(spmac(key, msg))