import struct
import os
import hashlib
import random
import utils

# CONSTANT INITIALIZATION

# They are derived by taking the cube root of each of the first 64 prime numbers, isolating the
# fractional part, and converting the first 32 bits of that fraction into a hexadecimal value.

K_rounds = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash Values: the starting state of the hash before any data is processed
H_init = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Definition of Logical functions

# Since all additions in SHA-256 are performed in modulo 2^32, if an addition exceeds 32 bits,
# the additional bits will be discarded, to do that we need to maintain the values of the bit
# and it's length.
# To do tht we need to sum a value that doesn't change anything in the actual value computed.
MAX_32 = 0xFFFFFFFF


# Right shift x by n bits
def shr(x: int, n: int) -> bytes:
    return (x >> n) & MAX_32


# Circular Right Rotation. Shift x right n times, and move the bits "falled" from the right side and re-input them
# from the left.
def rotr(x: int, n: int):
    return ((x >> n) | (x << (32 - n))) & MAX_32


# AUXILIARY FUNCTIONS

# For each bit index, if x is 1, choose the bit from y; if x = 0, choose the bit from z
def ch(x, y, z):
    return ((x & y) ^ ((~x) & z)) & MAX_32


# For each bit index, return 1 if the majority (two or more) of x, y, z are 1
def maj(x, y, z):
    return ((x & y) ^ (x & z) ^ (y & z)) & MAX_32

#LARGE SIGMA

def sigma_0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma_1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


# SMALL SIGMA

def sigma_2(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma_3(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

# Actual Hash function
def sha_256(message: bytes, length_offset: int = 0, initial_state: list[int] = None) -> str:

    message = bytearray(message)
    og_msg_length=(len(message) + length_offset) * 8

    message.append(0x80)

    while len(message) % 64 != 56:
        message.extend(b"\x00")

    message.extend(og_msg_length.to_bytes(8, byteorder="big"))

    if initial_state is None:
        H = list(H_init)
    elif isinstance(initial_state, (bytes, bytearray)):
        H = list(struct.unpack('>8I', initial_state))
    else:
        H = list(initial_state)

    for i in range(0, len(message), 64):
        chunk = message[i : i + 64]

        W = list(struct.unpack('>16I', chunk)) + [0] * 48

        for j in range(16, 64):
            W[j] = (sigma_3(W[j - 2]) + W[j - 7] + sigma_2(W[j - 15]) + W[j - 16]) & MAX_32

        a, b, c, d, e, f, g, h = H

        for t in range(0, 64):
            T_1 = (h + sigma_1(e) + ch(e, f, g) + K_rounds[t] + W[t]) & MAX_32
            T_2 = (sigma_0(a) + maj(a, b, c)) & MAX_32

            h = g
            g = f
            f = e
            e = (d + T_1) & MAX_32
            d = c
            c = b
            b = a
            a = (T_1 + T_2) & MAX_32

        H[0] = (H[0] + a) & MAX_32
        H[1] = (H[1] + b) & MAX_32
        H[2] = (H[2] + c) & MAX_32
        H[3] = (H[3] + d) & MAX_32
        H[4] = (H[4] + e) & MAX_32
        H[5] = (H[5] + f) & MAX_32
        H[6] = (H[6] + g) & MAX_32
        H[7] = (H[7] + h) & MAX_32

    return ''.join(f'{value:08x}' for value in H)

def run_tests():
    print("Starting Interoperability Tests against Python's hashlib...\n")

    test_cases = [
        (b"", "Empty string"),
        (b"abc", "Standard short string"),
        (b"a" * 55, "Edge case: 55 bytes (leaves exactly 1 byte for 0x80, needs padding)"),
        (b"a" * 56, "Edge case: 56 bytes (forces an extra block for padding)"),
        (b"a" * 64, "Edge case: 64 bytes (exact block size)"),
        (b"a" * 100000, "Large string (100,000 bytes)")
    ]

    # Static edge cases
    for data, desc in test_cases:
        my_hash = sha_256(data)
        ref_hash = hashlib.sha256(data).hexdigest()
        assert my_hash == ref_hash, f"FAIL: {desc}"
        print(f"[PASS] {desc}")

    # Randomized Fuzzing
    print("\nRunning 1,000 randomized fuzzing tests...")
    for _ in range(1000):
        length = random.randint(0, 2000)
        data = os.urandom(length)

        # Fixed typo: changed sha256 to sha_256
        my_hash = sha_256(data)
        ref_hash = hashlib.sha256(data).hexdigest()

        if my_hash != ref_hash:
            print(f"[FAIL] Interoperability broke on data of length {length}")
            print(f"Data: {data.hex()}")
            return

    print("[PASS] All 1,000 randomized tests successfully matched hashlib.sha256!")

if __name__ == "__main__":
    run_tests()