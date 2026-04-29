import struct
import os
import hashlib
import random

# =====================================================================
# 1. SHA-256 Constants (FIPS 180-4, Section 4.2.2)
# =====================================================================
# The first 32 bits of the fractional parts of the cube roots of the first 64 primes.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# The first 32 bits of the fractional parts of the square roots of the first 8 primes.
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# =====================================================================
# 2. Logical Functions (FIPS 180-4, Section 4.1.2)
# =====================================================================
# Python handles arbitrarily large integers, so we must mask with
# 0xFFFFFFFF to simulate 32-bit unsigned integer wrapping.
MAX_32 = 0xFFFFFFFF


def rotr(x, n):
    """Right rotate (circular right shift)"""
    return ((x >> n) | (x << (32 - n))) & MAX_32


def shr(x, n):
    """Right shift"""
    return (x >> n) & MAX_32


def ch(x, y, z):
    """Choose"""
    return (x & y) ^ (~x & z) & MAX_32


def maj(x, y, z):
    """Majority"""
    return (x & y) ^ (x & z) ^ (y & z)


def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


# =====================================================================
# 3. Main SHA-256 Algorithm
# =====================================================================
def sha256(message: bytes) -> str:
    """Returns the SHA-256 hash of the input bytes as a hex string."""

    # --- Step 1: Preprocessing (Padding) ---
    # Append '1' bit (0x80 in bytes), then pad with '0's until length in bits
    # is congruent to 448 mod 512 (which is 56 bytes mod 64 bytes).
    original_bit_len = len(message) * 8
    message += b'\x80'

    while len(message) % 64 != 56:
        message += b'\x00'

    # Append the original length as a 64-bit big-endian integer.
    message += struct.pack('>Q', original_bit_len)

    # Initialize working variables to current hash values
    H = H_INIT.copy()

    # --- Step 2: Process the message in 512-bit (64-byte) blocks ---
    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]

        # 1. Prepare the message schedule, W
        # Unpack 64 bytes into 16 32-bit big-endian words
        W = list(struct.unpack('>16I', chunk)) + [0] * 48

        for t in range(16, 64):
            W[t] = (sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) & MAX_32

        # 2. Initialize the eight working variables with the (i-1)-st hash value
        a, b, c, d, e, f, g, h = H

        # 3. Apply the 64 compression rounds
        for t in range(64):
            T1 = (h + Sigma1(e) + ch(e, f, g) + K[t] + W[t]) & MAX_32
            T2 = (Sigma0(a) + maj(a, b, c)) & MAX_32

            h = g
            g = f
            f = e
            e = (d + T1) & MAX_32
            d = c
            c = b
            b = a
            a = (T1 + T2) & MAX_32

        # 4. Compute the i-th intermediate hash value
        H[0] = (H[0] + a) & MAX_32
        H[1] = (H[1] + b) & MAX_32
        H[2] = (H[2] + c) & MAX_32
        H[3] = (H[3] + d) & MAX_32
        H[4] = (H[4] + e) & MAX_32
        H[5] = (H[5] + f) & MAX_32
        H[6] = (H[6] + g) & MAX_32
        H[7] = (H[7] + h) & MAX_32

    # --- Step 3: Final Output ---
    # Concatenate the final hash values as a hex string
    return ''.join(f'{value:08x}' for value in H)


# =====================================================================
# 4. Randomized Interoperability Tests
# =====================================================================
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
        my_hash = sha256(data)
        ref_hash = hashlib.sha256(data).hexdigest()
        assert my_hash == ref_hash, f"FAIL: {desc}"
        print(f"[PASS] {desc}")

    # Randomized Fuzzing
    print("\nRunning 1,000 randomized fuzzing tests...")
    for _ in range(1000):
        # Generate random length between 0 and 2000 bytes
        length = random.randint(0, 2000)
        data = os.urandom(length)

        my_hash = sha256(data)
        ref_hash = hashlib.sha256(data).hexdigest()

        if my_hash != ref_hash:
            print(f"[FAIL] Interoperability broke on data of length {length}")
            print(f"Data: {data.hex()}")
            return

    print("[PASS] All 1,000 randomized tests successfully matched hashlib.sha256!")


if __name__ == "__main__":
    run_tests()