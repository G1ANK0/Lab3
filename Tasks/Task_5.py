import os
import random
import hashlib
import hmac
import sys

from classes.hmac import HMAC

HASH_ALGORITHMS = [
    ("sha-256",  "sha256"),
    ("sha-512",  "sha512"),
    ("sha-224",  "sha224"),
    ("sha-384",  "sha384"),
    ("sha-1",    "sha1"),
]

def key_categories(block_size: int):
    """Return one key per category: shorter, equal, longer than block_size."""
    return {
        "short": os.urandom(random.randint(1, block_size - 1)),
        "equal": os.urandom(block_size),
        "long": os.urandom(random.randint(block_size + 1, block_size * 3)),
    }


def run_tests(n_random: int = 300, seed: int = 42) -> None:
    random.seed(seed)

    passed = 0
    failed = 0
    failures = []

    # ── 1. Edge-case tests: one per (algorithm × key-category) ──────────────
    print("\n[1/2] Edge-case tests (short / equal / long key)")

    for our_name, stdlib_name in HASH_ALGORITHMS:
        block_size = hashlib.new(our_name).block_size
        keys = key_categories(block_size)

        for cat, key in keys.items():
            msg = os.urandom(random.randint(0, 256))
            our = HMAC(key, msg, our_name).digest().hex()
            ref = hmac.new(key, msg, stdlib_name).hexdigest()
            status = "PASS" if our == ref else "FAIL"
            label = f"{our_name:<10} key={cat:<6}"

            print(f"  {status}  {label}  msg_len={len(msg):>3}")

            if our == ref:
                passed += 1
            else:
                failed += 1
                failures.append((label, our, ref))

    # ── 2. Random tests ──────────────────────────────────────────────────────
    print(f"\n[2/2] Random tests ({n_random} trials)")

    for i in range(n_random):
        our_name, stdlib_name = random.choice(HASH_ALGORITHMS)
        block_size = hashlib.new(our_name).block_size
        key_len = random.randint(1, block_size * 3)
        key = os.urandom(key_len)
        msg = os.urandom(random.randint(0, 512))

        our = HMAC(key, msg, our_name).digest().hex()
        ref = hmac.new(key, msg, stdlib_name).hexdigest()

        if our == ref:
            passed += 1
        else:
            failed += 1
            failures.append((f"{our_name} key_len={key_len}", our, ref))

    # ── Summary ──────────────────────────────────────────────────────────────
    total = passed + failed
    print("\n" + "=" * 65)
    print(f"  RESULTS:  {passed}/{total} passed   {failed} failed")
    print("=" * 65)

    if failures:
        print("\nFailed cases:")
        for label, got, expected in failures[:10]:  # show at most 10
            print(f"  {label}")
            print(f"    Got:      {got}")
            print(f"    Expected: {expected}")
        sys.exit(1)
    else:
        print("\n  All tests passed")

if __name__ == "__main__":
    run_tests(n_random=1000)