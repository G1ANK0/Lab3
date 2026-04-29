import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Task_1')))


from Task_1 import sha256

def spmac(k: bytearray, u: bytearray) -> str:
    message_to_hash = bytearray(k)
    message_to_hash.extend(u)

    return sha256(message_to_hash)

def tests():
    with open("lab3vectors\lab3task2.json", "r") as f:
        data = json.load(f)

    count = 0

    for test in data:
        key = bytearray()
        msg = bytearray()
        
        number = test['number']
        key_hex = test['key']
        msg_hex = test['msg']
        tag_hex = test['tag']
        
        print(f"--- TEST: {number} ---")
        print(f"Key (hex): {key_hex}")
        print(f"Msg (hex): {msg_hex}")
        print(f"Expected Tag (hex): {tag_hex}\n")

        key = bytearray.fromhex(key_hex)
        msg = bytearray.fromhex(msg_hex)

        result = spmac(key, msg)

        if result == tag_hex:
            print("Test: ", number, " passed\n")
        else:
            print("Test failed\n")


if __name__ == "__main__":
    tests()