# Task 4

================================================
<!-- Giovanni's Version-->

## Mini-Report: Attack Success Probability of Length-Extension Attacks on Secret-Prefix MAC

### 1. Introduction and Logical Reasoning

A secret-prefix Message Authentication Code (MAC) is usually constructed as `MAC = H(secret_key || message)`, with ht `H` relying
on hash functions built upon the Merkle-Damgård construction (such as the SHA-2 family), this specific implementation is 
vulnerable to length-extension attacks.

The length-extension attack logic relies on the ability of the attacker to take the digest (the output) of a hash 
function, use it to reconstruct the hash function's internal state (the final blocks of the has cycle), and subsequently 
feed additional data into the algorithm to generate a valid new MAC without ever needing to know the original `secret_key`.

The success probability of this attack hinges almost entirely on one factor: **whether the hash function outputs its full 
internal state or a truncated version of it.**

If the algorithm outputs is its full internal state, the attacker, knowing the exact variables needed to append
data, guaranteeing `P(success) = 1`. However, if the algorithm outputs a truncated digest, the attacker is left "blind" 
to a portion of the internal state, so the attacker must perform brute-forceing or correctly guess these missing bits to 
restore the internal state perfectly.

Therefore, the probability of successfully executing the attack is defined by the formula:

`P = 1 / 2^(Bit_starting_message - Bit_Final_digest)`

Where: 
- `Bit_starting_digest` is the internal state size (in bits) 
- `Bit_Final_digest` is the truncated output size (in bits).


### 2. Categorization and Findings

Based on the cryptographic logic above, we can categorize the requested SHA-2 algorithms into two distinct groups: 
**Full-State Hashes** and **Truncated-State Hashes**.

#### Category A: Full-State Hash Functions

In these algorithms, the final digest size is exactly equal to the internal state size. No truncation occurs, meaning the 
attacker receives all the necessary bits to resume the hash computation. The success probability is absolute.

- **SHA-256**
  - Internal State: 256 bits
  - Digest Output: 256 bits
  - **Calculus:** `1 / 2^(256 - 256) = 1 / 2^0 = 1 / 1 = 1` (100% probability) 

**SHA-512**
Internal State: 512 bits
Digest Output: 512 bits
**Calculus:** `1 / 2^(512 - 512) = 1 / 2^0 = 1 / 1 = 1` (100% probability)

#### Category B: Truncated-State Hash Functions

These algorithms intentionally drop a specific number of bits from the final internal state before returning the digest. 
For an attacker to perform a length-extension attack, they must accurately guess the dropped bits to correctly restore 
the Merkle-Damgård state. The success probability drops exponentially based on the number of missing bits.

- **SHA-224**
    - Internal State: 256 bits (utilizes the SHA-256 core)
    - Digest Output: 224 bits
    - Missing Bits to Guess: 32
    - **Calculus:** `1 / 2^(256 - 224) = 1 / 2^32` (approx. `2.32 × 10^-10` probability)


- **SHA-384**
  - Internal State: 512 bits (utilizes the SHA-512 core)\n
  - Digest Output: 384 bits\n
  - Missing Bits to Guess: 128\n
  - **Calculus:** `1 / 2^(512 - 384) = 1 / 2^128 = ` (approx. `2.39 × 10^-39` probability)


- **SHA-512/256**
  - Internal State: 512 bits (utilizes the SHA-512 core)
  - Digest Output: 256 bits
  - Missing Bits to Guess: 256
  - **Calculus:** `1 / 2^(512 - 256) = 1 / 2^256 = ` (approx. `8.36 × 10^-79` probability)


- **SHA-512/224**
  - Internal State: 512 bits (utilizes the SHA-512 core)
  - Digest Output: 224 bits
  - Missing Bits to Guess: 288
  - **Calculus:** `1 / 2^(512 - 224) = 1 / 2^288 =` (approx. `2.01 × 10^-87` probability)


### 3. Conclusion

Using truncated variants of the SHA-2 family (like SHA-384 or SHA-512/256) effectively reduces length-extension attacks
in practical scenarios, as the probability of guessing the missing state bits (`1 / 2^128` and lower) is computationally 
infeasible, we would've need much time. 
Conversely, full-state variants (SHA-256, SHA-512) are trivially broken when used in a naive `MAC = H(k||m)` 
construction. SHA-224 while not being computationally trivial, successfully guessing 32 bits (`1 / 2^32` probability) 
requires much less cycles than the bigger truncated versions, making it highly exploitable with nowadays technology.

#================================================



#================================================
<!-- Denis's Version-->



#================================================