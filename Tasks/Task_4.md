# Task 4

================================================
<!-- Giovanni's Version-->

## Mini-Report: Attack Success Probability of Length-Extension Attacks on Secret-Prefix MAC

### 1. Introduction and Logical Reasoning

A secret-prefix Message Authentication Code (MAC) is usually constructed as `MAC = H(secret_key || message)`, with `H` relying
on hash functions built upon the Merkle-Damgård construction (such as the SHA-2 family), this specific implementation is 
vulnerable to length-extension attacks.

The length-extension attack logic relies on the ability of the attacker to take the digest (the output) of a hash 
function, use it to reconstruct the hash function's internal state (the final blocks of the has cycle), and subsequently 
feed additional data into the algorithm to generate a valid new MAC without ever needing to know the original `secret_key`.

The success probability of this attack hinges almost entirely on one factor: **whether the hash function outputs its full 
internal state or a truncated version of it.**

If the algorithm outputs is its full internal state, the attacker, knowing the exact variables needed to append
data, guarantees `P(success) = 1` but, if the algorithm outputs a truncated digest, the attacker must perform brute-forcing 
or correctly guess these missing bits to recreate the full internal state.

Therefore, the probability of successfully executing the attack is defined by the formula:

`P = 1 / 2^(Missing Bits to Guess)`

Where **Missing Bits to Guess** is the difference between:
  - `Bit_starting_digest` is the internal state size (in bits) 
  - `Bit_Final_digest` is the truncated output size (in bits).


### 2. Categorization and Findings

Based on the logic above, we can categorize the SHA-2 algorithms into two groups: 
**Full-State Hashes** and **Truncated-State Hashes**.

#### 2.1 Full-State Hash Functions

In these algorithms, the final digest size is exactly equal to the internal state size. No truncation occurs, meaning the 
attacker receives all the necessary bits to resume the hash computation. The success probability is absolute.

| Algorithm   | Internal State | Digest Output | **P(Success)**                            |
|-------------|----------------|---------------|-------------------------------------------|
| **SHA-256** | 256            | 256           | `1 / 2^(256 - 256) = 1 / 2^0 = 1 / 1 = 1` |
| **SHA-512** | 512            | 512           | `1 / 2^(512 - 512) = 1 / 2^0 = 1 / 1 = 1` |                                         |


#### 2.2 Truncated-State Hash Functions

These algorithms intentionally drop a specific number of bits from the final internal state before returning the digest. 
For an attacker to perform a length-extension attack, they must accurately guess the dropped bits to correctly restore 
the Merkle-Damgård state. The success probability drops exponentially based on the number of missing bits.

| Algorithm       | Internal State (Bits) | Digest Output (Bits) | Missing Bits to Guess | P(Success)                                                  |
|-----------------|-----------------------|----------------------|-----------------------|-------------------------------------------------------------|
| **SHA-224**     | 256                   | 224                  | 32                    | `1 / 2^(Missing Bits to Guess) = 1 / 2^32 = 2.32 × 10^-10`  |
| **SHA-384**     | 512                   | 384                  | 128                   | `1 / 2^(Missing Bits to Guess) = 1 / 2^128 = 2.39 × 10^-39` |
| **SHA-512/256** | 512                   | 256                  | 256                   | `1 / 2^(Missing Bits to Guess) = 1 / 2^256 = 8.36 × 10^-79` |
| **SHA-512/224** | 512                   | 224                  | 288                   | `1 / 2^(Missing Bits to Guess) = 1 / 2^288 = 2.01 × 10^-87` |

### 3. Conclusion

Using truncated variants of the SHA-2 family (like SHA-384 or SHA-512/256) effectively reduces length-extension attacks
in practical scenarios, as the probability of guessing the missing state bits (`1 / 2^128` and lower) is computationally 
infeasible, we would've need much time. 
In contrary, full-state variants (SHA-256, SHA-512) are totally broken, when we use them in a really simple Hashing style 
like `MAC = H(k||m)` construction. SHA-224 while not being computationally trivial, successfully guessing 32 bits 
(`1 / 2^32` probability) requires much less cycles than the bigger truncated versions, making it less secure with nowadays
technology.

#================================================



#================================================
<!-- Denis's Version-->

**SHA-2 family** algorithms by construction(Merkle-Damgård) are vulnerable to length-extension attacks. 
However, many of them, such as *SHA-224*, *SHA-384*, *SHA-512/224* and *SHA-512/256*, are not vulnerable to length-extension attacks 
because their output is the internal state, as for *SHA-256* and *SHA-512*, but is truncated.
In other words, the attacker is possible in the case of **SHA-256** and **SHA-512** with probability 1 even if the attacker doesn't know the key length 
but can guess it with a brute force approach choosing as internal state of the hash algorithm the result itself allows forging a valid tag without knowing the key.
On the other hand, talking about **SHA-224**, **SHA-384**, **SHA-512/224** and **SHA-512/256**, attacker cannot forge a valid tag and then succeeding with the attack with probability 1. This is
because he doesn't know the entire internal state but only a truncated version of it, so the attacker must guess the truncated blocks requiring a lot of time leading the probability
to succeeding with the attack to almost 0 (more precisely $2^{-32}$, $2^{-128}$, $2^{-288}$ and $2^{-256}$, respectively). In addition, as for *SHA-256* and *SHA-512*, the attacker must guess the key length.

Obviously, larger is the key, more time is needed to guess the key length with brute force.

#================================================