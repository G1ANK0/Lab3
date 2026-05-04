# Task 4

================================================
<!-- Giovanni's Version-->



#================================================



#================================================
<!-- Denis' Version-->

**SHA-2 family** algorithms by construction(Merkle-Damgård) are vulnerable to length-extension attacks. 
However, many of them, such as *SHA-224*, *SHA-384*, *SHA-512/224* and *SHA-512/256*, are not vulnerable to length-extension attacks 
because their output is the internal state, as for *SHA-256* and *SHA-512*, but is truncated.
In other words, the attacker is possible in the case of **SHA-256** and **SHA-512** with probability 1 even if the attacker doesn't know the key length 
but can guess it with a brute force approach choosing as internal state of the hash algorithm the result itself allows forging a valid tag without knowing the key.
On the other hand, talking about **SHA-224**, **SHA-384**, **SHA-512/224** and **SHA-512/256**, attacker cannot forge a valid tag and then succeeding with the attack with probability 1. This is
because he doesn't know the entire internal state but only a truncated version of it, so the attacker must guess the truncated blocks requiring a lot of time leading the probability
to succeeding with the attack to almost 0 (respectively $2^{-32}$, $2^{-128}$, $2^{-288}$ and $2^{-256}$). In addition, as for *SHA-256* and *SHA-512*, the attacker must guess the key length.

Obviously, larger is the key, more time is needed to guess the key length with brute force.



#================================================