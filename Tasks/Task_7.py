from ecdsa import NIST256p, SigningKey, BadSignatureError
import hashlib
import requests

msg = b"MD5 2026-05-04"

sig_fermat = "1b687e1c62e5d5790d2f8b002b7623b76bd3179bf7b875dbcdc7c23e48921a67b67833e591f90d80a940989a4c60b765797cb335b2ff928e13c83059985a21e5"
sig_cauchy = "1b687e1c62e5d5790d2f8b002b7623b76bd3179bf7b875dbcdc7c23e48921a67b9eb744bcfb22f8ec0395a378f431eda42d4c70d565fc7e0a482af06925f1fea"

r_fermat = sig_fermat[:64] 
s_fermat=  sig_fermat[64:]
r_cauchy = sig_cauchy[:64]
s_cauchy=  sig_cauchy[64:]


z1 = int(hashlib.sha256(b"Fermat 1918-10-27").hexdigest(), 16)
z2 = int(hashlib.sha256(b"Cauchy 1656-12-14").hexdigest(), 16)

# To craft the new signature, we need to find the private key d. When r is the same we obtain (for math see report):
# d = r^-1 (z_1s_2 - z_2s_1)/(s_1 - s_2) mod n, where z_1 and z_2 are the hashes of the messages, s_1 and s_2 are the signatures.

n = NIST256p.order

assert r_cauchy == r_fermat, "The nonce r is not reused"
r = int(r_fermat, 16)
s1 = int(s_fermat, 16)
s2 = int(s_cauchy,16)

k = (z1 - z2) * pow(s1 - s2, -1, n) % n 
d = pow(r, -1, n) * (s1 * k - z1)  % n

print(d)

sk = SigningKey.from_secret_exponent(d, NIST256p)

signature = sk.sign(msg, hashfunc=hashlib.sha256 )

r_new = signature[:32]
s_new = signature[32:]

vk = sk.get_verifying_key()

try:
    vk.verify(signature, msg, hashfunc=hashlib.sha256)
    print("Signature is valid.")
except BadSignatureError:
    print("Signature is invalid.")
    exit(1)


print(r_new, s_new)

payload = {
    "msg": msg.decode(),
    "sig-r": r_new.hex(),
    "sig-s": s_new.hex()
}

response = requests.post("https://interrato.dev/infosec/badecdsa", data=payload)

print(response.text)