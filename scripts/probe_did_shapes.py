#!/usr/bin/env python3
"""Which crafted 32-byte encodings wrap into valid did:key:z6Mk... (48 chars)?
Determines which rejection reason each attack surfaces through the DID gate."""
import base64

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P = 2**255 - 19
L = 7237005577332262213973186563042994240857116359379907606001950938285454250989


def b58(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def did_for(pub):
    return "did:key:z" + b58(b"\xed\x01" + pub)


torsion = [
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
]

print("== torsion keys ==")
for t in torsion:
    d = did_for(t)
    ok = len(d) == len("did:key:") + 48 and d.startswith("did:key:z6Mk")
    print(f"  {t[:4].hex()}.. -> did len {len(d)-8}, z6Mk-prefix: {d[8:12] == 'z6Mk'} -> {'DID OK' if ok else 'malformed did'}")

print("\n== non-canonical y>=p keys ==")
for y in [P + 1, P + 2, P + 3, P + 5, P + 17, 2 * P - 1, (1 << 255) - 1]:
    enc = y.to_bytes(32, "little")
    d = did_for(enc)
    ok = len(d) == len("did:key:") + 48 and d.startswith("did:key:z6Mk")
    print(f"  y={hex(y)[:14]}.. -> {'DID OK (48ch z6Mk)' if ok else f'no (len {len(d)-8}, prefix {d[8:12]})'}")

print("\n== real key (control) ==")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("0b" * 32))
d = did_for(key.public_key().public_bytes_raw())
print(f"  len {len(d)-8}, prefix {d[8:12]}")

print("\n== s+L fits in 32 bytes? ==")
sig = key.sign(b"x")
s = int.from_bytes(sig[32:], "little")
print(f"  s={s.bit_length()} bits, s+L={(s+L).bit_length()} bits, fits:", (s + L) < (1 << 256))
