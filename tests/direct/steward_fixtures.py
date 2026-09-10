"""Steward security fixtures — crafted Ed25519 attack material, shared by the
adversarial test suite and the parity corpus generator.

Every crafted value here is DERIVED, not copy-pasted from literature:
  * torsion encodings come from scripts/derive_torsion.py (verified subgroup)
  * non-canonical encodings are computed from p / L
  * real signatures come from the `cryptography` package
Nothing is asserted by fiat; the tests prove behavior of the real contract.
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

P = 2**255 - 19
L = 7237005577332262213973186563042994240857116359379907606001950938285454250989

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED_PREFIX = b"\xed\x01"

# The full 8-torsion (verified by scripts/derive_torsion.py; matches the
# contract constant _SMALL_ORDER_ENC and the browser SMALL_ORDER_ENC_HEX).
TORSION_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
)
IDENTITY_ENC = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
ORDER2_ENC = bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
ORDER8_ENC = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
ORDER4_ENC = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
ZERO_SCALAR = bytes(32)


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def did_for_pub(pub32: bytes) -> str:
    return "did:key:z" + b58(ED_PREFIX + pub32)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def new_key(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def sign_canonical(key: Ed25519PrivateKey, room: str, nonce: str, text: str) -> str:
    return b64url(key.sign(f"{room}|{nonce}|{text}".encode()))


def malleate_s_plus_l(sig_b64: str) -> str:
    """s := s + L on a REAL signature (malleability probe)."""
    raw = base64.urlsafe_b64decode(sig_b64 + "==")
    s = int.from_bytes(raw[32:], "little")
    return b64url(raw[:32] + (s + L).to_bytes(32, "little"))


def noncanon_point(y: int) -> bytes:
    """Compressed encoding with a y >= p (non-canonical field element)."""
    return y.to_bytes(32, "little")


def steward_attack_record(room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """The Steward's exact crafted record: identity-point key, identity R,
    zero scalar. Classifies INVALID_SIGNATURE / 'small-order public key'."""
    sig = IDENTITY_ENC + ZERO_SCALAR
    return {
        "sequence": seq,
        "senderDid": did_for_pub(IDENTITY_ENC),
        "nonce": nonce,
        "signature": b64url(sig),
        "text": text,
    }


def small_order_key_record(enc_hex: str, room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """Record whose DID wraps a torsion point key (R = identity, s = 0)."""
    A = bytes.fromhex(enc_hex)
    return {
        "sequence": seq,
        "senderDid": did_for_pub(A),
        "nonce": nonce,
        "signature": b64url(IDENTITY_ENC + ZERO_SCALAR),
        "text": text,
    }


def small_order_r_record(key: Ed25519PrivateKey, enc_hex: str, room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """Real key A, torsion R (from enc_hex), s = 0."""
    R = bytes.fromhex(enc_hex)
    pub = key.public_key().public_bytes_raw()
    return {
        "sequence": seq,
        "senderDid": did_for_pub(pub),
        "nonce": nonce,
        "signature": b64url(R + ZERO_SCALAR),
        "text": text,
    }


def noncanon_a_record(y: int, room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """DID wrapping a y >= p encoding (same point as identity here)."""
    enc = noncanon_point(y)
    return {
        "sequence": seq,
        "senderDid": did_for_pub(enc),
        "nonce": nonce,
        "signature": b64url(IDENTITY_ENC + ZERO_SCALAR),
        "text": text,
    }


def noncanon_r_record(key: Ed25519PrivateKey, y: int, room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """Real key A, R with y >= p encoding, s = 0."""
    enc = noncanon_point(y)
    pub = key.public_key().public_bytes_raw()
    return {
        "sequence": seq,
        "senderDid": did_for_pub(pub),
        "nonce": nonce,
        "signature": b64url(enc + ZERO_SCALAR),
        "text": text,
    }


def zero_scalar_record(key: Ed25519PrivateKey, room: str, seq: int, text: str, nonce: str = "1") -> dict:
    """Real key A, R = identity (small-order, rejected first), s = 0."""
    pub = key.public_key().public_bytes_raw()
    return {
        "sequence": seq,
        "senderDid": did_for_pub(pub),
        "nonce": nonce,
        "signature": b64url(IDENTITY_ENC + ZERO_SCALAR),
        "text": text,
    }


def real_record(key: Ed25519PrivateKey, room: str, seq: int, text: str, nonce: str) -> dict:
    """A genuine, correctly signed record."""
    return {
        "sequence": seq,
        "senderDid": did_for_pub(key.public_key().public_bytes_raw()),
        "nonce": nonce,
        "signature": sign_canonical(key, room, nonce, text),
        "text": text,
    }


def unsigned_rec(seq: int, sender: str, text: str) -> dict:
    return {"sequence": seq, "senderDid": sender, "nonce": "", "signature": "", "text": text}


def records_json(records) -> str:
    return json.dumps(records)


OFFER_TEXT = (
    "I need data normalization for the sales CSV. Output must be JSON. "
    "Maximum latency 30 seconds. Price is 5 credits."
)
ACCEPT_TEXT = "Accepted. I will normalize the sales CSV to JSON within 30 seconds for 5 credits."
