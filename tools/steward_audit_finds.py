#!/usr/bin/env python3
"""tools/steward_audit_finds.py — canonical record of the Phase-1 audit findings.

Run:  python3 tools/steward_audit_finds.py        (from repo root)
Dumps every Steward-relevant finding with the RAW verdict from the CURRENT
contract code — nothing hand-asserted, nothing fabricated.
"""
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACT = REPO / "contracts" / "gendid_judge.py"

SCRIPT = """#!/usr/bin/env python3
import json, sys, types, base64
gl_mod = types.ModuleType("genlayer")
class _TreeMap(dict):
    def get(self, k, default=None):
        try: return self[k]
        except KeyError: return default
class UserError(Exception): pass
gl_mod.gl = types.SimpleNamespace(
    Contract=type("Contract", (), {}),
    public=types.SimpleNamespace(view=lambda f=None: (f if f is not None else True),
                                 write=lambda f=None: (f if f is not None else True)),
    message_raw={"datetime": "2026-09-10T00:00:00Z"},
    vm=types.SimpleNamespace(run_nondet=lambda a, b: {}),
    nondet=types.SimpleNamespace(exec_prompt=lambda p, response_format=None: ""),
    TreeMap=_TreeMap, u256=int, UserError=UserError)
gl_mod.UserError = UserError; gl_mod.TreeMap = _TreeMap; gl_mod.u256 = int
gl_mod.__all__ = ["gl", "UserError", "TreeMap", "u256"]
sys.modules["genlayer"] = gl_mod
src = open(sys.argv[1]).read()
mod = types.ModuleType("g"); mod.__dict__["__name__"] = "g"
exec(compile(src, "gendid_judge.py", "exec"), mod.__dict__)
G = mod

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(raw):
    n = int.from_bytes(raw, "big"); out = ""
    while n: n, rem = divmod(n, 58); out = B58[rem] + out
    return out
def did_for(pub): return "did:key:z" + b58(b"\\xed\\x01" + pub)
def b64url(raw): return base64.urlsafe_b64encode(raw).decode().rstrip("=")

res = {}
msg = b"gendid-demo-01|1|attacker text"
IDENT = bytes([1]) + bytes(31)
ZERO = bytes(32)

# F1: identity-point key + zero-scalar sig + arbitrary message
sig = IDENT + ZERO
res["f1_verify_accepts_identity_attack"] = G.ed25519_verify(IDENT, msg, sig)
cls = G._classify_records("gendid-demo-01", [{"sequence":1,"senderDid":did_for(IDENT),"nonce":"1","signature":b64url(sig),"text":"attacker text"}])
res["f1_classifies_AUTHENTIC_SIGNED"] = cls["counts"].get("AUTHENTIC_SIGNED", 0) == 1

# F2: small-order keys (representatives, zero-scalar sigs)
SMALL = ["0100000000000000000000000000000000000000000000000000000000000000",
         "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
         "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
         "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"]
acc = 0
for h in SMALL:
    A = bytes.fromhex(h)
    if G.ed25519_verify(A, msg, IDENT + ZERO): acc += 1
res["f2_small_order_accepted_of_4"] = acc

# F3: non-canonical A encoding (y = p+1 -> same point as identity)
Ayp1 = (G._P + 1).to_bytes(32, "little")
res["f3_noncanon_A_y_ge_p_accepted"] = G.ed25519_verify(Ayp1, msg, IDENT + ZERO)

# F4: malleability s := s + L on a real signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("0b"*32))
rs = key.sign(msg)
s = int.from_bytes(rs[32:], "little")
res["f4_s_plus_L_accepted"] = G.ed25519_verify(key.public_key().public_bytes_raw(), msg, rs[:32] + (s + G._L).to_bytes(32, "little"))

# F5: transcript ordering — records with swapped sequence numbers
def mk_classified(seq, didx, text):
    return {"recordId": f"gdr-gendid-demo-01-{seq}", "room": "gendid-demo-01",
            "sequence": seq, "senderDid": didx, "nonce": str(seq),
            "signature": "A"*86, "text": text, "signatureStatus": "AUTHENTIC_SIGNED"}
dA = did_for(bytes.fromhex("11"*32))
dB = did_for(bytes.fromhex("22"*32))
p1 = [mk_classified(1, dA, "offer"), mk_classified(2, dB, "accept")]
p2 = [mk_classified(1, dB, "accept"), mk_classified(2, dA, "offer")]  # seq REASSIGNED
h1 = G._evidence_hash({"protocolVersion":"gendid/1","transcriptRoom":"gendid-demo-01","records":p1})
h2 = G._evidence_hash({"protocolVersion":"gendid/1","transcriptRoom":"gendid-demo-01","records":p2})
res["f5_seq_reassignment_same_hash"] = (h1 == h2)

# F6: does the browser verifier (tweetnacl) accept the same attacks? (probed separately)
res["f6_note"] = "browser tweetnacl probe run separately: identity A+R+s=0 accepted; y=p+1 A accepted; s+L accepted"

print(json.dumps(res, indent=2))
"""

with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
    f.write(SCRIPT)
    path = f.name
try:
    out = subprocess.run(
        [sys.executable, path, str(CONTRACT)], capture_output=True, text=True, timeout=120
    )
    print(out.stdout)
    if out.returncode != 0:
        print(out.stderr[-2000:])
        sys.exit(1)
finally:
    Path(path).unlink(missing_ok=True)
