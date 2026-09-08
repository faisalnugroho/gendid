// test-parity.mjs — Node tests for the gendid browser lib.
// Verifies (1) DID kit mirrors official sign.py, (2) canonical JSON byte-parity
// with the contract's Python canonicalization, (3) JS verification accepts
// Python-signed records and rejects tampering, (4) evidence hash parity.
//
// Run: node tests/js/test-parity.mjs
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const require = createRequire(import.meta.url);
globalThis.window = globalThis;
// node 22 already provides global crypto (webcrypto); nothing to shim.
if (typeof btoa === "undefined") {
  globalThis.btoa = (s) => Buffer.from(s, "binary").toString("base64");
  globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
}
const LIB_DIR = new URL("../../frontend/lib/", import.meta.url).pathname;
// browser build expects a global `nacl` (script tag); in node, wire it manually
globalThis.nacl = require(join(LIB_DIR, "tweetnacl.min.js"));
require(join(LIB_DIR, "gendid-lib.js"));
const GD = globalThis.window.GD;

let passed = 0;
let failed = 0;
function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${extra ? " — " + extra : ""}`);
  }
}

// ---------------------------------------------------------------- parity tooling
// A tiny Python helper that uses the contract's OWN code (imported from the
// contract file) to sign/classify/hash — guaranteeing we test against the real
// implementation, not a re-implementation.
const CONTRACT = new URL("../../contracts/gendid_judge.py", import.meta.url).pathname;
const PY = "/usr/bin/python3";

function pyRunner(code, payload) {
  const dir = mkdtempSync(join(tmpdir(), "gendid-parity-"));
  const script = join(dir, "run.py");
  if (payload !== undefined) {
    writeFileSync(join(dir, "payload.json"), JSON.stringify(payload));
    code = "import json as _pj\n_payload = _pj.load(open(" + JSON.stringify(join(dir, "payload.json")) + "))\n" + code;
  }
  writeFileSync(script, code);
  const out = execFileSync(PY, [script], { encoding: "utf8", timeout: 60_000 });
  return JSON.parse(out);
}

const pyPrelude = `
import json, sys, types, base64
# Stub genlayer with an iterable __all__ so 'from genlayer import *' works
# outside the GenVM. Only the names the pure functions touch are needed.
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
    message_raw={"datetime": "2026-09-08T00:00:00Z"},
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
src = open(${JSON.stringify(CONTRACT)}).read()
mod = types.ModuleType("gendid")
mod.__dict__["__name__"] = "gendid"
exec(compile(src, "gendid_judge.py", "exec"), mod.__dict__)
G = mod

def _py_did_of(key):
    pub = key.public_key().public_bytes_raw()
    n = int.from_bytes(b"\\xed\\x01" + pub, "big")
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "did:key:z" + out
`;

// ---------------------------------------------------------------- T1 DID parity
console.log("T1  DID kit parity with contract/official sign.py");
{
  const seedHex = "a".repeat(64);
  const r = pyRunner(`${pyPrelude}
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("${seedHex}"))
did = _py_did_of(key)
sig = base64.urlsafe_b64encode(key.sign(b"probe")).decode().rstrip("=")
print(json.dumps({"did": did, "sig": sig}))
`);
  const jsId = GD.identityFromSeed(seedHex);
  check("JS did:key === Python did:key", jsId.did === r.did, `${jsId.did} vs ${r.did}`);
}

// ---------------------------------------------------------------- T2 sign/verify parity
console.log("T2  JS signature == Python signature over canonical string");
{
  const seedHex = "b".repeat(64);
  const room = "gendid-demo-01";
  const nonce = "1757318042512";
  const text = "I need data normalization. Output must be JSON. Price is 5 credits.";
  const r2 = pyRunner(`${pyPrelude}
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("${seedHex}"))
did = _py_did_of(key)
swept = G.tc_sweep(_payload)
msg = f"${room}|${nonce}|{swept}"
sig = base64.urlsafe_b64encode(key.sign(msg.encode())).decode().rstrip("=")
print(json.dumps({"did": did, "sig": sig, "swept": swept}))
`, text);
  const jsId = GD.identityFromSeed(seedHex);
  const jsSig = GD.signSay(jsId, room, nonce, text);
  check("JS sig === Python sig over <room>|<nonce>|<swept>", jsSig === r2.sig, `${jsSig} vs ${r2.sig}`);
  check("JS swept === Python swept", GD.swept(text) === r2.swept);

  // verify on the JS side
  const cls = GD.verifyRecord(room, {
    sequence: 1,
    timestamp: "2026-09-08T07:14:02.512Z",
    senderDid: r2.did,
    nonce,
    signature: jsSig,
    text,
  });
  check("JS verify accepts Python-signed record", cls.signatureStatus === "AUTHENTIC_SIGNED", cls.signatureStatus + " " + (cls.reject || ""));

  // tampered
  const clsBad = GD.verifyRecord(room, {
    sequence: 1, senderDid: r2.did, nonce, signature: jsSig, text: text + " and pay 100 more",
  });
  check("JS verify rejects tampered text", clsBad.signatureStatus === "INVALID_SIGNATURE");

  // wrong room binding
  const clsRoom = GD.verifyRecord("gendid-other", {
    sequence: 1, senderDid: r2.did, nonce, signature: jsSig, text,
  });
  check("JS verify rejects wrong-room signature", clsRoom.signatureStatus === "INVALID_SIGNATURE");
}

// ---------------------------------------------------------------- T3 canonical JSON parity
console.log("T3  canonicalJson byte-parity with contract's _canonical_json");
{
  const samples = [
    { b: 1, a: "hello", c: [3, 1, 2] },
    { z: "ünïcödé", y: null, x: true },
    { deep: { arr: [{ k: "v" }, {}] }, n: -5 },
    { quote: 'he said "hi" \\ back', nl: "a\nb\tc" },
    { big: 9007199254740991, zero: 0 },
  ];
  const py = pyRunner(`${pyPrelude}
print(json.dumps([G._canonical_json(s) for s in _payload]))
`, samples);
  const js = samples.map((s) => GD.canonicalJson(s));
  for (let i = 0; i < samples.length; i++) {
    check(`canonicalJson sample ${i + 1}`, js[i] === py[i], `${js[i]} vs ${py[i]}`);
  }
}

// ---------------------------------------------------------------- T4 evidence hash parity
console.log("T4  evidenceHash parity (JS sha256Hex == contract _evidence_hash)");
{
  const room = "gendid-demo-01";
  const seedA = "c".repeat(64);
  const seedB = "d".repeat(64);
  const idA = GD.identityFromSeed(seedA);
  const idB = GD.identityFromSeed(seedB);
  const recs = [
    {
      recordId: "gdr-gendid-demo-01-1", room, sequence: 1,
      timestamp: "2026-09-08T07:14:02.512Z", senderDid: idA.did,
      nonce: "1757318042512", signature: GD.signSay(idA, room, "1757318042512", "Task: normalize CSV. Output JSON. Price 5 credits."),
      text: "Task: normalize CSV. Output JSON. Price 5 credits.",
    },
    {
      recordId: "gdr-gendid-demo-01-2", room, sequence: 2,
      timestamp: "2026-09-08T07:14:09.100Z", senderDid: idB.did,
      nonce: "1757318049100", signature: GD.signSay(idB, room, "1757318049100", "Accepted."),
      text: "Accepted.",
    },
  ];
  const jsPkg = await GD.buildEvidencePackage(room, recs);

  const r = pyRunner(`${pyPrelude}
room = _payload["room"]
cls = G._classify_records(room, _payload["records"])
package = {"protocolVersion": "gendid/1", "transcriptRoom": room, "records": cls["records"]}
eh = G._evidence_hash(package)
agreement = "GD-" + room[:24] + "-" + eh[:16]
print(json.dumps({"hash": eh, "agreement": agreement, "counts": cls["counts"], "participants": cls["participants"]}))
`, { room, records: recs.map(({ recordId, ...rest }) => rest) });
  check("evidenceHash JS == Python", jsPkg.evidenceHash === r.hash, `${jsPkg.evidenceHash} vs ${r.hash}`);
  check("agreementId JS == Python", jsPkg.agreementId === r.agreement, `${jsPkg.agreementId} vs ${r.agreement}`);
  check("counts parity AUTHENTIC=2", jsPkg.counts.AUTHENTIC_SIGNED === 2 && r.counts.AUTHENTIC_SIGNED === 2);
  check("participants parity", JSON.stringify(jsPkg.participants) === JSON.stringify(r.participants));
}

// ---------------------------------------------------------------- T5 sweep parity
console.log("T5  sweep parity incl. control chars");
{
  const cases = [
    "plain text",
    "trailing spaces   ",
    "\u00a0nbsp\u00a0",
    "zero\u200bwidth joiner",
    "tab\tand\u0000nul",
    "  trim me  ",
  ];
  const py = pyRunner(`${pyPrelude}
print(json.dumps([G.tc_sweep(c) for c in _payload]))
`, cases);
  cases.forEach((c, i) => {
    check(`sweep "${c.slice(0, 14)}"`, GD.swept(c) === py[i], JSON.stringify(GD.swept(c)) + " vs " + JSON.stringify(py[i]));
  });
}

// ---------------------------------------------------------------- T6 tclk tag
console.log("T6  tclk frame tag (display-only)");
{
  check("offer frame tagged", GD.tclkTag('tclk1 {"type":"offer","from":"did:key:z6Mkx"}') === "offer");
  check("plain text untagged", GD.tclkTag("Accepted.") === "");
  check("bad json untagged", GD.tclkTag("tclk1 {oops") === "");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
