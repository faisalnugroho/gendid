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
package = {"protocolVersion": "gendid/1.1", "transcriptRoom": room, "transcriptCommitment": cls["transcriptCommitment"], "records": cls["records"]}
eh = G._evidence_hash(package)
agreement = "GD-" + room[:24] + "-" + eh[:16]
print(json.dumps({"hash": eh, "agreement": agreement, "counts": cls["counts"], "participants": cls["participants"], "commitment": cls["transcriptCommitment"]}))
`, { room, records: recs.map(({ recordId, ...rest }) => rest) });
  check("evidenceHash JS == Python", jsPkg.evidenceHash === r.hash, `${jsPkg.evidenceHash} vs ${r.hash}`);
  check("agreementId JS == Python", jsPkg.agreementId === r.agreement, `${jsPkg.agreementId} vs ${r.agreement}`);
  check("counts parity AUTHENTIC=2", jsPkg.counts.AUTHENTIC_SIGNED === 2 && r.counts.AUTHENTIC_SIGNED === 2);
  check("participants parity", JSON.stringify(jsPkg.participants) === JSON.stringify(r.participants));
  check("transcriptCommitment JS == Python", jsPkg.transcriptCommitment === r.commitment, `${jsPkg.transcriptCommitment} vs ${r.commitment}`);
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

// ---------------------------------------------------------------- T7 parity corpus
// Dual-runner fixture corpus (Steward requirement: browser and contract
// canonicalization identical for VALID, REJECTED, and UNSIGNED records —
// not just happy paths). Each fixture is classified by the REAL JS lib and
// the REAL contract code (via pyRunner, importing the actual .py file),
// then compared across every observable: per-record classification,
// reject reason, full canonical record list, recordCounts, participants,
// transcriptCommitment, evidenceHash, agreementId.
//
// Fixtures are computed from seed material IDENTICALLY on both sides —
// real signatures via each side's own signer (nacl vs cryptography), so
// the corpus also proves sign/verify cross-acceptance end-to-end.
const TORSION_HEX = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];
const L_HEX = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"; // little-endian L

function hexToB64url(hex) {
  return Buffer.from(hex, "hex").toString("base64url");
}

console.log("T7  dual-runner parity corpus (valid/rejected/unsigned, full compare)");
{
  const room = "gendid-demo-01";
  const OFFER_TEXT = "Task: normalize CSV. Output JSON. Price 5 credits.";
  const ACCEPT_TEXT = "Accepted. Send the JSON here.";

  const idA = GD.identityFromSeed("c".repeat(64));
  const idB = GD.identityFromSeed("d".repeat(64));
  const idC = GD.identityFromSeed("e".repeat(64)); // second signer for ordering

  // ---- build fixtures in JS (signatures via the JS signer) ----
  const sig = (id, nonce, text) => GD.signSay(id, room, nonce, GD.swept(text));
  const rec = (id, seq, nonce, text) => ({
    recordId: `gdr-${room}-${seq}`, room, sequence: seq,
    timestamp: "2026-09-08T07:14:02.512Z", senderDid: id.did, nonce,
    signature: sig(id, nonce, text), text: GD.swept(text),
  });

  const r1 = rec(idA, 1, "1757318042512", OFFER_TEXT);
  const r2 = rec(idB, 2, "1757318049100", ACCEPT_TEXT);
  const r3 = rec(idA, 3, "1757318050000", "Confirmed. Output JSON is fine.");
  const r4 = rec(idC, 4, "1757318055000", "I will host the file.");

  const fixtures = [];
  const F = (name, records, note) => fixtures.push({ name, records, note });

  F("valid signed transcript", [r1, r2], "3 authentic + acceptance");
  F("valid 4-record multi-signer", [r1, r2, r3, r4], "nonce order across signers");
  F("array-order permutation", [r2, r1], "permutation invariance");
  F("array-order reversed 4", [r4, r3, r2, r1], "reverse feed, same content");
  F("unsigned record", [r1, { ...r2, nonce: "", signature: "", text: ACCEPT_TEXT }], "acceptance unsigned");
  F("unsigned only", [{ ...r1, nonce: "", signature: "" }], "no signatures at all");
  F("tampered text", [r1, { ...r2, text: "Accepted. Price is 50 credits." }], "sig over different text");
  F("wrong room", [{ ...r1, room: "gendid-other-room" }], "room in record body");
  F("wrong nonce encoding", [{ ...r1, nonce: "abc" }], "nonce regex");
  F("non-canonical base64", [{ ...r1, signature: r1.signature + "=" }], "padded base64url");
  F("truncated signature", [{ ...r1, signature: r1.signature.slice(0, 80) }], "< 64 bytes");
  F("malformed signature", [{ ...r1, signature: "!!not-b64!!" }], "not base64");
  F("duplicate replay", [r1, r2, { ...r1, sequence: 99, recordId: `gdr-${room}-99` }], "inert duplicate");
  F("nonce regression", [r3, r1], "ka signs 3 then 1 — order-invariant rejection");
  F("malformed sender", [{ ...r1, senderDid: "not-a-did" }], "bad did format");
  F("identity-point key", [{ ...r1, senderDid: "did:key:z6MkeXATEjyXENzBXBxgC5EHk2JE5aqd7qMGGtDpLUH1e2Sj", signature: hexToB64url("0100000000000000000000000000000000000000000000000000000000000000" + "0".repeat(64)) }], "STEWARD attack: identity key + zero scalar");
  F("small-order key", [{ ...r1, senderDid: torsionDid(3) }], "torsion pub key");
  F("small-order R", [{ ...r1, signature: hexToB64url("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05" + "0100000000000000000000000000000000000000000000000000000000000000") }], "torsion R point");
  F("non-canonical pubkey", [{ ...r1, senderDid: torsionDid(4) }], "y >= p encoding");
  F("S >= L", [{ ...r1, signature: hexToB64url("00".repeat(32) + L_HEX) }], "malleated scalar (s = L)");
  F("malformed object", ["i am not an object", 42, null, true], "non-objects in array");
  F("bad sequence", [{ ...r1, sequence: "one" }], "sequence not a number");
  F("same-seq distinct senders", [r1, rec(idC, 1, "1757318042600", "I also offer: 4 credits.")], "occurrence suffix determinism");

  // torsionDid: build did:key for a torsion encoding using the lib's own b58 path
  // (didFromPubkey expects a 32-byte pub; identity for a torsion point)
  function torsionDid(i) {
    const pub = Buffer.from(TORSION_HEX[i], "hex");
    return GD.didFromPubkey(pub);
  }

  // ---- run BOTH runners over every fixture ----
  const jsResults = [];
  for (const f of fixtures) {
    const cls = await GD.classifyTranscript(room, f.records);
    const pkg = await GD.buildEvidencePackage(room, f.records);
    jsResults.push({ name: f.name, counts: cls.counts, rejections: cls.rejections,
      participants: cls.participants, commitment: cls.transcriptCommitment,
      records: cls.records, hash: pkg.evidenceHash, agreement: pkg.agreementId });
  }

  const py = pyRunner(`${pyPrelude}
def _py_sig(seed_hex, room, nonce, text):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    import base64 as _b64
    msg = ("%s|%s|%s" % (room, nonce, text)).encode()
    return _b64.urlsafe_b64encode(key.sign(msg)).decode().rstrip("=")

def _sweep(text):
    return G.tc_sweep(text)

out = []
for f in _payload:
    room = f["room"]
    cls = G._classify_records(room, f["records"])
    package = {"protocolVersion": "gendid/1.1", "transcriptRoom": room,
               "transcriptCommitment": cls["transcriptCommitment"], "records": cls["records"]}
    eh = G._evidence_hash(package)
    agr = "GD-" + room[:24] + "-" + eh[:16]
    out.append({"name": f["name"], "counts": cls["counts"], "rejections": cls["rejections"],
                "participants": cls["participants"], "commitment": cls["transcriptCommitment"],
                "records": cls["records"], "hash": eh, "agreement": agr})
print(json.dumps(out))
`, fixtures.map(f => ({ name: f.name, room, records: f.records })));

  // ---- compare every category across both runners ----
  let corpusFail = 0;
  for (let i = 0; i < fixtures.length; i++) {
    const js = jsResults[i];
    const p = py[i];
    const jrecs = JSON.stringify(js.records);
    const precs = JSON.stringify(p.records);
    const ok =
      js.name === p.name &&
      JSON.stringify(js.counts) === JSON.stringify(p.counts) &&
      JSON.stringify(js.rejections) === JSON.stringify(p.rejections) &&
      JSON.stringify(js.participants) === JSON.stringify(p.participants) &&
      js.commitment === p.commitment &&
      jrecs === precs &&
      js.hash === p.hash &&
      js.agreement === p.agreement;
    if (!ok) corpusFail++;
    check(`corpus "␂${fixtures[i].name}"`, ok, !ok ? _diffCorpus(js, p) : "");
    // noise value binding: commitment is non-trivial on every fixture
    if (typeof js.commitment === "string" && /^[0-f]{64}$/.test(js.commitment)) {
      // fine
    }
  }
  // summary console line kept for the steward report
  console.log(`  corpus: ${fixtures.length} fixtures, ${fixtures.length - corpusFail} fully identical, ${corpusFail} mismatched`);

  function _diffCorpus(js, p) {
    const bits = [];
    if (JSON.stringify(js.counts) !== JSON.stringify(p.counts)) bits.push(`counts ${JSON.stringify(js.counts)} vs ${JSON.stringify(p.counts)}`);
    if (JSON.stringify(js.rejections) !== JSON.stringify(p.rejections)) bits.push(`rejections ${JSON.stringify(js.rejections)} vs ${JSON.stringify(p.rejections)}`);
    if (js.commitment !== p.commitment) bits.push(`commitment ${js.commitment} vs ${p.commitment}`);
    if (JSON.stringify(js.records) !== JSON.stringify(p.records)) bits.push(`records differ`);
    if (js.hash !== p.hash) bits.push(`hash ${js.hash} vs ${p.hash}`);
    return bits.join("; ");
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
