// gendid-lib.js — GenDid core client library. Zero-backend: everything runs in
// the browser against technocore.chat (CORS *) and GenLayer Studionet via the
// genlayer-js SDK bundle.
//
// Layers:
//   DID kit          Ed25519 did:key mint/sign/verify (tweetnacl), mirrors the
//                    official technocore sign.py exactly.
//   Technocore       room read (JSON lane), signed/unsigned writes, retry.
//   Verification     same canonical string as the contract: <room>|<nonce>|<swept>
//                    + STRICT application-level Ed25519 checks (small-order
//                    points, canonical encodings, canonical scalar) identical
//                    to the contract's Python — enforced by tests/js parity
//                    fixtures.
//   Evidence          gendid/1.1 canonical records, classifications, package
//                    hash, transcript order commitment (hash chain).
//                    Byte-parity with the contract's Python, tested.
/* global nacl */

// ============================== DID kit ==============================

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);

// edwards25519 group order L = 2^252 + 27742317777372353535851937790883648493
const L = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
// field prime p = 2^255 - 19
const P = 2n ** 255n - 19n;

// The complete 8-torsion subgroup of edwards25519 (all points P with [8]P == O),
// canonical compressed encodings, little-endian hex. Derived + self-verified by
// scripts/derive_torsion.py; matches the contract's _SMALL_ORDER_ENC exactly.
const SMALL_ORDER_ENC_HEX = [
  "0000000000000000000000000000000000000000000000000000000000000000", // (x=0,y=0)  order 4
  "0000000000000000000000000000000000000000000000000000000000000080", // (x=0,y=0)  non-canon
  "0100000000000000000000000000000000000000000000000000000000000000", // identity
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // (0,p-1) order 2
];
const SMALL_ORDER_SET = new Set(SMALL_ORDER_ENC_HEX);

const MAX_SAFE_SEQ = Number.MAX_SAFE_INTEGER; // 2^53-1; JS-visible bound, matches contract _MAX_SEQ

function base58(raw) {
  let n = 0n;
  for (const b of raw) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    const rem = n % 58n;
    n = n / 58n;
    out = B58[Number(rem)] + out;
  }
  for (const b of raw) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

function unbase58(s) {
  let n = 0n;
  for (const ch of s) {
    const d = B58.indexOf(ch);
    if (d < 0) return null;
    n = n * 58n + BigInt(d);
  }
  const body = n === 0n ? new Uint8Array(0) : bigIntToBytes(n);
  let pad = 0;
  for (const ch of s) {
    if (ch === "1") pad++;
    else break;
  }
  const out = new Uint8Array(pad + body.length);
  out.set(body, pad);
  return out;
}

function bigIntToBytes(n) {
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n = n >> 8n;
  }
  return new Uint8Array(bytes);
}

function bytesToBigIntLE(b) {
  // little-endian bytes -> BigInt
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}

function hexOfBytes(b) {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function didFromPubkey(pub) {
  const mb = "z" + base58(new Uint8Array([...MULTICODEC_ED25519, ...pub]));
  if (mb.length !== 48) throw new Error("internal: bad multibase length " + mb.length);
  return "did:key:" + mb;
}

function pubkeyFromDid(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  const mb = did.slice("did:key:".length);
  if (mb.length !== 48) return null;
  const decoded = unbase58(mb.slice(1));
  if (!decoded || decoded.length !== 34) return null;
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.slice(2);
}

// Identity: seed stays in localStorage ONLY. Never sent anywhere.
function identityFromSeed(seedHex) {
  const seed = hexToBytes(seedHex);
  if (seed.length !== 32) throw new Error("seed must be 64 hex chars");
  const kp = nacl.sign.keyPair.fromSeed(seed);
  return { seedHex: seedHex.toLowerCase(), did: didFromPubkey(kp.publicKey), kp };
}

function generateIdentity() {
  const kp = nacl.sign.keyPair();
  const seedHex = bytesToHex(kp.secretKey.slice(0, 32));
  return { seedHex, did: didFromPubkey(kp.publicKey), kp };
}

// technocore sweep: Cc/Cf/Cs/Co/Zl/Zp -> space, trim (server's clean_text)
function swept(text) {
  return text.replace(/\p{Cc}|\p{Cf}|\p{Cs}|\p{Co}|\p{Zl}|\p{Zp}/gu, " ").trim();
}

function signSay(identity, room, nonce, text) {
  // sign the SWEPT text — the stored bytes, exactly the server's canonical string
  const message = `${room}|${nonce}|${swept(text)}`;
  const sig = nacl.sign.detached(new TextEncoder().encode(message), identity.kp.secretKey);
  return b64url(sig);
}

// ============================== strict Ed25519 ==============================
// Application-level strictness mirrored from contracts/gendid_judge.py
// (ed25519_verify + _classify_records). Reasons are IDENTICAL STRINGS so
// browser and contract produce byte-identical classification reports.
// tweetnacl.verify itself is the last check; the checks below run FIRST so
// the failure reason is precise (tweetnacl says only "false").

function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

// Mirror of the contract's _point_decompress None-ness for a 32-byte
// compressed encoding: returns true iff the encoding is a CANONICAL
// on-curve point encoding. False for: y >= p; y with non-square x
// (off-curve); x=0 with sign bit set (non-canonical). (The four x=0
// torsion points themselves are caught by the small-order set first.)
function pointEncodingIsCanonical(b32) {
  const raw = bytesToBigIntLE(b32);
  const sign = raw >> 255n;
  const y = raw & ((1n << 255n) - 1n);
  if (y >= P) return false; // non-canonical field element
  // y in {0, 1, p-1} occurs ONLY at torsion points (mirrors the contract's
  // decompress rule; the small-order set check normally fires first — this
  // is defense-in-depth and keeps byte-identical parity with the contract).
  if (y === 0n || y === 1n || y === P - 1n) return false;
  // d = -121665/121666 mod p (same constant as the contract)
  const D = (P - 121665n) * modPow(121666n, P - 2n, P) % P;
  const xx = ((y * y - 1n) * modPow(D * y * y + 1n, P - 2n, P)) % P;
  return modPow(xx, (P - 1n) / 2n, P) === 1n; // x must be a square
}

function isSmallOrderEnc(b32) {
  return SMALL_ORDER_SET.has(hexOfBytes(b32));
}

function scalarIsCanonical(b64SigBytes) {
  const s = bytesToBigIntLE(b64SigBytes.slice(32));
  return s < L; // covers s >= L AND nothing else; s == 0 handled separately
}

function strictRejectReason(pub, sigBytes) {
  // Returns "" when the pair passes strict checks; else the reject reason
  // EXACTLY as the contract produces it (same order of checks).
  if (isSmallOrderEnc(pub)) return "small-order public key";
  if (!pointEncodingIsCanonical(pub)) return "non-canonical public key encoding";
  if (isSmallOrderEnc(sigBytes.slice(0, 32))) return "small-order signature R point";
  if (!pointEncodingIsCanonical(sigBytes.slice(0, 32))) return "non-canonical signature R point encoding";
  const s = bytesToBigIntLE(sigBytes.slice(32));
  if (s >= L) return "non-canonical scalar s >= L";
  if (s === 0n) return "zero-scalar signature";
  return "";
}

// ============================== verification ==============================

// Deterministic client-side verification, same canonical string as the contract.
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function verifyRecord(room, rec) {
  // returns classification string + canonical record
  // NOTE: canonical records mirror the contract's _classify_records EXACTLY
  // (no timestamp field — seq is venue metadata; the SIGNED nonce is the
  // canonical order key, exactly as documented in the contract).
  const mk = (status) => ({
    recordId: `gdr-${room}-${rec.sequence}`,
    room,
    sequence: rec.sequence,
    senderDid: rec.senderDid,
    nonce: rec.nonce || "",
    signature: rec.signature || "",
    text: rec.text,
    signatureStatus: status,
  });
  if (typeof rec !== "object" || rec === null) return { ...mk("MALFORMED"), reject: "not an object" };
  const { senderDid, text } = rec;
  if (typeof senderDid !== "string" || typeof text !== "string" || !isCanonicalSeq(rec.sequence)) {
    return { ...mk("MALFORMED"), sequence: null, reject: "missing fields" };
  }
  if (!rec.signature && !rec.nonce) {
    return { ...mk("UNSIGNED"), reject: "" };
  }
  if (!DID_RE.test(senderDid)) return { ...mk("INVALID_SIGNATURE"), reject: "malformed did" };
  if (!NONCE_RE.test(String(rec.nonce || "")) || !SIG_RE.test(String(rec.signature || ""))) {
    return { ...mk("INVALID_SIGNATURE"), reject: "malformed nonce/signature" };
  }
  const pub = pubkeyFromDid(senderDid);
  if (!pub) return { ...mk("INVALID_SIGNATURE"), reject: "did not ed25519-pub" };
  const sigBytes = b64urlDecode(rec.signature);
  if (!sigBytes || sigBytes.length !== 64) return { ...mk("INVALID_SIGNATURE"), reject: "sig not 64 bytes" };
  if (b64url(sigBytes) !== rec.signature) return { ...mk("INVALID_SIGNATURE"), reject: "non-canonical base64url signature" };
  // STRICT application-level checks — identical order & reasons as the contract
  const reason = strictRejectReason(pub, sigBytes);
  if (reason) return { ...mk("INVALID_SIGNATURE"), reject: reason };
  const message = new TextEncoder().encode(`${room}|${rec.nonce}|${swept(rec.text)}`);
  const ok = nacl.sign.detached.verify(message, sigBytes, pub);
  if (!ok) return { ...mk("INVALID_SIGNATURE"), reject: "signature does not verify" };
  return mk("AUTHENTIC_SIGNED");
}

function isCanonicalSeq(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE_SEQ;
}

// Full transcript classification — mirrors the contract's _classify_records
// STEP BY STEP (same order of checks, same reject-reason strings, same
// canonical record on every path). Parity enforced by tests/js fixtures.
// ASYNC: the transcript commitment is a sha256 hash chain computed with the
// platform's audited WebCrypto implementation (crypto.subtle) — the lib never
// hand-rolls hashing primitives.
// ============================== canonical JSON + hash ==============================
// Byte-parity with the contract: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)

// Canonical pre-sort key: the CANONICAL SCAN ORDER (gendid/1.1) — mirrors
// _raw_sort_key in contracts/gendid_judge.py EXACTLY (same groups, same
// components, same order, same cross-runtime type tags). Classification is
// a pure function of the record SET: rid assignment, dedup, nonce
// monotonicity, and malformed-record recordIds never depend on input order.
function rawSortKey(entry) {
  const [idx, rec] = entry;
  // cross-runtime type tag: z null/undefined, b bool, i integral-safe
  // number, n other number, s string, o other — identical to the contract
  function t(v) {
    if (v === null || v === undefined) return "z";
    if (typeof v === "boolean") return "b";
    if (typeof v === "number") {
      if (Number.isInteger(v) && Math.abs(v) <= MAX_SAFE_SEQ) return "i";
      return "n";
    }
    if (typeof v === "string") return "s";
    return "o";
  }
  function tv(v) {
    const tag = t(v);
    if (tag === "s") return canonicalJson(v);
    if (tag === "i") return String(BigInt(Math.trunc(v)));
    return "";
  }
  if (typeof rec !== "object" || rec === null) {
    return [2, t(rec), tv(rec), idx];
  }
  const seqOk = isCanonicalSeq(rec.sequence);
  const seqInt = seqOk ? Number(rec.sequence) : 0;
  const group = seqOk ? 0 : 1;
  const seq = rec.sequence;
  const sender = rec.senderDid;
  const nonce = rec.nonce;
  const sig = rec.signature;
  const text = rec.text;
  const blob = canonicalJson([
    t(seq), tv(seq),
    t(sender), tv(sender),
    t(nonce), tv(nonce),
    t(sig), tv(sig),
    t(text), tv(text),
  ]);
  return [
    group,
    seqInt,
    typeof sender === "string" ? sender : "",
    typeof nonce === "string" ? nonce : "",
    typeof sig === "string" ? sig : "",
    typeof text === "string" ? text : "",
    blob,
    idx,
  ];
}

function compareRawKeys(a, b) {
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    const y = b[i];
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

async function classifyTranscript(room, rawRecords) {
  const seen = new Set();        // content keys of AUTHENTIC records
  const lastNonce = new Map();    // sender -> last accepted nonce (Number)
  const records = [];
  const counts = { AUTHENTIC_SIGNED: 0, UNSIGNED: 0, INVALID_SIGNATURE: 0, MALFORMED: 0, DUPLICATE: 0 };
  const rejections = {};
  const authenticIds = new Set();
  const participants = new Set();
  const seqIds = new Map();       // seq -> occurrences, recordId disambiguation
  const authenticEntries = [];    // [nonceInt, sequence, recordId, canonical]

  // CANONICAL SCAN ORDER (mirrors the contract): array-order-invariant.
  const entries = rawRecords
    .map((rec, idx) => [idx, rec])
    .sort((e1, e2) => compareRawKeys(rawSortKey(e1), rawSortKey(e2)));

  let scan = 0;
  for (const [idx, raw] of entries) {
    scan += 1; // 1-based CANONICAL SCAN POSITION (array-order-invariant)
    if (typeof raw !== "object" || raw === null) {
      const rid = `x${scan}`;
      records.push({
        recordId: rid, room, sequence: null, senderDid: "", nonce: "", signature: "",
        text: "", signatureStatus: "MALFORMED",
      });
      counts.MALFORMED++;
      rejections[rid] = "not an object";
      continue;
    }
    if (!isCanonicalSeq(raw.sequence)) {
      const rid = `x${scan}`;
      records.push({
        recordId: rid, room, sequence: null,
        senderDid: typeof raw.senderDid === "string" ? raw.senderDid : "",
        nonce: "", signature: "",
        text: typeof raw.text === "string" ? raw.text : "",
        signatureStatus: "MALFORMED",
      });
      counts.MALFORMED++;
      rejections[rid] = "bad or non-canonical sequence";
      continue;
    }
    const seq = raw.sequence;
    const occ = seqIds.get(seq) || 0;
    seqIds.set(seq, occ + 1);
    const rid = occ === 0 ? `gdr-${room}-${seq}` : `gdr-${room}-${seq}-${occ + 1}`;

    const sender = typeof raw.senderDid === "string" ? raw.senderDid : null;
    const text = typeof raw.text === "string" ? raw.text : null;
    if (sender === null || text === null) {
      records.push({
        recordId: rid, room, sequence: seq,
        senderDid: sender || "", nonce: "", signature: "",
        text: text || "", signatureStatus: "MALFORMED",
      });
      counts.MALFORMED++;
      rejections[rid] = "missing senderDid/text";
      continue;
    }
    const sig = raw.signature;
    const nonce = raw.nonce;
    const sigS = typeof sig === "string" ? sig : "";
    const nonceS = typeof nonce === "string" ? nonce : "";
    if ((sig === undefined || sig === null || sig === "") && (nonce === undefined || nonce === null || nonce === "")) {
      records.push({
        recordId: rid, room, sequence: seq, senderDid: sender,
        nonce: "", signature: "", text, signatureStatus: "UNSIGNED",
      });
      counts.UNSIGNED++;
      continue;
    }
    const invalid = (why) => {
      counts.INVALID_SIGNATURE++;
      rejections[rid] = why;
      records.push({
        recordId: rid, room, sequence: seq, senderDid: sender,
        nonce: nonceS, signature: sigS, text, signatureStatus: "INVALID_SIGNATURE",
      });
    };
    if (typeof sig !== "string" || typeof nonce !== "string") { invalid("sig/nonce not strings"); continue; }
    if (!DID_RE.test(sender)) { invalid("malformed did"); continue; }
    if (!NONCE_RE.test(nonce) || !SIG_RE.test(sig)) { invalid("malformed nonce/signature encoding"); continue; }
    const sigBytes = b64urlDecode(sig);
    if (!sigBytes) { invalid("signature not base64url"); continue; }
    if (sigBytes.length !== 64) { invalid("signature not 64 bytes"); continue; }
    if (b64url(sigBytes) !== sig) { invalid("non-canonical base64url signature"); continue; }
    const pub = pubkeyFromDid(sender);
    if (!pub) { invalid("did does not decode to ed25519-pub"); continue; }
    // strict application-level Ed25519 checks (same order & reasons as contract)
    const reason = strictRejectReason(pub, sigBytes);
    if (reason) { invalid(reason); continue; }
    const contentKey = `${sender}|${nonce}|${sig}|${text}`;
    if (seen.has(contentKey)) {
      counts.DUPLICATE++;
      records.push({
        recordId: rid, room, sequence: seq, senderDid: sender,
        nonce, signature: sig, text, signatureStatus: "DUPLICATE",
      });
      continue;
    }
    const message = new TextEncoder().encode(`${room}|${nonce}|${swept(text)}`);
    const ok = nacl.sign.detached.verify(message, sigBytes, pub);
    if (!ok) { invalid("signature does not verify"); continue; }
    const prev = lastNonce.get(sender) || -1;
    if (Number(nonce) <= prev) { invalid("nonce not increasing for key in room"); continue; }
    lastNonce.set(sender, Number(nonce));
    seen.add(contentKey);
    counts.AUTHENTIC_SIGNED++;
    authenticIds.add(rid);
    participants.add(sender);
    authenticEntries.push([Number(nonce), seq, rid, {
      recordId: rid, room, sequence: seq, senderDid: sender,
      nonce, signature: sig, text, signatureStatus: "AUTHENTIC_SIGNED",
    }]);
  }

  // ---- canonical total order (identical to contract) ----
  authenticEntries.sort((e1, e2) =>
    e1[0] !== e2[0] ? e1[0] - e2[0]
    : e1[1] !== e2[1] ? e1[1] - e2[1]
    : e1[2] < e2[2] ? -1 : e1[2] > e2[2] ? 1 : 0);
  const authRids = new Set(authenticEntries.map((e) => e[2]));
  const context = records.filter((r) => !authRids.has(r.recordId));
  context.sort((a, b) => {
    const aNull = !isCanonicalSeq(a.sequence);
    const bNull = !isCanonicalSeq(b.sequence);
    if (aNull !== bNull) return aNull ? 1 : -1;
    if (!aNull && a.sequence !== b.sequence) return a.sequence - b.sequence;
    return a.recordId < b.recordId ? -1 : a.recordId > b.recordId ? 1 : 0;
  });
  let order = 1;
  let chainHex = await sha256Hex("gendid/1.1|" + room);
  const ordered = [];
  for (const [nonceInt, seq2, rid2, canonical] of authenticEntries) {
    chainHex = await sha256Hex(chainHex + "|" + canonicalJson(canonical));
    const out = { ...canonical, orderIndex: order, orderCommit: chainHex };
    ordered.push(out);
    order++;
  }
  for (const rec of context) {
    rec.orderIndex = order;
    ordered.push(rec);
    order++;
  }
  return {
    records: ordered,
    counts,
    rejections,
    authenticIds,
    participants: [...participants].sort(),
    transcriptCommitment: chainHex,
  };
}

// ============================== canonical JSON + hash ==============================
// Byte-parity with the contract: json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("non-integer in canonical json");
    return String(value);
  }
  if (typeof value === "string") return jsonStr(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => jsonStr(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }
  throw new Error("unsupported type in canonical json");
}

function jsonStr(s) {
  // mirrors Python ensure_ascii=True: non-ASCII -> \uXXXX
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (cp < 0x20 || cp > 0x7e) {
      if (cp > 0xffff) {
        const h = cp - 0x10000;
        const hi = 0xd800 + (h >> 10);
        const lo = 0xdc00 + (h & 0x3ff);
        out += "\\u" + hi.toString(16).padStart(4, "0") + "\\u" + lo.toString(16).padStart(4, "0");
      } else {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    } else out += ch;
  }
  return out + '"';
}

// sha256 hex over a string (UTF-8), via the platform's audited WebCrypto.
// Sync sha256 does NOT exist in this lib by design: hashing always goes
// through crypto.subtle (browsers + Node 18+ both provide it).
async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function buildEvidencePackage(room, rawRecords) {
  const cls = await classifyTranscript(room, rawRecords);
  const package_ = {
    protocolVersion: "gendid/1.1",
    transcriptRoom: room,
    transcriptCommitment: cls.transcriptCommitment,
    records: cls.records,
  };
  const evidenceHash = await sha256Hex(canonicalJson(package_));
  const agreementId = `GD-${room.slice(0, 24)}-${evidenceHash.slice(0, 16)}`;
  return { ...cls, package: package_, evidenceHash, agreementId };
}

// tclk/1 frame recognition (display only)
const TCLK_TYPES = new Set(["offer", "accept", "lock", "reveal", "refund", "cancel", "receipt", "heartbeat"]);
function tclkTag(text) {
  if (typeof text !== "string" || !text.startsWith("tclk1 ")) return "";
  try {
    const obj = JSON.parse(text.slice(6));
    return TCLK_TYPES.has(obj.type) ? obj.type : "";
  } catch {
    return "";
  }
}

// ============================== technocore client ==============================

const TC_BASE = "https://technocore.chat";

async function tcFetch(url, init, tries = 5) {
  let last = null;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { ...init, cache: "no-store" });
      if ([500, 502, 503].includes(r.status)) {
        last = r;
        await sleep(1200 * (i + 1));
        continue;
      }
      return r;
    } catch {
      await sleep(1200 * (i + 1));
    }
  }
  if (last) return last;
  throw new Error("technocore.chat unreachable");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function tcReadRoom(room, limit = 200) {
  const r = await tcFetch(`${TC_BASE}/r/${encodeURIComponent(room)}?format=json&limit=${Math.min(limit, 200)}&n=${Date.now()}`);
  if (!r.ok) throw new Error(`read room ${room}: HTTP ${r.status}`);
  const obj = await r.json();
  return obj.messages || [];
}

async function tcSaySigned(room, did, sig, nonce, text) {
  const url = `${TC_BASE}/r/${encodeURIComponent(room)}/say-signed/${encodeURIComponent(did)}/${encodeURIComponent(sig)}/${nonce}/${encodeURIComponent(text)}`;
  const r = await tcFetch(url, undefined, 6);
  return r;
}

async function tcSayUnsigned(room, nick, text) {
  const url = `${TC_BASE}/r/${encodeURIComponent(room)}/say/${encodeURIComponent(nick)}/${encodeURIComponent(text)}`;
  return tcFetch(url, undefined, 4);
}

// ============================== helpers ==============================

function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error("invalid seed: expected 64 hex chars");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  try {
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function nextNonce() {
  return String(Date.now() + Math.floor(Math.random() * 1000));
}

function shortDid(did) {
  if (!did.startsWith("did:key:")) return did;
  const key = did.slice("did:key:".length);
  return key.length < 14 ? key : `${key.slice(0, 7)}…${key.slice(-4)}`;
}

window.GD = {
  // did
  identityFromSeed, generateIdentity, didFromPubkey, pubkeyFromDid, signSay, swept,
  // strict ed25519
  strictRejectReason, isSmallOrderEnc, pointEncodingIsCanonical,
  // verify
  verifyRecord, classifyTranscript, isCanonicalSeq,
  // evidence
  canonicalJson, sha256Hex, buildEvidencePackage, tclkTag,
  // technocore
  tcReadRoom, tcSaySigned, tcSayUnsigned, TC_BASE,
  // helpers
  nextNonce, shortDid, b64url, b64urlDecode,
  // constants for tests/UI
  SMALL_ORDER_ENC_HEX, L, P,
  // regexes for the UI
  ROOM_RE, DID_RE,
};
