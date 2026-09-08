// gendid-lib.js — GenDid core client library. Zero-backend: everything runs in
// the browser against technocore.chat (CORS *) and GenLayer Studionet via the
// genlayer-js SDK bundle.
//
// Layers:
//   DID kit          Ed25519 did:key mint/sign/verify (tweetnacl), mirrors the
//                    official technocore sign.py exactly.
//   Technocore       room read (JSON lane), signed/unsigned writes, retry.
//   Verification     same canonical string as the contract: <room>|<nonce>|<swept>
//   Evidence          gendid/1 canonical records, classifications, package hash
//                    (byte-parity with the contract's Python, tested).
/* global nacl */

// ============================== DID kit ==============================

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);

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

// ============================== verification ==============================

// Deterministic client-side verification, same canonical string as the contract.
const DID_RE = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;
const NONCE_RE = /^[0-9]{1,19}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const ROOM_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function verifyRecord(room, rec) {
  // returns classification string + canonical record
  // NOTE: canonical records mirror the contract's _classify_records EXACTLY
  // (no timestamp field — seq is the total order; ts is venue metadata).
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
  if (typeof rec !== "object" || rec === null) return { ...mk("MALFORMED") };
  const { senderDid, text } = rec;
  if (typeof senderDid !== "string" || typeof text !== "string" || typeof rec.sequence !== "number") {
    return { ...mk("MALFORMED"), reject: "missing fields" };
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
  const message = new TextEncoder().encode(`${room}|${rec.nonce}|${swept(rec.text)}`);
  const sigBytes = b64urlDecode(rec.signature);
  if (!sigBytes || sigBytes.length !== 64) return { ...mk("INVALID_SIGNATURE"), reject: "sig not 64 bytes" };
  const ok = nacl.sign.detached.verify(message, sigBytes, pub);
  if (!ok) return { ...mk("INVALID_SIGNATURE"), reject: "signature does not verify" };
  return mk("AUTHENTIC_SIGNED");
}

// Full transcript classification: duplicates, nonce regressions, room binding.
function classifyTranscript(room, rawRecords) {
  const seen = new Set();
  const lastNonce = new Map();
  const records = [];
  const counts = { AUTHENTIC_SIGNED: 0, UNSIGNED: 0, INVALID_SIGNATURE: 0, MALFORMED: 0, DUPLICATE: 0 };
  const rejections = {};
  const authenticIds = new Set();
  const participants = new Set();

  for (const raw of rawRecords) {
    const c = verifyRecord(room, raw);
    if (c.signatureStatus === "UNSIGNED") {
      counts.UNSIGNED++;
      records.push(c);
      continue;
    }
    if (c.signatureStatus !== "AUTHENTIC_SIGNED") {
      counts[c.signatureStatus in counts ? c.signatureStatus : "MALFORMED"]++;
      if (c.reject) rejections[c.recordId] = c.reject;
      records.push(c);
      continue;
    }
    const key = `${c.senderDid}|${c.nonce}|${c.signature}|${c.text}`;
    if (seen.has(key)) {
      counts.DUPLICATE++;
      c.signatureStatus = "DUPLICATE";
      records.push(c);
      continue;
    }
    seen.add(key);
    const prev = lastNonce.get(c.senderDid) || -1;
    if (Number(c.nonce) <= prev) {
      counts.INVALID_SIGNATURE++;
      c.signatureStatus = "INVALID_SIGNATURE";
      rejections[c.recordId] = "nonce not increasing for key in room";
      records.push(c);
      continue;
    }
    lastNonce.set(c.senderDid, Number(c.nonce));
    counts.AUTHENTIC_SIGNED++;
    authenticIds.add(c.recordId);
    participants.add(c.senderDid);
    records.push(c);
  }
  records.sort((a, b) => a.sequence - b.sequence);
  return {
    records,
    counts,
    rejections,
    authenticIds,
    participants: [...participants].sort(),
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

// sha256 hex over a string (UTF-8)
async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function buildEvidencePackage(room, rawRecords) {
  const cls = classifyTranscript(room, rawRecords);
  const package_ = {
    protocolVersion: "gendid/1",
    transcriptRoom: room,
    records: cls.records,
  };
  const evidenceHash = await sha256Hex(canonicalJson(package_));
  const agreementId = `GD-${room.slice(0, 24)}-${(await sha256Hex(canonicalJson(package_))).slice(0, 16)}`;
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
  // verify
  verifyRecord, classifyTranscript,
  // evidence
  canonicalJson, sha256Hex, buildEvidencePackage, tclkTag,
  // technocore
  tcReadRoom, tcSaySigned, tcSayUnsigned, TC_BASE,
  // helpers
  nextNonce, shortDid, b64url, b64urlDecode,
  // regexes for the UI
  ROOM_RE, DID_RE,
};
