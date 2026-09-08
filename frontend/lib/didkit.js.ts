// didkit.ts — Ed25519 did:key for technocore, fully in the browser.
// Mirrors the official scripts/sign.py: multibase z + base58btc(ed25519-pub
// multicodec 0xed01 + 32 raw pubkey), signatures are 86-char unpadded
// base64url over "<room>|<nonce>|<swept-text>".
import nacl from "tweetnacl";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);

function base58(raw: Uint8Array): string {
  let n = 0n;
  for (const b of raw) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    const rem = n % 58n;
    n = n / 58n;
    out = B58[Number(rem)] + out;
  }
  // leading zero bytes -> '1'
  for (const b of raw) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out;
}

export type Identity = {
  seedHex: string; // 64 hex chars — the ONLY secret, keep it safe
  did: string; // did:key:z6Mk… (48 chars after prefix)
};

export function identityFromSeed(seedHex: string): Identity {
  const seed = hexToBytes(seedHex);
  if (seed.length !== 32) throw new Error("seed must be 64 hex chars (32 bytes)");
  const kp = nacl.sign.keyPair.fromSeed(seed);
  return { seedHex: seedHex.toLowerCase(), did: didFromPubkey(kp.publicKey) };
}

export function generateIdentity(): Identity {
  const kp = nacl.sign.keyPair();
  return { seedHex: bytesToHex(kp.secretKey.slice(0, 32)), did: didFromPubkey(kp.publicKey) };
}

export function didFromPubkey(pub: Uint8Array): string {
  const mb = "z" + base58(new Uint8Array([...MULTICODEC_ED25519, ...pub]));
  if (mb.length !== 48) throw new Error(`internal: bad multibase length ${mb.length}`);
  return "did:key:" + mb;
}

export function signSay(identity: Identity, room: string, nonce: string, sweptText: string): string {
  const message = `${room}|${nonce}|${sweptText}`;
  const kp = nacl.sign.keyPair.fromSeed(hexToBytes(identity.seedHex));
  const sig = nacl.sign.detached(new TextEncoder().encode(message), kp.secretKey);
  return base64url(sig);
}

export function signSet(identity: Identity, ns: string, key: string, nonce: string, sweptValue: string): string {
  const message = `${ns}|${key}|${nonce}|${sweptValue}`;
  const kp = nacl.sign.keyPair.fromSeed(hexToBytes(identity.seedHex));
  const sig = nacl.sign.detached(new TextEncoder().encode(message), kp.secretKey);
  return base64url(sig);
}

// monotonic nonce: ms epoch as ASCII digits (server wants 1-19 digits, increasing per key per room)
export function nextNonce(): string {
  return String(Date.now() + Math.floor(Math.random() * 1000));
}

// ---------- hex / base64url ----------
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase().replace(/\s+/g, "");
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error("invalid seed: expected 64 hex characters");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (const c of b) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// validate a pasted did before scanning
export function isValidDid(did: string): boolean {
  return /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(did.trim());
}
