# GenDid Security Model (gendid/1.2)

This document maps the Sep 2026 Steward security findings to the exact
implementation and the regression tests that prove each fix. Nothing here is
claimed without an executed test; counts are from the runs listed in the
Steward response.

## 1. Root cause of the original finding

The Steward attack: *an identity-point public key with a zero-scalar
signature verifies for arbitrary messages*.

Mathematically, Ed25519 verification checks `sB == R + kA` where
`k = H(R||A||M) mod L`. With `A = identity` (and s = 0, R = identity — or
more generally any small-order A with a matching small-order R and s = 0):

```
sB  = [0]B    = identity
R + kA         = identity + [k](small-order point) = a small-order point
```

For the identity-point key the two sides are equal for EVERY message and
every k — the attacker never needs the private key. The pre-hardening
verifier only checked encoding shape (32-byte key, 64-byte signature,
base64url) and then ran the verification equation, which the crafted pair
satisfies vacuously. Hence "accepted records prove DID-key control" was
false: that record proved nothing.

## 2. Strict Ed25519 validation (the fix)

The contract's vendored verifier (`contracts/gendid_judge.py`,
`ed25519_verify` + the classification path) and the browser verifier
(`frontend/lib/gendid-lib.js`) now reject, with distinct machine-readable
reason strings, in this exact order:

| # | Check | Reject reason |
|---|-------|---------------|
| 1 | key/sig/nonce are strings, DID shape, nonce 1-19 digits, sig base64url shape | `malformed nonce/signature encoding` |
| 2 | signature decodes to exactly 64 bytes | `signature not 64 bytes` |
| 3 | signature is canonical unpadded base64url (re-encode == stored) | `non-canonical base64url signature` |
| 4 | DID decodes to a 32-byte Ed25519 public key (multicodec `0xed01`) | `did does not decode to ed25519-pub` |
| 5 | public key not in the 8-encoding small-order set (identity, order-2/4/8 points) | `small-order public key` |
| 6 | public key decompresses to a canonical curve point (y < p, no x=0,y=p-1 aliasing) | `non-canonical public key encoding` |
| 7 | signature R (first 32 bytes) not small-order | `small-order signature R point` |
| 8 | signature R decompresses canonically | `non-canonical signature R point encoding` |
| 9 | scalar S (last 32 bytes, little-endian) < group order L | `non-canonical scalar s >= L` |
| 10 | scalar S ≠ 0 | `zero-scalar signature` |
| 11 | Ed25519 equation actually verifies over `room\|nonce\|swept-text` | `signature does not verify` |

Checks 5-10 are the application-level rejection layer on top of RFC 8032:
the equation alone is satisfiable without the private key exactly when
small-order points are allowed, so the prime-order-subgroup membership of
both A and R, plus scalar canonicality, is what makes "AUTHENTIC_SIGNED ⇒
control of the DID key" a true statement.

Regression suite: `tests/direct/test_adversarial_ed25519.py` — 16 tests,
all 13 Steward-required cases plus torsion sweep, transcript-level attack,
and a no-shortcut test that the verifier is actually invoked. The same
fixtures run against the browser lib inside the parity corpus (T7), so a
divergence between the two implementations fails CI.

## 3. Transcript order binding

See `docs/PROTOCOL.md` §3.3. The signed payload commits each signer's
nonce; GenDid adds a hash chain over the authenticated records in canonical
order (`transcriptCommitment`) with per-record `orderIndex`/`orderCommit`.
Reorder/insert/delete/duplicate each change the commitment or classify
inertly (`DUPLICATE`); tests `test_o1`–`test_o10`.

Array-order invariance (canonical scan order): the raw input array is
sorted by content before classification, so no classification output or
hash depends on the order records were fed in. This closes a consensus
hazard where two validators paging the same room differently (or an
attacker reordering the array) would produce different evidence hashes.

## 4. Grounded consensus

The LLM labels questions Q1-Q6 with cited `recordId`s; the contract
re-derives the final status deterministically and rejects any label set
whose citations do not resolve to `AUTHENTIC_SIGNED` records that exist in
the stored evidence (`evidence_grounded` gate, phantom-evidence test
`test_t11`). Unsigned or invalid records can never ground a term
(`test_t5`, `test_t15`); an LLM claiming acceptance where only an offer
exists cannot produce AGREED (`test_t11`, `test_t15`); garbage LLM output
fail-safes to `INSUFFICIENT_EVIDENCE`/`NOT_AGREED`, never AGREED
(`test_t12`). Prompt injection inside transcript text is data, not
instructions (`test_t13`, `test_t14`).

## 5. Browser / contract parity

One canonicalization spec (PROTOCOL.md §3), two implementations (Python in
the contract, JS in the browser lib), one shared fixture corpus:
`tests/js/test-parity.mjs` T7 — 23 fixtures covering valid, unsigned,
invalid (every reject reason), malformed, duplicate, wrong-DID, wrong-nonce,
tampered text, invalid point, small-order key/R, non-canonical signature,
reordered records, and the exact Steward attack material. Each fixture's
INPUT, BROWSER output, and CONTRACT output (full canonical record list,
counts, rejections, participants, commitment, evidenceHash, agreementId)
must be byte-identical. CI executes both runners on every push.

## 6. Transcript snapshot authority (gendid/1.2 — the second Steward finding)

The second Steward concern: *the caller of `submit_evidence` chooses the
record set*. Per-record DID signatures authenticate each record's content
and the hash chain binds the supplied package's order — but neither proves
the package is the COMPLETE room history rather than a caller-selected
subset (omit the cancellation, submit only the favorable records).

Fix: a **jointly-authenticated immutable transcript manifest**, derived —
never caller-supplied — by both the contract and the browser from the
authenticated record set:

```
manifest = {
  protocolVersion: "gendid/1.2", room, recordCount,
  recordIds:      [ordered ids of AUTHENTIC records],
  recordDigests:  [sha256(canonical_json(record_core)) per record],
  participants:  [sorted distinct senderDIDs of AUTHENTIC records],
  transcriptCommitment: <the gendid/1.1 order chain root>
}
manifestStr = "<room>|<recordCount>|<recordIds joined>|<participants joined>|<transcriptCommitment>"
```

Authority = **every participant** (each distinct `senderDid`) must supply
an Ed25519 signature over `manifestStr`, made with the same key that
signed their records, verified through the same strict layer (§2 —
small-order keys/R, non-canonical encodings, S≥L, S=0 all reject with
distinct `manifest_*` reasons).

Security property (exact): the manifest binds record count, ordered ids,
per-record content digests, the participant set, and the commitment.
Therefore:

| manipulation | effect on authority |
|---|---|
| omit a record (CASE A) | recordCount/digest list change → old manifest signatures no longer verify → `manifest_incomplete_or_invalid_signatures` |
| insert a record (CASE B) | same — even a genuinely signed new record changes the manifest |
| reorder chronology (CASE C) | canonical order is (nonce, seq, id) — a different chronology is a different manifestStr |
| change any text/nonce | record digest changes → invalid |
| change attribution | participant set / digests change → invalid |
| swap in another signer's key | manifest signature must come from the record-set participant's own did:key |
| conflicting snapshots (CASE F) | first authoritative finalization seals the room on-chain (`room_seals`); any different manifest for that room → `conflicting_snapshot` |
| no manifest at all | `NON_AUTHORITATIVE` — the LLM never runs |

The status `NON_AUTHORITATIVE` is a new explicit, tested, frontend-mirrored
state: a non-authoritative submission is *recorded* (auditability) but the
adjudication questions are never asked — a semantic answer can never arise
from unauthoritative evidence.

Why honest parties sign: each participant's manifest signature is a fresh
commitment that the record set they witnessed is exactly this snapshot.
A caller without every participant's key cannot mint authority for a
manipulated set. (In the production dApp the browser holds the demo
identities and signs the manifest for them; for pasted third-party
transcripts, each participant's manifest signature must be supplied —
incomplete authority is surfaced explicitly in the UI before submission.)

Adversarial regression suite: `tests/direct/test_authority.py` — 23 tests
covering Steward cases A–I (omission, omission-of-contradiction,
insertion, reordering, array-permutation ≠ reorder, sequence collision,
cross-party nonce manipulation, same-DID nonce regression, conflicting
snapshots + idempotent resubmission, unsigned insertion, attack material
as manifest signature, forged manifest signature, prompt injection under
authority, and invariant tests: manifest sensitivity, two conflicts never
both authoritative, invalid signatures never enter the manifest, unsigned
never authenticated, non-authoritative never falls through to AGREED,
authority only after the deterministic gate).

## 7. Standing test counts (gendid/1.2)

- Contract + adjudication: `test_gendid_judge.py` — 20 tests
- Adversarial Ed25519: `test_adversarial_ed25519.py` — 16 tests
- Snapshot authority: `test_authority.py` — 23 tests
- Order binding: `test_order_binding.py` — 10 tests (total direct: 73)
- Browser parity + corpus + manifest parity + demo determinism: `test-parity.mjs` — 75 checks (incl. T9: the public demo builds byte-identical records/manifest/commitment/evidenceHash on every load — the room-seal idempotency regression)
- Attack reproducer: `scripts/attack_repro.py` — identity point, all 8
  torsion points, arbitrary message, AND the gendid/1.2 subset /
  insertion / wrong-key / zero-scalar manifest attacks — all rejected
- `genvm-lint` clean (`{"ok":true,...}`)

Exact reproduction commands: `docs/REPRODUCIBILITY.md`. CI runs the same
commands on every push.
