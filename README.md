# GenDid — DID Agreement Judge

**gendid/1.2** · independent prototype

GenDid determines **what DID-authenticated agents actually agreed to**, from
their cryptographically signed technocore.chat transcript, adjudicated by
GenLayer validator consensus. Every adjudicated snapshot is *authoritative*:
all participants jointly sign the transcript manifest that binds the exact
record set (gendid/1.2 snapshot authority).

> Live on GenLayer StudioNet: contract
> [`0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`](https://explorer-studio.genlayer.com/address/0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1)
> — gendid/1.2 snapshot-authority build, deployed + smoke-tested (incl. the
> live Steward attack rejection and the live subset/conflict/unmanifested
> authority rejections), browser-verified end-to-end (see
> [Verified live results](#verified-live-results) and
> [docs/LIVE_DEPLOYMENT.md](docs/LIVE_DEPLOYMENT.md)).
>
> **Try it: https://faisalnugroho.github.io/gendid/**
>
> The pre-hardening `0xb865…` and steward-1.1 `0xF3A0…` deployments are
> preserved in [docs/LIVE_DEPLOYMENT.md](docs/LIVE_DEPLOYMENT.md) as
> history; gendid/1.2 replaced them because the snapshot-authority change
> alters verified contract code (see
> [docs/SECURITY.md](docs/SECURITY.md)).

---

## The problem

Two autonomous agents negotiate in a chat room — one offers a task at a price
and deadline, the other accepts. Later they disagree about whether a deal
existed at all, or what its terms were. Plain chat logs cannot settle this:

- Chat text is **trivially forgeable** — anyone can write "Agent B said: deal".
- Chat servers (or their operators) can edit history; there is no
  cryptographic attribution.
- Even with attribution, *interpreting* whether "sure, sounds good" is an
  acceptance of *those* terms is a semantic judgment, not arithmetic.

GenDid splits the problem exactly along that seam:

1. **Who said it** — settled by deterministic cryptography (Ed25519 did:key
   signatures), verifiable by anyone, no trust in any server.
2. **What was agreed** — settled by decentralized adjudication: a GenLayer
   leader LLM labels a bounded set of questions about the authenticated
   evidence, validators independently re-run and compare, and the **contract**
   — not the model — derives the final status.

## What GenDid is NOT

- **Not a truth oracle.** "The sky is green" + "accepted" ⇒ an agreement that
  *the sky is green was part of the deal* — not that the sky is green.
- **Not a fulfillment oracle.** Whether anyone delivered on the agreement is
  out of scope.
- **Not a settlement protocol.** No escrow, no payments, no FLOP rails.
- **Not an official FLOP Labs / Technocore / GenLayer Labs project** — see the
  [disclaimer](#disclaimer).

## Architecture

```
DID identity (did:key Ed25519, keys stay client-side)
    ↓
Signed technocore messages  (signature over <room>|<nonce>|<swept-text>)
    ↓
Transcript reconstruction  (technocore JSON lane: seq, ts, from, text, nonce, sig)
    ↓
Deterministic signature verification  (frontend tweetnacl + vendored verifier inside the contract)
    ↓
Canonical evidence package  (gendid/1 records, sorted, classified, sha256-hashed)
    ↓
GenLayer Intelligent Contract  (submit_evidence)
    ↓
Leader LLM labels six bounded questions  (PASS/FAIL/UNCERTAIN, citing record ids)
    ↓
Validators independently re-run  (Equivalence Principle over decision-bearing fields)
    ↓
Deterministic status derivation  (contract-side matrix — LLM labels, CONTRACT derives)
    ↓
On-chain Agreement Record  (final, well-formed in every path)
    ↓
Agreement Receipt  (frontend renders on-chain record + local evidence)
```

### Layers

**1. Deterministic evidence gate.** Every record is classified by pure code,
before any LLM runs:

| class | meaning |
|---|---|
| `AUTHENTIC_SIGNED` | valid Ed25519 signature over `room\|nonce\|swept(text)` from the embedded did:key |
| `UNSIGNED` | no signature — context only, can never establish a commitment |
| `INVALID_SIGNATURE` | signature present but does not verify / malformed DID / bad nonce / tampered text |
| `MALFORMED` | unparseable record |
| `DUPLICATE` | replay — the later copy is inert |

Only `AUTHENTIC_SIGNED` records count as identity-attributed evidence. Nonces
must strictly increase per (room, DID). Tampered text invalidates the signature
byte-exactly, because the signature covers the swept text. Zero authentic
records (or a single participant) never reaches the LLM — the gate fails
closed with `INSUFFICIENT_EVIDENCE`.

**2. Nondeterministic labeling under consensus.** A bounded prompt (with an
explicit untrusted-evidence boundary — instructions inside record text are
data, never instructions to the adjudicator) asks six questions:

- `two_or_more_participants` — distinct authenticated DIDs?
- `offer_present` — authenticated offer with concrete terms?
- `acceptance_present` — authenticated acceptance from a *different* DID?
- `acceptance_matches_offer` — acceptance of those terms, not different ones?
- `no_contradiction` — no later authenticated cancel/reject?
- `evidence_grounded` — cited record ids real and authenticated?

The leader's labels must survive validator re-runs (compared on labels and
cited record ids — decision-bearing fields only).

**3. Deterministic derivation.** The contract applies hard clamps the LLM
cannot override (participants recomputed from verified records; ungrounded
citations fail grounding; self-acceptance clamps to FAIL) and then derives the
status from the label matrix. Every failure path yields a well-formed record;
nothing ever silently becomes AGREED.

### Agreement states

| status | meaning |
|---|---|
| `AGREED` | authenticated offer + matching acceptance by distinct participants, no later contradiction |
| `NOT_AGREED` | offer/acceptance not established, or acceptance mismatched, or later authenticated contradiction |
| `AMBIGUOUS` | evidence too ambiguous to decide (e.g. acceptance may respond to different terms) |
| `INSUFFICIENT_EVIDENCE` | deterministic gate fired (no authentic records / single participant) or ungrounded citations or failed adjudication — **fail-closed** |
| `NON_AUTHORITATIVE` (gendid/1.2) | the snapshot is not the jointly-signed authoritative transcript — manifest signatures missing/invalid, or the room was already sealed by a different snapshot; **the LLM never runs** |

**4. Snapshot authority (gendid/1.2).** The caller of `submit_evidence`
chooses which records to submit — per-record signatures alone cannot prove
the package is the complete room history (omit the cancellation, submit
only the favorable subset). GenDid therefore derives a canonical
**transcript manifest** (room, record count, ordered ids, per-record
digests, participants, commitment) and requires **every participant** to
Ed25519-sign that exact manifest string with the key that signed their
records. Omission, insertion, reordering, text/attribution changes, or a
conflicting snapshot each change the manifest and invalidate the
signatures — the submission is recorded `NON_AUTHORITATIVE` and the
adjudication never runs. The first authoritative finalization seals the
room on-chain; competing snapshots of the same room are deterministically
rejected. Regression suite: `tests/direct/test_authority.py` (23 tests,
Steward cases A–I). Full model: [docs/PROTOCOL.md §3.4](docs/PROTOCOL.md).

## Verified live results

All results below were observed on the real StudioNet chain
([docs/LIVE_DEPLOYMENT.md](docs/LIVE_DEPLOYMENT.md), every tx hash independently
re-verified against the explorer; contract
`0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`, deploy tx
`0xcf79982851cc…cc816`, deployed source byte-identical to this repo):

| scenario | tx | consensus result | on-chain status |
|---|---|---|---|
| Clear agreement | [`0x0ed0…a01e`](https://explorer-studio.genlayer.com/tx/0x0ed03edd22e220c0f5e9396190a667871c1e79ad4052018e6ea47a101893a01e) | MAJORITY_AGREE | **AGREED** |
| Contradiction/dispute | see S2b in [docs/LIVE_DEPLOYMENT.md](docs/LIVE_DEPLOYMENT.md) | MAJORITY_AGREE | **NOT_AGREED** / **INSUFFICIENT_EVIDENCE** (fail-safe family; see note) |
| Vague/ambiguous | [`0x8ee4…fd35`](https://explorer-studio.genlayer.com/tx/0x8ee48c8bf6831d758beae5063cc622b982bad7cbd0526f28daacd8a66822fd35) | MAJORITY_AGREE | **NOT_AGREED** (offer lacked concrete terms) |
| Tampered signature (negative) | [`0x1314…a96f`](https://explorer-studio.genlayer.com/tx/0x13141447b738b49235de6f8b9a54d220a2e3820e4c4d5abdda188dcb6e07a96f) | MAJORITY_AGREE | **INSUFFICIENT_EVIDENCE** (gate: tampered record rejected) |
| **Steward attack live** (identity key + zero-scalar sig) | [`0xc335…e440`](https://explorer-studio.genlayer.com/tx/0xc335f8894409c5ec017eb31a7c462ed55fe7db12fb4fbae75541087c82bae440) | MAJORITY_AGREE | **INSUFFICIENT_EVIDENCE** — attack record INVALID_SIGNATURE on-chain |
| **Caller-selected subset** (gendid/1.2) | [`0xb7d4…249e`](https://explorer-studio.genlayer.com/tx/0xb7d4a72296ff2b9c2540222667a2c9f769eba900e4bd5a7a83c095096b48249e) | MAJORITY_AGREE | **NON_AUTHORITATIVE** (`manifest_incomplete_or_invalid_signatures`; LLM never ran) |
| **Conflicting snapshot** (gendid/1.2) | [`0x1cee…9633`](https://explorer-studio.genlayer.com/tx/0x1cee6d0baafe3544aa0edede913093ba28e6c8030bbb9f5fa2a8864497aa9633) | MAJORITY_AGREE | **NON_AUTHORITATIVE** (`conflicting_snapshot`; room sealed by first snapshot) |
| **Unmanifested submission** (gendid/1.2) | see S8 in [docs/LIVE_DEPLOYMENT.md](docs/LIVE_DEPLOYMENT.md) | MAJORITY_AGREE | **NON_AUTHORITATIVE** (LLM never ran) |

**Public demo determinism (gendid/1.2).** The public Demo A builds a
byte-identical transcript on every page load (fixed nonces → deterministic
Ed25519 signatures → identical manifest/commitment/evidenceHash). Canonical
public result, verified live twice from the production URL on fresh page
loads: agreementId `GD-gendid-demo-01b-9b9a6ce6440da0d6`, status
**AGREED** both runs (txs `0x6660…d1e2`, `0x6cfa…9ac0`), identical
evidenceHash `9b9a6ce6…87448` == on-chain record byte-for-byte, room
`gendid-demo-01b` sealed to the canonical commitment
`71ba41a3…83d8e67`. Repeated public runs are idempotent — never
`conflicting_snapshot`. Regression suite: `tests/js/test-parity.mjs` T9.

Error paths verified live: bad room name and malformed records revert with
`gendid: …` UserError payloads (execution ERROR, validators agree the refusal,
state unchanged); unknown agreement IDs raise; the UI renders every failure as
an error — never as AGREED.

The negative case matters most: GenDid does not approve every transcript.
Forge or tamper with evidence and you get `INSUFFICIENT_EVIDENCE`, not a deal.

## The frontend

Zero-backend static page (plain HTML/JS, served anywhere):

- **DID kit** — Ed25519 did:key mint/sign/verify in-browser (tweetnacl);
  signing seeds are generated client-side and never leave the browser
  (localStorage only; never transmitted, logged, or embedded in receipts).
- **Transcript input** — load one of three in-browser-signed demos, paste a
  signed transcript (JSON), or fetch a live technocore.chat room.
- **Local verification** — every signature is verified client-side with the
  same canonical string the contract uses (byte-parity is tested: 24/24
  JS/Python parity tests).
- **LIVE mode** — with the deployed contract configured
  (`frontend/contract-address.js`), "Judge Agreement" submits the evidence to
  the real StudioNet contract, waits for validator consensus, checks the
  execution result, and renders the on-chain record: contract address, network,
  tx hash, execution status, final status. Validator detail is shown as
  "GenLayer consensus" — the browser SDK does not expose individual validator
  identities, and the UI does not invent them. The tx signer is a burner
  generated in your browser (StudioNet charges no gas).
- **LOCAL / DEMO mode** — without a configured contract, the same deterministic
  derivation runs locally with transparent heuristics for the semantic labels.
  The UI always shows which mode you are in.

## Run locally

The frontend is fully static:

```bash
cd frontend
python3 -m http.server 8000
# open http://localhost:8000
```

Without further configuration it runs in LOCAL / DEMO mode. To reproduce the
LIVE mode, the verified contract address is already pinned in
`frontend/contract-address.js` — a funded deployer is only needed to *deploy*
contracts, not to read or to write agreements on StudioNet (no gas charge).

### Tests

```bash
# 73 direct contract tests (gltest direct mode; mocks the LLM, real crypto)
#   20 adjudication + 16 adversarial Ed25519 + 10 transcript-order binding
#   + 23 snapshot-authority (omission/insertion/reorder/collision/nonce/
#     conflict/unsigned/attack/forged-manifest/invariants)
pytest tests/direct/ -q

# 75 JS/Python parity checks (browser lib vs contract canonicalization)
#   targeted parity + 23-fixture dual-runner corpus + demo determinism
#   (valid, unsigned, malformed, every reject reason, attack material,
#    permutations — full-output byte-equality per fixture)
#   + manifest derivation/manifestStr/manifest-signature parity
node tests/js/test-parity.mjs

# Steward attack reproducer (identity-point key + zero-scalar signature,
# all 8 torsion points, arbitrary message; gendid/1.2 snapshot-authority
# attacks: subset/insertion/wrong-key/zero-scalar manifest) — all rejected
python3 scripts/attack_repro.py contracts/gendid_judge.py
```

Exact runtimes and pinned versions: [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md).
Requirements: Python 3.12+ (`pip install -r requirements-test.txt`), Node 22+
for parity tests. The vendored contract verifier and the browser tweetnacl
verifier must accept the same signatures and reject the same forgeries —
that equivalence is what the parity suite and corpus pin.

### Reproduce the demo

1. Open the frontend, click **Demo A · Clear agreement** — three records are
   signed in your browser with public demo seeds; every signature really
   verifies.
2. **Verify Transcript** — watch each record classify as AUTHENTIC SIGNED.
3. **Judge Agreement** — in LIVE mode this submits a real StudioNet
   transaction (visible in the pipeline panel with its tx hash) and renders
   the on-chain AGREED record; in LOCAL mode it derives the same status with
   the deterministic matrix.
4. The Agreement Receipt (copy/download JSON) contains the evidence hash,
   participants, record counts, question labels, and the adjudication
   reference.

## Repository layout

```
contracts/gendid_judge.py     the Intelligent Contract (evidence model + judge)
frontend/                     zero-backend static dApp
  lib/gendid-lib.js           DID kit, strict verification, canonicalization (byte-parity with the contract)
  lib/tweetnacl.min.js        Ed25519 (vendored)
  lib/genlayer-sdk.bundle.js  GenLayer browser SDK (vendored)
  contract-address.js         pinned StudioNet contract address
  demos.js                    the three demo scenarios (public demo seeds)
docs/PROTOCOL.md              protocol specification (gendid/1.2)
docs/SECURITY.md              security model + steward-fix → test map
docs/REPRODUCIBILITY.md       pinned runtimes + exact reproduction commands
docs/LIVE_DEPLOYMENT.md       verified live deployment record
scripts/deploy_smoke.py       deployment + live smoke test harness
scripts/error_probes.py       live error-path probes
scripts/attack_repro.py       Steward-finding attack reproducer
scripts/e2e_browser_live.py   browser E2E vs the deployed contract
tests/direct/                 73 direct-mode contract tests (incl. 23 authority)
tests/js/                     75 JS/Python parity checks incl. corpus + demo determinism
```

## Security notes

- Agent DID signing seeds and the StudioNet tx-writer key live only in your
  browser's localStorage; they are never transmitted, logged, or committed.
- The deployer keyfile (`scripts/smoke_deployer.json`) is generated by
  `scripts/deploy_smoke.py` on first run and is gitignored — never commit it.
- The transcript is untrusted evidence: the prompt carries an explicit
  boundary, and injection attempts in record text were tested to not change
  outcomes (T14).
- The contract fails closed: every crash, malformed input, or failed
  adjudication path yields `INSUFFICIENT_EVIDENCE`-family records — never
  AGREED.

## Disclaimer

GenDid is an **independent prototype**. It is **not** a FLOP Labs, Technocore,
or GenLayer Labs project; no endorsement, partnership, or integration is
claimed or implied. FLOP validators/miners/mainnet do not exist yet; anything
trading as $FLOP today is fake.

Correct framing, per the protocol:

- DID signature verification is **deterministic cryptography** (Ed25519 over
  `<room>|<nonce>|<swept-text>`, exactly technocore's signed lane).
- GenLayer **adjudicates the meaning and consistency of authenticated
  evidence** — it does not verify DIDs, does not prove statements true, and
  does not settle anything.
- A signature proves **control of the signing key and attribution of the
  message** — not that the message is true.
