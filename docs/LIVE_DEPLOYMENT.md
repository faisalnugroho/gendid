# GenDid — Live Deployment Record (VERIFIED ONLY)

Date: 2026-09-10 (UTC) — gendid/1.1 steward-hardened build
(Supersedes the 2026-09-08 gendid/1 deployment; the original record is
preserved below for history. The old `0xb865…` contract predates the
steward hardening and is NOT the production contract anymore.)
Everything below was observed on-chain. No field is fabricated.

## Network

- **StudioNet** (GenLayer Studio Network), chain id 61999
- RPC: `https://studio.genlayer.com/api` (as shipped in genlayer-py `studionet`)
- Explorer: `https://explorer-studio.genlayer.com`
- Deployer account: `0x5E77b8D3655918454134a2d5BAd9dd76B741b4cB`
  (funded via the official Studio faucet RPC `sim_fundAccount` — the
  same mechanism as the Studio account-selector 💧 button; keyfile
  `scripts/smoke_deployer.json`, gitignored, never printed/committed)

## Contract (gendid/1.1 — CURRENT PRODUCTION)

- **Address: `0xF3A0Fc40Cc75FbCb9Ae24E1250D67cEe5A13158a`**
- Deploy transaction: `0xaaa4cc91402839dd930e0fedf9a37a5f11a8e1d499d1440db32b8b836255a71a`
  (FINALIZED, MAJORITY_AGREE, leader exec SUCCESS)
- Explorer: https://explorer-studio.genlayer.com/address/0xF3A0Fc40Cc75FbCb9Ae24E1250D67cEe5A13158a
- Why redeployed: the steward hardening changed contract code (strict
  Ed25519 validation layer, canonical scan order, transcript order
  commitment, grounding gates) — the Sep-08 contract cannot be patched
  in place; an upgrade means a new address.
- The exact steward attack was run LIVE against this contract (S4b
  below): identity-point key + zero-scalar signature + arbitrary
  acceptance text → classified INVALID_SIGNATURE on-chain, transcript
  INSUFFICIENT_EVIDENCE, never AGREED.

## Live test transactions (gendid/1.1 contract, all FINALIZED)

| # | Scenario | Tx | Vote | Leader exec | On-chain status |
|---|---|---|---|---|---|
| S1 | Clear agreement (demo A fixture) | `0xba0120dab6e629937f0f538b01d1504b685f266a37e31f9c9b811a9edf55efe1` | MAJORITY_AGREE | SUCCESS | **AGREED** |
| S2 | Contradiction/dispute | `0x154789ebd0d8d9732fbdb6c982eb2a45e1d8ac8dcbbd16459b1789d6ccb88976` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** (see note) |
| S2b | Contradiction/dispute (re-run, fresh room) | `0xae16be4e05089d29045234574df7dddf9500aa377d0e82ea17a42779b0ab4011` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** |
| S3 | Vague/ambiguous (demo C fixture) | `0x29711038e9acc519aea77da5c8791ea89a6b3b880fd64571ed1b656db62e8bf3` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** (safe family) |
| S3b | Vague/ambiguous (re-run, fresh room) | `0xe004a06e3e29df75782b52f6d3aee7b155e465ba50bee15dfa13bfdc647f7932` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** |
| S4 | Negative: tampered signature | `0x9ec99d315879fe0aea1dab18c5641819ff23ac23c9892b4ffb8d4266ff12303c` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** |
| S4b | **STEWARD ATTACK (identity key + zero-scalar sig)** | `0x3c9f79a8a63c77f85192e4e77ea38b471e6ff2ed88cdcf2ebb35812d8c80ef07` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** — attack record INVALID_SIGNATURE, never AGREED |

**Note on S2 (the grounding gate working live):** on the first S2 run the
live validator LLM returned otherwise-PASS labels but cited record ids that
do not exist in the authenticated transcript. The contract's deterministic
grounding gate (`evidence_grounded`) caught the ungrounded citations,
marked them FAIL, and derived the fail-safe INSUFFICIENT_EVIDENCE instead
of trusting the leader's PASS labels — exactly the defense the Steward
required ("leader output alone is never trusted"). The S2b re-run with a
fresh room shows the grounded path: correct citations → no_contradiction
FAIL → NOT_AGREED. Both outcomes are non-AGREED; the gate makes invented
evidence unable to produce AGREED.

On-chain agreement records (read back via `get_agreement`): see
`docs/deployment_log.json` (checked into the repo) for the full records
including recordCounts, questionLabels, and the transcriptCommitment for
every scenario above.

## Browser E2E (gendid/1.1 contract, full live path, 2026-09-10)

- Driven with Playwright against the real frontend (`scripts/e2e_browser_live.py`,
  local static serve): Demo A → browser strict verification (3 AUTHENTIC_SIGNED)
  → LIVE Judge submit → on-chain status.
- Live tx `0xd63b11e57ba16495505638e4ad52a08704af1611c740a3fbb331b2ef3a6615b0`
  (in-browser burner writer) — on-chain status **AGREED**.
- **Canonicalization parity, live**: browser-computed
  `evidenceHash e9dd0be4691b2077d4f59a2055509914ef4278816035cf9f97fdae240498daef`
  == the on-chain record's evidenceHash (read back via `get_agreement` for
  `GD-gendid-demo-01-e9dd0be4691b2077`), byte-identical — the JS and Python
  implementations produce the same canonical bytes on a real consensus run.
- UI fix found during this E2E: the **Judge Agreement** button lived inside a
  section that only the judge handler itself could reveal (unclickable by a
  real user — a pre-existing bug since the first release). Verification now
  reveals the adjudication panel; fixed in `frontend/gendid-app.js`.

---

# History — gendid/1 deployment (2026-09-08, SUPERSEDED)

Everything below refers to the superseded `0xb865…` contract. It is kept
as the original verified record of that deployment.

### S3 result vs the demo annotation — honest discrepancy report

Demo C was annotated "AMBIGUOUS or INSUFFICIENT_EVIDENCE" before any live run.
Live consensus (two independent runs, different validator sets, S3 + S3b
`0x0088d00a8d20f1205d55991a12d16952216735b608ceae2259b55457053ee869`) labeled
the vague offer **offer_present=FAIL** (no concrete terms), yielding NOT_AGREED
via the derivation matrix. This is protocol-consistent (Q2 demands concrete
terms; FAIL is an affirmative "not established") but differs from the
pre-deployment annotation family. Per instructions the enum was NOT changed;
the demo annotation was updated to state the actual live family.

## Error-path probes (live, final contract)

- **Bad room name** `0x908d7557f2a0c321567ed335dbccc1277c1517f5c537ae1f95aefb5da60742b7`:
  leader exec ERROR with rollback payload `gendid: bad room name`; validators
  agreed the refusal was correct; contract state unchanged.
- **Malformed records JSON** `0x2f0f9fdc2dd3c99ad83c83a0822176238f86ca06ac81154298d350e3b53c41d4`:
  leader exec ERROR with rollback payload `gendid: records is not valid JSON`;
  state unchanged.
- **Unknown agreementId** (view): raises `execution failed` (RPC -32000).
- **Unfunded writer**: studionet does not charge tx senders — a zero-balance
  burner's submit executed, consensus-agreed, and finalized
  (`0x38d04376…` on the superseded contract). "Insufficient funds" is NOT a
  failure mode on this network; the frontend still surfaces wallet/RPC errors
  as failures, never as AGREED.

## Browser E2E (full live path through the frontend)

- Demo A clicked in the served frontend (local static server; the app is
  zero-backend static HTML/JS).
- Browser verified signatures client-side (3 AUTHENTIC), evidence hash
  `5e40b39d9bbc71b06c26…`.
- Live tx `0xe32ae1a1335115ca45e06a7a5d261fcf1d64c67715c96a2193fff8f71e22af8d`
  from the in-browser burner writer `0x16F5D13d29bc6C63B4F1C2739f68DCC9Ed0Aca70`.
- On-chain record `GD-gendid-demo-01-5e40b39d9bbc71b0` — **AGREED**; the
  agreementId embeds the exact hash the browser computed (client/chain
  canonicalization parity proven live).

## Contract changes made during deployment (all fail-live-found, minimal)

1. Prompt: transcript lines now print `gdr-<room>-<seq>` record ids (were
   `#<seq>`), so the model can cite the ids the report format demands. Found
   live: first deployment's S1 got MAJORITY_DISAGREE because models cited
   `#1`/`#2` ids that `_opt_id`/grounding dropped.
2. Equivalence comparison narrowed to decision-bearing fields (six labels +
   cited record ids); term key/value prose was being compared verbatim, which
   made validators vote on phrasing (live: identical labels + identical state
   hash, still MAJORITY_DISAGREE).
3. `raise UserError(...)` → `raise gl.vm.UserError(...)`: the pinned GenVM
   std lib does not export `UserError` via `from genlayer import *`; local
   gltest stubs masked this. Found live: E1/E2 crashed with NameError inside
   the revert (still fail-closed, but not the intended clean UserError).
   The AgentProof live pattern uses `gl.vm.UserError`.

Evidence model, canonicalization, classification, clamps, and the derivation
matrix are unchanged. After the changes: 20/20 direct tests, 24/24 JS/Python
parity tests, and all live scenarios re-verified on the final contract.

## Frontend

- `frontend/contract-address.js` pins the verified address; index.html now
  loads `contract-address.js` + `lib/genlayer-sdk.bundle.js` (both were
  referenced-but-commented before).
- Live mode: shows contract address, network (studionet, chain 61999), real
  tx hash + execution status + the on-chain record; validator detail is shown
  as "GenLayer consensus" (the SDK receipt does not expose individual
  validator identities in the browser bundle).
- Live writes are signed by an in-browser burner (generated client-side,
  stored only in localStorage; studionet charges no gas).
- Failures (chain errors, contract reverts incl. `gendid: …` UserError
  payloads) render as errors — never as AGREED.
- Deployment URL: **https://faisalnugroho.github.io/gendid/** (GitHub Pages,
  verified 2026-09-08: page loads in LIVE mode with the pinned contract
  address; demo A executed through a real StudioNet consensus round from the
  public URL — tx `0xd30b9230690c9850d4e7cf27b8682071190c6ca0cae70764f307ba8d84b820c9`
  finalized MAJORITY_AGREE and the on-chain record
  `GD-gendid-demo-01-f58655301684b609` reads AGREED; zero console errors;
  390px mobile layout verified with no horizontal overflow).

## Regression summary (after final contract changes)

- 20/20 direct contract tests (gltest direct mode) — PASS
- 24/24 JS/Python parity tests (node) — PASS
- Frontend parsing/demo checks (node syntax + demo integrity) — PASS
- Live integration checks (S1–S5, error probes, browser E2E) — PASS
  (S3 status family mismatch vs pre-deployment annotation: documented above)
