# GenDid — Live Deployment Record (VERIFIED ONLY)

Date: 2026-09-08 (UTC)
Everything below was observed on-chain. No field is fabricated.

## Network

- **StudioNet** (GenLayer Studio Network), chain id 61999
- RPC: `https://studio.genlayer.com/api` (as shipped in genlayer-py `studionet`)
- Explorer: `https://explorer-studio.genlayer.com`
- Deployer account: `0x5E77b8D3655918454134a2d5BAd9dd76B741b4cB`
  (funded 10 GEN via the official Studio faucet RPC `sim_fundAccount` — the
  same mechanism as the Studio account-selector 💧 button; keyfile
  `scripts/smoke_deployer.json`, gitignored, never printed/committed)

## Contract

- **Address: `0xb86505e421cfc256df41900c0c1203cBD26415bf`**
- Deploy transaction: `0x8dd23d9603cd043b5748ede94339084223e1746d481214ac62cae69f33666494`
  (FINALIZED, MAJORITY_AGREE, leader exec SUCCESS)
- Explorer: https://explorer-studio.genlayer.com/address/0xb86505e421cfc256df41900c0c1203cBD26415bf
- Two earlier same-code deploys (0xF163…E00, 0x27cF…04A) were superseded by the
  final one after live integration fixes (see "Contract changes" below).

## Live test transactions (all on the final contract above)

| # | Scenario | Tx | Vote | Leader exec | On-chain status |
|---|---|---|---|---|---|
| S1 | Clear agreement (demo A fixture) | `0xec7f73f84e205f4c5bdf0f29e42da81723ff63d8b4c7124eef2627cb381d767f` | MAJORITY_AGREE | SUCCESS | **AGREED** |
| S2 | Contradiction/dispute (demo B fixture) | `0xb8518b8758622d942f81e9ad595cd9803afe250a08bbcaf49a1800b771c140e4` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** |
| S3 | Ambiguous (demo C fixture) | `0xa6128b28a2c26858e005feb5e2513dd7fb7122e9103906d7f17b324069f17367` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** |
| S4 | Negative: tampered signature | `0xc7d1a129acd10cc50231c4dba77ca9910e61eb360f31965856c1a4baa6d2bf2d` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** |

On-chain agreement records (read back via `get_agreement`):

- `GD-gendid-live-s1-aba81600813fa2b2` — AGREED (2 participants, 4 grounded terms)
- `GD-gendid-live-s2-1cde5c8c99968624` — NOT_AGREED (no_contradiction=FAIL)
- `GD-gendid-live-s3-54b72220b93023c0` — NOT_AGREED (offer_present=FAIL)
- `GD-gendid-live-s4-fe4df72b35485afd` — INSUFFICIENT_EVIDENCE (deterministic
  gate: tampered record rejected → single authentic participant)

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
- Deployment URL: not yet deployed to a public host (static site; deployment
  is out of scope for this round per the stop condition).

## Regression summary (after final contract changes)

- 20/20 direct contract tests (gltest direct mode) — PASS
- 24/24 JS/Python parity tests (node) — PASS
- Frontend parsing/demo checks (node syntax + demo integrity) — PASS
- Live integration checks (S1–S5, error probes, browser E2E) — PASS
  (S3 status family mismatch vs pre-deployment annotation: documented above)
