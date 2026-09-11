# GenDid — Live Deployment Record (VERIFIED ONLY)

Date: 2026-09-11 (UTC) — **gendid/1.2 snapshot-authority build**
(Supersedes the 2026-09-10 gendid/1.1 and 2026-09-08 gendid/1 deployments;
those records are preserved below for history. The `0xF3A0…` and `0xb865…`
contracts predate the snapshot-authority hardening and are NOT the
production contract anymore.)
Everything below was observed on-chain. No field is fabricated.

## Network

- **StudioNet** (GenLayer Studio Network), chain id 61999
- RPC: `https://studio.genlayer.com/api` (as shipped in genlayer-py `studionet`)
- Explorer: `https://explorer-studio.genlayer.com`
- Deployer account: `0x5E77b8D3655918454134a2d5BAd9dd76B741b4cB`
  (funded via the official Studio faucet RPC `sim_fundAccount` — the
  same mechanism as the Studio account-selector 💧 button; keyfile
  `scripts/smoke_deployer.json`, gitignored, never printed/committed)

## Contract (gendid/1.2 — CURRENT PRODUCTION)

- **Address: `0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`**
- Deploy transaction: `0xcf79982851cc510fe09e006f7d9f721cd23704c1ee93fe0d9b9f8f6ee96cc816`
  (FINALIZED, MAJORITY_AGREE, leader exec SUCCESS)
- Explorer: https://explorer-studio.genlayer.com/address/0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1
- **Deployed source byte-identity**: sha256 of the deploy tx's
  `data.contract_code` == sha256 of `contracts/gendid_judge.py` at the
  release commit — 62,511 bytes,
  `6497e5f5b7f78842f38a7263a8b8dc033999a0aecfa31bced3835c6ac15bc8ac`.
- Why redeployed: the gendid/1.2 snapshot-authority change (jointly-signed
  transcript manifest, room seals, NON_AUTHORITATIVE state, new
  `submit_evidence` signature) changes verified contract code and storage —
  the 1.1 contract cannot be patched in place; an upgrade means a new address.
- The exact Steward attacks were run LIVE against this contract: the
  Ed25519 identity-point attack (S4b) and the gendid/1.2 authority attacks
  (S6 caller-selected subset, S7 conflicting snapshot, S8 unmanifested) —
  all rejected on-chain, none AGREED.

## Live test transactions (gendid/1.2 contract, all FINALIZED)

| # | Scenario | Tx | Vote | Leader exec | On-chain status |
|---|---|---|---|---|---|
| S1 | Clear agreement (full manifest authority) | `0x0ed03edd22e220c0f5e9396190a667871c1e79ad4052018e6ea47a101893a01e` | MAJORITY_AGREE | SUCCESS | **AGREED** |
| S2 | Contradiction/dispute | `0xe62f171ccd70d2890c964bc3b0e87fdbfa26a87ce4162c8b2cb303059e27e858` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** (see note) |
| S2b | Contradiction/dispute (re-run, fresh room) | `0x6c7b11b39571ae7af5bc5ab54aa646038ec2ac321f998e7a23a20dc94da66e91` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** (grounded: no_contradiction FAIL) |
| S3 | Vague/ambiguous (no concrete terms) | `0x8ee48c8bf6831d758beae5063cc622b982bad7cbd0526f28daacd8a66822fd35` | MAJORITY_AGREE | SUCCESS | **NOT_AGREED** (offer lacked concrete terms) |
| S4 | Negative: tampered signature | `0x13141447b738b49235de6f8b9a54d220a2e3820e4c4d5abdda188dcb6e07a96f` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** (single participant after rejection) |
| S4b | **STEWARD ATTACK (identity key + zero-scalar sig)** | `0xc335f8894409c5ec017eb31a7c462ed55fe7db12fb4fbae75541087c82bae440` | MAJORITY_AGREE | SUCCESS | **INSUFFICIENT_EVIDENCE** — attack record INVALID_SIGNATURE, never AGREED |
| S6 | **AUTHORITY: caller-selected subset + full-manifest sigs** | `0xb7d4a72296ff2b9c2540222667a2c9f769eba900e4bd5a7a83c095096b48249e` | MAJORITY_AGREE | SUCCESS | **NON_AUTHORITATIVE** (`manifest_incomplete_or_invalid_signatures`; questionLabels empty — LLM never ran) |
| S7a | Conflicting snapshots — first | `0xc8c010fcee63c0dd649117d49dd1db68bd010273e526b00ee60837308ea464fe` | MAJORITY_AGREE | SUCCESS | **AGREED** (seals room) |
| S7b | **Conflicting snapshots — second** | `0x1cee6d0baafe3544aa0edede913093ba28e6c8030bbb9f5fa2a8864497aa9633` | MAJORITY_AGREE | SUCCESS | **NON_AUTHORITATIVE** (`conflicting_snapshot`) |
| S8 | **AUTHORITY: unmanifested (no participant sigs)** | `0xc2d437f805b21658493b1e1fb7e2e310b3c701181f366ff955deeae1c26614eb` | MAJORITY_AGREE | SUCCESS | **NON_AUTHORITATIVE** (`manifest_incomplete_or_invalid_signatures`; LLM never ran) |

**Room seal (S7):** `get_room_seal("gendid-live-s7")` read back live =
`02155affb205d51cee8cbe58d3e2eceac714018b1e1e6f4bbff38df196121944` —
equals S7a's transcriptCommitment: the room is pinned to the FIRST
authoritative snapshot; the second (altered) snapshot is deterministically
non-authoritative forever.

**Note on S2 (the grounding gate working live, again):** as on the 1.1
deployment, the first dispute run's live validator LLM returned
otherwise-PASS labels with invented citations; the deterministic grounding
gate marked them FAIL and derived INSUFFICIENT_EVIDENCE (fail-safe, never
AGREED). The S2b re-run on a fresh room shows the grounded path: correct
citations → no_contradiction FAIL → NOT_AGREED. Both outcomes are
non-AGREED; invented evidence can never produce AGREED.

**S6 is the exact second-Steward scenario:** the truthful transcript ends
in a cancellation; the caller submits only offer+acceptance (all records
individually validly signed) carrying the FULL manifest's signatures.
On-chain: NON_AUTHORITATIVE — the derived manifest of the 2-record subset
differs from the signed 3-record manifest, so the signatures do not
verify against it, and the adjudication never runs.

On-chain agreement records (read back via `get_agreement`): see
`docs/deployment_log.json` (checked into the repo) for the full records
including recordCounts, questionLabels, and the transcriptCommitment for
every scenario above (under the `gendid/1.2 (CURRENT PRODUCTION)` key).

## Browser E2E (gendid/1.2 contract, full live path, 2026-09-11)

- Driven with Playwright against the real frontend (`scripts/e2e_browser_live.py`,
  local static serve of the deployed frontend/ tree): Demo A → browser strict
  verification (3 AUTHENTIC_SIGNED, 3/3 manifest signatures) → LIVE Judge
  submit → on-chain status.
- The dApp UI pinned and displayed the new contract
  (`studionet · contract 0xfb861614…8dD4B1`).
- Live tx `0x6dbe829e0f4ffe539550919987078148ccb0c02621d744cc01c7df371c91f2ff`
  (in-browser burner writer) — on-chain status **AGREED**.
- **Canonicalization + authority parity, live**: browser-computed
  `evidenceHash 3dc3e204fbca17254a12e949f1f9744086cbae53c6f03b41a1871038f1f03bbe`
  == the on-chain record's evidenceHash (read back via `get_agreement` for
  `GD-gendid-demo-01-3dc3e204fbca1725`,
  `scripts/e2e_readback_v12.py`), byte-identical; transcriptCommitment
  `1836a917253d145e3cccc29048666bec02b556f4ad706b21540e4a2e052530be` read
  back on-chain; all six question labels PASS. The in-browser manifest
  signing (demo participant keys) produced an authoritative snapshot that
  passed the on-chain authority gate.

## Public production-URL E2E (deterministic demo, 2026-09-11)

After the deployment above, the public Demo A was made deterministic
(buildDemo previously used a random nonce jitter, which collided with the
room seal: room `gendid-demo-01` was sealed by a random snapshot, and
every later public run was NON_AUTHORITATIVE/conflicting_snapshot — the
contract behaving CORRECTLY, the demo was nondeterministic). Fix: fixed
nonces + fresh canonical room. Commit `ca90bd2`.

Canonical public demo (all verified from
`https://faisalnugroho.github.io/gendid/` on fresh page loads,
`scripts/e2e_production_url.py`):

- Room: `gendid-demo-01b`
- agreementId: `GD-gendid-demo-01b-9b9a6ce6440da0d6`
- evidenceHash: `9b9a6ce6440da0d6a0b2697b7d521ab19bd6823281879099ab5e836ff287a448`
- transcriptCommitment == room seal:
  `71ba41a30cd313fe4f4b36b44e9197d5794ac73db1f38fc74054dd86383d8e67`
- status: **AGREED**, finalized, all six labels PASS
- Run 1 (fresh load) tx `0x6660621ee269e771d45a9dff202afb6fc7462bd1e782e49f69b201b2476cd1e2`
- Run 2 (fresh load) tx `0x6cfac3e2e4e3f084ed984d39d7a4a41c4e0d496068a8a1d77eae3fdbe77c9ac0`
- Both runs FINALIZED, exec SUCCESS, 3-4 validator agrees per round; both
  produce the IDENTICAL canonical agreementId/evidenceHash (idempotent
  resubmission of the identical manifest — never conflicting_snapshot).
- Browser evidenceHash == on-chain evidenceHash, byte-identical; room seal
  pins the canonical commitment. Old room `gendid-demo-01` remains sealed
  under the historical random snapshot — permanent, honest history.

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
