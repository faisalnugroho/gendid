# Steward Remediation — GenDid v1.2 (2026-09-13)

This document corrects the previous remediation's ambiguous wording and provides
fresh, independently checkable evidence for every point the Steward raised.

## 1. Corrected contract-history statement (supersedes prior wording)

**GenDid v1.2 materially modified the contract relative to the previous
deployment and deployed the hardened contract at
`0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`. No contract modification or
redeployment has occurred after that v1.2 deployment.**

The earlier statement that the contract was "not modified or redeployed" was
written comparing v1.2 against itself (post-deployment state) and was wrong to
omit the v1.1 → v1.2 change. Exact history:

| version | contract | deployed (UTC) | source commit |
|---|---|---|---|
| gendid/1 | `0xb86505e421cfc256df41900c0c1203cBD26415bf` | 2026-09-08 | `20f1cbe` |
| gendid/1.1 | `0xF3A0Fc40Cc75FbCb9Ae24E1250D67cEe5A13158a` | 2026-09-10 | `687b1f5` |
| **gendid/1.2 (current production)** | **`0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`** | **2026-09-11T11:36:17** | `89c9b27` (code), `c5e9976` (deploy record) |

- What changed v1.1 → v1.2: `89c9b27` "transcript snapshot authority —
  jointly-signed manifest, room seals, NON_AUTHORITATIVE state" —
  269 insertions / 18 deletions in `contracts/gendid_judge.py`
  (`git diff 687b1f5 c5e9976 --stat -- contracts/`). This changes verified
  code and storage, so it required a new deployment (new address).
- v1.2 deploy transaction:
  `0xcf79982851cc510fe09e006f7d9f721cd23704c1ee93fe0d9b9f8f6ee96cc816`
  (FINALIZED, MAJORITY_AGREE).
- Proof 0xfb… is the v1.2 contract: the deploy tx's `data.contract_code`
  (fetched live from `studio.genlayer.com` via `eth_getTransactionByHash`,
  base64-decoded) is **byte-identical** to `contracts/gendid_judge.py` —
  62,511 bytes, sha256
  `6497e5f5b7f78842f38a7263a8b8dc033999a0aecfa31bced3835c6ac15bc8ac`.
- Proof nothing changed after: `git log c5e9976..HEAD -- contracts/` is empty;
  sha256 of `contracts/gendid_judge.py` at HEAD == at `c5e9976` == the
  deployed bytes. Reproduce: `python3 scripts/steward_live_identity.py`.

## 2. Production URL — Chromium verification (fresh profiles)

`https://faisalnugroho.github.io/gendid/` was loaded in **real Chromium**
(Playwright Chromium 151.0.7922.34, headless, fresh profile per run — empty
cache/storage, no service worker):

- 3/3 fresh contexts: HTTP 200, full load 2.0–2.7 s, zero JS errors, zero
  failed requests, `window.GENDID_CONTRACT = 0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1`,
  mode tag **GENLAYER · LIVE** (`studionet · contract 0xfb861614…8dD4B1`).
- DNS 4.4 ms (185.199.108–111.153 + IPv6), TLS 1.3 handshake 70 ms,
  HSTS present, `cache-control: max-age=600`, edge `x-cache: MISS, age: 0`.
- External-path check with resolver pinned via Cloudflare DoH: 200 in 0.17 s.
- No external CDN dependency exists: all 7 JS assets are same-origin
  relative paths. A third-party CDN cannot block initialization.
- All 7 served assets are byte-identical (sha256) to `frontend/` at the
  production commit; served JS contains **zero** references to the retired
  `0xF3A0…` / `0xb865…` addresses.
- The Steward-side timeout could not be reproduced from 3 fresh contexts or
  the DoH-pinned path. GitHub Pages (Fastly) is reachable and serving the
  current build; the earlier timeout is consistent with a transient
  edge/regional issue in the Steward's Chrome environment, not a deployment
  defect. Reproduce: `python3 scripts/steward_env_repro.py`.

## 3. Fresh live transactions from the public URL (2026-09-13)

Two completely fresh Chromium contexts each drove the real UI
(Demo A → Verify → Judge Agreement) against the public URL. Both finalized
**AGREED** on `0xfb86…dD4B1`, each with a NEW transaction:

| run | transaction hash | vote | leader exec |
|---|---|---|---|
| 1 | `0x20080cfdb4120d467b90b310dc854e84583438a2029bde95622a9539b8e9c163` | MAJORITY_AGREE | SUCCESS |
| 2 | `0xdfb26c3c27668194b3f44bb2532348f91635d0274ef1d6cc8834418f359204d3` | MAJORITY_AGREE | SUCCESS |

Explorer (verified HTTP 200):
- https://explorer-studio.genlayer.com/tx/0x20080cfdb4120d467b90b310dc854e84583438a2029bde95622a9539b8e9c163
- https://explorer-studio.genlayer.com/tx/0xdfb26c3c27668194b3f44bb2532348f91635d0274ef1d6cc8834418f359204d3

Both are idempotent resubmissions of the same deterministic canonical
agreement (identical agreementId/evidenceHash, distinct tx hashes):

- agreementId: `GD-gendid-demo-01b-9b9a6ce6440da0d6`
- evidenceHash: `9b9a6ce6440da0d6a0b2697b7d521ab19bd6823281879099ab5e836ff287a448`
- transcriptCommitment / room seal (`get_room_seal("gendid-demo-01b")`):
  `71ba41a30cd313fe4f4b36b44e9197d5794ac73db1f38fc74054dd86383d8e67`
- status **AGREED**, finalized=true, protocolVersion **gendid/1.2**
- manifest authority verified on-chain for both participants:
  `did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK`,
  `did:key:z6MktULudTtAsAhRegYPiZ6631RV3viv12qd4GQF8z1xB22S`
- recordCounts: AUTHENTIC_SIGNED 3 / others 0
- questionLabels: all six PASS
- acceptedTerms: output_format JSON · deadline "Maximum latency 30 seconds" · price "5 credits"

Browser values == on-chain values for every field above (byte-for-byte),
verified by independent SDK readback
(`python3 scripts/steward_readback.py`, evidence in
`evidence/steward-remediation-2026-09-13/`).

## 4. All three contract arguments (no bypass)

`submit_evidence(room, records_json, manifest_sigs_json)`:

1. `room` = `gendid-demo-01b`
2. `records_json` = the 3-record canonical array —
   sha256 `f04a23814284b66e856b39e34495550fd7055af18117206cfbf568a055019f47`
3. `manifest_sigs_json` = `{did: Ed25519-over-manifestStr}` —
   sha256 `b04bde1ed024afb2a9fb457051b681c9532bd34b2abaf46163dfe75355f368a1`

The GenLayerSDK client was instrumented in the page's main world; exactly one
`writeContract` call occurred per run. The on-chain calldata of BOTH txs was
decoded (`genlayer_py.abi.calldata.decode`) and its three arguments hash to
the exact same values — the contract received byte-identically what the
browser generated. Python Ed25519 verification of the captured arguments:
all 3 record signatures VALID over `room|nonce|text`; both manifest
signatures VALID over the manifestStr
`gendid-demo-01b|3|gdr-gendid-demo-01b-1,…-3|<participants>|71ba41a3…`.
The recomputed manifest from the captured records carries
`protocolVersion: "gendid/1.2"`, and its transcriptCommitment equals the
sealed room commitment. No default/demo bypass exists: LIVE mode is only
active when `contract-address.js` sets `window.GENDID_CONTRACT`, and the
captured write is the sole chain write.

## 5. Python 3.12 reproducibility (fresh environment)

Fresh venv (Python 3.12.3, pip 26.2.1) — NOT the previous genlayer-venv —
installed only from `requirements-test.txt` (+ playwright, genvm-linter):

```
python3.12 -m venv .venv && pip install -r requirements-test.txt
# genlayer-test==0.29.2, pytest==8.3.5, cryptography 43.0.3,
# genlayer-py 0.16.3 (test-stack only; contract is pure stdlib)
# GenVM runner: ~/.cache/gltest-direct/genvm-universal-v0.3.0-rc7.tar.xz
# (pinned by the contract header py-genlayer:1jb45aa8…; seeded per
#  docs/REPRODUCIBILITY.md — this is the only cached binary)
```

Results in that environment:

- **73/73** direct contract tests:
  `pytest tests/direct/{test_adversarial_ed25519,test_authority,test_gendid_judge,test_order_binding}.py -v`
- Steward attack reproducer (`scripts/attack_repro.py`): identity-point key
  ACCEPTS=False, all 8 torsion points ACCEPTS=False, zero-scalar ACCEPTS=False;
  gendid/1.2 authority attacks (subset/insertion/wrong-key/zero-scalar
  manifest sigs) all rejected.
- **75/75** browser/Python parity checks: `node tests/js/test-parity.mjs`
  (JS lib vs contract Python, byte-identical canonical outputs; demo
  determinism incl. fixed nonces 1757318047000/54000/61000 — no
  Math.random).
- genvm-lint (genvm-linter 0.11.0, Python 3.12):
  `{"ok":true,"lint":{"ok":true,"passed":3},"validate":{"ok":true,…}}`

## 6. Security regression

None. Security logic is unchanged since the v1.2 code commit `89c9b27`
(byte-identity above). The 73-test suite covers: identity-point attack,
all small-order/torsion keys, zero-scalar, malleated/non-canonical/malformed
signatures, subset manifest, insertion, omission, reordering,
duplicate/collision, cross-party nonce manipulation, conflicting snapshots,
prompt-injection-as-data, and the grounding gate (validator labels with
invented citations are FAIL — never AGREED). Live on-chain attacks against
this exact contract (S4b Ed25519 identity attack, S6 subset-with-full-sigs,
S7 conflicting snapshot, S8 unmanifested) all finalized non-AGREED /
NON_AUTHORITATIVE (docs/LIVE_DEPLOYMENT.md).

## 7. Known cosmetic note (not a defect)

The site banner and one panel label use the family shorthand `gendid/1`
("gendid/1 · independent prototype", "Evidence hash (sha256, gendid/1)") —
this denotes the gendid/1 evidence-format family documented in
docs/PROTOCOL.md. Every authoritative artifact — the receipt JSON
(`protocolVersion: "gendid/1.2"`), the on-chain agreement record, the
manifest, and the contract — identifies the protocol as **gendid/1.2**.
No old protocol version is presented as production anywhere that matters.
