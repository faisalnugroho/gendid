# GenDid — Reproducibility Guide (gendid/1.2)

Exact runtimes, pinned dependencies, and commands an independent engineer
needs to reproduce the full test suite from a clean checkout. The CI
workflow (`.github/workflows/tests.yml`) runs exactly these commands —
there is no CI-only path.

## Toolchain (pinned)

| component | version | where pinned |
|---|---|---|
| Python | 3.12 (`actions/setup-python@v5` with `python-version: "3.12"`) | `.github/workflows/tests.yml` |
| Node.js | 22 (`actions/setup-node@v4` with `node-version: "22"`) | `.github/workflows/tests.yml` |
| package manager | pip (stdlib venv, `python -m venv`) + npm (only for vendored browser deps, none needed to run tests) | workflow |
| `genlayer-test` | `==0.29.2` | `requirements-test.txt` |
| `pytest` | `==8.3.5` | `requirements-test.txt` |
| `cryptography` | `>=43.0.1,<44` (test-only; the contract itself is pure stdlib) | `requirements-test.txt` |
| `requests` | `>=2.32.0,<3` (test-only) | `requirements-test.txt` |
| GenVM runner | tarball `genvm-universal-v0.3.0-rc7.tar.xz`, resolved by the contract header `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` → genvm v0.3.0-rc7 | seeded in CI from the official release `github.com/genlayerlabs/genvm/releases/download/v0.3.0-rc7/genvm-runners-all.tar.xz` |

Why `genlayer-test==0.29.2` and not 1.x: the 1.x line is a breaking rewrite
with a different plugin surface; 0.29.2 is the newest line that matches the
`gltest direct` mode and the `py-genlayer` runner pin above. The version
cannot float because the runner tarball is content-addressed by the
contract header (a newer gltest would try to resolve a newer runner).

`cryptography` is a range, not an exact pin, because it ships prebuilt
wheels per-platform (manylinux/mac-arm) whose exact build differs per
platform; the API surface used (Ed25519 private key sign + public key
bytes) is stable across the whole range. Everything the contract itself
runs is pure Python stdlib — no third-party import exists inside the
GenVM.

`gltest direct mode` downloads the GenVM runner at first run into
`~/.cache/gltest-direct/`. CI pre-seeds the exact tarball (see workflow
step "Seed GenVM runner tarball") so the runner version is deterministic
and no floating download occurs.

## Exact commands (clean environment)

```bash
# 1. checkout
git clone https://github.com/faisalnugroho/gendid
cd gendid

# 2. Python environment (3.12 required by genlayer-py: collections.abc.Buffer)
python3.12 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-test.txt

# 3. seed the GenVM runner (once; skip if ~/.cache/gltest-direct already has it)
python - <<'EOF'
import urllib.request, os
home = os.path.expanduser('~/.cache/gltest-direct')
os.makedirs(home, exist_ok=True)
dst = home + '/genvm-universal-v0.3.0-rc7.tar.xz'
if not os.path.exists(dst):
    urllib.request.urlretrieve(
        'https://github.com/genlayerlabs/genvm/releases/download/v0.3.0-rc7/genvm-runners-all.tar.xz',
        dst)
print('seeded', dst)
EOF

# 4. contract tests (deterministic crypto layer, adjudication, gates,
#    Steward adversarial Ed25519, snapshot authority, order binding)
cd tests/direct
python -m pytest test_adversarial_ed25519.py test_authority.py \
    test_gendid_judge.py test_order_binding.py -v
#    -> 73 passed

# 5. browser/contract parity + dual-runner corpus + manifest parity
cd ../..
node tests/js/test-parity.mjs
#    -> 61 passed, 0 failed

# 6. Steward attack reproducer (identity-point key + zero-scalar sig,
#    8 torsion points, and the gendid/1.2 snapshot-authority attacks)
python scripts/attack_repro.py contracts/gendid_judge.py
#    -> every attack line must print ACCEPTS: False / ok=False
#       (exit code 0; the CI grep guards are in the workflow)

# 7. genvm-lint (static contract check; GENVMROOT must exist)
mkdir -p /tmp/genvmroot
genvm-lint check --json contracts/gendid_judge.py
#    -> {"ok":true,"lint":{"ok":true,"passed":3},"validate":{"ok":true,...}}
```

The parity corpus (`tests/js/test-parity.mjs`) is a dual runner: for every
fixture it executes the REAL contract code (`contracts/gendid_judge.py`,
loaded with a stubbed `genlayer` module) in Python and the REAL browser
lib (`frontend/lib/gendid-lib.js`) in Node, then compares full canonical
outputs byte-for-byte. No obsolete interpreters are hardcoded anywhere;
the runner is always `sys.executable` / the venv's Node — the historical
`usr/inv/python3` invocation is gone (grep the repo to confirm: zero
occurrences).

## Browser E2E (optional; needs a GUI-less chromium)

```bash
python -m pip install playwright && python -m playwright install chromium
python scripts/e2e_browser_live.py        # serves frontend/ on :8123, drives the real UI
```

This exercises the deployed StudioNet contract through the production
frontend (Demo A → Verify → Judge → on-chain AGREED + evidenceHash
parity). It requires the frontend pin (`frontend/contract-address.js`)
to point at the current production deployment
(see `docs/LIVE_DEPLOYMENT.md`).

## Live smoke (StudioNet; needs the gitignored deployer keyfile)

```bash
python scripts/deploy_smoke.py   # deploy + S1..S8 scenarios + readback, appends docs/deployment_log.json
```

The deployer keyfile `scripts/smoke_deployer.json` is created on first run
(funded via the official Studio faucet RPC `sim_fundAccount`) and is
gitignored — never committed.

## What CI runs

`.github/workflows/tests.yml` — on every push/PR to `main`:

1. `pip install -r requirements-test.txt`
2. seed the pinned GenVM runner tarball
3. `pytest` (the 4 direct suites, 73 tests)
4. `node tests/js/test-parity.mjs` (61 checks)
5. `python3 scripts/attack_repro.py` with fatal guards on any accepted
   attack

No Hermes-specific paths, no CI-only scripts: every step is the same
command documented above.
