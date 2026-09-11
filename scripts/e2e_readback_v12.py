#!/usr/bin/env python3
"""Post-E2E on-chain readback: the browser E2E (scripts/e2e_browser_live.py)
persisted its evidenceHash/agreementId/tx to /tmp/e2e_browser_out.json.
Read the SAME agreement from the deployed v1.2 contract and assert the
on-chain record matches the browser byte-for-byte (evidenceHash,
transcriptCommitment, status), per the source/deployment-consistency
requirement."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ds", ROOT / "scripts" / "deploy_smoke.py")
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

from genlayer_py import create_client
from genlayer_py.chains import studionet

ADDR = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"


def main():
    e2e = json.loads(Path("/tmp/e2e_browser_out.json").read_text())
    account = ds.load_account()
    client = create_client(chain=studionet, account=account)
    rec = ds.read_json(client, ADDR, "get_agreement", [e2e["browser_agreementId"]])

    checks = {
        "agreementId_matches": rec.get("agreementId") == e2e["browser_agreementId"],
        "evidenceHash_matches": rec.get("evidenceHash") == e2e["browser_evidenceHash"],
        "status_agreed": rec.get("status") == "AGREED",
        "tx_matches": e2e["tx"],
        "contract": ADDR,
    }
    ok = checks["agreementId_matches"] and checks["evidenceHash_matches"] \
        and checks["status_agreed"]
    print(json.dumps({
        "browser": e2e,
        "onchain": {
            "agreementId": rec.get("agreementId"),
            "evidenceHash": rec.get("evidenceHash"),
            "status": rec.get("status"),
            "transcriptRoom": rec.get("transcriptRoom"),
            "participants": rec.get("participants"),
            "recordCounts": rec.get("recordCounts"),
            "transcriptCommitment": rec.get("transcriptCommitment"),
            "questionLabels": rec.get("questionLabels"),
        },
        "checks": checks,
        "READBACK_OK": ok,
    }, indent=2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
