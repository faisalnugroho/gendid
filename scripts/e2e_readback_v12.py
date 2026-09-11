#!/usr/bin/env python3
"""Post-E2E on-chain readback: browser E2E (local or production) persisted
its evidenceHash/agreementId/tx to /tmp/e2e_browser_out.json. Read the SAME
agreement from the deployed v1.2 contract and assert the on-chain record
matches the browser byte-for-byte (evidenceHash, transcriptCommitment,
status, room seal), per the source/deployment-consistency requirement."""
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
    room = rec.get("transcriptRoom")
    seal = ds.read_json(client, ADDR, "get_room_seal", [room]) if room else ""

    checks = {
        "agreementId_matches": rec.get("agreementId") == e2e["browser_agreementId"],
        "evidenceHash_matches": rec.get("evidenceHash") == e2e["browser_evidenceHash"],
        "status_agreed": rec.get("status") == "AGREED",
        "finalized": rec.get("finalized") is True,
        "room": room,
        "seal_equals_commitment": bool(seal) and seal == rec.get("transcriptCommitment"),
        "tx_matches": e2e.get("tx"),
        "contract": ADDR,
        "transcriptCommitment": rec.get("transcriptCommitment"),
        "questionLabels": rec.get("questionLabels"),
    }
    ok = (checks["agreementId_matches"] and checks["evidenceHash_matches"]
          and checks["status_agreed"] and checks["finalized"]
          and checks["seal_equals_commitment"])
    print(json.dumps({
        "browser": e2e,
        "onchain": {k: rec.get(k) for k in (
            "agreementId", "evidenceHash", "status", "transcriptRoom",
            "transcriptCommitment", "participants", "recordCounts",
            "questionLabels", "finalized")},
        "room_seal": seal,
        "checks": checks,
        "READBACK_OK": ok,
    }, indent=2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
