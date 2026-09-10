#!/usr/bin/env python3
"""Re-run S2 (dispute) and S3 (vague) with FRESH rooms against the deployed
gendid/1.1 contract — checking whether the live LLM grounds citations
correctly this time (S2's first run: LLM mis-cited ids, contract's grounding
gate overrode to fail-safe INSUFFICIENT_EVIDENCE — requirement-6 proof).
Safe-family invariant either way: never AGREED.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, "scripts")
from deploy_smoke import (  # noqa: E402
    ACCEPT_TEXT, CANCEL_TEXT, OFFER_TEXT, VAGUE_ACCEPT, VAGUE_OFFER,
    adjudicate, load_account, make_record, new_agent,
)
from genlayer_py import create_client  # noqa: E402
from genlayer_py.chains import studionet  # noqa: E402

ADDR = "0xF3A0Fc40Cc75FbCb9Ae24E1250D67cEe5A13158a"


def main():
    account = load_account()
    client = create_client(chain=studionet, account=account)

    print("--- S2b DISPUTE (fresh room): expect NOT_AGREED (or fail-safe) ---",
          flush=True)
    a2, b2 = new_agent(), new_agent()
    room2 = "gendid-live-s2b"
    recs2 = [
        make_record(a2, room2, 1, OFFER_TEXT, "1757318120001"),
        make_record(b2, room2, 2, ACCEPT_TEXT, "1757318120002"),
        make_record(b2, room2, 3, CANCEL_TEXT, "1757318120003"),
    ]
    s2b = adjudicate(client, ADDR, "S2b", room2, recs2, "NOT_AGREED")
    print(json.dumps({k: s2b[k] for k in ("status", "match")}, indent=2))

    print("--- S3b VAGUE (fresh room): expect AMBIGUOUS family ---", flush=True)
    a3, b3 = new_agent(), new_agent()
    room3 = "gendid-live-s3b"
    recs3 = [
        make_record(a3, room3, 1, VAGUE_OFFER, "1757318130001"),
        make_record(b3, room3, 2, VAGUE_ACCEPT, "1757318130002"),
    ]
    s3b = adjudicate(client, ADDR, "S3b", room3, recs3,
                     ["AMBIGUOUS", "INSUFFICIENT_EVIDENCE", "NOT_AGREED"])
    print(json.dumps({k: s3b[k] for k in ("status", "match")}, indent=2))

    out = {"s2b": {k: s2b[k] for k in ("status", "match", "agreementId", "tx")},
           "s3b": {k: s3b[k] for k in ("status", "match", "agreementId", "tx")},
           "s2b_labels": s2b["record"].get("questionLabels"),
           "s3b_labels": s3b["record"].get("questionLabels")}
    Path("/tmp/re_smoke.json").write_text(json.dumps(out, indent=2))
    print("saved /tmp/re_smoke.json")


if __name__ == "__main__":
    main()
