#!/usr/bin/env python3
"""GenDid live error-path probes (point 11 error handling).

Proves on the REAL chain that failures stay distinguishable from AGREED:
  E1 bad room name        -> UserError revert (leader exec ERROR, no state)
  E2 malformed records    -> UserError revert (leader exec ERROR, no state)
  E3 unknown agreementId  -> view UserError (no such record)
  E4 unfunded writer      -> client-side insufficient-funds failure (no tx)
  E5 tampered signature   -> already live-proven in S4 (INSUFFICIENT_EVIDENCE)

Appends results to docs/deployment_log.json. Never prints private keys.
"""
import json
import sys
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet

sys.path.insert(0, "scripts")
from deploy_smoke import make_record, new_agent, wait_final, OFFER_TEXT, ACCEPT_TEXT  # noqa: E402

KEYFILE = Path("scripts/smoke_deployer.json")
LOG = Path("docs/deployment_log.json")


def main():
    kf = json.loads(KEYFILE.read_text())
    acct = create_account(account_private_key=kf["private_key"])
    client = create_client(chain=studionet, account=acct)
    log = json.loads(LOG.read_text())
    ADDR = log["deploy"]["address"]
    print("error probes against", ADDR, flush=True)
    out = {}

    a, b = new_agent(), new_agent()
    good = make_record(a, "gendid-live-e1", 1, OFFER_TEXT, "1757318100001")
    good2 = make_record(b, "gendid-live-e1", 2, ACCEPT_TEXT, "1757318100002")
    recs = json.dumps([{k: r[k] for k in
                        ("sequence", "senderDid", "nonce", "signature", "text")}
                       for r in (good, good2)])

    # E1: bad room name -> contract must revert with UserError
    try:
        tx = client.write_contract(address=ADDR, function_name="submit_evidence",
                                  args=["Bad Room!", recs],
                                  account=client.local_account)
        r = wait_final(client, tx, "E1 bad-room", strict=False)
        # execution_result inside leader receipt:
        lr = None
        try:
            raw = json.dumps(r)
            lr = raw
        except Exception:
            pass
        out["e1_bad_room"] = {"tx": tx, "vote": r["vote_result"],
                              "exec": r["execution_result"],
                              "reverted": r["execution_result"] not in
                              (None, "SUCCESS", "FINISHED_WITH_RETURN"),
                              "stderr_tail": r["stderr_tail"][-300:]}
        print("E1:", out["e1_bad_room"]["reverted"], r["execution_result"],
              str(r["stderr_tail"])[-160:], flush=True)
    except Exception as e:
        out["e1_bad_room"] = {"error": str(e)[:300]}
        print("E1 error:", str(e)[:200], flush=True)

    # E2: malformed records_json -> UserError
    try:
        tx = client.write_contract(address=ADDR, function_name="submit_evidence",
                                  args=["gendid-live-e1", "not-json-["],
                                  account=client.local_account)
        r = wait_final(client, tx, "E2 malformed", strict=False)
        out["e2_malformed"] = {"tx": tx, "vote": r["vote_result"],
                               "exec": r["execution_result"],
                               "reverted": r["execution_result"] not in
                               (None, "SUCCESS", "FINISHED_WITH_RETURN"),
                               "stderr_tail": r["stderr_tail"][-300:]}
        print("E2:", out["e2_malformed"]["reverted"], r["execution_result"],
              str(r["stderr_tail"])[-160:], flush=True)
    except Exception as e:
        out["e2_malformed"] = {"error": str(e)[:300]}
        print("E2 error:", str(e)[:200], flush=True)

    # E3: unknown agreementId -> view raises
    try:
        client.read_contract(address=ADDR, function_name="get_agreement",
                            args=["GD-nonexistent-0000000000000000"])
        out["e3_unknown_id"] = {"raised": False}
        print("E3: NO ERROR RAISED (unexpected)", flush=True)
    except Exception as e:
        out["e3_unknown_id"] = {"raised": True, "error": str(e)[:200]}
        print("E3: raised as expected:", str(e)[:120], flush=True)

    # E4: unfunded writer -> client-side failure, no tx submitted
    try:
        broke = create_account()  # fresh key, zero balance
        broke_client = create_client(chain=studionet, account=broke)
        tx = broke_client.write_contract(address=ADDR,
                                         function_name="submit_evidence",
                                         args=["gendid-live-e1", recs],
                                         account=broke_client.local_account)
        out["e4_unfunded"] = {"submitted": True, "tx": tx}
        print("E4: tx SUBMITTED with unfunded account (unexpected)", flush=True)
    except Exception as e:
        out["e4_unfunded"] = {"submitted": False, "error": str(e)[:300]}
        print("E4: refused as expected:", str(e)[:160], flush=True)

    # state must be unchanged by E1/E2: count still 5 (4 smoke + s3b)
    cnt = int(client.read_contract(address=ADDR,
                                   function_name="get_agreement_count", args=[]))
    out["agreement_count_after_errors"] = cnt
    print("count after error probes:", cnt, flush=True)

    log["error_probes"] = out
    LOG.write_text(json.dumps(log, indent=2, default=str))
    print("recorded.", flush=True)


if __name__ == "__main__":
    main()
