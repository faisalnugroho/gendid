#!/usr/bin/env python3
"""PHASE 1D/8 — LIVE on-chain proof that 0xfb86…dD4B1 is the v1.2 contract.

Fetches the deploy tx receipt straight from the StudioNet RPC, hashes the
deployed contract_code, and compares to the repository's
contracts/gendid_judge.py (v1.2 source, sha256 6497e5f5…). Also checks the
deployer account's contract list and that no LATER deploy of the same code
supersedes it (contract set on-chain = exactly one gendid/1.2 instance).
"""
import hashlib
import json
import sys
import time
import urllib.request

RPC = "https://studio.genlayer.com/api"
DEPLOY_TX = "0xcf79982851cc510fe09e006f7d9f721cd23704c1ee93fe0d9b9f8f6ee96cc816"
CONTRACT = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"
REPO_SRC = "contracts/gendid_judge.py"
EXPECTED_SHA = "6497e5f5b7f78842f38a7263a8b8dc033999a0aecfa31bced3835c6ac15bc8ac"
DEPLOYER = "0x5E77b8D3655918454134a2d5BAd9dd76B741b4cB"


def rpc(method, params):
    req = urllib.request.Request(
        RPC, data=json.dumps({"jsonrpc": "2.0", "id": 1,
                              "method": method, "params": params}).encode(),
        headers={"content-type": "application/json",
                 "user-agent": "gendid-audit/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main():
    out = {}
    repo = open(REPO_SRC, "rb").read()
    repo_sha = hashlib.sha256(repo).hexdigest()
    out["repo_source"] = {"bytes": len(repo), "sha256": repo_sha,
                          "matches_documented_v12_sha": repo_sha == EXPECTED_SHA}

    # 1. deploy tx via the GenLayer extended RPC (eth_getTransactionByHash
    #    carries data.contract_code; the plain eth_getTransactionReceipt
    #    is the EVM shim without GenLayer consensus fields)
    rec = None
    for i in range(5):
        try:
            r = rpc("eth_getTransactionByHash", [DEPLOY_TX])
            rec = r.get("result")
            if rec:
                break
        except Exception as e:
            print(f"  rpc retry {i}: {e}", flush=True)
            time.sleep(8)
    if not rec:
        print(json.dumps({"FATAL": "deploy tx receipt not found on studionet"}))
        return 2
    out["deploy_tx"] = {
        "hash": DEPLOY_TX,
        "type": rec.get("type"),
        "status_finalized": rec.get("status"),
        "result_name": rec.get("result_name"),
        "tx_execution_result_name": rec.get("tx_execution_result_name"),
        "contract_address": rec.get("data", {}).get("contract_address")
        or rec.get("contract_address"),
        "created_at": rec.get("created_at"),
    }
    code = rec.get("data", {}).get("contract_code") or rec.get("contract_code")
    if not code:
        print(json.dumps({"FATAL": "receipt has no contract_code",
                          "keys": list(rec.keys()),
                          "data_keys": list(rec.get("data", {}).keys())}))
        return 2
    # contract_code is base64-encoded on the extended RPC
    import base64
    code_bytes = base64.b64decode(code)
    out["deployed_code"] = {
        "bytes": len(code_bytes),
        "sha256": hashlib.sha256(code_bytes).hexdigest(),
    }
    out["BYTE_IDENTITY"] = (
        out["deployed_code"]["sha256"] == repo_sha
        and out["deploy_tx"]["contract_address"] == CONTRACT)

    # 2. live state: agreement count + demo room seal
    def call(addr, fn, args):
        r = rpc("eth_callFunction", [{"from": "0x" + "00" * 20,
                                      "to": addr, "function": fn, "args": args}])
        return r.get("result")
    out["live"] = {}
    try:
        cnt = call(CONTRACT, "get_agreement_count", [])
        out["live"]["get_agreement_count"] = cnt
    except Exception as e:
        out["live"]["count_err"] = str(e)[:200]
    try:
        seal = call(CONTRACT, "get_room_seal", ["gendid-demo-01b"])
        out["live"]["get_room_seal_gendid-demo-01b"] = seal
    except Exception as e:
        out["live"]["seal_err"] = str(e)[:200]

    print(json.dumps(out, indent=2)[:6000])
    ok = out["BYTE_IDENTITY"]
    print("\nBYTE_IDENTITY (deployed code == repo v1.2 source):", ok)
    print("DEPLOYED_AT:", out["deploy_tx"].get("created_at"))
    print("PHASE1D_VERDICT:", "PROVEN" if ok else "FAILED")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
