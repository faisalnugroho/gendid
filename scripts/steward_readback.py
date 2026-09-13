#!/usr/bin/env python3
"""PHASE 5/6 — independent on-chain readback + argument verification for the
NEW live transactions produced from the public GitHub Pages URL.

Reads the deployed v1.2 contract directly via genlayer-py (same SDK the
frontend uses) and asserts every field the Steward asked for. Also verifies
the manifest signatures captured from the browser's submit_evidence call
cryptographically (Ed25519 via the cryptography package).

Inputs: /tmp/phase4_e2e.json (browser evidence from 2 fresh contexts)
Output: /tmp/phase5_readback.json + full console evidence.
"""
import base64
import hashlib
import importlib.util
import json
import sys
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path("/home/ubuntu/gendid")
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("ds", ROOT / "scripts" / "deploy_smoke.py")
ds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ds)

from genlayer_py import create_client
from genlayer_py.chains import studionet

ADDR = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"
RPC = "https://studio.genlayer.com/api"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED_PREFIX = b"\xed\x01"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # leading '1's are leading zero bytes
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def did_to_pubkey(did: str) -> bytes:
    mb = did.replace("did:key:", "")
    assert mb.startswith("z"), "not base58 multibase"
    raw = b58decode(mb[1:])
    assert raw[:2] == b"\xed\x01" and len(raw) == 34, "not Ed25519 did:key"
    return raw[2:]


def rpc(m, p):
    req = urllib.request.Request(
        RPC, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m,
                              "params": p}).encode(),
        headers={"content-type": "application/json",
                 "user-agent": "gendid-audit/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def main():
    e2e = json.loads(Path("/tmp/phase4_e2e.json").read_text())
    run1, run2 = e2e[0], e2e[1]
    txs = [run1["r_tx_link"].split("/tx/")[-1], run2["r_tx_link"].split("/tx/")[-1]
           if run2["r_tx_link"].startswith("http") else run2["r_tx_link"]]

    out = {"browser_url": run1["url"], "contract": ADDR,
           "transactions": []}

    # ---- 1. both new tx receipts via extended RPC
    for i, tx in enumerate(txs, 1):
        rec = None
        for attempt in range(5):
            try:
                rec = rpc("eth_getTransactionByHash", [tx])["result"]
                if rec:
                    break
            except Exception as e:
                print(f"  tx{i} rpc retry: {e}")
                time.sleep(8)
        leader = ((rec.get("consensus_data") or {}).get("leader_receipt") or [{}])
        lead = leader[0] if leader else {}
        out["transactions"].append({
            "run": i, "hash": tx,
            "status": rec.get("status"),
            "result_name": rec.get("result_name"),
            "to_address": rec.get("to_address"),
            "created_at": rec.get("created_at"),
            "leader_execution_result": lead.get("execution_result"),
            "function": (rec.get("data", {}) or {}).get("calldata", {})
                        .get("function_name") if isinstance(
                            (rec.get("data", {}) or {}).get("calldata"), dict)
            else str((rec.get("data", {}) or {}).get("calldata"))[:120],
        })
        t = out["transactions"][-1]
        print(f"[tx run{i}] {tx}")
        print(f"  status={t['status']} vote={t['result_name']} "
              f"exec={t['leader_execution_result']} to={t['to_address']}")
        print(f"  created_at={t['created_at']} function={t['function']}")

    # ---- 2. on-chain agreement record via genlayer-py (SDK read path)
    account = ds.load_account()
    client = create_client(chain=studionet, account=account)
    aid = run1["agreementId_dom"]
    rec = ds.read_json(client, ADDR, "get_agreement", [aid])
    seal = ds.read_json(client, ADDR, "get_room_seal", ["gendid-demo-01b"])

    # ---- 3. manifest signature verification (browser-captured args)
    w = run1["sdk_writes"][0]
    room, records_json, sigs_json = w["args"]
    records = json.loads(records_json)
    sigs = json.loads(sigs_json)
    mstr = run1["browser_manifest_recompute"]["manifestStr"]
    sig_verify = {}
    for did, sig_b64 in sigs.items():
        try:
            sig = base64.urlsafe_b64decode(sig_b64 + "==")
            pub = Ed25519PublicKey.from_public_bytes(did_to_pubkey(did))
            pub.verify(sig, mstr.encode())
            sig_verify[did] = "VALID"
        except Exception as e:
            sig_verify[did] = f"INVALID: {e}"
    # record signatures (Ed25519 over room|nonce|text)
    rec_verify = []
    for r in records:
        msg = f"{room}|{r['nonce']}|{r['text']}".encode()
        try:
            sig = base64.urlsafe_b64decode(r["signature"] + "==")
            pub = Ed25519PublicKey.from_public_bytes(
                did_to_pubkey(r["senderDid"]))
            pub.verify(sig, msg)
            rec_verify.append({"seq": r["sequence"], "status": "VALID"})
        except Exception as e:
            rec_verify.append({"seq": r["sequence"],
                               "status": f"INVALID: {e}"})

    out["onchain_agreement"] = {k: rec.get(k) for k in (
        "agreementId", "evidenceHash", "status", "finalized",
        "transcriptRoom", "transcriptCommitment", "protocolVersion",
        "participants", "recordCounts", "questionLabels", "authority",
        "manifest", "relevantRecordIds", "acceptedTerms",
        "adjudicationSummary")}
    out["room_seal_gendid-demo-01b"] = seal
    out["manifest_sig_verification"] = sig_verify
    out["record_sig_verification"] = rec_verify
    out["arg_sha256"] = {
        "arg1_room": hashlib.sha256(room.encode()).hexdigest(),
        "arg2_records_json": hashlib.sha256(records_json.encode()).hexdigest(),
        "arg3_manifest_sigs_json": hashlib.sha256(sigs_json.encode()).hexdigest(),
    }

    # ---- 4. browser vs on-chain comparisons
    cmp = {
        "agreementId": rec.get("agreementId") == run1["agreementId_dom"],
        "evidenceHash": rec.get("evidenceHash") == run1["evidenceHash_dom"],
        "status_AGREED": rec.get("status") == "AGREED",
        "finalized": rec.get("finalized") is True,
        "protocolVersion_v12": rec.get("protocolVersion") == "gendid/1.2",
        "manifest_protocol_v12": (rec.get("manifest", {}) or {}).get(
            "protocolVersion") == "gendid/1.2",
        "room": rec.get("transcriptRoom") == "gendid-demo-01b",
        "commitment_matches_manifest":
            rec.get("transcriptCommitment")
            == (rec.get("manifest", {}) or {}).get("transcriptCommitment"),
        "seal_equals_commitment": seal == rec.get("transcriptCommitment"),
        "tx1_finalized_majority_agree":
            out["transactions"][0]["status"] == "FINALIZED"
            and out["transactions"][0]["result_name"] == "MAJORITY_AGREE"
            and out["transactions"][0]["to_address"] == ADDR,
        "tx2_finalized_majority_agree":
            out["transactions"][1]["status"] == "FINALIZED"
            and out["transactions"][1]["result_name"] == "MAJORITY_AGREE"
            and out["transactions"][1]["to_address"] == ADDR,
        "manifest_sigs_valid": all(v == "VALID"
                                   for v in sig_verify.values()),
        "record_sigs_valid": all(r["status"] == "VALID"
                                 for r in rec_verify),
        "authority_authoritative": (rec.get("authority", {}) or {}).get(
            "verified", []) or None,
    }
    out["comparisons"] = cmp

    print("\n[on-chain agreement record]")
    print(json.dumps(out["onchain_agreement"], indent=2, default=str)[:4000])
    print("\n[room seal gendid-demo-01b]", seal)
    print("\n[manifest sigs (Python Ed25519)]", json.dumps(sig_verify))
    print("[record sigs]", json.dumps(rec_verify))
    print("\n[comparisons]")
    for k, v in cmp.items():
        print(f"  {k}: {v}")

    ok = all(bool(v) for v in cmp.values())
    print("\nPHASE5_VERDICT:", "PASS — all fields independently verified on-chain"
          if ok else "FAIL")
    json.dump(out, open("/tmp/phase5_readback.json", "w"),
              indent=2, default=str)
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
