#!/usr/bin/env python3
"""GenDid — deploy to GenLayer Studionet + live consensus smoke test.

Adapted from the proven AgentProof pattern (scripts/_ref_deploy_smoke.py,
ALL_OK 2026-09-06) per skills/genlayer-live-deploy-and-smoke:

  S1 CLEAR:      demo A (clear agreement) → expect AGREED
  S2 DISPUTE:    demo B (contradiction)  → expect NOT_AGREED
  S3 AMBIGUOUS:  demo C (vague)          → expect AMBIGUOUS or
                                             INSUFFICIENT_EVIDENCE
  S4 NEGATIVE:   invalid-signature transcript → must NOT be AGREED
                 (tests the fail-closed gate with 1 participant left:
                  expect INSUFFICIENT_EVIDENCE)
  S5 VIEWS:      get_agreement + get_agreement_count readback

All records are really Ed25519-signed with the repo's OWN canonical format
(<room>|<nonce>|<swept-text>, same as tests/direct/conftest.py) — no second
signing scheme, no simulated consensus.

Keyfile: scripts/smoke_deployer.json (gitignored) — {address, private_key}.
NEVER commit it, never print the key.

Output: docs/deployment_log.json (address, tx hashes, results, timings).
Explorer: https://explorer-studio.genlayer.com/address/<addr>
"""
import base64
import json
import secrets
import sys
import time
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from genlayer_py import create_client, create_account
from genlayer_py.chains import studionet

CODE = Path("contracts/gendid_judge.py").read_text()
KEYFILE = Path("scripts/smoke_deployer.json")
LOG = Path("docs/deployment_log.json")

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED_PREFIX = b"\xed\x01"

# ---------------------------------------------------------------- fixtures
# Same demo scripts as frontend/demos.js (the repo's existing demos) and the
# same offer text as tests/direct/test_gendid_judge.py — no new scenarios.

OFFER_TEXT = (
    "I need data normalization for the sales CSV. Output must be JSON. "
    "Maximum latency 30 seconds. Price is 5 credits."
)
ACCEPT_TEXT = (
    "Accepted. I will normalize the sales CSV to JSON within 30 seconds "
    "for 5 credits."
)
CANCEL_TEXT = (
    "Cancel that. The price is wrong for this job — I withdraw my acceptance."
)
VAGUE_OFFER = "Maybe we could work together on that CSV thing sometime."
VAGUE_ACCEPT = "Sure, sounds good I guess."

TC_SWEEP_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def tc_sweep(text: str) -> str:
    cleaned = "".join(
        " " if unicodedata.category(c) in TC_SWEEP_CATEGORIES else c for c in text
    )
    return cleaned.strip()


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def new_agent(seed: bytes | None = None) -> dict:
    seed = seed or secrets.token_bytes(32)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pub = key.public_key().public_bytes_raw()
    mb = "z" + b58(ED_PREFIX + pub)
    assert len(mb) == 48
    return {"key": key, "did": "did:key:" + mb, "seed": seed.hex()}


def make_record(agent: dict, room: str, seq: int, text: str, nonce: str) -> dict:
    """Canonical gendid/1 record, really signed (same scheme as conftest.py)."""
    swept = tc_sweep(text)
    msg = f"{room}|{nonce}|{swept}".encode()
    return {
        "recordId": f"gdr-{room}-{seq}",
        "room": room,
        "sequence": seq,
        "timestamp": "2026-09-08T07:14:02.512Z",
        "senderDid": agent["did"],
        "nonce": nonce,
        "signature": b64url(agent["key"].sign(msg)),
        "text": swept,
        "signatureStatus": "AUTHENTIC_SIGNED",
    }


def manifest_str_for(room: str, records: list) -> str:
    """The contract-derived manifest string (real contract code, stubbed gl)."""
    import types
    import importlib.util

    gl_mod = types.ModuleType("genlayer")

    class _TreeMap(dict):
        def get(self, k, default=None):
            try:
                return self[k]
            except KeyError:
                return default

    class UserError(Exception):
        pass

    gl_mod.gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        public=types.SimpleNamespace(
            view=lambda f=None: (f if f is not None else True),
            write=lambda f=None: (f if f is not None else True),
        ),
        message_raw={"datetime": "2026-09-08T00:00:00Z"},
        vm=types.SimpleNamespace(run_nondet=lambda a, b: {}),
        nondet=types.SimpleNamespace(exec_prompt=lambda p, response_format=None: ""),
        TreeMap=_TreeMap, u256=int, UserError=UserError)
    gl_mod.UserError = UserError
    gl_mod.TreeMap = _TreeMap
    gl_mod.u256 = int
    gl_mod.__all__ = ["gl", "UserError", "TreeMap", "u256"]
    sys.modules["genlayer"] = gl_mod
    spec = importlib.util.spec_from_file_location(
        "gendid_pure", Path("contracts/gendid_judge.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ev = mod._classify_records(room, records)
    m = mod._build_manifest(room, ev)
    return mod._manifest_str(m)


def manifest_sigs(room: str, records: list, agents: list) -> dict:
    """Every participant signs the derived manifest string."""
    mstr = manifest_str_for(room, records)
    return {a["did"]: b64url(a["key"].sign(mstr.encode())) for a in agents}


def as_records_json(records: list) -> str:
    # the exact fields the contract's _classify_records reads
    slim = [
        {
            "sequence": r["sequence"],
            "senderDid": r["senderDid"],
            "nonce": r["nonce"],
            "signature": r["signature"],
            "text": r["text"],
        }
        for r in records
    ]
    return json.dumps(slim)


# ---------------------------------------------------------------- receipts


def wait_final(client, tx_hash, label, strict=True):
    """FINALIZED != success. Gate on vote (MAJORITY_AGREE) AND leader exec
    (FINISHED_WITH_RETURN). stderr TAIL carries any revert reason."""
    from genlayer_py.types import TransactionStatus

    last_err = None
    receipt = None
    for _ in range(6):
        try:
            receipt = client.wait_for_transaction_receipt(
                transaction_hash=tx_hash,
                status=TransactionStatus.FINALIZED,
                retries=100, interval=3000)
            break
        except Exception as e:
            last_err = e
            print(f"  [{label}] rpc error: {str(e)[:180]} — backing off 15s", flush=True)
            time.sleep(15)
    else:
        raise RuntimeError(f"{label} rpc failed: {last_err}")

    if isinstance(receipt, dict):
        data = receipt.get("data") or {}
        addr = data.get("contract_address") if isinstance(data, dict) else None
        if addr is None:
            addr = receipt.get("to_address")
        leader = (receipt.get("consensus_data") or {}).get("leader_receipt", [{}])
        lead = leader[0] if leader else {}
        exec_result = lead.get("execution_result")
        vote_result = receipt.get("result_name") or "UNKNOWN"
        exec_name = receipt.get("tx_execution_result_name")
        if exec_name is not None:
            exec_result = exec_name
        if exec_result is None:
            exec_result = receipt.get("result_name")
        stderr = str((lead.get("genvm_result") or {}).get("stderr") or "")
    else:
        addr = getattr(receipt, "contract_address", None)
        exec_result = None
        vote_result = "UNKNOWN"
        stderr = ""

    print(f"  [{label}] finalized vote={vote_result} exec={exec_result}", flush=True)
    ok_names = (None, "SUCCESS", "FINISHED_WITH_RETURN")
    if exec_result not in ok_names or vote_result not in ("MAJORITY_AGREE", None):
        print("EXECUTION FAILED — consensus data:", flush=True)
        print(json.dumps(receipt.get("consensus_data") if isinstance(receipt, dict)
                         else {}, default=str)[:3000], flush=True)
        if stderr:
            print("STDERR tail:", stderr[-1500:], flush=True)
        if strict:
            raise RuntimeError(f"{label} failed: vote={vote_result} exec={exec_result}")
        print(f"  [{label}] consensus mismatch (vote={vote_result}) — "
              "state change discarded, record remains PENDING", flush=True)
    return {"execution_result": exec_result or "SUCCESS",
            "vote_result": vote_result,
            "ok": exec_result in ok_names
                 and vote_result in ("MAJORITY_AGREE", None),
            "contract_address": addr, "stderr_tail": stderr[-1500:]}


def read_json(client, addr, fn, args):
    raw = client.read_contract(address=addr, function_name=fn, args=args)
    return json.loads(raw) if isinstance(raw, str) else raw


# ---------------------------------------------------------------- main


def load_account():
    if KEYFILE.exists():
        data = json.loads(KEYFILE.read_text())
        return create_account(account_private_key=data["private_key"])
    acct = create_account()
    KEYFILE.parent.mkdir(exist_ok=True)
    KEYFILE.write_text(json.dumps(
        {"address": acct.address, "private_key": acct.key.hex()}))
    return acct


def adjudicate(client, addr, label, room, records, expect, attempts=3,
                 sigs=None, mock_llm_collude=None):
    """submit_evidence -> read agreement. Re-crank on NO_MAJORITY/DISAGREE
    (retry path is part of the contract design: non-finalized records allow
    a fresh attempt). Judge on the FINAL record from the chain.

    sigs: {did: manifest-signature} — the gendid/1.2 authority argument.
    Pass None to exercise the NON_AUTHORITATIVE path deliberately."""
    t0 = time.time()
    sigs_json = json.dumps(sigs) if sigs is not None else ""
    tx = client.write_contract(
        address=addr, function_name="submit_evidence",
        args=[room, as_records_json(records), sigs_json],
        account=client.local_account)
    res = wait_final(client, tx, label + " submit")
    print(f"  [{label}] tx {tx}", flush=True)
    votes_seen = [res["vote_result"]]

    # agreementId derivation mirrors the contract: GD-<room24>-<hash16> where
    # hash is over the canonical package — but records_json differs from the
    # package shape, so read it back by count + probe instead of recomputing.
    aid = None
    rec = None
    for attempt in range(1, attempts + 1):
        cnt = int(read_json(client, addr, "get_agreement_count", []))
        # scan back to find our record (few agreements expected on a fresh
        # contract; match by room + evidence content)
        for i in range(max(0, cnt - 12), cnt):
            pass  # (count view has no list method; use direct get by id guess)
        # The contract returns agreementId from the tx — but read_contract
        # can't return it; instead reconstruct: scan recent GD- ids is not
        # possible without a list. So recompute the id exactly like the
        # contract does, from the canonical package.
        aid = compute_agreement_id(room, records)
        try:
            rec = read_json(client, addr, "get_agreement", [aid])
            break
        except Exception:
            pass
        if attempt < attempts:
            print(f"  [{label}] record not found yet — re-cranking", flush=True)
            tx = client.write_contract(
                address=addr, function_name="submit_evidence",
                args=[room, as_records_json(records), sigs_json],
                account=client.local_account)
            r2 = wait_final(client, tx, f"{label} re-crank #{attempt}")
            votes_seen.append(r2["vote_result"])

    t = time.time() - t0
    if rec is None:
        raise RuntimeError(f"{label}: agreement record never appeared on chain")
    status = rec.get("status")
    ok = status == expect if isinstance(expect, str) else status in expect
    print(f"  [{label}] {t:.0f}s votes={votes_seen} status={status} "
          f"(expected {expect}) -> {'OK' if ok else 'MISMATCH'}", flush=True)
    print(f"  [{label}] summary: {str(rec.get('adjudicationSummary'))[:180]}", flush=True)
    labels = rec.get("questionLabels") or {}
    if labels:
        print(f"  [{label}] labels: {json.dumps(labels)}", flush=True)
    return {"tx": tx, "agreementId": aid, "status": status, "expected": expect,
            "match": ok, "consensus_rounds": votes_seen,
            "secs": round(t, 1), "record": rec}


def compute_agreement_id(room, records):
    """Byte-exact mirror of the contract's id derivation — import the
    contract's own pure functions so we can't drift. Same genlayer stub
    approach as tests/js/test-parity.mjs (pyPrelude)."""
    import types
    gl_mod = types.ModuleType("genlayer")

    class _TreeMap(dict):
        def get(self, k, default=None):
            try:
                return self[k]
            except KeyError:
                return default

    class UserError(Exception):
        pass

    gl_mod.gl = types.SimpleNamespace(
        Contract=type("Contract", (), {}),
        public=types.SimpleNamespace(
            view=lambda f=None: (f if f is not None else True),
            write=lambda f=None: (f if f is not None else True),
        ),
        message_raw={"datetime": "2026-09-08T00:00:00Z"},
        vm=types.SimpleNamespace(run_nondet=lambda a, b: {}),
        nondet=types.SimpleNamespace(exec_prompt=lambda p, response_format=None: ""),
        TreeMap=_TreeMap,
        u256=int,
        UserError=UserError,
    )
    gl_mod.UserError = UserError
    gl_mod.TreeMap = _TreeMap
    gl_mod.u256 = int
    gl_mod.__all__ = ["gl", "UserError", "TreeMap", "u256"]
    sys.modules["genlayer"] = gl_mod

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gendid_judge_pure", Path("contracts/gendid_judge.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    evidence = mod._classify_records(room, records)
    package = {
        "protocolVersion": "gendid/1.1",
        "transcriptRoom": room,
        "transcriptCommitment": evidence["transcriptCommitment"],
        "records": evidence["records"],
    }
    canon = mod._canonical_json(package)
    return "GD-%s-%s" % (room[:24],
                         mod._sha256_hex(canon.encode("utf-8"))[:16])


def main():
    account = load_account()
    client = create_client(chain=studionet, account=account)
    print("deployer:", account.address, flush=True)

    # ---------------- deploy ----------------
    print(f"deploying GenDid judge ({len(CODE)} bytes)…", flush=True)
    tx = client.deploy_contract(code=CODE, account=client.local_account,
                                args=[], leader_only=True)
    res = wait_final(client, tx, "deploy")
    addr = res["contract_address"]
    if not addr:
        raise RuntimeError("no contract address in deploy receipt")
    print("CONTRACT:", addr, flush=True)
    print("explorer: https://explorer-studio.genlayer.com/address/" + addr, flush=True)
    log = {"deploy": {"tx_hash": tx, "address": addr, "deployer": account.address}}

    cnt = read_json(client, addr, "get_agreement_count", [])
    print("agreement_count after deploy:", cnt, flush=True)

    # ---------------- S1 clear agreement ----------------
    print("--- S1 CLEAR AGREEMENT: expect AGREED ---", flush=True)
    a1, b1 = new_agent(), new_agent()
    room1 = "gendid-live-s1"
    recs1 = [
        make_record(a1, room1, 1, OFFER_TEXT, "1757318040001"),
        make_record(b1, room1, 2, ACCEPT_TEXT, "1757318040002"),
        make_record(a1, room1, 3, "Confirmed. Send the JSON output to this room when ready.", "1757318040003"),
    ]
    s1 = adjudicate(client, addr, "S1", room1, recs1, "AGREED",
                    sigs=manifest_sigs(room1, recs1, [a1, b1]))
    log["s1_clear"] = s1

    # ---------------- S2 dispute ----------------
    print("--- S2 DISPUTE: expect NOT_AGREED ---", flush=True)
    a2, b2 = new_agent(), new_agent()
    room2 = "gendid-live-s2"
    recs2 = [
        make_record(a2, room2, 1, OFFER_TEXT, "1757318050001"),
        make_record(b2, room2, 2, ACCEPT_TEXT, "1757318050002"),
        make_record(b2, room2, 3, CANCEL_TEXT, "1757318050003"),
    ]
    s2 = adjudicate(client, addr, "S2", room2, recs2, "NOT_AGREED",
                    sigs=manifest_sigs(room2, recs2, [a2, b2]))
    log["s2_dispute"] = s2

    # ---------------- S3 ambiguous ----------------
    print("--- S3 AMBIGUOUS: expect AMBIGUOUS or INSUFFICIENT_EVIDENCE ---", flush=True)
    a3, b3 = new_agent(), new_agent()
    room3 = "gendid-live-s3"
    recs3 = [
        make_record(a3, room3, 1, VAGUE_OFFER, "1757318060001"),
        make_record(b3, room3, 2, VAGUE_ACCEPT, "1757318060002"),
    ]
    s3 = adjudicate(client, addr, "S3", room3, recs3,
                    ["AMBIGUOUS", "INSUFFICIENT_EVIDENCE", "NOT_AGREED"],
                    sigs=manifest_sigs(room3, recs3, [a3, b3]))
    log["s3_ambiguous"] = s3

    # ---------------- S4 negative: tampered sig ----------------
    print("--- S4 NEGATIVE: tampered evidence must NEVER be AGREED ---", flush=True)
    a4, b4 = new_agent(), new_agent()
    room4 = "gendid-live-s4"
    good = make_record(a4, room4, 1, OFFER_TEXT, "1757318070001")
    tampered = dict(good)
    tampered["text"] = good["text"] + " and pay me 100 credits"  # sig no longer covers
    recs4 = [tampered, make_record(b4, room4, 2, ACCEPT_TEXT, "1757318070002")]
    s4 = adjudicate(client, addr, "S4", room4, recs4, "INSUFFICIENT_EVIDENCE")
    log["s4_negative"] = s4

    # ---------------- S4b STEWARD ATTACK LIVE ----------------
    # The exact steward finding, live on chain: identity-point public key +
    # zero-scalar signature + arbitrary "acceptance" text. The attacker
    # record must classify INVALID_SIGNATURE and the transcript must never
    # be AGREED (fail-safe INSUFFICIENT_EVIDENCE: one authentic record,
    # nobody to agree with).
    print("--- S4b STEWARD ATTACK LIVE: identity key + zero-scalar sig ---",
          flush=True)
    a4b, b4b = new_agent(), new_agent()
    room4b = "gendid-live-s4b"
    real_offer = make_record(a4b, room4b, 1, OFFER_TEXT, "1757318071001")
    P = 2**255 - 19

    def _b58(raw: bytes) -> str:
        n = int.from_bytes(raw, "big")
        out = ""
        while n:
            n, rem = divmod(n, 58)
            out = B58[rem] + out
        return out

    def _did_for_pub(pub32: bytes) -> str:
        return "did:key:z" + _b58(b"\xed\x01" + pub32)

    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    identity_enc = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000")
    attack_record = {
        "recordId": f"gdr-{room4b}-2",
        "room": room4b,
        "sequence": 2,
        "timestamp": "2026-09-08T07:14:02.512Z",
        "senderDid": _did_for_pub(identity_enc),  # identity-point key
        "nonce": "1757318071002",
        # R = identity point, S = zero scalar
        "signature": _b64url(identity_enc + bytes(32)),
        "text": ACCEPT_TEXT,  # arbitrary message "accepted"
        "signatureStatus": "AUTHENTIC_SIGNED",  # liar's claim; classifier decides
    }
    recs4b = [real_offer, attack_record]
    s4b = adjudicate(client, addr, "S4b", room4b, recs4b,
                     "INSUFFICIENT_EVIDENCE",
                     sigs=manifest_sigs(room4b, recs4b, [a4b, b4b]))
    # hard assertions on the classification itself, not just the status
    assert s4b["record"]["recordCounts"]["INVALID_SIGNATURE"] == 1, \
        "attack record was not INVALID_SIGNATURE"
    assert s4b["record"]["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    print("  [S4b] steward attack record: INVALID_SIGNATURE (live), "
          "transcript NOT AGREED", flush=True)
    log["s4b_steward_attack"] = s4b

    # ---------------- S6 AUTHORITY: caller-selected subset ----------------
    # The gendid/1.2 remediation, live: an authoritative transcript ends in a
    # cancellation; the caller submits only the favorable subset carrying the
    # FULL manifest's signatures. Must be NON_AUTHORITATIVE, never AGREED.
    print("--- S6 SUBSET ATTACK: favorable subset + full-manifest sigs ---",
          flush=True)
    a6, b6 = new_agent(), new_agent()
    room6 = "gendid-live-s6"
    truthful6 = [
        make_record(a6, room6, 1, OFFER_TEXT, "1757318080001"),
        make_record(b6, room6, 2, ACCEPT_TEXT, "1757318080002"),
        make_record(b6, room6, 3, CANCEL_TEXT, "1757318080003"),
    ]
    sigs6_full = manifest_sigs(room6, truthful6, [a6, b6])
    favorable6 = truthful6[:2]
    s6 = adjudicate(client, addr, "S6", room6, favorable6,
                    "NON_AUTHORITATIVE", sigs=sigs6_full)
    assert s6["record"]["errorReason"] == \
        "manifest_incomplete_or_invalid_signatures", \
        f"S6 wrong reason: {s6['record'].get('errorReason')}"
    assert s6["record"]["questionLabels"] == {}, "S6: LLM must never run"
    print("  [S6] caller-selected subset: NON_AUTHORITATIVE, LLM never ran",
          flush=True)
    log["s6_subset_attack"] = s6

    # ---------------- S7 AUTHORITY: conflicting snapshots ----------------
    # Same room, two different authoritative-looking snapshots. First wins
    # and seals; the second must be NON_AUTHORITATIVE(conflicting_snapshot).
    print("--- S7 CONFLICTING SNAPSHOTS: first seals, second rejected ---",
          flush=True)
    a7, b7 = new_agent(), new_agent()
    room7 = "gendid-live-s7"
    snap7a = [
        make_record(a7, room7, 1, OFFER_TEXT, "1757318090001"),
        make_record(b7, room7, 2, ACCEPT_TEXT, "1757318090002"),
    ]
    snap7b = [
        make_record(a7, room7, 1, OFFER_TEXT + " Also latency 60s.",
                    "1757318091001"),
        make_record(b7, room7, 2, ACCEPT_TEXT, "1757318091002"),
    ]
    s7a = adjudicate(client, addr, "S7a", room7, snap7a, "AGREED",
                    sigs=manifest_sigs(room7, snap7a, [a7, b7]))
    s7b = adjudicate(client, addr, "S7b", room7, snap7b,
                    "NON_AUTHORITATIVE",
                    sigs=manifest_sigs(room7, snap7b, [a7, b7]))
    assert s7b["record"]["errorReason"] == "conflicting_snapshot", \
        f"S7b wrong reason: {s7b['record'].get('errorReason')}"
    seal = read_json(client, addr, "get_room_seal", [room7])
    assert seal == s7a["record"]["transcriptCommitment"], \
        "seal does not pin the first authoritative snapshot"
    print(f"  [S7] seal pins room to first snapshot: {seal[:16]}...", flush=True)
    log["s7_conflicting"] = {"s7a": s7a, "s7b": s7b, "seal": seal}

    # ---------------- S8 AUTHORITY: no manifest at all ----------------
    print("--- S8 UNMANIFESTED: valid records, no authority -> NON_AUTHORITATIVE ---",
          flush=True)
    a8, b8 = new_agent(), new_agent()
    room8 = "gendid-live-s8"
    recs8 = [
        make_record(a8, room8, 1, OFFER_TEXT, "1757318110001"),
        make_record(b8, room8, 2, ACCEPT_TEXT, "1757318110002"),
    ]
    s8 = adjudicate(client, addr, "S8", room8, recs8, "NON_AUTHORITATIVE",
                    sigs=None)  # deliberately unmanifested
    assert s8["record"]["errorReason"] == \
        "manifest_incomplete_or_invalid_signatures"
    assert s8["record"]["questionLabels"] == {}
    log["s8_unmanifested"] = s8

    # ---------------- S5 views readback ----------------
    print("--- S5 VIEWS: readback ---", flush=True)
    got1 = read_json(client, addr, "get_agreement", [s1["agreementId"]])
    cnt = int(read_json(client, addr, "get_agreement_count", []))
    views_ok = got1.get("status") == "AGREED" and cnt >= 9
    print(f"VIEWS_OK: {views_ok} (count={cnt}, s1 status={got1.get('status')})", flush=True)
    log["s5_views"] = {"ok": views_ok, "count": cnt,
                       "s1_readback_status": got1.get("status")}

    log["result"] = {
        "address": addr,
        "s1_clear_agreed": s1["match"],
        "s2_dispute_not_agreed": s2["match"],
        "s3_ambiguous_family": s3["match"],
        "s4_negative_not_agreed": s4["match"],
        "s4b_steward_attack_rejected": s4b["match"],
        "s6_subset_non_authoritative": s6["match"],
        "s7_conflict_first_wins": s7a["match"] and s7b["match"],
        "s8_unmanifested_non_authoritative": s8["match"],
        "views_ok": views_ok,
        "all_ok": all([s1["match"], s2["match"], s3["match"], s4["match"],
                       s4b["match"], s6["match"], s7a["match"], s7b["match"],
                       s8["match"], views_ok]),
    }
    LOG.parent.mkdir(exist_ok=True)
    LOG.write_text(json.dumps(log, indent=2, default=str))
    print("ALL_OK:", log["result"]["all_ok"], flush=True)
    print("DONE. contract:", addr, flush=True)
    print("log:", LOG, flush=True)
    return 0 if log["result"]["all_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
