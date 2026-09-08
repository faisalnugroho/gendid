"""GenDid gltest direct-mode fixtures + helpers.

Pins the runner via setup_sdk_paths(contract) so the py-genlayer hash in the
header resolves deterministically (the cache-masking pitfall), and provides a
local Ed25519 factory for building REAL signed technocore records with the
`cryptography` package — the contract's vendored verifier must accept them.
"""
from pathlib import Path

from gltest.direct.sdk_loader import setup_sdk_paths

_CONTRACT = (
    Path(__file__).resolve().parents[2] / "contracts" / "gendid_judge.py"
)
setup_sdk_paths(_CONTRACT)

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED_PREFIX = b"\xed\x01"


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def did_of(key: Ed25519PrivateKey) -> str:
    pub = key.public_key().public_bytes_raw()
    mb = "z" + b58(ED_PREFIX + pub)
    assert len(mb) == 48
    return "did:key:" + mb


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def new_agent(seed_hex: str | None = None) -> dict:
    seed = bytes.fromhex(seed_hex) if seed_hex else secrets.token_bytes(32)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return {"key": key, "did": did_of(key), "seed": seed.hex()}


def sign_say(agent: dict, room: str, nonce: str, swept_text: str) -> str:
    msg = f"{room}|{nonce}|{swept_text}"
    return b64url(agent["key"].sign(msg.encode()))


def tc_sweep_py(text: str) -> str:
    import unicodedata

    cats = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
    cleaned = "".join(
        " " if unicodedata.category(c) in cats else c for c in text
    )
    return cleaned.strip()


def record(
    agent: dict,
    room: str,
    seq: int,
    text: str,
    nonce: str | None = None,
    ts: str = "2026-09-08T07:14:02.512Z",
) -> dict:
    """A canonical gendid/1 record, really signed by agent."""
    swept = tc_sweep_py(text)
    nonce = nonce or str(1_757_000_000_000 + seq)
    return {
        "recordId": f"gdr-{room}-{seq}",
        "room": room,
        "sequence": seq,
        "timestamp": ts,
        "senderDid": agent["did"],
        "nonce": nonce,
        "signature": sign_say(agent, room, nonce, swept),
        "text": swept,
        "signatureStatus": "AUTHENTIC_SIGNED",
    }


def unsigned_record(nick: str, room: str, seq: int, text: str) -> dict:
    return {
        "recordId": f"gdr-{room}-{seq}",
        "room": room,
        "sequence": seq,
        "timestamp": "2026-09-08T07:14:03.000Z",
        "senderDid": nick,
        "nonce": "",
        "signature": "",
        "text": text,
        "signatureStatus": "UNSIGNED",
    }


def as_records_json(records: list) -> str:
    return json.dumps(records)


def deploy(vm):
    from gltest.direct import create_address, deploy_contract

    vm.sender = create_address("gendid_deployer")
    return deploy_contract(str(_CONTRACT), vm)


def llm_answer(labels=None, terms=None, offer=None, acceptance=None):
    """A well-formed LLM answer for mock_llm."""
    base = {
        "two_or_more_participants": "PASS",
        "offer_present": "PASS",
        "acceptance_present": "PASS",
        "acceptance_matches_offer": "PASS",
        "no_contradiction": "PASS",
        "evidence_grounded": "PASS",
        "acceptedTerms": terms
        or [
            {
                "key": "task",
                "value": "data normalization",
                "recordId": "gdr-gendid-demo-01-1",
            }
        ],
        "offerRecordId": offer or "gdr-gendid-demo-01-1",
        "acceptanceRecordId": acceptance or "gdr-gendid-demo-01-2",
        "contradictionRecordIds": [],
        "reasoning": "authentic offer + acceptance",
    }
    if labels:
        base.update(labels)
    return json.dumps(base)


def mock_llm_ok(vm, labels=None, terms=None, offer=None, acceptance=None):
    body = llm_answer(labels, terms, offer, acceptance)
    vm.clear_mocks()
    vm.mock_llm("impartial agreement adjudication", body)


def mock_llm_raw(vm, raw: str):
    vm.clear_mocks()
    vm.mock_llm("impartial agreement adjudication", raw)
