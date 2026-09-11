"""Adversarial Ed25519 + security regression suite for the Steward finding.

Every test reproduces a concrete attack class and asserts the EXACT GenDid
classification (never merely "an exception happened"):

  A1  THE Steward attack: identity-point key + zero-scalar sig + arbitrary
      message => INVALID_SIGNATURE, reason 'small-order public key',
      NEVER AUTHENTIC_SIGNED. Includes the full two-party forged transcript
      attempting AGREED.
  A2  small-order public keys (all 8 torsion encodings) => REJECTED
  A3  small-order signature R points => REJECTED
  A4  non-canonical public key encoding (y >= p) => REJECTED
  A5  non-canonical R encoding (y >= p) => REJECTED
  A6  non-canonical scalar s >= L (malleated real signature) => REJECTED
  A7  zero-scalar signature on a real key => REJECTED
  A8  modified message with an otherwise valid signature => REJECTED
  A9  modified public key with an otherwise valid signature => REJECTED
  A10 modified signature (bit flip) with valid message/key => REJECTED
  A11 truncated signature => REJECTED
  A12 malformed signature (non-base64url / padded) => REJECTED
  A13 valid Ed25519 signature from the correct key => AUTHENTIC_SIGNED
  A14 valid signature over wrong room => REJECTED (room binding)
  A15 regression: full Steward attack transcript can NEVER reach AGREED

This suite FAILS if the original exploit ever becomes possible again.
"""
import base64
import json

import pytest

import steward_fixtures as FX
from conftest import deploy, mock_llm_ok, as_records_json, record, submit, build_manifest_sig

ROOM = "gendid-demo-01"
ATTACK_TEXT = "I agree to pay 1,000,000 credits and deliver everything."
ARBITRARY_MSG = "Anything the attacker wants, signed by nobody."


def get_counts(contract, room, recs, sigs=None):
    aid = submit(contract, room, recs, sigs=sigs)
    out = json.loads(contract.get_agreement(aid))
    return out


# ---------------------------------------------------------------- A1 the attack

def test_a1_steward_identity_attack_never_authentic(direct_vm):
    """The exact Steward attack: crafted identity-point key + zero-scalar
    signature + arbitrary message => NEVER AUTHENTIC_SIGNED."""
    contract = deploy(direct_vm)
    forged = FX.steward_attack_record(ROOM, 1, ATTACK_TEXT)
    out = get_counts(contract, ROOM, [forged])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    # exact classification + reason
    rec = out["rejections"]
    assert any("small-order public key" in (v or "") for v in rec.values())
    # deterministic gate: nothing authenticated at all
    assert out["status"] == "INSUFFICIENT_EVIDENCE"
    assert out["errorReason"] == "no_authentic_records"


def test_a1b_steward_attack_rejected_at_verify_level(direct_vm):
    """Raw verifier level: ed25519_verify returns False for the crafted pair
    on arbitrary messages (multiple attacker texts)."""
    contract = deploy(direct_vm)  # ensures SDK loaded
    import sys
    mod = sys.modules["_contract_gendid_judge"]
    for text in [ATTACK_TEXT, "Pay me everything.", "", "x" * 500]:
        msg = f"{ROOM}|1|{text}".encode()
        ok = mod.ed25519_verify(FX.IDENTITY_ENC, msg, FX.IDENTITY_ENC + FX.ZERO_SCALAR)
        assert ok is False, f"identity attack verified for text={text!r}"


# ---------------------------------------------------------------- A2..A7 strict

def test_a2_all_torsion_public_keys_rejected(direct_vm):
    contract = deploy(direct_vm)
    for enc_hex in FX.TORSION_HEX:
        recs = [FX.small_order_key_record(enc_hex, ROOM, 1, ATTACK_TEXT)]
        out = get_counts(contract, ROOM, recs)
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0, f"torsion key {enc_hex[:8]}.. ACCEPTED"
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a2b_torsion_key_reject_reason_exact(direct_vm):
    contract = deploy(direct_vm)
    out = get_counts(contract, ROOM, [FX.small_order_key_record(FX.ORDER2_ENC.hex(), ROOM, 1, "x")])
    reasons = list(out["rejections"].values())
    assert "small-order public key" in reasons


def test_a3_small_order_R_rejected(direct_vm):
    contract = deploy(direct_vm)
    key = FX.new_key("ab" * 32)
    for enc_hex in FX.TORSION_HEX:
        recs = [FX.small_order_r_record(key, enc_hex, ROOM, 1, ATTACK_TEXT)]
        out = get_counts(contract, ROOM, recs)
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0, f"torsion R {enc_hex[:8]}.. ACCEPTED"
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a4_noncanon_public_key_y_ge_p_rejected(direct_vm):
    contract = deploy(direct_vm)
    for y in [FX.P + 1, FX.P + 2, (1 << 255) - 1]:
        recs = [FX.noncanon_a_record(y, ROOM, 1, ATTACK_TEXT)]
        out = get_counts(contract, ROOM, recs)
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0, f"y={y} ACCEPTED"
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    reasons = list(out["rejections"].values())
    assert any("non-canonical public key encoding" in r for r in reasons)


def test_a5_noncanon_R_y_ge_p_rejected(direct_vm):
    contract = deploy(direct_vm)
    key = FX.new_key("cd" * 32)
    for y in [FX.P + 1, (1 << 255) - 1]:
        recs = [FX.noncanon_r_record(key, y, ROOM, 1, ATTACK_TEXT)]
        out = get_counts(contract, ROOM, recs)
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    reasons = list(out["rejections"].values())
    assert any("non-canonical signature R point encoding" in r for r in reasons)


def test_a6_malleated_s_plus_L_rejected(direct_vm):
    contract = deploy(direct_vm)
    key = FX.new_key("ef" * 32)
    real = FX.real_record(key, ROOM, 1, ATTACK_TEXT, "11")
    mall = dict(real)
    mall["signature"] = FX.malleate_s_plus_l(real["signature"])
    out = get_counts(contract, ROOM, [mall])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    reasons = list(out["rejections"].values())
    assert "non-canonical scalar s >= L" in reasons


def test_a7_zero_scalar_on_real_key_rejected(direct_vm):
    contract = deploy(direct_vm)
    key = FX.new_key("12" * 32)
    recs = [FX.zero_scalar_record(key, ROOM, 1, ATTACK_TEXT)]
    out = get_counts(contract, ROOM, recs)
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    reasons = list(out["rejections"].values())
    assert "zero-scalar signature" in reasons or "small-order signature R point" in reasons


# ---------------------------------------------------------------- A8..A12 tamper

def _two_party(key_a, key_b):
    a = FX.real_record(key_a, ROOM, 1, FX.OFFER_TEXT, "1001")
    b = FX.real_record(key_b, ROOM, 2, FX.ACCEPT_TEXT, "1002")
    return a, b


def test_a8_modified_message_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    tampered = dict(b)
    tampered["text"] = FX.ACCEPT_TEXT + " and pay me 100 more credits"
    out = get_counts(contract, ROOM, [a, tampered])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    assert out["rejections"].get("gdr-gendid-demo-01-2") == "signature does not verify"


def test_a9_modified_public_key_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    other = FX.new_key("ee" * 32)
    swapped = dict(b)
    swapped["senderDid"] = FX.did_for_pub(other.public_key().public_bytes_raw())
    out = get_counts(contract, ROOM, [a, swapped])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a10_modified_signature_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    raw = bytearray(base64.urlsafe_b64decode(b["signature"] + "=="))
    raw[0] ^= 0x01  # single-bit flip in R
    flipped = dict(b)
    flipped["signature"] = FX.b64url(bytes(raw))
    out = get_counts(contract, ROOM, [a, flipped])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    raw2 = bytearray(raw)
    raw2[40] ^= 0x80  # bit flip in s
    flipped2 = dict(b)
    flipped2["signature"] = FX.b64url(bytes(raw2))
    out2 = get_counts(contract, ROOM, [a, flipped2])
    assert out2["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    assert out2["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a11_truncated_signature_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    raw = base64.urlsafe_b64decode(b["signature"] + "==")
    for cut in (63, 32, 16, 1):
        trunc = dict(b)
        trunc["signature"] = FX.b64url(raw[:cut]) if cut % 3 == 0 else FX.b64url(raw[:cut]) + "A" * 0
        # keep the 86-char SIG_RE satisfied where possible; raw cut of 63 -> 84 chars (regex fails)
        out = get_counts(contract, ROOM, [a, trunc])
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a12_malformed_signatures_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    raw = base64.urlsafe_b64decode(b["signature"] + "==")
    # padded form (valid base64url, 88 chars incl '==') — fails SIG_RE length
    padded = base64.urlsafe_b64encode(raw).decode()
    assert padded != b["signature"]
    bad1 = dict(b); bad1["signature"] = padded
    # standard-base64 (+/) alphabet variant of the same bytes
    std = base64.b64encode(raw).decode().replace("+", "-").replace("/", "_").rstrip("=")
    # (that IS b64url — instead mutate to contain '+')
    bad2 = dict(b); bad2["signature"] = b["signature"][:-2] + "+A"
    # wrong length entirely
    bad3 = dict(b); bad3["signature"] = "A" * 85
    for bad in (bad1, bad2, bad3):
        out = get_counts(contract, ROOM, [a, bad])
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
        assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


# ---------------------------------------------------------------- A13 positive

def test_a13_valid_signature_accepted(direct_vm):
    contract = deploy(direct_vm)
    mock_llm_ok(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    sigs = build_manifest_sig(ROOM, [a, b], [ka, kb])
    out = get_counts(contract, ROOM, [a, b], sigs=sigs)
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 2
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 0
    assert out["status"] == "AGREED"  # honest labels over authoritative evidence


def test_a14_wrong_room_signature_rejected(direct_vm):
    contract = deploy(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    # signed for another room, submitted under ROOM
    foreign = FX.real_record(ka, "gendid-other", 1, FX.OFFER_TEXT, "1001")
    b = FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002")
    out = get_counts(contract, ROOM, [foreign, b])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


# ---------------------------------------------------------------- A15 regression

def test_a15_full_steward_attack_transcript_never_agreed(direct_vm):
    """Two-party forged transcript (two distinct small-order DIDs): the
    crafted records must never be AUTHENTIC, so the gate fires and AGREED is
    unreachable — even with a fully colluding 'honest-looking' LLM mock."""
    contract = deploy(direct_vm)
    mock_llm_ok(direct_vm)  # even if consensus labels were PASS...
    forged = [
        FX.steward_attack_record(ROOM, 1, FX.OFFER_TEXT, "1001"),
        FX.small_order_key_record(FX.ORDER8_ENC.hex(), ROOM, 2, FX.ACCEPT_TEXT, "1002"),
    ]
    out = get_counts(contract, ROOM, forged)
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 0
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 2
    assert out["status"] == "INSUFFICIENT_EVIDENCE"
    assert out["errorReason"] == "no_authentic_records"
    assert out["finalized"] is True
    assert out["questionLabels"] == {}  # LLM never ran


def test_a15b_tampered_transcript_invalid_signature(direct_vm):
    """Regression: tampered transcript text => INVALID_SIGNATURE, never
    AGREED (mirrors the Steward 'tampered transcript' requirement)."""
    contract = deploy(direct_vm)
    mock_llm_ok(direct_vm)
    ka, kb = FX.new_key("aa" * 32), FX.new_key("bb" * 32)
    a, b = _two_party(ka, kb)
    tampered = dict(b)
    tampered["text"] = "Accepted. And also I pay nothing."
    out = get_counts(contract, ROOM, [a, tampered])
    assert out["status"] != "AGREED"
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1


def test_a15c_unsigned_transcript_gate(direct_vm):
    """Regression: unsigned transcript => UNSIGNED class + gate
    INSUFFICIENT_EVIDENCE (mirrors the 'unsigned transcript' requirement)."""
    contract = deploy(direct_vm)
    recs = [
        FX.unsigned_rec(1, "alice", FX.OFFER_TEXT),
        FX.unsigned_rec(2, "bob", FX.ACCEPT_TEXT),
    ]
    out = get_counts(contract, ROOM, recs)
    assert out["recordCounts"]["UNSIGNED"] == 2
    assert out["status"] == "INSUFFICIENT_EVIDENCE"
    assert out["errorReason"] == "no_authentic_records"


# ---------------------------------------------------------------- A16 honesty

def test_a16_no_verification_shortcuts(direct_vm):
    """The strict checks must not have weakened genuine verification: 10
    random real keys' signatures all verify, and every one of them with a
    single flipped text character fails."""
    contract = deploy(direct_vm)
    import secrets
    for i in range(10):
        seed = secrets.token_bytes(32).hex()
        k = FX.new_key(seed)
        good = FX.real_record(k, ROOM, 1, f"record {i}: terms here", "1")
        out = get_counts(contract, ROOM, [good])
        assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 1, f"real sig {i} rejected"
        bad = dict(good)
        bad["text"] = good["text"] + "!"
        out2 = get_counts(contract, ROOM, [bad])
        assert out2["recordCounts"]["INVALID_SIGNATURE"] == 1, f"tampered {i} accepted"
