"""Transcript-order binding tests (Steward requirement 2).

The gendid/1.1 order model:
  * the technocore signature itself commits to (room, nonce, swept-text) —
    the signer's NONCE is per-record signed data, and nonces are enforced
    strictly increasing per sender, so the SIGNED record set is a
    nonce-ordered sequence per signer;
  * venue `sequence`/`ts` are UNSIGNED metadata — GenDid does NOT claim
    they are cryptographically signed;
  * on top, GenDid adds the transcript commitment: a sha256 hash chain
    over the AUTHENTIC records in canonical (nonce, sequence, recordId)
    order, published in the prompt and stored on-chain.

Tests prove: reorder/insert/delete/duplicate of authenticated records all
change the commitment; same records in different order never produce the
same evidence hash; ordering is deterministic across runs.
"""
import json

import pytest

import steward_fixtures as FX
from conftest import deploy, mock_llm_ok, as_records_json, submit, build_manifest_sig

ROOM = "gendid-demo-01"


def _agents():
    return FX.new_key("aa" * 32), FX.new_key("bb" * 32)


def _transcript(ka, kb):
    return [
        FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1001"),
        FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
        FX.real_record(ka, ROOM, 3, "Confirmed. Send the JSON here.", "1003"),
    ]


def classify(direct_vm, recs, room=ROOM):
    """Classify ONE transcript against a freshly-deployed contract. NOTE:
    gltest direct mode loads the contract module once per process; tests that
    need MULTIPLE transcripts must use classify_all (single contract, N
    submits) instead of calling classify repeatedly."""
    contract = deploy(direct_vm)
    aid = submit(contract, room, recs)
    return json.loads(contract.get_agreement(aid))


def classify_all(direct_vm, transcripts, room=ROOM):
    """Classify N transcripts against ONE contract (deploy once, submit N —
    the direct-mode loader permits only one contract load per process)."""
    contract = deploy(direct_vm)
    outs = []
    for recs in transcripts:
        aid = submit(contract, room, recs)
        outs.append(json.loads(contract.get_agreement(aid)))
    return outs


def test_o1_original_order_valid_and_consistent(direct_vm):
    ka, kb = _agents()
    outs = classify_all(direct_vm, [_transcript(ka, kb), _transcript(ka, kb)])
    out, out2 = outs
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 3
    assert out["transcriptCommitment"]
    # deterministic across runs
    assert out["transcriptCommitment"] == out2["transcriptCommitment"]
    assert out["evidenceHash"] == out2["evidenceHash"]


def test_o2_nonce_reorder_changes_commitment(direct_vm):
    """Reordering the SIGNED chronology (swap which record comes first by
    nonce) changes the transcript commitment — the chain is order-sensitive."""
    ka, kb = _agents()
    t1 = [
        FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1001"),
        FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
    ]
    t2 = [
        FX.real_record(kb, ROOM, 1, FX.OFFER_TEXT, "1001"),
        FX.real_record(ka, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
    ]
    out1, out2 = classify_all(direct_vm, [t1, t2])
    assert out1["transcriptCommitment"] != out2["transcriptCommitment"]
    assert out1["evidenceHash"] != out2["evidenceHash"]


def test_o3_remove_record_changes_commitment(direct_vm):
    ka, kb = _agents()
    t = _transcript(ka, kb)
    out_full, out_removed = classify_all(direct_vm, [t, t[:2]])  # delete the last
    assert out_full["transcriptCommitment"] != out_removed["transcriptCommitment"]
    assert out_full["evidenceHash"] != out_removed["evidenceHash"]


def test_o4_insert_record_changes_commitment(direct_vm):
    ka, kb = _agents()
    t = _transcript(ka, kb)
    mid = FX.real_record(kb, ROOM, 4, "Amendment: price is now 6 credits.", "1004")
    out_before, out_after = classify_all(direct_vm, [t, t + [mid]])
    assert out_before["transcriptCommitment"] != out_after["transcriptCommitment"]
    assert out_before["evidenceHash"] != out_after["evidenceHash"]


def test_o5_duplicate_replay_rejected_inert(direct_vm):
    """Replaying an authentic record's exact content => DUPLICATE (inert),
    never a second AUTHENTIC record — and it does not change the semantics
    (counts.DUPLICATE=1)."""
    ka, kb = _agents()
    t = _transcript(ka, kb)
    dup = dict(t[0])
    dup["sequence"] = 99
    out = classify(direct_vm, t + [dup])
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 3
    assert out["recordCounts"]["DUPLICATE"] == 1


def test_o6_array_order_irrelevant_but_seq_reassignment_detected(direct_vm):
    """Feeding the same records in a different ARRAY order: canonicalization
    sorts them, so classification and hash are IDENTICAL (an honest client
    reading the venue in any order gets the same result).
    But records with REASSIGNED sequence numbers are different evidence
    (recordId embeds seq) => different hash."""
    ka, kb = _agents()
    t = _transcript(ka, kb)
    t3 = [
        FX.real_record(ka, ROOM, 5, FX.OFFER_TEXT, "1001"),
        FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
    ]
    t1 = _transcript(ka, kb)[:2]
    out1, out2, out3, out1b = classify_all(
        direct_vm, [t, list(reversed(t)), t3, t1]
    )
    assert out1["evidenceHash"] == out2["evidenceHash"]
    assert out1["transcriptCommitment"] == out2["transcriptCommitment"]
    assert out3["evidenceHash"] != out1b["evidenceHash"]


def test_o7_nonce_regression_rejected(direct_vm):
    """A record whose nonce goes BACKWARD for the same signer is rejected —
    the signer's signed chronology cannot be replayed out of order."""
    ka, kb = _agents()
    t = [
        FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1005"),
        FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
        FX.real_record(ka, ROOM, 3, "Confirmed.", "1001"),  # nonce regression
    ]
    out = classify(direct_vm, t)
    assert out["recordCounts"]["AUTHENTIC_SIGNED"] == 2
    assert out["recordCounts"]["INVALID_SIGNATURE"] == 1
    assert out["rejections"].get("gdr-gendid-demo-01-3") == "nonce not increasing for key in room"


def test_o8_commitment_in_prompt(direct_vm):
    """The consensus prompt shows the transcript commitment to every
    validator (grounded, identical input)."""
    contract = deploy(direct_vm)
    seen = []
    orig = direct_vm._match_llm_mock

    def spy(prompt, *a, **k):
        seen.append(prompt)
        return orig(prompt, *a, **k)

    direct_vm._match_llm_mock = spy
    mock_llm_ok(direct_vm)
    ka, kb = _agents()
    t = [FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1001"),
         FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002")]
    sigs = build_manifest_sig(ROOM, t, [ka, kb])
    aid = submit(contract, ROOM, t, sigs=sigs)
    direct_vm._match_llm_mock = orig
    assert seen, "LLM never saw a prompt"
    prompt = seen[0] if isinstance(seen[0], str) else seen[0][0]
    assert "Transcript order commitment" in prompt
    # commitment hex appears in the prompt...
    import re
    m = re.search(
        r"Transcript order commitment \(sha256 hash chain over the authenticated "
        r"records in canonical order\): ([0-9a-f]{64})",
        prompt,
    )
    assert m, "commitment hex not found in prompt"
    # ...and it is EXACTLY the commitment stored on-chain for this agreement
    out = json.loads(contract.get_agreement(aid))
    assert m.group(1) == out["transcriptCommitment"]


def test_o9_orderindex_continuous_over_authentic_first(direct_vm):
    """orderIndex is 1..N with authentic records first (canonical order),
    then context records — deterministic and identical across runs."""
    ka, kb = _agents()
    t = _transcript(ka, kb)
    t.append(FX.unsigned_rec(9, "listener", "just watching"))
    out1, out2 = classify_all(direct_vm, [t, t])
    assert out1["evidenceHash"] == out2["evidenceHash"]
    assert out1["recordCounts"]["AUTHENTIC_SIGNED"] == 3
    assert out1["recordCounts"]["UNSIGNED"] == 1


def test_o10_same_records_different_order_never_same_hash(direct_vm):
    """Property-style check: for permutations of venue-array order the hash
    is CONSTANT (canonicalization), but re-signed nonce-swapped variants
    (different signed chronology) all differ from each other."""
    import itertools

    ka, kb = _agents()
    t = [
        FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1001"),
        FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002"),
    ]
    perms = [list(p) for p in itertools.permutations(t)]
    variants = [
        [FX.real_record(ka, ROOM, 1, FX.OFFER_TEXT, "1001"),
         FX.real_record(kb, ROOM, 2, FX.ACCEPT_TEXT, "1002")],
        [FX.real_record(kb, ROOM, 1, FX.OFFER_TEXT, "1001"),
         FX.real_record(ka, ROOM, 2, FX.ACCEPT_TEXT, "1002")],
        [FX.real_record(ka, ROOM, 1, FX.ACCEPT_TEXT, "1001"),
         FX.real_record(kb, ROOM, 2, FX.OFFER_TEXT, "1002")],
    ]
    outs = classify_all(direct_vm, perms + variants)
    hashes = {o["evidenceHash"] for o in outs[: len(perms)]}
    assert len(hashes) == 1  # canonicalization kills array-order ambiguity

    # but chronology changes (who signed which nonce) => distinct commitments
    commits = {o["transcriptCommitment"] for o in outs[len(perms) :]}
    assert len(commits) == 3, "different signed chronologies must yield distinct commitments"
