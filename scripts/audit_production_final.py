#!/usr/bin/env python3
"""FINAL INDEPENDENT PRODUCTION AUDIT — read-only, no code changes.

Drives the EXACT public URL in pristine fresh browser sessions and records
the runtime truth: mode marker, contract address, demo room, live tx,
on-chain readback, hash/commitment equality, and second-session
idempotency. Also probes the pre-JS static HTML fallback (what a
no-JavaScript fetcher sees) to classify stale-marker visibility.
"""
import importlib.util
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
URL = "https://faisalnugroho.github.io/gendid/"
ADDR_EXPECTED = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"
AID_EXPECTED = "GD-gendid-demo-01b-9b9a6ce6440da0d6"
HASH_EXPECTED = "9b9a6ce6440da0d6a0b2697b7d521ab19bd6823281879099ab5e836ff287a448"
CMT_EXPECTED = "71ba41a30cd313fe4f4b36b44e9197d5794ac73db1f38fc74054dd86383d8e67"
ROOM = "gendid-demo-01b"


def audit_pass(pw, pass_no, out):
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context()  # pristine: no cache, no storage
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(URL, wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(1800)  # app init renders the mode marker async

    # ---- runtime DOM state BEFORE any demo click ----
    mode_tag = page.inner_text("#mode-tag").strip()
    gl_note = page.inner_text("#gl-note").strip()
    # runtime contract address straight from the app's own JS state
    runtime_addr = page.evaluate("window.GENDID_CONTRACT || '(unset)'")
    runtime_room = page.evaluate("(() => { try { return window.GENDID_DEMOS.clear.room } catch (e) { return 'ERR' } })()")
    live_flag = page.evaluate(
        "(() => { const el = document.getElementById('gl-explain');"
        " return el ? el.textContent.slice(0, 60) : '' })()")

    out[f"pass{pass_no}"] = {
        "mode_tag": mode_tag,
        "gl_note": gl_note,
        "runtime_contract_addr": runtime_addr,
        "runtime_demo_room": runtime_room,
        "gl_explain_prefix": live_flag,
        "js_errors": errors,
    }

    # ---- run Demo A end-to-end ----
    page.click('[data-demo="clear"]')
    page.wait_for_timeout(2500)
    vout = page.inner_text("#verify-out")
    auth_ok = "AUTHENTIC" in vout
    ev_hash = page.inner_text("#e-hash").strip()
    ev_aid = page.inner_text("#e-aid").strip()
    # manifest signature completeness is surfaced in the toast; the judge path
    # below is the authoritative proof of authority acceptance
    page.wait_for_selector("#btn-judge", state="visible", timeout=10000)
    page.click("#btn-judge")
    status = ""
    for _ in range(100):
        page.wait_for_timeout(3000)
        status = page.inner_text("#r-status").strip()
        if status and status != "—":
            break
    tx_line = page.inner_text("#r-tx").strip()
    err_reason = page.inner_text("#r-err").strip()
    room_ui = page.inner_text("#r-room").strip()
    cmt_ui = page.inner_text("#r-hash").strip()  # evidence hash in receipt
    r_aid = page.inner_text("#r-aid").strip()

    out[f"pass{pass_no}"].update({
        "verify_authentic": auth_ok,
        "browser_evidenceHash": ev_hash,
        "browser_agreementId": ev_aid,
        "judge_status": status,
        "tx": tx_line,
        "errorReason": err_reason,
        "ui_room": room_ui,
        "receipt_aid": r_aid,
        "receipt_hash": cmt_ui,
    })
    ctx.close()
    browser.close()


def main():
    out = {}
    with sync_playwright() as pw:
        audit_pass(pw, 1, out)
        audit_pass(pw, 2, out)  # fully fresh session (new context + browser)

    # ---- direct on-chain readback (deployed contract, own connection) ----
    spec = importlib.util.spec_from_file_location(
        "ds", ROOT / "scripts" / "deploy_smoke.py")
    ds = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ds)
    from genlayer_py import create_client
    from genlayer_py.chains import studionet
    client = create_client(chain=studionet, account=ds.load_account())
    rec = ds.read_json(client, ADDR_EXPECTED, "get_agreement", [AID_EXPECTED])
    seal = ds.read_json(client, ADDR_EXPECTED, "get_room_seal", [ROOM])
    out["onchain"] = {
        "status": rec.get("status"),
        "finalized": rec.get("finalized"),
        "evidenceHash": rec.get("evidenceHash"),
        "transcriptCommitment": rec.get("transcriptCommitment"),
        "transcriptRoom": rec.get("transcriptRoom"),
        "room_seal": seal,
        "questionLabels": rec.get("questionLabels"),
    }

    # ---- static-fallback probe: what a no-JS fetcher sees at the same URL ----
    import urllib.request
    req = urllib.request.Request(URL, headers={"User-Agent": "curl/8.0"})
    raw_html = urllib.request.urlopen(req, timeout=30).read().decode()
    out["static_fallback"] = {
        "nojs_mode_tag_literal": "LOCAL / DEMO MODE" in raw_html,
        "nojs_note_literal": "no contract address configured" in raw_html,
        "nojs_old_contract_0xb865": "0xb865" in raw_html,
        "nojs_old_contract_0xF3A0": "0xF3A0" in raw_html,
        "nojs_current_contract_present": "0xfb861614" in raw_html,
        "script_tags": raw_html.count("<script src="),
    }

    print(json.dumps(out, indent=2, default=str))

    # ---- verdict computation ----
    p1, p2, oc = out["pass1"], out["pass2"], out["onchain"]
    verdict = {
        "A_runtime_mode_is_live": p1["mode_tag"].upper().startswith("GENLAYER"),
        "B_contract_addr_exact": p1["runtime_contract_addr"] == ADDR_EXPECTED
                                 and p2["runtime_contract_addr"] == ADDR_EXPECTED,
        "D_live_tx_pass1": p1["tx"].startswith("0x") and len(p1["tx"]) >= 60,
        "D_live_tx_pass2": p2["tx"].startswith("0x") and len(p2["tx"]) >= 60,
        "E_onchain_status_agreed": oc["status"] == "AGREED",
        "F_hash_match": p1["browser_evidenceHash"] == oc["evidenceHash"] == HASH_EXPECTED
                        and p2["browser_evidenceHash"] == HASH_EXPECTED,
        "G_commitment_match": oc["transcriptCommitment"] == oc["room_seal"] == CMT_EXPECTED,
        "H_second_run_idempotent": (p2["judge_status"] == "AGREED"
                                    and p2["browser_agreementId"] == AID_EXPECTED
                                    and p2["browser_agreementId"] == p1["browser_agreementId"]
                                    and p2["browser_evidenceHash"] == p1["browser_evidenceHash"]
                                    and "conflicting" not in (p2["errorReason"] or "").lower()),
        "demo_room_correct": p1["runtime_demo_room"] == ROOM and p1["ui_room"] == ROOM,
        "agreementId_canonical": p1["browser_agreementId"] == AID_EXPECTED,
        "no_js_errors": not p1["js_errors"] and not p2["js_errors"],
    }
    print(json.dumps(verdict, indent=2))
    print("AUDIT_PASS:", all(verdict.values()))
    return 0 if all(verdict.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
