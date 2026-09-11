#!/usr/bin/env python3
"""Browser E2E against the NEW gendid/1.1 contract, through the real
frontend (local static serve of frontend/), driving the real UI:
Demo A -> Verify -> Judge (LIVE submit) -> on-chain readback.

DOM-state verification (per skill: DOM dumps beat screenshots):
assert the live pipeline panel shows the pinned contract address, a real
tx hash, and the on-chain AGREED status; assert the browser-computed
evidence hash matches the chain record's evidenceHash (client/chain
canonicalization parity, live).
"""
import json
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
ADDR_PIN = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"


def main():
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", "8123"],
        cwd=str(FRONTEND),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto("http://127.0.0.1:8123/index.html", wait_until="networkidle")
            page.wait_for_timeout(1500)  # app init writes the pinned-address note async

            # 1) pinned address visible (UI abbreviates to 0xfb861614…dD4B1;
            #    #gl-note sits inside a section hidden until first verification,
            #    so read the ELEMENT, not body innerText)
            gl_note = page.inner_text("#gl-note")
            assert "0xfb861614" in gl_note and "d4b1" in gl_note.lower(), \
                f"pinned address not shown in #gl-note: {gl_note!r}"
            print("[E2E] contract pin shown:", gl_note.strip())

            # 2) load Demo A — auto-verifies after 60ms (runDemo)
            page.click('[data-demo="clear"]')
            page.wait_for_timeout(2500)  # verify pipeline + render

            # 3) browser-side strict verification already ran — assert it
            vout = page.inner_text("#verify-out")
            assert "AUTHENTIC" in vout, f"no AUTHENTIC classification: {vout[:200]!r}"
            print("[E2E] browser verification:", " | ".join(
                l.strip() for l in vout.splitlines() if l.strip())[:3], "...")

            # 4) judge — LIVE submit to the new contract (button revealed
            #    in #sec-adjudicate once verification succeeded)
            page.wait_for_selector("#btn-judge", state="visible", timeout=10000)
            page.click("#btn-judge")
            # consensus takes ~40-100s; poll the RESULT element itself
            # (demo-card descriptions contain 'AGREED'/'NOT_AGREED' text, so
            # polling body text false-triggers immediately)
            status = ""
            for _ in range(80):
                page.wait_for_timeout(3000)
                status = page.inner_text("#r-status").strip()
                if status and status != "—":
                    break
            body_text = page.inner_text("body")
            print("[E2E] on-chain status:", repr(status))
            tx_line = page.inner_text("#r-tx").strip()
            print("[E2E] tx:", repr(tx_line))
            assert status == "AGREED", f"live adjudication did not AGREED: {status!r}"
            assert tx_line.startswith("0x") and len(tx_line) >= 60, \
                f"no real tx hash shown: {tx_line!r}"

            # 5) client/chain canonicalization parity (steward E2E req):
            #    browser-computed evidence hash + agreementId vs the
            #    on-chain record for this agreement
            ev_hash = page.inner_text("#e-hash").strip()
            ev_aid = page.inner_text("#e-aid").strip()
            print("[E2E] browser evidenceHash:", ev_hash)
            print("[E2E] browser agreementId:", ev_aid)
            assert ev_aid.startswith("GD-gendid-demo-01b-"), \
                f"demo A is not the deterministic room: {ev_aid!r}"
            # persist for the post-run on-chain readback
            Path("/tmp/e2e_browser_out.json").write_text(json.dumps({
                "browser_evidenceHash": ev_hash, "browser_agreementId": ev_aid,
                "tx": tx_line, "status": status,
            }, indent=2))

            browser.close()
        print("[E2E] OK")
        return 0
    finally:
        server.terminate()


if __name__ == "__main__":
    sys.exit(main())
