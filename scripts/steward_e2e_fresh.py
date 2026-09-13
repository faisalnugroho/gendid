#!/usr/bin/env python3
"""PHASE 4 — fresh live E2E from the ACTUAL PUBLIC GitHub Pages URL.

Two completely fresh Chromium contexts. Real UI clicks (Demo A -> Verify ->
Judge Agreement). The GenLayer SDK client is instrumented IN the page's main
world so we capture the EXACT three submit_evidence arguments the browser
generates, plus the readContract/get_agreement readback the frontend performs.

For each run we record: mode tag, window.GENDID_CONTRACT, verify output
(record statuses + manifest authority), the three tx arguments, tx hash,
final status, agreement id, evidence hash, and the browser-computed manifest
/ transcriptCommitment (recomputed from the captured records via the page's
own GD lib).
"""
import json
import sys
import time

from playwright.sync_api import sync_playwright

URL = "https://faisalnugroho.github.io/gendid/"
EXPECTED_CONTRACT = "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"
OUT = "/tmp/phase4_e2e.json"

INJECT = """
(() => {
  window.__CAP = { writes: [], reads: [], receipts: [], writer: null };
  const S = window.GenLayerSDK;
  const origCreate = S.createClient.bind(S);
  S.createClient = function (cfg) {
    const c = origCreate(cfg);
    const w = Object.create(c);
    w.writeContract = async function (o) {
      window.__CAP.writes.push({ ts: Date.now(), address: o.address,
        functionName: o.functionName, args: JSON.parse(JSON.stringify(o.args)) });
      return c.writeContract(o);
    };
    w.readContract = async function (o) {
      const r = await c.readContract(o);
      let rclip = r; try { rclip = JSON.stringify(r).slice(0, 4000); } catch (e) {}
      window.__CAP.reads.push({ ts: Date.now(), address: o.address,
        functionName: o.functionName, args: JSON.parse(JSON.stringify(o.args)),
        result: rclip });
      return r;
    };
    w.waitForTransactionReceipt = async function (o) {
      const r = await c.waitForTransactionReceipt(o);
      let rclip = r; try { rclip = JSON.stringify(r).slice(0, 6000); } catch (e) {}
      window.__CAP.receipts.push({ hash: o.hash, waitedStatus: o.status, result: rclip });
      return r;
    };
    return w;
  };
})();
"""

# after the submit is captured, recompute the browser-side canonical manifest
# from the EXACT captured records using the page's own gendid-lib (main world)
MANIFEST_RECOMPUTE = """
(async () => {
  const w = window.__CAP.writes[0];
  const room = w.args[0];
  const records = JSON.parse(w.args[1]);
  const ev = await window.GD.buildEvidencePackage(room, records);
  const manifest = await window.GD.buildManifest(room, ev);
  const sigs = JSON.parse(w.args[2]);
  // verify each captured manifest signature against the manifest string
  const mstr = window.GD.manifestStr(manifest);
  const sigChecks = {};
  for (const did of Object.keys(sigs)) {
    sigChecks[did] = window.GD.verifyManifestSig
      ? window.GD.verifyManifestSig(did, mstr, sigs[did])
      : 'no-helper';
  }
  return { room, manifestStr: mstr, manifest, sigChecks,
           evidenceHash: ev.evidenceHash, agreementId: ev.agreementId,
           counts: ev.counts, participants: ev.participants };
})()
"""


def one_run(pw, run_no):
    browser = pw.chromium.launch(headless=True, args=["--no-first-run"])
    ctx = browser.new_context()
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    out = {"run": run_no, "url": URL, "t_start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        page.goto(URL, wait_until="networkidle", timeout=60000)
        page.wait_for_timeout(1200)

        # 1-3: mode + contract pin (main world)
        pin = page.evaluate("""() => {
            const s = document.createElement('script');
            s.textContent = 'document.documentElement.setAttribute("d-p", window.GENDID_CONTRACT)';
            document.head.appendChild(s); s.remove();
            return document.documentElement.getAttribute('d-p');
        }""")
        mode_tag = page.inner_text("#mode-tag").strip()
        gl_note = page.inner_text("#gl-note").strip()
        out["window_GENDID_CONTRACT"] = pin
        out["mode_tag"] = mode_tag
        out["gl_note"] = gl_note
        assert pin == EXPECTED_CONTRACT, f"contract pin mismatch: {pin}"
        assert "GENLAYER · LIVE" in mode_tag, f"not live: {mode_tag}"

        # 4: load Demo A via the real button
        page.click('[data-demo="clear"]')
        page.wait_for_timeout(2500)

        # 5-7: verify (auto-run by runDemo; confirm output panel)
        verify_out = page.inner_text("#verify-out")
        out["verify_out_excerpt"] = verify_out[:400]
        assert "AUTHENTIC" in verify_out, f"verify output: {verify_out[:200]}"
        # record statuses rendered in the records table
        statuses = page.evaluate(
            "() => Array.from(document.querySelectorAll('.rec-status,.chip,.tag')).map(e=>e.textContent.trim()).filter(t=>/AUTHENTIC|UNSIGNED|INVALID|MALFORMED|DUPLICATE/.test(t))")
        out["record_statuses_seen"] = statuses

        # instrument SDK BEFORE clicking Judge
        page.evaluate(INJECT)

        # 8: submit via the real button
        page.wait_for_selector("#btn-judge", state="visible", timeout=10000)
        page.click("#btn-judge")

        # 10: wait for finalization (consensus ~60-90s live)
        deadline = time.time() + 420
        status = ""
        while time.time() < deadline:
            page.wait_for_timeout(4000)
            status = page.inner_text("#r-status").strip()
            if status and status not in ("", "—"):
                if page.inner_text("#r-state").strip().find("FINALIZED") >= 0:
                    break
        out["final_status_dom"] = status
        out["r_state"] = page.inner_text("#r-state").strip()
        out["r_tx_link"] = page.evaluate(
            "() => { const a = document.querySelector('#r-tx a'); return a ? a.href : null; }")
        out["agreementId_dom"] = page.inner_text("#r-aid").strip()
        out["evidenceHash_dom"] = page.inner_text("#e-hash").strip()
        out["e_aid"] = page.inner_text("#e-aid").strip()
        out["r_room"] = page.inner_text("#r-room").strip()
        out["r_hash"] = page.inner_text("#r-hash").strip()
        out["r_parts"] = page.inner_text("#r-parts").strip()
        out["r_counts"] = page.inner_text("#r-counts").strip()
        out["r_labels"] = page.inner_text("#r-labels").strip()
        out["r_summary"] = page.inner_text("#r-summary").strip()
        out["r_err"] = page.inner_text("#r-err").strip()
        out["pill"] = page.inner_text("#receipt-status-pill").strip()

        # captured SDK traffic
        cap = page.evaluate(
            "() => JSON.parse(JSON.stringify(window.__CAP))")
        out["sdk_writes"] = cap["writes"]
        out["sdk_reads"] = [{**r, "result": (r["result"] if isinstance(r["result"], str) else json.dumps(r["result"])[:3000])} for r in cap["reads"]]
        out["sdk_receipt_wait"] = [
            {"hash": r["hash"], "waitedStatus": r["waitedStatus"],
             "result": (r["result"][:3000] if isinstance(r["result"], str) else str(r["result"])[:3000])}
            for r in cap["receipts"]]
        # browser-computed canonical manifest from the EXACT captured args
        if cap["writes"]:
            out["browser_manifest_recompute"] = page.evaluate(MANIFEST_RECOMPUTE)

        out["js_errors"] = errors
        out["PASS"] = (
            status == "AGREED"
            and out["r_tx_link"] and out["r_tx_link"].startswith(
                "https://explorer-studio.genlayer.com/tx/0x")
            and len(cap["writes"]) == 1
            and cap["writes"][0]["functionName"] == "submit_evidence"
            and len(cap["writes"][0]["args"]) == 3
            and not errors)
    except Exception as e:
        out["FATAL"] = f"{type(e).__name__}: {str(e)[:400]}"
    finally:
        out["t_end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        browser.close()
    return out


def main():
    results = []
    with sync_playwright() as pw:
        for n in (1, 2):
            print(f"[E2E run {n}] fresh Chromium context -> {URL}", flush=True)
            r = one_run(pw, n)
            results.append(r)
            if "FATAL" in r:
                print(f"  FATAL: {r['FATAL']}")
            else:
                print(f"  status={r.get('final_status_dom')} "
                      f"tx={r.get('r_tx_link','')[-70:]}")
                w = r.get("sdk_writes", [])
                if w:
                    a = w[0]["args"]
                    print(f"  args: room={a[0]!r} records={len(json.loads(a[1]))} "
                          f"sigs={len(json.loads(a[2]))}")
            print(f"  PASS={r.get('PASS')}", flush=True)

    # idempotency check: same deterministic agreement, NEW tx each run
    if all(r.get("PASS") for r in results):
        a1, a2 = results[0], results[1]
        same_aid = a1["agreementId_dom"] == a2["agreementId_dom"]
        same_hash = a1["evidenceHash_dom"] == a2["evidenceHash_dom"]
        new_tx = a1["r_tx_link"] != a2["r_tx_link"]
        print(f"\n[idempotency] same agreementId={same_aid} "
              f"same evidenceHash={same_hash} distinct tx={new_tx}")
        print(f"[room] {a1['r_room']}  (expect gendid-demo-01b)")
        print(f"[manifest protocol] "
              f"{a1['browser_manifest_recompute']['manifest'].get('protocolVersion')}")
        m = a1["browser_manifest_recompute"]
        print(f"[manifestStr] {m['manifestStr'][:150]}…")
        print(f"[manifest sigs verified in-browser] {m['sigChecks']}")
        print(f"[transcriptCommitment] {m['manifest'].get('transcriptCommitment')}")

    json.dump(results, open(OUT, "w"), indent=2, default=str)
    ok = all(r.get("PASS") for r in results)
    print(f"\nPHASE4_VERDICT: {'PASS' if ok else 'FAIL'}  details: {OUT}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
