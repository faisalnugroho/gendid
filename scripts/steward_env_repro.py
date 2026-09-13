#!/usr/bin/env python3
"""Steward-environment reproduction: load the PRODUCTION GitHub Pages URL in
REAL Chromium (fresh profile per run), measure everything the Steward asked:
DNS, TLS, document response, JS asset load, JS execution, redirects, service
workers, runtime init, window.GENDID_CONTRACT, GENLAYER - LIVE rendering.

3 independent fresh-context runs + an external-path check.
"""
import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

URL = "https://faisalnugroho.github.io/gendid/"
HOST = "faisalnugroho.github.io"


def raw_dns_tls():
    """Raw DNS + TLS handshake timing outside the browser."""
    out = {}
    t0 = time.time()
    try:
        infos = socket.getaddrinfo(HOST, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        out["dns_resolve_ms"] = round((time.time() - t0) * 1000, 1)
        out["ips"] = ips
        t1 = time.time()
        ctx = ssl.create_default_context()
        with socket.create_connection((ips[0], 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=HOST) as tls:
                out["tls_handshake_ms"] = round((time.time() - t1) * 1000, 1)
                out["tls_version"] = tls.version()
                cert = tls.getpeercert()
                out["cert_not_after"] = cert.get("notAfter")
                san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNSName"]
                out["cert_san_sample"] = san[:4]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def chromium_pass(pw, run_no, slowmo=0):
    """One completely fresh Chromium profile -> URL -> full measurement."""
    browser = pw.chromium.launch(headless=True, args=[
        "--no-first-run", "--no-default-browser-check"])
    ctx = browser.new_context()  # fresh profile: empty storage, no SW
    page = ctx.new_page()

    net = {"requests": [], "failed": [], "redirects": []}
    js_errors, console = [], []
    page.on("pageerror", lambda e: js_errors.append(str(e)))
    page.on("console", lambda m: console.append(f"{m.type}: {m.text[:200]}"))
    page.on("requestfailed", lambda r: net["failed"].append(
        {"url": r.url, "err": r.failure} if r.failure else {"url": r.url}))
    def on_req(r):
        net["requests"].append({"url": r.url, "method": r.method})
        if r.redirected_from:
            net["redirects"].append({"from": r.redirected_from.url, "to": r.url})
    page.on("request", on_req)
    responses = {}
    def on_resp(r):
        responses[r.url] = {"status": r.status,
                            "cached": (r.headers.get("x-from-cache") == "1")}
    page.on("response", on_resp)

    result = {"run": run_no}
    t0 = time.time()
    try:
        resp = page.goto(URL, wait_until="domcontentloaded", timeout=45000)
        result["document"] = {
            "status": resp.status, "final_url": resp.url,
            "from_cache": "x-from-cache" in resp.headers
            and resp.headers.get("x-from-cache"),
            "server": resp.headers.get("server"),
            "age_header": resp.headers.get("age"),
            "cache_control": resp.headers.get("cache-control"),
        }
        page.wait_for_load_state("networkidle", timeout=30000)
        page.wait_for_timeout(1200)

        state = page.evaluate("""() => {
            const s = document.createElement('script');
            s.textContent = 'document.documentElement.setAttribute("d-a", ' +
                'JSON.stringify({c: window.GENDID_CONTRACT||null, ' +
                'sdk: typeof window.GenLayerSDK, nacl: typeof window.nacl, ' +
                'demos: typeof window.GENDID_DEMOS, lib: typeof window.GD}));';
            document.head.appendChild(s); s.remove();
            return JSON.parse(document.documentElement.getAttribute('d-a'));
        }""")
        mode = page.evaluate("""() => {
            const t = document.getElementById('mode-tag');
            return t ? t.textContent : 'NO-MODE-TAG';
        }""")
        result["js_execution"] = {
            "window_GENDID_CONTRACT": state.get("c"),
            "GenLayerSDK": state.get("sdk"), "nacl": state.get("nacl"),
            "GENDID_DEMOS": state.get("demos"), "GD_lib": state.get("lib"),
        }
        result["mode_tag"] = mode
        result["title"] = page.title()
        # service worker / cache
        result["service_worker"] = page.evaluate(
            """async () => navigator.serviceWorker
                 ? (await navigator.serviceWorker.getRegistrations()).length : -1""")
        result["localStorage_keys"] = page.evaluate(
            "() => Object.keys(window.localStorage)")
        result["banner_text"] = page.evaluate(
            "() => document.querySelector('.banner') ? document.querySelector('.banner').innerText.trim().slice(0,120) : null")
        # assets: all loaded, same-origin, relative
        assets = page.evaluate(
            "() => Array.from(document.scripts).map(s => s.src).filter(Boolean)")
        result["assets"] = assets
        result["assets_all_same_origin"] = all(
            a.startswith("https://faisalnugroho.github.io/") for a in assets)
        result["statuses"] = {u: responses.get(u, {}).get("status", "?")
                              for u in assets}
        result["net"] = {
            "request_count": len(net["requests"]),
            "non_pages_requests": [r["url"] for r in net["requests"]
                                    if "github.io" not in r["url"]],
            "failed": net["failed"],
            "redirects": net["redirects"],
        }
        result["js_errors"] = js_errors
        result["console"] = console[:10]
        result["load_ms_total"] = round((time.time() - t0) * 1000, 1)
        result["PASS"] = (
            result["document"]["status"] == 200
            and state.get("c") == "0xfb861614e3f274bc3e3253cd0857c70fc08dD4B1"
            and "GENLAYER · LIVE" in mode
            and not js_errors and not net["failed"]
            and result["assets_all_same_origin"]
            and result["service_worker"] == 0)
    except Exception as e:
        result["FATAL"] = f"{type(e).__name__}: {str(e)[:500]}"
        result["load_ms_total"] = round((time.time() - t0) * 1000, 1)
    finally:
        browser.close()
    return result


def main():
    print("=" * 70)
    print("PHASE 2 — STEWARD ENVIRONMENT REPRODUCTION (real Chromium)")
    print("=" * 70)
    print("\n[raw socket] DNS + TLS to github.io CDN:")
    print(json.dumps(raw_dns_tls(), indent=2))

    runs = []
    with sync_playwright() as pw:
        for n in (1, 2, 3):
            print(f"\n[chromium run {n}] fresh profile -> {URL}")
            r = chromium_pass(pw, n)
            runs.append(r)
            verdict = "PASS" if r.get("PASS") or r.get("document", {}).get("status") == 200 else "FATAL"
            if "FATAL" in r:
                verdict = "FATAL: " + r["FATAL"][:200]
            print(f"  document: {r.get('document',{}).get('status')} "
                  f"| total {r.get('load_ms_total')}ms | mode: {r.get('mode_tag')!r} "
                  f"| SW: {r.get('service_worker')} | errors: {len(r.get('js_errors',[]))} "
                  f"failed-req: {len(r.get('net',{}).get('failed',[]))} -> {verdict}")

    print("\n[summary] all three fresh Chromium contexts:")
    for r in runs:
        print(f"  run {r['run']}: PASS={r.get('PASS')} "
              f"contract={r.get('js_execution',{}).get('window_GENDID_CONTRACT')} "
              f"mode={r.get('mode_tag')}")

    print("\n[external path] curl from a DIFFERENT resolver path "
          "(public DoH-resolved IP pinned, TLS SNI):")
    try:
        doh = json.loads(urllib.request.urlopen(
            "https://cloudflare-dns.com/dns-query?name=" + HOST +
            "&type=A", headers={"accept": "application/dns-json"}, timeout=10).read())
        ip = doh["Answer"][0]["data"]
        print(f"  DoH A record: {ip}")
        out = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w",
             "%{http_code} dns=%{time_namelookup}s connect=%{time_connect}s "
             "tls=%{time_appconnect}s ttfb=%{time_starttransfer}s total=%{time_total}s",
             f"--resolve", f"{HOST}:443:{ip}", "--max-time", "30", URL],
            capture_output=True, text=True, timeout=40)
        print(f"  curl via {ip}: {out.stdout} {out.stderr.strip()}")
    except Exception as e:
        print(f"  external path failed: {e}")

    ok = all(r.get("PASS") for r in runs)
    print("\nPHASE2_VERDICT:", "REACHABLE_IN_CHROMIUM" if ok else "FAILURE_REPRODUCED")
    json.dump({"raw": raw_dns_tls(), "runs": runs},
              open("/tmp/phase2_steward_repro.json", "w"), indent=2)
    print("details: /tmp/phase2_steward_repro.json")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
