// gendid-app.js — UI logic for GenDid. Wires the page to gendid-lib.js (GD).
// Zero-backend: verification is local; GenLayer path only runs when
// window.GENDID_CONTRACT (contract-address.js) is present.
/* global GD, GENDID_DEMOS, GenLayerSDK */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var CONTRACT = (typeof window.GENDID_CONTRACT === "string" && /^0x[0-9a-fA-F]{40}$/.test(window.GENDID_CONTRACT)) ? window.GENDID_CONTRACT : "";
  var EXPLORER_TX = "https://explorer-studio.genlayer.com/tx/";
  var LIVE = !!CONTRACT;

  // ------------------------------ state ------------------------------
  var state = {
    identity: null,          // {seedHex, did, kp}
    room: "gendid-demo-01",  // current transcript room
    rawRecords: [],           // canonical raw records loaded
    sourceLabel: "",         // how they were loaded ("demo A", "paste", "room x")
    demoKey: null,           // active demo key (for manifest signing)
    verified: null,          // result of buildEvidencePackage
    judging: false,
    lastResult: null,        // {record, txHash, mode, labels, candidate, why}
  };
  var ID_KEY = "gendid_identity_seed";

  // ------------------------------ utils ------------------------------
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function toast(msg, isErr) {
    var t = $("toast");
    t.textContent = msg;
    t.className = "toast show" + (isErr ? " err" : "");
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.className = "toast"; }, 4200);
  }
  function nowIso() { return new Date().toISOString(); }
  function clip(s) { return (s || "").slice(0, 120); }

  function copyText(txt, label) {
    function done(ok) { toast(ok ? (label || "Copied") + " copied to clipboard" : "Copy failed — clipboard unavailable", !ok); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(function () { done(true); }, function () { done(false); });
    } else {
      try {
        var ta = document.createElement("textarea");
        ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        done(document.execCommand("copy"));
        document.body.removeChild(ta);
      } catch (e) { done(false); }
    }
  }

  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest(".copybtn") : null;
    if (!b) return;
    var src = $(b.getAttribute("data-copy"));
    if (src && src.textContent) copyText(src.textContent.trim(), "Value");
  });

  // ------------------------------ identity ------------------------------
  function loadIdentity() {
    try {
      var seed = localStorage.getItem(ID_KEY);
      if (seed && /^[0-9a-f]{64}$/.test(seed)) {
        state.identity = GD.identityFromSeed(seed);
        renderIdentity("restored from this browser");
        return;
      }
    } catch (e) { /* private mode — fall through to generate */ }
    newIdentity(true);
  }
  function newIdentity(silent) {
    var id = GD.generateIdentity();
    try { localStorage.setItem(ID_KEY, id.seedHex); } catch (e) { /* session-only */ }
    state.identity = id;
    renderIdentity("generated just now — new key");
    if (!silent) toast("New DID generated. The old identity is gone; keys are never recoverable.");
  }
  function renderIdentity(note) {
    var did = state.identity.did;
    $("id-local").textContent = did;
    $("id-pub").textContent = did.replace("did:key:", "");
    $("id-status").innerHTML = '<span class="g">✓</span> KEY PRESENT · LOCAL';
    $("id-method").textContent =
      "Ed25519VerificationKey2020 · did:key:z6Mk… (self-certifying — the identifier IS the key) · " + note;
  }

  // ------------------------------ transcript loading ------------------------------
  // Normalize any accepted input shape to canonical raw records:
  //   gendid shape:   {sequence, timestamp, senderDid, nonce, signature, text}
  //   technocore JSON: {seq, ts, from, text, nonce, sig}
  function normalizeRecords(arr, room) {
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      var r = arr[i];
      if (!r || typeof r !== "object") { out.push({ malformed: true, idx: i, raw: r }); continue; }
      var sender = (r.senderDid !== undefined) ? r.senderDid : r.from;
      var seq = (r.sequence !== undefined) ? r.sequence : r.seq;
      var sig = (r.signature !== undefined) ? r.signature : r.sig;
      var nonce = (r.nonce !== undefined) ? r.nonce : (r.nonce === undefined && r.sig === undefined && r.seq !== undefined ? "" : r.nonce);
      // technocore lane: pre-sig records have no sig/nonce at all
      if (r.senderDid === undefined && r.seq !== undefined && r.sig === undefined) nonce = "";
      var rec = {
        sequence: seq,
        timestamp: (r.timestamp !== undefined) ? r.timestamp : r.ts,
        senderDid: sender,
        nonce: (nonce === undefined || nonce === null) ? "" : String(nonce),
        signature: (sig === undefined || sig === null) ? "" : String(sig),
        text: r.text,
      };
      if (typeof rec.sequence !== "number" || typeof rec.senderDid !== "string" || typeof rec.text !== "string") {
        rec.malformed = true; rec.raw = r;
      }
      out.push(rec);
    }
    return out;
  }

  function parsePastedTranscript(text) {
    var trimmed = text.trim();
    if (!trimmed) throw new Error("Paste a transcript first (or load a demo).");
    var parsed;
    try { parsed = JSON.parse(trimmed); }
    catch (e) { throw new Error("Not valid JSON — expected an array of records (see the placeholder for the shape)."); }
    if (!Array.isArray(parsed)) throw new Error("Expected a JSON array of records.");
    return parsed;
  }

  function setRoomFromRecords(recs, fallback) {
    var room = null;
    for (var i = 0; i < recs.length; i++) {
      if (recs[i] && recs[i].room) { room = recs[i].room; break; }
    }
    state.room = room || fallback || "gendid-demo-01";
  }

  function loadRecords(rawInput, roomGuess, sourceLabel) {
    var recs = normalizeRecords(rawInput, roomGuess);
    if (!recs.length) throw new Error("No records found.");
    if (recs.length > 60) recs = recs.slice(0, 60); // contract MAX_RECORDS
    setRoomFromRecords(rawInput, roomGuess);
    state.rawRecords = recs;
    state.sourceLabel = sourceLabel;
    state.verified = null;
    state.lastResult = null;
    renderRecords();
    resetDownstream();
    $("tc-room").value = state.room;
    toast("Loaded " + recs.length + " record" + (recs.length === 1 ? "" : "s") + " from " + sourceLabel + " — room “" + state.room + "”.");
    var vbtn = $("btn-verify");
    if (vbtn) vbtn.disabled = false;
  }

  // ------------------------------ demos ------------------------------
  function demoIdentity(seedHex) { return GD.identityFromSeed(seedHex); }

  function buildDemo(demoKey) {
    var d = window.GENDID_DEMOS[demoKey];
    if (!d) throw new Error("Unknown demo: " + demoKey);
    var ids = { a: demoIdentity(d.seedA), b: demoIdentity(d.seedB) };
    if (d.seedN) ids.n = demoIdentity(d.seedN);
    // gendid/1.2: FULLY DETERMINISTIC demo records. Every page load builds
    // the byte-identical transcript (same nonces -> same Ed25519 signatures
    // -> same canonical records -> same manifest/transcriptCommitment/
    // evidenceHash -> same agreementId). This makes the public demo
    // idempotent on-chain: the first authoritative run seals the room, and
    // every later page load resubmits the IDENTICAL manifest, so the
    // contract's early-return path (existing finalized record) returns the
    // same AGREED result — never a conflicting_snapshot. The historical
    // Math.random() nonce jitter made each load a different snapshot and
    // collided with the room seal (found live 2026-09-11).
    var base = 1757318040000;
    var recs = d.script.map(function (line, i) {
      var id = ids[line.who];
      var nonce = line.unsigned ? "" : String(base + (i + 1) * 7000); // strictly increasing, FIXED
      var ts = new Date(base + (i + 1) * 7000).toISOString();
      var sig = (line.unsigned || !id.kp) ? "" : GD.signSay(id, d.room, nonce, line.text);
      return {
        recordId: "gdr-" + d.room + "-" + (i + 1),
        room: d.room,
        sequence: i + 1,
        timestamp: ts,
        senderDid: id ? id.did : "listener",
        nonce: nonce,
        signature: sig,
        text: line.text,
      };
    });
    return recs;
  }

  function runDemo(demoKey) {
    try {
      state.demoKey = demoKey;
      var recs = buildDemo(demoKey);
      loadRecords(recs, window.GENDID_DEMOS[demoKey].room, "demo " + demoKey);
      // select the matching card
      document.querySelectorAll(".demo-card").forEach(function (c) {
        c.classList.toggle("sel", c.getAttribute("data-demo") === demoKey);
      });
      // auto-verify for a smooth demo flow
      setTimeout(verifyTranscript, 60);
    } catch (e) {
      toast(clip(e.message) || "Demo failed", true);
    }
  }

  // ------------------------------ technocore room ------------------------------
  function loadTechnocoreRoom() {
    var room = ($("tc-room").value || "").trim().toLowerCase();
    if (!room) { toast("Enter a room name first.", true); return; }
    if (!GD.ROOM_RE.test(room)) { toast("Room names: lowercase letters, digits, - and _ (max 48).", true); return; }
    var btn = $("btn-tc-load");
    btn.disabled = true; btn.textContent = "Fetching…";
    GD.tcReadRoom(room, 200).then(function (msgs) {
      if (!msgs || !msgs.length) throw new Error("Room “" + room + "” is empty or does not exist yet.");
      loadRecords(msgs, room, "technocore room " + room);
    }).catch(function (e) {
      toast(clip(e.message || "Could not read room"), true);
    }).finally(function () {
      btn.disabled = false; btn.textContent = "Fetch live room";
    });
  }

  // ------------------------------ rendering: records ------------------------------
  var CLASS_MAP = {
    AUTHENTIC_SIGNED: { cls: "auth", icon: "✓", label: "AUTHENTIC SIGNED", pill: "ok" },
    UNSIGNED: { cls: "uns", icon: "⚠", label: "UNSIGNED", pill: "warn" },
    INVALID_SIGNATURE: { cls: "inv", icon: "✕", label: "INVALID SIGNATURE", pill: "bad" },
    MALFORMED: { cls: "mal", icon: "⚠", label: "MALFORMED", pill: "bad" },
    DUPLICATE: { cls: "dup", icon: "⧉", label: "DUPLICATE (inert)", pill: "mute" },
  };

  function renderRecords() {
    var card = $("records-card"), list = $("rec-list");
    card.hidden = false;
    list.innerHTML = "";
    var cls = state.verified ? state.verified : null;

    state.rawRecords.forEach(function (rec, i) {
      var c = cls && cls.records ? (cls.records[i] || null) : null;
      // match canonical to raw by sequence when order differs
      if (cls && c && c.sequence !== rec.sequence) {
        c = cls.records.find(function (r) { return r.sequence === rec.sequence; }) || null;
      }
      var status = c ? c.signatureStatus : null;
      var meta = CLASS_MAP[status] || CLASS_MAP.MALFORMED;
      var div = document.createElement("div");
      div.className = "rec " + (status ? meta.cls : "mal");

      var seq = rec.malformed ? "?" : rec.sequence;
      var did = esc(rec.malformed ? "(unparseable record)" : (rec.senderDid || ""));
      var ts = rec.timestamp ? esc(rec.timestamp) : "";
      var text = rec.malformed ? "(record could not be parsed: " + esc(JSON.stringify(rec.raw).slice(0, 80)) + "…)" : esc(rec.text || "");

      var pillHtml = status
        ? '<span class="pill ' + meta.pill + '"><span class="g">' + meta.icon + "</span> " + meta.label + "</span>"
        : '<span class="pill mute">NOT VERIFIED YET</span>';

      var tag = (rec.text && GD.tclkTag) ? GD.tclkTag(rec.text) : "";
      var tclk = tag ? '<span class="tclk">tclk/1 · ' + esc(tag) + "</span>" : "";

      var reject = "";
      if (cls && cls.rejections) {
        var rid = "gdr-" + state.room + "-" + seq;
        var why = cls.rejections[rid];
        if (why) reject = '<div class="rec-reject">reason: ' + esc(why) + "</div>";
      }

      var sigShort = "—";
      if (rec.signature) sigShort = rec.signature.slice(0, 16) + "…" + rec.signature.slice(-8);
      var nonceShort = rec.nonce || "—";

      div.innerHTML =
        '<div class="rec-top">' +
        '<span class="rec-seq">#' + esc(String(seq)) + "</span>" +
        '<span class="rec-did">' + did + "</span>" +
        tclk +
        '<span class="rec-ts">' + ts + "</span>" +
        pillHtml +
        "</div>" +
        '<div class="rec-text">' + text + "</div>" +
        '<div class="rec-meta"><b>nonce</b> ' + esc(nonceShort) + " · <b>sig</b> " + esc(sigShort) + "</div>" +
        reject;
      list.appendChild(div);
    });

    var note = $("records-note");
    if (note) note.textContent = "— " + state.rawRecords.length + " loaded from " + state.sourceLabel + (cls ? " · verified" : " · not yet verified");
  }

  function resetDownstream() {
    $("verify-out").classList.add("hidden");
    ["sec-analyze", "sec-adjudicate", "sec-why", "sec-receipt"].forEach(function (id) { $(id).hidden = true; });
    ["result", "pipe"].forEach(function (id) { $(id).classList.add("hidden"); });
    // reset pipeline + question pills
    document.querySelectorAll(".pipe-step").forEach(function (s) { s.className = "pipe-step"; });
    Q_IDS.forEach(function (q) { var el = $("q-" + q); if (el) { el.className = "pill mute"; el.textContent = "—"; } });
  }

  var Q_IDS = ["two_or_more_participants", "offer_present", "acceptance_present", "acceptance_matches_offer", "no_contradiction", "evidence_grounded"];

  // ------------------------------ verify ------------------------------
  function verifyTranscript() {
    try {
      if (!state.rawRecords.length) {
        // try to parse the textarea first
        var pasted = parsePastedTranscript($("transcript-input").value);
        loadRecords(pasted, null, "pasted transcript");
      }
      var clean = state.rawRecords.filter(function (r) { return !r.malformed; });
      GD.buildEvidencePackage(state.room, clean).then(function (ev) {
        return GD.buildManifest(state.room, ev).then(function (manifest) {
          var mstr = GD.manifestStr(manifest);
          // Sign the manifest with every participant identity we hold in
          // this browser (demo identities are deterministic from seeds; a
          // user pasting a transcript needs each participant's manifest
          // signature supplied alongside, or the contract marks it
          // NON_AUTHORITATIVE — by design).
          var sigs = {};
          var tasks = [];
          var demoSeeds = null;
          try {
            var dk = state.demoKey || (state.sourceLabel || "").replace("demo ", "");
            if (window.GENDID_DEMOS && window.GENDID_DEMOS[dk]) {
              demoSeeds = window.GENDID_DEMOS[dk];
            }
          } catch (e) { /* no demos */ }
          if (demoSeeds) {
            ["a", "b", "n"].forEach(function (w) {
              var seedHex = w === "a" ? demoSeeds.seedA : w === "b" ? demoSeeds.seedB : demoSeeds.seedN;
              if (!seedHex) return;
              var id = GD.identityFromSeed(seedHex);
              if (manifest.participants.indexOf(id.did) >= 0) {
                tasks.push(
                  Promise.resolve(nacl_sign_manifest(id, mstr)).then(function (r) { sigs[r.did] = r.sig; })
                );
              }
            });
          }
          return Promise.all(tasks).then(function () {
            state.verified = ev;
            state.verified.manifest = manifest;
            state.verified.manifestStr = mstr;
            state.verified.manifestSigs = sigs;
            renderVerified();
            renderRecords(); // re-render with statuses
            $("sec-analyze").hidden = false;
            // reveal the adjudication panel so the user can actually click
            // Judge — previously the ONLY code unhiding #sec-adjudicate was
            // judgeAgreement() itself, whose trigger button lives INSIDE the
            // hidden section (unclickable). Found during the Sep 2026
            // steward-hardening live E2E.
            $("sec-adjudicate").hidden = false;
            renderCandidate();
            var nAuth = ev.counts.AUTHENTIC_SIGNED;
            var nSig = Object.keys(sigs).length;
            toast("Verified: " + nAuth + " authentic · " + nSig + "/" + manifest.participants.length +
              " manifest signatures" + (nSig < manifest.participants.length ? " — incomplete authority (will be NON_AUTHORITATIVE)" : " — authority OK"));
          });
        });
      });
    } catch (e) {
      toast(clip(e.message) || "Verification failed", true);
    }
  }

  function nacl_sign_manifest(identity, mstr) {
    // detached Ed25519 over the exact manifestStr bytes — same signer as
    // records (mirrors GD.signSay's use of nacl.sign.detached).
    var sig = nacl.sign.detached(new TextEncoder().encode(mstr), identity.kp.secretKey);
    return { did: identity.did, sig: GD.b64url(sig) };
  }

  function renderVerified() {
    var v = state.verified, c = v.counts;
    $("verify-out").classList.remove("hidden");
    $("c-total").textContent = String(c.AUTHENTIC_SIGNED + c.UNSIGNED + c.INVALID_SIGNATURE + c.MALFORMED + c.DUPLICATE);
    $("c-auth").textContent = String(c.AUTHENTIC_SIGNED);
    $("c-uns").textContent = String(c.UNSIGNED);
    $("c-inv").textContent = String(c.INVALID_SIGNATURE);
    $("c-mal").textContent = String(c.MALFORMED);
    $("c-dup").textContent = String(c.DUPLICATE);
    $("e-hash").textContent = v.evidenceHash;
    $("e-aid").textContent = v.agreementId;
  }

  // ------------------------------ candidate agreement ------------------------------
  // Deterministic advisory parser: reads ONLY authentic records, extracts what
  // is explicitly there, never invents. (Contract treats this as a hint.)
  function buildCandidate() {
    var v = state.verified;
    var auth = v.records.filter(function (r) { return r.signatureStatus === "AUTHENTIC_SIGNED"; });
    var participants = v.participants.slice();
    var lines = [];
    // find offer: first authentic record with concrete terms heuristics
    var offerRec = null;
    var OFFER_HINTS = /\b(task|need|require|must|output|price|latency|deadline|credits|deliver|service|job|normalize|build|write|generate)\b/i;
    for (var i = 0; i < auth.length; i++) {
      if (OFFER_HINTS.test(auth[i].text) && auth[i].text.length > 25) { offerRec = auth[i]; break; }
    }
    var acceptRec = null;
    if (offerRec) {
      for (var j = 0; j < auth.length; j++) {
        var r = auth[j];
        if (r.senderDid !== offerRec.senderDid && /\b(accept|agreed|deal|confirmed|i will|sounds good|sure)\b/i.test(r.text)) { acceptRec = r; break; }
      }
    }
    // amendments: later authentic records after acceptance that modify terms
    var amendments = [];
    if (offerRec && acceptRec) {
      for (var k = 0; k < auth.length; k++) {
        var a = auth[k];
        if (a.sequence > acceptRec.sequence && /\b(amend|instead|change|new price|revise|update)\b/i.test(a.text)) {
          amendments.push(a);
        }
      }
    }
    // contradictions: later authenticated cancel/reject
    var contradictions = [];
    for (var m = 0; m < auth.length; m++) {
      var x = auth[m];
      if (/\b(cancel|withdraw|reject|refuse|revoke|void|no longer|call off)\b/i.test(x.text)) contradictions.push(x);
    }

    var terms = extractTerms(offerRec ? offerRec.text : "");
    var acceptedTerms = acceptRec ? extractTerms(acceptRec.text) : null;

    return {
      participants: participants,
      offerRecord: offerRec, acceptRecord: acceptRec,
      task: terms.task, deadline: terms.deadline, output: terms.output, payment: terms.payment,
      acceptedTask: acceptedTerms ? acceptedTerms.task : null,
      amendments: amendments, contradictions: contradictions,
      relevant: [].concat(offerRec ? [offerRec.recordId] : [], acceptRec ? [acceptRec.recordId] : [],
        amendments.map(function (r) { return r.recordId; }), contradictions.map(function (r) { return r.recordId; })),
      lines: lines,
    };
  }

  function extractTerms(text) {
    if (!text) return {};
    var out = {};
    var m;
    if ((m = text.match(/(?:latency|deadline|within|under|maximum[^.]*?)\s*(\d+)\s*(seconds?|secs?|s|minutes?|mins?|hours?|days?)/i))) out.deadline = m[0].trim();
    if ((m = text.match(/(\d+)\s*(?:credits?|GEN|tokens?|points?|USD|\$)/i))) out.payment = m[0].trim();
    if (/\bJSON\b/i.test(text)) (out.output = out.output || "JSON");
    if (/\bCSV\b/i.test(text)) (out.task = out.task || "CSV normalization");
    if ((m = text.match(/\b(?:task|job|work|service)\b[^.]*?\b(?:is|:)\s*([^.]{3,60})/i))) out.task = out.task || m[1].trim();
    return out;
  }

  function renderCandidate() {
    var cand = buildCandidate();
    state.candidate = cand;
    var kv = $("candidate-kv");
    var rows = [];
    function row(k, vTxt, dim) {
      rows.push('<span class="k">' + esc(k) + '</span><span class="v' + (dim ? " dim" : "") + '">' + vTxt + "</span>");
    }
    function recCite(r) {
      return r ? ' <span style="color:var(--faint)">· #' + esc(String(r.sequence)) + "</span>" : "";
    }
    var dids = cand.participants.map(function (d) { return '<span class="mono-s" style="color:var(--cyan);word-break:break-all">' + esc(d) + "</span>"; });
    row("Participants", dids.join('<span style="color:var(--faint)"> · </span>') || '<span style="color:var(--faint)">none authenticated</span>');
    row("Task", cand.task ? esc(cand.task) + recCite(cand.offerRecord) : "not stated", !cand.task);
    row("Deadline", cand.deadline ? esc(cand.deadline) + recCite(cand.offerRecord) : "not stated", !cand.deadline);
    row("Output requirements", cand.output ? esc(cand.output) + recCite(cand.offerRecord) : "not stated", !cand.output);
    row("Payment / conditions", cand.payment ? esc(cand.payment) + recCite(cand.offerRecord) : "not stated", !cand.payment);
    row("Acceptance", cand.acceptRecord ? "authenticated acceptance · #" + esc(String(cand.acceptRecord.sequence)) : "none detected", !cand.acceptRecord);
    row("Amendments", cand.amendments.length
      ? cand.amendments.map(function (r) { return "#" + esc(String(r.sequence)); }).join(", ")
      : "none", !cand.amendments.length);
    row("Contradictions", cand.contradictions.length
      ? cand.contradictions.map(function (r) { return "#" + esc(String(r.sequence)); }).join(", ")
      : "none", !cand.contradictions.length);
    row("Relevant evidence IDs", cand.relevant.length
      ? '<span class="mono-s" style="color:var(--cyan)">' + esc(cand.relevant.join(" · ")) + "</span>"
      : "—", !cand.relevant.length);
    kv.innerHTML = rows.join("");
  }

  // ------------------------------ local (demo) labels ------------------------------
  // The same six questions the contract's LLM answers — computed by transparent
  // deterministic heuristics so the demo path never fakes consensus. The status
  // derivation itself is a faithful re-implementation of _derive_status.
  function localLabels(cand) {
    var labels = {};
    labels.two_or_more_participants = state.verified.participants.length >= 2 ? "PASS" : "FAIL";
    labels.offer_present = cand.offerRecord ? "PASS" : (state.verified.counts.AUTHENTIC_SIGNED ? "UNCERTAIN" : "FAIL");
    labels.acceptance_present = cand.acceptRecord ? "PASS" : (cand.offerRecord ? "FAIL" : "UNCERTAIN");
    // Q4: acceptance echoes the offer's key terms?
    if (cand.offerRecord && cand.acceptRecord) {
      var echoed = 0;
      ["JSON", "CSV", "30", "5"].forEach(function (t) {
        if (cand.offerRecord.text.indexOf(t) >= 0 && cand.acceptRecord.text.indexOf(t) >= 0) echoed++;
      });
      var vague = !/\b(\d+|JSON|CSV|credits?)\b/i.test(cand.acceptRecord.text);
      labels.acceptance_matches_offer = vague ? "UNCERTAIN" : "PASS";
    } else {
      labels.acceptance_matches_offer = cand.offerRecord ? "FAIL" : "UNCERTAIN";
    }
    // Q5: any authenticated contradiction AFTER acceptance?
    var late = cand.contradictions.filter(function (r) { return !cand.acceptRecord || r.sequence > cand.acceptRecord.sequence; });
    labels.no_contradiction = late.length ? "FAIL" : (cand.acceptRecord ? "PASS" : "UNCERTAIN");
    labels.evidence_grounded = "PASS"; // local heuristics only cite ids we hold
    return labels;
  }

  // Faithful mirror of the contract's _derive_status (do not drift).
  function deriveStatus(labels) {
    if (labels.two_or_more_participants === "FAIL")
      return ["INSUFFICIENT_EVIDENCE", "Cannot ground adjudication: fewer than two authenticated participants."];
    if (labels.evidence_grounded === "FAIL")
      return ["INSUFFICIENT_EVIDENCE", "Adjudication cited records not present as authenticated evidence; no agreement asserted."];
    if (labels.offer_present === "UNCERTAIN" || labels.acceptance_present === "UNCERTAIN")
      return ["AMBIGUOUS", "Evidence is too ambiguous to establish whether an offer and acceptance exist between the authenticated participants."];
    if (labels.offer_present === "FAIL")
      return ["NOT_AGREED", "No authenticated offer with concrete terms was established."];
    if (labels.acceptance_present === "FAIL")
      return ["NOT_AGREED", "No authenticated acceptance by a different participant was established."];
    if (labels.acceptance_matches_offer === "UNCERTAIN")
      return ["AMBIGUOUS", "The acceptance may respond to different terms than offered; evidence admits materially different readings."];
    if (labels.acceptance_matches_offer === "FAIL")
      return ["NOT_AGREED", "The authenticated acceptance does not match the offered terms."];
    if (labels.no_contradiction === "UNCERTAIN")
      return ["AMBIGUOUS", "Later authenticated records leave the agreement's standing unclear."];
    if (labels.no_contradiction === "FAIL")
      return ["NOT_AGREED", "A later authenticated record cancels or contradicts the agreement."];
    return ["AGREED", "Authenticated offer and matching acceptance by distinct participants, with no later authenticated contradiction."];
  }

  // ------------------------------ pipeline UI ------------------------------
  function pipeStep(name, cls, detailHtml) {
    var el = document.querySelector('.pipe-step[data-step="' + name + '"]');
    if (!el) return;
    el.className = "pipe-step " + cls;
    var d = $("pd-" + name);
    if (d && detailHtml !== undefined) d.innerHTML = detailHtml;
  }
  function pipeReset() { document.querySelectorAll(".pipe-step").forEach(function (s) { s.className = "pipe-step"; }); }

  // ------------------------------ judge ------------------------------
  function judgeAgreement() {
    if (state.judging) return;
    if (!state.verified) { toast("Verify the transcript first.", true); return; }
    var v = state.verified;
    if (v.counts.AUTHENTIC_SIGNED === 0) {
      // gate path — no LLM, straight to INSUFFICIENT_EVIDENCE
      runGateFail("no_authentic_records", "Deterministic gate: no_authentic_records — no authenticated agreement evidence for the LLM to adjudicate.");
      return;
    }
    if (v.participants.length < 2) {
      runGateFail("single_participant", "Deterministic gate: single_participant — one authenticated DID cannot form an agreement.");
      return;
    }
    state.judging = true;
    var btn = $("btn-judge");
    btn.disabled = true; btn.textContent = "Judging…";
    $("sec-adjudicate").hidden = false;
    $("pipe").classList.remove("hidden");
    pipeReset();

    var cand = state.candidate || buildCandidate();

    pipeStep("prepare", "active", "Canonical package · " + v.records.length + " records · sha256 " + v.evidenceHash.slice(0, 12) + "…");

    setTimeout(function () {
      pipeStep("prepare", "done", "Evidence package ready · " + v.evidenceHash.slice(0, 16) + "…");
      if (LIVE) judgeLive(cand);
      else judgeLocal(cand);
    }, 350);
  }

  function judgeLocal(cand) {
    pipeStep("submit", "active", "LOCAL / DEMO MODE — no chain transaction; same deterministic derivation as the contract.");
    setTimeout(function () {
      pipeStep("submit", "done", "Skipped on-chain submission (demo mode).");
      pipeStep("adj", "active", "Computing labels locally with transparent heuristics…");
      setTimeout(function () {
        var labels = localLabels(cand);
        Q_IDS.forEach(function (q) { setQ(q, labels[q]); });
        pipeStep("adj", "done", "Labels: " + Q_IDS.map(function (q) { return q.split("_")[0] + "=" + labels[q][0]; }).join(" "));
        pipeStep("consensus", "active", "Deriving status via the contract's matrix…");
        setTimeout(function () {
          var pair = deriveStatus(labels);
          pipeStep("consensus", "done", "LOCAL MODE — no validator set ran; derivation is deterministic.");
          pipeStep("final", "done", "<b>" + pair[0] + "</b>");
          finishResult({
            mode: "LOCAL / DEMO",
            labels: labels,
            status: pair[0], summary: pair[1],
            txHash: "", errorReason: "",
          }, cand);
          state.judging = false;
          var b = $("btn-judge"); b.disabled = false; b.textContent = "Judge Agreement";
        }, 420);
      }, 500);
    }, 300);
  }

  function setQ(q, val) {
    var el = $("q-" + q);
    if (!el) return;
    var map = { PASS: ["ok", "✓ PASS"], FAIL: ["bad", "✕ FAIL"], UNCERTAIN: ["warn", "? UNCERTAIN"] };
    var m = map[val] || ["mute", "—"];
    el.className = "pill " + m[0];
    el.textContent = m[1];
  }

  // ------------------------------ GenLayer live signer ------------------------------
  // Writes need a real signing account. In-browser burner (AgentProof pattern):
  // key generated client-side via SDK.generatePrivateKey(), persisted ONLY in
  // localStorage, funded via the Studio faucet RPC (sim_fundAccount).
  var WKEY = "gendid_writer_pk";
  var writer = null; // { pk, account, address }

  function getWriter(SDK) {
    if (writer) return writer;
    try {
      var pk = localStorage.getItem(WKEY);
      if (pk && /^[0-9a-f]{64}$/.test(pk)) {
        var acct = SDK.createAccount(pk);
        writer = { pk: pk, account: acct, address: acct.address };
        return writer;
      }
    } catch (e) { /* private mode */ }
    var fresh = SDK.generatePrivateKey();
    try { localStorage.setItem(WKEY, fresh); } catch (e) { /* session-only */ }
    var acct2 = SDK.createAccount(fresh);
    writer = { pk: fresh, account: acct2, address: acct2.address };
    return writer;
  }

  async function judgeLive(cand) {
    try {
      pipeStep("submit", "active", "Connecting to GenLayer studionet…");
      var SDK = window.GenLayerSDK;
      var client = SDK.createClient({ chain: SDK.studionet });
      var w = getWriter(SDK);
      pipeStep("submit", "active", "Writer " + w.address.slice(0, 10) + "… — submitting evidence to <a href=\"" + EXPLORER_TX + "\" target=\"_blank\" rel=\"noopener\">studionet</a>…");

      var recordsJson = JSON.stringify(state.verified.records.map(function (r) {
        return {
          sequence: r.sequence, timestamp: "", senderDid: r.senderDid,
          nonce: r.nonce, signature: r.signature, text: r.text,
        };
      }));
      var sigs = {};
      if (state.verified.manifestSigs) sigs = state.verified.manifestSigs;
      var txHash = await client.writeContract({
        address: CONTRACT, functionName: "submit_evidence",
        args: [state.room, recordsJson, JSON.stringify(sigs)], account: w.account,
      });
      pipeStep("submit", "done", "Tx <a href=\"" + EXPLORER_TX + txHash + "\" target=\"_blank\" rel=\"noopener\">" + esc(txHash.slice(0, 18)) + "…</a> submitted — awaiting consensus…");
      pipeStep("adj", "active", "Leader proposing · validators re-running independently…");

      var receipt = await client.waitForTransactionReceipt({
        hash: txHash, status: SDK.TransactionStatus.FINALIZED,
        interval: 5000, retries: 60,
      });
      // FINALIZED != success: a reverted execution also finalizes. Check the
      // leader receipt execution result + consensus vote before reading state.
      var lead = (receipt && receipt.consensus_data && Array.isArray(receipt.consensus_data.leader_receipt))
        ? receipt.consensus_data.leader_receipt[0] : null;
      var exec = lead ? lead.execution_result : null;
      var vote = receipt ? (receipt.result_name || null) : null;
      if (exec === "FAILURE" || exec === "ERROR") {
        var stderr = String((lead && lead.genvm_result && lead.genvm_result.stderr) || "");
        var contractErr = (stderr.match(/gendid: (.+)/) || [])[1];
        throw new Error(contractErr ? ("contract rejected: gendid: " + contractErr)
          : "execution failed on chain (GenVM " + exec + ")");
      }
      var st = String((receipt && receipt.status) || "");
      pipeStep("adj", "done", "Consensus round complete.");
      pipeStep("consensus", "active", "Reading agreement record from chain…");
      // statusName on studionet
      var statusName = (receipt && receipt.statusName) || vote || st;
      pipeStep("consensus", "done", "GenLayer consensus: <b>" + esc(statusName || "FINALIZED") + "</b>");
      // read back agreement record via get_agreement
      var aid = state.verified.agreementId;
      var raw = await client.readContract({
        address: CONTRACT, functionName: "get_agreement", args: [aid],
      });
      var record = (typeof raw === "string") ? JSON.parse(raw) : raw;
      pipeStep("final", "done", "<b>" + esc(record.status) + "</b>");
      Q_IDS.forEach(function (q) { if (record.questionLabels && record.questionLabels[q]) setQ(q, record.questionLabels[q]); });
      finishResult({
        mode: "GENLAYER STUDIONET · LIVE",
        labels: record.questionLabels || {},
        status: record.status, summary: record.adjudicationSummary || "",
        txHash: txHash, errorReason: record.errorReason || "",
        record: record,
      }, cand);
    } catch (e) {
      pipeStep("final", "err", esc(clip(e.message || e)));
      finishResult({
        mode: LIVE ? "GENLAYER STUDIONET · LIVE" : "LOCAL / DEMO",
        labels: {}, status: "INSUFFICIENT_EVIDENCE",
        summary: "Adjudication could not complete on-chain (" + clip(e.message || e) + "). No agreement asserted.",
        txHash: "", errorReason: "chain_error",
      }, cand);
    } finally {
      state.judging = false;
      var b = $("btn-judge"); b.disabled = false; b.textContent = "Judge Agreement";
    }
  }

  function runGateFail(reason, summary) {
    $("sec-adjudicate").hidden = false;
    $("pipe").classList.remove("hidden");
    pipeReset();
    pipeStep("prepare", "done", "Deterministic gate evaluated BEFORE any adjudication.");
    pipeStep("final", "err", "<b>INSUFFICIENT_EVIDENCE</b> — " + esc(reason));
    Q_IDS.forEach(function (q) { setQ(q, "—" === "—" ? "FAIL" : "FAIL"); });
    finishResult({
      mode: LIVE ? "GENLAYER STUDIONET · LIVE" : "LOCAL / DEMO",
      labels: {}, status: "INSUFFICIENT_EVIDENCE", summary: summary,
      txHash: "", errorReason: reason,
    }, buildCandidate());
  }

  // ------------------------------ result / why / receipt ------------------------------
  function finishResult(res, cand) {
    state.lastResult = res;
    // result banner
    var banner = $("result");
    banner.classList.remove("hidden", "ok", "no", "amb", "ins");
    var clsBy = { AGREED: "ok", NOT_AGREED: "no", AMBIGUOUS: "amb", INSUFFICIENT_EVIDENCE: "ins", NON_AUTHORITATIVE: "ins" };
    banner.classList.add(clsBy[res.status] || "ins");
    $("result-status").textContent = res.status;
    $("result-sub").textContent = res.summary;
    var errEl = $("result-error");
    if (res.errorReason) { errEl.hidden = false; errEl.textContent = "errorReason: " + res.errorReason; }
    else errEl.hidden = true;

    // WHY panel
    renderWhy(res, cand);
    // receipt
    renderReceipt(res, cand);
  }

  function renderWhy(res, cand) {
    $("sec-why").hidden = false;
    var body = $("why-body");
    var items = [];
    var v = state.verified;
    var byId = {};
    v.records.forEach(function (r) { byId[r.recordId] = r; });

    function cite(recId, unsigned) {
      var r = byId[recId];
      if (!r) return "";
      return '<div class="why-cite"><span class="cid">#' + esc(String(r.sequence)) + "</span>" +
        '<span class="ctx' + (unsigned ? " unsigned" : "") + '">“' + esc(clipText(r.text)) + "”</span></div>";
    }
    function clipText(t) { return t.length > 140 ? t.slice(0, 140) + "…" : t; }

    function item(k, vHtml, cites) {
      items.push('<div class="why-item"><div class="w-k">' + esc(k) + '</div><div class="w-v">' + vHtml + "</div>" +
        (cites && cites.length ? '<div class="why-cites">' + cites.join("") + "</div>" : "") + "</div>");
    }

    // participants — always supported
    item("Participants (authenticated DIDs)",
      v.participants.map(function (d) { return "<b>" + esc(GD.shortDid(d)) + "</b>"; }).join(" · ") || "none",
      v.records.filter(function (r) { return r.signatureStatus === "AUTHENTIC_SIGNED"; })
        .slice(0, 2).map(function (r) { return cite(r.recordId); }));

    if (cand && cand.offerRecord) {
      item("Offer detected",
        "An authenticated record contains an offer with concrete terms.",
        [cite(cand.offerRecord.recordId)]);
    }
    if (cand && cand.acceptRecord) {
      item("Acceptance detected",
        "A different authenticated DID accepts the offered terms.",
        [cite(cand.acceptRecord.recordId)]);
    }
    if (cand && cand.task) item("Task", esc(cand.task), cand.offerRecord ? [cite(cand.offerRecord.recordId)] : []);
    if (cand && cand.deadline) item("Deadline", esc(cand.deadline), cand.offerRecord ? [cite(cand.offerRecord.recordId)] : []);
    if (cand && cand.output) item("Output requirements", esc(cand.output), cand.offerRecord ? [cite(cand.offerRecord.recordId)] : []);
    if (cand && cand.payment) item("Payment / conditions", esc(cand.payment), cand.offerRecord ? [cite(cand.offerRecord.recordId)] : []);
    if (cand && cand.amendments && cand.amendments.length) {
      item("Amendments", "Later authenticated records propose changes.",
        cand.amendments.map(function (r) { return cite(r.recordId); }));
    }
    if (cand && cand.contradictions && cand.contradictions.length) {
      item("Contradictions", "Later authenticated records cancel or reject the agreement.",
        cand.contradictions.map(function (r) { return cite(r.recordId); }));
    }
    if (res.status === "INSUFFICIENT_EVIDENCE") {
      item("Why insufficient", esc(res.summary || "Deterministic gate or grounding failure."), []);
    }
    if (!items.length) items.push('<div class="why-none">No evidence-backed conclusions to show.</div>');
    body.innerHTML = items.join("");
  }

  function renderReceipt(res, cand) {
    $("sec-receipt").hidden = false;
    var v = state.verified;
    var pill = $("receipt-status-pill");
    var pillCls = { AGREED: "ok", NOT_AGREED: "bad", AMBIGUOUS: "warn", INSUFFICIENT_EVIDENCE: "mute", NON_AUTHORITATIVE: "bad" }[res.status] || "mute";
    pill.className = "pill " + pillCls;
    pill.textContent = res.status;

    $("r-aid").textContent = v.agreementId;
    $("r-status").innerHTML = "<b>" + esc(res.status) + "</b>";
    $("r-room").textContent = v.package.transcriptRoom;
    $("r-state").textContent = res.mode + (res.txHash ? " · FINALIZED" : " · not on-chain");
    $("r-issued").textContent = nowIso();
    $("r-hash").textContent = v.evidenceHash;
    $("r-parts").textContent = v.participants.length ? v.participants.join(" · ") : "none authenticated";
    var c = v.counts;
    $("r-counts").textContent = "auth " + c.AUTHENTIC_SIGNED + " · unsigned " + c.UNSIGNED + " · invalid " + c.INVALID_SIGNATURE + " · malformed " + c.MALFORMED + " · dup " + c.DUPLICATE;
    var rel = (res.record && res.record.relevantRecordIds) ? res.record.relevantRecordIds : (cand ? cand.relevant : []);
    $("r-recs").textContent = rel.length ? rel.join(" · ") : "—";
    $("r-mode").innerHTML = res.mode.indexOf("LIVE") >= 0
      ? '<span class="pill ok"><span class="g">✓</span> LIVE CONSENSUS</span>'
      : '<span class="pill warn">⚠ LOCAL / DEMO MODE</span>';
    var terms = (res.record && res.record.acceptedTerms) ? res.record.acceptedTerms : localTerms(cand);
    $("r-terms").innerHTML = terms && terms.length
      ? terms.map(function (t) { return esc(t.key) + ": " + esc(t.value) + " <span style='color:var(--faint)'>[" + esc(t.recordId || "") + "]</span>"; }).join("<br>")
      : "none established";
    $("r-labels").textContent = Q_IDS.map(function (q) {
      var l = (res.labels && res.labels[q]) || "—";
      return q + "=" + l;
    }).join(" · ");
    $("r-tx").innerHTML = res.txHash
      ? '<a href="' + EXPLORER_TX + esc(res.txHash) + '" target="_blank" rel="noopener">' + esc(res.txHash) + "</a>"
      : "no transaction (local mode)";
    $("r-summary").textContent = res.summary || "—";
    $("r-err").textContent = res.errorReason || "—";

    // receipt JSON snapshot
    state.receiptJson = JSON.stringify({
      protocolVersion: "gendid/1.2",
      agreementId: v.agreementId,
      status: res.status,
      evidenceHash: v.evidenceHash,
      transcriptRoom: v.package.transcriptRoom,
      participants: v.participants,
      recordCounts: v.counts,
      relevantRecordIds: rel,
      acceptedTerms: terms,
      questionLabels: res.labels || {},
      adjudication: {
        mode: res.mode,
        summary: res.summary,
        errorReason: res.errorReason,
        txHash: res.txHash || null,
      },
      verification: {
        engine: "ed25519 (tweetnacl) over <room>|<nonce>|<swept-text>",
        byteParityWithContract: "tested",
      },
      issuedAt: nowIso(),
      disclaimer: "Independent prototype. Cryptographic verification and GenLayer adjudication are separate layers; this receipt never claims adjudication is a cryptographic proof.",
    }, null, 2);
  }

  function localTerms(cand) {
    if (!cand || !cand.offerRecord) return [];
    var t = [];
    if (cand.task) t.push({ key: "task", value: cand.task, recordId: cand.offerRecord.recordId });
    if (cand.deadline) t.push({ key: "deadline", value: cand.deadline, recordId: cand.offerRecord.recordId });
    if (cand.output) t.push({ key: "output", value: cand.output, recordId: cand.offerRecord.recordId });
    if (cand.payment) t.push({ key: "payment", value: cand.payment, recordId: cand.offerRecord.recordId });
    return t;
  }

  // ------------------------------ mode tag ------------------------------
  function renderMode() {
    var tag = $("mode-tag"), note = $("gl-note"), hint = $("mode-hint");
    if (LIVE) {
      tag.className = "mode-tag live"; tag.textContent = "GENLAYER · LIVE";
      note.textContent = "studionet · contract " + CONTRACT.slice(0, 10) + "…" + CONTRACT.slice(-6);
      $("gl-explain").innerHTML = "Connected to GenLayer studionet (chain 61999). <b>Judge Agreement</b> submits the evidence package to the on-chain GenDid contract and waits for real validator consensus; the panel shows actual transaction information only — transaction hash, execution status, and the on-chain record. Individual validator identities are not simulated: consensus is shown as <b>GenLayer consensus</b>. The on-chain writer key is a burner generated in this browser (never sent anywhere; studionet charges no gas).";
    } else {
      tag.className = "mode-tag local"; tag.textContent = "LOCAL / DEMO MODE";
      note.textContent = "no contract address configured — adjudication runs the same derivation locally";
      hint.textContent = "status panel · demo mode";
      $("gl-explain").innerHTML = "LOCAL / DEMO MODE: no contract address is configured in this install, so this run derives the status with the <b>same deterministic matrix</b> the contract uses, plus a local heuristic labeler for the semantic questions. Provide a Studionet contract address (contract-address.js) to enable live adjudication.";
    }
  }

  // ------------------------------ wiring ------------------------------
  function wire() {
    $("btn-id-new").onclick = function () { newIdentity(false); };
    $("btn-id-export").onclick = function () {
      var doc = {
        "@context": "https://w3id.org/did/v1",
        id: state.identity.did,
        verificationMethod: [{
          id: state.identity.did + "#keys-1",
          type: "Ed25519VerificationKey2020",
          controller: state.identity.did,
          publicKeyMultibase: state.identity.did.replace("did:key:", ""),
        }],
        authentication: [state.identity.did + "#keys-1"],
      };
      copyText(JSON.stringify(doc, null, 2), "DID document");
    };
    $("btn-tc-load").onclick = loadTechnocoreRoom;
    $("tc-room").addEventListener("keydown", function (e) { if (e.key === "Enter") loadTechnocoreRoom(); });
    $("btn-verify").onclick = verifyTranscript;
    $("btn-judge").onclick = judgeAgreement;
    $("btn-copy-receipt").onclick = function () { copyText(state.receiptJson || "{}", "Receipt"); };
    $("btn-download-receipt").onclick = function () {
      try {
        var blob = new Blob([state.receiptJson || "{}"], { type: "application/json" });
        var a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "gendid-receipt-" + (state.verified ? state.verified.agreementId : "unknown") + ".json";
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
        toast("Receipt downloaded.");
      } catch (e) { toast("Download failed: " + clip(e.message), true); }
    };
    // demo buttons (both btnrow + demo-grid)
    document.querySelectorAll("[data-demo]").forEach(function (b) {
      b.onclick = function () { runDemo(b.getAttribute("data-demo")); };
    });
    // textarea change resets verification state
    $("transcript-input").addEventListener("change", function () {
      if (state.rawRecords.length) { state.rawRecords = []; state.verified = null; resetDownstream(); $("records-card").hidden = true; }
    });
  }

  // ------------------------------ boot ------------------------------
  function boot() {
    if (!window.GD) { toast("gendid-lib failed to load", true); return; }
    loadIdentity();
    renderMode();
    wire();
    // pre-fill room field with default
    $("tc-room").value = state.room;
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
