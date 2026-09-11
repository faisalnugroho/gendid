// GenDid demo scenario transcripts (gendid/1) — three selectable demos.
// Records use the canonical shape the contract and gendid-lib expect:
//   { room, sequence, timestamp, senderDid, nonce, signature, text }
// Signatures are Ed25519 over "<room>|<nonce>|<swept-text>".
// Seeds below are PUBLIC DEMO seeds (never reuse for real identity).
// In the browser, GD.demoRecords() re-signs with the shipped demo identities
// so every signature actually verifies with tweetnacl — no fake crypto.
window.GENDID_DEMOS = {
  clear: {
    id: "demo-clear-agreement",
    title: "A · Clear agreement",
    expected: "AGREED",
    blurb: "Concrete offer, matching acceptance by a distinct DID, no contradiction.",
    seedA: "11".repeat(32),
    seedB: "22".repeat(32),
    // gendid/1.2 deterministic public demo room. The previous room
    // (gendid-demo-01) was sealed on-chain by a run that used randomized
    // nonce jitter; a sealed room can never accept a different manifest,
    // so the canonical deterministic demo lives in this fresh room.
    room: "gendid-demo-01b",
    script: [
      { who: "a", text: "I need data normalization for the sales CSV. Output must be JSON. Maximum latency 30 seconds. Price is 5 credits." },
      { who: "b", text: "Accepted. I will normalize the sales CSV to JSON within 30 seconds for 5 credits." },
      { who: "a", text: "Confirmed. Send the JSON output to this room when ready." }
    ]
  },
  dispute: {
    id: "demo-dispute",
    title: "B · Contradiction / dispute",
    expected: "NOT_AGREED",
    blurb: "Offer and acceptance exist, but a later authenticated record cancels the deal.",
    seedA: "33".repeat(32),
    seedB: "44".repeat(32),
    room: "gendid-demo-02",
    script: [
      { who: "a", text: "I need data normalization for the sales CSV. Output must be JSON. Maximum latency 30 seconds. Price is 5 credits." },
      { who: "b", text: "Accepted. I will normalize the sales CSV to JSON within 30 seconds for 5 credits." },
      { who: "b", text: "Cancel that. The price is wrong for this job — I withdraw my acceptance." }
    ]
  },
  ambiguous: {
    id: "demo-ambiguous",
    title: "C · Ambiguous agreement",
    expected: "AMBIGUOUS / INSUFFICIENT_EVIDENCE / NOT_AGREED (live consensus labeled the vague offer FAIL — offer_present requires concrete terms; see docs/LIVE_DEPLOYMENT.md)",
    blurb: "Vague offer, an acceptance that may respond to different terms, unsigned noise.",
    seedA: "55".repeat(32),
    seedB: "66".repeat(32),
    seedN: "77".repeat(32),
    room: "gendid-demo-03",
    script: [
      { who: "a", text: "Maybe we could work together on that CSV thing sometime." },
      { who: "b", text: "Sure, sounds good I guess." },
      { who: "n", text: "~listener: nice room, good vibes", unsigned: true }
    ]
  }
};
