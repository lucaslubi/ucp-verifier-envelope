#!/usr/bin/env node
/**
 * Conformance vectors for the decision-provenance claim type
 * (`com.fidacy.decision_provenance`), built to the envelope spec's own bar
 * (spec/envelope.md §8): a positive vector every conformant verifier MUST
 * accept, and a matched negative vector for each reject reason it MUST reject,
 * so a green run demonstrates the verifier discriminates rather than accepts.
 *
 *   npm i && node gen-vectors.mjs
 *
 * A provenance receipt is a plain compact JWS (typ fidacy-artifact-receipt+jws,
 * EdDSA), so it verifies with ANY JOSE library; no vendor verifier needed. The
 * claims attest that a decision record with a given sha256 existed at ts, at
 * audit position seq of a hash-chained log whose checkpoints anchor to Bitcoin.
 *
 * Outcomes:
 *   valid            -> verifies; consumer hash-check passes
 *   tampered-record  -> signature VERIFIES; the consumer's sha256 recompute
 *                       mismatches (authenticity vs integrity-of-the-record:
 *                       same authenticity/scope split as wrong-session and
 *                       wrong-audience in the sibling claim types)
 *   bad-signature    -> ERR_JWS_SIGNATURE_VERIFICATION_FAILED
 *   rotated-key      -> ERR_JWKS_NO_MATCHING_KEY
 *   pre-checkpoint   -> signature VERIFIES; anchor leg is pending (consumer
 *                       decides which trust legs it requires)
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { generateKeyPair, exportJWK, calculateJwkThumbprint, CompactSign, compactVerify, createLocalJWKSet, jwtVerify, errors } from "jose";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "vectors");
mkdirSync(OUT, { recursive: true });

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// The demo decision record: bytes the receipt attests to. Committed alongside
// the vectors so the consumer-side hash check is reproducible byte-for-byte.
const RECORD = Buffer.from(
  JSON.stringify({
    record: "decision",
    decisionId: "demo-000042",
    status: "DENY",
    violatedRule: "payee_not_in_allowlist:supplier:evil",
    subject: "agent:demo-northwind",
    ts: "2026-07-18T12:00:00.000Z",
  }) + "\n",
);
writeFileSync(join(OUT, "decision-record.json"), RECORD);

// Test issuer keys: active is published; rotated is not.
const active = await generateKeyPair("Ed25519", { extractable: true });
const rotated = await generateKeyPair("Ed25519", { extractable: true });
const activeJwk = await exportJWK(active.publicKey);
const rotatedJwk = await exportJWK(rotated.publicKey);
const activeKid = await calculateJwkThumbprint(activeJwk, "sha256");
const rotatedKid = await calculateJwkThumbprint(rotatedJwk, "sha256");
activeJwk.kid = activeKid;
rotatedJwk.kid = rotatedKid;
const testJwks = { keys: [{ ...activeJwk, use: "sig", alg: "EdDSA" }] };
writeFileSync(join(OUT, "test-jwks.json"), JSON.stringify(testJwks, null, 2));
const JWKS = createLocalJWKSet(testJwks);

// JCS-sorted claims, matching the production receipt shape (fidacy.artifact.v1).
const claims = (over = {}) => {
  const c = {
    artifactId: "0f24ec66-demo-4bd2-9c1a-6f6cf2f8a001",
    audit: { hash: "9a".repeat(32).slice(0, 64), seq: 42 },
    digest: "53".repeat(32).slice(0, 64),
    kind: "custom",
    org: "org-demo",
    sha256: sha256(RECORD),
    subject: "agent:demo-northwind",
    ts: "2026-07-18T12:00:05.000Z",
    v: "fidacy.artifact.v1",
    ...over,
  };
  return Object.fromEntries(Object.entries(c).sort(([a], [b]) => (a < b ? -1 : 1)));
};
const sign = (c, key, kid) =>
  new CompactSign(new TextEncoder().encode(JSON.stringify(c)))
    .setProtectedHeader({ alg: "EdDSA", kid, typ: "fidacy-artifact-receipt+jws" })
    .sign(key);

let pass = 0, fail = 0;
const ok = (cond, label, extra = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? "  (" + extra + ")" : ""}`); };

// Authenticity: genuine, untampered receipt from the published key set.
async function verifyReceipt(jws) {
  const { payload, protectedHeader } = await compactVerify(jws, JWKS);
  if (protectedHeader.typ !== "fidacy-artifact-receipt+jws") throw new Error("typ mismatch");
  if (protectedHeader.alg !== "EdDSA") throw new Error("alg not allowed");
  return JSON.parse(new TextDecoder().decode(payload));
}

const vectors = {};

// 1) valid — signature verifies AND the consumer's recomputed hash matches.
const vValid = await sign(claims(), active.privateKey, activeKid);
vectors.valid = { jws: vValid, expect: "valid; consumer sha256(decision-record.json) matches the claim" };
{
  const c = await verifyReceipt(vValid);
  ok(c.sha256 === sha256(RECORD), "valid -> verifies and record hash matches");
}

// 2) tampered-record — the RECEIPT is authentic; the RECORD bytes changed.
const tampered = Buffer.from(RECORD); tampered[20] ^= 1;
vectors["tampered-record"] = {
  jws: vValid,
  tampered_record_hint: "flip any byte of decision-record.json",
  expect: "signature valid; consumer hash mismatch — the tampering signal",
  note: "NOT A HOLE, by design: the receipt is authentic. The verifier proves the receipt is real; the consumer proves the record in hand is the one attested by recomputing sha256. Authenticity and record-integrity are different questions, the same split wrong-session and wrong-audience draw in the sibling claim types.",
};
{
  const c = await verifyReceipt(vValid);
  ok(c.sha256 !== sha256(tampered), "tampered-record -> consumer hash mismatch detected");
}

// 3) bad-signature — flip a MIDDLE character of the signature segment. (The
// LAST base64url char carries spare padding bits that decoders ignore, so a
// flip there can decode to the identical 64 bytes and still verify — a real
// footgun worth documenting for anyone porting these vectors.)
const parts = vValid.split(".");
const mid = Math.floor(parts[2].length / 2);
parts[2] = parts[2].slice(0, mid) + (parts[2][mid] === "A" ? "B" : "A") + parts[2].slice(mid + 1);
const vBad = parts.join(".");
vectors["bad-signature"] = { jws: vBad, expect: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" };
try { await verifyReceipt(vBad); ok(false, "bad-signature -> rejected", "verified but should not"); }
catch (e) { ok(e instanceof errors.JWSSignatureVerificationFailed, "bad-signature -> rejected ERR_JWS_SIGNATURE_VERIFICATION_FAILED", e.code ?? e.message); }

// 4) rotated-key
const vRot = await sign(claims(), rotated.privateKey, rotatedKid);
vectors["rotated-key"] = { jws: vRot, expect: "ERR_JWKS_NO_MATCHING_KEY" };
try { await verifyReceipt(vRot); ok(false, "rotated-key -> rejected", "verified but should not"); }
catch (e) { ok(e instanceof errors.JWKSNoMatchingKey, "rotated-key -> rejected ERR_JWKS_NO_MATCHING_KEY", e.code ?? e.message); }

// 5) pre-checkpoint — authentic receipt whose anchor leg has not confirmed yet.
const vPre = await sign(claims({ audit: { hash: "9b".repeat(32).slice(0, 64), seq: 43 } }), active.privateKey, activeKid);
vectors["pre-checkpoint"] = {
  jws: vPre,
  anchor_status: "queued",
  expect: "signature valid; anchor leg pending — consumers requiring the Bitcoin leg MUST wait for the covering checkpoint to confirm",
};
{
  const c = await verifyReceipt(vPre);
  ok(c.audit.seq === 43, "pre-checkpoint -> signature leg verifies; anchor leg is a separate, later check");
}

writeFileSync(join(OUT, "vectors.json"), JSON.stringify({
  claim_type: "decision-provenance",
  signal: "com.fidacy.decision_provenance",
  envelope: "compact JWS, EdDSA (Ed25519), kid in protected header, typ fidacy-artifact-receipt+jws; verifies with any JOSE library",
  record: "decision-record.json",
  test_jwks: "test-jwks.json",
  vectors,
}, null, 2));

// jwtVerify imported to mirror the identity pack's tooling surface; unused here
// because receipts are compactVerify territory (no exp semantics on the sig leg).
void jwtVerify;

console.log(`\nconformance vectors: ${pass} pass, ${fail} fail`);
process.exit(fail === 0 ? 0 : 1);
