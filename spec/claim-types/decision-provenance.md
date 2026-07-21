# Claim type: decision-provenance (`com.fidacy.decision_provenance`)

The after-the-fact half of the envelope, the use case
[UCP #534](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
opened with (via [#56](https://github.com/Universal-Commerce-Protocol/ucp/discussions/56)):
proof that a specific decision existed, with exactly that content, at that
moment, and was not rewritten afterwards. Not "who is the agent" (identity) and
not "should this happen" (risk) — the question an auditor, insurer or dispute
asks months later, when nobody trusts anybody's server logs.

This is also the claim type [`envelope.md` §7](../envelope.md#7-payload-size)
names as the one that most needs the hash-referenced payload model, and it uses
exactly that: only the record's `sha256` travels; the record itself never does.

## Signal

```jsonc
"com.fidacy.decision_provenance": {
  "format": "fidacy-artifact-receipt+jws",
  "jws": "<compact JWS — the receipt, the only trusted element>",
  "kid": "<protected-header kid, convenience copy>",
  "provider_jwks": "https://api.fidacy.com/.well-known/jwks.json"  // non-normative hint
}
```

## Protected header

```json
{ "alg": "EdDSA", "kid": "<key id>", "typ": "fidacy-artifact-receipt+jws" }
```

A receipt is a plain compact JWS: it verifies with any JOSE library, no vendor
verifier required. Ed25519 only; `alg: none` MUST be rejected.

## Claims

| claim | meaning |
|---|---|
| `v` | format version, `fidacy.artifact.v1` |
| `artifactId` | issuer-side id of the anchored record |
| `sha256` | SHA-256 of the decision-record bytes; the record itself is never uploaded |
| `subject` | the agent / mandate the decision was about |
| `kind` | record kind (`custom`, `conversation`, `invoice`, …) |
| `ts` | ISO 8601 moment of attestation |
| `audit.seq` / `audit.hash` | position and entry hash in the issuer's hash-chained audit |
| `digest` | the audit-leaf digest the chain entry commits to |
| `org` | issuing account scope |

Two independent trust legs: the **signature leg** (the JWS against the pinned
key set) proves the issuer attested to these bytes at `ts`; the **anchor leg**
(`audit.seq` resolving to a Merkle checkpoint inside a Bitcoin transaction)
bounds existence in time without trusting the issuer at all — it survives the
issuer disappearing. Consumers that store the receipt plus its inclusion proof
after the covering checkpoint confirms need the issuer for nothing, ever.

Canonical spec and schema:
[fidacy-open/spec/decision-provenance-claim.md](https://github.com/fidacy/fidacy-open/blob/main/spec/decision-provenance-claim.md)
(Apache-2.0), including a live production example: a real receipt signed by the
live engine, whose committed record hashes byte-for-byte to the anchored value
(audit seq 158, covered by Bitcoin checkpoint 29).

## Scope: authenticity vs consumer checks

The verifier answers "is this a genuine, untampered receipt?". The consumer then
makes two checks of its own:

1. **Record integrity**: recompute `sha256` over the decision-record bytes in
   hand and compare to the claim. A mismatch is the tampering signal — the
   `tampered-record` vector demonstrates it, and its signature verifies by
   design (the receipt is authentic; the record changed). Same split as
   `wrong-session` and `wrong-audience` in the sibling claim types.
2. **Anchor maturity**: between issuance and the first covering checkpoint only
   the signature leg holds; consumers requiring the Bitcoin leg MUST wait for
   `confirmed`. The `pre-checkpoint` vector demonstrates the state.

## Conformance vectors

In [`../fidacy-provenance/`](../fidacy-provenance/), meeting
[§8](../envelope.md#8-conformance): `npm i && node gen-vectors.mjs`, every
vector self-validated with plain `jose`.

| vector | expect |
|---|---|
| `valid` | verifies; consumer hash of `decision-record.json` matches |
| `tampered-record` | signature valid; consumer hash mismatch — the tampering signal |
| `bad-signature` | rejected `ERR_JWS_SIGNATURE_VERIFICATION_FAILED` |
| `rotated-key` | rejected `ERR_JWKS_NO_MATCHING_KEY` |
| `pre-checkpoint` | signature valid; anchor leg pending |

## Notes

**Issuer requirements (normative).** This claim type has three that the others
do not share:

1. **Non-party issuer.** The issuer MUST NOT operate, meter, settle, or take a
   fee on the transaction whose decision it attests — a rail attesting to its
   own decision log is exactly what the after-the-fact consumer distrusts. Same
   structural-neutrality rule as the risk profile; recurring across two
   profiles, it is a candidate for promotion into
   [`envelope.md` §8](../envelope.md#8-conformance).
2. **Long-horizon evidence.** The attestation MUST remain verifiable for years.
   Short TTLs are correct for identity credentials; they answer nothing in a
   dispute two quarters later.
3. **Issuer-independent anchoring.** Existence-in-time MUST be provable without
   trusting the issuer: external, publicly verifiable timestamping. This profile
   anchors Merkle checkpoints of the audit chain into Bitcoin transactions,
   checkable on any explorer.
