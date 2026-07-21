# Decision-provenance conformance vectors (Fidacy)

The vector pack for the `com.fidacy.decision_provenance` claim type
([spec/claim-types/decision-provenance.md](../spec/claim-types/decision-provenance.md)),
built to the envelope's conformance bar ([spec/envelope.md §8](../spec/envelope.md#8-conformance)):
one positive vector plus a matched negative for each reject reason.

```bash
npm i
node gen-vectors.mjs   # 5 pass, self-validated with plain jose
```

| vector | expect |
|---|---|
| `valid` | verifies; `sha256(vectors/decision-record.json)` matches the claim |
| `tampered-record` | signature valid BY DESIGN; the consumer's recomputed hash mismatches — the tampering signal |
| `bad-signature` | rejected `ERR_JWS_SIGNATURE_VERIFICATION_FAILED` |
| `rotated-key` | rejected `ERR_JWKS_NO_MATCHING_KEY` |
| `pre-checkpoint` | signature valid; the Bitcoin anchor leg is pending |

Receipts are plain compact JWS (`typ fidacy-artifact-receipt+jws`, EdDSA), so
they verify with any JOSE library — no vendor verifier. A porting note baked
into the generator: flip a MIDDLE character of the signature segment for the
negative vector; the LAST base64url char carries spare padding bits many
decoders ignore, so a flip there can still verify.

A live production receipt (real engine signature, record hash matching the
anchored value, audit seq 158 under Bitcoin checkpoint 29) is committed in the
canonical spec:
[fidacy-open/spec](https://github.com/fidacy/fidacy-open/blob/main/spec/decision-provenance-claim.md).
