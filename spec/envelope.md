# The UCP verifier-attestation envelope

A common wire shape for carrying independently verifiable third-party
attestations in the UCP Signals slot: one identity verdict, one risk verdict,
and any later claim type, riding the same `signals` map, each verified offline by
the merchant against the issuer's own published keys with no issuer online at
verify time.

Grew out of, and is the concrete field-name proposal for,
[UCP #534](https://github.com/Universal-Commerce-Protocol/ucp/discussions/534)
(the envelope) and
[#535](https://github.com/Universal-Commerce-Protocol/ucp/discussions/535)
(the neutral external-verifier role). The running end-to-end demonstration is in
[`../cross-verify/`](../cross-verify/); the per-issuer conformance vectors are in
[`../facet-identity/`](../facet-identity/) and [`../fidacy-risk/`](../fidacy-risk/).

This spec belongs to no issuer. It is published here as a joint reference and is
intended to graduate to a neutral namespace.

## 1. Shape

Attestations ride a `signals` map, keyed by a reverse-domain **signal name**.
Each entry is a signed credential plus the minimum needed to route and resolve
it:

```jsonc
"signals": {
  "llc.facet.kya": {
    "format": "kya+jwt",
    "jws": "<compact JWS>",
    "kid": "facet-1b644cbb",
    "provider_jwks": "https://issuer.facet.llc/.well-known/jwks.json"
  },
  "com.fidacy.trust_verdict": {
    "format": "application/vc+jws",
    "jws": "<compact JWS>",
    "kid": "1zoM57brjllufNTzCwI5-j5jFkiAslyzVDbPAcR_f-M",
    "provider_jwks": "https://api.fidacy.com/.well-known/jwks.json"
  }
}
```

The reverse-domain key encodes both the issuer namespace and the claim type in
one token (`llc.facet.kya` is Facet's identity signal, `com.fidacy.trust_verdict`
is Fidacy's risk signal). Adding a claim type is adding a key. A verifier that
does not recognize a key ignores that entry; unknown signals are not an error.

## 2. Entry fields

| field | required | meaning |
|---|---|---|
| `jws` | yes | The attestation, as an RFC 7515 compact JWS (`header.payload.signature`). The only trusted element. |
| `format` | yes | The JWS `typ` (for example `kya+jwt`, `application/vc+jws`). A routing hint; MUST match the `typ` in the protected header, and the header value wins. |
| `kid` | no | Convenience copy of the protected-header `kid`. A cold reader may read it without base64url-decoding the header. Non-authoritative; the header `kid` is what selects the key. |
| `provider_jwks` | no | Convenience hint at the issuer's JWKS URL. NON-NORMATIVE. MUST NOT override the verifier's pinned source (section 4). |

Everything outside `jws` is an untrusted hint until the signature verifies. A
lying `format`, `kid`, or `provider_jwks` cannot make a bad credential verify: at
worst it selects the wrong key or host and fails closed against the pin.

Why a JWS and not a hand-rolled `signature` field: RFC 7515 defines the signing
input exactly (base64url header, dot, base64url payload), the signature lives
outside the payload, and every mainstream JOSE library agrees on it byte for
byte. A custom "signature over the JCS bytes minus the signature field" gets
re-implemented slightly differently N times, which is the interop failure this
envelope exists to prevent. JCS (RFC 8785) still earns its place *inside* a
payload where equal claims must serialize to equal bytes; it is not the outer
signing scheme.

## 3. What moved inside the payload

The subject, timestamps, and claim body are JWT claims inside the signed
payload, not envelope-level fields:

| concern | where it lives |
|---|---|
| issuer | `iss` claim |
| subject (agent or session) | `sub` / `aud` claims (see section 5) |
| validity window | `iat`, `nbf`, `exp` claims |
| the claim itself | claim-type-specific payload fields |
| signature | the JWS signature segment |

They are signed, so a consumer reasons about them only after verification.

## 4. Key resolution and the merchant allow-list

Key resolution is out of band. The authoritative JWKS for each claim type is
**pinned in that claim type's public spec**, not configured per verifier, and
seeded into the merchant's allow-list. This is what keeps the trust decision
auditable instead of buried in one verifier's private config.

A merchant advertises what it accepts in `/.well-known/ucp`:

```jsonc
"verifier_attestations": {
  "accepted": [
    {
      "signal": "llc.facet.kya",
      "issuer": "https://issuer.facet.llc",
      "jwks_uri": "https://issuer.facet.llc/.well-known/jwks.json"
    },
    {
      "signal": "com.fidacy.trust_verdict",
      "issuer": "did:web:fidacy.com",
      "jwks_uri": "https://api.fidacy.com/.well-known/jwks.json"
    }
  ]
}
```

The JWKS fetch then only ever targets a pinned, merchant-chosen host, and `kid`
selects a key *within* that pinned set rather than selecting a host. The fetch
MUST be SSRF-guarded: https only, reject internal / loopback / link-local /
cloud-metadata hosts, disable redirects. `provider_jwks` in the envelope is a
convenience for a cold reader and MUST NOT be fetched in place of the pinned
`jwks_uri`; if the two disagree, the pinned source wins.

## 5. Verification

For each recognized `signals` entry:

1. Decode the JWS protected header. Confirm `typ` matches the entry `format`.
2. Look up the signal in the merchant allow-list; if absent, the merchant does
   not accept this issuer, stop.
3. Resolve the header `kid` against the pinned JWKS for that signal. Unknown
   `kid` rejects (`unknown_kid`).
4. Verify the signature, dispatching on the header `alg` (ES256, EdDSA, ...).
   Failure rejects (`invalid_signature`).
5. Enforce the validity window (`exp`, `nbf`). Expired rejects (`expired`).
6. Run the consumer-side **scope check** for the claim type:
   - transaction-scoped claims (for example risk): the payload `aud` or session
     binding MUST match the checkout session in hand.
   - agent-scoped claims (for example identity): the payload `aud` MUST match the
     merchant's own id; the claim is durable and reusable across requests.

Steps 1 to 5 are authenticity ("is this a genuine, unmodified credential from
the named issuer"). Step 6 is scope ("was it issued for me / for this session").
The verifier owns authenticity; the consumer owns scope. Keeping them separate is
why the same envelope carries both an agent-scoped identity credential and a
session-scoped risk verdict without special-casing either.

## 6. Replay and TTL

Short `exp` is necessary but not sufficient for payment-adjacent claims: a
5-minute expiry is a 5-minute replay window. For transaction-scoped claim types,
the session binding in step 6 plus single-use enforcement per session covers
replay without a global nonce store. Payment-capable credentials SHOULD also
carry a single-use `nonce`, claimed atomically and namespaced by issuer or `kid`,
with a documented fail-closed rule: if the nonce store is unreachable, reject.
Agent-scoped identity credentials are durable by design, so expiry matters more
than replay for them.

## 7. Payload size

Sign small claims inline. For bulky evidence, sign a `sha256` of the content and
reference the content out of band; only the hash travels and stays verifiable
after the envelope expires. Decision-provenance
([#56](https://github.com/Universal-Commerce-Protocol/ucp/discussions/56)) is the
claim type that most needs this, and it slots in as another `signals` entry with
no change to the envelope.

## 8. Conformance

A claim-type profile is real when an independent party can recompute its verdicts
from committed bytes without running the issuer's service. Each profile ships a
two-sided vector set: a positive vector every conformant verifier MUST accept, and
a matched negative vector for each reject reason it MUST reject. The suite asserts
it observed both a pass and every reject reason, so a green run demonstrates the
verifier discriminates rather than merely accepts.

The current profiles verify from more than one independent codebase; the
[`../cross-verify/`](../cross-verify/) run exercises both in a single reproducible
script (`npm i && node cross-verify.mjs`).

## 9. Claim-type registry

| signal | claim type | scope | alg | `typ` | profile |
|---|---|---|---|---|---|
| `llc.facet.kya` | identity | agent | ES256 (P-256) | `kya+jwt` | [claim-types/identity.md](claim-types/identity.md) |
| `com.fidacy.trust_verdict` | risk | session | EdDSA (Ed25519) | `application/vc+jws` | [claim-types/risk.md](claim-types/risk.md) |
| `com.fidacy.decision_provenance` | decision-provenance | record | EdDSA (Ed25519) | `fidacy-artifact-receipt+jws` | [claim-types/decision-provenance.md](claim-types/decision-provenance.md) |

Three claim types are registered with runnable vector sets; two issuers verify
under the envelope end to end today, which is the bar for graduating the envelope
from vendor-namespaced to a core, neutrally-owned spec.
