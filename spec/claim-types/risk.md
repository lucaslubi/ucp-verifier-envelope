# Claim type: risk (`com.fidacy.trust_verdict`)

The transaction-risk half of the envelope: a signed approve / review / deny on a
specific transaction, issued by a party outside it. Session-scoped: one verdict
is about one checkout, and presenting it for another is the consumer-side
rejection its vectors demonstrate.

This is the profile for the signal already registered in
[`envelope.md` §9](../envelope.md#9-claim-type-registry); the runnable half
(vectors, generators, a live-signed production verdict) lives in
[`../fidacy-risk/`](../fidacy-risk/).

## Signal

```jsonc
"com.fidacy.trust_verdict": {
  "format": "application/vc+jws",
  "jws": "<compact JWS — the verdict, the only trusted element>",
  "kid": "<protected-header kid, convenience copy>",
  "provider_jwks": "https://api.fidacy.com/.well-known/jwks.json"  // non-normative hint
}
```

Key resolution is out of band per the envelope's trust model: the pin lives in
this profile (the canonical JWKS URL above; the issuer is a `did:web`, so the
DID document is a second resolution path off the same pin).

## Protected header

```json
{ "alg": "EdDSA", "kid": "<key id>", "typ": "application/vc+jws" }
```

Ed25519 only; `alg: none` and non-EdDSA algorithms MUST be rejected.

## Claims

The payload is the Risk Payload, serialized as RFC 8785 (JCS) canonical JSON and
signed as raw bytes — a verifier verifies the exact payload bytes and never
re-canonicalizes.

| claim | meaning |
|---|---|
| `issuer` | `did:web:fidacy.com#<kid>` |
| `subject` | the agent / mandate the verdict is about |
| `decision` | `approve` \| `review` \| `deny` |
| `score` | 0–100 |
| `signals` | the evidence map behind the decision |
| `model_version` | the risk model that decided |
| `policy_version` | the policy active at signing time (`none` if unset) |
| `assessed_at` | ISO 8601 |

`model_version` and `policy_version` pinned inside the credential are what let a
consumer prove, long after the fact, *which* rules produced a verdict — the
bridge to the decision-provenance claim type.

Canonical claim schema: [fidacy-open/spec/risk-payload.md](https://github.com/fidacy/fidacy-open/blob/main/spec/risk-payload.md)
(Apache-2.0), the profile's source of truth.

## Scope: authenticity vs consumer check

The verifier answers "is this a genuine, untampered Fidacy verdict?" — signature
against the pinned key set, `typ` and `alg` pinned. The consumer answers "is it
about the checkout in front of me?" by comparing the claim's `subject` to the
session in hand. The `wrong-session` vector demonstrates exactly this: its
signature verifies by design, and the rejection is the consumer's. Same split as
`wrong-audience` (identity) and `tampered-record` (decision-provenance).

## Conformance vectors

In [`../fidacy-risk/`](../fidacy-risk/), meeting [§8](../envelope.md#8-conformance):
one positive vector plus a matched negative per reject reason, self-validated by
the published [`@fidacy/verify`](https://www.npmjs.com/package/@fidacy/verify)
(the receipts also verify with any JOSE library; `@fidacy/verify` adds the
policy layer — typ/issuer pinning and stable reason codes).

| vector | expect |
|---|---|
| `valid` | verifies (plus a live-signed production verdict against the live JWKS) |
| `expired` | rejected `expired` |
| `bad-signature` | rejected `invalid_signature` |
| `rotated-key` | rejected `unknown_kid` |
| `wrong-session` | signature valid; consumer rejects on session mismatch |

## Notes

**Issuer requirement (normative).** A verifier MUST NOT issue a risk verdict for
a transaction to which it is a party — where a party is anyone who meters,
settles, or takes a fee on it. The signer of an authorization mandate is a party
by definition; the risk judgment only carries third-party weight when its issuer
has nothing at stake in the outcome. Fidacy takes no fee, settles nothing, and
holds no funds, so it is a non-party to the verdicts it issues; the clause
applies to Fidacy exactly as to anyone else, and was agreed on the public record
in [UCP #535](https://github.com/Universal-Commerce-Protocol/ucp/discussions/535).
Because the same non-party requirement recurs in the decision-provenance profile,
it is a candidate for promotion into [`envelope.md` §8](../envelope.md#8-conformance)
as a per-claim-type conformance rule rather than a per-profile note.

**Advisory action.** The verdict never owns checkout state: the engine returns a
`recommended_action` (`proceed` / `step_up` / `decline`) that the merchant maps
onto its own flow. The merchant owns the decision; the verdict is evidence.
