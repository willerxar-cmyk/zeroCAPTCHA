# HTTP API

The engine binds to a private address by default. Only a trusted application
server should call these routes. All POST requests use `application/json`.

## GET /health

Returns `status`, `service`, `configured`, `minted` and `verified` for
liveness and process-local counters. Confirm replay store connectivity
separately.

## POST /v1/challenge

Send the expected `purpose` (`login`, `register`, `recovery`, or `booking`)
and a server-derived `client_binding` consisting of 64 lowercase hex
characters. The application may set `difficulty`, `algorithm`, `ttl_secs`,
or a `precision` policy. Example request with a placeholder binding:

```json
{
  "purpose": "login",
  "difficulty": "medium",
  "ttl_secs": 600,
  "client_binding": "<64 lowercase hexadecimal characters>"
}
```

HTTP 200 returns `success: true` and a signed `challenge`. The challenge
includes `id`, `alg`, `salt`, `cost`, `prefix`, `expires_at`,
`purpose`, `kind`, `client_binding`, optional `precision`, and `sig`.
Treat it as an opaque value apart from the solver fields. Return all
original fields with the solution. HTTP 429 includes `retry_after_secs`
for issuance quotas. Invalid input is rejected, and HTTP 503 means the
service could not mint the challenge.

## POST /v1/verify

Send a body with `solution`, the expected `purpose` and the independently
derived `client_binding`. A solution includes the complete signed
`challenge`, `counter`, `key` (64 lowercase hex characters),
optional `evidence` and, if timing was requested, a `precision_receipt`.
The application can set a per-request `evidence_mode`.

HTTP 200 returns `valid: true` for a successfully consumed proof or
`valid: false` with a machine-readable `reason` for rejection. A normal
verification request that exceeds its quota returns HTTP 429. Your
application should require both HTTP 200 and `valid: true` to proceed.

### Browser evidence

- `off`: ignore evidence.
- `lenient`: reject supplied evidence that has neither interaction nor
  focus. Missing evidence remains accepted.
- `strict`: require at least one interaction or focus signal.

Evidence contains interaction count, document focus and solve duration.
Treat this client-asserted evidence solely as an abuse signal.
Proof of work increases the cost of abuse and can be solved by automation.

## Optional precision protocol

The trusted application may add `precision` to creation:

```json
{"min_hold_ms":3000,"max_hold_ms":6000,"release_window_ms":2000}
```

These example values come from application policy. Hold bounds must be in
1,000–30,000 ms, the release window in 100–20,000 ms, and the maximum hold plus
window must be strictly shorter than the effective challenge TTL. Malformed
or unknown policy fields are rejected. The engine chooses a cryptographically
random target in the inclusive range and signs `precision: {hold_ms,
release_window_ms}` into a `proof_of_work` challenge. Omitting the policy uses
the ordinary proof-of-work flow.

Send the following tagged bodies to `/v1/verify` from the trusted application
server. Recompute the binding for each request.

```json
{"operation":"precision_start","challenge":{},"purpose":"login","client_binding":"64-lowercase-hex-characters"}
```

The complete signed challenge replaces the illustrative empty object. A valid
start returns `valid: true` and `precision_ticket`, containing `challenge_id`,
`challenge_sig`, `purpose`, `client_binding`, `started_at_ms`, and `sig`.
Start is atomically permitted once per challenge.

```json
{"operation":"precision_release","challenge":{},"ticket":{},"purpose":"login","client_binding":"64-lowercase-hex-characters"}
```

Release submits that ticket and the complete challenge. The engine records
server receipt time before the replay-store round trip and accepts elapsed
time from `hold_ms` through `hold_ms + release_window_ms`, inclusive. Every
authenticated release attempt is consumed atomically, including early or late
release; retrying requires a fresh challenge. Success returns
`precision_receipt: {ticket, released_at_ms, sig}`. Ticket and receipt signatures
use distinct domains and bind the original challenge signature, purpose and
client pseudonym.

Attach the returned `precision_receipt` to the final ordinary solution. Final
verification authenticates timing before KDF work and still re-derives the
submitted PoW key and atomically consumes the challenge. Computation may finish
after the release window; the signed receipt fixes the earlier release instant.
Server expiry remains enforced at final consumption. Client event durations
and evidence cannot replace the receipt. Missing receipts, substitutions,
tampering, replay, and storage errors are rejected.

Timing includes network and application latency. Production replicas must have
synchronized clocks, and application policy must allow a suitable release
window for transport jitter. Browsers should announce server acceptance before
starting the countdown and cancel on loss of focus or the active pointer.
