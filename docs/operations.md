# Configuration and operations

All operational settings are environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `ZEROCAPTCHA_SECRET` | Required | Fresh 32-byte random signing key encoded as 64 hexadecimal characters |
| `ZEROCAPTCHA_HOST` | `127.0.0.1` | Private HTTP bind address |
| `ZEROCAPTCHA_PORT` | `3028` | Private HTTP port |
| `ZEROCAPTCHA_REDIS_URL` | Unset | Shared single-use store. Requires the `redis` feature |
| `ZEROCAPTCHA_EVIDENCE_MODE` | `strict` | Evidence policy, `off`, `lenient` or `strict` |
| `ZEROCAPTCHA_ADAPTIVE_DIFFICULTY` | `true` | Escalate work under per-client pressure |
| `ZEROCAPTCHA_DIFFICULTY_DEFAULT` | `medium` | Default difficulty, `low`, `medium` or `high` |
| `ZEROCAPTCHA_CHALLENGE_TTL_DEFAULT_SECS` | `600` | Challenge TTL, clamped to 30–3,600 seconds |
| `ZEROCAPTCHA_ISSUE_PER_WINDOW` | `20` | Issue quota per client window |
| `ZEROCAPTCHA_VERIFY_PER_WINDOW` | `60` | Verify quota per client window |
| `ZEROCAPTCHA_WINDOW_SECS` | `60` | Rate-limit window |
| `ZEROCAPTCHA_RATE_LIMIT_MAX_KEYS` | `100000` | Maximum number of in-process client buckets |
| `ZEROCAPTCHA_MEMO_MAX_ENTRIES` | `10000` | Replay memo capacity |
| `ZEROCAPTCHA_MEMO_TTL_SECS` | `120` | Replay memo lifetime |
| `ZEROCAPTCHA_HTTP_MAX_BODY_BYTES` | `16384` | Request body cap, clamped to 1 KiB–1 MiB |
| `ZEROCAPTCHA_HTTP_API_ENABLED` | `true` | Enable the private challenge and verify routes |

Build with `--features redis` for a shared, atomic single-use store. Each
replica serving the same application must use the same signing key and
shared store. Isolate the store and engine on a trusted network, use a
protected transport across hosts and restrict access to both. Enable
persistence as needed to keep consumed IDs across restarts. Keep Redis on a
no-eviction policy so live replay records cannot be evicted. A configured
store that is unavailable causes verification to reject the request.

The in-memory store is meant for local testing or an isolated single process.
Its replay records and signing key are scoped to the process, so restarts
invalidate all its outstanding proofs.
Rotate a shared signing key across all replicas together. In-flight proofs
signed with the previous key become invalid, and clients need a fresh challenge.
Keep keys in your deployment secret store and use different keys for the
engine and your application bindings.

Proof of work increases the cost of automation. Use rate limits on the public
edge for both issuance and verification, since engine limits are process-local
and keyed by client. Bound the total concurrent verification load at the edge
and test difficulty on representative client devices. Place the engine's
private API behind your application server so browsers cannot choose
difficulty, purpose, binding, TTL, or evidence policy.

The available algorithms are `S6-PBKDF2-SHA256` and `S6-SHA256`.
`S6-ARGON2ID` and `S6-SCRYPT` need the `argon2` and `scrypt` build
features respectively. The bundled widget uses `S6-PBKDF2-SHA256`.

## Verify a checkout

```sh
cargo fmt --all --check
cargo test --locked
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
node --experimental-strip-types --test __tests__/*.test.mjs
```

When updating dependencies, regenerate or update `Cargo.lock` only for this
checkout and run `cargo audit` with RustSec's `cargo-audit` installed.
Check the browser demo with the actual engine and review the public file
list before cutting a release. Report sensitive findings to the repository
maintainers privately. Keep credentials, infrastructure identifiers and
reproduction material out of public issue bodies.
