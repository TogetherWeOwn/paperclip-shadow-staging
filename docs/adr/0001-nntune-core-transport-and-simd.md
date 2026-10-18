# ADR 0001: nntune-core transport trait, feature flags, and yEnc SIMD strategy

Status: accepted (with `crates/nntune-core` initial PR).

## Context

All backend Workers are Rust (`workers-rs` → wasm32), sharing
`crates/nntune-core` with native services and Container batch jobs.
Sibling cards build `workers/{api,stream,ingest,mb}` on top of this crate
in parallel and need a stable contract now.

## Decisions

1. **The crate never touches the network or the clock.** NNTP I/O goes
   through the `transport::Transport` trait (async `read` / `write_all` /
   `shutdown`); every implementation enforces the configured per-operation
   timeout and reports expiry as `io::ErrorKind::TimedOut`. Protocol code
   is therefore identical on tokio and Workers.
2. **Feature flags select the transport, not `cfg(target_arch)` alone:**
   `native-tls` (tokio + rustls, default) and `worker-transport`
   (`worker::Socket` + `worker::Delay`, wasm32 only). Workers enable
   `worker-transport` and disable default features.
3. **yEnc SIMD is an explicit fast path, not autovectorisation hope:**
   clean 16-byte lanes go through SSE2 (x86_64) / simd128 (wasm32 with
   `RUSTFLAGS="-C target-feature=+simd128"`); lanes containing `=` take
   the scalar loop. Wire behaviour is byte-identical to the v1 Go worker
   (proven by committed Go-exported vectors).
4. **PAR2 repair is native-only** (`repair::repair_with_binary` shells out
   to `par2cmdline-turbo` in a Container scratch dir). Verify and
   precheck are wasm-safe and run in Workers; the wasm repair stub
   returns `UnsupportedOnWasm`.
5. **NZB canonical XML is out of scope** for the core: v1's canonical
   re-serialisation served storage dedup in the ingest pipeline. The core
   keeps the content identity primitive (`segment_digest`, byte-identical
   to v1); canonicalisation, if still needed, belongs to the ingest
   worker.
6. **Directives (incl. bare `<!DOCTYPE>`) are rejected**, matching v1's
   hard XXE posture. Real-world NZBs often carry one — the ingest worker
   owns the strip-or-reject policy decision (flagged, not fixed here).

## Consequences

- Worker builds must set `RUSTFLAGS="-C target-feature=+simd128"` to get
  the vectorised yEnc path; without it the scalar fallback is used
  (correct, slower). CI checks both wasm builds plus the simd128 build.
- `workers/bench` (sibling card) still owes the wasm-on-Workers ms/MB
  measurement to fully close the bench gate.
