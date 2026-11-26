## What and why

## Checks

- [ ] `cargo fmt --check` and `RUSTFLAGS=-Dwarnings cargo clippy --all-targets` are clean
- [ ] `cargo test` passes
- [ ] FUSE integration tests pass (Docker recipe in CONTRIBUTING.md) if `src/guest/` or the protocol changed
- [ ] Peer-supplied data is length-bounded and never reaches `unwrap`, indexing or a panic
- [ ] Docs updated if behaviour, flags or the protocol changed
