# Contributing

csync serves a project from a macOS or Linux host to a Linux guest over FUSE. Two rules come before everything else:
a guest must never reach outside the project root, and the guest mount should feel like a local disk.

## Build and test

```sh
git clone https://github.com/Seggys116/csync
cd csync
cargo build
cargo test
```

Rust 1.89 or newer is required (edition 2024).

Before opening a pull request:

```sh
cargo fmt --check
RUSTFLAGS=-Dwarnings cargo clippy --all-targets
cargo test
```

CI runs these on Linux x86_64, Linux arm64 and macOS, checks the `x86_64-apple-darwin` target, builds the static
musl release binaries, and runs the FUSE integration tests against them as both a normal user and root.

## FUSE integration tests

`tests/fuse_it.rs` drives a real host and guest against the binary named by `CSYNC_BIN`. It needs Linux with
`/dev/fuse` and `fusermount3`. On macOS, run it in Docker:

```sh
docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN \
  -v "$PWD":/src -w /src -e CARGO_TARGET_DIR=/target rust:1 sh -c '
    set -e
    apt-get update -qq && apt-get install -y --no-install-recommends fuse3 musl-tools inotify-tools
    t="$(uname -m)-unknown-linux-musl"
    rustup target add "$t"
    cargo build --locked --release --target "$t"
    CSYNC_BIN="/target/$t/release/csync" cargo test --locked --test fuse_it -- --test-threads=1'
```

`CARGO_TARGET_DIR` keeps the Linux build out of your local `target/`. The container runs as root, which matches the
CI `root` leg. On hosts with AppArmor, add `--security-opt apparmor:unconfined` if the mount is denied.

## Fuzzing

The decoders and path, delta and merge logic have fuzz targets in `fuzz/`. They need a nightly toolchain and
`cargo-fuzz`:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run frame_decode -- -max_total_time=60
```

CI fuzzes every target weekly.

## Conventions

* Performance and security come first. Any change on a hot path (scan, fetch, commit, inotify injection) should say
  what it costs.
* Peer data is decoded with postcard, every length is bounded before allocation, and no peer-data path uses
  `unwrap`, indexing or anything else that can panic. Release builds abort on panic, so a panic is a denial of
  service.
* `unsafe` is denied crate-wide and allowed only in `src/sys/`.
* Comments are rare (roughly 1 to 5% of lines), single-line and lowercase, and explain why rather than what.
* Tests must be able to fail for a real bug. Do not add tests that only restate the implementation. Every bug fix
  comes with a regression test.

## Releases

1. Bump the version in `Cargo.toml` and `Cargo.lock`, and add the release's changes to `CHANGELOG.md`.
2. Push to `main` and wait for CI on that exact commit to pass.
3. Tag that commit `vX.Y.Z`, matching the package version, and push the tag.

The release workflow refuses a tag that does not match the package version or whose commit has no successful CI
run on `main`. It builds macOS and static Linux binaries for arm64 and x86_64, and publishes them with a `.sha256` file
per archive, which `install.sh` verifies, and a combined `SHA256SUMS`.
