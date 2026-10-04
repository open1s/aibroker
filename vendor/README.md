# vendored dependencies

## pingora-rustls 0.8.0

A patched copy of the crates.io release, referenced from the root
`Cargo.toml` via `[patch.crates-io]`.

**Why**: upstream declares `rustls = "0.23"` and `tokio-rustls = "0.26"` with
default features. Those defaults select the `aws-lc-rs` crypto provider, which
pulls in `aws-lc-sys`: a C and assembly build requiring cmake and, for x86_64,
NASM. It is the only component that fails our release pipeline — cross-building
`x86_64-apple-darwin` on an arm64 runner — and it is dead weight, because the
crate never uses it: it hashes with `ring` directly and installs no crypto
provider at all.

**What changed**: two dependency declarations now disable default features and
select ring instead.

```toml
[dependencies.rustls]
version = "0.23.12"
default-features = false
features = ["ring", "logging", "std", "tls12"]

[dependencies.tokio-rustls]
version = "0.26.0"
default-features = false
features = ["ring", "logging", "tls12"]
```

`Cargo.toml.orig` is the unmodified manifest, kept so the delta is auditable.

**Removing this patch**: drop the `[patch.crates-io]` entry in the root
`Cargo.toml`, delete this directory, and confirm
`cargo tree -i aws-lc-sys` reports nothing. Upstream will need to stop enabling
the `aws-lc-rs` provider by default for that to work.

**Risk**: the patch pins us to a copy of a dependency. It contains no source
changes, only the two feature selections above, and the crate's own tests are
unaffected. Verify TLS after any change here: build, then drive a real HTTPS
upstream through the proxy (see `tests/manual/run_feature_tests.py --profile
real`) — `ring` is the provider that must be selected.
