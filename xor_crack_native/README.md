# xor_crack_native

Native (Rust) repeating-key XOR cracker backing `tools/xor_crack.py`. See
that module's docstring, and `POLYGLOT_CORE_ADDITIONS.md` at the repo
root, for the full rationale and benchmark numbers.

`tools/xor_crack.py` auto-detects this extension and falls back to a
pure-Python implementation with the same interface if it isn't built --
building it is a performance optimization, not a hard requirement.

## Build

```bash
cd xor_crack_native
pip install maturin
maturin develop --release   # builds and installs into the active venv
```

or, to build a wheel without installing directly:

```bash
maturin build --release
pip install target/wheels/xor_crack_native-*.whl
```

## Test

```bash
cargo test
```

`cargo test` builds the `rlib` target and runs the Rust-side unit tests
in `src/lib.rs` directly -- no Python involved. To exercise the compiled
Python extension itself, build it with `maturin develop` first, then run
`pytest tests/test_xor_crack.py` from the repo root (it cross-checks the
native and pure-Python backends against each other whenever the native
extension is importable).
