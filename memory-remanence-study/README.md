# Memory Remanence Verification Study

The file encryptor uses `Zeroizing<T>` to prevent key material from
lingering in freed memory. This folder contains the hands-on verification
study behind that design choice — demonstrating concretely why a naive
manual zeroing loop is insufficient, and what mechanism `zeroize` uses to
solve it.

Full writeup: [Verifying Why `zeroize` Matters: Dead-Store Elimination and
Memory Remanence in Rust](https://quietbytes.hashnode.dev/verifying-why-zeroize-matters-dead-store-elimination-and-memory-remanence-in-rust) (Part 2 of the

## What's here

- `c/naive_zero.c` — a naive manual zeroing loop, compiled with `-O2` and
  inspected via `objdump` to show the optimizer eliminating it as a dead
  store.
- `rust/` — the same pattern reproduced in Rust, plus `zeroize`'s
  volatile-write equivalent, to show the write surviving optimization.
- `screenshots/` — assembly output supporting the above.

## Scope and honesty about what this is

This reproduces a well-established result (see `CWE-226`, the `zeroize`
crate's own documentation, and RustCrypto's design rationale) — it is not
a novel finding. What's here is a from-scratch, hands-on verification
rather than taking the claim on faith: compiling the code myself,
inspecting the actual assembly, and connecting it precisely to this
project's own `derive_key() -> Zeroizing<[u8; KEY_LEN]>` design.