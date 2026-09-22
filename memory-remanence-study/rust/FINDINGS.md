# Rust findings: dead-store elimination on a naive zeroing loop

## Setup

Two functions, tested on Compiler Explorer (godbolt.org), `rustc 1.98.0`,
flag `-C opt-level=3`, target x86-64:

- `naive_zero.rs` — allocates a 32-byte stack array, initializes it,
  passes a reference to `std::hint::black_box` (forces the compiler to
  treat the value as genuinely used/observed, so it can't eliminate the
  whole function as dead), then attempts to zero it with a plain `for`
  loop.
- `volatile_zero.rs` — identical, except the zeroing loop writes through
  `core::ptr::write_volatile` instead of a plain indexed assignment.

Both functions are marked `#[unsafe(no_mangle)] pub extern "C"` so the
compiler treats them as externally callable symbols and doesn't inline or
discard them entirely as unused. (`#[no_mangle]` requires the `unsafe(...)`
wrapper as of recent Rust editions, since it can violate safety guarantees
if two functions collide on the same exported symbol name — a small but
real edition-specific detail worth noting for anyone reproducing this on
an older toolchain.)

## Result

**`naive_zero.rs`:** the compiled function initializes the 32-byte array
(the compiler folded the `0..32` initialization loop into two 16-byte SIMD
loads via `movaps`, since the values are known at compile time), computes
the buffer's address for `black_box`, and returns. **No zeroing
instructions appear anywhere in the output.** The entire
`for i in 0..32 { key[i] = 0; }` loop compiled to nothing.

**`volatile_zero.rs`:** the compiled function performs the same
initialization, then emits **32 individual `mov byte ptr [...], 0`
instructions** — one explicit store per byte, fully unrolled from the
source loop — writing zero to each of the 32 stack offsets, before
returning.

## Why this happens

Same underlying mechanism as the C case, expressed through Rust's
optimizer instead of GCC's: `-O`-level optimization performs dead store
elimination, removing any write the compiler can prove has no effect on
subsequent observable program behavior. After the call to `black_box`,
nothing in the function reads `key` again — the compiler correctly
determines that writing zeros to memory about to be deallocated has no
effect on the program's output, and removes every one of those writes.

The array being "sensitive key material about to leave scope" carries no
weight in this analysis, because nothing in Rust's type system marks a
`[u8; 32]` holding a cryptographic key as different from a `[u8; 32]`
holding anything else. The optimizer's job is to preserve observable
behavior, not to infer intent about what the data represents.

`write_volatile` changes the outcome because volatile semantics are part
of the language's defined behavior, not a heuristic the optimizer can
override: a volatile write is defined to be observable regardless of
whether any later code reads the value, so the compiler is not permitted
to treat it as dead. This is visible directly in the assembly — the loop
was even unrolled (a genuine optimization, applied for performance), but
every one of the 32 individual volatile stores it unrolled into survived
intact. Volatile-ness applies per write, not per loop: the compiler could
restructure *how* the writes happen, but could not eliminate *whether*
they happen.

## Implication

This reproduces, in Rust specifically, the same finding as the C
experiment: a plain zeroing loop is not a reliable way to guarantee
sensitive memory is actually wiped, because "the compiler proved nothing
reads this again" and "it's safe to leave unzeroed" are different
properties, and only the first is something the optimizer reasons about.
This is precisely the gap the `zeroize` crate is built to close — its
`Zeroize` trait implementations use `write_volatile` (or an equivalent
compiler-fence-based approach) internally, which is exactly the mechanism
demonstrated by hand here. In this project, `derive_key()` returns
`Zeroizing<[u8; KEY_LEN]>` rather than a plain `[u8; KEY_LEN]` specifically
so that this volatile-write guarantee applies automatically when the key
goes out of scope, rather than depending on a manually written loop that
this experiment shows the optimizer is free to delete.

## Caveat

This reproduces a well-known result, applied here to Rust specifically
(see CWE-226, and the `zeroize` crate's own documentation, which states
the same rationale). It is not a novel finding — it is a from-scratch,
hands-on verification: compiling the exact code myself and reading the
actual generated assembly, rather than accepting the claim on faith.
Results are specific to this compiler version, this optimization level,
and this target architecture (x86-64, via Compiler Explorer); a different
target, an older/newer `rustc`, or a different code shape (e.g. a
larger or variable-length buffer instead of a fixed 32-byte array) could
produce different specific assembly while illustrating the same
underlying principle.

## Connection to the `zeroize` crate

The crate's own documentation confirms this experiment reflects its actual
mechanism: zeroize "uses core::ptr::write_volatile and
core::sync::atomic memory fences" — the same primitive used by hand in
`volatile_zero.rs` above, with no FFI or inline assembly involved.

Two things worth adding precision to, beyond what this experiment covers:

1. The crate guarantees two properties, not one: (a) the write can't be
   optimized away, and (b) subsequent reads are guaranteed to see the
   zeroed value. This experiment only demonstrates (a) — that the store
   instruction survives optimization. Guarantee (b) is subtler and was
   historically debated within the Rust community (whether mixing
   volatile and non-volatile memory accesses was well-defined), and was
   resolved through work by the Unsafe Code Guidelines Working Group.
   This project's manual experiment doesn't independently verify (b); it
   relies on the crate's documented claim and the resolved language-level
   guarantee behind it.
2. Zeroing memory does not protect against microarchitectural
   side-channel attacks (Spectre/Meltdown-class techniques that could
   leak values through covert channels even after correct zeroing) — the
   crate is explicit about this. Memory remanence and side-channel
   leakage are different threats; this study, and `zeroize` itself,
   addresses only the former.