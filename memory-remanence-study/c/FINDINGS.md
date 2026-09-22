# C findings: dead-store elimination on a naive zeroing loop

## Setup

Two functions, compiled separately with `gcc -O2`, target `pe-i386` (32-bit
x86 on Windows/MinGW):

- `naive_zero.c` — allocates a 32-byte stack buffer, "derives" a key into
  it, passes it to an opaque external function `use_key()`, then attempts
  to zero it with a plain `for` loop before returning.
- `volatile_zero.c` — identical, except the zeroing loop writes through a
  `volatile unsigned char *` pointer instead of a plain pointer.

`use_key()` is declared but never defined in either file, so the compiler
cannot see inside it or prove anything about what it does with the buffer —
this forces the compiler to treat the buffer as genuinely used at least
once, isolating the interesting behavior to what happens *after* that call.

## Result

**`naive_zero.c`:** after `-O2`, the compiled function contains the
initialization loop and the call to `use_key()`, then immediately returns.
The manual zeroing loop is entirely absent from the assembly — no store
instructions writing zero appear anywhere in the function body.

**`volatile_zero.c`:** the compiled function contains the same
initialization loop and call, followed by a second loop of 32 individual
byte-store instructions (`movb $0x0, (...)`) writing zero — present in
full, unmodified by `-O2`.

## Why this happens

This is not a compiler bug. `-O2` performs dead store elimination: a write
to memory is eliminated if the compiler can prove no subsequent code path
reads the value written. In `naive_zero.c`, after `use_key()` returns, the
function immediately returns too — nothing in the visible program ever
reads `key` again. The compiler correctly concludes the zeroing writes have
no observable effect on the program's behavior, and removes them.

The buffer being about to be deallocated (the stack frame reclaimed) makes
no difference to this analysis — the compiler doesn't reason about "this
memory is about to go away, so its final contents matter for security."
It only reasons about whether writes affect anything the *program* can
observe going forward. A stack-allocated 32-byte key and a stack-allocated
32-byte loop counter are, to the optimizer, indistinguishable: both are
just memory with no further reads.

`volatile` changes this because it's part of the C standard's memory
model, not a compiler heuristic: writes through a `volatile`-qualified
pointer are defined to have an observable side effect, regardless of
whether any code reads the value afterward. The compiler is not permitted
to treat a volatile write as dead, because "dead" is defined in terms of
observable behavior, and volatile writes are defined to always be part of
observable behavior — originally so this qualifier could correctly express
things like memory-mapped hardware registers, where a write matters even
though no C code reads it back.

## Implication

Zeroing sensitive memory before it's freed is not something you can
reliably get from "remembering to write a loop" — the correctness of that
loop, under optimization, depends on a plain compiler behavior (dead store
elimination) that has nothing to do with security and everything to do
with normal program semantics. The compiler is doing exactly what it's
supposed to do; the gap is that "no further reads" and "safe to leave
unzeroed" are different properties, and only the first one is something
the type system or optimizer can reason about. Expressing "this data is
security-sensitive and must be wiped regardless of whether anything reads
it again" requires a mechanism that sits outside normal dead-code
reasoning — which is exactly what a volatile write, and by extension the
`zeroize` crate's design in Rust, provides.

## Caveat

This reproduces a well-known result (see CWE-226, and the rationale given
in the `zeroize` crate's own documentation and in longstanding C security
guidance recommending `explicit_bzero`/`SecureZeroMemory` over plain
`memset`). It is not a novel finding — it's a from-scratch, hands-on
verification of a known failure mode and its known mitigation, done by
compiling the code myself and inspecting the actual assembly rather than
taking the claim on faith. Results are specific to this compiler (`gcc`),
this optimization level (`-O2`), and this target (`pe-i386`); other
compilers, flags, or architectures could show different specific assembly
while illustrating the same underlying principle.