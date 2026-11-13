# Optional native helpers

This directory contains the optional native helpers used by GARBAGE. They are
never required: Python remains the reference implementation and every caller
has a fallback.

| Language | File | Used for |
| --- | --- | --- |
| C | `c/garbage_native.c` | Bounded ELF/PE hardening scan (PIE, NX, RELRO, bind-now, canary, Fortify, ASLR, CFG) and byte entropy |
| C | `c/garbage_fuzzy.c` | TLSH and ssdeep digests, TLSH distance and ssdeep score (byte-compatible with py-tlsh 5 and ssdeep 2.14) |
| C++ | `cpp/garbage_graph.cpp` | Relationship graph components, isolates, degree, density and reciprocal edges |
| Rust | `rust/src/lib.rs` | Bounded Damerau-Levenshtein distance and domain skeleton for lookalike analysis |
| Rust | `rust/src/signatures.rs` | Embedded signature scan over 29 formats (list-only, no carving) |

## Build

```sh
make -C native
```

Outputs:

```
native/build/libgarbage_c.so
native/build/libgarbage_cpp.so
native/build/libgarbage_rust.so
```

On macOS the extension is `.dylib`. Builds are optional and are not downloaded
at runtime.

## Loading rules

- `GARBAGE_NATIVE_DIR` may point to an explicit build directory.
- Without it, GARBAGE looks in `native/build/` next to the package.
- A missing library, wrong ABI version or missing symbol is ignored and the
  Python fallback is used. The UI/API reports the engine that actually ran.
- Native code never opens a file, starts a process, executes input or uses the
  network. The caller supplies bytes and owns all output buffers.

## Safety contract

- Every read is bounds-checked against the supplied length.
- ELF/PE parsing stops at explicit header, section, program-header and dynamic
  entry limits.
- Graph indices are validated before use.
- String similarity rejects inputs longer than 253 bytes and returns early when
  the requested distance bound is exceeded.
- The libraries expose only fixed C ABI functions; no allocator, callback or
  owned pointer crosses the boundary.

## Verification

```sh
make -C native check
GARBAGE_NATIVE_DIR="$PWD/native/build" python3 -m unittest tests.test_native -v
```

The tests compare native results with the Python fallback and cover malformed
or truncated inputs. A compiler is required only for the native tests; the
regular test suite skips them when the libraries are absent.
