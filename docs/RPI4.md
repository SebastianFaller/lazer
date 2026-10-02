# Raspberry Pi 4 (aarch64) performance branch

Branch `rpi4-optimizations` (lazer) and the matching branch of the `src/labrados` submodule speed up lazer and Labrador on aarch64 CPUs without crypto extensions (Raspberry Pi 4, Cortex-A72). **All changes are transcript-compatible**: proofs are bit-identical to the original code, and on x86-64 the original code paths are unchanged.

Branch `rpi4-chacha` adds an optional ChaCha20 PRG on top. It is **not** transcript-compatible, so proofs only verify between builds that use the same PRG.

## Build
```sh
git clone --recursive <this repo> lazer && cd lazer   # submodule URL is relative: ../labrador.git
make all
cd python && python3 lazer_cffi_build.py ..          # or: pip install -e .
```
Threads for Labrador: `LAB_THREADS=<n>` at run time (default 4). `LAB_THREADS=1` runs the original serial loops.

## What changed
| change | where | Cortex-A72 effect (micro-benchmarks) |
|---|---|---|
| JL-projection collapse: 16-entry table lookup indexed by public JL-matrix nibbles instead of SIMDe-emulated `_mm512_permutex2var_epi64` | labrados `jlproj.c` | 8.5x; this was ~50% of all Labrador cycles |
| NEON versions of other SIMDe-emulated kernels: `jlproj_add64`, sprod, pointwise, reduce, scale, caddp, polz center/reduce, zz_poly_fma, … | labrados `poly.c`, `polz.c`, `jlproj.c`, `simd_neon.h` | 1.2–7x per kernel |
| NEON NTT/INTT/nttunpack with the same per-coefficient operation sequence | labrados `ntt.c` | 2.9x / 3.2x / 2.8x |
| Constant-time NEON bitsliced AES-CTR (8 blocks per pass), with bitsliced keys cached in the context | `src/aes-neonbs.h`, `src/aes256ctr.c`, labrados `aesctr.[ch]` | 2.2–2.4x |
| Multi-threaded Labrador (pthread pool); work split only by public sizes; transcript and randomness order unchanged | labrados `parallel.h` and others | prove/verify 1.4x on a Pi 4 (up to ~2x); 3.2x on 4 fast cores |
| HEXL `MSB()` via `clz` instead of `std::log2l` (128-bit *software* float on aarch64) | `src/hexl.patch` | ≈10% of LNP time removed |
| Exact branch-free 128÷64 remainder instead of libgcc `__modti3` (also removes variable-time division on secret data); int64 Schwartz–Zippel accumulation; fewer copies and allocations | `src/modred.h`, `src/vr_accum.h`, `src/lin-proofs.c`, `src/poly.c`, … | LNP verify ~1.45x, prove −20–30% |
| `polyvec_to_ar` in one C call | `python/labrados.py` | 22x |
| Restore `polymat_t.lift()`, which the Pi port commit 8c008ab removed | `python/lazer.py` | – |

## Switches to force the original code paths (used by the equivalence tests)
- `-DJL_FORCE_AVX512`, `-DLABRADOS_FORCE_AVX512`, `-DNTT_FORCE_AVX512`: original labrados SIMDe code
- `-DLAZER_AES_NO_NEON`: original scalar bitsliced AES
- `LAB_THREADS=1`: no threads

## Verification
- **Each change:** equivalence tests compare old against new code on random and edge-case inputs, for LOGQ = 32, 36 and 38.
- **End to end:** a full anonymous-credential protocol (BLNS with device binding, using LNP and Labrador) was run with deterministic OS randomness. Every protocol message and proof was hashed. The hashes are identical to the unmodified build for 1 and 4 threads.
- ThreadSanitizer is clean for the thread pool.
