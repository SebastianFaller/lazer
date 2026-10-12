# lazer on aarch64 (Raspberry Pi 4)

This branch (`rpi4`) is upstream lazer plus two kinds of changes, so that lazer
and its Labrador backend (the `src/labrados` submodule, branch `rpi4` of the
labrador fork) build and run fast on 64-bit ARM. The main target is the
Raspberry Pi 4: a Cortex-A72 without the ARMv8 crypto extensions.

1. **Port** (R. Polig): on non-x86 CPUs, lazer uses its portable code paths:
   - a constant-time bitsliced AES instead of AES-NI;
   - Falcon without AVX2;
   - HEXL's native kernels;
   - Labrador's AVX-512 code compiled through
     [SIMDe](https://github.com/simd-everywhere/simde).
2. **Optimizations**: native aarch64 code for the hot spots that the port
   leaves slow, and a multi-threaded Labrador.

Two properties hold for every change:

- **Proofs are bit-identical.** Each change computes exactly the same bytes as
  the code it replaces, for all inputs. Proofs made on a Pi verify on x86-64
  and the other way round, and a run with fixed randomness produces the same
  transcript on both.
- **x86-64 is unchanged.** An x86-64 build compiles exactly the upstream code,
  including its AES-NI, AVX2 and AVX-512 paths. Every aarch64 change sits
  behind a switch that is never set on x86-64, with the upstream code kept
  unchanged in the `#else` branch.

## Switches

| switch | where it is set | when | what it enables |
|---|---|---|---|
| `X86_NATIVE` (make) | `Makefile` | x86-64, unless `make PORTABLE=1` | upstream build rules; otherwise the port's (SIMDe, HEXL patch, aarch64 `-pthread`) |
| `TARGET` | `config.h` | `TARGET_AMD64` on x86-64, else `TARGET_GENERIC` | upstream's two code paths |
| `LAZER_AARCH64` | `src/lazer-in2.h` (lazer.h) | aarch64, unless `-DLAZER_NO_AARCH64` | lazer optimizations below |
| `LAZER_AES_NEONBS` | `src/lazer-in2.h` | `LAZER_AARCH64` and NEON | NEON AES-256-CTR |
| `LABRADOS_NEON` | `src/labrados/simd_neon.h` | aarch64, unless `-DLABRADOS_FORCE_AVX512` | Labrador NEON code, JL table lookup, NEON AES |
| `LAB_PARALLEL` | `src/labrados/parallel.h` | aarch64, unless `-DLAB_NO_THREADS` | multi-threaded Labrador |

The `-D...` opt-outs compile the original code on aarch64 as well. The
equivalence tests use them to compare the two builds.

## Build and test on the Pi

64-bit Raspberry Pi OS (or another aarch64 Linux):

```sh
sudo apt install build-essential cmake git unzip libgmp-dev libmpfr-dev \
                 python3-dev python3-cffi
git clone --recursive -b rpi4 <lazer fork> lazer   # submodule URL is relative: ../labrador.git
cd lazer
pip install -e .        # builds liblazer.so, liblabrador38.so and the Python bindings
make check              # lazer's tests (rng-test checks the AES keystream)
make -C tests/aarch64 check                 # src/modred.h against C's %
make -C src/labrados/tests/aarch64 check    # Labrador: original vs aarch64 code, byte-identical
```

On x86-64 (or with an x86-64 cross target), check that this branch compiles
exactly upstream's code:

```sh
git clone --recursive https://github.com/lazer-crypto/lazer.git ../lazer-upstream
(cd ../lazer-upstream && git checkout b958e24 && git submodule update)
scripts/check_x86_identical.sh ../lazer-upstream
```

`LAB_THREADS=<n>` sets the number of Labrador threads at run time (default 4;
`LAB_THREADS=1` starts no threads). The number of threads does not change
the proofs.

## What changed

| change | where | why only on aarch64 | effect on a Pi 4 |
|---|---|---|---|
| JL collapse as a 16-entry table lookup, indexed by public matrix nibbles | labrados `jlproj.c` | it replaces `_mm512_permutex2var_epi64`, which SIMDe emulates lane by lane | 8.5x; this was 51% of all Labrador cycles |
| NEON versions of SIMDe-emulated kernels (`jlproj_add64`, inner products, pointwise ops, reductions, ...) | labrados `poly.c`, `polz.c`, `jlproj.c`, `simd_neon.h` | they replace SIMDe emulation | 1.2–7x per kernel |
| NEON NTT, INTT and nttunpack with the same int16 operations per coefficient | labrados `ntt.c` | they replace SIMDe emulation | 2.9x, 3.2x, 2.8x |
| Constant-time NEON bitsliced AES-CTR, 8 blocks per pass, bitsliced keys cached | `src/aes-neonbs.h`, `src/aes256ctr.c`, labrados `aesctr.[ch]` | x86-64 uses AES-NI | 2.2–2.4x |
| Multi-threaded Labrador (pthread pool); work split by public sizes only; randomness and transcript order unchanged | labrados `parallel.h` and the vector code | keeps the x86-64 build as upstream | prove and verify about 1.4x on 4 cores |
| HEXL `MSB()` via `clz` instead of `std::log2l` | `src/hexl.patch` | `long double` is 128-bit *software* float on aarch64 | about 10% of LNP time removed |
| Branch-free 128-by-64-bit remainder (Möller–Granlund) instead of libgcc `__modti3`; int64 Schwartz–Zippel accumulation; fewer copies and allocations | `src/modred.h`, `src/vr_accum.h`, `src/lin-proofs.c`, `src/poly.c`, `src/int.c`, `src/intvec.c` | aarch64 has no 128-by-64-bit divide, so `__modti3` is a slow library call | LNP prove and verify 23–43% faster |

The labrados changes are explained in detail in
`src/labrados/README-aarch64.md`. The comments in the code give the exactness
argument for each change.

### Side channels

None of the changes adds a secret-dependent branch or memory access:
- table indices and the split of work between threads depend only on public
  data;
- the AES is bitsliced;
- `modred.h` is branch-free and *removes* the variable-time `__modti3`
  division that the port applies to secret coefficients.

## How this was verified

- **Each kernel:** the equivalence tests above. Each test is built twice
  (original vs aarch64 code), on random and edge-case inputs, at LOGQ 32, 36
  and 38. They include 8 end-to-end Labrador proofs at 1 and 4 threads.
- **End to end:** the device-binding protocol was run with deterministic OS
  randomness, and every message and proof was hashed. The hashes equal
  those of the build without the optimizations, for 1 and 4 threads.
- **Threads:** ThreadSanitizer is clean.
- **x86-64:** `scripts/check_x86_identical.sh <upstream checkout>` preprocesses
  every translation unit of the library (lazer, lattice-hash, labrados at LOGQ
  32/36/38, the cffi headers; 97 in total) with x86-64 AVX-512 flags, in this
  branch and in upstream lazer b958e24. All of them are identical.
