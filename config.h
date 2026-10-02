/*
 * TARGET: GENERIC, AMD64
 * Architecture target.
 * Auto-selected: AMD64 on x86-64, GENERIC elsewhere (e.g. aarch64).
 * Define LAZER_PORTABLE to force GENERIC on x86-64.
 */
#ifndef TARGET
#if defined(__x86_64__) && !defined(LAZER_PORTABLE)
#define TARGET TARGET_AMD64
#else
#define TARGET TARGET_GENERIC
#endif
#endif

/*
 * RNG: SHAKE128, AES256CTR, CHACHA20
 * Use Shake128, AES-256-CTR or ChaCha20 for pseudorandom generation.
 * The choice changes all derived randomness (public parameters,
 * challenges, ...), so proofs are only interoperable between builds
 * using the same RNG.
 * Can be overridden without editing this file: `make RNG=CHACHA20`
 * (bakes the choice into the generated lazer.h) or -DLAZER_RNG=RNG_CHACHA20.
 */
#ifndef RNG
#ifdef LAZER_RNG
#define RNG LAZER_RNG
#else
#define RNG RNG_AES256CTR
#endif
#endif

/*
 * ASSERT: ENABLED, DISABLED
 * Enable or diasble assertions.
 */
#define ASSERT ASSERT_DISABLED

/*
 * TIMERS: ENABLED, DISABLED
 * Run timers and print the results.
 */
#define TIMERS TIMERS_DISABLED

/*
 * DEBUGINFO: ENABLED, DISABLED
 * Print out debug information.
 */
#define DEBUGINFO DEBUGINFO_DISABLED

/*
 * VALGRIND: ENABLED, DISABLED
 * Build and run valgrind tests.
 * Requires valgrind installation.
 * Requires ASSERT_DISABLED
 */
#define VALGRIND VALGRIND_DISABLED
