/*
 * Test of src/modred.h (the aarch64 replacement for __int128 %, see
 * docs/RPI4.md): compares _modpre_rem2, _modpre_srem, _modpre_int_mod and
 * _modpre_int_mod_hexl with C's % and with the original int_mod_XXX code,
 * on random and edge-case inputs for fixed (lazer's CRT moduli) and random
 * moduli. Also prints a micro-benchmark against __modti3.
 *
 *   make -C tests/aarch64 check
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
typedef uint64_t limb_t;
#define MODRED_STANDALONE
#include "../../src/modred.h"

static uint64_t s[2] = { 0x123456789abcdefULL, 0xfedcba9876543210ULL };
static uint64_t
rnd (void)
{
  uint64_t s1 = s[0];
  const uint64_t s0 = s[1];
  const uint64_t r = s0 + s1;
  s[0] = s0;
  s1 ^= s1 << 23;
  s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
  return r;
}
static uint64_t
rndbits (void)
{
  unsigned b = rnd () % 65;
  uint64_t x = rnd ();
  return b == 64 ? x : (x & ((1ULL << b) - 1));
}

static long nfail = 0;
#define CHECK(c, ...)                                                         \
  do                                                                          \
    {                                                                         \
      if (!(c))                                                               \
        {                                                                     \
          if (nfail++ < 10)                                                   \
            printf (__VA_ARGS__);                                             \
        }                                                                     \
    }                                                                         \
  while (0)

static void
test_mod (uint64_t m, long iters)
{
  _modpre_t pre;
  _modpre_init (&pre, m);
  int sgn = (int64_t)m > 0;
  for (long i = 0; i < iters; i++)
    {
      uint64_t u1, u0;
      switch (i % 4)
        {
        case 0:
          u1 = rnd () % m;
          u0 = rnd ();
          break;
        case 1:
          u1 = m - 1 - (rnd () % 4 % m);
          u0 = (i & 8) ? ~(uint64_t)0 - rnd () % 3 : rnd () % 3;
          break;
        case 2:
          u1 = rndbits () % m;
          u0 = rndbits ();
          break;
        default:
          { /* near multiples of m */
            unsigned __int128 t
                = (unsigned __int128)(rnd () % m) * m + m - (rnd () % 3);
            u1 = (uint64_t)(t >> 64) % m;
            u0 = (uint64_t)t;
          }
        }
      unsigned __int128 x = ((unsigned __int128)u1 << 64) | u0;
      uint64_t ref = (uint64_t)(x % m);
      uint64_t got = _modpre_rem2 (&pre, u1, u0);
      CHECK (ref == got, "rem2 fail m=%llu u1=%llu u0=%llu ref=%llu got=%llu\n",
             (unsigned long long)m, (unsigned long long)u1,
             (unsigned long long)u0, (unsigned long long)ref,
             (unsigned long long)got);
      if (sgn)
        {
          /* signed: emulate original int_mod_XXX semantics and srem */
          __int128 xs = (__int128)x;
          if (u1 >> 63)
            continue;
          if (i & 1)
            xs = -xs;
          int64_t sref = (int64_t)(xs % (__int128)(int64_t)m);
          int64_t sgot = _modpre_srem (&pre, xs);
          CHECK (sref == sgot, "srem fail m=%llu\n", (unsigned long long)m);
          /* k*c products as in poly_fromcrt */
          int64_t k = (int64_t)(rnd () % m) - (int64_t)(m / 2);
          if ((uint64_t)(k < 0 ? -k : k) > (m - 1) / 2)
            k = 0;
          int64_t c = (int64_t)rndbits ();
          if (i & 2)
            c = -c;
          __int128 pr = (__int128)k * c;
          sref = (int64_t)(pr % (__int128)(int64_t)m);
          sgot = _modpre_srem (&pre, pr);
          CHECK (sref == sgot, "srem kc fail m=%llu k=%lld c=%lld\n",
                 (unsigned long long)m, (long long)k, (long long)c);
        }
    }
}

/* original int_mod_XXX / _hexl from lazer-in2.h */
static int64_t
orig_int_mod (const limb_t *limbs, unsigned n, limb_t neg, int64_t m)
{
  limb_t d1, d2, r = 0;
  for (int k = n - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = limbs[k];
      r = (((__int128)d1 << 64) + d2) % m;
    }
  return neg ? -r : r;
}
static uint64_t
orig_int_mod_hexl (const limb_t *limbs, unsigned n, limb_t neg, int64_t m)
{
  limb_t d1, d2, r = 0;
  for (int k = n - 1; k >= 0; k--)
    {
      d1 = r;
      d2 = limbs[k];
      r = (((__int128)d1 << 64) + d2) % m;
    }
  return neg ? m - r : r;
}

static void
test_intmod (uint64_t m, long iters)
{
  _modpre_t pre;
  _modpre_init (&pre, m);
  for (long i = 0; i < iters; i++)
    {
      limb_t l[4];
      unsigned n = 1 + rnd () % 4;
      for (unsigned j = 0; j < n; j++)
        l[j] = (i & 1) ? rnd () : rndbits ();
      if (i % 7 == 0)
        for (unsigned j = 0; j < n; j++)
          l[j] = 0;
      limb_t neg = rnd () & 1;
      CHECK (orig_int_mod (l, n, neg, m) == _modpre_int_mod (&pre, l, n, neg),
             "int_mod fail\n");
      CHECK (orig_int_mod_hexl (l, n, neg, m)
                 == _modpre_int_mod_hexl (&pre, l, n, neg),
             "int_mod_hexl fail\n");
    }
}

static double
now (void)
{
  struct timespec t;
  clock_gettime (CLOCK_MONOTONIC, &t);
  return t.tv_sec + 1e-9 * t.tv_nsec;
}

int
main (int argc, char **argv)
{
  long it = argc > 1 ? atol (argv[1]) : 2000000;
  const uint64_t fixed[]
      = { 1125899906840833ULL, 1125899906839937ULL, 1125899906837633ULL,
          1125899906826241ULL, 8796093023213ULL, 1, 2, 3, 255, 256, 257,
          (1ULL << 50) - 1, 1ULL << 50, (1ULL << 62) + 1, (1ULL << 63) - 1,
          1ULL << 63, (1ULL << 63) + 1, ~0ULL, ~0ULL - 1, 4294967291ULL,
          4294967296ULL, 4294967297ULL };
  for (unsigned i = 0; i < sizeof (fixed) / sizeof (fixed[0]); i++)
    {
      test_mod (fixed[i], it);
      if ((int64_t)fixed[i] > 0)
        test_intmod (fixed[i], it / 4);
    }
  for (int i = 0; i < 3000; i++)
    {
      uint64_t m = rndbits ();
      if (m == 0)
        m = 1;
      test_mod (m, it / 300);
      if ((int64_t)m > 0)
        test_intmod (m, it / 1000);
    }
  printf ("correctness: %s (%ld failures)\n", nfail ? "FAIL" : "OK", nfail);

  /* micro bench: k*c % p as in poly_fromcrt */
  {
    enum { N = 4096 };
    static int64_t c[N], k[N];
    const int64_t p = 1125899906840833LL;
    _modpre_t pre;
    _modpre_init (&pre, p);
    for (int i = 0; i < N; i++)
      {
        c[i] = rnd () % p;
        k[i] = (int64_t)(rnd () % p) - p / 2;
      }
    volatile int64_t sink = 0;
    double best1 = 1e9, best2 = 1e9;
    for (int rep = 0; rep < 20; rep++)
      {
        int64_t acc = 0;
        double t0 = now ();
        for (int i = 0; i < N; i++)
          acc += (int64_t)(((__int128)k[i] * c[i]) % p);
        double t1 = now ();
        for (int i = 0; i < N; i++)
          acc -= _modpre_srem (&pre, (__int128)k[i] * c[i]);
        double t2 = now ();
        sink += acc;
        if (acc != 0)
          printf ("bench mismatch\n");
        if (t1 - t0 < best1)
          best1 = t1 - t0;
        if (t2 - t1 < best2)
          best2 = t2 - t1;
      }
    printf ("k*c%%p: __modti3 %.2f ns/op, modred %.2f ns/op (%.1fx)\n",
            best1 * 1e9 / N, best2 * 1e9 / N, best1 / best2);
  }
  return nfail != 0;
}
