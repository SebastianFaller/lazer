#ifndef MODRED_H
#define MODRED_H
/*
 * Exact, branch-free remainder of a 128-bit dividend by a 64-bit modulus
 * using a precomputed reciprocal (Moeller-Granlund, "Improved division by
 * invariant integers", IEEE TC 2011, Alg. 4 "div_2by1_preinv").
 *
 * Replaces C's `(__int128) x % m`, which on aarch64 is a call to libgcc's
 * __modti3 (no 128/64 hardware divide; slow and data-dependent timing).
 *
 * The reciprocal depends only on the (public) modulus; computing it costs one
 * __udivti3 on public data. The reduction itself has no secret-dependent
 * branches or memory accesses and uses only mul/umulh/add/sub/csel (the
 * Cortex-A72 multiplier is constant-time).
 */
#ifndef MODRED_STANDALONE /* standalone unit test defines limb_t itself */
#include "lazer.h"
#endif
#include <stdint.h>

typedef struct
{
  uint64_t m;  /* modulus, 1 <= m < 2^64 */
  uint64_t dn; /* normalized modulus m << sh (top bit set) */
  uint64_t v;  /* floor((2^128 - 1) / dn) - 2^64 */
  unsigned int sh;
} _modpre_t;

static inline void
_modpre_init (_modpre_t *pre, uint64_t m)
{
  const unsigned int sh = (unsigned int)__builtin_clzll (m);
  const uint64_t dn = m << sh;

  pre->m = m;
  pre->sh = sh;
  pre->dn = dn;
  /* ((2^64 - 1 - dn) * 2^64 + 2^64 - 1) / dn = floor((2^128-1)/dn) - 2^64 */
  pre->v = (uint64_t)(((((unsigned __int128)~dn) << 64) | ~(uint64_t)0)
                      / dn);
}

/* all-ones if a > b else 0, without branches */
static inline uint64_t
_modpre_gtmask (uint64_t a, uint64_t b)
{
  /* borrow of b - a */
  return (uint64_t)0 - (uint64_t)(((unsigned __int128)b - a) >> 127 & 1);
}

/*
 * (u1 * 2^64 + u0) mod m. Requires u1 < m.
 */
static inline uint64_t
_modpre_rem2 (const _modpre_t *pre, uint64_t u1, uint64_t u0)
{
  const unsigned int sh = pre->sh;
  const uint64_t d = pre->dn;
  uint64_t n1, n0, q1, q0, r, mask;
  unsigned __int128 q;

  /* normalize: (n1:n0) = (u1:u0) << sh, n1 < d since u1 < m */
  n1 = (u1 << sh) | ((u0 >> 1) >> (63 - sh));
  n0 = u0 << sh;

  q = (unsigned __int128)pre->v * n1;
  q += ((unsigned __int128)n1 << 64) | n0;
  q1 = (uint64_t)(q >> 64) + 1;
  q0 = (uint64_t)q;
  r = n0 - q1 * d;
  mask = _modpre_gtmask (r, q0); /* r > q0 */
  r += mask & d;
  mask = ~_modpre_gtmask (d, r); /* r >= d */
  r -= mask & d;

  return r >> sh;
}

/*
 * (int64_t)(x % (__int128)m) with C semantics (remainder has the sign of the
 * dividend, |result| < m). Requires |x| < m * 2^64 and m < 2^63.
 */
static inline int64_t
_modpre_srem (const _modpre_t *pre, __int128 x)
{
  const uint64_t s = (uint64_t)(x >> 127); /* 0 or all-ones */
  const unsigned __int128 s2 = ((unsigned __int128)s << 64) | s;
  const unsigned __int128 a = ((unsigned __int128)x ^ s2) - s2; /* |x| */
  uint64_t r;

  r = _modpre_rem2 (pre, (uint64_t)(a >> 64), (uint64_t)a);
  return (int64_t)((r ^ s) - s);
}

/*
 * Same as int_mod_XXX (a, m) for 0 < m < 2^63:
 * |a| mod m with the sign of a, as int64.
 */
static inline int64_t
_modpre_int_mod (const _modpre_t *pre, const limb_t *limbs,
                 unsigned int nlimbs, limb_t neg)
{
  uint64_t r = 0, s;
  int k;

  for (k = (int)nlimbs - 1; k >= 0; k--)
    r = _modpre_rem2 (pre, r, limbs[k]);

  s = (uint64_t)0 - (uint64_t)(neg != 0);
  return (int64_t)((r ^ s) - s);
}

/*
 * Same as int_mod_XXX_hexl (a, m) for 0 < m < 2^63:
 * r = |a| mod m; returns neg ? m - r : r (note: m, not 0, for r == 0).
 */
static inline uint64_t
_modpre_int_mod_hexl (const _modpre_t *pre, const limb_t *limbs,
                      unsigned int nlimbs, limb_t neg)
{
  uint64_t r = 0, s;
  int k;

  for (k = (int)nlimbs - 1; k >= 0; k--)
    r = _modpre_rem2 (pre, r, limbs[k]);

  s = (uint64_t)0 - (uint64_t)(neg != 0);
  return r ^ (s & (r ^ (pre->m - r)));
}

#endif
