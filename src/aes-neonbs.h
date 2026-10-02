#ifndef AES_NEONBS_H
#define AES_NEONBS_H

/*
 * Constant-time bitsliced AES encryption for AArch64 NEON (ASIMD), for
 * CPUs without the ARMv8 crypto extensions (e.g. Cortex-A72 / Raspberry
 * Pi 4). Encrypts 8 blocks in parallel in eight 128-bit registers.
 * Shared by lazer (src/aes256ctr.c) and labrador (src/labrados/aesctr.c).
 *
 * Layout (Kaesper-Schwabe style): after the input transform, register
 * ("plane") i holds bit i of every state byte of all 8 blocks; bit k of a
 * plane byte belongs to block k, and plane byte 4*r+c holds AES state byte
 * (row r, column c), i.e. byte r+4*c of a block ("row-major"). Hence
 * SubBytes is the Boyar-Peralta circuit (same as in aes-ct64.h) on full
 * registers, ShiftRows is a fixed byte permutation (TBL with constant
 * indices), the MixColumns row rotations are EXT by 4 / 8 bytes, and the
 * round keys are bytes 0x00 / 0xff per plane.
 *
 * Constant-time: only bitwise operations, constant shifts and fixed
 * (data-independent) register permutations; no memory lookups indexed by
 * secret data and no secret-dependent branches.
 *
 * The four complemented outputs of the S-box circuit (the affine constant
 * 0x63) are not computed in the S-box but folded into the round keys of
 * rounds 1..R (ShiftRows and MixColumns commute with adding a constant byte
 * to all state bytes, since 2^3^1^1 == 1 in GF(2^8)), see
 * _aes_nbs_expand_rks().
 */

#include <arm_neon.h>
#include <stdint.h>

/* keep the 8 state registers in registers across all helpers */
#define AES_NBS_INLINE static inline __attribute__ ((always_inline))

/* bitsliced round key: 8 planes of 16 bytes */
#define AES_NBS_RKBYTES 128

/* row-major <-> column-major byte order (4x4 transpose, an involution) */
static const uint8_t _aes_nbs_rm_idx[16]
    = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };

/*
 * Expand a 16-byte value (in AES byte order) into bitsliced form (all 8
 * blocks equal): plane i, byte 4*r+c = 0xff if bit i of x[r+4*c] is set.
 */
AES_NBS_INLINE void
_aes_nbs_broadcast (uint8x16_t q[8], uint8x16_t x)
{
  int i;

  x = vqtbl1q_u8 (x, vld1q_u8 (_aes_nbs_rm_idx));
  for (i = 0; i < 8; i++)
    q[i] = vtstq_u8 (x, vdupq_n_u8 ((uint8_t)(1u << i))); /* branch-free */
}

/*
 * Convert the (rounds+1) standard 16-byte round keys rks[] into bitsliced
 * form, AES_NBS_RKBYTES bytes per round key, for _aes_nbs_encrypt8 /
 * _aes_nbs_ctr8. The S-box constant 0x63 is folded into the keys of rounds
 * 1..rounds; the last round key is stored in column-major byte order (the
 * last round converts the state back to column-major before adding it).
 */
static void
_aes_nbs_expand_rks (uint8_t *out, const uint8_t *rks, int rounds)
{
  uint8x16_t q[8], k;
  int r, i;

  for (r = 0; r <= rounds; r++)
    {
      k = vld1q_u8 (rks + 16 * r);
      if (r > 0)
        k = veorq_u8 (k, vdupq_n_u8 (0x63));
      if (r == rounds) /* cancel the row-major permutation */
        k = vqtbl1q_u8 (k, vld1q_u8 (_aes_nbs_rm_idx));
      _aes_nbs_broadcast (q, k);
      for (i = 0; i < 8; i++)
        vst1q_u8 (out + AES_NBS_RKBYTES * r + 16 * i, q[i]);
    }
}

/* in-place 8x8 bit-matrix transpose per byte position (an involution) */
#define _AES_NBS_SWAPMOVE(a, b, n, m)                                         \
  do                                                                          \
    {                                                                         \
      uint8x16_t t_ = vandq_u8 (veorq_u8 (vshrq_n_u8 ((a), (n)), (b)), (m));  \
      (b) = veorq_u8 ((b), t_);                                               \
      (a) = veorq_u8 ((a), vshlq_n_u8 (t_, (n)));                             \
    }                                                                         \
  while (0)

AES_NBS_INLINE void
_aes_nbs_transpose (uint8x16_t q[8])
{
  const uint8x16_t m1 = vdupq_n_u8 (0x55);
  const uint8x16_t m2 = vdupq_n_u8 (0x33);
  const uint8x16_t m4 = vdupq_n_u8 (0x0f);

  _AES_NBS_SWAPMOVE (q[0], q[1], 1, m1);
  _AES_NBS_SWAPMOVE (q[2], q[3], 1, m1);
  _AES_NBS_SWAPMOVE (q[4], q[5], 1, m1);
  _AES_NBS_SWAPMOVE (q[6], q[7], 1, m1);

  _AES_NBS_SWAPMOVE (q[0], q[2], 2, m2);
  _AES_NBS_SWAPMOVE (q[1], q[3], 2, m2);
  _AES_NBS_SWAPMOVE (q[4], q[6], 2, m2);
  _AES_NBS_SWAPMOVE (q[5], q[7], 2, m2);

  _AES_NBS_SWAPMOVE (q[0], q[4], 4, m4);
  _AES_NBS_SWAPMOVE (q[1], q[5], 4, m4);
  _AES_NBS_SWAPMOVE (q[2], q[6], 4, m4);
  _AES_NBS_SWAPMOVE (q[3], q[7], 4, m4);
}

/*
 * Boyar-Peralta S-box circuit (see aes-ct64.h), without the final
 * complements (folded into the round keys). q[i] = bit plane i.
 */
AES_NBS_INLINE void
_aes_nbs_sbox (uint8x16_t q[8])
{
#define X_(a, b) veorq_u8 ((a), (b))
#define A_(a, b) vandq_u8 ((a), (b))
  uint8x16_t x0, x1, x2, x3, x4, x5, x6, x7;
  uint8x16_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
  uint8x16_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
  uint8x16_t y20, y21;
  uint8x16_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
  uint8x16_t z10, z11, z12, z13, z14, z15, z16, z17;
  uint8x16_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
  uint8x16_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
  uint8x16_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
  uint8x16_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
  uint8x16_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
  uint8x16_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
  uint8x16_t t60, t61, t62, t63, t64, t65, t66, t67;

  x0 = q[7];
  x1 = q[6];
  x2 = q[5];
  x3 = q[4];
  x4 = q[3];
  x5 = q[2];
  x6 = q[1];
  x7 = q[0];

  /* top linear transformation */
  y14 = X_ (x3, x5);
  y13 = X_ (x0, x6);
  y9 = X_ (x0, x3);
  y8 = X_ (x0, x5);
  t0 = X_ (x1, x2);
  y1 = X_ (t0, x7);
  y4 = X_ (y1, x3);
  y12 = X_ (y13, y14);
  y2 = X_ (y1, x0);
  y5 = X_ (y1, x6);
  y3 = X_ (y5, y8);
  t1 = X_ (x4, y12);
  y15 = X_ (t1, x5);
  y20 = X_ (t1, x1);
  y6 = X_ (y15, x7);
  y10 = X_ (y15, t0);
  y11 = X_ (y20, y9);
  y7 = X_ (x7, y11);
  y17 = X_ (y10, y11);
  y19 = X_ (y10, y8);
  y16 = X_ (t0, y11);
  y21 = X_ (y13, y16);
  y18 = X_ (x0, y16);

  /* non-linear section */
  t2 = A_ (y12, y15);
  t3 = A_ (y3, y6);
  t4 = X_ (t3, t2);
  t5 = A_ (y4, x7);
  t6 = X_ (t5, t2);
  t7 = A_ (y13, y16);
  t8 = A_ (y5, y1);
  t9 = X_ (t8, t7);
  t10 = A_ (y2, y7);
  t11 = X_ (t10, t7);
  t12 = A_ (y9, y11);
  t13 = A_ (y14, y17);
  t14 = X_ (t13, t12);
  t15 = A_ (y8, y10);
  t16 = X_ (t15, t12);
  t17 = X_ (t4, t14);
  t18 = X_ (t6, t16);
  t19 = X_ (t9, t14);
  t20 = X_ (t11, t16);
  t21 = X_ (t17, y20);
  t22 = X_ (t18, y19);
  t23 = X_ (t19, y21);
  t24 = X_ (t20, y18);

  t25 = X_ (t21, t22);
  t26 = A_ (t21, t23);
  t27 = X_ (t24, t26);
  t28 = A_ (t25, t27);
  t29 = X_ (t28, t22);
  t30 = X_ (t23, t24);
  t31 = X_ (t22, t26);
  t32 = A_ (t31, t30);
  t33 = X_ (t32, t24);
  t34 = X_ (t23, t33);
  t35 = X_ (t27, t33);
  t36 = A_ (t24, t35);
  t37 = X_ (t36, t34);
  t38 = X_ (t27, t36);
  t39 = A_ (t29, t38);
  t40 = X_ (t25, t39);

  t41 = X_ (t40, t37);
  t42 = X_ (t29, t33);
  t43 = X_ (t29, t40);
  t44 = X_ (t33, t37);
  t45 = X_ (t42, t41);
  z0 = A_ (t44, y15);
  z1 = A_ (t37, y6);
  z2 = A_ (t33, x7);
  z3 = A_ (t43, y16);
  z4 = A_ (t40, y1);
  z5 = A_ (t29, y7);
  z6 = A_ (t42, y11);
  z7 = A_ (t45, y17);
  z8 = A_ (t41, y10);
  z9 = A_ (t44, y12);
  z10 = A_ (t37, y3);
  z11 = A_ (t33, y4);
  z12 = A_ (t43, y13);
  z13 = A_ (t40, y5);
  z14 = A_ (t29, y2);
  z15 = A_ (t42, y9);
  z16 = A_ (t45, y14);
  z17 = A_ (t41, y8);

  /* bottom linear transformation (complements omitted) */
  t46 = X_ (z15, z16);
  t47 = X_ (z10, z11);
  t48 = X_ (z5, z13);
  t49 = X_ (z9, z10);
  t50 = X_ (z2, z12);
  t51 = X_ (z2, z5);
  t52 = X_ (z7, z8);
  t53 = X_ (z0, z3);
  t54 = X_ (z6, z7);
  t55 = X_ (z16, z17);
  t56 = X_ (z12, t48);
  t57 = X_ (t50, t53);
  t58 = X_ (z4, t46);
  t59 = X_ (z3, t54);
  t60 = X_ (t46, t57);
  t61 = X_ (z14, t57);
  t62 = X_ (t52, t58);
  t63 = X_ (t49, t58);
  t64 = X_ (z4, t59);
  t65 = X_ (t61, t62);
  t66 = X_ (z1, t63);
  q[7] = X_ (t59, t63);       /* s0 */
  q[1] = X_ (t56, t62);       /* s6 ^ 0xff */
  q[0] = X_ (t48, t60);       /* s7 ^ 0xff */
  t67 = X_ (t64, t65);
  q[4] = X_ (t53, t66);       /* s3 */
  q[3] = X_ (t51, t66);       /* s4 */
  q[2] = X_ (t47, t65);       /* s5 */
  q[6] = X_ (t64, q[4]);      /* s1 ^ 0xff (uses s3) */
  q[5] = X_ (t55, t67);       /* s2 ^ 0xff */
#undef X_
#undef A_
}

AES_NBS_INLINE void
_aes_nbs_add_rk (uint8x16_t q[8], const uint8_t *rk)
{
  int i;

  for (i = 0; i < 8; i++)
    q[i] = veorq_u8 (q[i], vld1q_u8 (rk + 16 * i));
}

/* ShiftRows (row-major): new byte 4r+c = old byte 4r+(c+r)%4 */
static const uint8_t _aes_nbs_sr_idx[16]
    = { 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14 };
/* row-major -> ShiftRows -> column-major: new[r+4c] = old[4r+(c+r)%4] */
static const uint8_t _aes_nbs_sr_cm_idx[16]
    = { 0, 5, 10, 15, 1, 6, 11, 12, 2, 7, 8, 13, 3, 4, 9, 14 };

/* ShiftRows + MixColumns */
AES_NBS_INLINE void
_aes_nbs_sr_mc (uint8x16_t q[8], uint8x16_t sr)
{
  uint8x16_t r[8], t[8];
  int i;

  for (i = 0; i < 8; i++)
    {
      uint8x16_t s = vqtbl1q_u8 (q[i], sr); /* a = SR(x)                */
      r[i] = vextq_u8 (s, s, 4);            /* rot1(a): row r <- row r+1 */
      t[i] = veorq_u8 (s, r[i]);            /* a ^ rot1(a)              */
    }
  /* out = 2*t ^ rot1(a) ^ rot2(t) */
#define R2_(x) vextq_u8 ((x), (x), 8)
  q[0] = veorq_u8 (veorq_u8 (t[7], r[0]), R2_ (t[0]));
  q[1] = veorq_u8 (veorq_u8 (veorq_u8 (t[0], t[7]), r[1]), R2_ (t[1]));
  q[2] = veorq_u8 (veorq_u8 (t[1], r[2]), R2_ (t[2]));
  q[3] = veorq_u8 (veorq_u8 (veorq_u8 (t[2], t[7]), r[3]), R2_ (t[3]));
  q[4] = veorq_u8 (veorq_u8 (veorq_u8 (t[3], t[7]), r[4]), R2_ (t[4]));
  q[5] = veorq_u8 (veorq_u8 (t[4], r[5]), R2_ (t[5]));
  q[6] = veorq_u8 (veorq_u8 (t[5], r[6]), R2_ (t[6]));
  q[7] = veorq_u8 (veorq_u8 (t[6], r[7]), R2_ (t[7]));
#undef R2_
}

/*
 * All rounds on a row-major bitsliced state, then back to 8 blocks in
 * standard byte order at out[128].
 */
AES_NBS_INLINE void
_aes_nbs_rounds_out (uint8_t out[128], uint8x16_t q[8], const uint8_t *rk,
                     int rounds)
{
  const uint8x16_t sr = vld1q_u8 (_aes_nbs_sr_idx);
  const uint8x16_t srcm = vld1q_u8 (_aes_nbs_sr_cm_idx);
  int i, r;

  _aes_nbs_add_rk (q, rk);
  for (r = 1; r < rounds; r++)
    {
      _aes_nbs_sbox (q);
      _aes_nbs_sr_mc (q, sr);
      _aes_nbs_add_rk (q, rk + AES_NBS_RKBYTES * r);
    }
  _aes_nbs_sbox (q);
  for (i = 0; i < 8; i++)
    q[i] = vqtbl1q_u8 (q[i], srcm); /* ShiftRows, back to column-major */
  _aes_nbs_add_rk (q, rk + AES_NBS_RKBYTES * rounds);
  _aes_nbs_transpose (q);
  for (i = 0; i < 8; i++)
    vst1q_u8 (out + 16 * i, q[i]);
}

/*
 * Encrypt 8 arbitrary blocks: in/out are 8 consecutive 16-byte blocks (may
 * alias). rk: bitsliced round keys from _aes_nbs_expand_rks.
 */
static __attribute__ ((noinline)) void
_aes_nbs_encrypt8 (uint8_t out[128], const uint8_t in[128],
                   const uint8_t *rk, int rounds)
{
  const uint8x16_t rm = vld1q_u8 (_aes_nbs_rm_idx);
  uint8x16_t q[8];
  int i;

  for (i = 0; i < 8; i++)
    q[i] = vld1q_u8 (in + 16 * i);
  _aes_nbs_transpose (q);
  for (i = 0; i < 8; i++)
    q[i] = vqtbl1q_u8 (q[i], rm); /* column-major -> row-major */
  _aes_nbs_rounds_out (out, q, rk, rounds);
}

/*
 * CTR mode fast path: encrypt the 8 blocks blk + k (k = 0..7), where "+ k"
 * only changes the 3 low bits of byte pos of blk, which must be zero
 * (i.e. the counter's least significant byte is at pos and the first
 * counter is a multiple of 8). The bitsliced input is built directly
 * (all blocks equal except for 3 bit-planes of one byte), without the
 * input transpose.
 */
AES_NBS_INLINE void
_aes_nbs_ctr8 (uint8_t out[128], const uint8_t blk[16], unsigned int pos,
               const uint8_t *rk, int rounds)
{
  /* mask of the row-major position of AES byte pos */
  const uint8x16_t sel
      = vceqq_u8 (vld1q_u8 (_aes_nbs_rm_idx), vdupq_n_u8 ((uint8_t)pos));
  uint8x16_t q[8];

  _aes_nbs_broadcast (q, vld1q_u8 (blk));
  /* bit i (i < 3) of the counter byte of block k is bit i of k */
  q[0] = veorq_u8 (q[0], vandq_u8 (sel, vdupq_n_u8 (0xaa)));
  q[1] = veorq_u8 (q[1], vandq_u8 (sel, vdupq_n_u8 (0xcc)));
  q[2] = veorq_u8 (q[2], vandq_u8 (sel, vdupq_n_u8 (0xf0)));
  _aes_nbs_rounds_out (out, q, rk, rounds);
}

#endif
