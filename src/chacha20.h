#ifndef LAZER_CHACHA20_H
#define LAZER_CHACHA20_H

/*
 * Constant-time ChaCha20 keystream generator (header-only).
 *
 * Block function as in RFC 8439, section 2.3 (20 rounds, 256-bit key).
 * The 16-word state is
 *
 *   s[0..3]   "expand 32-byte k"
 *   s[4..11]  key (little-endian words)
 *   s[12..13] 64-bit block counter (s[12] low word, s[13] high word)
 *   s[14..15] 64-bit nonce (little-endian)
 *
 * i.e. the original 64-bit-counter/64-bit-nonce layout of ChaCha. While the
 * counter stays below 2^32 this is bit-for-bit identical to RFC 8439 with
 * 32-bit counter s[12] and 96-bit nonce (s[13], s[14], s[15]) =
 * (0x00000000, nonce_lo, nonce_hi); chacha20_init_ietf() sets up exactly
 * the RFC 8439 state (used for the RFC test vectors).
 *
 * chacha20_blocks() writes nblocks*64 keystream bytes and advances the
 * 64-bit counter by nblocks. On little-endian aarch64 with NEON, 4 blocks
 * are computed in parallel (one block per 32-bit lane); remaining blocks use
 * the portable scalar code. All operations are add/rotate/xor on data
 * independent of secret values: no secret-dependent branches or memory
 * accesses.
 *
 * Define CHACHA20_NO_NEON to force the scalar code.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(CHACHA20_NO_NEON) && defined(__aarch64__)                       \
    && defined(__ARM_NEON) && defined(__BYTE_ORDER__)                         \
    && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CHACHA20_NEON 1
#include <arm_neon.h>
#else
#define CHACHA20_NEON 0
#endif

#define CHACHA20_BLOCKBYTES 64

static inline uint32_t
_chacha20_load32le (const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void
_chacha20_store32le (uint8_t *p, uint32_t x)
{
  p[0] = (uint8_t)x;
  p[1] = (uint8_t)(x >> 8);
  p[2] = (uint8_t)(x >> 16);
  p[3] = (uint8_t)(x >> 24);
}

static inline void
_chacha20_setkey (uint32_t s[16], const uint8_t key[32])
{
  int i;

  s[0] = 0x61707865; /* "expa" */
  s[1] = 0x3320646e; /* "nd 3" */
  s[2] = 0x79622d32; /* "2-by" */
  s[3] = 0x6b206574; /* "te k" */
  for (i = 0; i < 8; i++)
    s[4 + i] = _chacha20_load32le (key + 4 * i);
}

/* 64-bit nonce, 64-bit counter := 0 */
static inline void
chacha20_init (uint32_t s[16], const uint8_t key[32], uint64_t nonce)
{
  _chacha20_setkey (s, key);
  s[12] = 0;
  s[13] = 0;
  s[14] = (uint32_t)nonce;
  s[15] = (uint32_t)(nonce >> 32);
}

/* re-set the nonce and reset the counter to 0, keep the key */
static inline void
chacha20_setnonce (uint32_t s[16], uint64_t nonce)
{
  s[12] = 0;
  s[13] = 0;
  s[14] = (uint32_t)nonce;
  s[15] = (uint32_t)(nonce >> 32);
}

/* RFC 8439 layout: 32-bit counter, 96-bit nonce (for test vectors) */
static inline void
chacha20_init_ietf (uint32_t s[16], const uint8_t key[32],
                    const uint8_t nonce[12], uint32_t counter)
{
  _chacha20_setkey (s, key);
  s[12] = counter;
  s[13] = _chacha20_load32le (nonce + 0);
  s[14] = _chacha20_load32le (nonce + 4);
  s[15] = _chacha20_load32le (nonce + 8);
}

static inline void
chacha20_clear (uint32_t s[16])
{
  volatile uint32_t *p = s;
  int i;

  for (i = 0; i < 16; i++)
    p[i] = 0;
}

static inline void
_chacha20_ctr_add (uint32_t s[16], uint64_t n)
{
  uint64_t c = ((uint64_t)s[13] << 32) | s[12];

  c += n;
  s[12] = (uint32_t)c;
  s[13] = (uint32_t)(c >> 32);
}

#define _CHACHA20_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define _CHACHA20_QR(a, b, c, d)                                              \
  do                                                                          \
    {                                                                         \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = _CHACHA20_ROTL32 (d, 16);                                           \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = _CHACHA20_ROTL32 (b, 12);                                           \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = _CHACHA20_ROTL32 (d, 8);                                            \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = _CHACHA20_ROTL32 (b, 7);                                            \
    }                                                                         \
  while (0)

/* portable scalar code: one block per iteration */
static inline void
chacha20_blocks_scalar (uint32_t s[16], uint8_t *out, size_t nblocks)
{
  uint32_t x[16];
  size_t blk;
  int i;

  for (blk = 0; blk < nblocks; blk++)
    {
      for (i = 0; i < 16; i++)
        x[i] = s[i];
      for (i = 0; i < 10; i++)
        {
          _CHACHA20_QR (x[0], x[4], x[8], x[12]);
          _CHACHA20_QR (x[1], x[5], x[9], x[13]);
          _CHACHA20_QR (x[2], x[6], x[10], x[14]);
          _CHACHA20_QR (x[3], x[7], x[11], x[15]);
          _CHACHA20_QR (x[0], x[5], x[10], x[15]);
          _CHACHA20_QR (x[1], x[6], x[11], x[12]);
          _CHACHA20_QR (x[2], x[7], x[8], x[13]);
          _CHACHA20_QR (x[3], x[4], x[9], x[14]);
        }
      for (i = 0; i < 16; i++)
        _chacha20_store32le (out + 4 * i, x[i] + s[i]);
      _chacha20_ctr_add (s, 1);
      out += CHACHA20_BLOCKBYTES;
    }
  for (i = 0; i < 16; i++)
    ((volatile uint32_t *)x)[i] = 0;
}

#if CHACHA20_NEON

#define _CHACHA20_V_ROTL(x, n) vsriq_n_u32 (vshlq_n_u32 ((x), (n)), (x), 32 - (n))
#define _CHACHA20_V_ROT16(x) vreinterpretq_u32_u16 (vrev32q_u16 (vreinterpretq_u16_u32 (x)))
#define _CHACHA20_V_ROT8(x, tbl)                                              \
  vreinterpretq_u32_u8 (vqtbl1q_u8 (vreinterpretq_u8_u32 (x), (tbl)))

#define _CHACHA20_VQR(a, b, c, d)                                             \
  do                                                                          \
    {                                                                         \
      a = vaddq_u32 (a, b);                                                   \
      d = veorq_u32 (d, a);                                                   \
      d = _CHACHA20_V_ROT16 (d);                                              \
      c = vaddq_u32 (c, d);                                                   \
      b = veorq_u32 (b, c);                                                   \
      b = _CHACHA20_V_ROTL (b, 12);                                           \
      a = vaddq_u32 (a, b);                                                   \
      d = veorq_u32 (d, a);                                                   \
      d = _CHACHA20_V_ROT8 (d, rot8);                                         \
      c = vaddq_u32 (c, d);                                                   \
      b = veorq_u32 (b, c);                                                   \
      b = _CHACHA20_V_ROTL (b, 7);                                            \
    }                                                                         \
  while (0)

/* store words w0..w3 (each holding word i of blocks 0..3 in lanes 0..3)
 * transposed: block b gets 16 bytes at out + 64*b + off */
#define _CHACHA20_V_STORE4(w0, w1, w2, w3, off)                               \
  do                                                                          \
    {                                                                         \
      uint32x4_t t0 = vtrn1q_u32 (w0, w1); /* w0[0] w1[0] w0[2] w1[2] */      \
      uint32x4_t t1 = vtrn2q_u32 (w0, w1); /* w0[1] w1[1] w0[3] w1[3] */      \
      uint32x4_t t2 = vtrn1q_u32 (w2, w3);                                    \
      uint32x4_t t3 = vtrn2q_u32 (w2, w3);                                    \
      uint32x4_t b0 = vreinterpretq_u32_u64 (vtrn1q_u64 (                     \
          vreinterpretq_u64_u32 (t0), vreinterpretq_u64_u32 (t2)));           \
      uint32x4_t b1 = vreinterpretq_u32_u64 (vtrn1q_u64 (                     \
          vreinterpretq_u64_u32 (t1), vreinterpretq_u64_u32 (t3)));           \
      uint32x4_t b2 = vreinterpretq_u32_u64 (vtrn2q_u64 (                     \
          vreinterpretq_u64_u32 (t0), vreinterpretq_u64_u32 (t2)));           \
      uint32x4_t b3 = vreinterpretq_u32_u64 (vtrn2q_u64 (                     \
          vreinterpretq_u64_u32 (t1), vreinterpretq_u64_u32 (t3)));           \
      vst1q_u8 (out + 0 * 64 + (off), vreinterpretq_u8_u32 (b0));             \
      vst1q_u8 (out + 1 * 64 + (off), vreinterpretq_u8_u32 (b1));             \
      vst1q_u8 (out + 2 * 64 + (off), vreinterpretq_u8_u32 (b2));             \
      vst1q_u8 (out + 3 * 64 + (off), vreinterpretq_u8_u32 (b3));             \
    }                                                                         \
  while (0)

/* NEON code: 4 blocks per iteration, nblocks must be a multiple of 4 */
static inline void
chacha20_blocks_neon4 (uint32_t s[16], uint8_t *out, size_t nblocks)
{
  static const uint8_t rot8_idx[16]
      = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
  const uint8x16_t rot8 = vld1q_u8 (rot8_idx);
  uint32x4_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13,
      x14, x15;
  uint32x4_t i12, i13;
  uint32_t lo[4], hi[4];
  uint64_t c;
  size_t blk;
  int i;

  for (blk = 0; blk + 4 <= nblocks; blk += 4)
    {
      c = ((uint64_t)s[13] << 32) | s[12];
      for (i = 0; i < 4; i++)
        {
          lo[i] = (uint32_t)(c + i);
          hi[i] = (uint32_t)((c + i) >> 32);
        }
      i12 = vld1q_u32 (lo);
      i13 = vld1q_u32 (hi);

      x0 = vdupq_n_u32 (s[0]);
      x1 = vdupq_n_u32 (s[1]);
      x2 = vdupq_n_u32 (s[2]);
      x3 = vdupq_n_u32 (s[3]);
      x4 = vdupq_n_u32 (s[4]);
      x5 = vdupq_n_u32 (s[5]);
      x6 = vdupq_n_u32 (s[6]);
      x7 = vdupq_n_u32 (s[7]);
      x8 = vdupq_n_u32 (s[8]);
      x9 = vdupq_n_u32 (s[9]);
      x10 = vdupq_n_u32 (s[10]);
      x11 = vdupq_n_u32 (s[11]);
      x12 = i12;
      x13 = i13;
      x14 = vdupq_n_u32 (s[14]);
      x15 = vdupq_n_u32 (s[15]);

      for (i = 0; i < 10; i++)
        {
          _CHACHA20_VQR (x0, x4, x8, x12);
          _CHACHA20_VQR (x1, x5, x9, x13);
          _CHACHA20_VQR (x2, x6, x10, x14);
          _CHACHA20_VQR (x3, x7, x11, x15);
          _CHACHA20_VQR (x0, x5, x10, x15);
          _CHACHA20_VQR (x1, x6, x11, x12);
          _CHACHA20_VQR (x2, x7, x8, x13);
          _CHACHA20_VQR (x3, x4, x9, x14);
        }

      x0 = vaddq_u32 (x0, vdupq_n_u32 (s[0]));
      x1 = vaddq_u32 (x1, vdupq_n_u32 (s[1]));
      x2 = vaddq_u32 (x2, vdupq_n_u32 (s[2]));
      x3 = vaddq_u32 (x3, vdupq_n_u32 (s[3]));
      x4 = vaddq_u32 (x4, vdupq_n_u32 (s[4]));
      x5 = vaddq_u32 (x5, vdupq_n_u32 (s[5]));
      x6 = vaddq_u32 (x6, vdupq_n_u32 (s[6]));
      x7 = vaddq_u32 (x7, vdupq_n_u32 (s[7]));
      x8 = vaddq_u32 (x8, vdupq_n_u32 (s[8]));
      x9 = vaddq_u32 (x9, vdupq_n_u32 (s[9]));
      x10 = vaddq_u32 (x10, vdupq_n_u32 (s[10]));
      x11 = vaddq_u32 (x11, vdupq_n_u32 (s[11]));
      x12 = vaddq_u32 (x12, i12);
      x13 = vaddq_u32 (x13, i13);
      x14 = vaddq_u32 (x14, vdupq_n_u32 (s[14]));
      x15 = vaddq_u32 (x15, vdupq_n_u32 (s[15]));

      _CHACHA20_V_STORE4 (x0, x1, x2, x3, 0);
      _CHACHA20_V_STORE4 (x4, x5, x6, x7, 16);
      _CHACHA20_V_STORE4 (x8, x9, x10, x11, 32);
      _CHACHA20_V_STORE4 (x12, x13, x14, x15, 48);

      _chacha20_ctr_add (s, 4);
      out += 4 * CHACHA20_BLOCKBYTES;
    }
}

#endif /* CHACHA20_NEON */

/* write nblocks * 64 keystream bytes to out, advance the counter */
static inline void
chacha20_blocks (uint32_t s[16], uint8_t *out, size_t nblocks)
{
#if CHACHA20_NEON
  size_t n4 = nblocks & ~(size_t)3;

  chacha20_blocks_neon4 (s, out, n4);
  out += n4 * CHACHA20_BLOCKBYTES;
  nblocks -= n4;
#endif
  chacha20_blocks_scalar (s, out, nblocks);
}

#endif
