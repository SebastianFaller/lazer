#include "aes256ctr.h"
#include "lazer.h"

#include <stdlib.h>
#include <string.h>

#if RNG == RNG_AES256CTR
#if TARGET == TARGET_GENERIC

/*
 * Portable constant-time AES-256-CTR (bitsliced, 4 blocks in parallel),
 * based on BearSSL's aes_ct64, see aes-ct64.h.
 */

#include "aes-ct64.h"

static inline void
incbe (uint8_t n[16])
{
  unsigned int c = 1;
  int i;

  for (i = 15; i >= 0; i--)
    {
      c += n[i];
      n[i] = c & 0xff;
      c >>= 8;
    }
}

/* AES-256 key expansion into 60 little-endian 32-bit words (constant-time) */
static void
_aes256_expand_words (uint32_t skey[60], const uint8_t key[32])
{
  static const uint8_t rcon[]
      = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
  const int nk = 8, nkf = 60;
  uint32_t tmp;
  int i, j, k;

  for (i = 0; i < nk; i++)
    skey[i] = _aes_dec32le (key + 4 * i);
  tmp = skey[nk - 1];
  for (i = nk, j = 0, k = 0; i < nkf; i++)
    {
      if (j == 0)
        {
          tmp = (tmp << 24) | (tmp >> 8);
          tmp = _aes_ct64_sub_word (tmp) ^ rcon[k];
        }
      else if (j == 4)
        {
          tmp = _aes_ct64_sub_word (tmp);
        }
      tmp ^= skey[i - nk];
      skey[i] = tmp;
      if (++j == nk)
        {
          j = 0;
          k++;
        }
    }
}

#ifdef LAZER_AES_NEONBS

/*
 * NEON bitsliced AES-256-CTR (8 blocks in parallel), see aes-neonbs.h.
 * Same output as the portable/AES-NI code below/in aes256ctr-amd64.c.
 */

#include "aes-neonbs.h"

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                 const uint8_t nonce[16])
{
  uint32_t skey[60];
  uint8_t rk[15 * 16];
  int i;

  state->cache_ptr = NULL;
  state->nbytes = 0;
  memcpy (state->nonce, nonce, 16);

  _aes256_expand_words (skey, key);
  for (i = 0; i < 60; i++)
    _aes_enc32le (rk + 4 * i, skey[i]);
  _aes_nbs_expand_rks (state->sk_nbs, rk, 14);
  explicit_bzero (skey, sizeof (skey));
  explicit_bzero (rk, sizeof (rk));
}

static inline uint64_t
_aes_load64be (const uint8_t *b)
{
  uint64_t x = 0;
  int i;

  for (i = 0; i < 8; i++)
    x = (x << 8) | b[i];
  return x;
}

static inline void
_aes_store64be (uint8_t *b, uint64_t x)
{
  int i;

  for (i = 7; i >= 0; i--)
    {
      b[i] = (uint8_t)x;
      x >>= 8;
    }
}

/*
 * encrypt the next 8 counter blocks into out[128], advance the counter
 * (128-bit big-endian, as incbe())
 */
static inline void
_aes256ctr_8blocks (aes256ctr_state_t state, uint8_t out[128])
{
  uint64_t hi = _aes_load64be (state->nonce);
  uint64_t lo = _aes_load64be (state->nonce + 8);
  unsigned int i;

  if ((lo & 7) == 0)
    {
      /* blocks differ only in the 3 low counter bits (public data) */
      _aes_nbs_ctr8 (out, state->nonce, 15, state->sk_nbs, 14);
    }
  else
    {
      uint8_t ctr[128];

      for (i = 0; i < 8; i++)
        {
          uint64_t l = lo + i, h = hi + (l < lo);

          _aes_store64be (ctr + 16 * i, h);
          _aes_store64be (ctr + 16 * i + 8, l);
        }
      _aes_nbs_encrypt8 (out, ctr, state->sk_nbs, 14);
    }
  hi += (lo + 8 < lo);
  lo += 8;
  _aes_store64be (state->nonce, hi);
  _aes_store64be (state->nonce + 8, lo);
}

static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  size_t len;

  len = MIN (outlen, state->nbytes);
  memcpy (out, state->cache_ptr, len);

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

  while (outlen >= 128)
    {
      _aes256ctr_8blocks (state, out);

      out += 128;
      outlen -= 128;
    }
  if (outlen > 0)
    {
      _aes256ctr_8blocks (state, state->cache);

      memcpy (out, state->cache, outlen);

      state->cache_ptr = state->cache + outlen;
      state->nbytes = 128 - outlen;
    }
}

#else /* !LAZER_AES_NEONBS */

/* AES-256 key schedule, output in expanded bitsliced form (120 words) */
static void
_aes_ct64_keysched256 (uint64_t sk_exp[120], const uint8_t key[32])
{
  const int nkf = 60;
  uint32_t skey[60];
  uint64_t comp_skey[30];
  int i, j;

  _aes256_expand_words (skey, key);

  for (i = 0, j = 0; i < nkf; i += 4, j += 2)
    {
      uint64_t q[8];

      _aes_ct64_interleave_in (&q[0], &q[4], skey + i);
      q[1] = q[0];
      q[2] = q[0];
      q[3] = q[0];
      q[5] = q[4];
      q[6] = q[4];
      q[7] = q[4];
      _aes_ct64_ortho (q);
      comp_skey[j + 0] = (q[0] & (uint64_t)0x1111111111111111)
                         | (q[1] & (uint64_t)0x2222222222222222)
                         | (q[2] & (uint64_t)0x4444444444444444)
                         | (q[3] & (uint64_t)0x8888888888888888);
      comp_skey[j + 1] = (q[4] & (uint64_t)0x1111111111111111)
                         | (q[5] & (uint64_t)0x2222222222222222)
                         | (q[6] & (uint64_t)0x4444444444444444)
                         | (q[7] & (uint64_t)0x8888888888888888);
    }

  for (i = 0, j = 0; i < 30; i++, j += 4)
    {
      uint64_t x0, x1, x2, x3;

      x0 = x1 = x2 = x3 = comp_skey[i];
      x0 &= (uint64_t)0x1111111111111111;
      x1 &= (uint64_t)0x2222222222222222;
      x2 &= (uint64_t)0x4444444444444444;
      x3 &= (uint64_t)0x8888888888888888;
      x1 >>= 1;
      x2 >>= 2;
      x3 >>= 3;
      sk_exp[j + 0] = (x0 << 4) - x0;
      sk_exp[j + 1] = (x1 << 4) - x1;
      sk_exp[j + 2] = (x2 << 4) - x2;
      sk_exp[j + 3] = (x3 << 4) - x3;
    }

  explicit_bzero (skey, sizeof (skey));
  explicit_bzero (comp_skey, sizeof (comp_skey));
}

/* encrypt the next 4 counter blocks into out[64], advance the counter */
static void
_aes256ctr_4blocks (aes256ctr_state_t state, uint8_t out[64])
{
  const uint64_t *sk = state->sk_exp;
  uint32_t w[16];
  uint64_t q[8];
  unsigned int i;

  for (i = 0; i < 4; i++)
    {
      w[4 * i + 0] = _aes_dec32le (state->nonce + 0);
      w[4 * i + 1] = _aes_dec32le (state->nonce + 4);
      w[4 * i + 2] = _aes_dec32le (state->nonce + 8);
      w[4 * i + 3] = _aes_dec32le (state->nonce + 12);
      incbe (state->nonce);
    }
  for (i = 0; i < 4; i++)
    _aes_ct64_interleave_in (&q[i], &q[i + 4], w + (i << 2));
  _aes_ct64_ortho (q);

  _aes_ct64_add_round_key (q, sk);
  for (i = 1; i < 14; i++)
    {
      _aes_ct64_bitslice_sbox (q);
      _aes_ct64_shift_rows (q);
      _aes_ct64_mix_columns (q);
      _aes_ct64_add_round_key (q, sk + (i << 3));
    }
  _aes_ct64_bitslice_sbox (q);
  _aes_ct64_shift_rows (q);
  _aes_ct64_add_round_key (q, sk + (14 << 3));

  _aes_ct64_ortho (q);
  for (i = 0; i < 4; i++)
    _aes_ct64_interleave_out (w + (i << 2), q[i], q[i + 4]);
  for (i = 0; i < 16; i++)
    _aes_enc32le (out + 4 * i, w[i]);
}

static void
_aes256ctr_init (aes256ctr_state_t state, const uint8_t key[32],
                 const uint8_t nonce[16])
{
  state->cache_ptr = NULL;
  state->nbytes = 0;
  memcpy (state->nonce, nonce, 16);
  _aes_ct64_keysched256 (state->sk_exp, key);
}

static void
_aes256ctr_stream (aes256ctr_state_t state, uint8_t *out, size_t outlen)
{
  size_t len;

  len = MIN (outlen, state->nbytes);
  memcpy (out, state->cache_ptr, len);

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

  while (outlen >= 64)
    {
      _aes256ctr_4blocks (state, out);

      out += 64;
      outlen -= 64;
    }
  if (outlen > 0)
    {
      _aes256ctr_4blocks (state, state->cache);

      memcpy (out, state->cache, outlen);

      state->cache_ptr = state->cache + outlen;
      state->nbytes = 64 - outlen;
    }
}

#endif /* LAZER_AES_NEONBS */

#endif

static void
_aes256ctr_clear (aes256ctr_state_t state)
{
  explicit_bzero (state, sizeof (aes256ctr_state_struct));
}

#endif
