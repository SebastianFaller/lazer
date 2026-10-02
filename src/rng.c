#include "rng.h"
#include "aes256ctr.h"
#include "chacha20.h"
#include "lazer.h"
#include "shake128.h"

#include <string.h>

void
rng_init (rng_state_t state, const uint8_t seed[32], uint64_t dom)
{
  _rng_init (state, seed, dom);
}

void
rng_urandom (rng_state_t state, uint8_t *out, size_t outlen)
{
  _rng_urandom (state, out, outlen);
}

void
rng_clear (rng_state_t state)
{
  _rng_clear (state);
}

/*
 * RNG_CHACHA20: ChaCha20 (RFC 8439 block function, 20 rounds) with
 * key = seed (32 bytes), 64-bit nonce = dom (state words 14, 15, i.e. the
 * little-endian encoding of dom), 64-bit block counter starting at 0
 * (state words 12, 13). Equivalently: RFC 8439 ChaCha20 with
 * nonce = 00000000 || le64(dom) and initial counter 0 (for the first
 * 2^32 blocks). Distinct (seed, dom) pairs give independent streams,
 * exactly like the AES-256-CTR variant (nonce {dom, 0}).
 * Output is produced in units of 4 blocks (256 bytes); leftovers are
 * cached, so the stream does not depend on how the requests are split.
 */
#if RNG == RNG_CHACHA20
static void
_chacha20rng_stream (chacha20_state_t state, uint8_t *out, size_t outlen)
{
  size_t len;

  len = MIN (outlen, state->nbytes);
  memcpy (out, state->cache_ptr, len);

  state->cache_ptr += len;
  state->nbytes -= len;

  out += len;
  outlen -= len;

  len = outlen / sizeof (state->cache);
  if (len > 0)
    {
      chacha20_blocks (state->input, out, 4 * len);
      out += len * sizeof (state->cache);
      outlen -= len * sizeof (state->cache);
    }
  if (outlen > 0)
    {
      chacha20_blocks (state->input, state->cache, 4);

      memcpy (out, state->cache, outlen);

      state->cache_ptr = state->cache + outlen;
      state->nbytes = sizeof (state->cache) - outlen;
    }
}
#endif

static void
_rng_init (rng_state_t state, const uint8_t seed[32], uint64_t dom)
{
  dom = htole64 (dom);

#if RNG == RNG_SHAKE128
  _shake128_init (state->state);
  _shake128_absorb (state->state, seed, 32);
  _shake128_absorb (state->state, (uint8_t *)&dom, sizeof (dom));
#elif RNG == RNG_AES256CTR
  {
    uint64_t nonce[2] = { dom, 0 };

    _aes256ctr_init (state->state, seed, (uint8_t *)&nonce);
  }
#elif RNG == RNG_CHACHA20
  chacha20_init (state->state->input, seed, le64toh (dom));
  state->state->cache_ptr = NULL;
  state->state->nbytes = 0;
#endif
}

static void
_rng_urandom (rng_state_t state, uint8_t *out, size_t outlen)
{
  ASSERT_ERR (outlen > 0);

#if RNG == RNG_SHAKE128
  _shake128_squeeze (state->state, out, outlen);
#elif RNG == RNG_AES256CTR
  _aes256ctr_stream (state->state, out, outlen);
#elif RNG == RNG_CHACHA20
  _chacha20rng_stream (state->state, out, outlen);
#endif
}

static void
_rng_clear (rng_state_t state)
{
#if RNG == RNG_SHAKE128
  _shake128_clear (state->state);
#elif RNG == RNG_AES256CTR
  _aes256ctr_clear (state->state);
#elif RNG == RNG_CHACHA20
  explicit_bzero (state->state, sizeof (chacha20_state_struct));
#endif
}
