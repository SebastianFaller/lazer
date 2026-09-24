#include "test.h"

#if RNG == RNG_SHAKE128RNG
const char seedstr[]
    = "22c1fd7342356b0a1a0ef75e7346c2df8a76148407f7f1132e47ed9d59ae4147";
const char domstr[] = "a6211d51ed664050";
const char streamstr[] = "f99123f410a594dda2238d0007ec8d01";

int
main (void)
{
  uint8_t seed[32], out[16], stream[16];
  uint64_t dom = 0;
  rng_state_t state;
  size_t len;

  lazer_init();

  test_hexstr2buf (seed, &len, seedstr);
  TEST_ASSERT (len == 32);

  test_hexstr2buf ((uint8_t *)&dom, &len, domstr);
  TEST_ASSERT (len == 8);
  dom = le64toh (dom);

  test_hexstr2buf (stream, &len, streamstr);
  TEST_ASSERT (len == 16);

  rng_init (state, seed, dom);

  rng_urandom (state, out, 3);
  rng_urandom (state, out + 3, 10);
  rng_urandom (state, out + 3 + 10, 16 - 3 - 10);
  TEST_EXPECT (memcmp (out, stream, 16) == 0);

  rng_clear (state);
  TEST_PASS ();
}

#elif RNG == RNG_AES256CTR
const char seedstr[]
    = "FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D";
const char domstr[] = "001CC5B751A51D70";
const char streamstr[] = "913cd4d68a9feed715e3bd37489e266f8a3c490cefe47e14bbde"
                         "6ade9317f9619c99e38a";
/* 4096+16 byte stream from seed2/dom2 (see below): bytes 4080..4111 and
 * shake128 digest of the whole stream */
const char streamstr2_tail[] = "ee277be85974263757e7107eefdbb8ab"
                               "a35c5e1b07cccbd9cb2988a063dee80c";
const char streamstr2_shake[] = "2ffcd03e4d0fdaccbf73ce69e8b90972"
                                "5dda55d4a36968102efcb90f888c1eef";

int
main (void)
{
  uint8_t seed[32], out[36], stream[36];
  uint64_t dom = 0;
  rng_state_t state;
  size_t len;

  lazer_init();

  test_hexstr2buf (seed, &len, seedstr);
  TEST_ASSERT (len == 32);

  test_hexstr2buf ((uint8_t *)&dom, &len, domstr);
  TEST_ASSERT (len == 8);
  dom = le64toh (dom);

  test_hexstr2buf (stream, &len, streamstr);
  TEST_ASSERT (len == 36);

  rng_init (state, seed, dom);

  rng_urandom (state, out, 10);
  rng_urandom (state, out + 10, 10);
  rng_urandom (state, out + 20, 10);
  rng_urandom (state, out + 30, 6);

  TEST_EXPECT (memcmp (out, stream, sizeof (stream)) == 0);

  rng_clear (state);

  /* longer stream in odd-sized chunks: checks that the generic and the
   * amd64 (AES-NI) implementations produce identical output across
   * block and batch boundaries. */
  {
    uint8_t seed2[32], buf[4096 + 16], tail[32], h[32], hexp[32];
    shake128_state_t hstate;
    size_t off = 0, n = 1, k;
    int i;

    for (i = 0; i < 32; i++)
      seed2[i] = (uint8_t)(i * 7 + 3);

    test_hexstr2buf (tail, &len, streamstr2_tail);
    TEST_ASSERT (len == 32);
    test_hexstr2buf (hexp, &len, streamstr2_shake);
    TEST_ASSERT (len == 32);

    rng_init (state, seed2, 0x0123456789abcdefULL);
    while (off < sizeof (buf))
      {
        k = n;
        if (k > sizeof (buf) - off)
          k = sizeof (buf) - off;
        rng_urandom (state, buf + off, k);
        off += k;
        n = (n * 5 + 3) % 301 + 1;
      }
    rng_clear (state);

    TEST_EXPECT (memcmp (buf + 4096 - 16, tail, 32) == 0);

    shake128_init (hstate);
    shake128_absorb (hstate, buf, sizeof (buf));
    shake128_squeeze (hstate, h, 32);
    shake128_clear (hstate);
    TEST_EXPECT (memcmp (h, hexp, 32) == 0);
  }

  TEST_PASS ();
}

#else
#error "Invalid rng option."
#endif
