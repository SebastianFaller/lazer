#include "test.h"

#if RNG == RNG_SHAKE128
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

#elif RNG == RNG_CHACHA20
/*
 * rng(seed, dom) is RFC 8439 ChaCha20 with key = seed,
 * nonce = 00000000 || le64(dom), counter starting at 0.
 * RFC 8439 2.4.2: key 00..1f, nonce 000000000000004a00000000, counter 1,
 * so dom = 0x4a000000 and the RFC keystream starts at byte 64.
 */
const char seedstr[]
    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const char ptstr[]
    = "Ladies and Gentlemen of the class of '99: If I could offer you only "
      "one tip for the future, sunscreen would be it.";
const char ctstr[]
    = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
      "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
      "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
      "5af90bbf74a35be6b40b8eedf2785e42874d";

int
main (void)
{
  uint8_t seed[32], out[64 + 114], ct[114];
  rng_state_t state;
  size_t len, i;

  lazer_init ();

  test_hexstr2buf (seed, &len, seedstr);
  TEST_ASSERT (len == 32);
  test_hexstr2buf (ct, &len, ctstr);
  TEST_ASSERT (len == 114);

  rng_init (state, seed, 0x4a000000ULL);
  rng_urandom (state, out, 10);
  rng_urandom (state, out + 10, 60);
  rng_urandom (state, out + 70, sizeof (out) - 70);
  rng_clear (state);

  for (i = 0; i < 114; i++)
    out[64 + i] ^= (uint8_t)ptstr[i];
  TEST_EXPECT (memcmp (out + 64, ct, 114) == 0);

  /* odd-sized chunks across cache/batch boundaries == one-shot stream */
  {
    uint8_t seed2[32], buf[4096 + 16], ref[4096 + 16];
    size_t off = 0, n = 1, k;

    for (i = 0; i < 32; i++)
      seed2[i] = (uint8_t)(i * 7 + 3);

    rng_init (state, seed2, 0x0123456789abcdefULL);
    rng_urandom (state, ref, sizeof (ref));
    rng_clear (state);

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
    TEST_EXPECT (memcmp (buf, ref, sizeof (buf)) == 0);

    /* different dom gives a different stream */
    rng_init (state, seed2, 0x0123456789abcdeeULL);
    rng_urandom (state, buf, sizeof (buf));
    rng_clear (state);
    TEST_EXPECT (memcmp (buf, ref, sizeof (buf)) != 0);
  }

  TEST_PASS ();
}

#else
#error "Invalid rng option."
#endif
