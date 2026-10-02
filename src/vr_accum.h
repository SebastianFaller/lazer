#ifndef VR_ACCUM_H
#define VR_ACCUM_H
/*
 * acc[j * lambda + k] = sum_{i < ni} S[k * ni + i] * R_i[j]
 * for R_i in {-1,0,1}^ncols expanded row by row by expand (Ri, ncols, i, seed).
 *
 * Exact replacement of the __int128 accumulation loop in
 * ___schwartz_zippel_accumulate_z3/z4: the caller must guarantee
 * ni * max|S| < 2^63, so the int64 sums never overflow and equal the
 * __int128 sums. No data-dependent branches (zeros are added, not skipped),
 * rows are processed in chunks of VR_ICH so the accumulators of one column
 * stay in registers across VR_ICH rows.
 *
 * Rbuf must hold VR_ICH * ncols bytes.
 */
#include <stdint.h>
#include <string.h>

#define VR_ICH 16

typedef void (*_vr_expand_fn) (int8_t *Ri, unsigned int ncols, unsigned int i,
                               const uint8_t seed[32]);

static void
_vr_accum (int64_t *acc, const int64_t *S, unsigned int ni,
           unsigned int lambda, unsigned int ncols, int8_t *Rbuf,
           _vr_expand_fn expand, const uint8_t seed[32])
{
  unsigned int i0, ii, j, k, nch;

  memset (acc, 0, sizeof (int64_t) * lambda * ncols);

  for (i0 = 0; i0 < ni; i0 += nch)
    {
      nch = ni - i0 < VR_ICH ? ni - i0 : VR_ICH;

      for (ii = 0; ii < nch; ii++)
        expand (Rbuf + (size_t)ii * ncols, ncols, i0 + ii, seed);

      if (lambda == 4)
        {
          int64_t s[VR_ICH][4];

          for (ii = 0; ii < nch; ii++)
            for (k = 0; k < 4; k++)
              s[ii][k] = S[k * ni + i0 + ii];

          for (j = 0; j < ncols; j++)
            {
              int64_t a0 = acc[4 * j + 0], a1 = acc[4 * j + 1];
              int64_t a2 = acc[4 * j + 2], a3 = acc[4 * j + 3];
              const int8_t *r = Rbuf + j;

              for (ii = 0; ii < nch; ii++)
                {
                  const int64_t rj = r[(size_t)ii * ncols];
                  a0 += s[ii][0] * rj;
                  a1 += s[ii][1] * rj;
                  a2 += s[ii][2] * rj;
                  a3 += s[ii][3] * rj;
                }
              acc[4 * j + 0] = a0;
              acc[4 * j + 1] = a1;
              acc[4 * j + 2] = a2;
              acc[4 * j + 3] = a3;
            }
        }
      else
        {
          for (j = 0; j < ncols; j++)
            {
              const int8_t *r = Rbuf + j;

              for (k = 0; k < lambda; k++)
                {
                  const int64_t *sk = S + (size_t)k * ni + i0;
                  int64_t a = acc[(size_t)j * lambda + k];

                  for (ii = 0; ii < nch; ii++)
                    a += sk[ii] * (int64_t)r[(size_t)ii * ncols];
                  acc[(size_t)j * lambda + k] = a;
                }
            }
        }
    }
}

#endif
