#pragma once

#include "ktypes.h"

u32 test_avx(void);

void ex_vpgatherdd(const int *base, const int *idx, int *out);
void ex_vgatherdps(const float *base, const int *idx, float *out);
void ex_vpermd(const int *src, const int *perm, int *out);
void ex_vpermps(const float *src, const int *perm, float *out);
void ex_vpshufb(const unsigned char *src, const unsigned char *ctl, unsigned char *out);
void ex_vpmaskmovd_store(int *dst, const int *src, const int *mask);
void ex_vpmaskmovps_load(const float *src, const int *mask, float *out);
void ex_vblendvps(const float *a, const float *b, const int *mask, float *out);
void ex_vpmulld(const int *a, const int *b, int *out);
void ex_vpmuludq(const unsigned int *a, const unsigned int *b, unsigned long long *out);
void ex_vpmaddubsw(const unsigned char *a, const signed char *b, short *out);
void ex_vpmaddwd(const short *a, const short *b, int *out);
void ex_vfmaddsub231ps(const float *a, const float *b, const float *c, float *out);
void ex_vperm2i128(const int *a, const int *b, int *out);
void ex_vpsllvd(const int *src, const int *counts, int *out);
void ex_vpalignr(const unsigned char *a, const unsigned char *b, unsigned char *out);