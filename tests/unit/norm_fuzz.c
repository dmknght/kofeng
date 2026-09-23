/*
 * Adversarial input against every byte-level pass added this session.
 * Run under ASAN: what it is looking for is a read or a write outside a
 * buffer, not a wrong answer.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../libkofeng/analyzer/normalize/executables.h"

static unsigned s = 0x12345678u;
static unsigned rnd(void){ s = s*1103515245u + 12345u; return s>>8; }

int main(void)
{
	enum { N = 4096 };
	uint8_t *in = malloc(N), *tmp = malloc(N), *out = malloc(N);
	uint8_t *keep = malloc((N + 7) / 8);
	uint64_t mark[64], mark_out[64], src[64], dst[64];
	int it;

	for (it = 0; it < 20000; it++) {
		uint64_t n = 1 + rnd() % N;
		uint32_t k, mode = rnd() % 6u;
		uint64_t i;

		for (i = 0; i < n; i++) {
			switch (mode) {
			case 0: in[i] = (uint8_t)rnd(); break;
			case 1: in[i] = (uint8_t)("0123456789ABCDEF"[rnd()%16]); break;
			case 2: in[i] = (uint8_t)(rnd()%2 ? 0 : 'A'); break;
			case 3: in[i] = (uint8_t)(rnd()%4 ? 0 : (uint8_t)rnd()); break;
			case 4: in[i] = (uint8_t)("base64 -d|= \"'()\n"[rnd()%16]); break;
			default: in[i] = (uint8_t)(rnd()%2 ? (uint8_t)rnd() : 0); break;
			}
		}
		/* keep: random protected spans, including the degenerate ones */
		memset(keep, rnd()%3 ? 0 : 0xff, (size_t)((n + 7) / 8));
		for (k = 0; k < 8u; k++) {
			uint64_t a = rnd() % n, b = a + rnd() % 64u;
			for (i = a; i < b && i < n; i++)
				keep[i >> 3] |= (uint8_t)(1u << (i & 7u));
		}
		memcpy(tmp, in, (size_t)n);
		kof_exe_decode(tmp, n);
		kof_exe_unb64(tmp, n);
		kof_exe_unhex(tmp, n);

		for (k = 0; k < 64u; k++) {
			mark[k] = rnd() % (n + 2u);
			src[k]  = rnd() % (n + 2u);
		}
		/* mark must be ascending, as the contract says */
		for (k = 1; k < 64u; k++) {
			if (mark[k] < mark[k-1]) mark[k] = mark[k-1];
			if (src[k]  < src[k-1])  src[k]  = src[k-1];
		}
		kof_exe_norm_masked(tmp, n, rnd()%2 ? keep : NULL,
				    KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
				    out, n, mark, mark_out, 64u, NULL);
		kof_exe_norm_map(tmp, n, KOF_EXE_NORM_NULLRUN, src, dst, 64u);
		kof_exe_unwide(in, n, out);
		kof_exe_norm(tmp, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE,
			     out, n, NULL, 0, NULL);
	}
	printf("norm fuzz: %d iterations over every byte pass, no fault\n", it);
	free(in); free(tmp); free(out); free(keep);
	return 0;
}
