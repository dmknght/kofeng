/*
 * hostile_bcjenc.h - code-like test buffers and the BCJ2 ENCODER (four streams from one), written once and used by
 * api_filters.c (the filters' own test) and tests/fuzz/decomp/bcj.c (the seeds). The includer has hostile_common.h
 * (hv_rng32) and hostile_lzenc.h (the LZMA range encoder the BCJ2 rc stream is made with) in scope first.
 */
#ifndef HOSTILE_BCJENC_H
#define HOSTILE_BCJENC_H

/* code-like bytes: many E8/E9, 00 and FF operands, ordinary bytes */
static inline void code_bytes(uint8_t *p, size_t n, uint64_t *rs, unsigned flavour)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint32_t r = hv_rng32(rs) % 100u;

		p[i] = flavour == 0 ? (uint8_t)hv_rng32(rs) :
		       r < 15 ? 0xE8 : r < 25 ? 0xE9 : r < 45 ? 0x00 : r < 65 ? 0xFF : r < 70 ? 0x0F : (uint8_t)hv_rng32(rs);
	}
}

struct b2 {
	uint8_t main_s[4000], call_s[4000], jump_s[4000], rc_s[2000];
	size_t  nm, nc, nj, nr;
};

static inline int b2_branch(uint8_t prev, uint8_t b)
{
	return b == 0xE8 || b == 0xE9 || (prev == 0x0F && (b & 0xF0) == 0x80);
}

/* The encoder: convert a candidate when `want` says so (the test's policy), writing the four streams. */
static inline int b2_encode(struct b2 *s, const uint8_t *orig, size_t n, uint64_t seed, unsigned convert_pct)
{
	uint16_t prob[258];
	struct hv_lz e;
	uint64_t rs = seed;
	size_t i = 0;
	uint8_t prev = 0;

	memset(&e, 0, sizeof e);
	hv_lz_rc_start(&e, s->rc_s, sizeof s->rc_s);
	for (i = 0; i < 258; i++)
		prob[i] = 1024;
	s->nm = s->nc = s->nj = 0;
	i = 0;
	while (i < n) {
		uint8_t b = orig[i];

		s->main_s[s->nm++] = b;
		i++;
		if (!b2_branch(prev, b)) {
			prev = b;
			continue;
		}
		{
			uint16_t *pr = b == 0xE8 ? &prob[prev] : b == 0xE9 ? &prob[256] : &prob[257];
			int conv = i + 4 <= n && (hv_rng32(&rs) % 100u) < convert_pct;

			hv_lz_bit(&e, pr, conv ? 1u : 0u);
			if (!conv) {
				prev = b;
				continue;
			}
			{
				uint32_t disp = (uint32_t)orig[i] | (uint32_t)orig[i + 1] << 8 | (uint32_t)orig[i + 2] << 16 |
						(uint32_t)orig[i + 3] << 24;
				uint32_t abs_addr = disp + (uint32_t)(i + 4);
				uint8_t *dst = b == 0xE8 ? s->call_s + s->nc : s->jump_s + s->nj;

				dst[0] = (uint8_t)(abs_addr >> 24); dst[1] = (uint8_t)(abs_addr >> 16);
				dst[2] = (uint8_t)(abs_addr >> 8); dst[3] = (uint8_t)abs_addr;
				if (b == 0xE8)
					s->nc += 4;
				else
					s->nj += 4;
			}
			prev = orig[i + 3];
			i += 4;
		}
	}
	s->nr = hv_lz_rc_finish(&e);
	return !e.over && s->nm <= sizeof s->main_s;
}

#endif /* HOSTILE_BCJENC_H */
