/*
 * norm_pe_fx.h - the PE the normaliser's engine tests are made of: N code sections with a gap between
 * their file extents, each holding a zero run, a UTF-16LE string and a zero run, and a data section with
 * a wide string. Writable code is the shape of a packed image (its wide strings are narrowed in the view);
 * read-only code is kept verbatim. Shared by norm_defect_engine.c (N3) and silent_oom_sweep.c, which
 * refuses every allocation of a scan that makes such a view.
 */
#ifndef KOFENG_TESTS_NORM_PE_FX_H
#define KOFENG_TESTS_NORM_PE_FX_H

#include <stdint.h>
#include <string.h>

/* ---- a PE32 with N code sections, a gap between their file extents, and a data section --------- */

#define PE_MAX (0x1000u + 48u * 0x200u)

static inline void pw16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void pw32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

/* the body of one code section: 64 nops, 64 zeros, a UTF-16LE string, 64 zeros (224 bytes) */
#define SEC_LEN 224u
#define WIDE_TXT "ABCDEFGHIJKLMNOP"

static inline void sec_body(uint8_t *b)
{
	unsigned i;

	memset(b, 0, SEC_LEN);
	memset(b, 0x90, 64);
	for (i = 0; i < 16u; i++)
		b[128u + 2u * i] = (uint8_t)WIDE_TXT[i];
}

static inline uint32_t build_pe(uint8_t *out, unsigned ncode, uint32_t chars)
{
	const uint32_t hdr = 0x1000, opt = 0x80 + 24u, optsz = 0xe0, st = opt + optsz;
	const char *dw = "http://wide.example/payload.bin";
	uint32_t rp = hdr, i, k, data_rp, datalen;
	uint8_t *dp;

	memset(out, 0, PE_MAX);
	out[0] = 'M'; out[1] = 'Z';
	pw32(out + 0x3c, 0x80);
	memcpy(out + 0x80, "PE\0\0", 4);
	pw16(out + 0x84, 0x14c);
	pw16(out + 0x86, (uint16_t)(ncode + 1u));
	pw16(out + 0x94, (uint16_t)optsz);
	pw16(out + 0x96, 0x102);
	pw16(out + opt, 0x10b);
	pw32(out + opt + 16, 0x1000);
	pw32(out + opt + 28, 0x400000u);
	pw32(out + opt + 32, 0x1000);
	pw32(out + opt + 36, 0x200);
	pw32(out + opt + 56, 0x200000u);
	pw32(out + opt + 60, hdr);
	pw32(out + opt + 92, 16);
	for (i = 0; i < ncode; i++) {
		uint8_t *s = out + st + 40u * i;

		s[0] = '.'; s[1] = 't'; s[2] = (uint8_t)('0' + (i / 10u) % 10u); s[3] = (uint8_t)('0' + i % 10u);
		pw32(s + 8, SEC_LEN);
		pw32(s + 12, 0x1000u + i * 0x1000u);
		pw32(s + 16, SEC_LEN);
		pw32(s + 20, rp);
		pw32(s + 36, chars);
		sec_body(out + rp);
		rp += SEC_LEN + 0x100u;
	}
	/* the data section: zeros, a wide string, zeros */
	data_rp = rp;
	dp = out + data_rp + 64u;
	for (k = 0; dw[k]; k++)
		dp[2u * k] = (uint8_t)dw[k];
	datalen = 64u + 2u * k + 200u;
	{
		uint8_t *s = out + st + 40u * ncode;

		memcpy(s, ".data", 5);
		pw32(s + 8, datalen);
		pw32(s + 12, 0x100000u);
		pw32(s + 16, datalen);
		pw32(s + 20, data_rp);
		pw32(s + 36, 0xc0000040u);
	}
	return data_rp + datalen;
}

#endif
