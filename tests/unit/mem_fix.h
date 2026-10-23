/*
 * mem_fix.h - fixtures of the memory tests (mem_engine.c, mem_spill.c): an ELF whose view the
 * normaliser makes, one it does not, and a zip with one big entry that the engine has to
 * inflate into its sink (which is what spills). Built in memory; nothing is written to disk.
 * Needs caps_fix.h and caps_e2e.h first.
 */

#ifndef KOFENG_TESTS_MEM_FIX_H
#define KOFENG_TESTS_MEM_FIX_H

#include <stdlib.h>
#include <pthread.h>
#include "../../libkofeng/scanners/scan.h"

static uint32_t mf_crc(const uint8_t *p, uint64_t n)
{
	static uint32_t t[256];
	uint32_t c = 0xffffffffu;
	uint64_t i;

	if (!t[1]) {
		uint32_t k, j;

		for (k = 0; k < 256u; k++) {
			uint32_t v = k;

			for (j = 0; j < 8u; j++)
				v = (v & 1u) ? 0xedb88320u ^ (v >> 1) : v >> 1;
			t[k] = v;
		}
	}
	for (i = 0; i < n; i++)
		c = t[(c ^ p[i]) & 0xffu] ^ (c >> 8);
	return ~c;
}

/* The stager, 8 KB of zeros, a UTF-16 string: the normaliser makes a view of it. */
static __attribute__((unused)) uint64_t mf_view_elf(uint8_t *img, uint64_t cap, uint8_t *code)
{
	static const char *w = "Permission denied Connection refused";
	unsigned n = cf_stager64(code, 0), i;
	uint64_t len = cf_elf64(img, cap, code, n);

	memset(img + len, 0, 8192);
	len += 8192;
	for (i = 0; w[i]; i++) {
		img[len++] = (uint8_t)w[i];
		img[len++] = 0;
	}
	return len;
}

/* The stager and 6 KB that are neither zero runs nor wide text: no view can result. */
static __attribute__((unused)) uint64_t mf_noview_elf(uint8_t *img, uint64_t cap, uint8_t *code)
{
	unsigned n = cf_stager64(code, 0), i;
	uint64_t len = cf_elf64(img, cap, code, n);

	for (i = 0; i < 6000u; i++)
		img[len++] = (uint8_t)(1u + (i * 7u) % 250u);
	return len;
}

/*
 * A zip of one entry of `n` bytes, method 8 (deflate) written as stored deflate blocks, so
 * the engine inflates it and emits n bytes through its sink without this file needing a
 * compressor. The data is a repeating non-zero pattern. Returns the length; `out` must hold
 * n + n / 65535 * 5 + 200 bytes.
 */
static uint64_t mf_zip(uint8_t *out, uint8_t *data, uint64_t n)
{
	uint64_t at = 0, i, cd, csize = 0;
	uint32_t crc;
	static const char nm[] = "big.bin";

	for (i = 0; i < n; i++)
		data[i] = (uint8_t)('a' + (i * 13u + (i >> 9)) % 26u);
	crc = mf_crc(data, n);
	put32(out, 0, 0x04034b50u); put16(out, 4, 20); put16(out, 6, 0); put16(out, 8, 8);
	put16(out, 10, 0); put16(out, 12, 0x21);
	put32(out, 14, crc);
	put16(out, 26, (uint16_t)(sizeof nm - 1u)); put16(out, 28, 0);
	memcpy(out + 30, nm, sizeof nm - 1u);
	at = 30 + sizeof nm - 1u;
	for (i = 0; i < n; ) {
		uint64_t k = n - i > 65535u ? 65535u : n - i;

		out[at++] = (uint8_t)(i + k == n ? 1 : 0);
		put16(out, (unsigned)at, (uint16_t)k); at += 2;
		put16(out, (unsigned)at, (uint16_t)~k); at += 2;
		memcpy(out + at, data + i, (size_t)k);
		at += k; i += k;
		csize += k + 5u;
	}
	put32(out, 18, (uint32_t)csize);
	put32(out, 22, (uint32_t)n);
	cd = at;
	put32(out, (unsigned)at, 0x02014b50u); put16(out, (unsigned)at + 4, 20); put16(out, (unsigned)at + 6, 20);
	put16(out, (unsigned)at + 10, 8); put16(out, (unsigned)at + 14, 0x21);
	put32(out, (unsigned)at + 16, crc);
	put32(out, (unsigned)at + 20, (uint32_t)csize); put32(out, (unsigned)at + 24, (uint32_t)n);
	put16(out, (unsigned)at + 28, (uint16_t)(sizeof nm - 1u));
	memcpy(out + at + 46, nm, sizeof nm - 1u);
	at += 46 + sizeof nm - 1u;
	put32(out, (unsigned)at, 0x06054b50u); put16(out, (unsigned)at + 8, 1); put16(out, (unsigned)at + 10, 1);
	put32(out, (unsigned)at + 12, (uint32_t)(at - cd)); put32(out, (unsigned)at + 16, (uint32_t)cd);
	return at + 22;
}

/* What a scan said about every object it opened, flattened to one comparable record. */
struct mf_sig {
	unsigned n_obj;
	uint64_t h;             /* names, findings, verdicts, broken, incomplete */
	unsigned incomplete;    /* objects the verdict path called incomplete or broken */
};

static void mf_sig_of(const struct e2e *r, struct mf_sig *s)
{
	unsigned i, j;
	uint64_t h = 1469598103934665603ull;

	memset(s, 0, sizeof *s);
	s->n_obj = r->n;
	for (i = 0; i < r->n; i++) {
		const struct e2e_obj *o = &r->o[i];
		const char *t[2 + E2E_MAX_FIND];
		unsigned nt = 0;

		t[nt++] = o->name;
		t[nt++] = o->verdict;
		for (j = 0; j < o->n && j < E2E_MAX_FIND; j++)
			t[nt++] = o->find[j];
		for (j = 0; j < nt; j++) {
			const char *p = t[j];

			while (*p)
				h = (h ^ (uint8_t)*p++) * 1099511628211ull;
			h = (h ^ 0xffu) * 1099511628211ull;
		}
		h = (h ^ o->n) * 1099511628211ull;
		if (o->broken || o->vf_incomplete)
			s->incomplete++;
		h = (h ^ o->entry_kind) * 1099511628211ull;
	}
	s->h = h;
}

#endif
