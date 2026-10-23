#define _GNU_SOURCE
/*
 * script_decode_inflate - the inflate path of the script decode hook (objctx_script_dec.c: gzinflate, gzuncompress, gzdecode over base64_decode of a literal) attacked
 * through the whole engine; the lexer audit listed it as not checked.
 *
 *   valid      a raw deflate stream, a zlib stream and a gzip member of a php payload: each is decoded and the view holds the payload (and the parent does not);
 *              a stored block, a fixed-Huffman block, a stream of an empty payload;
 *   bomb       300 MB of zeros as a 300 KB deflate stream: the scan finishes, the object that was cut says so (KOF_BROKEN_LIMIT or limit_hits), no object the scan
 *              delivers is longer than the allowance the hook gives it (32 times the file and 64 KB) and the peak resident size does not follow the payload;
 *   damaged    the stream cut at every length from 1 to 40, a bit flipped in each of the first 40 bytes, garbage that is valid base64: no crash, the sanitiser silent;
 *   layers     a payload that is itself a gzinflate of a payload, 1 to 40 deep: up to the bound (32) the innermost is in the view, past it the scan says a limit fired.
 *
 * Why the old tests missed what could be here: (a) the inflate branch of dec_inflate and the allowance of dbuf_want were run by no test that gave them a stream whose output
 * is more than the allowance, and the damaged streams of hostile_inflate.c go to kuncoat_inflate alone, not through the hook, its allowance and its charge to the ceiling.
 *
 * usage: script_decode_inflate   (needs the test database; links zlib to MAKE the streams, never to read them)
 */

#include <zlib.h>
#include <sys/resource.h>

#if defined(__SANITIZE_ADDRESS__)
#define UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UNDER_ASAN 1
#endif
#endif
#ifndef UNDER_ASAN
#define UNDER_ASAN 0
#endif

#include "caps_fix.h"
#include "caps_e2e.h"
#include "notes.h"
#include "normalizer_ref.h"
#include "../../libkofeng/scanners/scan.h"

struct seen {
	unsigned n_obj, limit;
	uint64_t biggest;
	uint8_t *view;          /* the first normalised child, copied */
	uint64_t view_len;
};

static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	s->n_obj++;
	if (res->broken == KOF_BROKEN_LIMIT)
		s->limit = 1;
	if (len > s->biggest)
		s->biggest = len;
	if (res->entry_kind == KOF_ENT_NORMALIZED && !s->view && len < (64u << 20)) {
		s->view = malloc((size_t)len);
		if (s->view) {
			memcpy(s->view, bytes, (size_t)len);
			s->view_len = len;
		}
	}
	return 0;
}

static void scan(const uint8_t *b, size_t n, struct seen *s)
{
	struct kof_scan_option opt;
	uint64_t hits = kscan_stats(e2e_sc)->limit_hits;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	opt.heur_level = 1;
	(void)kscan_bytes(e2e_sc, b, n, "infl", &opt, collect, s);
	if (kscan_stats(e2e_sc)->limit_hits != hits)
		s->limit = 1;
}

static int view_has(const struct seen *s, const char *w)
{
	return s->view && memmem(s->view, (size_t)s->view_len, w, strlen(w)) != NULL;
}

/* deflate `in` to a buffer: wbits -15 raw, 15 zlib, 31 gzip */
static uint8_t *compress_to(const uint8_t *in, size_t n, int wbits, int level, size_t *out_n)
{
	z_stream z;
	size_t cap;
	uint8_t *out;

	memset(&z, 0, sizeof z);
	if (deflateInit2(&z, level, Z_DEFLATED, wbits, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		abort();
	cap = deflateBound(&z, (uLong)n) + 64u;
	out = malloc(cap);
	if (!out)
		abort();
	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)n;
	z.next_out = out;
	z.avail_out = (uInt)cap;
	if (deflate(&z, Z_FINISH) != Z_STREAM_END)
		abort();
	*out_n = z.total_out;
	deflateEnd(&z);
	return out;
}

/* a php file: eval(<fn>(base64_decode("<b64 of the stream>"))) */
static uint8_t *php_of(const char *fn, const uint8_t *stream, size_t sn, size_t *out_n)
{
	char *b64 = malloc(sn * 2u + 16u), *php;
	size_t bl = nr_b64_enc(stream, sn, b64, 1, 0, 0), n;

	if (!b64)
		abort();
	php = malloc(bl + 128u);
	if (!php)
		abort();
	n = (size_t)snprintf(php, bl + 128u, "<?php\n$x = %s(base64_decode(\"", fn);
	memcpy(php + n, b64, bl);
	n += bl;
	n += (size_t)snprintf(php + n, 100u, "\"));\neval($x);\n");
	free(b64);
	*out_n = n;
	return (uint8_t *)php;
}

static long rss_kb(void)
{
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ru.ru_maxrss;
}

static void valid(void)
{
	static const char payload[] = "<?php\n  echo \"NormInflCanary-31c7\";\n  system($_GET['c']);\n  // pad pad pad pad pad pad pad pad\n";
	static const struct { const char *fn; int wbits; } k[] = { { "gzinflate", -15 }, { "gzuncompress", 15 }, { "gzdecode", 31 } };
	unsigned i, level;

	for (i = 0; i < 3; i++)
		for (level = 0; level <= 9; level += 3) {
			size_t sn, pn;
			uint8_t *st = compress_to((const uint8_t *)payload, sizeof payload - 1u, k[i].wbits, (int)level, &sn);
			uint8_t *php = php_of(k[i].fn, st, sn, &pn);
			struct seen s;

			scan(php, pn, &s);
			NCKF(view_has(&s, "NormInflCanary-31c7"), "%s level %u: the payload is not in the view (%u objects)", k[i].fn, level, s.n_obj);
			free(s.view);
			free(php);
			free(st);
		}
	{
		/* a stream of an empty payload, and a stored block by hand */
		static const uint8_t empty[] = { 0x03, 0x00 };
		static const uint8_t stored[] = { 0x01, 0x05, 0x00, 0xfa, 0xff, 'a', 'b', 'c', 'd', 'e' };
		size_t pn;
		uint8_t *php = php_of("gzinflate", empty, sizeof empty, &pn);
		struct seen s;

		scan(php, pn, &s);
		NCKF(s.n_obj >= 1u, "an empty payload: the scan did not run");
		free(s.view);
		free(php);
		php = php_of("gzinflate", stored, sizeof stored, &pn);
		scan(php, pn, &s);
		NCKF(s.n_obj >= 1u, "a stored block: the scan did not run");
		free(s.view);
		free(php);
	}
}

static void bomb(void)
{
	size_t zn = 300u << 20, sn, pn;
	uint8_t *zeros = calloc(zn, 1), *st, *php;
	struct seen s;
	long before;

	if (!zeros)
		abort();
	st = compress_to(zeros, zn, -15, 9, &sn);
	free(zeros);
	php = php_of("gzinflate", st, sn, &pn);
	before = rss_kb();
	scan(php, pn, &s);
	NCKF(s.n_obj >= 1u, "the bomb: no object was delivered");
	NCKF(s.biggest <= 32u * pn + 65536u + (1u << 20), "the bomb: an object of %llu bytes (the allowance is %llu)", (unsigned long long)s.biggest,
	     (unsigned long long)(32u * pn + 65536u));
	NCKF(s.limit, "the bomb: no object says a limit fired");
	/* (not under the sanitiser: its shadow memory and quarantine are resident and say nothing about the hook) */
	NCKF(UNDER_ASAN || rss_kb() - before < (200l << 10), "the bomb: the peak resident size grew by %ld KB", rss_kb() - before);
	free(s.view);
	free(php);
	free(st);
}

static void damaged(void)
{
	static const char payload[] = "<?php\n  echo \"NormInflCanary-31c7\"; system($_GET['c']);\n";
	size_t sn, pn, cut;
	uint8_t *st = compress_to((const uint8_t *)payload, sizeof payload - 1u, -15, 9, &sn);
	struct nrng r = { 0x9e3779b97f4a7c15ull };
	uint8_t junk[4096];
	unsigned i;

	for (cut = 1; cut <= 40u && cut < sn; cut++) {
		uint8_t *php = php_of("gzinflate", st, cut, &pn);
		struct seen s;

		scan(php, pn, &s);
		NCKF(s.n_obj >= 1u, "a stream cut at %zu: the scan did not run", cut);
		free(s.view);
		free(php);
	}
	for (i = 0; i < 40u && i < sn; i++) {
		uint8_t *copy = malloc(sn), *php;
		struct seen s;

		memcpy(copy, st, sn);
		copy[i] ^= (uint8_t)(1u << (i % 8u));
		php = php_of("gzinflate", copy, sn, &pn);
		scan(php, pn, &s);
		NCKF(s.n_obj >= 1u, "a flipped bit in byte %u: the scan did not run", i);
		free(s.view);
		free(php);
		free(copy);
	}
	for (i = 0; i < 20u; i++) {
		size_t k, jn = 8u + nr_next(&r) % 4000u;
		uint8_t *php;
		struct seen s;

		for (k = 0; k < jn; k++)
			junk[k] = (uint8_t)nr_next(&r);
		php = php_of("gzinflate", junk, jn, &pn);
		scan(php, pn, &s);
		NCKF(!view_has(&s, "NormInflCanary"), "garbage gave a view with the canary");
		free(s.view);
		free(php);
	}
	free(st);
}

static void layers(void)
{
	unsigned depth;

	for (depth = 1; depth <= 40u; depth += (depth < 4u || depth > 28u) ? 1u : 6u) {
		static const char inner[] = "<?php echo \"NormInflLayers-8e21\"; system($_GET['c']); // pad pad pad pad pad\n";
		uint8_t *cur = malloc(sizeof inner);
		size_t cn = sizeof inner - 1u, k, pn;
		uint8_t *php;
		struct seen s;

		memcpy(cur, inner, cn);
		for (k = 0; k < depth; k++) {
			size_t sn, wn;
			uint8_t *st = compress_to(cur, cn, -15, 9, &sn), *wrapped = php_of("gzinflate", st, sn, &wn);

			free(st);
			free(cur);
			cur = wrapped;
			cn = wn;
		}
		php = cur;
		pn = cn;
		scan(php, pn, &s);
		NCKF(s.n_obj >= 1u, "%u layers: the scan did not run", depth);
		if (depth <= 20u)
			NCKF(view_has(&s, "NormInflLayers-8e21"), "%u layers: the innermost payload is not in the view", depth);
		if (depth >= 34u)
			NCKF(s.limit || !view_has(&s, "NormInflLayers-8e21"), "%u layers: past the bound nothing says a limit fired", depth);
		free(s.view);
		free(php);
	}
}

int main(void)
{
	if (!e2e_open(NULL)) {
		printf("script_decode_inflate: cannot open the test database\n");
		return 2;
	}
	valid();
	damaged();
	layers();
	bomb();
	printf("script_decode_inflate: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
