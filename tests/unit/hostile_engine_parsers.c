/*
 * hostile_engine_parsers.c - every parser in kof_parser_list, fed valid objects
 * that are cut, flipped and replaced by noise, from memory that faults on any
 * read outside it.
 *
 * What the other parser fuzzers here do not: hostile_fields changes one FIELD to
 * a value that breaks arithmetic, corpus_fuzz mutates files of the corpus with a
 * heap buffer behind them. This one gives each parser an input whose last byte is
 * the last byte before an inaccessible page (and, in a second pass, whose first
 * byte is the first after one), so a read of one byte too many - or too few - is a
 * SIGSEGV in the plain build, not something only a sanitiser sees.
 *
 *   TRUNCATION   every length of a small seed, and a dense-then-geometric set of
 *                lengths of the large ones (an ELF and a PE here are a megabyte).
 *                A length check that is off by one fails at exactly one length.
 *   FLIPS        every bit of the first bytes of the seed, which is where each
 *                format keeps the fields everything else is sized from.
 *   NOISE        constant fills of every small length, and the seed's magic
 *                followed by random bytes - the shapes a fuzzer's first minute
 *                produces and the sniffers must refuse or the parsers survive.
 *
 * Each seed runs in a forked child with an alarm: a parser that loops is a hang
 * reported by name, a parser that faults is a signal reported by name. After a
 * parse that says yes, every region the format declares is resolved and each
 * range must lie inside the object.
 */

#include "hostile_engine.h"
#include "hostile_engine_seeds.h"
#include "known_miss.h"

#include <time.h>

#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include <kofmod/kofsig.h>

/* ---- one parse ------------------------------------------------------------------- */

static const struct kof_parser *parser_of(uint8_t fmt)
{
	uint32_t n, i;
	const struct kof_parser *p = kof_parser_list(&n);

	for (i = 0; i < n; i++)
		if (p[i].format == fmt)
			return &p[i];
	return NULL;
}

static unsigned bad_regions;

/* After a successful parse: every region range lies inside the object. */
static void check_regions(const struct kof_parser *pr, const struct kof_obj_ctx *ctx,
			  uint64_t size, const char *what)
{
	uint32_t i, k, n;
	struct kof_range out[96];

	if (!ctx->resolve_scan)
		return;
	for (i = 0; i < pr->n_regions; i++) {
		n = ctx->resolve_scan(ctx, pr->regions[i], out, 96u);
		if (n > 96u) {
			bad_regions++;
			printf("  BAD %s: region %u answered %u ranges into a room of 96\n", what, i, n);
			continue;
		}
		for (k = 0; k < n; k++)
			if (out[k].off > size || out[k].len > size - out[k].off) {
				bad_regions++;
				printf("  BAD %s: region %u range %u [%llu+%llu] outside %llu\n", what, i, k,
				       (unsigned long long)out[k].off, (unsigned long long)out[k].len,
				       (unsigned long long)size);
			}
	}
}

/* A view that owns tables (zip, pdf: struct kof_view_ops) gives them back before it is freed. */
static void release_view(const struct kof_parser *pr, void *view)
{
	const struct kof_view_ops *o = kof_view_ops_of(pr->format);

	if (o && view)
		o->release(view);
}

struct work {
	const struct kof_parser *pr;
	void *view;
	uint64_t parsed, accepted;
};

static void one(struct work *w, const uint8_t *p, size_t n, const char *what)
{
	struct kof_obj_ctx ctx;
	kof_buf b = kof_buf_make(p, n);

	memset(&ctx, 0, sizeof ctx);
	(void)w->pr->sniff(b);
	w->parsed++;
	if (w->pr->parse(b, w->view, &ctx)) {
		w->accepted++;
		check_regions(w->pr, &ctx, n, what);
	}
}

/* Parse a guard-page copy of src[0..n), at the end of a page and then at the start of one. */
static void one_guarded(struct work *w, const uint8_t *src, size_t n, const char *what)
{
	struct he_guard g;
	int front;

	for (front = 0; front < 2; front++) {
		if (!he_guard_make2(&g, src, n, front))
			return;
		one(w, g.p, n, what);
		he_guard_free(&g);
	}
}

/* ---- the three sweeps --------------------------------------------------------------- */

static void sweep_trunc(struct work *w, const struct seed *s)
{
	size_t n, step;

	/* A small seed: every length. A large one: every length up to 600, then a
	 * geometric walk with each point's neighbours - the last bytes of a
	 * structure are where a bounds check is wrong. */
	if (s->n <= 4096u) {
		for (n = 0; n <= s->n; n++)
			one_guarded(w, s->p, n, s->name);
		return;
	}
	for (n = 0; n <= 600u; n++)
		one_guarded(w, s->p, n, s->name);
	for (step = 1024; step < s->n; step = step * 3u / 2u) {
		size_t k;

		for (k = step - 1u; k <= step + 1u && k <= s->n; k++)
			one_guarded(w, s->p, k, s->name);
	}
	one_guarded(w, s->p, s->n - 1u, s->name);
	one_guarded(w, s->p, s->n, s->name);
}

static void sweep_flip(struct work *w, const struct seed *s)
{
	struct he_guard g;
	size_t at, limit = s->n < 160u ? s->n : 160u;
	unsigned bit;

	if (!he_guard_make2(&g, s->p, s->n, 0))
		return;
	for (at = 0; at < limit; at++)
		for (bit = 0; bit < 8; bit++) {
			g.p[at] ^= (uint8_t)(1u << bit);
			one(w, g.p, s->n, s->name);
			g.p[at] ^= (uint8_t)(1u << bit);
		}
	/* Whole-byte extremes at the same places. */
	for (at = 0; at < limit; at++) {
		uint8_t keep = g.p[at];

		g.p[at] = 0x00;
		one(w, g.p, s->n, s->name);
		g.p[at] = 0xff;
		one(w, g.p, s->n, s->name);
		g.p[at] = 0x7f;
		one(w, g.p, s->n, s->name);
		g.p[at] = 0x80;
		one(w, g.p, s->n, s->name);
		g.p[at] = keep;
	}
	he_guard_free(&g);
}

static void sweep_noise(struct work *w, const struct seed *s)
{
	static const uint8_t fills[] = { 0x00, 0xff, 0x41, 0x7f, 0x80, 0x0a };
	uint8_t buf[2200];
	size_t n;
	unsigned f, r;

	for (f = 0; f < sizeof fills; f++)
		for (n = 0; n <= 80u; n++) {
			memset(buf, fills[f], n);
			one_guarded(w, buf, n, s->name);
		}
	he_seed(0x5eed0000u + s->fmt);
	for (r = 0; r < 250u; r++) {
		size_t len = 8u + he_below(2000u), i;

		for (i = 0; i < len; i++)
			buf[i] = (uint8_t)he_next();
		memcpy(buf, s->p, s->n < 8u ? s->n : 8u);
		one_guarded(w, buf, len, s->name);
	}
}

static void sweep_swap(struct work *w, const struct seed *s)
{
	/* The seed with a 4-byte window overwritten by extreme values at a stride: the
	 * counts and sizes of a format sit on 4 byte boundaries more often than not. */
	struct he_guard g;
	static const uint32_t vals[] = { 0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0xfffffffeu, 0x10000u };
	size_t at, limit = s->n < 256u ? s->n : 256u;
	unsigned v;

	if (!he_guard_make2(&g, s->p, s->n, 0))
		return;
	for (at = 0; at + 4u <= limit; at += 2u)
		for (v = 0; v < sizeof vals / sizeof vals[0]; v++) {
			uint8_t save[4];

			memcpy(save, g.p + at, 4);
			memcpy(g.p + at, &vals[v], 4);
			one(w, g.p, s->n, s->name);
			memcpy(g.p + at, save, 4);
		}
	he_guard_free(&g);
}


/* ---- pathological structure, at the size a file of that shape would be ----------------------------- */

struct patho {
	const char *name;
	uint8_t     fmt;
	const char *head;
	const char *unit;
	size_t      head_len, unit_len;
};

#define PH(n, f, h, u) { n, f, h, u, sizeof h - 1u, sizeof u - 1u }

static const struct patho pathos[] = {
	PH("rtf nesting", KOF_FMT_RTF, "{\\rtf1", "{"),
	PH("rtf unmatched closes", KOF_FMT_RTF, "{\\rtf1", "}"),
	PH("rtf destinations", KOF_FMT_RTF, "{\\rtf1", "{\\*\\x"),
	PH("rtf object data", KOF_FMT_RTF, "{\\rtf1{\\object\\objdata ", "4142434445464748"),
	PH("rtf binary lengths", KOF_FMT_RTF, "{\\rtf1", "\\bin99999999999 "),
	PH("rtf objects", KOF_FMT_RTF, "{\\rtf1", "{\\object\\objdata 41}"),
	PH("pdf objects", KOF_FMT_PDF, "%PDF-1.7\n", "1 0 obj<<>>endobj\n"),
	PH("pdf dict nesting", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj", "<<"),
	PH("pdf array nesting", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj", "["),
	PH("pdf stream keywords", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj<<>>", "stream\n"),
	PH("pdf references", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj [", "1 0 R "),
	PH("pdf trailers", KOF_FMT_PDF, "%PDF-1.7\n", "trailer<</Prev 0>>startxref\n0\n%%EOF\n"),
	PH("pdf xref sections", KOF_FMT_PDF, "%PDF-1.7\n", "xref\n0 1\n0000000000 65535 f \n"),
	PH("pdf strings", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj", "(("),
	PH("pdf hex strings", KOF_FMT_PDF, "%PDF-1.7\n1 0 obj", "<4142"),
	PH("pdf object streams", KOF_FMT_PDF, "%PDF-1.7\n", "1 0 obj<</Type/ObjStm/N 100000/First 0/Length 4>>stream\nAAAA\nendstream\nendobj\n"),
	PH("zip local headers", KOF_FMT_ZIP, "PK\3\4", "PK\3\4"),
	PH("zip directory records", KOF_FMT_ZIP, "PK\3\4", "PK\1\2"),
	PH("zip end records", KOF_FMT_ZIP, "PK\3\4", "PK\5\6"),
	PH("gzip magics", KOF_FMT_GZIP, "\x1f\x8b\x08\x00", "\x1f\x8b\x08"),
	PH("7z start headers", KOF_FMT_7Z, "7z\xbc\xaf\x27\x1c\x00\x04", "\x17"),
	PH("7z property ids", KOF_FMT_7Z, "7z\xbc\xaf\x27\x1c\x00\x04", "\x01\x04\x06"),
	PH("rar blocks", KOF_FMT_RAR, "Rar!\x1a\x07\x00", "\x00\x00\x74\x00\x00\x00\x00"),
	PH("xz headers", KOF_FMT_XZ, "\xfd" "7zXZ\x00\x00\x01", "\xfd"),
	PH("tar blocks of zeros", KOF_FMT_TAR, "", "\0"),
	PH("cab files", KOF_FMT_CAB, "MSCF", "MSCF"),
	PH("arj headers", KOF_FMT_ARJ, "\x60\xea", "\x60\xea\x20\x00"),
	PH("lha headers", KOF_FMT_LHA, "\x20\x00-lh0-", "-lh0-"),
	PH("chm directory", KOF_FMT_CHM, "ITSF", "ITSP"),
	PH("docole sectors", KOF_FMT_DOCOLE, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "\xff\xff\xff\xff"),
	PH("reg keys", KOF_FMT_REG, "Windows Registry Editor Version 5.00\r\n", "[a]\r\n\"b\"=\"c\"\r\n"),
	PH("reg hex continuations", KOF_FMT_REG, "Windows Registry Editor Version 5.00\r\n[a]\r\n\"x\"=hex:", "00,\\\r\n  "),
	PH("script shebang", KOF_FMT_SCRIPT, "#!/bin/sh\n", "#!"),
	PH("lnk strings", KOF_FMT_LNK, "L\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0F", "\xff\xff")
};

static int patho_child(void *arg)
{
	const struct patho *ph = &pathos[*(unsigned *)arg];
	const struct kof_parser *pr = parser_of(ph->fmt);
	size_t total = 1u << 20, at = 0, n;
	uint8_t *buf = malloc(total + ph->unit_len + ph->head_len);
	struct work w;
	struct he_guard g;
	struct timespec t0, t1;
	double dt;

	if (!pr || !buf)
		return 9;
	memcpy(buf, ph->head, ph->head_len);
	at = ph->head_len;
	while (at < total) {
		memcpy(buf + at, ph->unit, ph->unit_len);
		at += ph->unit_len;
	}
	n = at;
	if (!he_guard_make(&g, buf, n))
		return 9;
	free(buf);
	w.pr = pr;
	w.view = calloc(1, pr->view_size);
	w.parsed = w.accepted = 0;
	if (!w.view)
		return 9;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	one(&w, g.p, n, ph->name);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	dt = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	printf("  %-24s %8zu bytes: %.3fs%s\n", ph->name, n, dt, w.accepted ? "" : " (refused)");
	he_guard_free(&g);
	release_view(w.pr, w.view);
	free(w.view);
	if (bad_regions)
		return 2;
	return dt < 2.0 ? 0 : 3;
}

/* ---- the child ------------------------------------------------------------------------ */

struct job {
	unsigned seed;
	const char *sweep;
};

static int run_job(void *arg)
{
	struct job *j = (struct job *)arg;
	const struct seed *s = &seeds[j->seed];
	struct work w;
	uint32_t vs;
	int ok = 0;

	w.pr = parser_of(s->fmt);
	w.parsed = w.accepted = 0;
	if (!w.pr)
		return 3;
	vs = w.pr->view_size;
	w.view = calloc(1, vs);
	if (!w.view)
		return 4;
	{
		/* the valid seed is accepted, or the rest of this proves nothing */
		struct kof_obj_ctx ctx;

		memset(&ctx, 0, sizeof ctx);
		ok = w.pr->sniff(kof_buf_make(s->p, s->n)) && w.pr->parse(kof_buf_make(s->p, s->n), w.view, &ctx);
		if (!ok) {
			printf("  %s: the valid seed is not accepted\n", s->name);
			return 5;
		}
	}
	if (!strcmp(j->sweep, "trunc"))
		sweep_trunc(&w, s);
	else if (!strcmp(j->sweep, "flip"))
		sweep_flip(&w, s);
	else if (!strcmp(j->sweep, "swap"))
		sweep_swap(&w, s);
	else
		sweep_noise(&w, s);
	release_view(w.pr, w.view);
	free(w.view);
	printf("  %-7s %-5s parsed %6llu accepted %6llu\n", s->name, j->sweep,
	       (unsigned long long)w.parsed, (unsigned long long)w.accepted);
	return bad_regions ? 2 : 0;
}

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(void)
{
	static const char *sweeps[] = { "trunc", "flip", "swap", "noise" };
	unsigned i, k;
	double t0 = now();

	build_seeds();
	CK(n_seeds == SEEDS, "all %u seeds built (%u)", SEEDS, n_seeds);
	for (i = 0; i < n_seeds; i++)
		for (k = 0; k < 4; k++) {
			struct job j;
			struct he_status st;
			double t1 = now();

			j.seed = i;
			j.sweep = sweeps[k];
			st = he_child(run_job, &j, 60);
			CK(he_ok(st), "%s %s: %s", seeds[i].name, sweeps[k], he_how(st));
			if (now() - t1 > 20.0)
				printf("  note: %s %s took %.1fs\n", seeds[i].name, sweeps[k], now() - t1);
		}
	for (i = 0; i < sizeof pathos / sizeof pathos[0]; i++) {
		struct he_status st;
		unsigned idx = i;

		st = he_child(patho_child, &idx, 30);
		CK(he_ok(st), "pathological %s (1MB): %s", pathos[i].name, he_how(st));
	}
	printf("hostile_engine_parsers: %u seeds x 4 sweeps, %u checks, %u failed, %.1fs\n", n_seeds,
	       he_checks, he_fails, now() - t0);
	return he_fails != 0 || km_failed();
}
