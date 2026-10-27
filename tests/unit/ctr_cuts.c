/*
 * ctr_cuts - EXHAUSTIVE cuts and field flips of the writers' archives, through the parsers and through the whole engine.
 *
 * Fuzzing reaches the error returns of a parser by luck; this reaches them by construction and the same way on every run:
 *
 *   PREFIXES   every prefix of every archive, byte by byte from 0 to its full length (the writers' valid archive, and the
 *              archive with each header lie of ctr_liars.c): a parser that reads a header at an offset meets the end of the object
 *              at every one of its reads. Each prefix is copied under a guard page, then
 *                - parse level: sniff, parse into a zeroed view with the caller's room, the regions partition the object and the entry
 *                  table is sound (tests/lib/ctr_check.h), release;
 *                - engine level (the clean archive): kscan_bytes; every child is a prefix-substring of one of the members that were
 *                  put in (a cut archive never yields bytes that were not in it), none is longer than the file, names are clean.
 *   FIELDS     every field a writer publishes (declared sizes, counts, offsets: tests/lib/ctr_writers.h struct cw_map) set, one at a
 *              time, to each of 24 boundary values (0, 1, 2, 3, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
 *              0x7fffffff, 0x80000000, 0xffffffff, original +- 1, the file length and +- 1, twice the original): the same parse-level
 *              checks, and the engine scan answers with no child longer than the file and clean names.
 *
 * The known defects of ctr_regions.c (WP2-D9, D10, D11) are carved out by ctr_check.h and COUNTED: the number of overlaps the sweep
 * took is printed per format, so a fix of the engine shows as zero. Everything else is a failure. Each format is one forked case with
 * an alarm.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"
#include "../lib/ctr_check.h"

#define NM 3u
static uint8_t mem[NM][400];
static const unsigned msz[NM] = { 120, 200, 400 };

static const uint8_t fmt_of[CW_NFORMATS] = {
	KOF_FMT_ZIP, KOF_FMT_TAR, KOF_FMT_RAR, KOF_FMT_LHA, KOF_FMT_ARJ, KOF_FMT_CAB, KOF_FMT_CHM, KOF_FMT_7Z, KOF_FMT_DOCOLE, KOF_FMT_PDF, KOF_FMT_GZIP, KOF_FMT_RAR
};

enum { SH_CLEAN, SH_BOTH, SH_UNP, SH_COUNT, SH_OFFSET, SH_CYCLE, SH_NOEND, SH_EXTRA, SH_CRYPT, NSH };
static const char *const shname[NSH] = { "clean", "claimBoth", "claimUnp", "count", "offset", "cycle", "noend", "extra", "crypt" };

struct stat_ {
	uint64_t parsed, refused, known, scans, children;
};

static int write_shape(unsigned f, unsigned sh, struct cw *w, struct cw_map *m)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[NM];
	struct cw_lies l;
	unsigned n = F->max_members == 1 ? 1u : NM, k;
	static const char *const nm[NM] = { "a.txt", "b.txt", "c.txt" };

	memset(e, 0, sizeof e);
	memset(&l, 0, sizeof l);
	for (k = 0; k < NM; k++) {
		e[k].name = nm[k];
		e[k].data = mem[k];
		e[k].len = msz[k];
	}
	switch (sh) {
	case SH_BOTH:   e[1].claimed = 1; e[1].claim_packed = e[1].claim_unpacked = 0xfffffff0u; break;
	case SH_UNP:    e[1].claimed = 1; e[1].claim_packed = msz[1]; e[1].claim_unpacked = 0xfffffff0u; break;
	case SH_COUNT:  if (!(F->lies & CW_L_COUNT)) return 0; l.mask = CW_L_COUNT; l.count_claim = 60000; break;
	case SH_OFFSET: if (!(F->lies & CW_L_OFFSET)) return 0; l.mask = CW_L_OFFSET; l.off_claim = 0x7ffffff0u; break;
	case SH_CYCLE:  if (!(F->lies & CW_L_CYCLE)) return 0; l.mask = CW_L_CYCLE; break;
	case SH_NOEND:  if (!(F->lies & CW_L_NOEND)) return 0; l.mask = CW_L_NOEND; break;
	case SH_EXTRA:  if (!(F->lies & CW_L_EXTRA)) return 0; l.mask = CW_L_EXTRA; break;
	case SH_CRYPT:  if (!(F->lies & CW_L_CRYPT)) return 0; l.mask = CW_L_CRYPT; break;
	default: break;
	}
	if (n == 1 && (sh == SH_BOTH || sh == SH_UNP)) {
		e[0].claimed = 1;
		e[0].claim_packed = msz[0];
		e[0].claim_unpacked = 0xfffffff0u;
	}
	memset(m, 0, sizeof *m);
	F->write(w, e, n, &l, m);
	return !w->oom && w->n > 0;
}

/* Parse-level: NULL when sound, else why. `known` counts the carved-out overlaps taken. */
static const char *parse_check_fmt(uint8_t fmt, const uint8_t *p, size_t n, struct stat_ *st)
{
	const struct kof_parser *pr = kof_parser_of(fmt);
	const struct kof_view_ops *ops = kof_view_ops_of(fmt);
	void *view = calloc(1, pr->view_size);
	struct kof_obj_ctx ctx;
	struct cck_policy pol = cck_policy_of(fmt);
	struct he_guard g;
	const char *why = NULL;
	uint64_t known = 0;

	memset(&ctx, 0, sizeof ctx);
	if (!view || !he_guard_make(&g, p, n)) {
		free(view);
		return "no memory for the case";
	}
	if (!pr->sniff(kof_buf_make(g.p, g.n))) {
		st->refused++;
	} else {
		if (ops)
			ops->mem(view)->room = 16u << 20;
		if (pr->parse(kof_buf_make(g.p, g.n), view, &ctx)) {
			st->parsed++;
			why = ctr_partition(&ctx, pr, n, &pol, &known);
			if (!why)
				why = ctr_entries(&ctx, n, &pol, NULL);
			st->known += known;
		}
		if (ops)
			ops->release(view);
	}
	he_guard_free(&g);
	free(view);
	return why;
}

static const char *parse_check(unsigned f, const uint8_t *p, size_t n, struct stat_ *st)
{
	return parse_check_fmt(fmt_of[f], p, n, st);
}

/* Engine-level on a cut or a flipped archive. `strict` = the children are cut pieces of the members (a prefix); otherwise only sane. */
static const char *engine_check(unsigned f, const uint8_t *p, size_t n, int strict, struct stat_ *st)
{
	static struct kof_scan_option o;
	struct cs_run r;
	unsigned i, k;
	const char *why = NULL;

	o = cs_opt();
	if (cs_scan(p, n, "c.x", &o, &r))
		return "no memory for the case";
	st->scans++;
	st->children += r.n > 1 ? r.n - 1u : 0u;
	if (n > 0 && r.rc < 1)
		why = "the scan did not answer";
	if (r.slash_forged)
		why = "a child name carries a separator or a control byte";
	for (i = 1; !why && i < r.n && i < CS_MAXOBJ; i++) {
		const struct cs_obj *c = &r.o[i];
		int ok = 0;

		if (c->len > (uint64_t)n) {
			why = "a child is longer than the file that held it";
			break;
		}
		if (!strict)
			continue;
		if (cw_formats[f].lead && i == 1 && c->head[0] == 0x01)       /* the 7z file list */
			continue;
		for (k = 0; k < NM && !ok; k++) {
			size_t cmp = c->len < 32 ? (size_t)c->len : 32u;

			/* a PDF stream whose "endstream" is cut ends at the end of the file: up to a newline and the first letters of the word more */
			ok = c->len <= msz[k] + (fmt_of[f] == KOF_FMT_PDF ? 16u : 0u) && !memcmp(c->head, mem[k], cmp);
		}
		if (cw_formats[f].gathered)                                     /* the gathered OLE body is member 0, then 1, then 2 */
			ok = !memcmp(c->head, mem[0], c->len < 32 ? (size_t)c->len : 32u);
		if (!ok)
			why = "a child of a cut archive is not a piece of any member";
	}
	cs_free(&r);
	return why;
}

static const uint64_t interesting[] = { 0, 1, 2, 3, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffffu, 0x80000000u, 0xffffffffu };

static int one_format(void *arg)
{
	unsigned f = (unsigned)(uintptr_t)arg, sh;
	const struct cw_format *F = &cw_formats[f];
	struct stat_ pre = { 0 }, fld = { 0 };
	uint64_t muts = 0, cuts = 0;

	for (sh = 0; sh < NSH; sh++) {
		struct cw w = { 0 };
		struct cw_map m;
		size_t L, n;
		unsigned i, v;

		if (!write_shape(f, sh, &w, &m))
			continue;
		n = w.n;
		/* PREFIXES */
		for (L = 0; L <= n; L++) {
			const char *why = parse_check(f, w.p, L, &pre);

			cuts++;
			CK(why == NULL, "%s/%s: prefix %zu of %zu: %s", F->name, shname[sh], L, n, why ? why : "");
			if (sh == SH_CLEAN || sh == SH_EXTRA) {
				why = engine_check(f, w.p, L, sh == SH_CLEAN, &pre);
				CK(why == NULL, "%s/%s: engine on prefix %zu of %zu: %s", F->name, shname[sh], L, n, why ? why : "");
			}
			if (he_fails > 40)
				return 1;
		}
		/* FIELDS */
		for (i = 0; i < m.n; i++) {
			uint64_t orig = 0, vals[sizeof interesting / sizeof interesting[0] + 8];
			unsigned nv = 0, k, sz = m.f[i].size;
			uint64_t mask = sz == 8 ? ~0ull : ((1ull << (8u * sz)) - 1u);

			if ((uint64_t)m.f[i].off + sz > n)
				continue;
			for (k = 0; k < sz; k++)
				orig |= (uint64_t)w.p[m.f[i].off + k] << (8u * k);
			for (k = 0; k < sizeof interesting / sizeof interesting[0]; k++)
				vals[nv++] = interesting[k];
			vals[nv++] = orig - 1u;
			vals[nv++] = orig + 1u;
			vals[nv++] = (uint64_t)n;
			vals[nv++] = (uint64_t)n - 1u;
			vals[nv++] = (uint64_t)n + 1u;
			vals[nv++] = orig * 2u;
			vals[nv++] = ~0ull;
			for (v = 0; v < nv; v++) {
				uint8_t *copy = (uint8_t *)malloc(n);
				const char *why;
				uint64_t val = vals[v] & mask;

				if (!copy)
					return 9;
				memcpy(copy, w.p, n);
				for (k = 0; k < sz; k++)
					copy[m.f[i].off + k] = (uint8_t)(val >> (8u * k));
				muts++;
				why = parse_check(f, copy, n, &fld);
				CK(why == NULL, "%s/%s: field at %u (%u bytes) = 0x%llx: %s", F->name, shname[sh], m.f[i].off, sz, (unsigned long long)val, why ? why : "");
				if ((muts & 1u) == 0) {
					why = engine_check(f, copy, n, 0, &fld);
					CK(why == NULL, "%s/%s: engine, field at %u (%u bytes) = 0x%llx: %s", F->name, shname[sh], m.f[i].off, sz, (unsigned long long)val,
					   why ? why : "");
				}
				free(copy);
				if (he_fails > 40)
					return 1;
			}
		}
		cw_free(&w);
	}
	printf("  %-5s %llu prefixes (parsed %llu, refused by the sniff %llu, %llu engine scans), %llu field flips (parsed %llu, %llu engine scans), "
	       "known-defect overlaps taken %llu\n", F->name, (unsigned long long)cuts, (unsigned long long)pre.parsed, (unsigned long long)pre.refused,
	       (unsigned long long)pre.scans, (unsigned long long)muts, (unsigned long long)fld.parsed, (unsigned long long)fld.scans,
	       (unsigned long long)(pre.known + fld.known));
	return he_fails != 0 ? 1 : 0;
}

/*
 * The formats that have no writer (bz2, xz, rtf, lnk, reg): one literal object each, every prefix of it, every byte of it set to
 * 0x00 / 0x7f / 0x80 / 0xff in turn, at the parse level (the checks of ctr_check.h) and through the engine (it answers, no child longer than the file).
 */
static int literals(void *unused)
{
	static const uint8_t bz2[] = { 'B', 'Z', 'h', '9', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0 };
	static const uint8_t xz[] = { 0xfd, '7', 'z', 'X', 'Z', 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x21, 1, 0, 0, 0, 0,
		0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
		0, 1, 28, 32, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 'Y', 'Z' };
	static const char rtf[] = "{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata 01050000020000000a000000}}{\\pict\\bin8 ABCDEFGH}}";
	static const char reg[] = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\x]\r\n\"a\"=\"b\"\r\n\"run\"=hex:01,02,03\r\n";
	uint8_t lnk[80];
	static const uint8_t clsid[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46 };
	const struct { const char *name; uint8_t fmt; const uint8_t *p; size_t n; } lit[] = {
		{ "bz2", KOF_FMT_BZIP2, bz2, sizeof bz2 }, { "xz", KOF_FMT_XZ, xz, sizeof xz }, { "rtf", KOF_FMT_RTF, (const uint8_t *)rtf, sizeof rtf - 1u },
		{ "reg", KOF_FMT_REG, (const uint8_t *)reg, sizeof reg - 1u }, { "lnk", KOF_FMT_LNK, lnk, sizeof lnk }
	};
	unsigned k;
	struct stat_ st = { 0 };
	static const uint8_t vals[] = { 0x00, 0x7f, 0x80, 0xff };

	(void)unused;
	memset(lnk, 0, sizeof lnk);
	lnk[0] = 0x4c;
	memcpy(lnk + 4, clsid, sizeof clsid);
	for (k = 0; k < sizeof lit / sizeof lit[0]; k++) {
		size_t L, i;
		unsigned v;

		for (L = 0; L <= lit[k].n; L++) {
			const char *why = parse_check_fmt(lit[k].fmt, lit[k].p, L, &st);

			CK(why == NULL, "%s: prefix %zu of %zu: %s", lit[k].name, L, lit[k].n, why ? why : "");
		}
		for (i = 0; i < lit[k].n; i++)
			for (v = 0; v < sizeof vals; v++) {
				uint8_t *copy = (uint8_t *)malloc(lit[k].n);
				const char *why;
				struct cs_run r;
				struct kof_scan_option o = cs_opt();

				if (!copy)
					return 9;
				memcpy(copy, lit[k].p, lit[k].n);
				copy[i] = vals[v];
				why = parse_check_fmt(lit[k].fmt, copy, lit[k].n, &st);
				CK(why == NULL, "%s: byte %zu = 0x%02x: %s", lit[k].name, i, vals[v], why ? why : "");
				if (!cs_scan(copy, lit[k].n, "l.x", &o, &r)) {
					CK(r.rc >= 1 && r.child_bytes <= (uint64_t)lit[k].n * 4u + 64u, "%s: byte %zu = 0x%02x: the scan answers with bounded children", lit[k].name, i, vals[v]);
					cs_free(&r);
				}
				free(copy);
			}
	}
	printf("  literals: %llu parsed, %llu refused by the sniff\n", (unsigned long long)st.parsed, (unsigned long long)st.refused);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	unsigned f, k, bad = 0;
	struct he_status st;

	for (k = 0; k < NM; k++)
		cs_fill(mem[k], sizeof mem[k], k + 1u);
	cs_eng = keng_open(HE_DB);
	for (f = 0; f < CW_NFORMATS; f++) {
		st = he_child(one_format, (void *)(uintptr_t)f, 280);
		printf("cuts %-5s %s\n", cw_formats[f].name, he_how(st));
		bad |= !he_ok(st);
	}
	st = he_child(literals, NULL, 120);
	printf("cuts literals (bz2 xz rtf reg lnk) %s\n", he_how(st));
	bad |= !he_ok(st);
	printf("ctr_cuts: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
