#define _GNU_SOURCE
/*
 * normalizer_engine - the normalised view, through the whole engine.
 *
 * Objects are built in memory (normalizer_fx.h) and scanned with kscan_bytes
 * against the test database. Three small rules of tests/sigs/norm_view_*.c are
 * what the results are read through:
 *
 *   NormViewDecoded  four strings that exist in the file only encoded - base64
 *                    behind `base64 -d`, hex, percent escapes, UTF-16LE. The rule
 *                    can fire on the view and not on the parent.
 *   NormViewData     two markers in the DATA region, with zeros before, inside and
 *                    after them: fires on the view only if its DATA region is where
 *                    the collapse put the markers.
 *   NormViewEntry    twelve bytes at ctx->entry_off: fires on the view only if the
 *                    entry was carried through the collapse.
 *
 * WHAT IS PINNED
 *
 *   MADE            for ELF with and without a section table and for PE, for zeros
 *                   before the code, after it, inside the data and before the next
 *                   thing, alone and together: the view is the parent's only child,
 *                   it is marked NORMALIZED, the decoded string is found on it and
 *                   NOT on the parent, and the entry and data rules answer on the
 *                   view as they do on the parent (regions, entry carried).
 *   SAME SEARCH     every literal run of the parent outside the encoded stretch is
 *                   found in the view, and every literal run of the view is the
 *                   parent's or the decoded text: no match lost, none invented.
 *   NOT MADE        nothing revealed (padding only, nothing at all), too small to be
 *                   worth it, dense code, a decode that landed in a kept region and
 *                   was put back, a resident ceiling that cannot hold two copies. A
 *                   view of a view is not made either: every case above expects
 *                   exactly two objects. A view built and then refused (it does not
 *                   fit the object cap, or the produced budget) is read through its
 *                   the cases below, and the next scan of the same scanner
 *                   (reuse_and_threads) shows no trace of it.
 *   INHERITED       a diagnose that matched the parent matches its view, with the
 *                   code moved by a collapse before it.
 *   LIMITS          a decode budget that fires says so on the PARENT (broken =
 *                   LIMIT), and a decode that did not hit one does not.
 *   REUSE           one scanner over many objects in a row, and separate scanners on
 *                   separate threads, give each object the answer it gives alone.
 *   SCRIPTS         the script's own view: a shell script's base64 payload, its hex,
 *                   its percent escapes, and a php string built from pieces (only at
 *                   heuristic level 2).
 */

#include <pthread.h>

#include "caps_fix.h"
#include "caps_e2e.h"
#include "normalizer_ref.h"
#include "normalizer_fx.h"
#include "../../libkofeng/scanners/scan.h"

/* ---- a collector that keeps bytes --------------------------------------------------- */

#define MAXO 6u

struct eo {
	char     name[96];
	uint32_t kind, broken, n;
	char     find[10][120];
	uint8_t *bytes;
	uint64_t len;
};

struct er {
	unsigned n;
	struct eo o[MAXO];
};

static int collect(const char *name, const void *bytes, uint64_t len, const struct kof_result *res,
		   void *user)
{
	struct er *r = user;
	struct eo *o;
	uint32_t i;

	if (r->n >= MAXO)
		return 0;
	o = &r->o[r->n++];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name ? name : "");
	o->kind = res->entry_kind;
	o->broken = res->broken;
	o->n = res->n;
	for (i = 0; i < res->n && i < 10u; i++)
		snprintf(o->find[i], sizeof o->find[i], "%s", res->v[i].name);
	if (len && len < (8u << 20)) {
		o->bytes = malloc((size_t)len);
		if (o->bytes) {
			memcpy(o->bytes, bytes, (size_t)len);
			o->len = len;
		}
	}
	return 0;
}

static void er_free(struct er *r)
{
	unsigned i;

	for (i = 0; i < r->n; i++)
		free(r->o[i].bytes);
	r->n = 0;
}

static void defaults(struct kof_scan_option *opt, unsigned heur)
{
	memset(opt, 0, sizeof *opt);
	opt->all_matches = 1;
	opt->max_produced_bytes = 64u << 20;
	opt->max_resident_bytes = 256u << 20;
	opt->max_object_bytes = 64u << 20;
	opt->heur_level = heur;
}

static unsigned scan(kof_scanner *sc, const uint8_t *b, uint64_t n, const struct kof_scan_option *opt,
		     struct er *r)
{
	memset(r, 0, sizeof *r);
	(void)kscan_bytes(sc, b, n, "eng", opt, collect, r);
	return r->n;
}

static int has(const struct eo *o, const char *word)
{
	uint32_t i;

	if (!o)
		return 0;
	for (i = 0; i < o->n && i < 10u; i++)
		if (strstr(o->find[i], word))
			return 1;
	return 0;
}

static const struct eo *view_of(const struct er *r)
{
	unsigned i;

	for (i = 1; i < r->n; i++)
		if (r->o[i].kind == KOF_ENT_NORMALIZED)
			return &r->o[i];
	return NULL;
}

/* ---- the encoded tails --------------------------------------------------------------- */

#define CAN_B64  "NormCanaryB64-7f3a91"
#define CAN_HEX  "NormCanaryHEX-5e2b44"
#define CAN_PCT  "NormCanaryPCT-c9d012"
#define CAN_WIDE "NormCanaryWIDE-12ab9"

enum { P_B64, P_HEX, P_PCT, P_WIDE, P_COUNT };
static const char *const CAN[P_COUNT] = { CAN_B64, CAN_HEX, CAN_PCT, CAN_WIDE };

/* the tail for one encoding: begins with a newline, which is the delimiter */
static size_t make_tail(unsigned kind, uint8_t *out)
{
	char enc[512];
	size_t el, o = 0, i;
	const char *c = CAN[kind];

	out[o++] = '\n';
	switch (kind) {
	case P_B64:
		el = nr_b64_enc((const uint8_t *)c, strlen(c), enc, 1, 0, 0);
		memcpy(out + o, "echo ", 5u);
		o += 5u;
		memcpy(out + o, enc, el);
		o += el;
		memcpy(out + o, " | base64 -d\n", 13u);
		return o + 13u;
	case P_HEX:
		el = nr_hex_enc((const uint8_t *)c, strlen(c), enc, 0);
		memcpy(out + o, enc, el);
		o += el;
		out[o++] = '\n';
		return o;
	case P_PCT: {
		char plain[128];
		int pl = snprintf(plain, sizeof plain, "wget http://x/%s;x", c);

		el = nr_pct_enc((const uint8_t *)plain, (size_t)pl, enc, 1);
		memcpy(out + o, "Cmd=", 4u);
		o += 4u;
		memcpy(out + o, enc, el);
		o += el;
		memcpy(out + o, "&y=1\n", 5u);
		return o + 5u;
	}
	default:
		for (i = 0; c[i]; i++) {
			out[o++] = (uint8_t)c[i];
			out[o++] = 0;
		}
		return o;
	}
}

static const char *decoded_rule(int pe)
{
	return pe ? "NormViewDecodedPe" : "NormViewDecoded";
}

/* ---- the layout matrix ------------------------------------------------------------------ */

static uint8_t img[1u << 18], tailb[1024];

/* A maximal run of non-zero bytes, at least `min` long, as a search pattern. */
static int run_at(const uint8_t *p, size_t n, size_t *i, size_t *len, size_t min)
{
	size_t s = *i;

	while (s < n && !p[s])
		s++;
	if (s >= n)
		return 0;
	*i = s;
	while (s < n && p[s])
		s++;
	*len = s - *i;
	(void)min;
	return 1;
}

/*
 * SAME SEARCH. Every run of non-zero bytes of the parent that lies outside the
 * encoded tail is a substring of the view; every run of the view is a substring of
 * the parent or of the decoded plaintext. A zero-free pattern is a run of non-zero
 * bytes, so this is "view search equals parent search" for every literal there is.
 */
static int in_either(const uint8_t *par, size_t pn, const char *allowed, size_t an, const uint8_t *p,
		     size_t n)
{
	return n == 0 || memmem(par, pn, p, n) || memmem(allowed, an, p, n);
}

/* `run` is a piece of the parent, or of the decoded text, or the end of one followed
 * by the start of the other - the decoded text glued to the literal bytes that stood
 * before it (no zero between them in the parent either). */
static int explained(const uint8_t *par, size_t pn, const char *allowed, size_t an, const uint8_t *run,
		     size_t len)
{
	size_t lo = 0, hi = len, k;

	if (in_either(par, pn, allowed, an, run, len))
		return 1;
	/* the longest prefix that is the parent's (a substring property: monotone) */
	while (lo < hi) {
		size_t mid = lo + (hi - lo + 1u) / 2u;

		if (memmem(par, pn, run, mid))
			lo = mid;
		else
			hi = mid - 1u;
	}
	for (k = lo; k > 0 && lo - k < 64u; k--)
		if (in_either(par, pn, allowed, an, run + k, len - k))
			return 1;
	return 0;
}

static void same_search(const uint8_t *par, uint64_t pn, uint64_t tail_off, const uint8_t *view,
			uint64_t vn, const char *plain, size_t plain_n, const char *what)
{
	size_t i = 0, len;
	unsigned lost = 0, invented = 0;

	while (run_at(par, (size_t)tail_off < pn ? (size_t)tail_off : (size_t)pn, &i, &len, 4u)) {
		if (len >= 4u && !memmem(view, (size_t)vn, par + i, len))
			lost++;
		i += len;
	}
	i = 0;
	while (run_at(view, (size_t)vn, &i, &len, 4u)) {
		if (len >= 4u && !explained(par, (size_t)pn, plain, plain_n, view + i, len)) {
			if (!invented && nr_bad < 4u) {
				size_t q;

				printf("  invented run at view offset %zu, %zu bytes:", i, len);
				for (q = 0; q < len && q < 48u; q++)
					printf(" %02x", view[i + q]);
				printf("\n");
			}
			invented++;
		}
		i += len;
	}
	NCKF(!lost, "%s: %u literal runs of the parent are not in the view", what, lost);
	NCKF(!invented, "%s: %u literal runs of the view are neither the parent's nor decoded", what,
	     invented);
}

struct layout {
	const char *name;
	uint32_t gap_text, gap_code, data_zeros, gap_end;
};

static const struct layout LAYOUTS[] = {
	{ "no gaps",                      0,   0,   0,   0 },
	{ "zeros before the code",        300, 0,   0,   0 },
	{ "zeros after the code",         0,   200, 0,   0 },
	{ "zeros inside the data",        0,   0,   150, 0 },
	{ "zeros before the tail",        0,   0,   0,   500 },
	{ "zeros everywhere",             300, 200, 150, 500 },
	{ "7 zeros (under the floor)",    7,   7,   7,   7 },
	{ "8 zeros (at the floor)",       8,   8,   8,   8 },
	{ "9 zeros (over the floor)",     9,   9,   9,   9 },
};

static void one_matrix_cell(kof_scanner *sc, unsigned fmt, const struct layout *l, unsigned pay)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	uint64_t n;
	const struct eo *v;
	char what[160], plain[256];
	int pe = fmt == 2u;
	size_t pn;

	memset(&f, 0, sizeof f);
	f.gap_text = l->gap_text;
	f.gap_code = l->gap_code;
	f.data_zeros = l->data_zeros;
	f.gap_end = l->gap_end;
	f.sections = fmt != 1u;
	f.code_extra = 3900;                        /* the object is over the 4 KiB floor */
	f.tail_n = make_tail(pay, tailb);
	f.tail = tailb;
	n = pe ? fx_pe(img, &f, &at) : fx_elf(img, &f, &at);
	snprintf(what, sizeof what, "%s / %s / payload %u", fmt == 0 ? "ELF+sections" :
		 fmt == 1 ? "ELF stripped" : "PE", l->name, pay);
	defaults(&opt, 0);
	scan(sc, img, n, &opt, &r);
	NCKF(r.n == 2u, "%s: %u objects", what, r.n);
	if (r.n != 2u) {
		er_free(&r);
		return;
	}
	v = view_of(&r);
	NCKF(v != NULL && !strcmp(r.o[1].name + strlen(r.o[1].name) - 5u, ":norm"),
	     "%s: no view marked NORMALIZED, named :norm", what);
	if (!v) {
		er_free(&r);
		return;
	}
	/* the decoded string is on the view and not on the parent */
	NCKF(!has(&r.o[0], decoded_rule(pe)), "%s: the parent matched the decoded rule", what);
	NCKF(has(v, decoded_rule(pe)), "%s: the view did not match the decoded rule", what);
	/* regions and entry: the rules that read them answer on the view as on the parent */
	NCKF(has(&r.o[0], pe ? "NormViewEntryPe" : "NormViewEntry"), "%s: parent entry rule", what);
	NCKF(has(v, pe ? "NormViewEntryPe" : "NormViewEntry"), "%s: view entry rule (entry carried)", what);
	NCKF(has(&r.o[0], pe ? "NormViewDataPe" : "NormViewData"), "%s: parent data rule", what);
	NCKF(has(v, pe ? "NormViewDataPe" : "NormViewData"), "%s: view data rule (DATA carried)", what);
	/* the view is a view: no longer than the parent, and shorter wherever a collapse ran */
	NCKF(v->len && v->len <= n, "%s: view of %llu bytes from %llu", what, (unsigned long long)v->len,
	     (unsigned long long)n);
	if ((fmt != 1u && l->gap_text >= 8u && !pe) || l->gap_code >= 8u || l->data_zeros >= 8u ||
	    l->gap_end >= 8u || pay != P_WIDE)
		NCKF(v->len < n, "%s: nothing collapsed", what);
	/* what the view may hold that the parent does not: the decoded text with whatever
	 * stood next to it in the run (the newline, "echo ", "Cmd=...&y=1") */
	pn = (size_t)snprintf(plain, sizeof plain, "\necho %s\n\n%s\nCmd=wget http://x/%s;x&y=1\n%s", CAN[pay],
			      CAN[pay], CAN[pay], CAN[pay]);
	same_search(img, n, at.tail_off, v->bytes, v->len, plain, pn, what);
	/* and the parent was not handed back changed: the scan borrows the bytes */
	er_free(&r);
}

static void layout_matrix(void)
{
	unsigned fmt, l, pay, p;

	for (fmt = 0; fmt < 3u; fmt++)
		for (l = 0; l < sizeof LAYOUTS / sizeof LAYOUTS[0]; l++)
			for (pay = 0; pay < P_COUNT; pay++)
				one_matrix_cell(e2e_sc, fmt, &LAYOUTS[l], pay);
	/* THE VIEW IS NOT ANALYSED AGAIN: every product of the object - symbols, functions,
	 * the decode walk, relocations, imports, the diagnose graph - was built once for the
	 * parent and handed to the view, across all of the scans above on this one scanner
	 * (prod_once.c states the same invariant for the objects it scans). */
	for (p = 0; p < KOF_PROD_COUNT; p++)
		NCKF(kof_scan_prod_repeats(e2e_sc, (enum kof_prodkind)p) == 0u, "product '%s' was built again",
		     kof_prod_name((enum kof_prodkind)p));
}

/* ---- the encodings that are in more than one layer, at the engine -------------------------- */

static void nested_layers(void)
{
	/* hex of base64 of a canary, behind `echo`: both layers come out in the view */
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	char b64[256], hex[1024];
	uint8_t tail[2048];
	size_t el, hl, o = 0, inner;
	char inner_text[256];
	uint64_t n;

	el = nr_b64_enc((const uint8_t *)CAN_B64, strlen(CAN_B64), b64, 1, 0, 0);
	inner = (size_t)snprintf(inner_text, sizeof inner_text, "echo %.*s | base64 -d\n", (int)el, b64);
	hl = nr_hex_enc((const uint8_t *)inner_text, inner, hex, 0);
	tail[o++] = '\n';
	memcpy(tail + o, hex, hl);
	o += hl;
	tail[o++] = '\n';
	memset(&f, 0, sizeof f);
	f.sections = 1;
	f.code_extra = 3900;
	f.tail = tail;
	f.tail_n = o;
	n = fx_elf(img, &f, &at);
	defaults(&opt, 0);
	scan(e2e_sc, img, n, &opt, &r);
	NCK(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewDecoded"));
	NCK(!has(&r.o[0], "NormViewDecoded"));
	er_free(&r);
}

/* ---- not made ------------------------------------------------------------------------------- */

static void scan_fx(const struct fx *f, int pe, const struct kof_scan_option *opt, struct er *r,
		    struct fx_at *at)
{
	uint64_t n = pe ? fx_pe(img, f, at) : fx_elf(img, f, at);

	scan(e2e_sc, img, n, opt, r);
}

static void base_fx(struct fx *f)
{
	memset(f, 0, sizeof *f);
	f->sections = 1;
	f->code_extra = 3900;
}

/*
 * MANY PLACES TO CARRY. Every section of the description is four offsets the view
 * asks the collapse about, and the table of them starts at 64 and doubles; an ELF
 * with 100 more sections than a minimal one needs it to grow twice. The entry and
 * the DATA region must still be right, and so must every other answer.
 */
static void many_marks(void)
{
	unsigned extra;
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;

	defaults(&opt, 0);
	for (extra = 0; extra <= 120u; extra += 20u) {
		base_fx(&f);
		f.extra_sections = extra;
		f.gap_text = 300; f.gap_code = 200; f.data_zeros = 150; f.gap_end = 500;
		f.tail_n = make_tail(P_HEX, tailb);
		f.tail = tailb;
		scan_fx(&f, 0, &opt, &r, &at);
		NCKF(r.n == 2u && view_of(&r), "%u extra sections: %u objects", extra, r.n);
		if (r.n == 2u && view_of(&r)) {
			NCKF(has(view_of(&r), "NormViewEntry"), "%u extra sections: entry not carried", extra);
			NCKF(has(view_of(&r), "NormViewData"), "%u extra sections: DATA not carried", extra);
			NCKF(has(view_of(&r), "NormViewDecoded"), "%u extra sections: decode lost", extra);
		}
		er_free(&r);
	}
}

static void not_made(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	int pe;

	defaults(&opt, 0);
	for (pe = 0; pe < 2; pe++) {
		/* nothing to say: no zeros, no wide text, nothing encoded */
		base_fx(&f);
		scan_fx(&f, pe, &opt, &r, &at);
		NCKF(r.n == 1u && !view_of(&r), "pe=%d clean object: %u objects", pe, r.n);
		er_free(&r);
		/* zeros alone reveal nothing, however many: the collapse is not a reason */
		base_fx(&f);
		f.gap_text = 400; f.gap_code = 400; f.data_zeros = 400; f.gap_end = 900;
		scan_fx(&f, pe, &opt, &r, &at);
		NCKF(r.n == 1u && !view_of(&r), "pe=%d padding only: %u objects", pe, r.n);
		er_free(&r);
		/* encoded text, under the floor of NORM_MIN_OBJ (4 KiB), is not worth a copy,
		 * and the floor is exact: 4095 bytes is not viewed, 4096 is. The length is set
		 * through the zeros before the tail, so every byte of difference is one byte. */
		{
			uint64_t len0, fl;
			uint32_t gap;

			base_fx(&f);
			f.sections = 0;
			f.code_extra = 600;
			f.tail_n = make_tail(P_B64, tailb);
			f.tail = tailb;
			len0 = pe ? fx_pe(img, &f, &at) : fx_elf(img, &f, &at);
			NCKF(len0 < 4000u, "pe=%d the base object is %llu bytes", pe, (unsigned long long)len0);
			for (fl = 4094; fl <= 4097u; fl++) {
				gap = (uint32_t)(fl - len0);
				f.gap_end = gap;
				scan_fx(&f, pe, &opt, &r, &at);
				NCKF(at.len == fl, "pe=%d built %llu bytes, wanted %llu", pe,
				     (unsigned long long)at.len, (unsigned long long)fl);
				NCKF((r.n == 2u && view_of(&r) != NULL) == (fl >= 4096u),
				     "pe=%d %llu bytes: %u objects", pe, (unsigned long long)fl, r.n);
				er_free(&r);
			}
		}
	}
}

/* Dense code: the executable bytes are a stream (7.5 bits or more), so the view has
 * nothing to do to them and is not built, whatever is encoded after. */
static void dense_code(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	static uint8_t code[4096];
	struct nrng g;
	size_t i;
	int pe;

	nr_seed(&g, 77);
	for (i = 0; i < sizeof code; i++)
		code[i] = (uint8_t)nr_next(&g);
	defaults(&opt, 0);
	for (pe = 0; pe < 2; pe++) {
		base_fx(&f);
		f.code = code;
		f.code_len = sizeof code;
		f.tail_n = make_tail(P_B64, tailb);
		f.tail = tailb;
		scan_fx(&f, pe, &opt, &r, &at);
		NCKF(!view_of(&r), "pe=%d dense code: a view was made", pe);
		NCK(!has(&r.o[0], decoded_rule(pe)));
		er_free(&r);
		/* the same object with ordinary code is viewed */
		base_fx(&f);
		f.tail_n = make_tail(P_B64, tailb);
		f.tail = tailb;
		scan_fx(&f, pe, &opt, &r, &at);
		NCKF(view_of(&r) != NULL, "pe=%d ordinary code: no view", pe);
		er_free(&r);
	}
}

/*
 * A DECODE THAT LANDED IN A KEPT REGION IS PUT BACK, AND THEN THERE IS NOTHING TO
 * SHOW. The payload is in the code segment of a stripped ELF (all of it kept), so
 * the pass decodes it and restores it; the view would say nothing the parent does
 * not, and it is not made. The work was done and the child refused.
 */
static void decode_undone_by_keep(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	static uint8_t code[2048];
	size_t n = make_tail(P_B64, code);

	defaults(&opt, 0);
	base_fx(&f);
	f.sections = 0;                           /* stripped: the whole segment is code, kept */
	{
		static uint8_t big[4096];

		memset(big, 0x90, sizeof big);
		memcpy(big + 100, code, n);
		f.code = big;
		f.code_len = 3900;
		scan_fx(&f, 0, &opt, &r, &at);
		NCKF(r.n == 1u && !view_of(&r), "payload inside kept code: %u objects", r.n);
		NCK(!has(&r.o[0], "NormViewDecoded"));
		er_free(&r);
		/* with wide text in the DATA as well the view is made - and carries the
		 * payload in the code exactly as the parent has it */
		f.code = big;
		f.tail_n = make_tail(P_WIDE, tailb);
		f.tail = tailb;
		scan_fx(&f, 0, &opt, &r, &at);
		NCKF(r.n == 2u && view_of(&r), "wide text beside a kept payload: %u objects", r.n);
		{
			const struct eo *v = view_of(&r);

			NCK(v && v->bytes && memmem(v->bytes, v->len, "base64 -d", 9u) != NULL);
			NCK(v && v->bytes && memmem(v->bytes, v->len, CAN_B64, strlen(CAN_B64)) == NULL);
		}
		er_free(&r);
	}
}

/* A ceiling that cannot hold two copies of the object means no view; the object is
 * still scanned. The same scanner then makes one under a roomier ceiling. */
static void budget_gates(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	kof_scanner *sc = kscan_new(e2e_eng);

	CK(sc != NULL);
	if (!sc)
		return;
	base_fx(&f);
	f.code_extra = 8000;
	f.tail_n = make_tail(P_B64, tailb);
	f.tail = tailb;
	defaults(&opt, 0);
	opt.max_resident_bytes = 16u << 10;       /* two copies of ~8.4 KiB do not fit in what is left */
	{
		uint64_t n = fx_elf(img, &f, &at);

		(void)scan(sc, img, n, &opt, &r);
		NCKF(r.n >= 1u && !view_of(&r), "a resident ceiling of 16 KiB: %u objects", r.n);
		NCK(!has(&r.o[0], "NormViewDecoded"));
		NCK(has(&r.o[0], "NormViewEntry"));                 /* the parent was still scanned */
		er_free(&r);
		opt.max_resident_bytes = 256u << 20;
		(void)scan(sc, img, n, &opt, &r);
		NCKF(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewDecoded"),
		     "the same scanner under a roomier ceiling: %u objects", r.n);
		er_free(&r);
	}
	kscan_free(sc);
}

/* ---- the budgets a made view must fit, and the one that is not asked ----------------- */

/* a one-megabyte-and-more view goes out in chunks of a megabyte */
static uint8_t *big_object(size_t body, struct fx_at *at, uint64_t *n)
{
	struct fx f;
	size_t i, tl;
	uint8_t *t = malloc(body + 600u), *o = malloc(body + (1u << 16));

	for (i = 0; i < body; i++)
		t[i] = (uint8_t)"the quick brown fox jumps over the lazy dog. "[i % 45u];
	tl = make_tail(P_B64, t + body);
	base_fx(&f);
	f.tail = t;
	f.tail_n = body + tl;
	*n = fx_elf(o, &f, at);
	free(t);
	return o;
}

static void big_views(void)
{
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	uint64_t n;
	uint8_t *o = big_object(3u << 20, &at, &n);
	kof_scanner *sc = kscan_new(e2e_eng);

	CK(sc != NULL && o != NULL);
	if (!sc || !o)
		return;
	defaults(&opt, 0);
	scan(sc, o, n, &opt, &r);
	{
		const struct eo *v = view_of(&r);

		/* three chunks out, every byte there: the decoded eight zeros collapse to two */
		NCKF(r.n == 2u && v && v->len == n - 6u && has(v, "NormViewDecoded"),
		     "a 3 MiB view: %u objects, length %llu of %llu", r.n,
		     (unsigned long long)(v ? v->len : 0u), (unsigned long long)n);
		NCK(v && v->bytes && memcmp(v->bytes, o, 4096) == 0);
	}
	er_free(&r);
	/*
	 * A PRODUCED-BYTES BUDGET SMALLER THAN THE VIEW, in the two shapes it comes in.
	 *
	 * Under one chunk (1 MiB) the sink refuses the whole thing and there is no view.
	 * Past it the sink takes whole chunks until the budget is reached, and what it
	 * holds then is handed over as a child: the first two megabytes of a view of
	 * three, marked NORMALIZED, with the parent's header over it and the decoded
	 * payload - which was near the end - not in it. norm_fits asks about obj_cap, the
	 * resident ceiling and the produced-bytes budget for exactly this reason (a prefix
	 * of a view is a damaged executable): the view is not made, and the limit is said.
	 */
	opt.max_produced_bytes = 2u << 20;
	scan(sc, o, n, &opt, &r);
	{
		const struct eo *v = view_of(&r);

		NCKF(!v || has(v, "NormViewDecoded"),
		     "a view that does not fit the produced-bytes budget is not handed over as a prefix of "
		     "itself (2 MiB of 3)");
		NCK(r.o[0].n >= 2u);                            /* the parent was scanned whole */
	}
	er_free(&r);
	defaults(&opt, 0);
	/*
	 * A VIEW BUILT AND NEVER MADE, because it will not fit: the decode ran, the
	 * collapse ran, norm_fits said no. The parent is then the only object and says
	 * nothing about what it did not look at - the decoded text was never searched -
	 * where a bound that cuts the decode (above) is reported as BROKEN_LIMIT.
	 */
	opt.max_object_bytes = 2u << 20;
	scan(sc, o, n, &opt, &r);
	NCKF(r.n == 1u && !view_of(&r), "an object cap under the view: %u objects", r.n);
	NCK(!has(&r.o[0], "NormViewDecoded"));
	NCKF(r.n >= 1u && r.o[0].broken == KOF_BROKEN_LIMIT,
	     "a view refused for the object cap leaves the parent reading as complete (broken = %d)",
	     r.n >= 1u ? (int)r.o[0].broken : -1);
	er_free(&r);
	/* and a roomier cap is a view */
	opt.max_object_bytes = 8u << 20;
	scan(sc, o, n, &opt, &r);
	NCK(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewDecoded"));
	er_free(&r);
	free(o);
	kscan_free(sc);
}

static void produced_budget_under_a_chunk(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	kof_scanner *sc = kscan_new(e2e_eng);
	uint64_t n;

	CK(sc != NULL);
	if (!sc)
		return;
	base_fx(&f);
	f.gap_end = 40000;                                /* a 44 KB parent whose view is 4.4 KB */
	f.tail_n = make_tail(P_B64, tailb);
	f.tail = tailb;
	n = fx_elf(img, &f, &at);
	defaults(&opt, 0);
	opt.max_produced_bytes = 1000;
	scan(sc, img, n, &opt, &r);
	NCKF(r.n == 1u && !view_of(&r), "a produced budget of 1000: %u objects", r.n);
	NCK(has(&r.o[0], "NormViewEntry"));
	er_free(&r);
	opt.max_produced_bytes = 100000;
	scan(sc, img, n, &opt, &r);
	{
		const struct eo *v = view_of(&r);

		NCKF(r.n == 2u && v && v->len < 6000u && has(v, "NormViewDecoded"),
		     "a produced budget of 100000 and a 44 KB parent: %u objects", r.n);
	}
	er_free(&r);
	kscan_free(sc);
}

/* sixteen base64 characters decode to twelve bytes and leave four zeros: too few to
 * collapse, so the view is the parent rewritten in place - same length, same offsets */
static void one_for_one_view(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	char enc[64];
	uint8_t tail[128];
	size_t el, o = 0;
	uint64_t n;

	el = nr_b64_enc((const uint8_t *)"NormTiny-9ab", 12u, enc, 1, 0, 0);
	NCK(el == 16u);
	tail[o++] = '\n';
	memcpy(tail + o, "echo ", 5u);
	o += 5u;
	memcpy(tail + o, enc, el);
	o += el;
	memcpy(tail + o, " | base64 -d\n", 13u);
	o += 13u;
	base_fx(&f);
	f.tail = tail;
	f.tail_n = o;
	defaults(&opt, 0);
	n = fx_elf(img, &f, &at);
	scan(e2e_sc, img, n, &opt, &r);
	{
		const struct eo *v = view_of(&r);

		NCKF(r.n == 2u && v && has(v, "NormViewDecoded") && !has(&r.o[0], "NormViewDecoded"),
		     "a 1:1 view: %u objects", r.n);
		NCKF(v && v->len == n, "a 1:1 view keeps the length (%llu vs %llu)",
		     (unsigned long long)(v ? v->len : 0u), (unsigned long long)n);
		/* every byte before the payload is the parent's, and the entry rule still reads it */
		NCK(v && v->bytes && !memcmp(v->bytes, img, (size_t)at.tail_off));
		NCK(has(v, "NormViewEntry") && has(v, "NormViewData"));
	}
	er_free(&r);
	/* the same on a PE: its header padding is in no section, so that much collapses too */
	n = fx_pe(img, &f, &at);
	scan(e2e_sc, img, n, &opt, &r);
	NCKF(r.n == 2u && view_of(&r) && view_of(&r)->len <= n && has(view_of(&r), "NormViewDecodedPe"),
	     "a tiny-payload PE view: %u objects", r.n);
	er_free(&r);
}

/*
 * WHAT IS KEPT OF CODE. An instruction stream has no text in it to reveal and every
 * byte of it is somebody's operand, so an ELF's executable SECTIONS and a PE's
 * sections that are not writable come through the view byte for byte - a zero run
 * in them is not collapsed and a base64 payload in them is not decoded. A PE section
 * that is writable AND executable is a section the program rewrites, the shape of a
 * packed image, and its "instructions" are the whole program: that one is rewritten.
 */
static size_t code_with_text(uint8_t *c)
{
	size_t n = 0, o;
	uint8_t t[256];

	memcpy(c, FX_ENTRY_SIG, 12u);
	n = 12;
	memset(c + n, 0x90, 200);
	n += 200;
	memcpy(c + n, "KeepZ", 5u);                  /* a zero run inside the code, fenced */
	n += 5;
	memset(c + n, 0, 40);
	n += 40;
	memcpy(c + n, "KeepY", 5u);
	n += 5;
	o = make_tail(P_B64, t);                     /* a payload inside the code */
	memcpy(c + n, t, o);
	n += o;
	memset(c + n, 0x90, 3900);
	n += 3900;
	c[n++] = 0xc3;
	return n;
}

static void kept_code(void)
{
	static uint8_t code[8192];
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	unsigned mode;

	defaults(&opt, 0);
	for (mode = 0; mode < 3u; mode++) {
		/* 0 ELF with sections, 1 PE .text R+X, 2 PE .text R+W+X */
		const struct eo *v;
		size_t cn = code_with_text(code);
		int rewritten = mode == 2u;

		base_fx(&f);
		f.code = code;
		f.code_len = cn;
		f.text_flags = mode == 2u ? 0xe0000020u : 0u;
		f.tail_n = make_tail(P_WIDE, tailb);              /* something that makes a view */
		f.tail = tailb;
		scan_fx(&f, mode != 0u, &opt, &r, &at);
		v = view_of(&r);
		NCKF(r.n == 2u && v, "kept code, mode %u: %u objects", mode, r.n);
		if (v && v->bytes) {
			uint8_t fence[50];
			int zeros, decoded;

			memcpy(fence, "KeepZ", 5u);
			memset(fence + 5, 0, 40);
			memcpy(fence + 45, "KeepY", 5u);
			zeros = memmem(v->bytes, v->len, fence, sizeof fence) != NULL;
			decoded = memmem(v->bytes, v->len, CAN_B64, strlen(CAN_B64)) != NULL;

			if (!rewritten) {
				/* the whole section comes through untouched (a PE's header padding
				 * collapses ahead of it, so it is found, not looked up at its old offset) */
				NCKF(memmem(v->bytes, v->len, code, at.code_n) != NULL,
				     "mode %u: the kept code section changed", mode);
				NCKF(zeros && !decoded, "mode %u: zeros %d decoded %d", mode, zeros, decoded);
			} else {
				NCKF(!zeros && decoded, "mode 2 (writable code): zeros %d decoded %d", zeros, decoded);
			}
		}
		er_free(&r);
	}
}

/* ---- inherited analysis ------------------------------------------------------------------------ */

static void inherited_diagnose(void)
{
	/* the rwx_exec stager as the code of a two-segment ELF, with zeros before it:
	 * the collapse moves the code, and the view still says what the parent says */
	static uint8_t code[4096];
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	unsigned n_code = cf_stager64(code, 0), layout;
	static const uint32_t gaps[][4] = { { 0, 0, 0, 0 }, { 400, 0, 0, 0 }, { 0, 600, 0, 0 },
					    { 400, 600, 300, 700 } };

	defaults(&opt, 0);
	for (layout = 0; layout < 4u; layout++) {
		base_fx(&f);
		f.code = code;
		f.code_len = n_code;
		f.gap_text = gaps[layout][0];
		f.gap_code = gaps[layout][1];
		f.data_zeros = gaps[layout][2];
		f.gap_end = gaps[layout][3];
		f.tail_n = make_tail(P_B64, tailb);
		f.tail = tailb;
		/* pad the object past the floor through the data segment's zeros */
		f.gap_end += 4096u;
		scan_fx(&f, 0, &opt, &r, &at);
		NCKF(r.n == 2u, "layout %u: %u objects", layout, r.n);
		if (r.n == 2u && view_of(&r)) {
			const struct eo *v = view_of(&r);
			unsigned a;

			NCKF(r.o[0].n == v->n - (has(v, "NormViewDecoded") ? 1u : 0u),
			     "layout %u: the view's findings are the parent's plus the decoded one (%u vs %u)",
			     layout, v->n, r.o[0].n);
			for (a = 0; a < r.o[0].n && a < 10u; a++) {
				unsigned b, hit = 0;

				for (b = 0; b < v->n && b < 10u; b++)
					hit |= !strcmp(r.o[0].find[a], v->find[b]);
				NCKF(hit, "layout %u: finding [%s] of the parent is not on the view", layout,
				     r.o[0].find[a]);
			}
			NCKF(r.o[0].n > 0, "layout %u: the parent matched nothing", layout);
		}
		er_free(&r);
	}
}

/* ---- limits ------------------------------------------------------------------------------------ */

/* "x=" + the slashes of `s` percent-encoded `layers` times, then "&" */
static size_t pct_layers(unsigned layers, uint8_t *out)
{
	static uint8_t a[1u << 16], b[1u << 16];
	size_t n = 0, i;
	unsigned k;

	for (n = 0; n < 128u; n += 2u) {
		a[n] = (uint8_t)('a' + (n / 2u) % 26u);
		a[n + 1u] = '/';
	}
	for (k = 0; k < layers; k++) {
		size_t o = 0;

		for (i = 0; i < n; i++) {
			if (a[i] == '/' || a[i] == '%') {
				b[o++] = '%';
				b[o++] = '2';
				b[o++] = a[i] == '/' ? 'F' : '5';
			} else {
				b[o++] = a[i];
			}
		}
		memcpy(a, b, o);
		n = o;
	}
	out[0] = '\n';
	memcpy(out + 1, "x=", 2u);
	memcpy(out + 3, a, n);
	out[3 + n] = '&';
	out[4 + n] = '\n';
	return n + 5u;
}

static void limits_propagate(void)
{
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	unsigned layers, first = 0;
	static uint8_t tl[1u << 16];
	kof_scanner *sc = kscan_new(e2e_eng);

	CK(sc != NULL);
	if (!sc)
		return;
	defaults(&opt, 0);
	for (layers = 1; layers <= 60u; layers++) {
		base_fx(&f);
		f.tail = tl;
		f.tail_n = pct_layers(layers, tl);
		scan_fx(&f, 0, &opt, &r, &at);
		/* the decode budget is eight times the object; the view is made either way,
		 * and the parent says when a bound cut what it was read for */
		NCKF(r.n == 2u && view_of(&r), "layers %u: %u objects", layers, r.n);
		if (r.n >= 1u) {
			int limited = r.o[0].broken == KOF_BROKEN_LIMIT;

			if (limited && !first)
				first = layers;
			if (first && layers >= first)
				NCKF(limited, "layers %u: the limit went away", layers);
			if (!first)
				NCKF(r.o[0].broken == 0, "layers %u: broken %u without a limit", layers,
				     r.o[0].broken);
		}
		er_free(&r);
	}
	/* the object is small, so the same arithmetic as the unit test, a little earlier or
	 * later: the point is that it is reached and that nothing before it says it was */
	NCKF(first >= 8u && first <= 60u, "the limit first reaches the parent at %u layers", first);
	printf("  engine: decode budget first marks the parent BROKEN_LIMIT at %u layers\n", first);
	/* the scanner's counter moved once per limited object */
	NCKF(kscan_stats(sc)->limit_hits == 0u, "an unused scanner reports limit hits");
	{
		struct er r2;

		base_fx(&f);
		f.tail = tl;
		f.tail_n = pct_layers(first ? first : 30u, tl);
		(void)scan_fx(&f, 0, &opt, &r2, &at);
		er_free(&r2);
		(void)at;
		{
			uint64_t n = fx_elf(img, &f, &at);

			(void)scan(sc, img, n, &opt, &r2);
			NCK(kscan_stats(sc)->limit_hits >= 1u);
			er_free(&r2);
		}
	}
	kscan_free(sc);
}

/* ---- reuse and threads --------------------------------------------------------------------------- */

/*
 * THE SCANNERS ARE MADE BEFORE ANY THREAD STARTS, and that is the fix for a flake, not a style.
 *
 * Each thread used to call kscan_new itself. A scanner's memory share for an object is
 * (cap - database) / scanners ALIVE AT THAT MOMENT (kof_scan_root_share), and the first thread
 * to start an object, seeing two holders, took half of the engine's cap and kept it for the
 * length of the object; a thread that started later found only a few MB of room, got share 0,
 * and its 64 KB object was refused (broken=LIMIT, no view) - whenever the threads overlapped,
 * which is whenever the machine was loaded (about one run in six with twelve copies at once).
 * ThreadSanitizer finds no race in the engine on this test; its one report was the test's own
 * (main read job[k].ok before pthread_join). With the holders fixed first every thread's share
 * is the same fair slice and no run depends on timing. That a scanner made while others scan can
 * be starved is a product defect and is pinned in scan_share.c.
 */
struct job {
	unsigned    id;
	int         ok;
	kof_scanner *sc;
};

static void *worker(void *p)
{
	struct job *j = p;
	kof_scanner *sc = j->sc;
	unsigned rep;
	static const unsigned pay[4] = { P_B64, P_HEX, P_PCT, P_WIDE };

	j->ok = sc != NULL;
	for (rep = 0; sc && rep < 24u; rep++) {
		struct fx f;
		struct fx_at at;
		struct er r;
		struct kof_scan_option opt;
		uint8_t *buf = malloc(1u << 16), tail[600];
		uint64_t n;
		unsigned k = (rep + j->id) % 4u;

		memset(&f, 0, sizeof f);
		f.sections = (int)(rep & 1u);
		f.code_extra = 3900;
		f.gap_text = (rep % 3u) * 200u;
		f.gap_code = (rep % 2u) * 300u;
		f.tail_n = make_tail(pay[k], tail);
		f.tail = tail;
		n = (rep & 2u) ? fx_pe(buf, &f, &at) : fx_elf(buf, &f, &at);
		defaults(&opt, 0);
		scan(sc, buf, n, &opt, &r);
		j->ok &= r.n == 2u && view_of(&r) && has(view_of(&r), (rep & 2u) ? "NormViewDecodedPe" :
							"NormViewDecoded") &&
			 !has(&r.o[0], (rep & 2u) ? "NormViewDecodedPe" : "NormViewDecoded");
		er_free(&r);
		free(buf);
	}
	return NULL;
}

static void reuse_and_threads(void)
{
	pthread_t t[6];
	struct job job[6];
	int started[6];
	unsigned k;
	struct fx f;
	struct fx_at at;
	struct er r;
	struct kof_scan_option opt;
	kof_scanner *sc = kscan_new(e2e_eng);

	/* one scanner, objects of every kind in a row: no state leaks from one to the next */
	CK(sc != NULL);
	defaults(&opt, 0);
	for (k = 0; sc && k < 40u; k++) {
		uint64_t n;
		int viewed = (k % 3u) != 1u;

		base_fx(&f);
		f.gap_text = (k % 4u) * 100u;
		if (viewed) {
			f.tail_n = make_tail(k % 4u, tailb);
			f.tail = tailb;
		}
		n = (k & 1u) ? fx_pe(img, &f, &at) : fx_elf(img, &f, &at);
		scan(sc, img, n, &opt, &r);
		NCKF((r.n == 2u && view_of(&r) != NULL) == viewed, "reuse step %u: %u objects", k, r.n);
		if (view_of(&r))
			NCKF(has(view_of(&r), (k & 1u) ? "NormViewDecodedPe" : "NormViewDecoded"),
			     "reuse step %u: the view lost its finding", k);
		NCKF(!has(&r.o[0], "NormViewDecoded"), "reuse step %u: parent matched", k);
		er_free(&r);
	}
	if (sc)
		kscan_free(sc);
	for (k = 0; k < 6u; k++) {
		job[k].id = k;
		job[k].ok = 0;
		job[k].sc = kscan_new(e2e_eng);
	}
	for (k = 0; k < 6u; k++)                /* every holder exists before the first scan starts */
		started[k] = job[k].sc != NULL && pthread_create(&t[k], NULL, worker, &job[k]) == 0;
	for (k = 0; k < 6u; k++) {
		if (started[k])
			pthread_join(t[k], NULL);       /* job[k].ok is read only after this */
		if (job[k].sc)
			kscan_free(job[k].sc);
		NCKF(started[k] && job[k].ok == 1, "thread %u got a wrong answer", k);
	}
}

/* ---- scripts ---------------------------------------------------------------------------------------- */

static void script_scan(const char *text, unsigned heur, struct er *r)
{
	struct kof_scan_option opt;

	defaults(&opt, heur);
	scan(e2e_sc, (const uint8_t *)text, strlen(text), &opt, r);
}

static void scripts(void)
{
	char enc[256], hex[256], pct[512], text[2048];
	struct er r;
	unsigned heur;
	size_t el;

	el = nr_b64_enc((const uint8_t *)"NormScriptB64-a1f0c2", 20u, enc, 1, 0, 0);
	enc[el] = 0;
	for (heur = 0; heur <= 2u; heur++) {
		snprintf(text, sizeof text, "#!/bin/sh\n# a dropper\n  echo %s | base64 -d | sh\n\n\n  rm -f /tmp/x\n"
			 "  ls   -la\n   exit 0\n", enc);
		script_scan(text, heur, &r);
		NCKF(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewScript") && !has(&r.o[0], "NormViewScript"),
		     "shell + base64, heur %u: %u objects", heur, r.n);
		er_free(&r);
	}
	el = nr_hex_enc((const uint8_t *)"NormScriptHEX-77d5e8", 20u, hex, 0);
	hex[el] = 0;
	snprintf(text, sizeof text, "#!/bin/sh\n  CMD=\"%s\"\n\n  run   $CMD\n   rm -f /tmp/x\n   exit 0\n", hex);
	script_scan(text, 1, &r);
	NCKF(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewScript") && !has(&r.o[0], "NormViewScript"),
	     "shell + hex: %u objects", r.n);
	er_free(&r);
	el = nr_pct_enc((const uint8_t *)"wget http://x/NormScriptPCT-04b9aa;x", 36u, pct, 1);
	pct[el] = 0;
	snprintf(text, sizeof text, "#!/bin/sh\n   curl -d 'Cmd=%s&y=1' http://host/\n\n\n   exit 0\n", pct);
	script_scan(text, 1, &r);
	NCKF(r.n == 2u && view_of(&r) && has(view_of(&r), "NormViewScript") && !has(&r.o[0], "NormViewScript"),
	     "shell + percent: %u objects", r.n);
	er_free(&r);
	/* no view for a script that has nothing to say plainly and is already tight */
	script_scan("#!/bin/sh\nls\n", 1, &r);
	NCKF(!view_of(&r), "a tight script was viewed (%u objects)", r.n);
	er_free(&r);
	/* a string built from pieces: only the fold - level 2 - puts it together, and only
	 * when what it builds is most of the file and was not written out whole */
	snprintf(text, sizeof text,
		 "<?php\n$a = 'NormScriptFOLD-9e61d3-bu';\n$b = 'ilt-from-pieces';\n$c = 'pad-pad-pad-pad-pad-p';\n"
		 "$d = $a . $b . $c . 'ad-pad-pad-pad-pad';\n");
	script_scan(text, 1, &r);
	{
		unsigned i, found = 0;

		for (i = 0; i < r.n; i++)
			found |= (unsigned)has(&r.o[i], "NormViewScript");
		NCKF(!found, "the fold ran at heuristic level 1");
	}
	er_free(&r);
	script_scan(text, 2, &r);
	{
		const struct eo *v = view_of(&r);

		NCKF(v && has(v, "NormViewScript") && !has(&r.o[0], "NormViewScript"),
		     "the fold at heuristic level 2: %u objects", r.n);
	}
	er_free(&r);
}

int main(void)
{
	if (!e2e_open(NULL)) {
		printf("normalizer_engine: cannot open the test database\n");
		return 2;
	}
	layout_matrix();
	nested_layers();
	many_marks();
	not_made();
	dense_code();
	decode_undone_by_keep();
	budget_gates();
	kept_code();
	inherited_diagnose();
	big_views();
	produced_budget_under_a_chunk();
	one_for_one_view();
	limits_propagate();
	reuse_and_threads();
	scripts();
	printf("normalizer_engine: %u checks, %u failed, %d old-style failed\n",
	       nr_ok + nr_bad, nr_bad, fails);
	return nr_bad != 0 || fails != 0;
}
