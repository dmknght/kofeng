/*
 * container/walk - the whole engine over a container: kscan_bytes on the bytes, the real parsers, unpackers, budgets and
 * object tree, with the database of build/release/databases (make databases first).
 *
 * Seeds: every format's writer archive (valid and with each lie, tests/fuzz/container/ctr_seeds.h, field maps included), the
 * nesting chains (zip > tar > pdf > ole ..., and every format wrapped around one leaf), polyglots (one format's file followed
 * by another's) and a magic of one format laid over the body of another. The mutators move the declared sizes, counts and
 * offsets the writers publish, then the bytes.
 *
 * Held, on every input: the scan answers; no object name has a path separator or a control byte in its leaf (a name a member
 * chose is never a path or a forged object separator); no object is deeper than the layer allowance (64); the objects are at
 * most the children quota; the bytes produced below the root stay inside max_produced_bytes plus the windows the root can
 * hold (windows cost nothing, so only produced objects are counted: the object's own length when it is not a window of the
 * input is not knowable here, so the bound used is the quota's: objects times the largest window); the peak resident stays
 * under the scan's ceiling; a KOF_BROKEN_LIMIT is on some object whenever a count was cut; the digest of (depth, length,
 * broken) of every object is the same when the same bytes are scanned again (the driver checks) and when the k-th allocation
 * fails the answer is a subset or says why (a status, or a broken object).
 */
#include <kofmod/kofsig.h>
#include "../../../libkofeng/kofeng.h"
#include "../../../libkofeng/kofcore/kofobjname.h"

#include "ctr_seeds.h"
#include "../../lib/ctr_check.h"

static kof_engine *eng;

#define W_RESIDENT (24ull << 20)
#define W_PRODUCED (8ull << 20)
#define W_OBJECT   (4ull << 20)

static void seed_chain(struct fz_corpus *c, const char *what, const char *const *fmts, unsigned n)
{
	struct cw cur, nxt;
	unsigned k;
	static const char leaf[] = "leaf-leaf-leaf-leaf-leaf-leaf";

	memset(&cur, 0, sizeof cur);
	cw_put(&cur, leaf, sizeof leaf - 1u);
	for (k = 0; k < n; k++) {
		unsigned f = cw_find(fmts[k]);

		if (f >= CW_NFORMATS)
			continue;
		nxt = cw_wrap(f, &cur);
		cw_free(&cur);
		cur = nxt;
	}
	csd_add(c, "chain", what, &cur, NULL);
	cw_free(&cur);
}

/* An overlap bomb: a zip of two members that share ONE data run, wrapping a zip of the same shape, `depth` times (the file stays a few KB, the tree
 * would hold 2^depth leaves), and a chain of `chain` single-member zips (past the layer allowance of 64). The mutators then move the sizes and
 * offsets of the outermost zip; what is checked is that the walk stops at the children quota and the allowance and says so. */
static void seed_bomb(struct fz_corpus *c, unsigned depth, unsigned chain)
{
	struct cw cur, nxt;
	struct cw_map m;
	static const char leaf[] = "leaf-leaf-leaf-leaf-leaf-leaf";
	unsigned k, zip = cw_find("zip");
	char nm[24];

	memset(&cur, 0, sizeof cur);
	memset(&m, 0, sizeof m);
	cw_put(&cur, leaf, sizeof leaf - 1u);
	for (k = 0; k < depth; k++) {
		struct cw_ent e[2];

		memset(e, 0, sizeof e);
		memset(&nxt, 0, sizeof nxt);
		memset(&m, 0, sizeof m);
		e[0].name = "a"; e[0].data = cur.p; e[0].len = cur.n;
		e[1].name = "b"; e[1].data = cur.p; e[1].len = cur.n; e[1].share = 1;
		cw_zip(&nxt, e, 2, NULL, &m);
		cw_free(&cur);
		cur = nxt;
	}
	snprintf(nm, sizeof nm, "bomb%u", depth);
	csd_add(c, "overlap", nm, &cur, &m);
	cw_free(&cur);
	memset(&cur, 0, sizeof cur);
	cw_put(&cur, leaf, sizeof leaf - 1u);
	for (k = 0; k < chain; k++) {
		nxt = cw_wrap(zip, &cur);
		cw_free(&cur);
		cur = nxt;
	}
	snprintf(nm, sizeof nm, "chain%u", chain);
	csd_add(c, "layers", nm, &cur, NULL);
	cw_free(&cur);
}

static void seeds(struct fz_corpus *c)
{
	static const char *const c1[] = { "zip", "tar", "pdf", "ole" };
	static const char *const c2[] = { "gzip", "7z", "cab", "chm", "zip" };
	static const char *const c3[] = { "rar", "lha", "arj", "tar", "zip", "gzip" };
	unsigned f, a, b;
	struct cw file[CW_NFORMATS];

	for (f = 0; f < CW_NFORMATS; f++)
		csd_format(c, f);
	seed_chain(c, "zip-tar-pdf-ole", c1, 4);
	seed_chain(c, "gzip-7z-cab-chm-zip", c2, 5);
	seed_chain(c, "rar-lha-arj-tar-zip-gzip", c3, 6);
	seed_bomb(c, 12, 70);
	for (f = 0; f < CW_NFORMATS; f++) {
		static uint8_t d[200];
		struct cw_ent e;

		memset(&file[f], 0, sizeof file[f]);
		memset(d, 'q', sizeof d);
		memset(&e, 0, sizeof e);
		e.name = "x";
		e.data = d;
		e.len = sizeof d;
		cw_formats[f].write(&file[f], &e, 1, NULL, NULL);
	}
	for (a = 0; a < CW_NFORMATS; a += 2)             /* polyglots: A's file followed by B's, and A's head over B's body */
		for (b = 1; b < CW_NFORMATS; b += 3) {
			struct cw x;
			char nm[16];

			if (a == b)
				continue;
			memset(&x, 0, sizeof x);
			cw_put(&x, file[a].p, file[a].n);
			cw_put(&x, file[b].p, file[b].n);
			snprintf(nm, sizeof nm, "%u-%u", a, b);
			csd_add(c, "polyglot", nm, &x, NULL);
			cw_free(&x);
			memset(&x, 0, sizeof x);
			cw_put(&x, file[b].p, file[b].n);
			{
				size_t span = file[a].n < 16u ? file[a].n : 16u;

				memcpy(x.p, file[a].p, span < x.n ? span : x.n);
			}
			csd_add(c, "headswap", nm, &x, NULL);
			cw_free(&x);
		}
	for (f = 0; f < CW_NFORMATS; f++)
		cw_free(&file[f]);
	/* open the engine now: the driver's leak check counts what a CALL allocates, and the database is not a call's */
	eng = keng_open("build/release/databases");
	if (eng) {
		kof_scanner *sc = kscan_new(eng);

		if (sc) {                                /* one scan to build every lazy table of the engine */
			struct kof_scan_option o;

			memset(&o, 0, sizeof o);
			o.heur_level = 1;
			o.recurse_dirs = 1;
			(void)kscan_bytes(sc, "PK\003\004", 4, "warm", &o, NULL, NULL);
			kscan_free(sc);
		}
	}
}

struct wk {
	struct fz_ctx *c;
	unsigned       n, deepest;
	uint64_t       limit_objs, produced_est;
};

static int wk_cb(const char *name, const void *b, uint64_t len, const struct kof_result *res, void *user)
{
	struct wk *w = (struct wk *)user;
	uint32_t d = kobj_depth(name);
	const char *leaf = name, *q;

	(void)b;
	w->n++;
	fz_step(&w->c->steps, 1);
	for (q = name; *q; q++)
		if (q[0] == '/' && q[1] == '/')
			leaf = q + 2;
	if (d > 0)
		for (q = leaf; *q; q++)
			if (*q == '/' || *q == '\\' || (uint8_t)*q < 0x20) {
				FZ_CHECK(w->c, 0, "a child's name carries a path separator or a control byte");
				break;
			}
	if (d > w->deepest)
		w->deepest = d;
	if (res && res->broken == KOF_BROKEN_LIMIT)
		w->limit_objs++;
	fz_digest(w->c, ((uint64_t)d << 56) ^ (len * 0x9e3779b97f4a7c15ull) ^ (res ? res->broken : 0u));
	return 0;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	kof_scanner *sc;
	struct kof_scan_option o;
	struct wk w;
	int rc;

	if (!eng) {
		FZ_CHECK(c, 0, "no database: run `make databases` first (build/release/databases)");
		return 0;
	}
	sc = kscan_new(eng);
	if (!sc) {
		fz_digest(c, 0xbad);
		return -1;
	}
	memset(&o, 0, sizeof o);
	memset(&w, 0, sizeof w);
	w.c = c;
	o.heur_level = 1;
	o.recurse_dirs = 1;
	o.max_resident_bytes = W_RESIDENT;
	o.max_produced_bytes = W_PRODUCED;
	o.max_object_bytes = W_OBJECT;
	rc = kscan_bytes(sc, in, n, "fuzz.x", &o, wk_cb, &w);
	FZ_CHECK(c, w.deepest <= 64u, "an object deeper than the layer allowance of 64");
	FZ_CHECK(c, w.n <= (n / 5u > 4096u ? n / 5u : 4096u) + 2u, "more objects than the children quota allows");
	FZ_CHECK(c, kscan_stats(sc)->peak_resident <= W_RESIDENT + (4ull << 20), "peak resident past the ceiling");
	fz_digest(c, (uint64_t)(unsigned)rc ^ ((uint64_t)w.n << 20) ^ w.limit_objs);
	kscan_free(sc);
	return rc;
}

static const char *const dict[] = { "PK\003\004", "PK\001\002", "PK\005\006", "Rar!\x1a\x07", "7z\xbc\xaf\x27\x1c", "MSCF", "ITSF", "ITSP", "PMGL",
				    "%PDF-1.", "endstream", "stream\n", "xref", "startxref", "\x60\xea", "-lh0-", "-lh5-", "ustar", "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
				    "../", "\x1f\x8b\x08", NULL };

/* FZ_MAY_HIT_CAP: a RAR3 PPMd block asks for a 64 MiB arena and libuncoat callocs it without asking the scan's ledger (WP2-D12,
 * tests/unit/ctr_resources.c has it as a KM_CHECK): under this row's 24 MiB ceiling that is an allocation past the driver's caps. The hits are
 * counted in the summary line ("cap-hits") and are the only ones the flag hides. */
FZ_ADAPTER(cw_walk, .name = "container/walk", .shape = FZ_REQ, .flags = FZ_MAY_HIT_CAP, .seeds = seeds, .dict = dict, .run = run,
	   .steps_base = 200000, .steps_per_byte = 200, .backstop_s = 120);
