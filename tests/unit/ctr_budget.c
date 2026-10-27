/*
 * ctr_budget - the limits of the container walk, one writer per format: which bound applies to which kind of child, that
 * a hit is REPORTED, and that the walk goes on to the entries after a cut entry.
 *
 * Two kinds of child (kofoption.h, "A child that is a window into its parent costs none of the three"):
 *   WINDOW     a stored member of zip, tar, rar, lha, arj, chm, pdf: nothing is produced, so max_object_bytes and
 *              max_produced_bytes do not apply to it; max_children and the layer allowance do
 *   PRODUCED   a decoded member (cab folder, 7z folder, a gzip stream, the gathered OLE body): charged to all three
 *
 * ROWS (members [s1 1000 bytes, BIG 3 MiB, s2 900 bytes]):
 *   window formats        BIG is opened whole under max_object_bytes = 1 MiB and max_produced_bytes = 1 MiB, nothing reported
 *   object cap, produced  BIG is cut at exactly the cap and the CUT CHILD carries KOF_BROKEN_LIMIT, limit_hits counts it, and the
 *                         member AFTER it is walked (cab, 7z); gzip's one stream is cut the same way; the OLE body is
 *                         reported (kofeng/CLAUDE.md rule 4: an entry's own bound is not the tree's)
 *   produced budget       the bytes of the tree stay under max_produced_bytes (1 MiB) and the stop is said, on an object
 *   child quota           max_children = 1: never more than one child, and members lost are said (a LIMIT object)
 *   resident ceiling      max_resident_bytes = 4 MiB: peak_resident stays under it, and a refusal is said
 *   tail after a cut      [s, BIG over the cap, 2000 members of 100 bytes]: the 2000 are all walked (cab, 7z). This is the
 *                         84 MB archive / 91 MB member lesson of kofeng/CLAUDE.md, at 1/40 of the size
 *   window allowance      a chain of 64 zips around a leaf of S MiB: the windows may total at most root + max_produced_bytes
 *                         (the ledger's window_left); past it the walk is cut at that depth and a LIMIT object says so (the depth
 *                         allowance, 64 MiB over the size, cuts a chain at the same depth, so a WIDE case is the one that
 *                         isolates the ledger: window fan, 100 zip members sharing one 2 MiB run)
 *   zip deflated cut      the streaming-sink path of the same rule: a deflated member over the cap is cut, and 2000 members
 *                         after it are walked (the other rows' cab and 7z reach oc_entry_cut by another road)
 *
 * Why the old tests missed them: hostile_engine_archives.c builds these cases for zip only, and zip is a WINDOW format, so its
 * "object cap" rows never reached the cut-entry path that cab, 7z and gzip have.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

#define MB (1024ull * 1024ull)

static uint8_t big[3u << 20], sm[1000], tail[100];

static int is_window(const struct cw_format *F)
{
	return !strcmp(F->name, "zip") || !strcmp(F->name, "tar") || !strcmp(F->name, "rar") || !strcmp(F->name, "rar5") || !strcmp(F->name, "lha") ||
	       !strcmp(F->name, "arj") || !strcmp(F->name, "chm") || !strcmp(F->name, "pdf");
}

static int has_hash(const struct cs_run *r, uint64_t h)
{
	unsigned i;

	for (i = 1; i < r->n && i < CS_MAXOBJ; i++)
		if (r->o[i].hash == h)
			return 1;
	return 0;
}

static unsigned children(const struct cs_run *r)
{
	return r->n ? r->n - 1u : 0u;
}

static int one_format(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p;
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[3];
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o;
	unsigned n = F->max_members == 1 ? 1u : 3u, i;
	uint64_t hs1, hs2, hbig;
	int win = is_window(F), produced_cut = !strcmp(F->name, "cab") || !strcmp(F->name, "7z");

	cs_fill(big, sizeof big, 7);
	cs_fill(sm, sizeof sm, 1);
	hs1 = cs_fnv(sm, sizeof sm);
	hs2 = cs_fnv(sm, 900);
	hbig = cs_fnv(big, sizeof big);
	memset(e, 0, sizeof e);
	e[0].name = "s1";  e[0].data = sm;  e[0].len = sizeof sm;
	e[1].name = "BIG"; e[1].data = big; e[1].len = sizeof big;
	e[2].name = "s2";  e[2].data = sm;  e[2].len = 900;
	if (n == 1)
		e[0] = e[1];
	F->write(&w, e, n, NULL, NULL);

	/* ---- object cap 1 MiB ---- */
	o = cs_opt();
	o.max_object_bytes = 1 * MB;
	if (cs_scan(w.p, w.n, "b.x", &o, &r))
		return 9;
	if (win) {
		CK(has_hash(&r, hbig) && has_hash(&r, hs1) && has_hash(&r, hs2), "%s: a window member is opened whole under a 1 MiB object cap", F->name);
		CK(r.broken == 0 && r.limit_hits == 0, "%s: and nothing is reported (windows cost none of the budgets)", F->name);
	} else if (!strcmp(F->name, "ole")) {
		CK(r.broken_limit >= 1 && r.limit_hits >= 1, "ole: the body over the cap is reported (%llu LIMIT objects, %llu hits)", (unsigned long long)r.broken_limit, (unsigned long long)r.limit_hits);
		CK(children(&r) == 1 && r.o[1].len >= 1900, "ole: what fits is kept (%llu bytes)", children(&r) ? (unsigned long long)r.o[1].len : 0ull);
	} else if (!strcmp(F->name, "gzip")) {
		CK(children(&r) == 1 && r.o[1].len == 1 * MB && r.o[1].broken == KOF_BROKEN_LIMIT, "gzip: the stream is cut at the cap and the child says Limit (%llu bytes, broken %u)",
		   children(&r) ? (unsigned long long)r.o[1].len : 0ull, children(&r) ? r.o[1].broken : 0u);
		CK(r.limit_hits >= 1, "gzip: limit_hits counts the cut (%llu)", (unsigned long long)r.limit_hits);
	} else {
		unsigned cutn = 0;

		for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
			if (r.o[i].len == 1 * MB && r.o[i].broken == KOF_BROKEN_LIMIT)
				cutn++;
		CK(cutn == 1, "%s: BIG is cut at exactly the cap and the cut child says Limit (%u such children)", F->name, cutn);
		CK(r.limit_hits >= 1, "%s: limit_hits counts the cut (%llu)", F->name, (unsigned long long)r.limit_hits);
		CK(has_hash(&r, hs1) && has_hash(&r, hs2), "%s: the members before AND AFTER the cut one are walked", F->name);
	}
	cs_free(&r);

	/* ---- produced-bytes budget 1 MiB ---- */
	o = cs_opt();
	o.max_produced_bytes = 1 * MB;
	if (cs_scan(w.p, w.n, "b.x", &o, &r))
		return 9;
	if (win) {
		CK(has_hash(&r, hbig) && r.broken == 0, "%s: a window member is outside the produced-bytes budget", F->name);
	} else {
		CK(r.child_bytes <= 1 * MB, "%s: the tree produced %llu bytes under a 1 MiB budget", F->name, (unsigned long long)r.child_bytes);
		CK(r.broken_limit >= 1, "%s: the stop is said on an object (%llu LIMIT objects)", F->name, (unsigned long long)r.broken_limit);
	}
	cs_free(&r);

	/* ---- child quota of 1 ---- */
	o = cs_opt();
	o.max_children = 1;
	if (cs_scan(w.p, w.n, "b.x", &o, &r))
		return 9;
	CK(children(&r) <= 1, "%s: max_children = 1 gave %u children", F->name, children(&r));
	if (n == 3 && !F->gathered)
		CK(r.broken_limit >= 1, "%s: the members the quota refused are said (%llu LIMIT objects)", F->name, (unsigned long long)r.broken_limit);
	cs_free(&r);

	/* ---- resident ceiling 4 MiB ---- */
	o = cs_opt();
	o.max_resident_bytes = 4 * MB;
	if (cs_scan(w.p, w.n, "b.x", &o, &r))
		return 9;
	CK(r.peak <= 4 * MB, "%s: peak resident %llu inside a 4 MiB ceiling", F->name, (unsigned long long)r.peak);
	if (!win && !F->gathered && children(&r) < n + F->lead)
		CK(r.broken_limit >= 1, "%s: a member refused by the ceiling is said", F->name);
	cs_free(&r);
	cw_free(&w);

	/* ---- tail after a cut entry ---- */
	if (produced_cut) {
		enum { TAILN = 2000 };
		struct cw_ent *t = (struct cw_ent *)calloc(2u + TAILN, sizeof *t);
		unsigned found = 0;
		uint64_t ht;

		if (!t)
			return 9;
		cs_fill(tail, sizeof tail, 5);
		ht = cs_fnv(tail, sizeof tail);
		t[0].name = "head"; t[0].data = sm; t[0].len = sizeof sm;
		t[1].name = "BIG";  t[1].data = big; t[1].len = sizeof big;
		for (i = 0; i < TAILN; i++) {
			t[2u + i].name = "t";
			t[2u + i].data = tail;
			t[2u + i].len = sizeof tail;
		}
		F->write(&w, t, 2u + TAILN, NULL, NULL);
		o = cs_opt();
		o.max_object_bytes = 1 * MB;
		if (cs_scan(w.p, w.n, "t.x", &o, &r))
			return 9;
		for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
			found += r.o[i].hash == ht && r.o[i].len == sizeof tail;
		CK(found == TAILN, "%s: %u of the %d members after the cut entry were walked", F->name, found, (int)TAILN);
		CK(r.limit_hits >= 1, "%s: and the cut entry was counted (%llu)", F->name, (unsigned long long)r.limit_hits);
		cs_free(&r);
		cw_free(&w);
		free(t);
	}
	return he_fails != 0 ? 1 : 0;
}

/* ---- window allowance ----------------------------------------------------------------------------- */

static int window_allowance(void *unused)
{
	static const unsigned sz[] = { 1, 2, 4, 8 };
	static uint8_t leaf[8u << 20];
	unsigned i, k, zip = cw_find("zip");

	(void)unused;
	for (i = 0; i < sizeof sz / sizeof sz[0]; i++) {
		struct cw cur = { 0 }, nxt;
		struct cs_run r;
		struct kof_scan_option o = cs_opt();
		size_t ln = (size_t)sz[i] << 20;
		uint64_t total = 0, allow;
		unsigned j;

		cs_fill(leaf, ln, 3);
		cw_put(&cur, leaf, ln);
		for (k = 0; k < 64; k++) {
			nxt = cw_wrap(zip, &cur);
			cw_free(&cur);
			cur = nxt;
		}
		allow = (uint64_t)cur.n + o.max_produced_bytes;
		if (cs_scan(cur.p, cur.n, "w.zip", &o, &r))
			return 9;
		for (j = 1; j < r.n && j < CS_MAXOBJ; j++)
			total += r.o[j].len;
		printf("  window chain, leaf %u MiB x 64: %u objects, deepest %u, windows %llu of %llu allowed, limit objects %llu\n", sz[i], r.n, r.max_depth,
		       (unsigned long long)total, (unsigned long long)allow, (unsigned long long)r.broken_limit);
		CK(total <= allow, "window chain %u MiB: the windows total %llu, past root + produced budget %llu", sz[i], (unsigned long long)total, (unsigned long long)allow);
		if (r.max_depth < 64)
			CK(r.broken_limit == 1 && r.o[r.n - 1u].broken == KOF_BROKEN_LIMIT, "window chain %u MiB: cut at depth %u and the deepest object says Limit (%llu)", sz[i], r.max_depth,
			   (unsigned long long)r.broken_limit);
		else
			CK(r.broken == 0, "window chain %u MiB: reached 64 and nothing is reported", sz[i]);
		cs_free(&r);
		cw_free(&cur);
	}
	return he_fails != 0 ? 1 : 0;
}

/* A WIDE window bomb: 100 members of one zip that SHARE one 2 MiB data run (a 2 MiB file of a few KB of headers... plus the 2 MiB).
 * The depth allowance does not see it (one level) and the quota does not (100 children); the window allowance does:
 * the windows may total root + max_produced_bytes (about 66 MiB) and the rest are refused and said. */
static int window_fan(void *unused)
{
	enum { N = 100 };
	static uint8_t leaf[2u << 20];
	struct cw_ent *e = (struct cw_ent *)calloc(N, sizeof *e);
	static char nm[N][8];
	struct cw w = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	uint64_t total = 0, allow;
	unsigned i;

	(void)unused;
	if (!e)
		return 9;
	cs_fill(leaf, sizeof leaf, 3);
	for (i = 0; i < N; i++) {
		snprintf(nm[i], sizeof nm[i], "w%u", i);
		e[i].name = nm[i];
		e[i].data = leaf;
		e[i].len = sizeof leaf;
		e[i].share = i ? 1 : 0;
	}
	cw_zip(&w, e, N, NULL, NULL);
	allow = (uint64_t)w.n + o.max_produced_bytes;
	if (cs_scan(w.p, w.n, "fan.zip", &o, &r))
		return 9;
	for (i = 1; i < r.n && i < CS_MAXOBJ; i++)
		total += r.o[i].len;
	printf("  window fan: %zu byte zip, %u members of 2 MiB opened of %d, windows %llu of %llu allowed, limit objects %llu\n", w.n, r.n - 1u, (int)N,
	       (unsigned long long)total, (unsigned long long)allow, (unsigned long long)r.broken_limit);
	CK(total <= allow, "window fan: the windows total %llu, past root + produced budget %llu", (unsigned long long)total, (unsigned long long)allow);
	CK(r.n - 1u < N && r.broken_limit >= 1, "window fan: the members past the allowance are refused and said (%u opened, %llu LIMIT objects)", r.n - 1u,
	   (unsigned long long)r.broken_limit);
	cs_free(&r);
	cw_free(&w);
	free(e);
	return he_fails != 0 ? 1 : 0;
}

/* A zip member DEFLATED over the object cap is a produced child (the streaming sink, not a window): it is cut at the cap, the cut
 * child says Limit, and the members after it, 2000 of them, are walked. This is the path oc_stream_note takes (STOPPED is the sink
 * refusing the entry, not the tree). */
static int zip_deflated_cut(void *unused)
{
	enum { TAILN = 2000 };
	struct cw_ent *e = (struct cw_ent *)calloc(2u + TAILN, sizeof *e);
	struct cw w = { 0 }, df = { 0 };
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	uint8_t t[100];
	uint64_t ht;
	unsigned i, found = 0, cut = 0;

	(void)unused;
	if (!e)
		return 9;
	cs_fill(big, sizeof big, 7);
	cs_fill(t, sizeof t, 5);
	ht = cs_fnv(t, sizeof t);
	cw_deflate_stored(&df, big, sizeof big);
	e[0].name = "head"; e[0].data = sm; e[0].len = sizeof sm;
	e[1].name = "BIG";  e[1].data = df.p; e[1].len = df.n; e[1].method = 8;
	e[1].claimed = 1; e[1].claim_packed = df.n; e[1].claim_unpacked = sizeof big;
	for (i = 0; i < TAILN; i++) {
		e[2u + i].name = "t";
		e[2u + i].data = t;
		e[2u + i].len = sizeof t;
	}
	cw_zip(&w, e, 2u + TAILN, NULL, NULL);
	o.max_object_bytes = 1 * MB;
	if (cs_scan(w.p, w.n, "d.zip", &o, &r))
		return 9;
	for (i = 1; i < r.n && i < CS_MAXOBJ; i++) {
		found += r.o[i].hash == ht && r.o[i].len == sizeof t;
		cut += r.o[i].len == 1 * MB && r.o[i].broken == KOF_BROKEN_LIMIT;
	}
	CK(cut == 1, "zip deflated: the member over the cap is cut at the cap and says Limit (%u such children)", cut);
	CK(found == TAILN, "zip deflated: %u of the %d members after the cut entry were walked", found, (int)TAILN);
	CK(r.limit_hits >= 1, "zip deflated: the cut entry is counted (%llu)", (unsigned long long)r.limit_hits);
	cs_free(&r);
	cw_free(&w);
	cw_free(&df);
	free(e);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	unsigned f, bad = 0;
	struct he_status st;

	cs_eng = keng_open(HE_DB);
	for (f = 0; f < CW_NFORMATS; f++) {
		st = he_child(one_format, (void *)(uintptr_t)f, 240);
		printf("budget %-5s %s\n", cw_formats[f].name, he_how(st));
		bad |= !he_ok(st);
	}
	st = he_child(window_allowance, NULL, 240);
	printf("budget window allowance %s\n", he_how(st));
	bad |= !he_ok(st);
	st = he_child(window_fan, NULL, 240);
	printf("budget window fan %s\n", he_how(st));
	bad |= !he_ok(st);
	st = he_child(zip_deflated_cut, NULL, 240);
	printf("budget zip deflated cut %s\n", he_how(st));
	bad |= !he_ok(st);
	printf("ctr_budget: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
