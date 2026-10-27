/*
 * ctr_liars - containers whose HEADERS lie, one writer per format (tests/lib/ctr_writers.h), through the whole engine.
 *
 * The matrix is format x lie, 11 x 9, each cell a three member archive (gzip: one) written truthfully except for the lie:
 *
 *   clean      the control: every member is opened, nothing is reported
 *   claimBoth  the middle member's headers say 4 GB packed AND unpacked (data written: 200 bytes)
 *   claimPack  ... only the packed size
 *   claimUnp   ... only the unpacked size (a ratio lie: 200 bytes "inflating" to 4 GB)
 *   share      the last member's header points at the FIRST member's data (overlap)
 *   count      the declared number of members / chunks / blocks is 60000
 *   offset     the declared directory / next header / content offset is past the end of the file
 *   cycle      the directory / chain / xref points back at itself
 *   noend      the terminator (end block, EOCD, trailer) is left out
 *
 * What a cell asserts, and why that is the contract and not a snapshot:
 *   - NEVER a crash, a hang or a read past the object (a forked child, an alarm, a guard page, ASAN in the other build);
 *   - NEVER a child longer than the container that held it (stored formats cannot make bytes), and never the same answer
 *     twice differently (the matrix is scanned twice per cell; every object name, length and hash must repeat);
 *   - the walk's answer is the table's: how many members were opened and whether the engine SAID something (a broken
 *     reason on some object, or a limit hit). The table is the measured behaviour of this tree, so a change in either
 *     number is red and has to be looked at;
 *   - and, written as the expectation, three kinds of defect the matrix found are KM_CHECKs (known_miss.h): green while
 *     the engine has the defect, RED the day it is fixed so the marker comes out.
 *       WP2-D1  a member lost with nothing said (lha, arj: a size past the end ends the walk with broken = 0)
 *       WP2-D2  a member dropped from the table with nothing said (cab, chm: a file whose size runs past its data)
 *       WP2-D3  an archive that opens as nothing with nothing said (zip, cab, chm: a directory offset past the end)
 *       WP2-D4  a stored zip member whose header claims more than the file holds is a child of the bytes up to the END of
 *               the file (the sibling's data and the central directory included) and no anomaly is raised
 *       WP2-D5  7z: the folder after one whose declared unpack size is over the budget is lost (a bound of ONE entry
 *               ended the walk: kofeng/CLAUDE.md rule 4, "an entry's own bound is not the tree's")
 *
 *       WP2-D13 lha, arj: a member that cannot be decoded ends the module's walk (zip and rar go on to the members after it); see
 *               coded_first() below
 *
 * Why the old tests missed them: hostile_engine_archives.c has a lying writer for zip only, and the *_walk tests use
 * fixtures whose claims are on the first member (c: executed without a boundary input for the later members).
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

enum { S_CLEAN, S_BOTH, S_PACK, S_UNP, S_SHARE, S_COUNT, S_OFFSET, S_CYCLE, S_NOEND, NSC };
static const char *const sname[NSC] = { "clean", "claimBoth", "claimPack", "claimUnp", "share", "count", "offset", "cycle", "noend" };

/* km: 0 nothing; 1 D1/D2/D3 silent loss; 2 D4 clamp; 3 D5 sibling after a cut */
struct exp { signed char found, rep, km; };

#define E(f, r, k) { f, r, k }
static const struct exp tab[CW_NFORMATS][NSC] = {
	/* zip  */ { E(3,0,0), E(3,0,2), E(3,0,2), E(3,0,0), E(3,0,0), E(3,0,0), E(0,0,1), E(0,0,1), E(0,0,0) },
	/* tar  */ { E(3,0,0), E(1,1,0), E(3,0,0), E(1,1,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) },
	/* rar  */ { E(3,0,0), E(1,1,0), E(1,1,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) },
	/* lha  */ { E(3,0,0), E(1,0,1), E(1,0,1), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) },
	/* arj  */ { E(3,0,0), E(1,0,1), E(1,0,1), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) },
	/* cab  */ { E(3,0,0), E(2,0,1), E(3,0,0), E(2,0,1), E(3,0,0), E(3,0,0), E(0,0,1), E(3,0,0), E(3,0,0) },
	/* chm  */ { E(3,0,0), E(2,0,1), E(3,0,0), E(2,0,1), E(3,0,0), E(3,0,0), E(0,0,1), E(3,0,0), E(3,0,0) },
	/* 7z   */ { E(3,0,0), E(2,1,0), E(2,1,0), E(2,1,3), E(3,0,0), E(0,1,0), E(0,1,0), E(3,0,0), E(3,0,0) },
	/* ole  */ { E(1,0,0), E(1,1,0), E(1,0,0), E(1,1,0), E(1,0,0), E(1,0,0), E(0,1,0), E(1,1,0), E(1,0,0) },
	/* pdf  */ { E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) },
	/* gzip */ { E(1,0,0), E(1,0,0), E(1,0,0), E(1,0,0), E(1,0,0), E(1,0,0), E(1,0,0), E(1,0,0), E(1,1,0) },
	/* rar5 */ { E(3,0,0), E(1,1,0), E(1,1,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0), E(3,0,0) }
};

static uint8_t d0[100], d1[200], d2[300];

/* One scan of one cell: the archive written, the answer summarised. */
struct cell {
	struct cw w;
	struct cs_run r;
	unsigned put, found, rep;
	uint64_t maxlen;
};

static int make_cell(unsigned f, unsigned sc, struct cell *c)
{
	const struct cw_format *F = &cw_formats[f];
	struct cw_ent e[3];
	struct cw_lies l;
	struct kof_scan_option o = cs_opt();
	unsigned n = F->max_members == 1 ? 1u : 3u, i;
	char root[32];

	memset(c, 0, sizeof *c);
	memset(e, 0, sizeof e);
	memset(&l, 0, sizeof l);
	e[0].name = "a.txt"; e[0].data = d0; e[0].len = sizeof d0;
	e[1].name = "b.txt"; e[1].data = d1; e[1].len = sizeof d1;
	e[2].name = "c.txt"; e[2].data = d2; e[2].len = sizeof d2;
	switch (sc) {
	case S_BOTH:   e[1].claimed = 1; e[1].claim_packed = e[1].claim_unpacked = 0xfffffff0u; break;
	case S_PACK:   e[1].claimed = 1; e[1].claim_packed = 0xfffffff0u; e[1].claim_unpacked = sizeof d1; break;
	case S_UNP:    e[1].claimed = 1; e[1].claim_packed = sizeof d1; e[1].claim_unpacked = 0xfffffff0u; break;
	case S_SHARE:  e[2].share = 1; break;
	case S_COUNT:  l.mask = CW_L_COUNT; l.count_claim = 60000; break;
	case S_OFFSET: l.mask = CW_L_OFFSET; l.off_claim = 0x7ffffff0u; break;
	case S_CYCLE:  l.mask = CW_L_CYCLE; break;
	case S_NOEND:  l.mask = CW_L_NOEND; break;
	default: break;
	}
	if (n == 1)
		e[0].claimed = (sc == S_BOTH || sc == S_PACK || sc == S_UNP), e[0].claim_packed = sizeof d0, e[0].claim_unpacked = sizeof d0;
	cw_formats[f].write(&c->w, e, n, &l, NULL);
	snprintf(root, sizeof root, "x.%s", F->name);
	if (cs_scan(c->w.p, c->w.n, root, &o, &c->r))
		return -1;
	c->put = n;
	c->found = c->r.n > 1u + F->lead ? c->r.n - 1u - F->lead : 0u;
	c->rep = c->r.broken > 0 || c->r.limit_hits > 0;
	for (i = 1; i < c->r.n && i < CS_MAXOBJ; i++)
		if (c->r.o[i].len > c->maxlen)
			c->maxlen = c->r.o[i].len;
	return 0;
}

static void drop_cell(struct cell *c)
{
	cs_free(&c->r);
	cw_free(&c->w);
}

static int one_format(void *p)
{
	unsigned f = (unsigned)(uintptr_t)p, sc;
	const struct cw_format *F = &cw_formats[f];

	cs_fill(d0, sizeof d0, 0);
	cs_fill(d1, sizeof d1, 1);
	cs_fill(d2, sizeof d2, 2);
	for (sc = 0; sc < NSC; sc++) {
		struct cell c, c2;
		struct exp x = tab[f][sc];
		unsigned i, same = 1;

		if (make_cell(f, sc, &c) || make_cell(f, sc, &c2))
			return 9;
		CK(c.found == (unsigned)x.found, "%s/%s: %u members opened, the table says %d (objects %u, broken %llu, limit hits %llu)", F->name,
		   sname[sc], c.found, x.found, c.r.n, (unsigned long long)c.r.broken, (unsigned long long)c.r.limit_hits);
		CK(c.rep == (unsigned)x.rep, "%s/%s: reported %u, the table says %d", F->name, sname[sc], c.rep, x.rep);
		CK(c.maxlen <= c.w.n || x.km == 2, "%s/%s: a child of %llu bytes out of a %zu byte container", F->name, sname[sc],
		   (unsigned long long)c.maxlen, c.w.n);
		CK(c.r.n == c2.r.n, "%s/%s: two scans, two object counts (%u, %u)", F->name, sname[sc], c.r.n, c2.r.n);
		for (i = 0; i < c.r.n && i < c2.r.n && i < CS_MAXOBJ; i++)
			same &= c.r.o[i].hash == c2.r.o[i].hash && c.r.o[i].len == c2.r.o[i].len && c.r.o[i].broken == c2.r.o[i].broken &&
				!strcmp(c.r.o[i].name, c2.r.o[i].name);
		CK(same, "%s/%s: two scans of one input gave different objects", F->name, sname[sc]);
		CK(c.r.slash_forged == 0, "%s/%s: a forged separator", F->name, sname[sc]);
		if (x.km == 1) {
			const char *id = !strcmp(F->name, "zip") || sc == S_OFFSET ? "WP2-D3" : (!strcmp(F->name, "cab") || !strcmp(F->name, "chm")) ? "WP2-D2" : "WP2-D1";
			char what[128];

			snprintf(what, sizeof what, "%s/%s: members lost (%u of %u) with nothing said", F->name, sname[sc], c.found, c.put);
			/* KNOWN DEFECT WP2-D1 (2026-10-24, M): this row pins it, green until fixed (the row of WP2-D1b, WP2-D2, WP2-D2b, WP2-D3, WP2-D3b, WP2-D3c too). */
			KM_CHECK(c.found == c.put || c.rep, what, id);
		}
		if (x.km == 2) {
			const struct cs_obj *b = cs_find(&c.r, ":b.txt");
			char what[128];

			snprintf(what, sizeof what, "%s/%s: the member's child is %llu bytes, past its own 200", F->name, sname[sc],
				 b ? (unsigned long long)b->len : 0ull);
			/* KNOWN DEFECT WP2-D4 (2026-10-24, M): this row pins it, green until fixed. */
			KM_CHECK(b && b->len == sizeof d1, what, "WP2-D4");
		}
		if (x.km == 3) {
			char what[128];

			snprintf(what, sizeof what, "%s/%s: the folder after the cut one was %s", F->name, sname[sc], c.found == c.put ? "walked" : "lost");
			/* KNOWN DEFECT WP2-D5 (2026-10-24, M): this row pins it, green until fixed. */
			KM_CHECK(c.found == c.put, what, "WP2-D5");
		}
		drop_cell(&c);
		drop_cell(&c2);
	}
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

/*
 * WP2-D13, from the other side: a member that cannot be DECODED, and a member whose HEADER is wrong, in the first and
 * second place of a three member archive, the others stored and good.
 *   zip (method 8 over bytes that are not deflate) and rar (method 0x33 over the same): the root says DAMAGED and the two stored members
 *   after the failure are walked (2 children)
 *   lha (-lh6-) and arj (method 1) over the same bytes: the root says DAMAGED and NOTHING after it is walked (0 children): the module's
 *   loop ends at the first member it cannot decode instead of at the host's refusal (kofeng/CLAUDE.md rule 4)   [WP2-D13]
 *   tar with the second header's first byte flipped (its checksum is then wrong): still opened, all three members
 */
static int coded_first(void *unused)
{
	static const struct { const char *fmt; unsigned method; int walks_on; } rows[] = {
		{ "zip", 8, 1 }, { "rar", 0x33, 1 }, { "lha", 6, 0 }, { "arj", 1, 0 }
	};
	unsigned k, i;

	(void)unused;
	cs_fill(d0, sizeof d0, 0);
	cs_fill(d1, sizeof d1, 1);
	cs_fill(d2, sizeof d2, 2);
	for (k = 0; k < sizeof rows / sizeof rows[0]; k++) {
		unsigned f = cw_find(rows[k].fmt);
		struct cw_ent e[3];
		struct cw w = { 0 };
		struct cs_run r;
		struct kof_scan_option o = cs_opt();
		unsigned found;
		char what[160];

		memset(e, 0, sizeof e);
		e[0].name = "a.txt"; e[0].data = d0; e[0].len = sizeof d0; e[0].method = rows[k].method;
		e[1].name = "b.txt"; e[1].data = d1; e[1].len = sizeof d1;
		e[2].name = "c.txt"; e[2].data = d2; e[2].len = sizeof d2;
		cw_formats[f].write(&w, e, 3, NULL, NULL);
		if (cs_scan(w.p, w.n, "x.y", &o, &r))
			return 9;
		found = r.n ? r.n - 1u : 0u;
		CK(r.o[0].broken == KOF_BROKEN_DAMAGED || r.o[0].broken == KOF_BROKEN_UNSUPPORTED, "%s: an undecodable first member is said on the root (%u)", rows[k].fmt, r.o[0].broken);
		if (rows[k].walks_on) {
			CK(found == 2, "%s: the two stored members after an undecodable one are walked (%u)", rows[k].fmt, found);
		} else {
			snprintf(what, sizeof what, "%s: the walk ended at the first undecodable member: %u of the 2 stored members after it opened", rows[k].fmt, found);
			/* KNOWN DEFECT WP2-D13 (2026-10-25, M): this row pins it, green until fixed. */
			KM_CHECK(found == 2, what, "WP2-D13");
		}
		cs_free(&r);
		cw_free(&w);
	}
	{
		struct cw_ent e[3];
		struct cw w = { 0 };
		struct cs_run r;
		struct kof_scan_option o = cs_opt();
		char what[160];

		memset(e, 0, sizeof e);
		e[0].name = "a.txt"; e[0].data = d0; e[0].len = sizeof d0;
		e[1].name = "b.txt"; e[1].data = d1; e[1].len = sizeof d1;
		e[2].name = "c.txt"; e[2].data = d2; e[2].len = sizeof d2;
		cw_tar(&w, e, 3, NULL, NULL);
		w.p[1024] ^= 0x01u;                       /* the second header's name: its checksum no longer matches */
		if (cs_scan(w.p, w.n, "x.tar", &o, &r))
			return 9;
		(void)i;
		(void)what;
		CK(r.n - 1u == 3u, "tar: a header whose checksum is wrong is still opened (it is an anomaly, not an end): %u of 3 members", r.n - 1u);
		cs_free(&r);
		cw_free(&w);
	}
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

int main(void)
{
	unsigned f, bad = 0;
	struct he_status st2;

	st2 = he_child(coded_first, NULL, 60);
	printf("liars coded-first+tar-checksum %s\n", he_how(st2));
	bad |= !he_ok(st2);
	for (f = 0; f < CW_NFORMATS; f++) {
		struct he_status st = he_child(one_format, (void *)(uintptr_t)f, 120);

		printf("liars %-5s %s\n", cw_formats[f].name, he_how(st));
		bad |= !he_ok(st);
	}
	printf("ctr_liars: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
