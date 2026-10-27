/*
 * ctr_nest - containers inside containers, and files whose header says one format and whose body is another.
 *
 *   CHAIN        zip in zip in zip ... to depth N (writers wrap one member each time): the leaf is a child at depth N up to
 *                the layer allowance (64 for a small file) and past it the cut is REPORTED: exactly one object, at the
 *                allowance, reads KOF_BROKEN_LIMIT, and nothing deeper exists
 *   MIXED        every one of the 11 formats wrapped around the leaf, in eleven rotations of the order and in reverse
 *                (zip > tar > rar > ... > pdf > gzip is one of them): the leaf comes out at depth 11 with its own bytes,
 *                each level the size of the archive that held it, nothing reported broken
 *   OVERLAP BOMB a zip of two members that SHARE one data run, wrapping a zip of the same shape, to depth 12 / 20 / 30: the
 *                file stays a few KB and the tree would have 2^30 leaves. The walk stops at the children quota, says so
 *                (a LIMIT object), and finishes in bounded time with a bounded peak
 *   CONFUSED     for every ordered pair of formats (A, B), A != B: B's file with A's first 64 bytes laid over its head, with
 *                A's last 64 bytes laid over its tail, and A's file followed by B's (a polyglot). The scan answers, twice
 *                the same, and the tree stays inside the produced-bytes budget. What the engine makes of each is not
 *                asserted per pair (a polyglot IS two formats); that it makes the same of it every time, with no
 *                crash, no hang and no read past the object, is
 *
 *   WP2-D7 (KM_CHECK): a layer cut marks the object KOF_BROKEN_LIMIT but kof_stats.limit_hits stays 0, although
 *          kof_stats.limit_hits is documented (kofresult.h) as counting every object a bound cut. The same holds for a
 *          children-quota stop (a LIMIT root, limit_hits 0) and a produced-bytes stop; a cut of ONE entry does count.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"

#include <time.h>

static const char leaf[] = "leaf-leaf-leaf-leaf-leaf";
#define LEAF_N (sizeof leaf - 1)

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static unsigned leaf_depth(const struct cs_run *r)
{
	unsigned i, d = 0;

	for (i = 0; i < r->n && i < CS_MAXOBJ; i++)
		if (r->o[i].len == LEAF_N && r->o[i].hash == cs_fnv(leaf, LEAF_N))
			d = r->o[i].depth;
	return d;
}

/* ---- chain ------------------------------------------------------------------------------------------ */

static int chain(void *unused)
{
	static const unsigned depths[] = { 1, 2, 4, 8, 16, 32, 48, 63, 64, 65, 70, 100, 200 };
	unsigned di, zip = cw_find("zip");
	struct kof_scan_option o = cs_opt();

	(void)unused;
	for (di = 0; di < sizeof depths / sizeof depths[0]; di++) {
		struct cw cur = { 0 }, nxt;
		struct cs_run r;
		unsigned k, ld, d = depths[di];

		cw_put(&cur, leaf, LEAF_N);
		for (k = 0; k < d; k++) {
			nxt = cw_wrap(zip, &cur);
			cw_free(&cur);
			cur = nxt;
		}
		if (cs_scan(cur.p, cur.n, "n.zip", &o, &r))
			return 9;
		ld = leaf_depth(&r);
		if (d <= 64) {
			CK(ld == d, "chain %u: the leaf is at depth %u", d, ld);
			CK(r.broken == 0, "chain %u: nothing is reported broken (%llu)", d, (unsigned long long)r.broken);
		} else {
			CK(ld == 0, "chain %u: nothing past the allowance is opened (the leaf is at %u)", d, ld);
			CK(r.max_depth == 64, "chain %u: the deepest object is the allowance, 64 (%u)", d, r.max_depth);
			CK(r.broken_limit == 1, "chain %u: exactly one object says Limit (%llu)", d, (unsigned long long)r.broken_limit);
			CK(r.o[r.n - 1u].broken == KOF_BROKEN_LIMIT && r.o[r.n - 1u].depth == 64, "chain %u: and it is the deepest one", d);
			if (d == 65) {
				char what[160];

				snprintf(what, sizeof what, "chain %u: the layer cut is a LIMIT object and limit_hits is %llu", d, (unsigned long long)r.limit_hits);
				/* KNOWN DEFECT WP2-D7 (2026-10-24, M): this row pins it, green until fixed. */
				KM_CHECK(r.limit_hits >= r.broken_limit, what, "WP2-D7");
			}
		}
		cs_free(&r);
		cw_free(&cur);
	}
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

/* The same chain over a big leaf: the allowance falls with the size (kofoption.h max_object_depth), and a cut is said. */
static int chain_big(void *unused)
{
	static uint8_t big[16u << 20];
	struct cw cur = { 0 }, nxt;
	struct cs_run r;
	struct kof_scan_option o = cs_opt();
	unsigned k, zip = cw_find("zip"), i, deepest = 0;

	(void)unused;
	cs_fill(big, sizeof big, 3);
	cw_put(&cur, big, sizeof big);
	for (k = 0; k < 40; k++) {
		nxt = cw_wrap(zip, &cur);
		cw_free(&cur);
		cur = nxt;
	}
	if (cs_scan(cur.p, cur.n, "n.zip", &o, &r))
		return 9;
	for (i = 0; i < r.n && i < CS_MAXOBJ; i++)
		if (r.o[i].len == sizeof big && r.o[i].hash == cs_fnv(big, sizeof big))
			deepest = r.o[i].depth;
	printf("  chain of 40 zips around a 16 MiB leaf: %u objects, deepest %u, leaf at %u, broken %llu\n", r.n, r.max_depth, deepest,
	       (unsigned long long)r.broken);
	CK(deepest == 40 || (r.broken_limit >= 1 && r.max_depth < 40), "big chain: the leaf is opened or the cut is reported (leaf %u, deepest %u, limit objects %llu)",
	   deepest, r.max_depth, (unsigned long long)r.broken_limit);
	cs_free(&r);
	cw_free(&cur);
	return he_fails != 0 ? 1 : 0;
}

/* ---- mixed ------------------------------------------------------------------------------------------ */

static int mixed(void *unused)
{
	unsigned rot, rev;
	struct kof_scan_option o = cs_opt();

	(void)unused;
	for (rev = 0; rev < 2; rev++)
		for (rot = 0; rot < CW_NFORMATS; rot++) {
			struct cw cur = { 0 }, nxt;
			struct cs_run r;
			unsigned k, ld, order[CW_NFORMATS];
			char names[160] = "";

			cw_put(&cur, leaf, LEAF_N);
			for (k = 0; k < CW_NFORMATS; k++) {
				order[k] = rev ? (unsigned)((CW_NFORMATS - 1u - k + rot) % CW_NFORMATS) : (unsigned)((k + rot) % CW_NFORMATS);
				strncat(names, cw_formats[order[k]].name, sizeof names - strlen(names) - 2u);
				strncat(names, ">", sizeof names - strlen(names) - 1u);
				nxt = cw_wrap(order[k], &cur);
				cw_free(&cur);
				cur = nxt;
			}
			if (cs_scan(cur.p, cur.n, "m.x", &o, &r))
				return 9;
			ld = leaf_depth(&r);
			CK(ld == CW_NFORMATS, "mixed %s: the leaf is at depth %u (wanted %u; %u objects)", names, ld, (unsigned)CW_NFORMATS, r.n);
			CK(r.broken == 0, "mixed %s: nothing reported broken (%llu)", names, (unsigned long long)r.broken);
			cs_free(&r);
			cw_free(&cur);
		}
	return he_fails != 0 ? 1 : 0;
}

/* ---- overlap bomb ---------------------------------------------------------------------------------- */

static int bomb(void *unused)
{
	static const unsigned depths[] = { 12, 20, 30 };
	unsigned di;

	(void)unused;
	for (di = 0; di < 3; di++) {
		struct cw cur = { 0 }, nxt;
		struct cs_run r;
		struct kof_scan_option o = cs_opt();
		unsigned k;
		double t0, secs;

		cw_put(&cur, leaf, LEAF_N);
		for (k = 0; k < depths[di]; k++) {
			struct cw_ent e[2];

			memset(e, 0, sizeof e);
			memset(&nxt, 0, sizeof nxt);
			e[0].name = "a"; e[0].data = cur.p; e[0].len = cur.n;
			e[1].name = "b"; e[1].data = cur.p; e[1].len = cur.n; e[1].share = 1;
			cw_zip(&nxt, e, 2, NULL, NULL);
			cw_free(&cur);
			cur = nxt;
		}
		t0 = now();
		if (cs_scan(cur.p, cur.n, "o.zip", &o, &r))
			return 9;
		secs = now() - t0;
		printf("  overlap bomb depth %u: %zu byte file, %u objects (quota 4096+1), limit objects %llu, peak %llu, %.2f s\n", depths[di], cur.n, r.n,
		       (unsigned long long)r.broken_limit, (unsigned long long)r.peak, secs);
		CK(cur.n < 8192u, "bomb %u: the file is small (%zu)", depths[di], cur.n);
		if (depths[di] >= 12) {
			CK(r.n <= 4097u, "bomb %u: the walk stops at the children quota (%u objects)", depths[di], r.n);
			CK(r.broken_limit >= 1, "bomb %u: and says so, a LIMIT object (%llu)", depths[di], (unsigned long long)r.broken_limit);
		}
		CK(secs < 20.0, "bomb %u: bounded time (%.1f s)", depths[di], secs);
		CK(r.peak <= o.max_resident_bytes, "bomb %u: peak resident %llu inside the ceiling", depths[di], (unsigned long long)r.peak);
		cs_free(&r);
		cw_free(&cur);
	}
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

/* ---- confused --------------------------------------------------------------------------------------- */

static int confused(void *unused)
{
	static uint8_t m[3][400];
	struct cw file[CW_NFORMATS];
	struct cw_ent e[3];
	unsigned a, b, v, k, scans = 0;
	struct kof_scan_option o = cs_opt();

	(void)unused;
	for (k = 0; k < 3; k++)
		cs_fill(m[k], sizeof m[k], k);
	for (a = 0; a < CW_NFORMATS; a++) {
		unsigned n = cw_formats[a].max_members == 1 ? 1u : 3u;

		memset(&file[a], 0, sizeof file[a]);
		memset(e, 0, sizeof e);
		for (k = 0; k < 3; k++) {
			static char nm[3][8] = { "x0", "x1", "x2" };

			e[k].name = nm[k];
			e[k].data = m[k];
			e[k].len = sizeof m[k];
		}
		cw_formats[a].write(&file[a], e, n, NULL, NULL);
	}
	for (a = 0; a < CW_NFORMATS; a++)
		for (b = 0; b < CW_NFORMATS; b++) {
			if (a == b)
				continue;
			for (v = 0; v < 3; v++) {
				struct cw x = { 0 };
				struct cs_run r1, r2;
				unsigned i, same = 1;

				if (v == 2) {
					cw_put(&x, file[a].p, file[a].n);
					cw_put(&x, file[b].p, file[b].n);
				} else {
					size_t span = file[a].n < 64u ? file[a].n : 64u;

					cw_put(&x, file[b].p, file[b].n);
					if (span > x.n)
						span = x.n;
					if (v == 0)
						memcpy(x.p, file[a].p, span);
					else
						memcpy(x.p + x.n - span, file[a].p + file[a].n - span, span);
				}
				if (cs_scan(x.p, x.n, "c.x", &o, &r1) || cs_scan(x.p, x.n, "c.x", &o, &r2))
					return 9;
				scans++;
				CK(r1.rc >= 1, "confused %s/%s v%u: the scan answers", cw_formats[a].name, cw_formats[b].name, v);
				CK(r1.n == r2.n, "confused %s/%s v%u: two scans, two object counts (%u, %u)", cw_formats[a].name, cw_formats[b].name, v, r1.n, r2.n);
				for (i = 0; i < r1.n && i < r2.n && i < CS_MAXOBJ; i++)
					same &= r1.o[i].hash == r2.o[i].hash && r1.o[i].broken == r2.o[i].broken && !strcmp(r1.o[i].name, r2.o[i].name);
				CK(same, "confused %s/%s v%u: two scans of one input gave different objects", cw_formats[a].name, cw_formats[b].name, v);
				CK(r1.child_bytes <= o.max_produced_bytes + (uint64_t)x.n * 4u, "confused %s/%s v%u: %llu child bytes out of a %zu byte file",
				   cw_formats[a].name, cw_formats[b].name, v, (unsigned long long)r1.child_bytes, x.n);
				CK(r1.slash_forged == 0, "confused %s/%s v%u: a forged separator", cw_formats[a].name, cw_formats[b].name, v);
				cs_free(&r1);
				cs_free(&r2);
				cw_free(&x);
			}
		}
	for (a = 0; a < CW_NFORMATS; a++)
		cw_free(&file[a]);
	printf("  confused: %u scans (every ordered pair of %u formats, three ways)\n", scans, (unsigned)CW_NFORMATS);
	return he_fails != 0 ? 1 : 0;
}

int main(void)
{
	static const struct { int (*fn)(void *); const char *what; unsigned secs; } jobs[] = {
		{ chain, "chain", 120 }, { chain_big, "chain over a 16 MiB leaf", 240 }, { mixed, "mixed formats", 120 },
		{ bomb, "overlap bomb", 240 }, { confused, "format confusion", 300 }
	};
	unsigned i, bad = 0;

	cs_eng = keng_open(HE_DB);
	for (i = 0; i < sizeof jobs / sizeof jobs[0]; i++) {
		struct he_status st = he_child(jobs[i].fn, NULL, jobs[i].secs);

		printf("nest %-26s %s\n", jobs[i].what, he_how(st));
		bad |= !he_ok(st);
	}
	printf("ctr_nest: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
