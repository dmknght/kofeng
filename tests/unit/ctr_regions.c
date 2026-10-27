/*
 * ctr_regions - the REGIONS and ENTRIES every container parser declares, on archives that lie (tests/lib/ctr_writers.h).
 *
 * A region says which bytes are what; the regions of one object must partition it exactly (every byte in one region, no extent
 * past the end, none wrapping, none empty), because a matcher searches region by region and a byte in two regions is searched
 * twice while a byte in none is never searched. An entry table must be in range and must not amplify (entry_check.h). Both
 * checks are the ones parser_fuzz.c makes on its own generated objects; this file makes them on the WRITERS' archives for every
 * container format and every lie (the nine columns of ctr_liars.c), which parser_fuzz.c does not for lha, arj, cab and chm.
 *
 * WP2-D9 (KM_CHECK, found by the fuzz adapter container/parse_cab and parse_chm, reproducers in tests_wp2/findings):
 * a CAB whose first folder's data offset is 0 and a CHM whose directory section is absent declare a DATA / CONTENT region that
 * STARTS AT BYTE 0 and so overlaps the HEADERS region (cab_parse.c cab_resolve_scan, chm_parse.c chm_resolve_scan: `from` is
 * lifted past the names / the directory, not past the headers). chm_parse.c says in its own comment that a content offset
 * pointing into the directory "breaks the partition every region mask here rests on"; the headers are the same case.
 */
#define _GNU_SOURCE
#include "hostile_engine.h"
#include "known_miss.h"
#include "../lib/ctr_writers.h"
#include "../lib/ctr_scan.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "partition_check.h"
#include "entry_check.h"

static uint8_t d0[100], d1[200], d2[300];

static const uint8_t fmt_of[CW_NFORMATS] = {
	KOF_FMT_ZIP, KOF_FMT_TAR, KOF_FMT_RAR, KOF_FMT_LHA, KOF_FMT_ARJ, KOF_FMT_CAB, KOF_FMT_CHM, KOF_FMT_7Z, KOF_FMT_DOCOLE, KOF_FMT_PDF, KOF_FMT_GZIP, KOF_FMT_RAR
};

struct res {
	int sniffed, parsed;
	uint64_t pc_failed, ec_failed;
};

static struct res check(uint8_t fmt, const uint8_t *p, size_t n)
{
	const struct kof_parser *pr = kof_parser_of(fmt);
	const struct kof_view_ops *ops = kof_view_ops_of(fmt);
	void *view = calloc(1, pr->view_size);
	struct kof_obj_ctx ctx;
	struct pc_report rep;
	struct ec_report er;
	struct he_guard g;
	struct res r;

	memset(&r, 0, sizeof r);
	memset(&ctx, 0, sizeof ctx);
	memset(&rep, 0, sizeof rep);
	memset(&er, 0, sizeof er);
	rep.quiet = er.quiet = 1;
	if (!view || !he_guard_make(&g, p, n))
		return r;
	r.sniffed = pr->sniff(kof_buf_make(g.p, g.n));
	if (r.sniffed) {
		if (ops)
			ops->mem(view)->room = 16u << 20;
		r.parsed = pr->parse(kof_buf_make(g.p, g.n), view, &ctx);
		if (r.parsed) {
			pc_check("ctr", &ctx, n, pr->regions, pr->n_regions, &rep);
			ec_check("ctr", &ctx, n, &er);
		}
		if (ops)
			ops->release(view);
	}
	r.pc_failed = rep.failed;
	r.ec_failed = er.failed;
	he_guard_free(&g);
	free(view);
	return r;
}

static int matrix(void *unused)
{
	static const char *const sname[9] = { "clean", "claimBoth", "claimPack", "claimUnp", "share", "count", "offset", "cycle", "noend" };
	unsigned f, sc;

	(void)unused;
	cs_fill(d0, sizeof d0, 0);
	cs_fill(d1, sizeof d1, 1);
	cs_fill(d2, sizeof d2, 2);
	for (f = 0; f < CW_NFORMATS; f++)
		for (sc = 0; sc < 9; sc++) {
			const struct cw_format *F = &cw_formats[f];
			struct cw_ent e[3];
			struct cw_lies l;
			struct cw w = { 0 };
			struct res r;
			unsigned n = F->max_members == 1 ? 1u : 3u;

			memset(e, 0, sizeof e);
			memset(&l, 0, sizeof l);
			e[0].name = "a.txt"; e[0].data = d0; e[0].len = sizeof d0;
			e[1].name = "b.txt"; e[1].data = d1; e[1].len = sizeof d1;
			e[2].name = "c.txt"; e[2].data = d2; e[2].len = sizeof d2;
			switch (sc) {
			case 1: e[1].claimed = 1; e[1].claim_packed = e[1].claim_unpacked = 0xfffffff0u; break;
			case 2: e[1].claimed = 1; e[1].claim_packed = 0xfffffff0u; e[1].claim_unpacked = sizeof d1; break;
			case 3: e[1].claimed = 1; e[1].claim_packed = sizeof d1; e[1].claim_unpacked = 0xfffffff0u; break;
			case 4: e[2].share = 1; break;
			case 5: l.mask = CW_L_COUNT; l.count_claim = 60000; break;
			case 6: l.mask = CW_L_OFFSET; l.off_claim = 0x7ffffff0u; break;
			case 7: l.mask = CW_L_CYCLE; break;
			case 8: l.mask = CW_L_NOEND; break;
			default: break;
			}
			if (n == 1 && sc >= 1 && sc <= 3) {
				e[0].claimed = 1;
				e[0].claim_packed = sc == 3 ? sizeof d0 : 0xfffffff0u;
				e[0].claim_unpacked = sc == 2 ? sizeof d0 : 0xfffffff0u;
			}
			F->write(&w, e, n, &l, NULL);
			r = check(fmt_of[f], w.p, w.n);
			CK(r.pc_failed == 0, "%s/%s: the regions do not partition the object", F->name, sname[sc]);
			CK(r.ec_failed == 0, "%s/%s: an entry is out of range, amplifies or repeats", F->name, sname[sc]);
			if (sc == 0)
				CK(r.sniffed && r.parsed, "%s/clean: the parser accepts its own writer's archive (sniff %d, parse %d)", F->name, r.sniffed, r.parsed);
			cw_free(&w);
		}
	return he_fails != 0 ? 1 : 0;
}

/* WP2-D9: the region that starts at byte 0 over the headers. */
static int d9(void *unused)
{
	struct cw_ent e[2];
	struct cw w = { 0 };
	struct res r;
	uint8_t one[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	static uint8_t big[300];              /* function scope: e[] keeps pointing at it for the rows below */
	static uint8_t hundred[100];

	(void)unused;
	memset(e, 0, sizeof e);
	e[0].name = "a"; e[0].data = one; e[0].len = sizeof one;
	e[1].name = "b"; e[1].data = one; e[1].len = sizeof one;

	/* a CAB with no files whose only folder says its data begins at offset 0 (nothing lifts the DATA region past the names) */
	cw_cab(&w, e, 0, NULL, NULL);
	r = check(KOF_FMT_CAB, w.p, w.n);
	CK(r.pc_failed == 0, "cab control: the unedited archive partitions");
	cw_at32(&w, 36, 0);                       /* the folder record's coffCabStart */
	r = check(KOF_FMT_CAB, w.p, w.n);
	/* KNOWN DEFECT WP2-D9 (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(r.pc_failed == 0, "cab: a folder whose data offset is 0 leaves a DATA region that overlaps the headers", "WP2-D9");
	cw_free(&w);

	/* a CHM with no directory section and no content offset: ITSF offsets 72, 80 (the section) and 88 (the content) are zero */
	cw_chm(&w, e, 2, NULL, NULL);
	r = check(KOF_FMT_CHM, w.p, w.n);
	CK(r.pc_failed == 0, "chm control: the unedited archive partitions");
	cw_at64(&w, 72, 0);
	cw_at64(&w, 80, 0);
	cw_at64(&w, 88, 0);
	r = check(KOF_FMT_CHM, w.p, w.n);
	/* KNOWN DEFECT WP2-D9b (2026-10-24, M): this row pins it, green until fixed. */
	KM_CHECK(r.pc_failed == 0, "chm: no directory section leaves a CONTENT region that overlaps the headers", "WP2-D9");
	cw_free(&w);

	/* WP2-D10: a CAB whose header says a reserved area follows it puts the folder table past the file table: HEADERS is [0, 172)
	 * and NAMES begins at coffFiles (44) */
	{
		memset(big, 'x', sizeof big);
		e[0].data = big; e[0].len = sizeof big;
		e[1].data = big; e[1].len = sizeof big;
		cw_cab(&w, e, 2, NULL, NULL);
		cw_at16(&w, 30, 4);                   /* flags: the reserve field is present */
		cw_at16(&w, 36, 132);                 /* cbCFHeader: the folder table moves to 36 + 4 + 132 */
		r = check(KOF_FMT_CAB, w.p, w.n);
		/* KNOWN DEFECT WP2-D10 (2026-10-24, M): this row pins it, green until fixed. */
		KM_CHECK(r.pc_failed == 0, "cab: a reserved header area leaves HEADERS overlapping NAMES", "WP2-D10");
		cw_free(&w);
	}

	/* WP2-D11: two file records of one CAB naming the same bytes are two entries over one range (zip's shared entries are not:
	 * entry_check.h "distinct"). The second record's offset in the folder (at 66) is set to the first's (0). */
	cw_cab(&w, e, 2, NULL, NULL);
	r = check(KOF_FMT_CAB, w.p, w.n);
	CK(r.ec_failed == 0, "cab control: two members at two offsets are two distinct entries");
	cw_at32(&w, 66, 0);
	r = check(KOF_FMT_CAB, w.p, w.n);
	KM_CHECK(r.ec_failed == 0, "cab: two file records over the same bytes are two entries over one range", "WP2-D11");
	cw_free(&w);

	/* WP2-D11 again, in a CHM: the first member has no bytes of its own but claims 100, so the second starts at the same offset */
	e[0].len = 0;
	e[0].claimed = 1;
	e[0].claim_packed = e[0].claim_unpacked = 100;
	e[1].len = 100;
	{
		memset(hundred, 'h', sizeof hundred);
		e[1].data = hundred;
		cw_chm(&w, e, 2, NULL, NULL);
		r = check(KOF_FMT_CHM, w.p, w.n);
		KM_CHECK(r.ec_failed == 0, "chm: two file records over the same bytes are two entries over one range", "WP2-D11");
		cw_free(&w);
	}
	return (he_fails != 0 || km_failed()) ? 1 : 0;
}

int main(void)
{
	struct he_status st;
	int bad = 0;

	st = he_child(matrix, NULL, 120);
	printf("regions matrix %s\n", he_how(st));
	bad |= !he_ok(st);
	st = he_child(d9, NULL, 60);
	printf("regions WP2-D9 %s\n", he_how(st));
	bad |= !he_ok(st);
	printf("ctr_regions: %s\n", bad ? "FAIL" : "ok");
	return bad ? 1 : 0;
}
