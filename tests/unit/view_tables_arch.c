/*
 * view_tables_arch - the views of tar, lha, arj, cab, chm, docole, rar and 7z are tables the size
 * of the FILE, and what bounds them is the file and the ledger, never a count the file states.
 *
 * The same change view_tables.c asserts for zip and pdf, and the same three promises, asked of
 * eight more formats through ONE harness (the parser's own row in kofformat.h and the view's own
 * handles, struct kof_view_ops - so a format added to that list is not tested until it is here):
 *
 *   WHOLE     2100, 5000 and 20000 entries parse to every row; the regions still partition the file
 *             byte for byte; the tables hold a stated multiple of the file and no more (QUALITY_AUDIT
 *             I.B); and nothing is reported - no "full" bit, no limit.
 *   BOUNDED   hostile files allocate a multiple of their own length and take bounded time, whatever
 *             they claim: counts of 65535 and 2^40 over a handful of records, folders and chunks
 *             that all name the same blocks, chains that loop, a file cut short.
 *   REPORTED  a ledger that cannot afford the tables stops the parse and the format's own "full" bit
 *             says so (kof_parser_cut_bits), with the rows already read whole; an allocation sweep
 *             (every allocation of a parse refused in turn) is survived to the same answer or SAID,
 *             and so is a whole scan under a ladder of resident ceilings.
 *
 * The engine half (a database from this tree) opens the same archives and counts the children.
 */

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "failalloc.h"
#include "arch_fixtures.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include <kofmod/tar.h>
#include <kofmod/lha.h>
#include <kofmod/arj.h>
#include <kofmod/cab.h>
#include <kofmod/chm.h>
#include <kofmod/docole.h>
#include <kofmod/rar.h>
#include <kofmod/sevenzip.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/* The stated multiple: what a view's tables may hold, in bytes, for a file of n bytes. The worst
 * ratio is chm - a 5 byte directory entry is a 64 byte row and an 8 byte one beside it - which is
 * why it is not a small number; what it is not is a count the file chose. */
#define HELD_MULT  96u
#define HELD_FLOOR (256u * 1024u)
#define HELD_OK(held, n) ((held) <= (uint64_t)HELD_MULT * (n) + HELD_FLOOR)

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---- the formats under test ---------------------------------------------------------------------- */

struct fmt {
	const char *name;
	uint8_t format;
	struct made (*build)(unsigned n, int kind);
	uint64_t full;        /* the bits that mean a table of the parse was full */
	unsigned max_n;       /* the largest n the format's own counters can state */
	unsigned hostile[4];  /* the hostile kinds that make sense for it, 0 ending the list */
};

static const struct fmt fmts[] = {
	{ "tar",    KOF_FMT_TAR,    b_tar, KOF_TAR_ANOM_ENTRIES_FULL | KOF_TAR_ANOM_EXTENTS_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
	{ "lha",    KOF_FMT_LHA,    b_lha, KOF_LHA_ANOM_ENTRIES_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
	{ "arj",    KOF_FMT_ARJ,    b_arj, KOF_ARJ_ANOM_ENTRIES_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
	{ "cab",    KOF_FMT_CAB,    b_cab, KOF_CAB_ANOM_FILES_FULL, 20000u, { K_CUT, K_CLAIM, K_SHARED, 0 } },
	{ "chm",    KOF_FMT_CHM,    b_chm, KOF_CHM_ANOM_ENTRIES_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
	{ "docole", KOF_FMT_DOCOLE, b_ole, KOF_DOCOLE_ANOM_ENT_RUNS_FULL | KOF_DOCOLE_ANOM_DIR_OVERFLOW |
					   KOF_DOCOLE_ANOM_EXTENTS_FULL | KOF_DOCOLE_ANOM_ENTRIES_FULL |
					   KOF_DOCOLE_ANOM_WORK_FULL, 20000u, { K_CUT, K_LOOP, 0, 0 } },
	{ "rar",    KOF_FMT_RAR,    b_rar, KOF_RAR_ANOM_ENTRIES_FULL | KOF_RAR_ANOM_EXTENTS_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
	{ "7z",     KOF_FMT_7Z,     b_7z,  KOF_7Z_ANOM_FOLDERS_FULL, 20000u, { K_CUT, K_CLAIM, 0, 0 } },
};

/* One parse of `b`, through the format's own row, into a view the caller owns. `room` is the
 * ledger (0: none). Returns the view; the rows and the anomaly word are read from it. */
struct parsed {
	void *view;
	const struct kof_parser *pr;
	const struct kof_view_ops *vo;
	struct kof_obj_ctx ctx;
	int ok;
	unsigned rows;        /* what the walk hands out */
	uint64_t anom, held;
	double secs;
};

static void parse_one(const struct fmt *f, const uint8_t *b, size_t len, uint64_t room, struct parsed *p)
{
	uint32_t cur = 0;
	double t0 = now();

	memset(p, 0, sizeof *p);
	p->pr = kof_parser_of(f->format);
	p->vo = kof_view_ops_of(f->format);
	if (!p->pr || !p->vo)
		return;
	p->view = calloc(1, p->pr->view_size);
	if (!p->view)
		return;
	p->vo->mem(p->view)->room = room;
	p->ok = p->pr->parse(kof_buf_make(b, len), p->view, &p->ctx);
	p->secs = now() - t0;
	p->anom = p->pr->anomalies(p->view);
	p->held = p->vo->mem(p->view)->held;
	while (p->vo->next(p->view, &cur))
		p->rows++;
}

static void parse_free(struct parsed *p)
{
	if (p->view && p->vo)
		p->vo->release(p->view);
	free(p->view);
	p->view = NULL;
}

/*
 * The regions of a parsed object, every extent of every region, and whether they partition it:
 * sorted and walked, no byte in two and none in none. The scanner's buffer grows; this one is as
 * long as the object, which is the most ranges a region can have (a range is at least a byte).
 */
static int cmp_range(const void *a, const void *b)
{
	const struct kof_range *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static int partition(const struct parsed *p, uint64_t size)
{
	struct kof_range *e;
	uint64_t at = 0, sum = 0;
	uint32_t i, k, n = 0, cap;

	if (!p->ctx.resolve_scan || size > 0x7fffffffu / 32u)
		return -1;
	/* As many ranges as a region could have in a sound parse of this many rows - and no more, so a
	 * file of twenty megabytes does not cost a buffer of three hundred. A region that fills it is a
	 * question this cannot answer (-1). */
	cap = (uint32_t)(16ull * p->rows + 65536u);
	if (cap > (uint32_t)size + 2u)
		cap = (uint32_t)size + 2u;
	e = malloc((size_t)cap * sizeof *e);
	if (!e)
		return -1;
	for (k = 0; k < p->pr->n_regions; k++) {
		uint32_t got = p->ctx.resolve_scan(&p->ctx, p->pr->regions[k], e + n, cap - n);

		n += got;
		if (n >= cap) {
			free(e);
			return -1;
		}
	}
	qsort(e, n, sizeof *e, cmp_range);
	for (i = 0; i < n; i++) {
		if (e[i].off != at) {
			free(e);
			return 1;
		}
		at += e[i].len;
		sum += e[i].len;
	}
	free(e);
	return sum == size ? 0 : 1;
}

/* ---- WHOLE -------------------------------------------------------------------------------------- */

static void whole(const struct fmt *f, unsigned n)
{
	struct made m = f->build(n, K_CLEAN);
	struct parsed p;
	int part;

	CK(m.p != NULL, "%s %u: fixture", f->name, n);
	if (!m.p)
		return;
	parse_one(f, m.p, m.len, 0, &p);
	part = partition(&p, m.len);
	printf("  %-6s %5u entries: %5u rows, held %9llu bytes of a %9zu byte file (%.1fx), anomalies %#llx, %.3fs\n", f->name, n, p.rows,
	       (unsigned long long)p.held, m.len, (double)p.held / (double)m.len, (unsigned long long)p.anom, p.secs);
	CK(p.ok && p.rows == m.rows, "%s %u: %u rows of %u", f->name, n, p.rows, m.rows);
	CK(!(p.anom & f->full), "%s %u: a table said it was full (%#llx)", f->name, n, (unsigned long long)(p.anom & f->full));
	CK(HELD_OK(p.held, m.len), "%s %u: the tables hold %llu bytes of a %zu byte file", f->name, n, (unsigned long long)p.held, m.len);
	CK(part == 0 || part == -1, "%s %u: the regions do not partition the file", f->name, n);
	CK(p.secs < 2.0, "%s %u: %.2fs", f->name, n, p.secs);
	parse_free(&p);
	free(m.p);
}

/* ---- BOUNDED ------------------------------------------------------------------------------------ */

static void hostile(const struct fmt *f)
{
	unsigned k;

	for (k = 0; k < 4u && f->hostile[k]; k++) {
		unsigned kind = f->hostile[k];
		struct made m = f->build(kind == K_SHARED ? 20000u : 3000u, (int)kind);
		struct parsed p;
		int part;

		CK(m.p != NULL, "%s kind %u: fixture", f->name, kind);
		if (!m.p)
			continue;
		parse_one(f, m.p, m.len, 0, &p);
		part = partition(&p, m.len);
		printf("  %-6s hostile kind %u (%zu bytes): ok %d, %u rows, held %llu, anomalies %#llx, %.3fs\n", f->name, kind, m.len, p.ok,
		       p.rows, (unsigned long long)p.held, (unsigned long long)p.anom, p.secs);
		CK(HELD_OK(p.held, m.len), "%s kind %u: the tables hold %llu bytes of a %zu byte file", f->name, kind,
		   (unsigned long long)p.held, m.len);
		CK(p.secs < 2.0, "%s kind %u: %.2fs", f->name, kind, p.secs);
		CK(part == 0 || part == -1, "%s kind %u: the regions do not partition the file", f->name, kind);
		/* the cabinet whose folders all name the same blocks is the one place the work is budgeted */
		if (f->format == KOF_FMT_CAB && kind == K_SHARED)
			CK(p.secs < 1.0, "cab: 20000 folders over one block chain cost %.2fs", p.secs);
		parse_free(&p);
		free(m.p);
	}
}

/* ---- REPORTED: the ledger ----------------------------------------------------------------------- */

static void ledger(const struct fmt *f, unsigned n)
{
	struct made m = f->build(n, K_CLEAN);
	struct parsed full;
	static const unsigned div[] = { 64, 16, 8, 4, 2, 1 };
	unsigned k, hit = 0;

	if (!m.p)
		return;
	parse_one(f, m.p, m.len, 0, &full);
	for (k = 0; k < sizeof div / sizeof div[0]; k++) {
		struct parsed p;
		uint64_t room = full.held / div[k];

		if (room < 1u)
			room = 1u;
		parse_one(f, m.p, m.len, room, &p);
		if (p.rows == full.rows && !(p.anom & f->full)) {
			CK(p.held <= room, "%s: room %llu, held %llu", f->name, (unsigned long long)room, (unsigned long long)p.held);
		} else {
			hit++;
			CK(p.anom & f->full, "%s: room %llu gave %u of %u rows and no table said it was full", f->name,
			   (unsigned long long)room, p.rows, full.rows);
			CK(p.held <= room, "%s: room %llu, held %llu - the account was passed", f->name, (unsigned long long)room,
			   (unsigned long long)p.held);
		}
		parse_free(&p);
	}
	printf("  %-6s ledger ladder over %u entries: %u of %zu rungs were short, every one said so\n", f->name, n, hit,
	       sizeof div / sizeof div[0]);
	CK(hit > 0, "%s: no rung of the ladder was short - the ledger is not asked", f->name);
	parse_free(&full);
	free(m.p);
}

/* ---- REPORTED: the allocator -------------------------------------------------------------------- */

#if FA_AVAILABLE
static void sweep_parse(const struct fmt *f)
{
	struct made m = f->build(900, K_CLEAN);
	struct parsed base;
	long count, nth, hits = 0, same = 0, said = 0;

	if (!m.p)
		return;
	fa_init();
	fa_arm_nth(0);
	parse_one(f, m.p, m.len, 0, &base);
	count = fa_count();
	(void)fa_disarm_hit();
	CK(count > 0, "%s parse: allocations to sweep (%ld)", f->name, count);
	for (nth = 1; nth <= count; nth++) {
		struct parsed p;
		int reached;

		fa_arm_nth(nth);
		parse_one(f, m.p, m.len, 0, &p);
		reached = fa_disarm_hit();
		if (!reached) {
			parse_free(&p);
			continue;
		}
		hits++;
		if (!p.view) {
			said++;               /* the view itself was refused: nothing built, and the caller knows */
			continue;
		}
		if (p.ok && p.rows == base.rows && !(p.anom & f->full))
			same++;
		else if (p.anom & f->full)
			said++;
		else
			CK(0, "%s parse, allocation %ld refused: %u of %u rows and nothing said (anomalies %#llx)", f->name, nth, p.rows,
			   base.rows, (unsigned long long)p.anom);
		parse_free(&p);
	}
	printf("  %-6s parse sweep: %ld allocations, %ld refused in turn: %ld survived to the same answer, %ld said\n", f->name, count, hits, same,
	       said);
	CK(hits == count && same + said == hits, "%s parse: every refusal survived or said", f->name);
	parse_free(&base);
	free(m.p);
}
#endif

/* ---- the engine --------------------------------------------------------------------------------- */

struct seen {
	unsigned objs, marker, top_broken, any_broken;
	double secs;
};

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	if (!s->objs)
		s->top_broken = res->broken;
	s->objs++;
	if (bytes && len == 8u && memcmp(bytes, MARKER, 8) == 0)
		s->marker++;
	if (res->broken && !s->any_broken)
		s->any_broken = res->broken;
	return 0;
}

static kof_engine *eng;
static kof_scanner *sc;

static void scan_q(const uint8_t *b, uint64_t n, struct seen *s, uint64_t ceiling, uint32_t quota)
{
	struct kof_scan_option opt;
	double t0 = now();

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_children = quota;
	if (ceiling) {
		opt.max_resident_bytes = ceiling;
		opt.resident_per_scanner = 1;
	}
	(void)kscan_bytes(sc, b, n, "x", &opt, on_object, s);
	s->secs = now() - t0;
}

static void scan(const uint8_t *b, uint64_t n, struct seen *s, uint64_t ceiling)
{
	/* a quota the archive cannot reach: what is asked of the TABLES here is that they hold every
	 * member, and the host's default quota is its own question (engine_default below) */
	scan_q(b, n, s, ceiling, 0x7fffffffu);
}

/* every member opened: a child each, the marker among them, nothing reported, in well under a second
 * or two - the zero-children / broken=Limit answers the fixed tables gave are gone */
static void engine_whole(const struct fmt *f, unsigned n)
{
	struct made m = f->build(n, K_CLEAN);
	struct seen s;
	unsigned kids;

	if (!m.p)
		return;
	scan(m.p, m.len, &s, 0);
	kids = s.objs ? s.objs - 1u : 0u;
	printf("  engine, %-6s %5u entries: %5u children, marker %u, top broken=%u, %.2fs\n", f->name, n, kids, s.marker,
	       s.top_broken, s.secs);
	CK(kids >= m.kids && !s.top_broken && s.marker >= 1u, "%s %u: %u children of %u, marker %u, top broken %u", f->name, n, kids, m.kids,
	   s.marker, s.top_broken);
	CK(s.secs < 5.0, "%s %u: %.2fs", f->name, n, s.secs);
	free(m.p);
}

/* a ladder of resident ceilings: every rung either opens everything or says it did not */
static void engine_ladder(const struct fmt *f, unsigned n)
{
	static const uint64_t ladder[] = { 1u << 18, 1u << 20, 2u << 20, 4u << 20, 8u << 20, 16u << 20, 64u << 20, 256u << 20 };
	struct made m = f->build(n, K_CLEAN);
	unsigned k, whole_n = 0, said = 0, silent = 0;

	if (!m.p)
		return;
	for (k = 0; k < sizeof ladder / sizeof ladder[0]; k++) {
		struct seen s;
		unsigned kids;

		scan(m.p, m.len, &s, ladder[k]);
		kids = s.objs ? s.objs - 1u : 0u;
		if (kids >= m.kids && !s.any_broken)
			whole_n++;
		else if (s.any_broken)
			said++;
		else {
			silent++;
			printf("  silent: %s, ceiling %llu: %u of %u children, nothing said\n", f->name, (unsigned long long)ladder[k], kids, m.kids);
		}
	}
	printf("  engine, %-6s %5u entries, ladder of ceilings: %u whole, %u said, %u silent\n", f->name, n, whole_n, said, silent);
	CK(silent == 0, "%s: %u ceiling(s) lost members and said nothing", f->name, silent);
	CK(whole_n > 0, "%s: no ceiling opened the archive whole", f->name);
	free(m.p);
}

/*
 * THE HOST'S OWN DEFAULT QUOTA over the same archives: what the engine opens when nobody says how
 * many children a tree may have (the root's length over the smallest stored record of any format,
 * 5 bytes, at least 4096 - objctx_child.c). A CHECK: every member is opened and nothing is said.
 * It was information only while the divisor was 32, because a member that costs fewer than 32
 * bytes of the archive (a cab file is 23 with its eight bytes, a chm entry 21, a 7z folder 26) was
 * past the quota at about 5000 members and the object said Limit (cab 4846 of 5000, chm and 7z
 * 4096): reported, but a cut of members the file really held.
 */
static void engine_default(const struct fmt *f, unsigned n)
{
	struct made m = f->build(n, K_CLEAN);
	struct seen s;
	unsigned kids;

	if (!m.p)
		return;
	scan_q(m.p, m.len, &s, 0, 0);
	kids = s.objs ? s.objs - 1u : 0u;
	printf("  engine, %-6s %5u entries, the default quota: %5u of %u children, marker %u, top broken=%u\n", f->name, n, kids, m.kids,
	       s.marker, s.top_broken);
	CK(kids >= m.kids && !s.top_broken && s.marker >= 1u, "%s %u: %u of %u children under the default quota, marker %u, top broken %u",
	   f->name, n, kids, m.kids, s.marker, s.top_broken);
	free(m.p);
}

#if FA_AVAILABLE
/*
 * The big allocations of a whole scan refused in turn, and a CHECK that none loses members in
 * silence. The first few of them are the walk's stack of layers growing (16, 32 ... children,
 * scanners/scan_walk.c stack_reserve), and a refusal there dropped the children that did not
 * fit with only the walk's own `incomplete` flag as a trace, after the object that held them
 * had been reported clean: 8 of the 32 refusals of a tar, none of them a table of the parse
 * (measured on the tree before the room for the layers was asked for ahead of the verdict).
 * Now the refusal is the parent's KOF_BROKEN_LIMIT, and every refusal either keeps every member
 * or says so. The parse-level sweep above asserts the same of the tables of a view and the
 * ladder of ceilings of the whole scan.
 */
static void engine_sweep(const struct fmt *f)
{
	struct made m = f->build(1500, K_CLEAN);
	long count, nth, hits = 0, silent = 0;
	struct seen s;

	if (!m.p)
		return;
	fa_init();
	fa_arm_min(4096, 0);
	scan(m.p, m.len, &s, 0);
	count = fa_count();
	(void)fa_disarm_hit();
	for (nth = 1; nth <= count; nth++) {
		unsigned kids;

		fa_arm_min(4096, nth);
		scan(m.p, m.len, &s, 0);
		if (!fa_disarm_hit())
			continue;
		hits++;
		kids = s.objs ? s.objs - 1u : 0u;
		if (kids < m.kids && !s.any_broken && !s.top_broken)
			silent++;
	}
	printf("  engine, %-6s scan sweep: %ld allocations of 4 KiB and up, %ld refused in turn, %ld lost members silently (the child sink)\n",
	       f->name, count, hits, silent);
	CK(hits > 0, "%s: no allocation of 4 KiB and up was reached by the sweep", f->name);
	CK(silent == 0, "%s: %ld refusal(s) lost members and said nothing", f->name, silent);
	free(m.p);
}
#endif

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	static const unsigned ns[] = { 2100, 5000, 20000 };
	unsigned i, k;

	printf("== tar, lha, arj, cab, chm, docole, rar, 7z: tables the size of the file, bounded by it and by the ledger\n");
	for (i = 0; i < sizeof fmts / sizeof fmts[0]; i++) {
		const struct fmt *f = &fmts[i];

		for (k = 0; k < sizeof ns / sizeof ns[0]; k++)
			whole(f, ns[k] > f->max_n ? f->max_n : ns[k]);
		hostile(f);
		ledger(f, 5000);
#if FA_AVAILABLE
		sweep_parse(f);
#endif
	}
#if !FA_AVAILABLE
	printf("  allocation sweeps skipped: a sanitizer owns malloc here\n");
#endif

	eng = keng_open(db);
	if (!eng) {
		printf("view_tables_arch: no database at %s - the engine half was not run\n", db);
	} else {
		sc = kscan_new(eng);
		CK(sc != NULL, "scanner");
		if (sc) {
			for (i = 0; i < sizeof fmts / sizeof fmts[0]; i++) {
				const struct fmt *f = &fmts[i];

				for (k = 0; k < sizeof ns / sizeof ns[0]; k++)
					engine_whole(f, ns[k] > f->max_n ? f->max_n : ns[k]);
				engine_default(f, 5000);
				engine_default(f, 20000u > f->max_n ? f->max_n : 20000u);
				engine_ladder(f, 20000);
#if FA_AVAILABLE
				engine_sweep(f);
#endif
			}
			kscan_free(sc);
		}
		keng_close(eng);
	}
	if (fails) {
		printf("view_tables_arch: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("view_tables_arch: whole, bounded, reported - ok\n");
	return 0;
}
