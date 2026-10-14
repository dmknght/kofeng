/*
 * endian_view - a rule cut from the little-endian build finds the big-endian one.
 *
 * The scanner makes the normalised view of a big-endian ELF in the canonical byte
 * order (libgenome/genotype/image/endian.h) when - and only when - a loaded rule
 * could use it. This is that, end to end, from an in-memory object to a finding:
 *
 *   1  differential    tests/sigs/sig_endian_mips_00.c is twelve instruction words in the
 *                      order a little-endian MIPS object holds them. It finds the
 *                      little-endian object, does NOT find the big-endian object of the same
 *                      program, and DOES find that object's view. The same for PowerPC64.
 *   2  the block path  a similarity block (tests/sigs/mutations/fixture_00.c) written into a function
 *                      of the object is scored on the little-endian object, not on the big-endian
 *                      one, and is on its view: the view's functions are the parent's, found again
 *   3  the view        is the little-endian twin where the normaliser did not shorten it: the
 *                      ELF header, the code and every table the plan swaps, each found whole
 *   4  no cross-arch   the same words in an ARM object are no MIPS or PowerPC64 detection,
 *                      in the object or in its view
 *   5  gating          an engine with no ELF rule makes no endian view; an architecture with no
 *                      little-endian twin gets one only for UTF-16BE text and keeps its code;
 *                      without that text it gets none
 *   6  wide text       a UTF-16BE string of a big-endian object reads as ASCII in the view
 *   7  limits          a view the ceiling refuses is reported for a big-endian object that
 *                      needed it, and for none that did not
 *   8  plan bound      a plan past its span bound is reported as a limit of the object
 *   9  threads         four scanners over one engine give one answer
 */

#define _GNU_SOURCE

#define EK_MAX 16384u
#define EK_CODE_UNITS 1500u

#include <pthread.h>
#include <sys/stat.h>

#include "../lib/genome/endian_kit.h"
#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofentry.h"
#include "../../libkofeng/kofcore/kofbudget.h"

#define MAXV 12288u

struct seen {
	unsigned objects, views;
	int parent_mips, parent_ppc, view_mips, view_ppc;
	uint32_t parent_broken;
	uint8_t view[MAXV];
	uint32_t view_n;
	int view_wide;          /* the narrowed string is in the view */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;
	uint32_t i;
	int is_view = res && res->entry_kind == KOF_ENT_NORMALIZED;

	(void)name;
	s->objects++;
	if (!res)
		return 0;
	if (s->objects == 1)
		s->parent_broken = res->broken;
	if (is_view) {
		s->views++;
		if (len <= MAXV) {
			memcpy(s->view, bytes, (size_t)len);
			s->view_n = (uint32_t)len;
		}
		if (memmem(bytes, (size_t)len, "cmd.exe /c wget", 15))
			s->view_wide = 1;
	}
	for (i = 0; i < res->n; i++) {
		if (strstr(res->v[i].name, "EndianMips"))
			is_view ? (void)(s->view_mips = 1) : (void)(s->parent_mips = 1);
		if (strstr(res->v[i].name, "EndianPpc64"))
			is_view ? (void)(s->view_ppc = 1) : (void)(s->parent_ppc = 1);
	}
	return 0;
}

static int scan(kof_scanner *sc, const uint8_t *b, uint32_t n, struct seen *s,
		uint64_t max_resident)
{
	struct kof_scan_option opt;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = max_resident ? max_resident : 256u << 20;
	opt.max_object_bytes = 64u << 20;
	return kscan_bytes(sc, b, n, "endian", &opt, on_object, s) > 0;
}

static const struct ek_arch *arch_named(const char *name)
{
	unsigned i;

	for (i = 0; i < EK_NARCH; i++)
		if (!strcmp(ek_archs[i].name, name))
			return &ek_archs[i];
	for (i = 0; i < EK_NNOTWIN; i++)
		if (!strcmp(ek_notwin[i].name, name))
			return &ek_notwin[i];
	return NULL;
}

static int has(const uint8_t *v, uint32_t n, const uint8_t *p, uint32_t len)
{
	return len <= n && memmem(v, n, p, len) != NULL;
}

/*
 * THE VIEW IS THE TWIN where it is not shorter. The normaliser collapses zero runs (the
 * null section header is one), so the view is not the object's length and cannot be
 * compared byte for byte; what is compared is every piece the canonical form changes: the
 * ELF header, the code, and the tables it swaps, each found whole in the view.
 */
static unsigned differs_from_twin(const struct ek_obj *twin, const uint8_t *v, uint32_t n)
{
	unsigned bad = 0, k;
	static const unsigned tables[] = { EK_SYMTAB, EK_RELA, EK_REL, EK_DYNAMIC, EK_HASH,
					   EK_GNUHASH, EK_VERSYM, EK_INITARR, EK_WORDS };

	bad += n < 52u || memcmp(v, twin->b, 52u) != 0;
	bad += !has(v, n, twin->b + twin->text, twin->text_len);
	for (k = 0; k < sizeof tables / sizeof tables[0]; k++)
		bad += !has(v, n, twin->b + twin->sec_off[tables[k]], twin->sec_len[tables[k]]);
	return bad;
}

static void differential(kof_scanner *sc, const char *name, int ppc)
{
	static struct ek_obj be, le;
	struct seen s;
	const struct ek_arch *a = arch_named(name);

	ek_build(&be, a, 1, 1);
	ek_build(&le, a, 0, 1);

	CK(scan(sc, le.b, le.n, &s, 0));
	CK(ppc ? s.parent_ppc : s.parent_mips);          /* the rule finds the build it was cut from */
	CK(s.views <= 1);                                /* a view of it, if any, is the ordinary one */

	CK(scan(sc, be.b, be.n, &s, 0));
	CK(!(ppc ? s.parent_ppc : s.parent_mips));       /* not the object: the words are the other way round */
	CK(s.views == 1);
	CK(ppc ? s.view_ppc : s.view_mips);              /* the view: found */
	CK(differs_from_twin(&le, s.view, s.view_n) == 0);
	CK(s.view_wide);                                 /* the UTF-16BE string, as ASCII */
}

/* The same twelve words in another architecture are another program. */
static void cross_arch(kof_scanner *sc)
{
	static struct ek_obj be;
	struct seen s;
	unsigned k;
	const char *names[] = { "arm-be32", "sh", "microblaze" };

	for (k = 0; k < 3; k++) {
		ek_build(&be, arch_named(names[k]), 1, 1);
		CK(scan(sc, be.b, be.n, &s, 0));
		CK(!s.parent_mips && !s.parent_ppc && !s.view_mips && !s.view_ppc);
	}
}

static void gating(kof_scanner *sc, kof_scanner *script_only)
{
	static struct ek_obj be;
	struct seen s;
	uint32_t i;
	const struct ek_arch *sparc = arch_named("sparc");

	/* An engine with no ELF rule: no view, and nothing broken about it */
	ek_build(&be, arch_named("mips32"), 1, 1);
	CK(scan(script_only, be.b, be.n, &s, 0));
	CK(s.parent_broken == 0);
	/* the ordinary view, if one is made, holds the code as it was: nothing was swapped */
	CK(s.views == 0 || has(s.view, s.view_n, be.b + be.text, be.text_len));

	/* SPARC has no little-endian twin: with UTF-16BE text there is a view of that text and
	 * the code is the big-endian bytes it was */
	ek_build(&be, sparc, 1, 1);
	{
		static struct ek_obj copy;

		memcpy(&copy, &be, sizeof be);
		CK(scan(sc, be.b, be.n, &s, 0));
		CK(s.views == 1);
		CK(s.view_wide);
		CK(has(s.view, s.view_n, copy.b + copy.text, copy.text_len));   /* the code as it was */
		CK(s.view_n > 5u && s.view[5] == 2);      /* still declared big-endian */
	}
	/* ... and without the text, nothing to show: no view */
	ek_build(&be, sparc, 1, 1);
	for (i = 0; i < 2u * be.wide_chars + 2u; i++)
		be.b[be.wide_at + i] = (uint8_t)(0xf1 + (i & 3u));
	CK(scan(sc, be.b, be.n, &s, 0));
	CK(s.views == 0);
}

/* A big-endian object of `extra` bytes more than the kit makes, the added bytes all non-zero so
 * the normaliser has nothing to collapse in them; with or without its UTF-16 string. */
static uint8_t ov_be[4u << 20], ov_le[4u << 20];

static void blank_wide(struct ek_obj *e)
{
	uint32_t i;

	for (i = 0; i < 2u * e->wide_chars + 2u; i++)
		e->b[e->wide_at + i] = (uint8_t)(0xf1 + (i & 3u));
}

/*
 * The view is refused by the LEDGER, and only then is it a limit. The engine's cap is the knob
 * (keng_set_memory_cap, its 16 MiB floor): the object grows until the allowance left for its view
 * - half of the resident share, the view being built in one buffer beside the object's own -
 * is gone. The little-endian twin, written with no text to narrow, needs no view and says
 * nothing at any size the object itself fits in.
 */
static void limits(const char *db)
{
	static struct ek_obj be, le;
	struct seen s, sl;
	kof_engine *e = keng_open(db);
	kof_scanner *sc;
	uint32_t i, n;
	unsigned reported = 0, refused = 0, granted = 0;

	CK(e != NULL);
	if (!e)
		return;
	CK(keng_set_memory_cap(e, KOF_ENGINE_MEM_MIN) == 1);
	sc = kscan_new(e);
	CK(sc != NULL);
	ek_build(&be, arch_named("mips32"), 1, 1);
	ek_build(&le, arch_named("mips32"), 0, 1);
	blank_wide(&le);                /* the twin has nothing to show: no view is needed */
	memcpy(ov_be, be.b, be.n);
	memcpy(ov_le, le.b, le.n);
	{
		uint32_t z = 1;

		for (i = be.n; i < sizeof ov_be; i++) {
			z = z * 1103515245u + 12345u;
			ov_be[i] = ov_le[i] = (uint8_t)(1u | (z >> 16));
		}
	}
	for (n = be.n; sc && n <= sizeof ov_be; n += 32768u) {
		if (!scan(sc, ov_le, n, &sl, 0) || sl.parent_broken != 0)
			continue;       /* too big for the object itself: nothing to compare */
		(void)scan(sc, ov_be, n, &s, 0);
		if (s.views == 0) {
			refused++;
			/* The big-endian object needed its view and did not get it: said. */
			reported += s.parent_broken == KOF_BROKEN_LIMIT;
		} else {
			granted++;
			CK(s.parent_broken == 0);
		}
	}
	CK(granted > 0);
	CK(refused > 0);
	CK(reported == refused);
	if (sc)
		kscan_free(sc);
	keng_close(e);
}

/*
 * A SMALL big-endian object gets its view at every engine cap, and is never a limit: the ledger
 * has room for twice a few kilobytes at the floor, and the view is judged against the ledger
 * alone. (It was reported as a limit whenever the probe that asks "can a view result at all" read
 * the big-endian bytes, which show nothing a view would add - the swap is what makes the view.)
 */
static void small_object(const char *db)
{
	static struct ek_obj be, le;
	static const uint64_t caps[] = { 0, 16u << 20, 32u << 20, 64u << 20 };
	unsigned k;

	/* No text to narrow and no zero run to decode: what makes the view is the swap alone, as
	 * in a stripped router binary - and the bytes the normaliser's own probes read show none. */
	ek_build(&be, arch_named("mips32"), 1, 1);
	ek_build(&le, arch_named("mips32"), 0, 1);
	blank_wide(&be);
	blank_wide(&le);
	for (k = 0; k < sizeof caps / sizeof caps[0]; k++) {
		kof_engine *e = keng_open(db);
		kof_scanner *sc;
		struct seen s;

		CK(e != NULL);
		if (!e)
			continue;
		CK(keng_set_memory_cap(e, caps[k]) == 1);
		sc = kscan_new(e);
		CK(sc != NULL);
		if (sc) {
			CK(scan(sc, be.b, be.n, &s, 0));
			CK(s.views == 1 && s.view_mips);
			CK(s.parent_broken == 0);
			CK(scan(sc, le.b, le.n, &s, 0));
			CK(s.parent_broken == 0);
			kscan_free(sc);
		}
		keng_close(e);
	}
}


/*
 * THE BLOCK PATH, end to end. tests/sigs/mutations/fixture_00.c is a similarity rule over the
 * 2048 bytes a named generator makes; here they are a function of a MIPS (or PowerPC64)
 * object, written in that object's order. The little-endian object scores the block on
 * itself; the big-endian one does not - its bytes are the other way round - and does through
 * its view, whose functions the endian step finds again from the parent's: the plan is applied
 * to each function before it is looked for (kgenome_funcs_remap_endian).
 */
static void make_block(uint8_t *b)
{
	uint32_t s = 0xC0FFEEu, i;

	for (i = 0; i < 2048u; i++) {
		s ^= s << 13; s ^= s >> 17; s ^= s << 5;
		b[i] = (uint8_t)s;
	}
}

/* Entry 1 of the symbol table is the function, entry 0 stays null. */
static void put_block_function(struct ek_obj *e, const struct ek_arch *a, int be, const uint8_t *blk)
{
	uint32_t i;
	uint8_t *s = e->b + e->sec_off[EK_SYMTAB] + (a->is64 ? 24u : 16u);

	for (i = 0; i < 2048u; i += 4u)
		ek_put(e->b + e->text + i, (uint32_t)blk[i] | (uint32_t)blk[i + 1u] << 8 |
		       (uint32_t)blk[i + 2u] << 16 | (uint32_t)blk[i + 3u] << 24, 4, be);
	memset(s, 0, a->is64 ? 24u : 16u);
	if (a->is64) {
		s[4] = 0x12;
		ek_put(s + 6, 1, 2, be);
		ek_put(s + 8, 0x400000u + e->text, 8, be);
		ek_put(s + 16, 2048, 8, be);
	} else {
		ek_put(s + 4, 0x400000u + e->text, 4, be);
		ek_put(s + 8, 2048, 4, be);
		s[12] = 0x12;
		ek_put(s + 14, 1, 2, be);
	}
}

static int fixture_found(const char *name, const void *bytes, uint64_t len,
			 const struct kof_result *res, void *user)
{
	int *hit = user;
	uint32_t i;

	(void)name; (void)bytes; (void)len;
	for (i = 0; res && i < res->n; i++)
		if (strstr(res->v[i].name, "EndianBlock")) {
			hit[res->entry_kind == KOF_ENT_NORMALIZED ? 1 : 0] = 1;
		}
	return 0;
}

static void block_path(kof_scanner *sc)
{
	static struct ek_obj be, le;
	uint8_t blk[2048];
	const char *names[] = { "mips32", "ppc64" };
	unsigned k;

	make_block(blk);
	for (k = 0; k < 2; k++) {
		const struct ek_arch *a = arch_named(names[k]);
		int hit[2];
		struct kof_scan_option opt;

		memset(&opt, 0, sizeof opt);
		opt.all_matches = 1;
		opt.max_produced_bytes = 64u << 20;
		opt.max_resident_bytes = 256u << 20;
		opt.max_object_bytes = 64u << 20;
		ek_build(&be, a, 1, 1);
		ek_build(&le, a, 0, 1);
		put_block_function(&be, a, 1, blk);
		put_block_function(&le, a, 0, blk);
		hit[0] = hit[1] = 0;
		CK(kscan_bytes(sc, le.b, le.n, "block-le", &opt, fixture_found, hit) > 0);
		/* The little-endian object holds the block. (Where the engine scores it is its own
		 * business and not this test's: measured on the unmodified engine, the parent of
		 * this object is not credited and its ordinary view is.) */
		CK(hit[0] || hit[1]);
		hit[0] = hit[1] = 0;
		CK(kscan_bytes(sc, be.b, be.n, "block-be", &opt, fixture_found, hit) > 0);
		CK(!hit[0]);                            /* the big-endian object does not */
		CK(hit[1]);                             /* its canonical view does */
	}
}


/* A plan that hit its bound is a limit of the object, said in `broken`; the same object
 * little-endian has nothing to bound. */
static void plan_bound(kof_scanner *sc)
{
	enum { RECS = 70000 };
	static struct ek_obj be;
	static uint8_t big[EK_MAX + 12u * RECS], le_big[EK_MAX + 12u * RECS];
	struct ek_obj le;
	struct seen s;
	uint32_t n, sh;

	ek_build(&be, arch_named("mips32"), 1, 1);
	ek_build(&le, arch_named("mips32"), 0, 1);
	memcpy(big, be.b, be.n);
	memcpy(le_big, le.b, le.n);
	n = be.n + 12u * RECS;
	sh = be.sh + (EK_NOTE + 2u) * 40u;
	ek_put(big + sh + 16, be.n, 4, 1);
	ek_put(big + sh + 20, 12u * RECS, 4, 1);
	ek_put(le_big + sh + 16, be.n, 4, 0);
	ek_put(le_big + sh + 20, 12u * RECS, 4, 0);
	CK(scan(sc, big, n, &s, 0));
	CK(s.parent_broken == KOF_BROKEN_LIMIT);
	CK(scan(sc, le_big, n, &s, 0));
	CK(s.parent_broken == 0);
}

struct tj {
	kof_engine *eng;
	const uint8_t *b;
	uint32_t n;
	int ok;
	uint8_t view[MAXV];
	uint32_t view_n;
};

static void *worker(void *arg)
{
	struct tj *t = arg;
	kof_scanner *sc = kscan_new(t->eng);
	unsigned i;

	t->ok = sc != NULL;
	for (i = 0; sc && i < 40; i++) {
		struct seen s;

		if (!scan(sc, t->b, t->n, &s, 0) || !s.view_mips || s.views != 1) {
			t->ok = 0;
			break;
		}
		if (!i) {
			memcpy(t->view, s.view, s.view_n);
			t->view_n = s.view_n;
		} else if (s.view_n != t->view_n || memcmp(t->view, s.view, s.view_n)) {
			t->ok = 0;
			break;
		}
	}
	if (sc)
		kscan_free(sc);
	return NULL;
}

static void threads(kof_engine *eng)
{
	static struct ek_obj be;
	struct tj tj[4];
	pthread_t th[4];
	unsigned i;

	ek_build(&be, arch_named("mips32"), 1, 1);
	for (i = 0; i < 4; i++) {
		memset(&tj[i], 0, sizeof tj[i]);
		tj[i].eng = eng;
		tj[i].b = be.b;
		tj[i].n = be.n;
		CK(pthread_create(&th[i], NULL, worker, &tj[i]) == 0);
	}
	for (i = 0; i < 4; i++) {
		(void)pthread_join(th[i], NULL);
		CK(tj[i].ok);
		CK(tj[i].view_n == tj[0].view_n && !memcmp(tj[i].view, tj[0].view, tj[0].view_n));
	}
}

/* A database that is one pack of the test set: its script rules, none for an ELF. */
static kof_engine *engine_of_pack(const char *dir, const char *pack)
{
	char from[600], to[600], gate[600];
	FILE *a, *b;
	uint8_t buf[4096];
	size_t n;

	snprintf(gate, sizeof gate, "%.400s/../endian_gate", dir);
	(void)mkdir(gate, 0777);
	snprintf(from, sizeof from, "%.400s/%.100s", dir, pack);
	snprintf(to, sizeof to, "%.450s/%.100s", gate, pack);
	a = fopen(from, "rb");
	b = fopen(to, "wb");
	if (!a || !b) {
		if (a)
			fclose(a);
		if (b)
			fclose(b);
		return NULL;
	}
	while ((n = fread(buf, 1, sizeof buf, a)) > 0)
		(void)fwrite(buf, 1, n, b);
	fclose(a);
	fclose(b);
	return keng_open(gate);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine *eng = keng_open(db), *eng2;
	kof_scanner *sc, *sc2;

	if (!eng) {
		printf("  FAIL cannot open %s\n", db);
		return 1;
	}
	sc = kscan_new(eng);
	eng2 = engine_of_pack(db, "sigs-script.ksig");
	CK(eng2 != NULL);
	sc2 = eng2 ? kscan_new(eng2) : NULL;
	CK(sc && sc2);
	if (sc && sc2) {
		differential(sc, "mips32", 0);
		differential(sc, "ppc64", 1);
		cross_arch(sc);
		block_path(sc);
		gating(sc, sc2);
		limits(db);
		small_object(db);
		plan_bound(sc);
		threads(eng);
	}
	if (sc)
		kscan_free(sc);
	if (sc2)
		kscan_free(sc2);
	keng_close(eng);
	if (eng2)
		keng_close(eng2);
	if (hk_fails) {
		printf("endian_view: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("endian_view: ok\n");
	return 0;
}
