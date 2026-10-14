/*
 * pattern_equal_markers.c - markers that compare EQUAL in an ordering a table might use, and markers that
 * share a key.
 *
 * The bisect table this test was written for is gone (kofpix.h replaced the five table shapes), and what it
 * found is still the question: two markers that fold to the same bytes ("ptrace" and "Ptrace" beside one
 * ICASE marker), or two hex programs that share their concrete run, must BOTH be found. Measured on 100 000
 * markers of real strings the old table lost 499 of them over 42 of 67 objects. The sweep keys each marker
 * on four bytes that other markers share, sorts the survivors by directory bucket and searches inside it, so
 * the same families of input are what can break it, and they are the input here.
 *
 * Two parts, both through a real pack (kof_pack_build_opt, written, kof_db_load) so the table that is asked
 * is the one the loader opens - read with pread from the pack's tail in half the runs and built in memory
 * from the pack's own sections in the other half:
 *
 *   1. A fixed region of 140 markers on one four-byte key, holding case variants of one word, an ICASE one
 *      that makes the region fold, two hex programs with one anchor run, and the prefix chain of that
 *      anchor. An object plants each of them and the test names what must be found - and nothing else.
 *
 *   2. A property run: random marker sets with many equal-in-order siblings, prefix chains, case-exact and
 *      ICASE markers side by side and hex programs, in three shapes (a deep shared key, a shallow one, long
 *      markers only), against a reference that tries every marker at every position of the extent.
 *
 * The reference reads the markers the TEST declared and applies each marker's own flags with the same literal
 * rule and the same hex walk as the matcher; what it does not use is any key, directory, filter, order or
 * record, which is what is under test.
 */

#include "hostile_engine.h"

#include <stddef.h>
#include <sys/stat.h>

#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/pack/hexprog.h"
#include "../../libkofeng/detectors/pattern/kofmatch.h"
#include "../../libkofeng/detectors/pattern/kofmultimatch.h"
#include "../../libkofeng/detectors/pattern/kofpix.h"
#include <kofmod/kofsig.h>

#define SCANBIT 2u
#define MAX_MK  512u
#define MAX_LEN 40u

static char tmp[300];

/* One marker as the test declares it. */
struct mk {
	uint8_t  b[MAX_LEN];     /* literal bytes, or the hex anchor run */
	uint16_t len;
	uint8_t  flags;
	uint8_t  hex;
	uint8_t  tail;           /* hex: the byte after the one wildcard */
	_Alignas(8) uint8_t prog[256];     /* read as a struct by the walk: aligned */
	uint32_t plen;
};

static struct mk mks[MAX_MK];
static uint32_t  n_mk;

/* ---- building the pack and loading it ----------------------------------------------------- */

static uint8_t *build_pack(size_t *len, int embed)
{
	struct kof_pack_opt opt = { embed ? 1u : 0u };
	static uint8_t code[] = { 0x90, 0xc3 };
	static struct kof_pw_str strs[MAX_MK];
	static struct kof_pw_name names[1];
	static struct kof_pw_mod mods[MAX_MK / KOF_MAX_STR_PER_MODULE + 1u];
	static const uint32_t rng[1] = { 1u << SCANBIT };
	const uint32_t per = KOF_MAX_STR_PER_MODULE, nm = (n_mk + per - 1u) / per;
	uint32_t i;

	for (i = 0; i < n_mk; i++) {
		strs[i].bytes = mks[i].hex ? mks[i].prog : mks[i].b;
		strs[i].len = mks[i].hex ? (uint16_t)mks[i].plen : mks[i].len;
		strs[i].kind = mks[i].hex ? KOF_STR_HEX : KOF_STR_LITERAL;
		strs[i].flags = mks[i].flags;
	}
	names[0].id = 1;
	names[0].text = "Test.Equal";
	memset(mods, 0, sizeof mods);
	for (i = 0; i < nm; i++) {
		struct kof_pw_mod *m = &mods[i];

		m->code = code;
		m->code_len = sizeof code;
		m->n_target = 1;
		m->target[0] = KOF_FMT_UNKNOWN;
		m->scan_mask = 1u << SCANBIT;
		m->size_min = 1;
		m->str = strs + (size_t)i * per;
		m->n_str = i + 1u == nm ? n_mk - i * per : per;
		m->rng = rng;
		m->n_rng = 1;
		m->name = names;
		m->n_names = 1;
	}
	return kof_pack_build_opt(KOF_PACK_DETECT, mods, nm, &opt, len);
}

static struct kof_engine *load_markers(int embed)
{
	char dir[400], path[500];
	size_t len = 0;
	uint8_t *img = build_pack(&len, embed);
	struct kof_engine *e;
	FILE *f;

	if (!img)
		return NULL;
	snprintf(dir, sizeof dir, "%s/pack", tmp);
	mkdir(dir, 0700);
	snprintf(path, sizeof path, "%s/pack.ksig", dir);
	f = fopen(path, "wb");
	if (!f) {
		free(img);
		return NULL;
	}
	fwrite(img, 1, len, f);
	fclose(f);
	free(img);
	e = kof_db_load(dir);
	return e;
}

/* ---- declaring markers ---------------------------------------------------------------------- */

static struct mk *add_lit(const char *text, uint8_t flags)
{
	struct mk *k = &mks[n_mk++];

	memset(k, 0, sizeof *k);
	k->len = (uint16_t)strlen(text);
	memcpy(k->b, text, k->len);
	k->flags = flags;
	return k;
}

/* "<anchor bytes> ?? <tail>": the anchor is the longest concrete run, so it is what the table keys. */
static struct mk *add_hex(const uint8_t *anchor, uint16_t alen, uint8_t tail)
{
	struct mk *k = &mks[n_mk++];
	char txt[MAX_LEN * 3 + 16];
	struct kof_hex_stat st;
	uint32_t i, n = 0;

	memset(k, 0, sizeof *k);
	for (i = 0; i < alen; i++)
		n += (uint32_t)snprintf(txt + n, sizeof txt - n, "%02X ", anchor[i]);
	snprintf(txt + n, sizeof txt - n, "?? %02X", tail);
	k->plen = kof_hex_compile(txt, k->prog, sizeof k->prog, &st);
	if (!k->plen || st.anchor_len != alen) {
		printf("  FAIL hex program \"%s\" did not compile to a %u byte anchor\n", txt, alen);
		he_fails++;
		k->plen = 0;
	}
	memcpy(k->b, anchor, alen);
	k->len = alen;
	k->hex = 1;
	k->tail = tail;
	return k;
}

/* ---- the reference ------------------------------------------------------------------------- */

/* The marker as the matcher's verification sees it: the test's own bytes, not the table's. */
static void pat_of(const struct mk *k, struct kof_multimatch_pat *p)
{
	memset(p, 0, sizeof *p);
	p->b = k->b;
	p->len = k->len;
	p->flags = k->flags;
	p->is_hex = k->hex;
	p->prog = k->hex ? k->prog : NULL;
}

static int ref_at(const struct kof_multimatch_pat *p, kof_buf lim, uint64_t at)
{
	uint16_t i;

	if (p->is_hex)
		return kof_hex_walk_flags(lim, at, p->prog, p->flags);
	if (at + p->len > lim.n)
		return 0;
	for (i = 0; i < p->len; i++) {
		uint8_t x = lim.p[at + i], y = p->b[i];

		if (p->flags & KOF_STR_ICASE) {
			x = kof_lower_byte(x);
			y = kof_lower_byte(y);
		}
		if (x != y)
			return 0;
	}
	return 1;
}

/* Is the marker anywhere in [off, off+len) of d - every marker at every position. */
static int ref_find(const struct kof_multimatch_pat *p, kof_buf d, uint64_t off, uint64_t len)
{
	kof_buf lim = d;
	uint64_t at;

	if (off > d.n)
		return 0;
	if (len > d.n - off)
		len = d.n - off;
	lim.n = off + len;
	for (at = off; at < lim.n; at++)
		if (ref_at(p, lim, at))
			return 1;
	return 0;
}

/* The id the pack gave marker k (the table's answers are by id): found by what it is, in the pack's own
 * string table - bytes and options for a literal, the program for a hex marker. */
static int uid_of(const struct kof_engine *e, uint32_t k, uint32_t *uid)
{
	const struct kof_db_pack *pk = &e->packs[0];
	uint32_t s;

	for (s = 0; s < pk->n_desc; s++) {
		const struct kof_str_ent *d = &pk->desc[s];
		const uint8_t *bytes = pk->pool + d->off;

		if ((d->kind == KOF_STR_HEX) != (mks[k].hex != 0))
			continue;
		if (mks[k].hex) {
			if (d->len == mks[k].plen && !memcmp(bytes, mks[k].prog, mks[k].plen)) {
				*uid = d->uid;
				return 1;
			}
		} else if (d->len == mks[k].len && d->flags == mks[k].flags && !memcmp(bytes, mks[k].b, d->len)) {
			*uid = d->uid;
			return 1;
		}
	}
	return 0;
}

/*
 * One sweep of the region over `buf` against the reference, every declared marker compared.
 * Returns the number that differ; the first few are printed.
 */
static uint32_t compare_sweep(const struct kof_engine *e, struct kofpix_ctx *ctx,
			      const uint8_t *buf, uint64_t n, uint64_t off, uint64_t len,
			      uint32_t *n_found, const char *what)
{
	struct kof_match_ctx m;
	struct kof_range ext;
	uint32_t k, bad = 0;

	ext.off = off;
	ext.len = len;
	memset(&m, 0, sizeof m);
	kof_match_begin(&m, kof_buf_make(buf, n));
	kofpix_ctx_begin(ctx);
	kofpix_sweep(e->pix_set, ctx, SCANBIT, &m, &ext, 1);
	if (ctx->last) {
		printf("  FAIL %s: the sweep did not finish (status 0x%x)\n", what, ctx->last);
		return 1;
	}
	for (k = 0; k < n_mk; k++) {
		struct kof_multimatch_pat p;
		uint32_t uid;
		int want, got;

		if (!uid_of(e, k, &uid)) {
			printf("  FAIL %s: marker %u has no id in the pack\n", what, k);
			bad++;
			continue;
		}
		pat_of(&mks[k], &p);
		want = ref_find(&p, kof_buf_make(buf, n), off, len);
		got = (int)((kofpix_found_get(ctx, uid) >> SCANBIT) & 1u);
		*n_found += (uint32_t)got;
		if (want != got) {
			if (bad < 4)
				printf("  FAIL %s: marker %u (%s len %u flags %u \"%.*s\") %s\n", what, k,
				       mks[k].hex ? "hex" : "literal", mks[k].len, mks[k].flags, mks[k].hex ? 0 : mks[k].len,
				       (const char *)mks[k].b, want ? "is present and was NOT found" : "was reported and is absent");
			bad++;
		}
	}
	return bad;
}

/* ---- part 1: the fixed region ---------------------------------------------------------------- */

#define FILLERS 140u

enum { M_LOWER, M_TITLE, M_UPPER, M_ICASE, M_HEX1, M_HEX2, M_FILLER0 };

static const uint8_t anchor[] = { 'p', 't', 'r', 'a', 'c', 'e', 'X', 'Y' };

/* What an object holding `plant` must report, named by marker index. */
struct plant {
	const char *what;
	const char *bytes;
	uint32_t    len;
	int         want[8];     /* marker indices, -1 ends */
};

static void t_fixed(void)
{
	static const struct plant plants[] = {
		{ "lower",        "..ptrace..",         10, { M_LOWER, M_ICASE, -1 } },
		{ "title",        "..Ptrace..",         10, { M_TITLE, M_ICASE, -1 } },
		{ "upper",        "..PTRACE..",         10, { M_UPPER, M_ICASE, -1 } },
		{ "mixed",        "..PtRaCe..",         10, { M_ICASE, -1 } },
		{ "hex 1",        "..ptraceXYQ1..",     14, { M_LOWER, M_ICASE, M_HEX1, -1 } },
		{ "hex 2",        "..ptraceXYQ2..",     14, { M_LOWER, M_ICASE, M_HEX2, -1 } },
		{ "hex, no tail", "..ptraceXYQ3..",     14, { M_LOWER, M_ICASE, -1 } },
		{ "both hex",     "ptraceXYQ1.ptraceXYQ2", 21, { M_LOWER, M_ICASE, M_HEX1, M_HEX2, -1 } },
		{ "all four",     "ptrace.Ptrace.PTRACE.pTrace", 27, { M_LOWER, M_TITLE, M_UPPER, M_ICASE, -1 } },
		{ "a filler",     "..ptraf007..",       12, { M_FILLER0 + 7, -1 } },
		{ "nothing",      "..ptrac..PtracF..",  17, { -1 } },
	};
	struct kof_engine *e;
	struct kofpix_ctx ctx;
	uint32_t i, k, p, mode;
	char txt[16];

	for (mode = 0; mode < 2u; mode++) {
		n_mk = 0;
		add_lit("ptrace", 0);
		add_lit("Ptrace", 0);
		add_lit("PTRACE", 0);
		add_lit("pTrace", KOF_STR_ICASE);
		add_hex(anchor, sizeof anchor, '1');
		add_hex(anchor, sizeof anchor, '2');
		for (i = 0; i < FILLERS; i++) {
			snprintf(txt, sizeof txt, "ptraf%03u", i);
			add_lit(txt, 0);
		}
		e = load_markers((int)mode);
		if (!e || !e->pix_set || !e->packs[0].pix) {
			CK(0, "the fixed pack did not load with a table (%s)", mode ? "in the pack" : "in memory");
			if (e)
				kof_db_free(e);
			return;
		}
		CK(e->packs[0].has_pix == (int)mode && e->packs[0].pix_in_ram == (int)!mode,
		   "the table is %s", mode ? "read from the pack's tail" : "built in memory from its sections");
		CK(kofpix_region_n(e->packs[0].pix, SCANBIT) == n_mk, "the region holds all %u markers (%u)", n_mk,
		   kofpix_region_n(e->packs[0].pix, SCANBIT));
		if (!kofpix_ctx_init(&ctx, e->pix_set, 0)) {
			CK(0, "memory");
			kof_db_free(e);
			return;
		}
		for (p = 0; p < sizeof plants / sizeof plants[0]; p++) {
			struct kof_match_ctx m;
			struct kof_range ext;
			uint32_t hits = 0, want_n = 0;

			ext.off = 0;
			ext.len = plants[p].len;
			memset(&m, 0, sizeof m);
			kof_match_begin(&m, kof_buf_make(plants[p].bytes, plants[p].len));
			kofpix_ctx_begin(&ctx);
			kofpix_sweep(e->pix_set, &ctx, SCANBIT, &m, &ext, 1);
			for (k = 0; plants[p].want[k] >= 0; k++) {
				uint32_t uid = 0;
				int have = uid_of(e, (uint32_t)plants[p].want[k], &uid);

				want_n++;
				CK(have && ((kofpix_found_get(&ctx, uid) >> SCANBIT) & 1u), "%s, object \"%s\": marker %d is found",
				   mode ? "pack" : "memory", plants[p].what, plants[p].want[k]);
			}
			for (i = 0; i < n_mk; i++) {
				uint32_t uid;

				hits += uid_of(e, i, &uid) ? (kofpix_found_get(&ctx, uid) >> SCANBIT) & 1u : 0u;
			}
			CK(hits == want_n, "%s, object \"%s\": and nothing else (%u found, %u expected)", mode ? "pack" : "memory",
			   plants[p].what, hits, want_n);
		}
		kofpix_ctx_free(&ctx);
		kof_db_free(e);
	}
}

/* ---- part 2: the property run ---------------------------------------------------------------- */

static const char tail_alpha[] = "abAB";

/* Off for a set without an ICASE marker: its key then hashes by exact bytes, and case variants of it would be
 * spread over sixteen buckets, none of them deep. */
static int key_case = 1;

static uint8_t rnd_case(uint8_t c)
{
	return (uint8_t)((he_below(2u) && c >= 'a' && c <= 'z') ? c - 32u : c);
}

/* Four letters of key, then a short tail of two letters in two cases: siblings and prefix chains by construction. */
static int add_random_lit(const uint8_t *key, uint32_t min_tail, uint32_t max_tail, uint8_t flags)
{
	char t[MAX_LEN];
	uint32_t n = 0, i, tl = min_tail + he_below(max_tail - min_tail + 1u);

	for (i = 0; i < 4; i++)
		t[n++] = (char)(key_case ? rnd_case(key[i]) : key[i]);
	for (i = 0; i < tl; i++)
		t[n++] = tail_alpha[he_below(4u)];
	t[n] = 0;
	for (i = 0; i < n_mk; i++)       /* the packer interns equal bytes with equal flags to one uid */
		if (!mks[i].hex && mks[i].len == n && mks[i].flags == flags && !memcmp(mks[i].b, t, n))
			return 0;
	add_lit(t, flags);
	return 1;
}

static void add_random_hex(const uint8_t *key)
{
	uint8_t a[8];
	uint32_t i;

	for (i = 0; i < 4; i++)
		a[i] = key_case ? rnd_case(key[i]) : key[i];
	for (i = 4; i < 8; i++)
		a[i] = (uint8_t)tail_alpha[he_below(4u)];
	/* a small pool of anchors, so several programs share one run and differ only after the wildcard */
	if (he_below(2u))
		memcpy(a + 4, "abab", 4);
	add_hex(a, 8, (uint8_t)('1' + he_below(2u)));
}

/* A plant: the marker's bytes, in a random case when it folds and sometimes when it does not. */
static void plant_marker(uint8_t *buf, uint32_t n, const struct mk *k)
{
	uint32_t need = k->len + (k->hex ? 2u : 0u), at, i;

	if (need > n)
		return;
	at = he_below(n - need + 1u);
	for (i = 0; i < k->len; i++) {
		uint8_t c = k->b[i];

		if ((k->flags & KOF_STR_ICASE) ? he_below(2u) : !he_below(8u))
			c = (uint8_t)((c >= 'a' && c <= 'z') ? c - 32u : (c >= 'A' && c <= 'Z') ? c + 32u : c);
		buf[at + i] = c;
	}
	if (k->hex) {
		buf[at + k->len] = (uint8_t)tail_alpha[he_below(4u)];
		buf[at + k->len + 1u] = k->tail;
	}
}

enum { SHAPE_DEEP, SHAPE_SHALLOW, SHAPE_LONG, N_SHAPE };

static void make_set(uint32_t shape, const uint8_t *key)
{
	uint32_t n, i, tries = 0, n_hex = 0;
	int icase_wanted = he_below(8u) != 0;       /* one in eight has no ICASE marker: the order is not folded */

	n_mk = 0;
	key_case = icase_wanted;
	if (shape == SHAPE_DEEP)
		n = 130u + he_below(80u);
	else
		n = 12u + he_below(70u);
	while (n_mk < n && tries++ < 20000u) {
		uint8_t flags = (icase_wanted && he_below(5u) < 2u) ? KOF_STR_ICASE : 0;
		uint32_t lo = shape == SHAPE_LONG ? 4u : 0u, hi = shape == SHAPE_LONG ? 8u : 6u;

		add_random_lit(key, lo, hi, flags);
	}
	if (icase_wanted)
		add_random_lit(key, shape == SHAPE_LONG ? 4u : 0u, 6u, KOF_STR_ICASE);
	if (shape == SHAPE_SHALLOW)               /* one marker of five bytes at most: short ones beside the longer */
		add_random_lit(key, 0, 1, 0);
	n_hex = he_below(7u);
	for (i = 0; i < n_hex; i++)
		add_random_hex(key);
}

static void t_property(void)
{
	enum { RUNS = 3000, OBJECTS = 4 };
	static const uint8_t base_key[] = "ptra";
	uint32_t run, bad_runs = 0, total_found = 0, folded = 0, plain = 0, in_pack = 0, in_ram = 0;
	uint32_t objects = 0;
	uint8_t buf[400];

	he_seed(0x5eed0ff1ce5ull);
	for (run = 0; run < RUNS; run++) {
		uint32_t shape = run % N_SHAPE, obj, bad = 0, i, any_icase = 0;
		uint8_t key[4];
		struct kof_engine *e;
		struct kofpix_ctx ctx;

		for (i = 0; i < 4; i++)
			key[i] = (uint8_t)(he_below(3u) ? base_key[i] : 'a' + he_below(26u));
		make_set(shape, key);
		for (i = 0; i < n_mk; i++)
			any_icase |= (mks[i].flags & KOF_STR_ICASE) != 0;
		e = load_markers((int)(run & 1u));
		if (!e || !e->pix_set || !e->packs[0].pix) {
			/* a set no marker of which can be keyed has no table, and that is not a failure */
			if (e && !e->pix_markers) {
				kof_db_free(e);
				continue;
			}
			CK(0, "run %u: the pack did not load with a table", run);
			if (e)
				kof_db_free(e);
			continue;
		}
		in_pack += (uint32_t)e->packs[0].has_pix;
		in_ram += (uint32_t)e->packs[0].pix_in_ram;
		folded += any_icase;
		plain += !any_icase;
		if (!kofpix_ctx_init(&ctx, e->pix_set, 0)) {
			CK(0, "memory");
			kof_db_free(e);
			break;
		}
		for (obj = 0; obj < OBJECTS; obj++) {
			uint32_t n = 120u + he_below(sizeof buf - 120u), np = 4u + he_below(40u), j;
			uint64_t off = 0, len = n;
			char what[64];

			for (j = 0; j < n; j++) {
				uint32_t r = he_below(8u);

				buf[j] = r < 4 ? (uint8_t)tail_alpha[r] : r < 7 ? rnd_case(key[he_below(4u)]) : '.';
			}
			for (j = 0; j < np; j++)
				plant_marker(buf, n, &mks[he_below(n_mk)]);
			if (he_below(3u) == 0) {     /* an extent that may cut a marker at either edge, or run past the object */
				off = he_below(n);
				len = he_below(n + 16u);
			}
			snprintf(what, sizeof what, "run %u shape %u object %u", run, shape, obj);
			bad += compare_sweep(e, &ctx, buf, n, off, len, &total_found, what);
			objects++;
		}
		kofpix_ctx_free(&ctx);
		kof_db_free(e);
		bad_runs += bad != 0;
	}
	CK(bad_runs == 0, "%u of %u random marker sets differ from the reference", bad_runs, (unsigned)RUNS);
	CK(in_pack > 0 && in_ram > 0, "the table was read from the pack in %u runs and built in memory in %u", in_pack, in_ram);
	CK(folded > 0 && plain > 0, "sets with an ICASE marker (%u) and without (%u)", folded, plain);
	CK(total_found > 0, "the objects held markers (%u found over %u sweeps)", total_found, objects);
	printf("  property: %u sets, %u sweeps, %u markers found; %u with a table in the pack, %u in memory\n", (unsigned)RUNS, objects,
	       total_found, in_pack, in_ram);
}

/* ---- the run ---------------------------------------------------------------------------------- */

int main(void)
{
	snprintf(tmp, sizeof tmp, "build/test/pattern_equal_markers_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("pattern_equal_markers: no build/test directory - nothing tested\n");
		return 0;
	}
	t_fixed();
	t_property();
	he_rmtree(tmp);
	printf("pattern_equal_markers: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
