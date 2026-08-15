/*
 * hostile_fields.c - the fields that drive arithmetic, given the values that break it.
 *
 * The other fuzzers here generate whole structures at random and check what comes
 * out. This one does the opposite and it exists because the random ones missed a
 * bug that was reachable from four bytes: a section name offset pointing into a
 * string table with no terminator made the ELF parser scan the table once per
 * section - 26 billion iterations and 22 seconds out of a 200MB file. Twenty
 * thousand rounds of random headers never produced it, because the generator's
 * objects are 8KB and the bug needs a large table, and because the shape it needs
 * is specific rather than unusual.
 *
 * So: take a VALID object, and change exactly one field that a parser will do
 * arithmetic on, to exactly a value that breaks arithmetic. The field list is the
 * dangerous byte positions, written out per format; the value list is what has
 * historically broken size handling - zero, one, the maxima, the signed boundaries,
 * and the object's own length either side.
 *
 *
 * WHAT IS ASSERTED, AND WHY EACH ONE IS SEPARATE
 *
 *   TIME       Every case is timed and a slow one fails. This is what catches the
 *              class above - an amplification, or a loop whose exit depends on a
 *              field - and no other check here would notice, because such a parse
 *              returns perfectly correct results, eventually.
 *
 *   PARTITION  Regions still cover the object exactly once. A size that is wrong
 *              in a way that survives every bounds check still shows up here,
 *              because two regions cannot overlap unless the arithmetic that
 *              placed them disagreed with itself.
 *
 *   ALLOCATION Peak bytes held during one parse, bounded. An allocation sized from
 *              a field is the "alloc size mismatch" case, and it is not visible in
 *              the output at all.
 *
 *   MEMORY     Out of bounds reads and writes, use after free, double free and
 *              integer overflow are not asserted here. They are found by building
 *              this same binary under AddressSanitizer and UndefinedBehaviorSanitizer
 *              (`make unit-asan`), where every one of them aborts. Writing hand
 *              checks for them here would be a worse version of a tool that
 *              already exists.
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "../../libkofeng/kofparsers/binaries/elf_parse.h"
#include "../../libkofeng/kofparsers/binaries/pe_parse.h"
#include "../../libkofeng/kofparsers/containers/gzip_parse.h"
#include "../../libkofeng/kofparsers/containers/docole_parse.h"
#include "../../libkofeng/kofparsers/containers/zip_parse.h"
#include "../../libkofeng/kofparsers/containers/tar_parse.h"
#include "../../libkofeng/kofparsers/containers/sevenzip_parse.h"
#include "../../libkofeng/kofparsers/containers/rar_parse.h"
#include "../../libkofeng/kofparsers/containers/xz_parse.h"
#include "partition_check.h"



/*
 * How much slower than the CLEAN parse a mutated one may be.
 *
 * Relative, not absolute, and the difference is what makes this work. An absolute
 * bound has to be set from the seed size and the machine: the measured ELF bug is
 * 22 seconds on a 200MB object and 25 milliseconds on the 1MB one here, so a
 * threshold loose enough not to fire on a busy machine is also loose enough to miss
 * it. Against the clean parse the same bug is 4000x either way.
 *
 * The floor is there because the baseline is microseconds and timing noise is not -
 * but it has to sit just above the noise and no higher. Set too high it becomes the
 * real threshold and the ratio stops mattering: at a 0.003 ms baseline a 2 ms floor
 * demands a 666x amplification before anything can fail, which quietly turns a 200x
 * limit into a 666x one. Half a millisecond is comfortably above scheduler jitter
 * and leaves the ratio in charge.
 */
#define AMPLIFY_MAX  200.0
#define FLOOR_MS       0.5

/* No parse of a one megabyte object has a reason to hold more than this. */
#define ALLOC_LIMIT (24u << 20)

/* ---- allocation accounting ---------------------------------------------------- */

/*
 * Counted rather than sanitised, because the question is different.
 *
 * A sanitiser answers "was this access legal". This answers "was this allocation
 * SIZED from something the file said", which is legal, invisible, and the whole of
 * the bug where a two byte field becomes a gigabyte malloc. The parsers under test
 * allocate through the same wrappers as the rest of the engine, so the count here
 * is what the parse really asked for.
 */
static uint64_t alloc_live, alloc_peak;

void *kof_test_malloc(size_t n);
void kof_test_free(void *p, size_t n);

void *kof_test_malloc(size_t n)
{
	void *p = malloc(n);

	if (p) {
		alloc_live += n;
		if (alloc_live > alloc_peak)
			alloc_peak = alloc_live;
	}
	return p;
}

void kof_test_free(void *p, size_t n)
{
	if (p) {
		alloc_live -= n;
		free(p);
	}
}

/* ---- the hostile values ------------------------------------------------------- */


/*
 * A shorter list for the pairwise pass, because pairs multiply.
 *
 * These six are the ones that have historically mattered when combined: zero and
 * one for the degenerate cases, the object's length and half of it for the offsets
 * that stay just inside a bounds check, and the two maxima for the wrap.
 */
static uint64_t hostile_pair(uint32_t k, uint64_t obj_len)
{
	switch (k) {
	case 0:  return 0;
	case 1:  return 1;
	case 2:  return obj_len;
	case 3:  return obj_len / 2u;
	case 4:  return 0xffffffffu;
	default: return 0xffffffffffffffffull;
	}
}
#define HOSTILE_PAIR_N 6u

/* ---- one dangerous position --------------------------------------------------- */

#include "seeds.h"

/* ---- the table ---------------------------------------------------------------- */

typedef int (*parse_fn)(kof_buf, void *, struct kof_obj_ctx *);

#define WRAP(name, type, fn)                                               \
	static int name(kof_buf b, void *v, struct kof_obj_ctx *c)         \
	{ return fn(b, (type *)v, c); }

WRAP(w_elf,    struct kof_elf_info,    kof_elf_parse)
WRAP(w_pe,     struct kof_pe_info,     kof_pe_parse)
WRAP(w_gzip,   struct kof_gzip_info,   kof_gzip_parse)
WRAP(w_docole, struct kof_docole_info, kof_docole_parse)
WRAP(w_zip,    struct kof_zip_info,    kof_zip_parse)
WRAP(w_tar,    struct kof_tar_info,    kof_tar_parse)
WRAP(w_7z,     struct kof_7z_info,     kof_7z_parse)
WRAP(w_rar,    struct kof_rar_info,    kof_rar_parse)
WRAP(w_xz,     struct kof_xz_info,     kof_xz_parse)

struct target {
	const char *name;
	uint64_t (*seed)(uint8_t *);
	const struct field *fields;
	uint32_t n_fields;
	parse_fn parse;
	uint32_t view_size;
	const uint32_t *bits;
	uint32_t n_bits;
	uint32_t (*elems)(const void *view);
	uint32_t want_elems;
};

static uint32_t n_elf(const void *v)
{ return ((const struct kof_elf_info *)v)->sec_count; }
static uint32_t n_pe(const void *v)
{ return ((const struct kof_pe_info *)v)->sec_count; }
static uint32_t n_zip(const void *v)
{ return ((const struct kof_zip_info *)v)->n_entries; }
static uint32_t n_rar(const void *v)
{ return ((const struct kof_rar_info *)v)->n_entries; }
static uint32_t n_docole(const void *v)
{ return ((const struct kof_docole_info *)v)->n_entries; }
static uint32_t n_xz(const void *v)
{ return ((const struct kof_xz_info *)v)->n_blocks; }
static uint32_t n_tar(const void *v)
{ return ((const struct kof_tar_info *)v)->n_entries; }

static const struct target targets[] = {
	{ "elf",  seed_elf,  f_elf,  sizeof f_elf  / sizeof f_elf[0],
	  w_elf,  (uint32_t)sizeof(struct kof_elf_info),
	  kof_elf_region_bits,  KOF_ELF_REGION_COUNT, n_elf, ELF_NSEC },
	{ "pe",   seed_pe,   f_pe,   sizeof f_pe   / sizeof f_pe[0],
	  w_pe,   (uint32_t)sizeof(struct kof_pe_info),
	  kof_pe_region_bits,   KOF_PE_REGION_COUNT, n_pe, 1u },
	{ "zip",  seed_zip,  f_zip,  sizeof f_zip  / sizeof f_zip[0],
	  w_zip,  (uint32_t)sizeof(struct kof_zip_info),
	  kof_zip_region_bits,  KOF_ZIP_REGION_COUNT, n_zip, Z_NENT },
	{ "tar",  seed_tar,  f_tar,  sizeof f_tar  / sizeof f_tar[0],
	  w_tar,  (uint32_t)sizeof(struct kof_tar_info),
	  kof_tar_region_bits,  KOF_TAR_REGION_COUNT, n_tar, 1u },
	{ "gzip", seed_gzip, f_gzip, sizeof f_gzip / sizeof f_gzip[0],
	  w_gzip, (uint32_t)sizeof(struct kof_gzip_info),
	  kof_gzip_region_bits, KOF_GZIP_REGION_COUNT, NULL, 0 },
	{ "7z",   seed_7z,   f_7z,   sizeof f_7z   / sizeof f_7z[0],
	  w_7z,   (uint32_t)sizeof(struct kof_7z_info),
	  kof_7z_region_bits,   KOF_7Z_REGION_COUNT, NULL, 0 },
	{ "rar",  seed_rar,  f_rar,  sizeof f_rar  / sizeof f_rar[0],
	  w_rar,  (uint32_t)sizeof(struct kof_rar_info),
	  kof_rar_region_bits,  KOF_RAR_REGION_COUNT, n_rar, R_NENT },
	{ "docole", seed_docole, f_docole,
	  sizeof f_docole / sizeof f_docole[0],
	  w_docole, (uint32_t)sizeof(struct kof_docole_info),
	  kof_docole_region_bits, KOF_DOCOLE_REGION_COUNT, n_docole, 3u },
	{ "xz",   seed_xz,   f_xz,   sizeof f_xz   / sizeof f_xz[0],
	  w_xz,   (uint32_t)sizeof(struct kof_xz_info),
	  kof_xz_region_bits,   KOF_XZ_REGION_COUNT, n_xz, 1u }
};

/* ---- the run ------------------------------------------------------------------ */

static double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

#define TOP_N 12u

struct hit {
	double amp, ms;
	char where[96];
};

struct tally {
	uint64_t cases, parsed, slow, over_alloc;
	double worst_amp;
	const char *worst_where;
	char worst_field[64];
	struct hit top[TOP_N];
};

/* Keep the worst few, so the shape of the tail is visible rather than only its
 * end: a single outlier is one bug, and a cluster is a pattern. */
static void top_add(struct tally *t, double amp, double ms, const char *where)
{
	uint32_t i, at = TOP_N;

	for (i = 0; i < TOP_N; i++)
		if (amp > t->top[i].amp) { at = i; break; }
	if (at == TOP_N)
		return;
	for (i = TOP_N - 1u; i > at; i--)
		t->top[i] = t->top[i - 1u];
	t->top[at].amp = amp;
	t->top[at].ms = ms;
	snprintf(t->top[at].where, sizeof t->top[at].where, "%s", where);
}

/*
 * What the clean seed costs, as a median rather than a single reading.
 *
 * A median because the first parse of an object pays for its page faults and the
 * rest do not, and taking that one as the baseline would hide a factor of ten.
 */
static double baseline_ms(const struct target *tg, uint8_t *obj, void *view)
{
	double v[15];
	uint32_t i, j;
	uint64_t len = tg->seed(obj);

	for (i = 0; i < 15u; i++) {
		struct kof_obj_ctx ctx;
		double t0;

		memset(&ctx, 0, sizeof ctx);
		tg->seed(obj);
		t0 = now_ms();
		tg->parse(kof_buf_make(obj, len), view, &ctx);
		v[i] = now_ms() - t0;
	}
	for (i = 1; i < 15u; i++) {
		double k = v[i];
		for (j = i; j > 0 && v[j - 1] > k; j--)
			v[j] = v[j - 1];
		v[j] = k;
	}
	return v[7];
}

/*
 * One case, of one or two fields.
 *
 * Two, because one is not enough to express the shapes that hurt. The measured ELF
 * amplification needs a string table that spans the object AND a name offset
 * pointing deep into it: either alone is harmless and parses in microseconds, and a
 * harness that changes one field at a time can only find it if the seed was built
 * with half the bug already in place - which is writing the exam after seeing the
 * answer. `g` is NULL for the single field pass.
 */
static void one_case(const struct target *tg, uint8_t *obj, void *view,
		     const struct field *f, uint64_t v,
		     const struct field *g, uint64_t gv,
		     uint64_t seed_len,
		     double base, struct tally *t, struct pc_report *rep)
{
	struct kof_obj_ctx ctx;
	double t0, dt;
	char what[160];

	memset(&ctx, 0, sizeof ctx);
	tg->seed(obj);
	poke(obj, seed_len, f, v);
	if (g)
		poke(obj, seed_len, g, gv);

	alloc_live = 0;
	alloc_peak = 0;

	t0 = now_ms();
	if (tg->parse(kof_buf_make(obj, seed_len), view, &ctx)) {
		t->parsed++;
		if (g)
			snprintf(what, sizeof what, "%s %s=0x%llx %s=0x%llx",
				 tg->name, f->name, (unsigned long long)v,
				 g->name, (unsigned long long)gv);
		else
			snprintf(what, sizeof what, "%s %s=0x%llx", tg->name,
				 f->name, (unsigned long long)v);
		pc_check(what, &ctx, seed_len, tg->bits, tg->n_bits, rep);
	}
	dt = now_ms() - t0;
	t->cases++;

	{
		double amp = base > 0.0 ? dt / base : 0.0;
		char w[96];

		{

			if (g)
				snprintf(w, sizeof w, "%s %s=0x%llx %s=0x%llx",
					 tg->name, f->name,
					 (unsigned long long)v, g->name,
					 (unsigned long long)gv);
			else
				snprintf(w, sizeof w, "%s %s=0x%llx", tg->name,
					 f->name, (unsigned long long)v);
			if (dt > FLOOR_MS / 20.0)
				top_add(t, amp, dt, w);
		}
		/*
		 * Only rank a case whose absolute cost is above the noise.
		 *
		 * A gzip header parses in seventy nanoseconds, so a scheduler
		 * hiccup shows up as two hundred times the baseline and the
		 * headline number becomes a report on the machine's mood. The
		 * failure test already had a floor; the ranking needed the same
		 * one, or the worst case printed is never the worst case.
		 */
		if (dt > FLOOR_MS / 20.0 && amp > t->worst_amp) {
			t->worst_amp = amp;
			t->worst_where = tg->name;
			snprintf(t->worst_field, sizeof t->worst_field,
				 "%s=0x%llx", f->name, (unsigned long long)v);
		}
		if (dt > FLOOR_MS && amp > AMPLIFY_MAX) {
			t->slow++;
			printf("  AMPLIFY %s: %.2f ms against a %.3f ms "
			       "baseline (%.0fx)\n", w, dt, base, amp);
		}
	}
	if (alloc_peak > ALLOC_LIMIT) {
		t->over_alloc++;
		printf("  ALLOC %s %s=0x%llx: %llu bytes held\n", tg->name,
		       f->name, (unsigned long long)v,
		       (unsigned long long)alloc_peak);
	}
}

int main(void)
{
	uint8_t *obj = malloc(SEED_MAX + 64u);
	void *view = NULL;
	uint32_t view_cap = 0, ti, fi, vi;
	struct tally t;
	struct pc_report rep = { 0, 0, 0 };

	if (!obj)
		return 1;
	memset(&t, 0, sizeof t);

	for (ti = 0; ti < sizeof targets / sizeof targets[0]; ti++) {
		const struct target *tg = &targets[ti];
		uint64_t seed_len;
		double base;

		if (tg->view_size > view_cap) {
			free(view);
			view = malloc(tg->view_size);
			if (!view)
				return 1;
			view_cap = tg->view_size;
		}
		seed_len = tg->seed(obj);
		base = baseline_ms(tg, obj, view);

		/*
		 * The seed must parse AND be structurally rich.
		 *
		 * Parsing is not enough: a seed that parses as an archive holding
		 * one entry makes every per-element field below a single field
		 * again, and the whole reason those exist is that the shapes worth
		 * finding need several structures to say the same wrong thing. So
		 * the count the parse found is checked against what the seed was
		 * built to contain.
		 */
		{
			struct kof_obj_ctx ctx;

			memset(&ctx, 0, sizeof ctx);
			if (!tg->parse(kof_buf_make(obj, seed_len), view, &ctx)) {
				printf("  SEED %s does not parse - the cases "
				       "below test nothing\n", tg->name);
				rep.failed++;
			} else if (tg->want_elems &&
				   tg->elems(view) < tg->want_elems) {
				printf("  SEED %s holds %u element(s), built "
				       "for %u - per element fields are "
				       "testing one element\n", tg->name,
				       tg->elems(view), tg->want_elems);
				rep.failed++;
			}
		}

		/* One field at a time. */
		for (fi = 0; fi < tg->n_fields; fi++)
			for (vi = 0; vi < HOSTILE_N; vi++)
				one_case(tg, obj, view, &tg->fields[fi],
					 hostile(vi, seed_len), NULL, 0,
					 seed_len, base, &t, &rep);

		/* Then every ordered pair of distinct fields. Ordered rather than
		 * unordered because the two are written in sequence and a later
		 * poke can overwrite an earlier one where their bytes overlap. */
		for (fi = 0; fi < tg->n_fields; fi++) {
			uint32_t gi, gv;

			for (gi = 0; gi < tg->n_fields; gi++) {
				if (gi == fi)
					continue;
				for (vi = 0; vi < HOSTILE_PAIR_N; vi++)
					for (gv = 0; gv < HOSTILE_PAIR_N; gv++)
						one_case(tg, obj, view,
							 &tg->fields[fi],
							 hostile_pair(vi, seed_len),
							 &tg->fields[gi],
							 hostile_pair(gv, seed_len),
							 seed_len, base, &t,
							 &rep);
			}
		}
	}

	free(view);
	free(obj);

	if (t.worst_amp == 0.0)
		printf("hostile fields: %llu case(s) over %u format(s), %llu "
		       "parsed, partition %llu/%llu, no case above %.2f ms%s\n",
		       (unsigned long long)t.cases,
		       (unsigned)(sizeof targets / sizeof targets[0]),
		       (unsigned long long)t.parsed,
		       (unsigned long long)(rep.checked - rep.failed),
		       (unsigned long long)rep.checked, FLOOR_MS / 20.0,
		       (t.slow || t.over_alloc) ? " - FAILED" : "");
	else
	printf("hostile fields: %llu case(s) over %u format(s), %llu parsed, "
	       "partition %llu/%llu, worst amplification %.0fx (%s %s)%s\n",
	       (unsigned long long)t.cases,
	       (unsigned)(sizeof targets / sizeof targets[0]),
	       (unsigned long long)t.parsed,
	       (unsigned long long)(rep.checked - rep.failed),
	       (unsigned long long)rep.checked,
	       t.worst_amp, t.worst_where ? t.worst_where : "-",
	       t.worst_field,
	       (t.slow || t.over_alloc) ? " - FAILED" : "");

	if (t.worst_amp > 0.0) {
		uint32_t i;

		printf("  worst amplifications:\n");
		for (i = 0; i < TOP_N && t.top[i].amp > 0.0; i++)
			printf("    %6.0fx  %8.3f ms  %s\n", t.top[i].amp,
			       t.top[i].ms, t.top[i].where);
	}
	return (rep.failed || t.slow || t.over_alloc) ? 1 : 0;
}
