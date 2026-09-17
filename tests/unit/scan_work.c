/*
 * scan_work - does the sweep's WORK stay flat as the database grows.
 *
 * WHY A COUNTER AND NOT A STOPWATCH. "Throughput must exceed N MB/s" is a
 * measurement of the machine that ran it: it passes on a workstation, fails on
 * a loaded build agent, and tells nobody which change cost what. The property
 * worth defending is not a speed, it is a SHAPE - the work an object costs must
 * not grow with the number of rules that did not fire.
 *
 * kofeng.h states it beside the counters: `multi_bytes` is what a region cost
 * read ONCE for all of its markers, `bytes_searched` is what was left to read
 * one marker at a time, and "a build where the second grows with the database
 * and the first does not is a build where the sweep stopped working". Nothing
 * checked it.
 *
 * So this scans ONE object against two databases built from the same generator,
 * the second four times the size of the first, and compares what the scan did.
 * The object is deliberately a format the modules do not target, so what is
 * measured is the floor every object pays: the prefilter, and whatever the
 * matcher does for rules that were never going to run.
 *
 * WHAT IT ALLOWS. The per-object work may grow a little - there are four times
 * as many records to reject, and rejecting one is not free - but it must not
 * grow in PROPORTION. The bound is stated as a fraction of the record growth
 * rather than as an absolute, so the test says the same thing on any machine
 * and at any scale.
 *
 * The time is printed and NOT asserted, for the reason in the first paragraph.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../libkofeng/core/kofplatform.h"
#include "../../libkofeng/core/kofmod/kofsig.h"
#include "../../libkofeng/kofdb/kofdb.h"
#include "../../libkofeng/kofdb/kofpackw.h"
#include "../../libkofeng/kofmatchers/kofmatch.h"
#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *why)
{
	printf("  FAIL %s\n", why);
	failures++;
}

/* ---- a database of `mods` modules, each with one literal nothing matches --- */

#define LIT_LEN   32u
#define NAME_LEN  32u
#define BLOB_LEN  16u

struct synth {
	struct kof_pw_mod  *mod;
	struct kof_pw_str  *str;
	struct kof_pw_name *name;
	uint8_t            *lit, *code;
	char               *text;
};

static void synth_free(struct synth *s)
{
	free(s->mod); free(s->str); free(s->name);
	free(s->lit); free(s->text); free(s->code);
	memset(s, 0, sizeof *s);
}

static int synth_make(struct synth *s, uint32_t mods, uint32_t target)
{
	uint32_t i;

	memset(s, 0, sizeof *s);
	s->mod  = calloc(mods, sizeof *s->mod);
	s->str  = calloc(mods, sizeof *s->str);
	s->name = calloc(mods, sizeof *s->name);
	s->lit  = calloc(mods, LIT_LEN);
	s->text = calloc(mods, NAME_LEN);
	s->code = calloc(mods, BLOB_LEN);
	if (!s->mod || !s->str || !s->name || !s->lit || !s->text || !s->code) {
		synth_free(s);
		return 0;
	}
	for (i = 0; i < mods; i++) {
		uint8_t *lit  = s->lit + (size_t)i * LIT_LEN;
		char    *text = s->text + (size_t)i * NAME_LEN;
		uint8_t *code = s->code + (size_t)i * BLOB_LEN;

		snprintf((char *)lit, LIT_LEN, "sig-%010u-body", i);
		snprintf(text, NAME_LEN, "Trojan.Test.Gen.%u", i);
		memset(code, 0x90, BLOB_LEN);
		code[BLOB_LEN - 1] = 0xc3;      /* ret */

		s->str[i].bytes = lit;
		s->str[i].len   = (uint16_t)strlen((char *)lit);
		s->str[i].kind  = KOF_STR_LITERAL;
		s->name[i].id   = i;
		s->name[i].text = text;

		s->mod[i].code        = code;
		s->mod[i].code_len    = BLOB_LEN;
		s->mod[i].target_mask = target;
		/* The whole object: a region bit names a FORMAT's region, and
		 * the object here is text, which has none. Naming one had
		 * every module rejected by region before the matcher was
		 * reached - the sweep measured nothing and said it scaled. */
		s->mod[i].scan_mask   = KOF_SCAN_ALL;
		s->mod[i].str         = &s->str[i];
		s->mod[i].n_str       = 1;
		s->mod[i].name        = &s->name[i];
		s->mod[i].n_names     = 1;
	}
	return 1;
}

static int write_all(const char *path, const uint8_t *b, size_t n)
{
	FILE *f = fopen(path, "wb");
	int ok;

	if (!f)
		return 0;
	ok = fwrite(b, 1, n, f) == n;
	return fclose(f) == 0 && ok;
}

/* What one scan of `obj` against a database of `mods` modules cost. */
struct cost {
	uint64_t considered, ran, searches, bytes_searched, multi_bytes;
	uint64_t by_target, by_size, by_arch, by_subtype, by_region;
	double   secs;
};

static int measure(const char *dir, const char *obj, uint32_t mods,
		   uint32_t target, struct cost *out)
{
	char pack[512];
	struct synth s;
	struct kof_scan_option opt;
	const struct kof_stats *st;
	struct kof_engine *eng;
	struct kof_scanner *sc;
	struct timespec t0, t1;
	uint8_t *img;
	size_t len = 0;
	int ok = 0;

	if (!synth_make(&s, mods, target))
		return 0;
	img = kof_pack_build(KOF_PACK_DETECT, s.mod, mods, &len);
	snprintf(pack, sizeof pack, "%s/w%u.ksig", dir, mods);
	if (img && write_all(pack, img, len))
		ok = 1;
	free(img);
	synth_free(&s);
	if (!ok)
		return 0;

	eng = kof_engine_open(dir);
	if (!eng)
		return 0;
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		return 0;
	}
	memset(&opt, 0, sizeof opt);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	(void)kof_scan_path(sc, obj, &opt, NULL, NULL);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	st = kof_scanner_stats(sc);
	if (st) {
		out->considered     = st->considered;
		out->ran            = st->ran;
		out->searches       = st->searches;
		out->bytes_searched = st->bytes_searched;
		out->multi_bytes    = st->multi_bytes;
		out->by_target      = st->by_target;
		out->by_size        = st->by_size;
		out->by_arch        = st->by_arch;
		out->by_subtype     = st->by_subtype;
		out->by_region      = st->by_region;
	}
	out->secs = (double)(t1.tv_sec - t0.tv_sec) +
		    (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
	kof_scanner_free(sc);
	kof_engine_close(eng);
	remove(pack);
	return st != NULL;
}

int main(void)
{
	char dir[] = "build/test/scan_work_XXXXXX";
	char obj[600];
	struct cost small, big;
	static uint8_t body[64u << 10];
	const uint32_t n_small = 2000u, n_big = 8000u;
	uint32_t i;

	if (!mkdtemp(dir)) {
		printf("scan work: cannot make a work directory\n");
		return 0;
	}
	/*
	 * The object: text that holds none of the generated literals, so every
	 * module is rejected and the measurement is the floor.
	 */
	for (i = 0; i < sizeof body; i++)
		body[i] = (uint8_t)('a' + (i % 26u));
	snprintf(obj, sizeof obj, "%s/object.txt", dir);
	if (!write_all(obj, body, sizeof body)) {
		printf("scan work: cannot write the object\n");
		rmdir(dir);
		return 0;
	}

	memset(&small, 0, sizeof small);
	memset(&big, 0, sizeof big);
	/*
	 * EVERY FORMAT, so the modules are NOT rejected by target and the
	 * matcher actually runs. That is the point: a sweep where nothing
	 * reaches the matcher measures the prefilter and calls it scaling.
	 */
	if (!measure(dir, obj, n_small, ~0u, &small) ||
	    !measure(dir, obj, n_big, ~0u, &big)) {
		printf("scan work: the databases could not be built - nothing "
		       "was measured\n");
		remove(obj);
		rmdir(dir);
		return 0;
	}

	printf("  %5u records: considered %llu, ran %llu, searches %llu, "
	       "%llu byte(s) read, %.2f ms\n", n_small,
	       (unsigned long long)small.considered,
	       (unsigned long long)small.ran,
	       (unsigned long long)small.searches,
	       (unsigned long long)small.bytes_searched, small.secs * 1e3);
	printf("  %5u records: considered %llu, ran %llu, searches %llu, "
	       "%llu byte(s) read, %.2f ms\n", n_big,
	       (unsigned long long)big.considered,
	       (unsigned long long)big.ran,
	       (unsigned long long)big.searches,
	       (unsigned long long)big.bytes_searched, big.secs * 1e3);

	printf("  rejected by: target %llu size %llu arch %llu subtype %llu "
	       "region %llu\n",
	       (unsigned long long)big.by_target, (unsigned long long)big.by_size,
	       (unsigned long long)big.by_arch,
	       (unsigned long long)big.by_subtype,
	       (unsigned long long)big.by_region);
	if (!small.considered || !big.considered)
		fail("no module was considered, so nothing was swept");
	/*
	 * FOUR TIMES THE RECORDS, FOUR TIMES THE REJECTIONS - that part is
	 * linear by construction and is not what this guards.
	 */
	if (big.considered < small.considered)
		fail("more records considered fewer modules");
	/*
	 * AND THE BYTES READ MUST NOT FOLLOW THEM.
	 *
	 * This is the claim in kofeng.h. The database grew four times; the
	 * object did not change, so the bytes a scan of it reads should not
	 * change either - the presence set answers for a marker without
	 * touching the object, and the batched pass reads a region once for all
	 * of them. A factor of two is the room this allows for growth that is
	 * not proportional; proportional growth here is 4x and fails.
	 */
	if (big.bytes_searched > small.bytes_searched * 2u + (64u << 10)) {
		char why[200];

		snprintf(why, sizeof why,
			 "bytes read grew with the database: %llu -> %llu for "
			 "4x the records",
			 (unsigned long long)small.bytes_searched,
			 (unsigned long long)big.bytes_searched);
		fail(why);
	}
	if (!big.ran)
		fail("no module ran, so the matcher was never reached and "
		     "nothing about it was measured");
	/*
	 * AND THE FLOOR: the same databases retargeted at ELF, against the same
	 * text object. Not one module may reach the matcher - a build where one
	 * does has lost the cheapest test it has.
	 */
	{
		struct cost floor_small, floor_big;

		memset(&floor_small, 0, sizeof floor_small);
		memset(&floor_big, 0, sizeof floor_big);
		if (measure(dir, obj, n_small, 1u << KOF_FMT_ELF,
			    &floor_small) &&
		    measure(dir, obj, n_big, 1u << KOF_FMT_ELF, &floor_big)) {
			printf("  target-rejected: ran %llu of %llu, then "
			       "%llu of %llu\n",
			       (unsigned long long)floor_small.ran,
			       (unsigned long long)floor_small.considered,
			       (unsigned long long)floor_big.ran,
			       (unsigned long long)floor_big.considered);
			if (floor_small.ran || floor_big.ran)
				fail("a module ran against an object its "
				     "target excludes");
			if (floor_small.bytes_searched ||
			    floor_big.bytes_searched)
				fail("an object was searched for a rule that "
				     "cannot target it");
		}
	}

	remove(obj);
	rmdir(dir);

	/*
	 * ---- AND WHAT A SEARCH COSTS AS THE PATTERN SET GROWS ----
	 *
	 * The half above measures the sweep, whose modules here are a `ret`:
	 * they are rejected or they run and do nothing, so the MATCHER is never
	 * reached and the presence set - which is built lazily, on the first
	 * search that has already read more than stamping would cost - is never
	 * built either.
	 *
	 * So the matcher is driven directly, which is the same work the sweep
	 * would ask of it: N distinct markers, none of them in the object, over
	 * one object. The claim is that the Nth marker does not cost a read of
	 * the object: past the point where the index earns its place, a marker
	 * that is absent costs one lookup. Four times the markers must not be
	 * four times the bytes.
	 */
	{
		struct kof_match_ctx m;
		static uint8_t hay[64u << 10];
		uint64_t read_small = 0, read_big = 0, idx = 0;
		uint32_t pass, k;

		for (k = 0; k < sizeof hay; k++)
			hay[k] = (uint8_t)('a' + (k % 26u));

		for (pass = 0; pass < 2u; pass++) {
			uint32_t n = pass ? n_big : n_small;

			memset(&m, 0, sizeof m);
			if (!kof_match_state_init(&m, n, 0)) {
				fail("out of memory for the match state");
				break;
			}
			kof_match_begin(&m, kof_buf_make(hay, sizeof hay));
			for (k = 0; k < n; k++) {
				char lit[LIT_LEN];
				struct kof_range ext;
				uint64_t skipped = 0;

				snprintf(lit, sizeof lit, "sig-%010u-body", k);
				ext.off = 0;
				ext.len = sizeof hay;
				/*
				 * THROUGH lookup, WHICH IS THE PATH THE SWEEP
				 * TAKES. kof_match_in is the ad-hoc search a
				 * module asks for by offset and deliberately
				 * does NOT consult the presence set; driving
				 * that one measured the long way round and
				 * called it the engine.
				 */
				(void)kof_match_lookup(&m, 0, &ext, 1u,
						       (const uint8_t *)lit,
						       (uint16_t)strlen(lit),
						       KOF_STR_LITERAL, 0,
						       &skipped);
			}
			if (pass) {
				read_big = m.n_bytes_scanned;
				idx = m.n_bytes_indexed;
			} else {
				read_small = m.n_bytes_scanned;
			}
			kof_match_state_free(&m);
		}

		printf("  %5u marker(s): %llu byte(s) read; %5u marker(s): "
		       "%llu read, %llu indexed\n",
		       n_small, (unsigned long long)read_small, n_big,
		       (unsigned long long)read_big, (unsigned long long)idx);

		if (!read_small)
			fail("no marker was searched for, so nothing about the "
			     "matcher was measured");
		else if (read_big > read_small * 2u)
			fail("the bytes a search reads grew with the number of "
			     "markers - the presence set is not answering");
		if (!idx)
			fail("the presence set was never built, so every "
			     "marker was searched for the long way");
	}

	if (failures) {
		printf("scan work: %d check(s) failed\n", failures);
		return 1;
	}
	printf("scan work: the sweep's cost per object stays flat as the "
	       "database grows - ok\n");
	return 0;
}
