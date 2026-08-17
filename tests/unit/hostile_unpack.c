/*
 * hostile_unpack.c - the same hostile fields, but through the whole engine.
 *
 * hostile_fields stops at the parser. This does not: it loads the real database and
 * runs the real scan, so the mutated container reaches the real unpackers - the zip
 * module deciding what to inflate, the RAR module windowing entries, the compound
 * file module decompressing macros, UPX walking a block chain. Those read the view
 * the parser produced, and a view built from a hostile file is exactly what they
 * were never tested against.
 *
 * The distinction is worth stating because it is easy to assume the parser tests
 * cover it. They cover whether the VIEW is sane. This covers what happens when a
 * module believes it - a size used to window, an offset used to unpack, a count
 * used to loop - and that is a different body of code with a different failure
 * mode. Measured after the fact, it is also the newest code in the engine.
 *
 *
 * WHAT IS ASSERTED
 *
 *   TIME       Against the clean scan of the same seed, the same way and for the
 *              same reason as in hostile_fields: the budgets already bound how much
 *              a scan may PRODUCE, and nothing bounds how long it may take to
 *              decide to produce nothing.
 *
 *   PRODUCED   Bytes yielded, held to the budget the scan was given. The engine
 *              enforces this itself; asserting it here is what turns "the ceiling
 *              exists" into "the ceiling holds on adversarial input".
 *
 *   MEMORY     Left to `make unit-asan`, where this binary is built with the
 *              sanitisers and every use after free, double free and out of bounds
 *              access in the unpackers aborts.
 *
 * A scan needs a path, so each case goes through a temporary file. That is slower
 * than the parser tests by two orders of magnitude, which is why this runs the
 * single-field pass only - the pairwise pass belongs where it is cheap.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "../../libkofeng/kofeng.h"
#include "seeds.h"

/* Small enough that a scan of it is dominated by the engine rather than by writing
 * the file, large enough that an amplification inside a module still shows. */
#define UNPACK_SEED (64u << 10)

#define AMPLIFY_MAX 200.0
#define FLOOR_MS      0.5

/* What one object is allowed to yield here. Small on purpose: a module that
 * produces more than this from a 64KB seed has believed something. */
#define PRODUCE_CAP (4u << 20)

static double now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

/* ---- which formats have an unpacker at all ------------------------------------ */

struct utarget {
	const char *name;
	uint64_t (*seed)(uint8_t *);
	const struct field *fields;
	uint32_t n_fields;
	int produces;              /* a clean scan must yield a child */
};

static const struct utarget utargets[] = {
	{ "zip",    seed_zip,    f_zip,    sizeof f_zip    / sizeof f_zip[0], 1 },
	{ "rar",    seed_rar,    f_rar,    sizeof f_rar    / sizeof f_rar[0], 1 },
	{ "docole", seed_docole, f_docole, sizeof f_docole / sizeof f_docole[0], 1 },
	{ "tar",    seed_tar,    f_tar,    sizeof f_tar    / sizeof f_tar[0], 1 },
	{ "gzip",   seed_gzip,   f_gzip,   sizeof f_gzip   / sizeof f_gzip[0], 1 },
	{ "7z",     seed_7z,     f_7z,     sizeof f_7z     / sizeof f_7z[0], 0 },
	{ "elf",    seed_elf,    f_elf,    sizeof f_elf    / sizeof f_elf[0], 0 },
	{ "pe",     seed_pe,     f_pe,     sizeof f_pe     / sizeof f_pe[0], 0 },
	{ "xz",     seed_xz,     f_xz,     sizeof f_xz     / sizeof f_xz[0], 0 },
	/*
	 * Three that produce nothing, and are here for exactly that reason.
	 *
	 * RAR5 has no decompressor, and a PDF stream and an RTF hex object have no
	 * unpacker yet. A format with no unpacker is still driven through the whole
	 * scan by a hostile field, and "recovered nothing, refused cleanly, in the
	 * time a clean parse takes" is the property that has to hold - a module
	 * that unpacks a format it cannot unpack shows up here and nowhere else.
	 */
	{ "rar5",   seed_rar5,   f_rar5,   sizeof f_rar5   / sizeof f_rar5[0], 0 },
	{ "pdf",    seed_pdf,    f_pdf,    sizeof f_pdf    / sizeof f_pdf[0], 0 },
	{ "rtf",    seed_rtf,    f_rtf,    sizeof f_rtf    / sizeof f_rtf[0], 0 }
};

/* ---- the run ------------------------------------------------------------------ */

struct tally {
	uint64_t cases, slow, over_produce, errors, clean_bytes;
	double worst_amp;
	char worst[128];
};

static uint64_t produced_total;

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)res; (void)user;
	produced_total += len;
	return 0;
}

/*
 * One scan of one mutated object.
 *
 * The seed is rebuilt every time rather than patched back, because a mutation of a
 * table field writes into several places and undoing it correctly is the same work
 * as writing it again, done less reliably.
 */
static double scan_once(kof_scanner *sc, const char *path, uint8_t *obj,
			uint64_t len, const struct utarget *tg,
			const struct field *f, uint64_t v, int *err)
{
	struct kof_scan_option opt;
	FILE *fp;
	double t0;
	int rc;

	tg->seed(obj);
	if (f)
		poke(obj, len, f, v);

	fp = fopen(path, "wb");
	if (!fp || fwrite(obj, 1, (size_t)len, fp) != (size_t)len) {
		if (fp)
			fclose(fp);
		*err = 1;
		return 0.0;
	}
	fclose(fp);

	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = PRODUCE_CAP;
	opt.max_resident_bytes = 16u << 20;
	opt.max_object_bytes   = 2u << 20;

	produced_total = 0;
	t0 = now_ms();
	rc = kof_scan_path(sc, path, &opt, on_object, NULL);
	if (rc < 0)
		*err = 1;
	return now_ms() - t0;
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	char path[256];
	kof_engine *eng;
	kof_scanner *sc;
	uint8_t *obj;
	struct tally t;
	uint32_t ti, fi, vi;

	eng = kof_engine_open(db);
	if (!eng) {
		/* Not a failure. This test needs the engine's own database, which
		 * the parser tests do not, so a tree built for them alone should
		 * say so rather than fail. */
		printf("hostile unpack: no database at %s - skipped\n", db);
		return 0;
	}
	sc = kof_scanner_new(eng);
	obj = malloc(SEED_MAX + 64u);
	if (!sc || !obj)
		return 1;

	snprintf(path, sizeof path, "build/test/hostile-unpack-%d.bin",
		 (int)getpid());
	memset(&t, 0, sizeof t);

	for (ti = 0; ti < sizeof utargets / sizeof utargets[0]; ti++) {
		const struct utarget *tg = &utargets[ti];
		uint64_t len = tg->seed(obj);
		double base = 0.0;
		int err = 0;
		uint32_t k;

		if (len > UNPACK_SEED)
			len = UNPACK_SEED;

		/* The clean scan, median of a few, for the same reason the parser
		 * test takes one: the first pays for page faults. */
		{
			double v[5];
			uint32_t a, bidx;

			for (a = 0; a < 5u; a++)
				v[a] = scan_once(sc, path, obj, len, tg, NULL, 0,
						 &err);
			for (a = 1; a < 5u; a++) {
				double x = v[a];
				for (bidx = a; bidx > 0 && v[bidx - 1] > x; bidx--)
					v[bidx] = v[bidx - 1];
				v[bidx] = x;
			}
			base = v[2];
		}

		/*
		 * The clean scan must actually reach an unpacker.
		 *
		 * Same lesson as the seed richness check next door: a case that
		 * runs and exercises nothing passes, and passing is then evidence
		 * of nothing. A container seed whose clean scan produces no child
		 * has not been opened, so every mutation of it is testing the
		 * parser again through a slower path.
		 */
		if (tg->produces && produced_total == 0) {
			printf("  SEED %s produces no child - the unpacker was "
			       "never reached\n", tg->name);
			t.errors++;
			t.slow++;
		}
		t.clean_bytes += produced_total;

		for (fi = 0; fi < tg->n_fields; fi++) {
			for (vi = 0; vi < HOSTILE_N; vi++) {
				double dt = scan_once(sc, path, obj, len, tg,
						      &tg->fields[fi],
						      hostile(vi, len), &err);
				double amp = base > 0.0 ? dt / base : 0.0;

				t.cases++;
				if (err) {
					t.errors++;
					err = 0;
				}
				if (dt > FLOOR_MS / 20.0 && amp > t.worst_amp) {
					t.worst_amp = amp;
					snprintf(t.worst, sizeof t.worst,
						 "%s %s=0x%llx", tg->name,
						 tg->fields[fi].name,
						 (unsigned long long)hostile(vi, len));
				}
				if (dt > FLOOR_MS && amp > AMPLIFY_MAX) {
					t.slow++;
					printf("  AMPLIFY %s %s=0x%llx: %.2f ms "
					       "against %.3f ms (%.0fx)\n",
					       tg->name, tg->fields[fi].name,
					       (unsigned long long)hostile(vi, len),
					       dt, base, amp);
				}
				if (produced_total > PRODUCE_CAP) {
					t.over_produce++;
					printf("  PRODUCE %s %s=0x%llx: %llu "
					       "bytes past a %u cap\n", tg->name,
					       tg->fields[fi].name,
					       (unsigned long long)hostile(vi, len),
					       (unsigned long long)produced_total,
					       PRODUCE_CAP);
				}
			}
		}
		(void)k;
	}

	unlink(path);
	free(obj);
	kof_scanner_free(sc);
	kof_engine_close(eng);

	if (t.worst_amp > 0.0)
		printf("hostile unpack: %llu scan(s) over %u format(s) through "
		       "the real modules, %llu byte(s) recovered from the clean "
		       "seeds, worst amplification %.0fx (%s)%s\n",
		       (unsigned long long)t.cases,
		       (unsigned)(sizeof utargets / sizeof utargets[0]),
		       (unsigned long long)t.clean_bytes, t.worst_amp, t.worst,
		       (t.slow || t.over_produce) ? " - FAILED" : "");
	else
		printf("hostile unpack: %llu scan(s) over %u format(s) through "
		       "the real modules, %llu byte(s) recovered from the clean "
		       "seeds, no case above %.2f ms%s\n",
		       (unsigned long long)t.cases,
		       (unsigned)(sizeof utargets / sizeof utargets[0]),
		       (unsigned long long)t.clean_bytes, FLOOR_MS / 20.0,
		       (t.slow || t.over_produce) ? " - FAILED" : "");

	return (t.slow || t.over_produce) ? 1 : 0;
}
