/*
 * db_scale.c - what a database costs when it stops being small.
 *
 * Every other test here runs against the eighteen modules in bases/, where nothing
 * about size can go wrong because there is no size. The numbers that decide whether
 * this engine can hold a real database - Kaspersky shipped four million records -
 * are all per-record, and a per-record cost is invisible until it is multiplied.
 *
 * So this builds a pack with a lot of modules in it, loads it, and reports what the
 * process is holding. Not a benchmark: the point is the SHAPE of the cost, which is
 * linear in the record count and therefore fully determined by a coefficient that a
 * small run measures just as well as a big one. Measuring at sixty four thousand and
 * multiplying is honest arithmetic; the multiplier is printed so nobody has to
 * believe it.
 *
 *
 * WHY RESIDENT BYTES AND NOT THE FILE SIZE
 *
 * A pack on disk is mapped, and a mapped byte that is never touched costs nothing.
 * What costs is what kof_db_load BUILDS from it - the module table, the name table,
 * the string tables and pool, and the code arena, all of which are freshly allocated
 * and populated, and none of which are shared between processes or dropped under
 * pressure. That is what a scan session holds from its first object to its last,
 * and it is what has to fit.
 *
 *
 * WHY THE PER-OBJECT TIME IS HERE TOO
 *
 * Because the same multiplication applies and lands somewhere worse. The scan loop
 * in scan.c is linear over every module in the database, per object, with prefilter
 * as the only cheap rejection. Resident bytes at four million records is a number
 * that can be paid for with RAM; the sweep at four million records per object cannot
 * be paid for at all. Both are measured here so the two are read together.
 *
 * The object scanned is deliberately one the modules do not target, so the sweep is
 * pure prefilter and the measurement is of the floor - the cost an object pays for
 * modules that never run. An object that matches costs strictly more.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/vfs.h>

#include "../../libkofeng/kofdb/kofdb.h"
#include "../../libkofeng/kofdb/kofpackw.h"
#include "../../libkofeng/kofscanners/scan.h"
#include "../../libkofeng/kofeng.h"

static int failures;

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/*
 * How many modules to build. Overridable, because the interesting run is the one
 * nobody wants in the default suite: four million modules is a couple of gigabytes
 * and several minutes, and this file is also compiled under ASAN.
 */
#define SCALE_DEFAULT 65536u

/*
 * The ceiling this test enforces, in resident bytes per record.
 *
 * Not a wish - it is where the current layout sits plus room to move. It exists so
 * that a change which adds a fixed width field to a per-record structure fails here
 * rather than in a customer's memory graph two releases later. Raising it is a
 * decision; drifting past it is not.
 *
 * Measured, on disk: 32 bytes a record natively and 38 under ASAN, whose redzones
 * cost six. Sixty four leaves room for a field or two and still fails long before a
 * doubling.
 *
 * AND IT IS ONLY ENFORCED WHERE IT MEANS SOMETHING. On tmpfs the same database reads
 * 130, because a mapped pack cannot have clean pages when RAM is the backing store -
 * four times the figure, none of it the engine's doing. A budget checked against a
 * number that is known to be wrong is either loose enough to catch nothing or tight
 * enough to fail an innocent build; this one says so and stands down instead.
 */
#define BYTES_PER_REC_MAX 64u

/*
 * Records per routine in the data shaped run - the most the ABI allows.
 *
 * KOF_MAX_STR_PER_MODULE is 64, so a routine can carry sixty four patterns and no
 * more, and four million records need at least sixty two thousand five hundred
 * modules however data shaped the intent is. That cap is the ceiling on how far the
 * per-module overheads can be amortised, which makes this the best case the current
 * ABI can express rather than an arbitrary choice.
 */
#define SCALE_PER_ROUTINE KOF_MAX_STR_PER_MODULE

/* The record count the extrapolation targets, for no reason except that it is the
 * number a real database reached. */
#define REAL_WORLD_RECORDS 4000000ull

/* ---- measuring ------------------------------------------------------------ */

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/*
 * Two resident figures, because they are two different obligations.
 *
 * Resident used to be one number out of statm and that was honest while every byte
 * of the database was a private allocation. It is not any more: the packs stay
 * mapped for their names, and reading a mapping during load makes its pages resident
 * - so a single figure now adds page cache to private memory and calls the total the
 * cost of a scan session. It is not. Those two bytes behave differently under
 * pressure and only one of them is the process's to pay:
 *
 *   PRIVATE DIRTY is memory nobody else has and the kernel cannot take back, because
 *   there is nowhere to take it back to - it was written, and the only copy is here.
 *   It has to be paid, per process, and it is what a memory budget is about.
 *
 *   The rest is clean file pages from the mapped packs. They read as Private_Clean
 *   with one process mapping them, which sounds like a cost and is not: a clean file
 *   page can be dropped and re-read from the pack, and a second scanner mapping the
 *   same file shares them rather than duplicating them. Counting those as memory the
 *   process holds is what made mapping look worse than copying.
 *
 * smaps_rollup separates them; statm cannot. The distinction is the whole reason
 * mapping is worth doing, so a test that could not see it would be measuring the
 * change out of existence.
 */
struct rss { uint64_t priv, total; };

static struct rss rss_bytes(void)
{
	FILE *f = fopen("/proc/self/smaps_rollup", "r");
	struct rss r = { 0, 0 };
	char line[256];

	if (!f)
		return r;
	while (fgets(line, sizeof line, f)) {
		unsigned long kb;

		if (sscanf(line, "Private_Dirty: %lu kB", &kb) == 1)
			r.priv += (uint64_t)kb << 10;
		else if (sscanf(line, "Rss: %lu kB", &kb) == 1)
			r.total += (uint64_t)kb << 10;
	}
	fclose(f);
	return r;
}

static void human(uint64_t b, char *out, size_t cap)
{
	if (b >= (1ull << 30))
		snprintf(out, cap, "%.2f GB", (double)b / (double)(1ull << 30));
	else if (b >= (1ull << 20))
		snprintf(out, cap, "%.1f MB", (double)b / (double)(1ull << 20));
	else
		snprintf(out, cap, "%.1f KB", (double)b / 1024.0);
}

/*
 * Is the work directory RAM pretending to be a disk?
 *
 * It changes the headline by a factor of three, so it cannot be left for the reader
 * to guess. A pack mapped from a real filesystem contributes clean pages: droppable
 * under pressure, re-read from the file, shared with any other process mapping it.
 * A pack mapped from tmpfs contributes dirty ones, because RAM IS the backing store
 * and there is nowhere to drop them to - the same bytes, the same code, and an
 * obligation that cannot be given back.
 *
 * /tmp is tmpfs on most modern systems, which makes the default run the pessimistic
 * one. That is the right default for a test and the wrong number to quote.
 */
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

static int is_ram_backed(const char *path)
{
	struct statfs sf;

	return statfs(path, &sf) == 0 && (long)sf.f_type == TMPFS_MAGIC;
}

/* ---- the synthetic database ----------------------------------------------- */

/*
 * One module's worth of bytes, sized like the real ones.
 *
 * The blob is a no-op function - two nops and a return - padded to the length the
 * modules in bases/ actually compile to, because the code arena copies every blob
 * and its size is therefore a per-record cost like any other. A three byte stub
 * would measure a database that does not exist.
 */
#define BLOB_LEN 160u

struct synth {
	struct kof_pw_mod  *mod;
	struct kof_pw_str  *str;
	struct kof_pw_name *name;
	uint8_t            *lit;      /* LIT_LEN per module */
	char               *text;     /* NAME_LEN per module */
	uint8_t            *code;     /* BLOB_LEN per module */
	uint32_t            n;      /* modules */
	uint32_t            recs;   /* patterns with names on them */
};

#define LIT_LEN  24u
#define NAME_LEN 32u

static void synth_free(struct synth *s)
{
	free(s->mod);
	free(s->str);
	free(s->name);
	free(s->lit);
	free(s->text);
	free(s->code);
	memset(s, 0, sizeof *s);
}

/*
 * `recs` records spread over `mods` modules.
 *
 * THE RATIO IS THE WHOLE EXPERIMENT. A record is a pattern with a name on it; a
 * module is a compiled routine. Putting one record in each module measures a
 * database where every signature brought its own code, and that is the shape whose
 * per-record cost is dominated by things that are not the record - a 160 byte blob,
 * a 64 byte module row - none of which a pattern needs.
 *
 * Real databases are not that shape. ClamAV holds millions of signatures against a
 * fixed handful of matching routines, because a hash or a literal is DATA and does
 * not need a function of its own. Spreading the same records over a small fixed
 * number of modules measures that instead, and the difference between the two runs
 * is the cost of the premise rather than of the data.
 *
 * Distinct strings throughout, never one shared: a shared literal is pooled once and
 * the pool stops growing with the record count, which is the growth being measured.
 */
static int synth_build(struct synth *s, uint32_t recs, uint32_t mods)
{
	uint32_t i, m;
	uint32_t per = recs / mods;

	memset(s, 0, sizeof *s);
	if (!per)
		return 0;
	recs = per * mods;              /* exact, so the arithmetic below is too */
	s->n = mods;
	s->recs = recs;
	s->mod  = calloc(mods, sizeof *s->mod);
	s->str  = calloc(recs, sizeof *s->str);
	s->name = calloc(recs, sizeof *s->name);
	s->lit  = calloc(recs, LIT_LEN);
	s->text = calloc(recs, NAME_LEN);
	s->code = calloc(mods, BLOB_LEN);
	if (!s->mod || !s->str || !s->name || !s->lit || !s->text || !s->code) {
		synth_free(s);
		return 0;
	}

	for (i = 0; i < recs; i++) {
		uint8_t *lit  = s->lit + (size_t)i * LIT_LEN;
		char    *text = s->text + (size_t)i * NAME_LEN;

		snprintf((char *)lit, LIT_LEN, "sig-%010u-body", i);
		snprintf(text, NAME_LEN, "Trojan.Test.Gen.%u", i);

		s->str[i].bytes = lit;
		s->str[i].len   = (uint16_t)strlen((char *)lit);
		s->str[i].kind  = KOF_STR_LITERAL;

		s->name[i].id   = i;
		s->name[i].text = text;
	}

	for (m = 0; m < mods; m++) {
		uint8_t *code = s->code + (size_t)m * BLOB_LEN;

		memset(code, 0x90, BLOB_LEN);
		code[BLOB_LEN - 1] = 0xc3;   /* ret */

		s->mod[m].code        = code;
		s->mod[m].code_len    = BLOB_LEN;
		/* ELF only, so the object scanned below is rejected by format and
		 * the sweep measured is the prefilter and nothing else. */
		s->mod[m].target_mask = 1u << KOF_FMT_ELF;
		s->mod[m].scan_mask   = 1u << 2;
		s->mod[m].str         = &s->str[(size_t)m * per];
		s->mod[m].n_str       = per;
		s->mod[m].name        = &s->name[(size_t)m * per];
		s->mod[m].n_names     = per;
	}
	return 1;
}

/* ---- files ---------------------------------------------------------------- */

static int write_all(const char *path, const uint8_t *b, size_t n)
{
	FILE *f = fopen(path, "wb");
	size_t w;

	if (!f)
		return 0;
	w = fwrite(b, 1, n, f);
	fclose(f);
	return w == n;
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	(void)name; (void)bytes; (void)len; (void)res;
	++*(uint32_t *)user;
	return 0;
}

/* ---- the run -------------------------------------------------------------- */

struct shot {
	uint64_t held;        /* private resident bytes the load added */
	uint64_t held_total;  /* including the page cache it faulted in */
	uint32_t recs;
	size_t   img_len;
	double   build_ms, load_ms, scan_ms;
};

/*
 * Build a database of `recs` records over `mods` modules, load it, sweep one object.
 *
 * Returns zero on a failure it has already reported. Everything it allocates is
 * released before the resident figure is taken, so what is measured is what the
 * scan session holds and not what building it needed.
 */
static int build_here(const char *dir, uint32_t recs, uint32_t mods,
		      struct shot *out)
{
	char pack_path[512], obj_path[512];
	struct synth s;
	uint8_t *img = NULL;
	double t0;
	int ok = 0;

	memset(out, 0, sizeof *out);
	snprintf(pack_path, sizeof pack_path, "%s/scale.ksig", dir);
	snprintf(obj_path, sizeof obj_path, "%s/object.bin", dir);

	if (!synth_build(&s, recs, mods)) {
		fail("scale", "out of memory building the modules");
		return 0;
	}
	out->recs = s.recs;

	t0 = now_ms();
	img = kof_pack_build(KOF_PACK_DETECT, s.mod, s.n, &out->img_len);
	out->build_ms = now_ms() - t0;
	if (!img) {
		fail("scale", "kof_pack_build refused the module set");
		goto out_synth;
	}
	if (!write_all(pack_path, img, out->img_len)) {
		fail("scale", "cannot write the pack");
		goto out_img;
	}
	free(img);
	img = NULL;
	synth_free(&s);

	ok = 1;
	goto out_done;
out_img:
	free(img);
out_synth:
	synth_free(&s);
	return 0;
out_done:
	return ok;
}

/*
 * Load the pack that build_here wrote, and report what holding it costs.
 *
 * A SEPARATE FUNCTION BECAUSE IT MUST BE A SEPARATE PROCESS. Resident bytes are
 * measured as a delta across the load, and building a pack leaves the allocator
 * holding tens of megabytes of freed-but-touched heap that the load then reuses -
 * so a measurement taken in the builder's process attributes the builder's churn to
 * the engine. Measured: the engine's tables come to 30.5 bytes a record, and taking
 * the delta in the process that had just built the pack read 92.
 *
 * Three times the real figure, in the conservative direction, which is the direction
 * that hides nothing but wastes the effort of fixing what was never there.
 */
static int load_here(const char *dir, struct shot *out)
{
	char pack_path[512], obj_path[512];
	struct kof_engine *e = NULL;
	struct rss rss0, rss1;
	double t0;
	int ok = 0;

	snprintf(pack_path, sizeof pack_path, "%s/scale.ksig", dir);
	snprintf(obj_path, sizeof obj_path, "%s/object.bin", dir);
	rss0 = rss_bytes();
	t0 = now_ms();
	e = kof_db_load(pack_path);
	out->load_ms = now_ms() - t0;
	rss1 = rss_bytes();
	if (!e) {
		fail("scale", "the pack did not load");
		return 0;
	}
	out->held = rss1.priv > rss0.priv ? rss1.priv - rss0.priv : 0;
	out->held_total = rss1.total > rss0.total ? rss1.total - rss0.total : 0;

	{
		struct kof_scan_option opt;
		struct kof_scanner *sc;
		uint32_t seen = 0;

		memset(&opt, 0, sizeof opt);
		sc = kof_scan_new(e);
		if (!sc) {
			fail("scale", "cannot make a scanner");
			goto out_db2;
		}
		t0 = now_ms();
		kof_scan_walk(sc, obj_path, &opt, on_object, &seen);
		out->scan_ms = now_ms() - t0;
		kof_scan_free(sc);
		if (seen != 1u)
			fail("scale", "the object was not scanned");
	}
	ok = 1;
out_db2:
	kof_db_free(e);
	return ok;
}

/*
 * Build in one process, load in another, and keep only what each is entitled to say.
 *
 * Two forks rather than one. The first was already needed - a second shape measured
 * in a process that had run the first reads near zero, because the heap it grew is
 * still there to be reused. The second is needed for the same reason one level down:
 * the builder's freed memory would otherwise pay for the loader's tables.
 *
 * Neither child prints. They send their half of the result back and the parent joins
 * them, so there is one place that decides what a measurement means.
 */
static int run_stage(const char *dir, uint32_t recs, uint32_t mods, int building,
		     struct shot *out)
{
	int fd[2];
	pid_t pid;
	int status = 0;
	ssize_t got;

	if (pipe(fd) != 0) {
		fail("scale", "cannot make a pipe");
		return 0;
	}
	pid = fork();
	if (pid < 0) {
		close(fd[0]);
		close(fd[1]);
		fail("scale", "cannot fork");
		return 0;
	}
	if (pid == 0) {
		struct shot sh;
		int ok;

		close(fd[0]);
		memset(&sh, 0, sizeof sh);
		ok = building ? build_here(dir, recs, mods, &sh)
			      : load_here(dir, &sh);
		if (ok && write(fd[1], &sh, sizeof sh) != (ssize_t)sizeof sh)
			ok = 0;
		close(fd[1]);
		_exit(ok ? 0 : 1);
	}
	close(fd[1]);
	got = read(fd[0], out, sizeof *out);
	close(fd[0]);
	waitpid(pid, &status, 0);
	if (got != (ssize_t)sizeof *out) {
		fail("scale", "the measurement did not come back");
		return 0;
	}
	return 1;
}

static int measure(const char *dir, uint32_t recs, uint32_t mods, struct shot *out)
{
	struct shot built, loaded;

	memset(out, 0, sizeof *out);
	if (!run_stage(dir, recs, mods, 1, &built))
		return 0;
	if (!run_stage(dir, recs, mods, 0, &loaded))
		return 0;

	out->recs     = built.recs;
	out->img_len  = built.img_len;
	out->build_ms = built.build_ms;
	out->held       = loaded.held;
	out->held_total = loaded.held_total;
	out->load_ms    = loaded.load_ms;
	out->scan_ms    = loaded.scan_ms;
	return 1;
}

/* What the two shapes cost, per record, extrapolated. */
static void report(const char *what, const struct shot *sh)
{
	double per_rec = (double)sh->held / (double)sh->recs;
	double per_tot = (double)sh->held_total / (double)sh->recs;
	double per_us  = sh->scan_ms * 1000.0 / (double)sh->recs;
	char h1[32], h2[32], h3[32];

	human(sh->held, h1, sizeof h1);
	human((uint64_t)(per_rec * (double)REAL_WORLD_RECORDS), h2, sizeof h2);
	human((uint64_t)(per_tot * (double)REAL_WORLD_RECORDS), h3, sizeof h3);
	printf("  %-22s %8u rec  private %8s  %5.0f B/rec"
	       "  ->  %s at %lluM (%s incl. page cache)\n",
	       what, sh->recs, h1, per_rec, h2,
	       (unsigned long long)(REAL_WORLD_RECORDS / 1000000ull), h3);
	printf("  %-22s sweep %.3f ms (%.4f us/rec), build %.0f ms, load %.0f ms\n",
	       "", sh->scan_ms, per_us, sh->build_ms, sh->load_ms);
}

int main(void)
{
	/*
	 * TMPDIR is honoured, and on this test it is not a convenience.
	 *
	 * The pack is written and then mapped, so where it lands decides what the
	 * mapping costs: /tmp is frequently tmpfs, where the "file" is RAM already
	 * and mapping it measures nothing about a database on a disk. Pointing this
	 * at disk-backed storage is the only way the private/page-cache split above
	 * means what it says.
	 */
	const char *tmp = getenv("TMPDIR");
	char dir[256];
	char obj_path[512];
	const char *env = getenv("KOF_SCALE_MODS");
	uint32_t n = env ? (uint32_t)strtoul(env, 0, 10) : SCALE_DEFAULT;
	struct shot per_mod, as_data;
	int have_a, have_b;

	if (n < 1024u)
		n = 1024u;

	if (snprintf(dir, sizeof dir, "%s/kofscaleXXXXXX",
		     tmp && *tmp ? tmp : "/tmp") >= (int)sizeof dir) {
		fail("scale", "TMPDIR is too long to work in");
		return 1;
	}
	if (!mkdtemp(dir)) {
		fail("scale", "cannot make a work directory");
		return 1;
	}
	snprintf(obj_path, sizeof obj_path, "%s/object.bin", dir);
	{
		uint8_t buf[4096];

		memset(buf, 'A', sizeof buf);
		if (!write_all(obj_path, buf, sizeof buf)) {
			fail("scale", "cannot write the object");
			rmdir(dir);
			return 1;
		}
	}

	printf("db scale: %u records, two shapes, work dir %s\n", n,
	       is_ram_backed(dir) ? "on tmpfs (mapped packs count as dirty; "
				    "set TMPDIR to disk for the real figure)"
				  : "on disk");
	/* One module per record: every signature carries its own compiled code. */
	have_a = measure(dir, n, n, &per_mod);
	/* The same records as data, over a fixed handful of routines. */
	have_b = measure(dir, n, n / SCALE_PER_ROUTINE, &as_data);

	if (have_a)
		report("record = module", &per_mod);
	if (have_b)
		report("record = data row", &as_data);

	/*
	 * The ceiling applies to the shape a real database would use.
	 *
	 * Holding the module-per-record shape to it would be enforcing a budget on a
	 * configuration nobody should build; letting the data shape drift is how the
	 * per-record cost gets away.
	 */
	if (have_b && is_ram_backed(dir)) {
		printf("  ceiling not checked: the work dir is tmpfs, where the "
		       "figure is not the engine's\n");
	} else if (have_b) {
		double per_rec = (double)as_data.held / (double)as_data.recs;

		if (per_rec > (double)BYTES_PER_REC_MAX) {
			char why[128];

			snprintf(why, sizeof why,
				 "%.0f resident bytes per record, ceiling is %u",
				 per_rec, BYTES_PER_REC_MAX);
			fail("scale", why);
		}
	}

	/*
	 * The pack is unlinked HERE, by the parent, and not by whichever child last
	 * touched it. The two stages each have their own reasons to fail early and
	 * neither owns the file - when the cleanup lived in the loader it was simply
	 * skipped on the paths that did not reach it, and the leftovers were four
	 * megabytes a run in a directory nobody looks at.
	 */
	{
		char pack_path[512];

		snprintf(pack_path, sizeof pack_path, "%s/scale.ksig", dir);
		unlink(pack_path);
	}
	unlink(obj_path);
	rmdir(dir);
	if (failures)
		printf("db_scale: %d failure(s)\n", failures);
	return failures ? 1 : 0;
}
