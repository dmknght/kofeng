/*
 * budget - what a container is allowed to cost, and what happens when it asks for
 * more.
 *
 * A decompression bomb is not a deep archive. One layer of DEFLATE reaches about
 * 1000:1, so a bomb needs no nesting at all and a depth limit never sees it. The
 * thing that has to hold is a budget on PRODUCED BYTES, charged across the whole
 * tree under one top level object rather than per child - because a container full
 * of entries that are each individually reasonable is how the total gets away.
 *
 * And when it runs out, the answer has to be "did not finish", never "clean". An
 * exhausted budget reported as clean is not a limitation, it is a way of not being
 * scanned.
 *
 * The modules here are ordinary C functions with their address in a kof_module,
 * which is all a module ever is to the engine: a function pointer and some
 * preconditions. That means no database, no blob and no compiler in the loop, and
 * the test drives the real kof_scan_walk over a real file - so what is exercised is
 * the production path the scanner actually uses, not a model of it.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../libkofeng/kofscanners/scan.h"

static int failures;
static char root[256];
static char obj_path[512];

static void fail(const char *what, const char *why)
{
	printf("  FAIL %s: %s\n", what, why);
	failures++;
}

/* ---- what the run produced -------------------------------------------------- */

struct seen {
	uint64_t objects;
	uint64_t incomplete;
	uint64_t bytes;      /* every object scanned, summed: what was produced */
	uint64_t peak;       /* the most produced data alive at once */
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = user;

	(void)name;
	(void)bytes;
	(void)len;
	s->objects++;
	/* Any reason counts here: what these cases assert is that the object was
	 * not reported clean, not which of the three explanations applied. */
	s->incomplete += res->broken ? 1u : 0u;
	return 0;
}

/* ---- the modules ------------------------------------------------------------ */

/*
 * Produce far more than it consumes, and keep going until the host refuses.
 *
 * A real unpacker has exactly this shape, because emit is the only way to produce
 * output and it can say no. A module that ignored the refusal and looped anyway
 * would achieve nothing, which is the property under test: the limit is the host's
 * and does not depend on the module respecting it.
 */
static void mod_bomb(const struct kof_obj_ctx *ctx)
{
	static const char filler[64] = "bomb-filler-bomb-filler-bomb-filler-bomb";
	uint32_t round, i;

	for (round = 0; round < 8; round++) {
		for (i = 0; i < 4u * 1024u * 1024u; i++)
			if (!kof_emit(filler, sizeof filler))
				return;
		if (!kof_child())
			return;
	}
}

/*
 * A child identical to its parent, for ever.
 *
 * Costs no bytes at all - a window is the parent's mapping at a different offset -
 * so the byte budget never sees it. Depth and the child count are what have to stop
 * it, and if neither does the walk does not terminate.
 */
static void mod_selfwindow(const struct kof_obj_ctx *ctx)
{
	kof_child_window(0, ctx->obj_size);
}

/*
 * One entry, longer than any object is allowed to be.
 *
 * The shape of a real decompressor: emit until the host says no, then stop. What is
 * under test is what the host hands back - one object holding the FRONT of the
 * stream, not a series of fragments starting at arbitrary offsets. The front is the
 * part with the header in it, and an object without a header is one no format
 * parser and no format-targeted module can touch.
 */
static void mod_stream(const struct kof_obj_ctx *ctx)
{
	static uint8_t run[65536];
	uint32_t i;

	(void)ctx;
	memset(run, 'S', sizeof run);
	for (i = 0; i < 4096u; i++)          /* 256MB if it were allowed */
		if (!kof_emit(run, sizeof run))
			return;
	kof_child();
}

/*
 * Many siblings of a size worth holding: an archive of ordinary entries.
 *
 * This is the shape a zip or a tar has, and it is the one that shows what the
 * production model costs. A module runs to completion before any child it made is
 * scanned, so EVERY SIBLING IS ALIVE AT ONCE - the memory ceiling therefore bounds
 * the total unpacked size of one container, not the largest entry in it.
 *
 * The number this case pins down is how many entries of a given size a container
 * may have before the rest go unexamined.
 */
static void mod_siblings(const struct kof_obj_ctx *ctx)
{
	static uint8_t entry[65536];
	uint32_t i, k;

	(void)ctx;
	memset(entry, 'E', sizeof entry);
	for (i = 0; i < 64u; i++) {          /* 64 entries of 1MB */
		for (k = 0; k < 16u; k++)
			if (!kof_emit(entry, sizeof entry))
				return;
		if (!kof_child())
			return;
	}
}

/* Many small children rather than one large one: the shape a per-child limit
 * would let through. */
static void mod_wide(const struct kof_obj_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < 100000u; i++) {
		if (!kof_emit("x", 1))
			return;
		if (!kof_child())
			return;
	}
}

/*
 * One emit far larger than any honest one.
 *
 * A decompressor works from lengths written in the file it is decompressing, so a
 * wrong one is the ordinary hostile case. The host cannot check the length against
 * the module's own buffer, but it can refuse a length no honest caller has - which
 * is the difference between a refusal and a read of a gigabyte from a kilobyte.
 */
static void mod_bigemit(const struct kof_obj_ctx *ctx)
{
	static uint8_t huge[2u << 20];

	if (kof_emit(huge, sizeof huge))
		kof_child();
}

/* Emits and never closes the child. Nothing should be produced, and nothing
 * should leak - the sink is reset whether or not a module finished with it. */
static void mod_dangling(const struct kof_obj_ctx *ctx)
{
	uint32_t i;

	for (i = 0; i < 1000u; i++)
		if (!kof_emit("y", 1))
			return;
}

/* ---- driving the real scan path --------------------------------------------- */

static void run(const char *what, void (*fn)(const struct kof_obj_ctx *),
		const struct kof_scan_option *opt, struct seen *out)
{
	struct kof_engine eng;
	struct kof_module m;
	struct kof_scanner *sc;

	memset(&eng, 0, sizeof eng);
	memset(&m, 0, sizeof m);
	memset(out, 0, sizeof *out);

	m.fn = fn;
	m.target_mask = 0xffffffffu;   /* every format, including unidentified */
	eng.unp = &m;
	eng.n_unp = 1;

	sc = kof_scan_new(&eng);
	if (!sc) {
		fail(what, "out of memory");
		return;
	}
	kof_scan_walk(sc, obj_path, opt, on_object, out);
	{
		const struct kof_stats *st = kof_scan_stats(sc);

		out->bytes = st ? st->object_bytes : 0;
		out->peak  = st ? st->peak_resident : 0;
	}
	kof_scan_free(sc);
}

static void expect(const char *what, int cond, const char *why)
{
	if (!cond)
		fail(what, why);
}

static void trace(const char *what, const struct seen *s)
{
	if (getenv("KOF_BUDGET_TRACE"))
		printf("  [%s] objects=%llu incomplete=%llu bytes=%llu peak=%llu\n",
		       what, (unsigned long long)s->objects,
		       (unsigned long long)s->incomplete,
		       (unsigned long long)s->bytes,
		       (unsigned long long)s->peak);
}

int main(void)
{
	struct kof_scan_option opt;
	struct seen s;
	FILE *f;
	const char *tmp = getenv("TMPDIR");

	snprintf(root, sizeof root, "%s/kof_budget_XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(root)) {
		printf("budget: cannot make a work directory\n");
		return 1;
	}
	snprintf(obj_path, sizeof obj_path, "%s/obj", root);
	f = fopen(obj_path, "wb");
	if (!f) {
		printf("budget: cannot write the object\n");
		rmdir(root);
		return 1;
	}
	fwrite("a small file that produces a very large amount of nothing", 1, 57, f);
	fclose(f);

	memset(&opt, 0, sizeof opt);

	/*
	 * Everything below runs with the memory ceiling set low on purpose. It is
	 * the limit that matters and the one worth exercising: the engine maps
	 * objects rather than reading them, so producing children is the only path
	 * that allocates at all, and it must not undo that.
	 */
	opt.max_resident_bytes = 8u << 20;

	/* --- the total budget binds: 1MB allowed, 2GB attempted --- */
	opt.max_produced_bytes = 1u << 20;
	run("bomb", mod_bomb, &opt, &s);
	trace("bomb", &s);
	expect("bomb", s.incomplete >= 1,
	       "an exhausted budget was not reported as incomplete");
	expect("bomb", s.bytes <= 57 + (1u << 20),
	       "more was produced than the total budget allowed");
	expect("bomb", s.peak <= opt.max_resident_bytes,
	       "more produced data was alive at once than the ceiling allows");
	expect("bomb", s.bytes > 57,
	       "the budget discarded what had already been decompressed "
	       "instead of cutting");

	/*
	 * The same bomb with a total budget far above the memory ceiling.
	 *
	 * This is the case the two limits exist separately for: plenty of total
	 * work allowed, almost no memory. It has to produce children and it has to
	 * stop - and it must stop on the ceiling, not by running the machine out of
	 * memory, which is exactly what happened when the byte budget was the only
	 * limit there was.
	 */
	opt.max_produced_bytes = 64u << 20;
	run("bomb-roomy", mod_bomb, &opt, &s);
	trace("bomb-roomy", &s);
	expect("bomb-roomy", s.bytes <= 57 + (64u << 20),
	       "more was produced than the total budget allowed");
	expect("bomb-roomy", s.bytes >= (32u << 20),
	       "the memory ceiling stopped the tree far short of the work the "
	       "total budget allows: each object should be scanned and released, "
	       "making room for the next");
	expect("bomb-roomy", s.incomplete >= 1,
	       "reaching a limit was not reported");
	/*
	 * The whole point, and the only assertion that speaks to it directly:
	 * sixty-four megabytes went through a scanner that never held more than
	 * eight at once.
	 */
	expect("bomb-roomy", s.peak <= opt.max_resident_bytes,
	       "more produced data was alive at once than the ceiling allows");

	/*
	 * --- one long entry: truncated to its head, not cut into fragments ---
	 *
	 * The cap is half the resident ceiling, so 4MB here. Depth is 1 because the
	 * child is itself a stream of S and would otherwise be unpacked in turn;
	 * what this case is about is the shape of one object, not the tree.
	 */
	opt.max_produced_bytes = 1u << 30;
	opt.max_depth = 1;
	run("stream", mod_stream, &opt, &s);
	trace("stream", &s);
	expect("stream", s.objects == 2,
	       "a stream longer than the cap did not yield exactly one child: "
	       "it was cut into fragments instead of truncated");
	expect("stream", s.bytes <= 57 + (4u << 20),
	       "one produced object held more than the object cap");
	expect("stream", s.bytes >= 57 + (2u << 20),
	       "the cap truncated far below what it allows");
	expect("stream", s.incomplete >= 1,
	       "dropping the tail of an entry was not reported as incomplete");
	opt.max_depth = 0;

	/*
	 * --- an archive of ordinary entries, against a small ceiling ---
	 *
	 * 64 entries of 1MB each, a 1GB total budget, no child cap, depth 1 so the
	 * entries are not themselves unpacked. Nothing here is a bomb: every entry
	 * is a reasonable size and the total is 64MB. The only thing that can stop
	 * it is the ceiling, and what it stops is BREADTH.
	 */
	opt.max_produced_bytes = 1u << 30;
	opt.max_children = 0;
	opt.max_depth = 1;
	run("siblings", mod_siblings, &opt, &s);
	trace("siblings", &s);
	expect("siblings", s.peak <= opt.max_resident_bytes,
	       "more produced data was alive at once than the ceiling allows");
	/*
	 * Eight, because the ceiling is 8MB and the entries are 1MB: they are all
	 * held until the module returns. If production and scanning were ever
	 * interleaved this would reach 64 and this assertion is what would say so.
	 */
	expect("siblings", s.objects <= 1 + (opt.max_resident_bytes >> 20),
	       "more siblings survived than the ceiling can hold at once");
	expect("siblings", s.incomplete >= 1,
	       "entries left unexamined were not reported");
	opt.max_depth = 0;

	/* --- many small children: what a per-child limit would miss --- */
	opt.max_produced_bytes = 4096;
	opt.max_children = 0;
	run("wide", mod_wide, &opt, &s);
	trace("wide", &s);
	expect("wide", s.incomplete >= 1, "a wide bomb was not reported as incomplete");
	expect("wide", s.objects <= 4098,
	       "a byte budget did not bound a container of tiny entries");
	expect("wide", s.peak <= opt.max_resident_bytes,
	       "more produced data was alive at once than the ceiling allows");
	expect("wide", s.bytes <= 57 + 8192,
	       "a container of tiny entries produced more than its budget");

	/* --- the child count, independent of bytes --- */
	opt.max_produced_bytes = 1u << 30;
	opt.max_children = 8;
	run("children", mod_wide, &opt, &s);
	trace("children", &s);
	expect("children", s.objects <= 9, "the child cap did not hold");
	opt.max_children = 0;

	/*
	 * A window costs no bytes, so the byte budget cannot stop it. Depth has to,
	 * and if nothing does this call never returns.
	 */
	opt.max_produced_bytes = 1u << 30;
	opt.max_depth = 6;
	run("self-window", mod_selfwindow, &opt, &s);
	trace("self-window", &s);
	expect("self-window", s.objects == 7,
	       "a self-referential window was not bounded by depth");

	/*
	 * No depth limit at all. The child count is then the only thing left, and it
	 * has to be enough on its own - a caller who sets no limits must still get a
	 * scan that terminates.
	 */
	opt.max_depth = 0;
	opt.max_children = 32;
	run("self-window-nodepth", mod_selfwindow, &opt, &s);
	trace("self-window-nodepth", &s);
	expect("self-window-nodepth", s.objects <= 33,
	       "with no depth limit the child cap did not bound the tree");
	opt.max_children = 0;

	/* --- a single emit no honest decompressor makes --- */
	opt.max_depth = 0;
	opt.max_children = 0;
	opt.max_produced_bytes = 1u << 30;
	run("big-emit", mod_bigemit, &opt, &s);
	trace("big-emit", &s);
	expect("big-emit", s.objects == 1,
	       "an implausible emit length was accepted and became an object");
	expect("big-emit", s.incomplete == 1,
	       "an implausible emit length was refused without saying so");

	/* --- emitted but never closed: no object, and nothing left behind --- */
	opt.max_depth = 0;
	opt.max_produced_bytes = 1u << 20;
	run("dangling", mod_dangling, &opt, &s);
	trace("dangling", &s);
	expect("dangling", s.objects == 1,
	       "bytes that were never closed into a child became one anyway");

	unlink(obj_path);
	rmdir(root);

	printf("budget: bomb, stream, siblings, wide, window and dangling %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
