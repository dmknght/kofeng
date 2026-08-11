/*
 * child_fuzz - drive the child-object machinery with modules that behave badly.
 *
 * budget.c checks the limits with modules written to test one thing each. This does
 * the opposite: one module that does whatever the random number generator says -
 * emit a bit, open a window, close a child, emit nothing, close nothing, ask for a
 * range that is not there - against limits that are also random. What is asserted
 * is not what it produced but that the bookkeeping still adds up afterwards.
 *
 * The invariant that matters, and the reason this test exists:
 *
 *     when the walk is over, the resident count is back to zero
 *
 * That number is the memory ceiling. It goes up when bytes are produced and down
 * when they are freed, and every path a child can die on has to account for it: the
 * ordinary one, the child cap refusing it, an allocation failing, the walk being
 * abandoned part way. A path that forgets leaves the count high, and the ceiling
 * quietly shrinks for the rest of the scan - a limit that tightens itself as it goes
 * is a limit nobody can predict, and nothing else in the suite would notice.
 *
 * Under SAN=1 this is also where the reference counting is checked: a window holds
 * its parent alive, children outlive the module that made them, and the whole tree
 * is released in an order the generator chose rather than one anybody designed.
 * Getting that wrong is a use-after-free or a leak, and LeakSanitizer is watching.
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

static uint64_t rng_state = 1;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static void fail(uint64_t round, const char *why)
{
	printf("  FAIL round %llu: %s\n", (unsigned long long)round, why);
	failures++;
}

/* ---- a module that does whatever it is told ---------------------------------- */

/*
 * Every action a producer can take, chosen at random and repeated.
 *
 * Including the ones no sensible module would: emitting after being refused,
 * closing a child that has nothing in it, asking for a window past the end of the
 * object, asking for one of zero length. Those are the paths a real unpacker
 * reaches by having a bug, and they have to be as safe as the paths it reaches by
 * working.
 */
static void mod_random(const struct kof_obj_ctx *ctx)
{
	static uint8_t buf[70000];
	uint32_t steps = (uint32_t)(rnd() % 40);
	uint32_t i;

	for (i = 0; i < steps; i++) {
		switch (rnd() % 8) {
		case 0:
		case 1:
		case 2: {
			/* Emit a run. Sometimes larger than the host will take. */
			uint32_t n = (uint32_t)(rnd() % (rnd() % 4 ? 4096u
							       : sizeof buf));
			memset(buf, (int)(rnd() & 0xff), n);
			(void)kof_emit(buf, n);
			break;
		}
		case 3:
			(void)kof_child();
			break;
		case 4:
			/* A window somewhere inside, or somewhere outside. */
			(void)kof_child_window(rnd() % (ctx->obj_size + 64),
					       rnd() % (ctx->obj_size + 64));
			break;
		case 5:
			(void)kof_child_window(0, ctx->obj_size);
			break;
		case 6:
			(void)kof_emit(buf, 0);       /* nothing at all */
			break;
		default:
			(void)kof_child_window(ctx->obj_size + 1, 16);  /* nowhere */
			break;
		}
	}
}

/* ---- driving it -------------------------------------------------------------- */

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	uint64_t *n = user;

	(void)name;
	(void)bytes;
	(void)len;
	(void)res;
	(*n)++;
	/* Abandon the walk sometimes: an aborted walk drops children that were
	 * produced and never scanned, which is its own accounting path. */
	return (rnd() % 64) == 0 ? 1 : 0;
}

static void one_round(uint64_t round)
{
	struct kof_scan_option opt;
	struct kof_engine eng;
	struct kof_module m;
	struct kof_scanner *sc;
	uint64_t objects = 0;

	memset(&opt, 0, sizeof opt);
	memset(&eng, 0, sizeof eng);
	memset(&m, 0, sizeof m);

	/* Limits drawn small and odd on purpose: the interesting behaviour is at
	 * the edges, and a ceiling of a few kilobytes reaches them in one step. */
	opt.max_resident_bytes = 1024 + rnd() % (256u * 1024u);
	opt.max_produced_bytes = 1024 + rnd() % (1024u * 1024u);
	opt.max_children       = (uint32_t)(rnd() % 40);
	opt.max_depth          = (uint32_t)(rnd() % 8);
	opt.all_matches        = (int)(rnd() & 1);

	m.fn = mod_random;
	m.target_mask = 0xffffffffu;
	eng.unp = &m;
	eng.n_unp = 1;

	sc = kof_scan_new(&eng);
	if (!sc) {
		fail(round, "out of memory");
		return;
	}
	kof_scan_walk(sc, obj_path, &opt, on_object, &objects);

	/*
	 * The whole point. Every byte charged has to have been given back, whatever
	 * happened to the object that was holding it.
	 */
	if (sc->resident != 0)
		fail(round, "produced bytes were still charged after the walk");
	if (sc->st.peak_resident > opt.max_resident_bytes)
		fail(round, "more produced data was alive at once than the ceiling");
	if (sc->n_kids != 0)
		fail(round, "children were left attached to the scanner");
	if (sc->sink_fd >= 0 || sc->sink_mem)
		fail(round, "the emit sink was left open");

	kof_scan_free(sc);
}

int main(int argc, char **argv)
{
	uint64_t rounds = 3000, seed = 20240101u, r;
	const char *tmp = getenv("TMPDIR");
	FILE *f;
	uint32_t i;

	if (argc > 1)
		seed = strtoull(argv[1], 0, 0);
	if (argc > 2)
		rounds = strtoull(argv[2], 0, 0);
	rng_state = seed ? seed : 1;

	snprintf(root, sizeof root, "%s/kof_child_XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(root)) {
		printf("child fuzz: cannot make a work directory\n");
		return 1;
	}
	snprintf(obj_path, sizeof obj_path, "%s/obj", root);
	f = fopen(obj_path, "wb");
	if (!f) {
		printf("child fuzz: cannot write the object\n");
		rmdir(root);
		return 1;
	}
	/* Big enough that a window into it is a real range, small enough that the
	 * run is about the machinery rather than about copying. */
	for (i = 0; i < 8192; i++)
		fputc((int)(i * 7u + 3u) & 0xff, f);
	fclose(f);

	for (r = 0; r < rounds && failures < 8; r++)
		one_round(r);

	unlink(obj_path);
	rmdir(root);

	printf("child fuzz: %llu round(s) of random producers %s\n",
	       (unsigned long long)rounds, failures ? "FAILED" : "ok");
	return failures != 0;
}
