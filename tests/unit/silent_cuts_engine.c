/*
 * silent_cuts_engine - cuts of the engine's own tables that used to answer "nothing" in silence.
 *
 * 1. THE GRAPH BLOCK OF A LATER, LARGER OBJECT. oc_graph (objctx_diag.c) allocated the block a
 *    module reads once per scanner, sized by the first object that had nodes. A later object with
 *    more nodes made kof_diag_graph_build refuse whole (need > cap) and the graph read as absent:
 *    a rule over it saw no nodes and the object was "clean", with nothing said (the OBSERVATION
 *    row of docs/silent_loss_audit.txt). The block now grows for the object that needs it.
 *    tests/sigs/sig_graph_grow_00.c reads the graph of an object that holds a marker and infects
 *    when it has 20 nodes; the case scans a small object and then a large one on ONE scanner and
 *    asks for the finding on the large one, as a fresh scanner gives it.
 *
 * A REFUSED GRAPH BLOCK IS SAID is held by silent_oom_sweep.c, which scans this large object
 * (the "graph rule" fixture) with every allocation refused in turn and asks that a finding lost
 * to a refusal comes with a signal.
 */

#include "caps_fix.h"

static kof_engine *eng;

struct got {
	unsigned found;         /* GraphGrowTest on the top object */
	uint32_t broken;
};

static int on_obj(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	struct got *g = u;
	uint32_t i;

	(void)name; (void)b; (void)n;
	for (i = 0; i < r->n; i++)
		if (strstr(r->v[i].name, "GraphGrowTest"))
			g->found++;
	if (r->broken && !g->broken)
		g->broken = r->broken;
	return 0;
}

static uint8_t img[1u << 16];

/* `n` read() syscalls, a stager, and the marker the rule requires. */
static uint64_t build(unsigned fillers)
{
	uint8_t code[2048];
	unsigned at = 0, i;
	static const char marker[] = "GRAPHGROW-MARK";

	for (i = 0; i < fillers; i++)
		at = cf_filler64(code, at, i + 1u);
	at = cf_stager64(code, at);
	memcpy(code + at, marker, sizeof marker);
	return cf_elf64(img, sizeof img, code, at + sizeof marker);
}

static struct got scan(kof_scanner *sc, uint64_t n, const struct kof_stats **st)
{
	struct got g;
	struct kof_scan_option opt;

	memset(&g, 0, sizeof g);
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, img, n, "grow", &opt, on_obj, &g);
	if (st)
		*st = kscan_stats(sc);
	return g;
}

int main(int argc, char **argv)
{
	kof_scanner *a, *b;
	uint64_t small, big;
	struct got g;
	static uint8_t small_img[1u << 16];

	(void)argc; (void)argv;
	eng = keng_open("build/test/databases-sigs");
	if (!eng) {
		printf("silent_cuts_engine: no database - nothing tested\n");
		return 0;
	}
	small = build(1);
	memcpy(small_img, img, (size_t)small);
	big = build(30);

	/* the control: the large object alone, on a fresh scanner */
	b = kscan_new(eng);
	CK(b != NULL);
	g = scan(b, big, NULL);
	CK(g.found == 1u && g.broken == 0u);
	kscan_free(b);

	/* the same scanner sees a small object first, then the large one */
	a = kscan_new(eng);
	CK(a != NULL);
	{
		uint8_t keep[1u << 16];

		memcpy(keep, img, (size_t)big);
		memcpy(img, small_img, (size_t)small);
		g = scan(a, small, NULL);
		CK(g.found == 0u);              /* too few nodes, and the graph block is sized by it */
		memcpy(img, keep, (size_t)big);
	}
	g = scan(a, big, NULL);
	CK(g.found == 1u);                      /* before the change: 0, and nothing said */
	kscan_free(a);

	keng_close(eng);
	if (fails) {
		printf("silent_cuts_engine: %d check(s) failed\n", fails);
		return 1;
	}
	printf("silent_cuts_engine: the graph block grows for the object that needs it\n");
	return 0;
}
