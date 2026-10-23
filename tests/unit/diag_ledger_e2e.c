/*
 * diag_ledger_e2e - the memory allowance reaches the diagnose scan THROUGH THE
 * ENGINE, and what it cannot finish is said.
 *
 * kgenome_budget.c and tests/lib/genome/budget_status.c check the lib's ledger
 * (charge, refuse, release) and a scan handed a budget directly. What they cannot
 * check is the engine's half, objctx_diag.c: that the scanner passes what is LEFT
 * of its own ceiling as the scan's max_bytes (oc_scan_room), charges the bytes the
 * graph holds back to that ceiling (diag_charged), reads the status back
 * (kof_scan_diag_status), turns OVER_BUDGET and NOMEM into "cannot say"
 * (kof_scan_incomplete) and gives the bytes back when the object is finished
 * (kof_scan_diag_drop). Those are read here the only way a caller can: through
 * kscan_bytes, with kof_scan_option.max_resident_bytes as the ceiling, and from
 * the result - `broken`, the verdict's `verdict_incomplete`, the verdict - and the scan's
 * peak_resident.
 *
 * THE FIXTURE is an x86-64 ELF of `k` unrelated reads and then the rwx_exec
 * stager, built in memory: the diagnose graph of a few thousand nodes, so the
 * graph is what the ceiling is spent on. The tight ceiling is FOUND, by
 * bisection, as the smallest that lets the scan finish - so the test does not
 * pin the size of a graph node.
 *
 *   ceiling below that        the object is not "clean": broken is
 *                             KOF_BROKEN_LIMIT, the verdict says incomplete and
 *                             there is no verdict (a 'no' from a scan that was
 *                             refused its memory is not evidence)
 *   the ceiling itself        finishes whole, verdict Dropper, nothing said
 *   ...again and again        on the SAME scanner, with a refused scan between: nothing
 *                             a scan holds leaks into the next (the resident count
 *                             is reset at the start of a kscan_bytes call, so this
 *                             does NOT isolate the release - status_direct does)
 *   the peak                  of a scan that finished is at least what the graph
 *                             held (the charge is made) and never above the ceiling
 *   the bigger object         needs a bigger ceiling (the charge follows the graph,
 *                             not a constant)
 *
 * AND THE ENGINE'S THREE FUNCTIONS ON A HAND-BUILT STATE (status_direct): a
 * scanner holding a graph the ledger cut, so kof_scan_diag_status says
 * OVER_BUDGET, kof_scan_incomplete says 1, and kof_scan_diag_drop frees the
 * graph and gives back exactly the bytes charged for it, nothing more. The
 * end-to-end half cannot isolate them: a graph cut by the allowance has nodes
 * missing, which makes the diagnose 'cannot say' by another route, and the
 * release is only visible between the objects of ONE scan (the resident count
 * is reset at the start of a kscan_bytes call).
 */

#include "caps_fix.h"
#include "caps_e2e.h"
#include "known_miss.h"
#include "../../libkofeng/scanners/scan.h"

static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

static uint64_t build(unsigned k)
{
	unsigned n = 0, i;

	for (i = 0; i < k; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	return cf_elf64(img, sizeof img, code, n);
}

struct one {
	int      done;          /* the scan produced an object                        */
	int      whole;         /* verdict Dropper, not broken, not incomplete        */
	int      cut;           /* broken == LIMIT, incomplete, no verdict            */
	int      said;          /* not whole, and says why: incomplete - a verdict a finished graph found may stand */
	uint64_t peak;
};

/* One kscan_bytes on `sc` with the given ceiling; `again` scans of the object. */
static struct one scan_on(kof_scanner *sc, uint64_t len, uint64_t ceiling)
{
	struct kof_scan_option opt;
	struct e2e r;
	struct one o;

	memset(&r, 0, sizeof r);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = ceiling;
	opt.max_object_bytes = 64u << 20;
	(void)kscan_bytes(sc, img, len, "ledger", &opt, e2e_on_object, &r);
	memset(&o, 0, sizeof o);
	o.done = r.n > 0;
	if (o.done) {
		o.whole = e2e_verdict_is(&r.o[0], "Dropper") && r.o[0].broken == 0 &&
			  !r.o[0].vf_incomplete;
		o.cut = r.o[0].broken == KOF_BROKEN_LIMIT && r.o[0].vf_incomplete &&
			!e2e_verdict_is(&r.o[0], "Dropper");
		o.said = !o.whole && r.o[0].vf_incomplete;
	}
	o.peak = kscan_stats(sc)->peak_resident;
	return o;
}

/* The smallest ceiling (to a 256-byte step) at which a FRESH scanner finishes. */
static uint64_t tightest(uint64_t len, uint64_t hi)
{
	uint64_t lo = 0;

	while (hi - lo > 256u) {
		uint64_t mid = lo + (hi - lo) / 2u;
		kof_scanner *sc = kscan_new(e2e_eng);
		struct one o = scan_on(sc, len, mid);

		kscan_free(sc);
		if (o.whole)
			hi = mid;
		else
			lo = mid;
	}
	return hi;
}

/* A diagnose scan of the filler object under a memory allowance of `bytes`. */
static struct kgenome_diag_scan *scan_with_allowance(unsigned k, uint64_t bytes)
{
	const struct kof_parser *pl;
	struct kof_obj_ctx ctx;
	static unsigned char view[1u << 22];
	uint64_t len = build(k);
	uint32_t np, i;
	kof_buf buf;

	buf.p = img;
	buf.n = len;
	memset(view, 0, sizeof view);
	memset(&ctx, 0, sizeof ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) && pl[i].parse && pl[i].parse(buf, view, &ctx)) {
			struct kgenome_obj gobj;
			struct kgenome_diag_inputs in;
			struct kgenome_budget b;

			memset(&in, 0, sizeof in);
			memset(&b, 0, sizeof b);
			b.max_bytes = bytes;
			in.budget = bytes ? &b : NULL;
			kof_genome_obj(&ctx, &gobj);
			return kgenome_diag_scan_with_inputs(&gobj, img, len,
							     KGENOME_DIAG_RUN_SYSCALL, &in);
		}
	return NULL;
}

static void status_direct(void)
{
	struct kof_obj_ctx ctx;
	kof_scanner *sc;
	struct kgenome_diag_scan *g;
	uint64_t charged, peak;

	if (!e2e_eng)
		return;
	sc = kscan_new(e2e_eng);
	CK(sc != NULL);
	if (!sc)
		return;
	memset(&ctx, 0, sizeof ctx);
	ctx.priv = sc;

	/* nothing ran: whole */
	CK(kof_scan_diag_status(&ctx) == KGENOME_OK);
	CK(kof_scan_incomplete(&ctx) == 0);

	/* a graph that finished: whole */
	g = scan_with_allowance(300, 0);
	CK(g && kgenome_diag_scan_status(g) == KGENOME_OK);
	sc->obj.diag.graph = g;
	CK(kof_scan_diag_status(&ctx) == KGENOME_OK);
	CK(kof_scan_incomplete(&ctx) == 0);
	kof_scan_diag_drop(sc);
	CK(sc->obj.diag.graph == NULL);

	/* a graph the allowance cut (one block of nodes fits): OVER_BUDGET, read
	 * LIVE from the graph, and the object is not complete */
	g = scan_with_allowance(300, 64u * sizeof(struct kgenome_diag_hit));
	CK(g && kgenome_diag_scan_status(g) == KGENOME_OVER_BUDGET);
	charged = g ? kgenome_diag_scan_bytes(g, &peak) : 0;
	CK(charged > 0);
	sc->obj.diag.graph = g;
	sc->obj.diag.charged = charged;
	sc->ledger.resident = charged + 100u;          /* the graph's bytes and something else */
	CK(kof_scan_diag_status(&ctx) == KGENOME_OVER_BUDGET);
	CK(kof_scan_incomplete(&ctx) == 1);

	/* the drop frees the graph and gives back EXACTLY what was charged */
	kof_scan_diag_drop(sc);
	CK(sc->obj.diag.graph == NULL && sc->obj.diag.charged == 0);
	CK(sc->ledger.resident == 100u);
	CK(kof_scan_diag_status(&ctx) == KGENOME_OK);
	CK(kof_scan_incomplete(&ctx) == 0);
	/* a second drop is nothing, and cannot wrap the count */
	kof_scan_diag_drop(sc);
	CK(sc->ledger.resident == 100u);

	/* no graph, but the scan's own status says it could not finish: the status
	 * the engine kept when the graph went (an allocation that failed) is read */
	sc->obj.diag.status = KGENOME_NOMEM;
	CK(kof_scan_diag_status(&ctx) == KGENOME_NOMEM);
	CK(kof_scan_incomplete(&ctx) == 1);
	sc->obj.diag.status = KGENOME_OVER_BUDGET;
	CK(kof_scan_incomplete(&ctx) == 1);
	sc->obj.diag.status = KGENOME_TRUNCATED;    /* a per-diagnose limit: said by diag_unk, not here */
	CK(kof_scan_incomplete(&ctx) == 0);
	sc->obj.diag.status = KGENOME_OK;
	kscan_free(sc);
}

static void ledger(void)
{
	uint64_t len, small_len, tight, tight_small;
	struct one o;
	kof_scanner *sc;
	unsigned i;

	CK(e2e_open(NULL));
	if (!e2e_eng)
		return;

	len = build(4000);
	/* control: a roomy ceiling finishes */
	sc = kscan_new(e2e_eng);
	o = scan_on(sc, len, 256u << 20);
	CK(o.done && o.whole);
	CK(o.peak > 0);
	kscan_free(sc);

	tight = tightest(len, 256u << 20);
	printf("    measured: the 4000-filler object finishes from a ceiling of %llu bytes\n",
	       (unsigned long long)tight);
	/* the graph is a real charge: not a few bytes */
	CK(tight > 4096u * 8u);

	/* below it: said, never clean. A little below, the nodes may all be there and only the lineage stages short of
	 * room (an optional product, skipped with a status): the verdict the finished graph found stands and the
	 * object says it is incomplete; far below, the graph itself is cut and there is no verdict. */
	sc = kscan_new(e2e_eng);
	o = scan_on(sc, len, tight - 256u);
	CK(o.done && o.said);
	kscan_free(sc);
	sc = kscan_new(e2e_eng);
	o = scan_on(sc, len, 1024u);
	CK(o.done && o.cut);
	kscan_free(sc);

	/* AT it, and again on the same scanner: the graph of each is given back */
	sc = kscan_new(e2e_eng);
	for (i = 0; i < 4u; i++) {
		o = scan_on(sc, len, tight);
		CK(o.done && o.whole);
		CK(o.peak <= tight);            /* never above the allowance */
	}
	/* and a refusal on a scanner does not poison the next object: the cut
	 * scan above charged nothing it did not give back */
	o = scan_on(sc, len, tight - 256u);
	CK(o.done && o.said);
	o = scan_on(sc, len, tight);
	CK(o.done && o.whole);
	kscan_free(sc);

	/* the charge follows the graph: a smaller object needs less */
	small_len = build(200);
	tight_small = tightest(small_len, 256u << 20);
	printf("    measured: the 200-filler object finishes from %llu bytes\n",
	       (unsigned long long)tight_small);
	CK(tight_small < tight);
	/* ...and the peak of a finished scan is what the graph held: at least the
	 * nodes' own bytes */
	{
		struct kof_obj_ctx ctx;
		static unsigned char view[1u << 22];
		struct kgenome_diag_scan *s;

		len = build(4000);
		memset(view, 0, sizeof view);
		s = cf_scan(img, len, KGENOME_DIAG_RUN_SYSCALL, &ctx, view);
		CK(s != NULL);
		sc = kscan_new(e2e_eng);
		o = scan_on(sc, len, 256u << 20);
		CK(o.whole);
		CK(s && o.peak >= (uint64_t)kgenome_diag_scan_count(s) * sizeof(struct kgenome_diag_hit));
		kscan_free(sc);
		kgenome_diag_scan_free(s);
	}
}

int main(void)
{
	ledger();
	status_direct();
	printf("diag ledger e2e: %u known miss(es) recorded, %s\n", km_known(),
	       fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
