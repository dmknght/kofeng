/*
 * kgenome_budget - the budget the caller supplies, and what the lib does with it.
 *
 * Three properties, each a way a limit used to be wrong:
 *
 *   SCALING  kgenome_budget_default derives every limit from the object, and
 *            every one is non-decreasing in the object's size and in its code's
 *            size, with the old constants as the floor: a bigger object may hold
 *            bigger products, a small one costs what it did. A limit that
 *            shrinks as the input grows, or a fixed one, is the shape that lost
 *            11806 loops.
 *   HONESTY  a budget too small for the object gives a PARTIAL answer that says
 *            so: KGENOME_TRUNCATED or KGENOME_OVER_BUDGET, the nodes already
 *            found kept - never the clean answer of an object that had nothing.
 *   THE LEDGER charges what it is asked, refuses what would exceed the allowance
 *            with nothing charged, gives back on release and cannot be wrapped
 *            by a release that was never charged.
 */

#include "caps_fix.h"
#include <phenotype/diag_int.h>

static unsigned char view[1u << 22];
static uint8_t img[1u << 21];
static uint8_t code[1u << 20];

/* ---- scaling ---------------------------------------------------------------- */

static void scaling(void)
{
	static const uint64_t sizes[] = {
		0, 1, 100, 4096, 32768, 100000, 1ull << 20, 8ull << 20, 64ull << 20,
		1ull << 30, 1ull << 40, UINT64_MAX / 64u, UINT64_MAX
	};
	struct kgenome_budget prev, b;
	unsigned i, j;

	/* the floors: a tiny object gets exactly them */
	kgenome_budget_default(&b, 100, 0);
	CK(b.max_nodes == 4096u && b.max_names == 4096u);   /* max(1024, nodes) */
	CK(b.max_insn == KGENOME_INSN_MIN && b.max_insn_resolve == KGENOME_RESOLVE_MIN);
	CK(b.obj_size == 100u && b.code_bytes == 100u);     /* code unknown: the object */

	/* monotone in the object's size, code unknown */
	kgenome_budget_default(&prev, sizes[0], 0);
	for (i = 1; i < sizeof sizes / sizeof sizes[0]; i++) {
		kgenome_budget_default(&b, sizes[i], 0);
		CK(b.max_nodes >= prev.max_nodes);
		CK(b.max_names >= prev.max_names);
		CK(b.max_insn >= prev.max_insn && b.max_insn_resolve >= prev.max_insn_resolve);
		CK(b.max_steps >= prev.max_steps);
		CK(b.max_bytes >= prev.max_bytes);
		prev = b;
	}
	/* monotone in the code's size, for objects of one size */
	for (j = 0; j < sizeof sizes / sizeof sizes[0]; j++) {
		kgenome_budget_default(&prev, 1ull << 40, sizes[0] + 1u);
		for (i = 1; i < sizeof sizes / sizeof sizes[0]; i++) {
			kgenome_budget_default(&b, 1ull << 40, sizes[i]);
			CK(b.max_nodes >= prev.max_nodes);
			CK(b.max_insn >= prev.max_insn);
			CK(b.max_steps >= prev.max_steps);
			prev = b;
		}
	}
	/* a node and a name are both named by 16 bits: 65534 is the most, however
	 * big the object; a huge one reaches it and stops there */
	kgenome_budget_default(&b, UINT64_MAX, UINT64_MAX);
	CK(b.max_nodes == KGENOME_MAX_INDEX && b.max_names == KGENOME_MAX_INDEX);
	/* the scaling itself: max(4096, code / 8) */
	kgenome_budget_default(&b, 100000, 100000);
	CK(b.max_nodes == 12500u);
	kgenome_budget_default(&b, 800000, 400000);
	CK(b.max_nodes == 50000u && b.max_names == 50000u);
	CK(b.max_insn == 64ull * 400000ull);

	/*
	 * THE OTHER CEILINGS SCALE TOO, exactly, and not only monotonically: a
	 * constant is monotone, and a ceiling that is flat in the code's size is what
	 * stopped 11806 loops in a big object. 64 instructions per code byte for the
	 * run, the PE resolver's run (its own, larger floor) and the wrapper walk's
	 * steps; the floors are what a small object gets.
	 */
	kgenome_budget_default(&b, 1000, 1000);                     /* 64000: under every floor */
	CK(b.max_insn == KGENOME_INSN_MIN && b.max_insn_resolve == KGENOME_RESOLVE_MIN);
	CK(b.max_steps == (1ull << 20));
	kgenome_budget_default(&b, 100000, 40000);                  /* 2.56M: over the run's floor only */
	CK(b.max_insn == 64ull * 40000ull && b.max_insn > KGENOME_INSN_MIN);
	CK(b.max_insn_resolve == KGENOME_RESOLVE_MIN);              /* 2.56M < 4M */
	CK(b.max_steps == 64ull * 40000ull);
	kgenome_budget_default(&b, 100000, 60000);                  /* 3.84M: still under the resolver's floor */
	CK(b.max_insn_resolve == KGENOME_RESOLVE_MIN && b.max_insn == 64ull * 60000ull);
	kgenome_budget_default(&b, 100000, 100000);                 /* 6.4M: over every floor */
	CK(b.max_insn == 6400000ull && b.max_insn_resolve == 6400000ull);
	CK(b.max_steps == 6400000ull);
	/* a bigger object's resolver run is bigger than a small object's */
	{
		struct kgenome_budget small;

		kgenome_budget_default(&small, 100, 0);
		CK(b.max_insn_resolve > small.max_insn_resolve);
		CK(b.max_insn > small.max_insn && b.max_steps > small.max_steps);
	}
	/* code unknown: the object's size stands in for it */
	kgenome_budget_default(&b, 200000, 0);
	CK(b.max_insn == 12800000ull && b.max_insn_resolve == 12800000ull);
	CK(b.max_nodes == 25000u);
}

/* ---- the ledger ------------------------------------------------------------- */

static void ledger(void)
{
	struct kgenome_ledger l;

	kgenome_ledger_init(&l, 1000);
	CK(kgenome_ledger_charge(&l, 400) && l.used == 400u);
	CK(kgenome_ledger_charge(&l, 600) && l.used == 1000u);
	CK(l.status == KGENOME_OK);
	/* exactly at the allowance holds; one byte past is refused, charges nothing */
	CK(!kgenome_ledger_charge(&l, 1));
	CK(l.used == 1000u && l.status == KGENOME_OVER_BUDGET);
	kgenome_ledger_release(&l, 500);
	CK(l.used == 500u && l.peak == 1000u);
	CK(kgenome_ledger_charge(&l, 500));
	/* a release that was never charged cannot wrap the count */
	kgenome_ledger_release(&l, 1ull << 62);
	CK(l.used == 0);
	CK(kgenome_ledger_charge(&l, 1000));
	/* a charge near UINT64_MAX does not overflow the test */
	CK(!kgenome_ledger_charge(&l, UINT64_MAX));
	/* the SOFT charge (a cache): refused without a status */
	kgenome_ledger_init(&l, 100);
	CK(!kgenome_ledger_try(&l, 101) && l.status == KGENOME_OK);
	CK(kgenome_ledger_try(&l, 100) && l.used == 100u);
	/* a zeroed ledger has no allowance - a hand-built scan in a test */
	memset(&l, 0, sizeof l);
	CK(kgenome_ledger_charge(&l, 1ull << 40) && l.status == KGENOME_OK);
}

/* ---- a tiny budget gives a partial answer that says so ---------------------- */

static struct kgenome_diag_scan *scan_budget(unsigned n_fillers, const struct kgenome_budget *b)
{
	const struct kof_parser *pl;
	struct kof_obj_ctx ctx;
	uint32_t np, i;
	unsigned n = 0;
	uint64_t len;
	kof_buf buf;

	for (i = 0; i < n_fillers; i++)
		n = cf_filler64(code, n, i);
	n = cf_stager64(code, n);
	memset(view, 0, sizeof view);
	len = cf_elf64(img, sizeof img, code, n);
	buf.p = img;
	buf.n = len;
	memset(&ctx, 0, sizeof ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) && pl[i].parse &&
		    pl[i].parse(buf, view, &ctx)) {
			struct kgenome_obj gobj;
			struct kgenome_diag_inputs in;

			memset(&in, 0, sizeof in);
			in.budget = b;
			kof_genome_obj(&ctx, &gobj);
			return kgenome_diag_scan_with_inputs(&gobj, img, len,
							     KGENOME_DIAG_RUN_SYSCALL, &in);
		}
	return NULL;
}

static void tiny_budget(void)
{
	struct kgenome_diag_scan *s;
	struct kgenome_budget b;

	/* control: no budget, the defaults - whole */
	s = scan_budget(100, NULL);
	CK(s && kgenome_diag_scan_status(s) == KGENOME_OK);
	CK(kgenome_diag_scan_count(s) == 103u);
	CK(cf_match_rwx(s) == 1);
	kgenome_diag_scan_free(s);

	/* THE NODE LIMIT, eight nodes: partial, the first eight kept, TRUNCATED */
	memset(&b, 0, sizeof b);
	b.max_nodes = 8;
	s = scan_budget(100, &b);
	CK(s != NULL);
	CK(kgenome_diag_scan_count(s) == 8u);
	CK(kgenome_diag_scan_status(s) == KGENOME_TRUNCATED);
	CK(cf_match_rwx(s) == 0);       /* the stager is past the limit: not matched... */
	CK(kgenome_diag_scan_status(s) != KGENOME_OK);  /* ...and the answer is not "clean" */
	kgenome_diag_scan_free(s);

	/* THE MEMORY ALLOWANCE, one byte: not even the first block of nodes fits.
	 * The scan exists, holds nothing, and says OVER_BUDGET */
	memset(&b, 0, sizeof b);
	b.max_bytes = 1;
	s = scan_budget(100, &b);
	CK(s != NULL);
	CK(kgenome_diag_scan_count(s) == 0u);
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	CK(cf_match_rwx(s) == 0);
	kgenome_diag_scan_free(s);

	/* AN ALLOWANCE FOR SOME OF THE NODES (the first block is 64 nodes): partial,
	 * what fits is kept, and the status is OVER_BUDGET - not TRUNCATED, because the
	 * caller's allowance and not the node limit ended it */
	memset(&b, 0, sizeof b);
	b.max_bytes = 64u * sizeof(struct kgenome_diag_hit);
	s = scan_budget(300, &b);
	CK(s != NULL);
	CK(kgenome_diag_scan_count(s) == 64u);
	CK(kgenome_diag_scan_status(s) == KGENOME_OVER_BUDGET);
	{
		uint64_t peak = 0, used = kgenome_diag_scan_bytes(s, &peak);

		CK(used <= b.max_bytes && peak <= b.max_bytes);   /* never over the allowance */
		CK(used >= 64u * sizeof(struct kgenome_diag_hit));
	}
	kgenome_diag_scan_free(s);

	/* A BIGGER ALLOWANCE gives the same object whole: the budget is what decides,
	 * not the object */
	memset(&b, 0, sizeof b);
	b.max_bytes = 1u << 20;
	s = scan_budget(300, &b);
	CK(kgenome_diag_scan_status(s) == KGENOME_OK && kgenome_diag_scan_count(s) == 303u);
	CK(cf_match_rwx(s) == 1);
	kgenome_diag_scan_free(s);
}

int main(void)
{
	scaling();
	ledger();
	tiny_budget();
	printf("kgenome budget: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
