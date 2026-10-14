/*
 * api_engine_scanint.c - the scanner's unit API (scanners/scan.h) that can be
 * driven with a scanner and nothing else: kof_scan_budget (what the options turn
 * into, the defaults kofoption.h states in words), kof_scan_kids_reset and
 * kof_scan_sink_discard (idempotent on a scanner that holds nothing), and the product
 * counters (kof_prod_ran / kof_prod_again / kof_scan_prod_repeats / kof_prod_name).
 *
 * The rest of scan.h takes a module context and is reached only from inside a scan;
 * those are exercised by every scan and by the probe modules (api_engine_modabi.c),
 * and docs/api_coverage_engine.txt names which.
 *
 * The budget is the bomb defence, so its arithmetic is held to the edges: a product
 * of object size and 64 that would overflow saturates, a resident ceiling of 1 byte
 * leaves an object cap of 1 and never 0 (a cap of 0 is "refuse everything", which is
 * a different statement from "very small"), an unset option is the default and not
 * zero.
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/scanners/scan.h"
#include "../../libkofeng/scanners/scan_state.h"
#include "../../libkofeng/scanners/objctx_int.h"

#define MB (1024ull * 1024ull)

static void t_budget(kof_scanner *sc)
{
	struct kof_scan_option o;

	memset(&o, 0, sizeof o);
	kof_scan_budget(sc, 0, &o);
	CK(sc->ledger.budget == 64 * MB, "an empty object still gets the 64MB floor (%llu)", (unsigned long long)sc->ledger.budget);
	CK(sc->ledger.resident == 0 && sc->ledger.resident_max == 128 * MB, "default resident ceiling is 128MB, and nothing is resident yet");
	CK(sc->ledger.kids_left == 4096u, "default children: 4096 (%u)", sc->ledger.kids_left);
	CK(sc->ledger.obj_cap == 16 * MB, "default object cap: 16MB (%llu)", (unsigned long long)sc->ledger.obj_cap);
	CK(sc->ledger.emu_left == KOF_SCAN_EMU_MAX, "the interpreter's allowance is refilled");
	CK(sc->ledger.emu_insn_left == 64 * MB && sc->ledger.emu_floor_left == KOF_SCAN_EMU_FLOOR_RUNS,
	   "the tree's instruction allowance is the 64 Mi floor for an empty root, with its floor runs (%llu)",
	   (unsigned long long)sc->ledger.emu_insn_left);
	CK(sc->obj.open.broken == 0 && sc->obj.open.stop == 0, "broken and stop are cleared");

	kof_scan_budget(sc, 1 * MB, &o);
	CK(sc->ledger.budget == 64 * MB, "1MB x 64 = 64MB");
	CK(sc->ledger.emu_insn_left == 64 * MB + 512 * MB, "the instruction allowance follows the ROOT: 64 Mi + 512 per byte");
	kof_scan_budget(sc, 1ull << 40, &o);
	CK(sc->ledger.emu_insn_left == 4096 * MB, "and is bounded: 4 Gi instructions for a root of any size");
	o.max_emu_insn = 12345;
	kof_scan_budget(sc, 1 * MB, &o);
	CK(sc->ledger.emu_insn_left == 12345, "the host's allowance is taken as it is");
	o.max_emu_insn = 0;
	kof_scan_budget(sc, 1 * MB, &o);
	kof_scan_budget(sc, 2 * MB, &o);
	CK(sc->ledger.budget == 128 * MB, "2MB x 64 = 128MB: the budget follows the object");
	kof_scan_budget(sc, 1ull << 40, &o);
	CK(sc->ledger.budget == 64ull << 40, "a terabyte object");
	kof_scan_budget(sc, UINT64_MAX / 64u, &o);
	CK(sc->ledger.budget == (UINT64_MAX / 64u) * 64u, "the largest size that does not overflow");
	kof_scan_budget(sc, UINT64_MAX / 64u + 1u, &o);
	CK(sc->ledger.budget == UINT64_MAX, "one past it saturates instead of wrapping to a small budget");
	kof_scan_budget(sc, UINT64_MAX, &o);
	CK(sc->ledger.budget == UINT64_MAX, "an object of 2^64-1 bytes");

	o.max_produced_bytes = 1000;
	kof_scan_budget(sc, 1ull << 40, &o);
	CK(sc->ledger.budget == 1000, "an explicit budget is taken as it is, even below the floor");
	memset(&o, 0, sizeof o);
	o.max_children = 3;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.kids_left == 3, "explicit children");
	o.max_children = 0xffffffffu;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.kids_left == 0xffffffffu, "children is not clamped by the engine (a caller who asks for 2^32-1 gets it)");

	memset(&o, 0, sizeof o);
	o.max_resident_bytes = 10 * MB;
	kof_scan_budget(sc, 10, &o);
	/* half the ceiling less the record of the object in hand (oc_kid_cost): a collected child is charged
	 * its record as well as its bytes, and two objects at the cap must still fit */
	CK(sc->ledger.resident_max == 10 * MB && sc->ledger.obj_cap == 5 * MB - oc_kid_cost(),
	   "an object may be at most half the resident ceiling less a child's record (%llu)", (unsigned long long)sc->ledger.obj_cap);
	o.max_object_bytes = 1 * MB;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.obj_cap == 1 * MB, "an explicit object cap under half is kept");
	o.max_object_bytes = 100 * MB;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.obj_cap == 5 * MB - oc_kid_cost(), "one over half is cut to half less a child's record");
	o.max_resident_bytes = 1;
	o.max_object_bytes = 0;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.resident_max == 1 && sc->ledger.obj_cap == 1, "a resident ceiling of one byte leaves an object cap of one, never zero");
	o.max_resident_bytes = UINT64_MAX;
	o.max_object_bytes = UINT64_MAX;
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.obj_cap == sc->ledger.resident_max / 2u - oc_kid_cost() && sc->ledger.obj_cap < UINT64_MAX / 2u,
	   "everything at 2^64-1: the cap is half of the resident ceiling (less a child's record), which the engine memory budget (kofbudget.h) bounds, not half of 2^64-1");

	/* a budget resets what the previous object left */
	sc->ledger.resident = 12345;
	sc->obj.open.broken = 3;
	sc->obj.open.stop = 1;
	memset(&o, 0, sizeof o);
	kof_scan_budget(sc, 10, &o);
	CK(sc->ledger.resident == 0 && sc->obj.open.broken == 0 && sc->obj.open.stop == 0, "a new budget clears resident, broken and stop");
}

static void t_idempotent(kof_scanner *sc)
{
	unsigned i;

	for (i = 0; i < 3; i++) {
		kof_scan_kids_reset(sc);
		kof_scan_sink_discard(sc);
	}
	CK(sc->child.n == 0 && sc->sink.len == 0 && sc->sink.spilled == 0 && sc->sink.fd < 0 && sc->sink.mem == NULL,
	   "reset and discard on a scanner that holds nothing leave it holding nothing, however often");
}

static void t_prod(kof_scanner *sc)
{
	unsigned p;
	const char *seen[KOF_PROD_COUNT];

	for (p = 0; p < KOF_PROD_COUNT; p++) {
		unsigned q;

		seen[p] = kof_prod_name((enum kof_prodkind)p);
		CK(seen[p] && seen[p][0] && strcmp(seen[p], "?") != 0, "product %u has a name", p);
		for (q = 0; q < p; q++)
			CK(strcmp(seen[p], seen[q]) != 0, "products %u and %u have different names", q, p);
	}
	CK(strcmp(kof_prod_name(KOF_PROD_COUNT), "?") == 0 && strcmp(kof_prod_name((enum kof_prodkind)0xffff), "?") == 0, "past the products: ?");

	memset(sc->obj.prod_runs, 0, sizeof sc->obj.prod_runs);
	memset(sc->prod_repeat, 0, sizeof sc->prod_repeat);
	kof_prod_ran(sc, KOF_PROD_SYMS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 0, "the first run of a product is not a repeat");
	kof_prod_ran(sc, KOF_PROD_SYMS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_SYMS) == 1, "the second is");
	kof_prod_ran(sc, KOF_PROD_FUNCS);
	kof_prod_again(sc, KOF_PROD_FUNCS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_FUNCS) == 0 && sc->obj.prod_runs[KOF_PROD_FUNCS] == 2,
	   "a second run announced with `again` is counted as a run and not as a repeat: it is the one allowed second run");
	kof_prod_ran(sc, KOF_PROD_FUNCS);
	CK(kof_scan_prod_repeats(sc, KOF_PROD_FUNCS) == 1, "and a third is a repeat");
	for (p = 0; p < 300; p++)
		kof_prod_ran(sc, KOF_PROD_USE);
	CK(sc->obj.prod_runs[KOF_PROD_USE] == 255u, "the per-object count saturates at 255 and does not wrap to 0");
	CK(kof_scan_prod_repeats(sc, KOF_PROD_USE) == 299u, "repeats keep counting");
	CK(kof_scan_prod_repeats(NULL, KOF_PROD_SYMS) == 0 && kof_scan_prod_repeats(sc, KOF_PROD_COUNT) == 0, "NULL scanner, product out of range");
	for (p = 0; p < 300; p++)
		kof_prod_again(sc, KOF_PROD_RELOCS);
	CK(sc->obj.prod_runs[KOF_PROD_RELOCS] == 255u, "again saturates too");
}

static void t_attach(kof_scanner *sc)
{
	struct kof_obj_ctx ctx;
	const struct kof_content *det, *unp;

	memset(&ctx, 0, sizeof ctx);
	kof_mod_attach(&ctx, sc);
	CK(ctx.priv == (void *)sc && kof_scan_of(&ctx) == sc, "attach binds the context to the scanner");
	CK(ctx.content != NULL && ctx.report != NULL && ctx.debug != NULL, "and gives it the vtable, the report and the note channel");
	det = ctx.content;
	CK(det->rd8 && det->rd16 && det->rd32 && det->rd64 && det->memeq && det->csum && det->find_str && det->find_str_at && det->find_str_in &&
	   det->find_str_where, "a detector can read and search");
	CK(!det->emit && !det->child && !det->unpack && !det->window && !det->child_format && !det->produced_poke,
	   "and cannot make an object: every producing slot is NULL in a detector's table (the macros answer 0)");
	kof_mod_unpack_mode(&ctx, 1);
	unp = ctx.content;
	CK(unp != det && unp->emit && unp->child && unp->unpack && unp->window && unp->produced_read && unp->produced_poke,
	   "unpack mode swaps in a table that can");
	CK(unp->rd8 && unp->memeq && unp->find_str_at, "and still reads");
	kof_mod_unpack_mode(&ctx, 0);
	CK(ctx.content == det, "and back");
	kof_mod_unpack_mode(&ctx, 1);
	kof_mod_unpack_mode(&ctx, 1);
	CK(ctx.content == unp, "switching to the same mode twice is a no-op");
	kof_mod_attach(&ctx, sc);
	CK(ctx.content == det, "attach resets to the detector's table");
}

/*
 * kof_scan_trim / kscan_trim: what a scanner keeps between objects, given back on request. Never while a scan
 * is running on it (busy), idempotent (a second call finds nothing and is not counted), counted only when it
 * found something to give back, and a flag of 0 means both.
 */
static void t_trim(kof_scanner *sc)
{
	uint64_t n0;

	CK(KOF_TRIM_CACHES == KSCAN_TRIM_CACHES && KOF_TRIM_HEAP == KSCAN_TRIM_HEAP && KOF_TRIM_CACHES != KOF_TRIM_HEAP &&
	   !(KOF_TRIM_CACHES & KOF_TRIM_HEAP), "the engine's flags are the public ones, and two distinct bits");
	kof_scan_trim(NULL, KOF_TRIM_CACHES);           /* no scanner: nothing to do, nothing to fault on */
	kscan_trim(NULL, 0);

	kof_scan_trim(sc, KOF_TRIM_CACHES);
	n0 = kscan_stats(sc)->scan_trims;
	sc->cache.inf = malloc(sizeof *sc->cache.inf);
	CK(sc->cache.inf != NULL, "a cache to give back");
	sc->busy = 1;
	kof_scan_trim(sc, KOF_TRIM_CACHES | KOF_TRIM_HEAP);
	CK(sc->cache.inf != NULL && kscan_stats(sc)->scan_trims == n0, "while a scan is running on the scanner nothing is touched or counted");
	sc->busy = 0;
	kof_scan_trim(sc, KOF_TRIM_CACHES);
	CK(sc->cache.inf == NULL && kscan_stats(sc)->scan_trims == n0 + 1u, "between scans the cache goes, and the trim is counted once");
	kof_scan_trim(sc, KOF_TRIM_CACHES);
	CK(kscan_stats(sc)->scan_trims == n0 + 1u, "a second trim has nothing to give back and is not counted");
	kof_scan_trim(sc, KOF_TRIM_HEAP);
	CK(kscan_stats(sc)->scan_trims == n0 + 1u + (kof_heap_trim() ? 1u : 0u), "the heap flag alone is counted when the C library took it");
	n0 = kscan_stats(sc)->scan_trims;
	sc->cache.lzw = malloc(sizeof *sc->cache.lzw);
	kof_scan_trim(sc, 0);
	CK(sc->cache.lzw == NULL && kscan_stats(sc)->scan_trims > n0, "a flag of 0 is both");
	kscan_trim(sc, KSCAN_TRIM_CACHES);
	CK(kscan_stats(sc)->scan_trims >= n0, "the public call is the same");
}

static void t_direct_calls(kof_engine *e)
{
	static uint8_t buf[200];
	kof_scanner *a, *b;
	kof_scanner *two[2];
	struct kof_scan_option o = he_opt();
	struct he_tally t;

	/* Each scanner reserves its fixed cost from the engine memory budget (kofbudget.h) and
	 * kscan_new answers NULL when it cannot be afforded. Two fit under the default 512 MiB cap
	 * (scan_share.c makes them, and six, at it); the cap is raised here only so that nothing
	 * this test asserts about the walk depends on how the share of a scanner is cut. */
	CK(keng_set_memory_cap(e, 4ull << 30) != 0, "raise the memory cap so two scanners fit");
	a = kscan_new(e);
	b = kscan_new(e);
	if (!a || !b) {
		CK(0, "scanners");
		kscan_free(a);
		kscan_free(b);
		return;
	}
	memset(buf, 'A', sizeof buf);
	memset(&t, 0, sizeof t);
	CK(kof_scan_bytes(a, buf, sizeof buf, "direct", &o, he_on_object, &t) == 1 && t.objects == 1, "kof_scan_bytes is what kscan_bytes calls");
	CK(kof_scan_bytes(a, buf, 0, "direct", &o, NULL, NULL) == KOF_ERR_ARG && kof_scan_bytes(NULL, buf, 1, "x", &o, NULL, NULL) == KOF_ERR_ARG,
	   "and it refuses the same arguments");
	CK(kof_scan_stats(a) == kscan_stats(a) && kof_scan_stats(a)->objects == 1, "kof_scan_stats is the same table");
	two[0] = a;
	two[1] = b;
	CK(kof_scan_walk_mt(two, 2, "build/test/definitely-missing", &o, NULL, NULL) == KOF_ERR_OPEN, "kof_scan_walk_mt on a missing path");
	CK(kof_scan_walk_mt(two, 1, HE_DB, &o, NULL, NULL) >= 0, "kof_scan_walk_mt with one scanner is the serial walk");
	CK(kof_scan_walk(a, "build/test/definitely-missing", &o, NULL, NULL) == KOF_ERR_OPEN, "kof_scan_walk on a missing path");
	kof_scan_free(a);
	kof_scan_free(NULL);
	/* kof_scan_new(NULL) is not asked: the public kscan_new is the one that refuses NULL */
	kscan_free(b);
}

int main(void)
{
	kof_engine *e = keng_open(HE_DB);
	kof_scanner *sc;

	if (!e) {
		printf("api_engine_scanint: no database - nothing tested\n");
		return 0;
	}
	sc = kscan_new(e);
	if (!sc) {
		printf("api_engine_scanint: no scanner\n");
		keng_close(e);
		return 1;
	}
	t_budget(sc);
	t_idempotent(sc);
	t_prod(sc);
	t_attach(sc);
	t_trim(sc);
	t_direct_calls(e);
	kscan_free(sc);
	keng_close(e);
	printf("api_engine_scanint: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
