/*
 * mem_cap - the engine-level memory budget (kofcore/kofbudget.h): one number for the whole engine,
 * 512 MiB by default, the root every scanner's ceiling hangs from.
 *
 *   THE API          ask / charge / release are atomic and exact: threads hammering one budget never
 *                    take more than its cap, and a mispaired release cannot wrap it.
 *   THE CAP          default 512 MiB, never zero, refused below what is held, zero restores the default.
 *   SCANNERS         each reserves its fixed cost when made; one the budget cannot afford is not made
 *                    (kscan_new answers NULL), and the reservation comes back when it is freed.
 *   THE SHARE        what a scanner may hold for an object is (cap - database) / scanners alive, less its
 *                    fixed cost and its presence table; the shares taken at once never pass the cap, and
 *                    they are given back when the object ends.
 *   THE STRESS       four scanners on four threads scanning 24 MB objects under a cap too small to hold
 *                    their views: nothing passes the cap (the ledgers' peaks and the engine's own peak),
 *                    and what was given up is SAID - the objects come back incomplete, not clean.
 */

#define _GNU_SOURCE
#include "caps_fix.h"
#include "caps_e2e.h"
#pragma GCC diagnostic ignored "-Wunused-function"
#include "mem_fix.h"
#include "../../libkofeng/kofcore/kofbudget.h"
#include "../../libkofeng/databases/pack/dbtables.h"

static kof_engine *eng;         /* this test's own: no other scanner holds a reservation on it */
static uint8_t code[1u << 16];
static uint8_t big[26u << 20];

static struct kof_budget hb;

static void *hammer(void *p)
{
	unsigned i, mine = 0;
	uint64_t held[16] = { 0 };

	(void)p;
	for (i = 0; i < 200000u; i++) {
		unsigned k = i % 16u;

		if (held[k] && (i & 1u)) {
			kof_budget_release(&hb, held[k]);
			held[k] = 0;
			mine--;
		} else if (!held[k]) {
			uint64_t n = 1000u + (i % 7u) * 100u;

			if (kof_budget_charge(&hb, n)) {
				held[k] = n;
				mine++;
			}
		}
		if (atomic_load(&hb.used) > hb.cap)
			__atomic_store_n(&fails, fails + 1, __ATOMIC_RELAXED);
	}
	for (i = 0; i < 16u; i++)
		if (held[i])
			kof_budget_release(&hb, held[i]);
	return NULL;
}

static void api(void)
{
	pthread_t id[4];
	unsigned i;

	kof_budget_init(&hb, 0);
	CK(hb.cap == KOF_ENGINE_MEM_CAP);                       /* zero is the default, not "no limit" */
	kof_budget_init(&hb, 100000u);
	CK(kof_budget_ask(&hb, 60000u) == 60000u);
	CK(kof_budget_charge(&hb, 60000u));
	CK(kof_budget_ask(&hb, 60000u) == 40000u);              /* how much MAY be used, never more than is left */
	CK(!kof_budget_charge(&hb, 40001u));                    /* all or nothing */
	CK(atomic_load(&hb.used) == 60000u);
	CK(kof_budget_charge(&hb, 40000u));
	CK(kof_budget_room(&hb) == 0);
	kof_budget_release(&hb, 1000000u);                      /* mispaired: saturates */
	CK(atomic_load(&hb.used) == 0);
	CK(atomic_load(&hb.peak) == 100000u);
	kof_budget_init(&hb, 1u << 20);
	for (i = 0; i < 4u; i++)
		pthread_create(&id[i], NULL, hammer, NULL);
	for (i = 0; i < 4u; i++)
		pthread_join(id[i], NULL);
	CK(atomic_load(&hb.used) == 0);
	CK(atomic_load(&hb.peak) <= hb.cap);
}

static void cap_and_scanners(void)
{
	uint64_t fixed = kof_scan_fixed(eng), db = keng_memory_db(eng);
	kof_scanner *a, *b, *c;

	CK(keng_memory_cap(eng) == KOF_ENGINE_MEM_CAP);
	CK(db < KOF_ENGINE_MEM_CAP);
	CK(!keng_set_memory_cap(eng, 1));                   /* below the least that works */
	CK(keng_memory_cap(eng) == KOF_ENGINE_MEM_CAP);
	CK(keng_set_memory_cap(eng, db + fixed * 5u / 2u));
	a = kscan_new(eng);
	b = kscan_new(eng);
	c = kscan_new(eng);
	CK(a && b && !c);                                       /* the third cannot be afforded */
	CK(atomic_load(&eng->budget->used) == db + 2u * fixed);
	kscan_free(a);
	c = kscan_new(eng);
	CK(c != NULL);                                          /* its reservation came back */
	kscan_free(b);
	kscan_free(c);
	CK(atomic_load(&eng->budget->used) == db);
	CK(keng_set_memory_cap(eng, 0));
	CK(keng_memory_cap(eng) == KOF_ENGINE_MEM_CAP);
}

static void shares(void)
{
	uint64_t db = keng_memory_db(eng), fixed = kof_scan_fixed(eng);
	kof_scanner *s[4];
	struct kof_scan_option opt;
	unsigned i;
	uint64_t held = 0, fair;

	memset(&opt, 0, sizeof opt);
	opt.max_resident_bytes = 1ull << 40;                    /* the caller asks for far more than there is */
	for (i = 0; i < 4u; i++)
		s[i] = kscan_new(eng);
	fair = (KOF_ENGINE_MEM_CAP - db) / 4u;
	for (i = 0; i < 4u; i++) {
		CK(s[i] != NULL);
		kof_scan_budget(s[i], 1000, &opt);
		/* never above what a quarter of the engine allows, whatever the caller asked */
		CK(s[i]->ledger.resident_max <= fair - fixed);
		CK(s[i]->ledger.resident_max > (fair - fixed) / 2u);
		held += s[i]->root_held;
		CK(s[i]->match.m.gram_bits >= 12u && s[i]->match.m.gram_bits <= 24u);
	}
	CK(atomic_load(&eng->budget->used) == db + 4u * fixed + held);
	CK(atomic_load(&eng->budget->used) <= KOF_ENGINE_MEM_CAP);
	for (i = 0; i < 4u; i++)
		kof_scan_root_release(s[i]);                    /* the object ended */
	CK(atomic_load(&eng->budget->used) == db + 4u * fixed);
	for (i = 0; i < 4u; i++)
		kscan_free(s[i]);
	CK(atomic_load(&eng->budget->used) == db);
}

struct th { kof_scanner *sc; uint64_t peak; unsigned incomplete, runs; };

static void *th_main(void *p)
{
	struct th *t = p;
	struct kof_scan_option opt;
	unsigned i;

	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.max_produced_bytes = 1ull << 40;
	opt.max_object_bytes = 64u << 20;
	for (i = 0; i < 3u; i++) {
		struct e2e r;
		struct mf_sig s;

		memset(&r, 0, sizeof r);
		(void)kscan_bytes(t->sc, big, 24u << 20, "big", &opt, e2e_on_object, &r);
		mf_sig_of(&r, &s);
		t->incomplete += s.incomplete > 0;
		t->runs++;
	}
	t->peak = kscan_stats(t->sc)->peak_resident;
	return NULL;
}

static void stress(void)
{
	/* 128 MiB for the whole engine, four scanners, 24 MB objects whose view needs 48 MB each */
	uint64_t db = keng_memory_db(eng), total = 0;
	struct th t[4];
	pthread_t id[4];
	unsigned i, inc = 0;

	CK(keng_set_memory_cap(eng, db + (128ull << 20)));
	atomic_store(&eng->budget->peak, atomic_load(&eng->budget->used));   /* this phase's own peak */
	(void)mf_view_elf(big, 24u << 20, code);
	for (i = 0; i < 4u; i++) {
		memset(&t[i], 0, sizeof t[i]);
		t[i].sc = kscan_new(eng);
		CK(t[i].sc != NULL);
	}
	for (i = 0; i < 4u; i++)
		pthread_create(&id[i], NULL, th_main, &t[i]);
	for (i = 0; i < 4u; i++) {
		pthread_join(id[i], NULL);
		total += t[i].peak;
		inc += t[i].incomplete;
		CK(t[i].runs == 3u);
	}
	printf("    cap %llu MiB: ledgers' peaks %.1f MiB together, engine peak %.1f MiB, %u of 12 scans incomplete\n",
	       (unsigned long long)(keng_memory_cap(eng) >> 20), (double)total / 1048576.0,
	       (double)keng_memory_peak(eng) / 1048576.0, inc);
	CK(total <= keng_memory_cap(eng));
	CK(keng_memory_peak(eng) <= keng_memory_cap(eng));
	CK(inc > 0);                                            /* the view did not fit: said, not clean */
	for (i = 0; i < 4u; i++)
		kscan_free(t[i].sc);
	CK(atomic_load(&eng->budget->used) == db);
	CK(keng_set_memory_cap(eng, 0));
}

int main(int argc, char **argv)
{
	eng = keng_open(argc > 1 ? argv[1] : "build/test/databases-sigs");
	if (!eng) {
		printf("mem cap: no database\n");
		return 1;
	}
	api();
	cap_and_scanners();
	shares();
	stress();
	printf("mem cap: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
