/*
 * kofbudget.h - THE ENGINE'S MEMORY BUDGET, the root every other ledger hangs from.
 *
 * THE MODEL (CLAUDE.md section 12, "Memory"): the whole engine - the database it loaded, every
 * scanner of every job, the buffers, the emulator, the views, the spill-to-memory fallback -
 * stays under ONE number, 512 MiB by default (KOF_ENGINE_MEM_CAP), which a host may change
 * (keng_set_memory_cap) but never remove: zero means the default, not "no limit".
 *
 *   1. The database is charged FIRST, at load (what it holds in private memory: its index,
 *      its filters, its tables - not the record payloads, which stay in the read-only pack
 *      that is mapped and touched on demand).
 *   2. Each scanner reserves its FIXED cost when it is made (its struct, the parsed views, the
 *      decompressor states, the DB-sized tables it keeps per thread). A scanner the budget
 *      cannot afford is not made: kscan_new answers NULL.
 *   3. When a scanner starts an object it takes its SHARE of what is left, (cap - database) /
 *      scanners alive, minus its fixed cost and its presence table, charges it here and gives
 *      it back when the object ends. That share is the scanner's resident ceiling
 *      (struct kof_scan_ledger.resident_max): everything produced, decoded, emulated or copied
 *      for the object is charged to THAT, so the sum over scanners cannot pass the cap.
 *   4. What does not fit degrades in a fixed order, each step reported and none of them
 *      silent: caches shrink (the decode trace follows a quarter of the share, the presence
 *      table follows an eighth), copies become borrows (the emulator's image pages), optional
 *      products are skipped with a status (the normalised view, the emulate route: the object is
 *      marked incomplete, KOF_BROKEN_LIMIT / limit_hits), and the object is refused last.
 *
 * FOR A BUILDER OF A BIG TABLE (the matcher index): ask before you allocate -
 *
 *     granted = kof_budget_ask(b, fast_layout_bytes);
 *     if (granted < fast_layout_bytes) use the compact layout and say so;
 *     if (!kof_budget_charge(b, bytes_chosen)) refuse the rule set, loudly;
 *
 * `ask` answers how much MAY be used now (never more than is left), `charge` takes it for good
 * (until `release`), and the answer is atomic: scanners on other threads take theirs at the
 * same time.
 */

#ifndef KOFENG_KOFBUDGET_H
#define KOFENG_KOFBUDGET_H

#include <stdint.h>
#include <stdatomic.h>

#define KOF_ENGINE_MEM_CAP (512ull << 20)
/* The smallest cap a host may set: below it not even one scanner and a small object fit. */
#define KOF_ENGINE_MEM_MIN (16ull << 20)

struct kof_budget {
	uint64_t cap;                    /* the ceiling; never zero */
	_Atomic uint64_t used;           /* charged now */
	_Atomic uint64_t peak;           /* the most that was ever charged */
	_Atomic uint32_t holders;        /* scanners alive: what the share is divided by */
	uint64_t db;                     /* what the database holds privately (part of `used`) */
};

static inline void kof_budget_init(struct kof_budget *b, uint64_t cap)
{
	b->cap = cap ? cap : KOF_ENGINE_MEM_CAP;
	atomic_store(&b->used, 0);
	atomic_store(&b->peak, 0);
	atomic_store(&b->holders, 0);
	b->db = 0;
}

/* Bytes that may still be taken. */
static inline uint64_t kof_budget_room(const struct kof_budget *b)
{
	uint64_t u = atomic_load(&b->used);

	return u < b->cap ? b->cap - u : 0;
}

/* How much of `want` may be used right now; takes nothing. */
static inline uint64_t kof_budget_ask(const struct kof_budget *b, uint64_t want)
{
	uint64_t r = kof_budget_room(b);

	return want < r ? want : r;
}

/* Take `n`, all or nothing. 1 when it was taken. */
static inline int kof_budget_charge(struct kof_budget *b, uint64_t n)
{
	uint64_t u = atomic_load(&b->used), p;

	do {
		if (n > b->cap || u > b->cap - n)
			return 0;
	} while (!atomic_compare_exchange_weak(&b->used, &u, u + n));
	p = atomic_load(&b->peak);
	while (u + n > p && !atomic_compare_exchange_weak(&b->peak, &p, u + n))
		;
	return 1;
}

/* Give back; saturates, so a mispaired release cannot wrap the count. */
static inline void kof_budget_release(struct kof_budget *b, uint64_t n)
{
	uint64_t u = atomic_load(&b->used);

	while (!atomic_compare_exchange_weak(&b->used, &u, n > u ? 0 : u - n))
		;
}

#endif /* KOFENG_KOFBUDGET_H */
