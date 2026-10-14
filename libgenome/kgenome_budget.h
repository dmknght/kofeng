#ifndef KGENOME_BUDGET_H
#define KGENOME_BUDGET_H

/*
 * kgenome_budget.h - WHAT A CALL MAY COST, supplied by the caller.
 *
 * A lib never reads engine state to find out how much it may spend (CLAUDE.md
 * section 12). The caller says, in this struct, and the lib bounds ITS WORK by it.
 * Two properties are what make that the right shape:
 *
 *   EVERY LIMIT IS A FUNCTION OF THE INPUT. A fixed constant is right for one
 *   object size and wrong for every other: 4096 nodes was past the largest object
 *   of the sample set and then one 7.7 MB binary filled it. kgenome_budget_default
 *   derives each limit from the object's size and its code size, so a bigger
 *   object may hold bigger products and a small one stays as cheap as it was.
 *
 *   THE CALLER'S BUDGET IS THE DoS BOUND. The scaled limits only say how much
 *   work an honest object of that size needs. What stops a hostile one is
 *   max_bytes, max_insn and max_steps, which the caller sets from what it can
 *   afford for the whole scan; when one is exhausted the call stops, keeps what
 *   it has, and says KGENOME_OVER_BUDGET (kgenome_status.h) - "cannot say", not
 *   "nothing found".
 *
 * ZERO MEANS "NOT SET, USE THE DEFAULT FOR THIS OBJECT" in every field except
 * deadline_ms, where zero means no clock. A caller that only knows the object
 * fills obj_size and code_bytes and calls kgenome_budget_default; a caller with
 * a global allowance overrides max_bytes afterwards.
 */

#include <stddef.h>
#include <stdint.h>

#include "kgenome_status.h"

struct kgenome_budget {
	/* ---- what the object is: hints the defaults are scaled from ---------- */
	uint64_t obj_size;      /* the object's size in bytes                        */
	uint64_t code_bytes;    /* its executable bytes; 0 = obj_size                */
	/* ---- what the caller allows: the DoS bound --------------------------- */
	uint64_t max_bytes;     /* resident bytes for everything this call builds    */
	uint64_t max_insn;      /* emulated instructions of one run                  */
	uint64_t max_insn_resolve; /* ...of the PE API-resolver run, which stops when
	                         * the program goes silent - see KGENOME_RESOLVE_MIN */
	uint64_t max_steps;     /* analysis steps of the wrapper walk, whole object  */
	uint32_t deadline_ms;   /* wall clock of one emulator run (0 = none), applied
	                         * through kgenome_emu_set_deadline                  */
	/* ---- what an honest object of this size needs: scaled ---------------- */
	uint32_t max_nodes;     /* nodes of the diagnose graph                       */
	uint32_t max_names;     /* distinct names kept                               */
	/*
	 * THE CALLER'S MEMORY ACCOUNT FOR THE EMULATOR (kgenome_emu_cfg.account), for the
	 * entry points that build one from a budget (the unpack runs). Asked for bytes
	 * before they are taken, told (a negative delta) what is given back. NULL
	 * accounts nothing. APPENDED: a caller that zeroes the struct gets no account.
	 */
	int      (*account)(void *user, int64_t bytes);
	void      *account_user;
	/*
	 * THE CALLER'S ACCOUNT OF EMULATED INSTRUCTIONS. When set, every emulator this
	 * call builds adds the instructions it executed to `*insn_spent` as it is freed,
	 * so a caller that holds ONE allowance for many calls (the engine: a whole tree of
	 * objects) reads what a call cost without the lib knowing the allowance. A run's
	 * own limit stays max_insn / max_insn_resolve; the caller sets those to what its
	 * allowance has left. APPENDED: a zeroed struct accounts nothing.
	 */
	uint64_t  *insn_spent;
};

/*
 * THE NODE AND NAME INDEXES ARE 16 BITS - in a hit's links, in the origin map,
 * in the name table - and 0xffff and 0xfffe are the words "none" and "stack". So
 * 65534 is the most nodes or names an object can hold, a width and not a cost
 * bound: reaching it sets KGENOME_TRUNCATED like any other limit.
 */
#define KGENOME_MAX_INDEX 0xfffeu

/* The floors: what an object of any size may always hold. They are the old
 * constants, so a small object behaves exactly as before. */
#define KGENOME_NODES_MIN 4096u
#define KGENOME_NAMES_MIN 1024u
#define KGENOME_INSN_MIN  2000000ull
/*
 * THE PE RESOLVER'S FLOOR - its own number, because it is its own kind of run.
 * The emulate route runs a whole program and a program that spins runs to its
 * budget (a bot's idle loop: MEASURED, a 3.5x cost on one Mirai sample when the
 * floor and the stall stop were lifted), so that budget is a cost the floor sets
 * for every small object. The resolver runs only until the program stops calling
 * the API it is resolving (the silence window, an eighth of this), so a larger
 * budget costs only the runs that keep making calls. 4M instructions: a stager
 * that waits before it acts - a busy loop is the cheapest anti-analysis there is,
 * and a PE that makes a call every 140000 instructions for sixteen calls is not
 * a function of its size - is not stopped at 2.2M of waiting.
 */
#define KGENOME_RESOLVE_MIN 4000000ull

/*
 * THE SCALING, measured. Nodes: one per 8 bytes of code is far above anything
 * seen (the largest object of the sample set made 701 nodes from 1.1 MB, one per
 * 1500 bytes), and costs nothing until nodes exist. Instructions: 64 per code
 * byte is the order the unpackers measured for the cheapest decompressors (NRV
 * ~57 per input byte), so a run that is the size of the code is allowed to touch
 * all of it a few dozen times. Steps: the wrapper walk's whole-object budget.
 */
static inline uint64_t kgenome_budget_sat_mul(uint64_t a, uint64_t b)
{
	return b && a > UINT64_MAX / b ? UINT64_MAX : a * b;
}

/*
 * Fill `b` with defaults scaled to an object of `obj_size` bytes of which
 * `code_bytes` are executable (0: unknown, the object size is used). Every
 * default is non-decreasing in both arguments - tests/unit/kgenome_budget.c holds
 * that - and the floors above are what a small object gets.
 */
static inline void kgenome_budget_default(struct kgenome_budget *b, uint64_t obj_size,
					  uint64_t code_bytes)
{
	uint64_t code = code_bytes ? code_bytes : obj_size;
	uint64_t n;

	b->obj_size = obj_size;
	b->code_bytes = code;
	b->deadline_ms = 0;
	b->account = NULL;
	b->account_user = NULL;
	b->insn_spent = NULL;
	n = code / 8u;
	b->max_nodes = n < KGENOME_NODES_MIN ? KGENOME_NODES_MIN
		     : n > KGENOME_MAX_INDEX ? KGENOME_MAX_INDEX : (uint32_t)n;
	b->max_names = b->max_nodes > KGENOME_NAMES_MIN ? b->max_nodes : KGENOME_NAMES_MIN;
	n = kgenome_budget_sat_mul(code, 64u);
	b->max_insn = n < KGENOME_INSN_MIN ? KGENOME_INSN_MIN : n;
	b->max_insn_resolve = n < KGENOME_RESOLVE_MIN ? KGENOME_RESOLVE_MIN : n;
	n = kgenome_budget_sat_mul(code, 64u);
	b->max_steps = n < (1ull << 20) ? (1ull << 20) : n;
	/* 256 MiB of room plus 64 bytes per input byte: the products of the largest
	 * object measured are tens of MiB, and the caller replaces this with what it
	 * can afford. */
	n = kgenome_budget_sat_mul(obj_size, 64u);
	b->max_bytes = n > UINT64_MAX - (256ull << 20) ? UINT64_MAX : n + (256ull << 20);
}

/*
 * THE ACCOUNTING: a ledger the lib charges as it allocates a big product, and
 * that refuses once the allowance is spent.
 *
 * WHY A LEDGER AND NOT AN ALLOCATOR CALLBACK - the two ways to make memory the
 * caller's business, and this is the one chosen:
 *
 *   An allocator callback (malloc/realloc/free supplied by the caller) lets the
 *   caller see every byte, but the lib then cannot decide what refusal MEANS:
 *   the callback returns NULL in the middle of growing a table, and the lib's
 *   only honest answer is the one it already has for a failed malloc. It also
 *   puts an indirect call on every allocation, makes every product's free path
 *   depend on the caller's allocator staying alive, and needs a second callback
 *   for the arrays that realloc.
 *   A ledger keeps allocation where it is and moves only the DECISION: charge(n)
 *   before the allocation, release(n) with the free. A refusal is known at the
 *   one place that can react to it - keep the partial result, stop growing, set
 *   KGENOME_OVER_BUDGET - and the caller reads the total back (used/peak) to
 *   charge its own scan. Nothing about it needs the caller after the call returns.
 *
 * The ledger is the lib's, one per scan, and not thread-shared: a lib is safe on
 * many threads because every thread has its own scan and its own ledger.
 */
struct kgenome_ledger {
	uint64_t used, peak;    /* bytes charged now, and the most there ever was */
	uint64_t limit;         /* the allowance; zero (a zeroed struct) is none  */
	enum kgenome_status status;     /* worst status noted so far              */
};

static inline void kgenome_ledger_init(struct kgenome_ledger *l, uint64_t limit)
{
	l->used = l->peak = 0;
	l->limit = limit;
	l->status = KGENOME_OK;
}

/* Bytes still available: UINT64_MAX when there is no allowance. */
static inline uint64_t kgenome_ledger_room(const struct kgenome_ledger *l)
{
	if (!l->limit)
		return UINT64_MAX;
	return l->used < l->limit ? l->limit - l->used : 0;
}

/* Note a status on the ledger (the worse of it and what is there). */
static inline void kgenome_ledger_note(struct kgenome_ledger *l, enum kgenome_status s)
{
	l->status = kgenome_status_merge(l->status, s);
}

/* Charge `n` bytes. 1 when the allowance holds; 0 when it would be exceeded -
 * nothing is charged, the ledger says KGENOME_OVER_BUDGET, and the caller keeps
 * what it already has and does not allocate. */
static inline int kgenome_ledger_charge(struct kgenome_ledger *l, uint64_t n)
{
	if (n > kgenome_ledger_room(l)) {
		kgenome_ledger_note(l, KGENOME_OVER_BUDGET);
		return 0;
	}
	l->used += n;
	if (l->used > l->peak)
		l->peak = l->used;
	return 1;
}

/*
 * The SOFT charge, for a CACHE: the same accounting, but a refusal does not note
 * KGENOME_OVER_BUDGET, because a cache that is not kept only costs time (the
 * decode trace: the code is decoded again) and the answer is the same either way.
 * Marking that as a limit on the answer would be the opposite lie to a silent
 * cap. 1 when charged; 0 when refused (nothing charged, nothing noted).
 */
static inline int kgenome_ledger_try(struct kgenome_ledger *l, uint64_t n)
{
	if (n > kgenome_ledger_room(l))
		return 0;
	l->used += n;
	if (l->used > l->peak)
		l->peak = l->used;
	return 1;
}

/* Give bytes back (a product freed, or a table replaced by a bigger one).
 * Saturates: a mispaired release cannot wrap the count and refuse everything. */
static inline void kgenome_ledger_release(struct kgenome_ledger *l, uint64_t n)
{
	l->used = n > l->used ? 0 : l->used - n;
}

#endif /* KGENOME_BUDGET_H */
