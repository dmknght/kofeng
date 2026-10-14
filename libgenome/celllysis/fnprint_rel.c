/*
 * fnprint_rel.c - the relevance of one function: AUTHOR, LIB or UNKNOWN, and why.
 *
 * THE RELEVANCE RULES (kgenome_fnprint_decide), in the order they are tried, and what each
 * cannot do - written down because a rule's blind spot is the failure it
 * produces. They compute the LEGACY class; kgenome_fnprint_advise turns every LIB that is not
 * grounded in the function's own bytes (R_LIBDB, R_LIBWIN) into advice (UNKNOWN, kept) unless
 * OPT_LEGACY_EXCLUDE asks for the old behaviour, and the name is read only in that mode:
 *   1. a bogus extent is UNKNOWN, weight 0, no fingerprint (never silently
 *      dropped: it is in the stat);
 *   2. the entry function is LIB (startup);
 *   3. MAIN, the function the entry stub hands to the runtime, is AUTHOR by
 *      construction (a name that says library wins);
 *   4. a LIBRARY SIGNAL - a name the caller's vocabulary calls library, a
 *      fingerprint in the caller's known-library table, or a syscall wrapper
 *      (small, holds a kernel entry) - is LIB. In a STATIC object the third
 *      such signal after `main` latches the FRONTIER;
 *   5. a thunk is LIB: a few instructions, no call, ending in a jump. A tiny
 *      function ending in `ret` is a thunk only where the ABI has get-pc thunks
 *      (32-bit x86); on x86-64 it is an accessor or a handler;
 *   6. a name the vocabulary calls the author's is AUTHOR;
 *   7. otherwise by link kind. DYNAMIC: AUTHOR (the libraries are not in the
 *      file), provisionally. STATIC: UNKNOWN when the entry stub named no main;
 *      LIB before the entry (PRE_ENTRY: the libraries' cold parts and start-up
 *      groups come first in a gcc/ld link, main excepted); LIB at and behind the
 *      function the entry stub calls last (LIB_START: __libc_start_main) and
 *      behind the frontier (BEYOND); AUTHOR in between, provisionally.
 *   The AUTHOR of the last two is provisional because a pass in address order
 *   cannot know who calls whom: the held stretch is decided by reachability from
 *   main (fnprint_reach.c), which turns the crt helpers and libc-start's helpers,
 *   that the layout cannot tell from the program's own code, into LIB.
 *   A static object that never latches (stat.frontier_off == KGENOME_BROKEN) has
 *   AUTHOR labels nothing bounds, and says so there.
 * BLIND SPOTS: author code placed after the first library code (the frontier is
 * a layout assumption: the linker puts the program's objects before the
 * archives); an author function that holds a raw kernel entry is a "wrapper";
 * main handed to the runtime in a way the entry probe does not read; a function
 * only a data table names, and an author cold part before the entry (see the
 * known misses in tests/lib/genome/fnprint_gcc.c).
 */
#include "fnprint_private.h"

#include <stdlib.h>
#include <string.h>

void kgenome_fnprint_opts_resolve(struct kgenome_fnprint_opts *o)
{
	if (!o->tiny_insn) o->tiny_insn = 6;
	if (!o->huge_len) o->huge_len = 1ull << 20;
	if (!o->wcap) o->wcap = 256;
	if (!o->w_author) o->w_author = 100;
	if (!o->w_unknown) o->w_unknown = 25;
	if (!o->seeds_latch) o->seeds_latch = 3;
	if (!o->wrapper_insn) o->wrapper_insn = 48;
	if (!o->thunk_insn) o->thunk_insn = 3;
	if (!o->region_max) o->region_max = 262144u;
	if (!o->libwin_pct) o->libwin_pct = 60;
	if (!o->libwin_min) o->libwin_min = 8;
	if (!o->w_advised) o->w_advised = 25;
}

/*
 * WHAT MAY TAKE A FUNCTION OUT OF THE EVIDENCE. A function is LIB (and weighs nothing as author
 * code) only on the grounds of its own bytes: its fingerprint is in the library table (R_LIBDB) or
 * most of its windows are in the library window table (R_LIBWIN, whose residual - the windows that are
 * not in the table - still weighs as author code, so a payload inside a library function is kept).
 * A name, the layout, the entry stub, a wrapper's shape, a thunk's size are things an author can
 * change without touching the function: they are ADVICE (f->advice, R_ADVISED), the function stays
 * UNKNOWN, kept, and weighed at w_advised. OPT_LEGACY_EXCLUDE restores the old rule for the
 * measurements that need it.
 */
void kgenome_fnprint_advise(const struct kgenome_fnprint_opts *o, struct kgenome_fnprint_fn *f)
{
	int dead = (f->reason & (KGENOME_FNP_R_TINY | KGENOME_FNP_R_UNDECODED | KGENOME_FNP_R_OVERLAP)) != 0;

	f->advice = f->cls;
	if (f->cls != KGENOME_FNP_LIB || (o->flags & KGENOME_FNP_OPT_LEGACY_EXCLUDE))
		return;
	if (f->reason & KGENOME_FNP_R_LIBWIN) {
		/* the residual stays evidence: the share of its sampled windows that no library has */
		if (!dead && f->n_win && f->n_win_lib < f->n_win)
			f->weight = (uint32_t)((uint64_t)kgenome_fnprint_weight(o, KGENOME_FNP_AUTHOR, f->n_insn) *
					       (f->n_win - f->n_win_lib) / f->n_win);
		return;
	}
	if (f->reason & KGENOME_FNP_R_LIBDB)
		return;
	f->cls = KGENOME_FNP_UNKNOWN;
	f->reason |= KGENOME_FNP_R_ADVISED;
	f->weight = dead ? 0 : (uint32_t)((uint64_t)(f->n_insn < o->wcap ? f->n_insn : o->wcap) * o->w_advised / 100u);
}

uint32_t kgenome_fnprint_weight(const struct kgenome_fnprint_opts *o, uint8_t cls, uint32_t n_insn)
{
	uint64_t base = n_insn < o->wcap ? n_insn : o->wcap;
	uint32_t pct = cls == KGENOME_FNP_AUTHOR ? o->w_author :
		       cls == KGENOME_FNP_UNKNOWN ? o->w_unknown : o->w_lib;

	return (uint32_t)(base * pct / 100u);
}

int kgenome_fnprint_sorted(const struct kgenome_func_set *s)
{
	uint32_t i;

	for (i = 1; s && i < s->n; i++)
		if (s->v[i].off < s->v[i - 1].off)
			return 0;
	return 1;
}

static int in_table(const uint64_t *t, uint32_t n, uint64_t v)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2u;

		if (t[m] < v)
			lo = m + 1u;
		else
			hi = m;
	}
	return lo < n && t[lo] == v;
}

/* Is a node in [off, off+len)? The first node >= off, and it is below the end. */
int kgenome_fnprint_has_node(const struct kgenome_fnprint_hints *h, uint64_t off, uint64_t len)
{
	uint32_t lo = 0, hi = h->n_node;

	if (!h->n_node || !h->node_at)
		return 0;
	while (lo < hi) {
		uint32_t m = lo + (hi - lo) / 2u;

		if (h->node_at[m] < off)
			lo = m + 1u;
		else
			hi = m;
	}
	return lo < h->n_node && h->node_at[lo] - off < len;
}

void kgenome_fnprint_decide(const struct kgenome_fnprint_req *rq, const struct kgenome_fnprint_opts *o,
		struct kgenome_fnprint_state *st, struct kgenome_fnprint_fn *f, int name,
		int is_entry, int in_diag)
{
	const struct kgenome_fnprint_hints *h = &rq->hint;
	int thunk, wrapper, libdb, libwin = 0, strong, anchored;

	f->cls = KGENOME_FNP_UNKNOWN;
	if (in_diag)
		f->reason |= KGENOME_FNP_R_DIAG;
	if (f->reason & KGENOME_FNP_R_BAD) {
		f->weight = 0;
		return;
	}
	if (f->n_insn < o->tiny_insn)
		f->reason |= KGENOME_FNP_R_TINY;
	if (f->n_bad * 2u > f->len)
		f->reason |= KGENOME_FNP_R_UNDECODED;
	/* zero bytes decode as `add [rax],al`: a function a quarter of which is that is padding or data (a table, relocation entries) */
	if (f->n_insn >= 4 && f->n_zero * 4u >= f->n_insn)
		f->reason |= KGENOME_FNP_R_ZEROES | KGENOME_FNP_R_UNDECODED;
	/* A thunk transfers control and does nothing else. A tiny function that ends in
	 * `ret` is one only where the ABI has get-pc thunks (32-bit x86: mov (%esp),%reg; ret);
	 * on x86-64 it is a leaf function (an accessor, a handler) and no thunk. */
	thunk = f->n_insn && f->n_insn <= o->thunk_insn && !f->n_call &&
		(f->last_op == KGENOME_CELL_JMP ||
		 (f->last_op == KGENOME_CELL_RET &&
		  (rq->arch != KGENOME_ARCH_X86_64 || (o->off & KGENOME_FNP_OFF_THUNK_RET))));
	wrapper = f->n_syscall && f->n_insn <= o->wrapper_insn;
	libdb = h->n_lib_fp && in_table(h->lib_fp, h->n_lib_fp, f->fp);
	if (h->libtab && !(f->reason & KGENOME_FNP_R_BAD)) {
		struct kgenome_fnprint_libvote v;

		kgenome_fnprint_libvote(h->libtab, rq->p + f->off, f->body_len ? f->body_len : f->len, &v);
		f->n_win = v.n_sampled;
		f->n_win_lib = v.n_hit;
		/* library BYTES: most of the sampled windows are in the table, and enough of them to say */
		libwin = v.n_sampled >= o->libwin_min && (uint64_t)v.n_hit * 100u >= (uint64_t)o->libwin_pct * v.n_sampled;
		if (libwin)
			f->reason |= KGENOME_FNP_R_LIBWIN;
	}
	/* A NAME IS ADVICE: it is recorded and explained, and only the legacy rules let it decide. An
	 * author who renames his functions to reserved or libc names, or libc's to his own, changes
	 * nothing in the walk (fnprint_adv_names.c). */
	if (name == 1) f->reason |= KGENOME_FNP_R_NAME_LIB;
	if (name == 2) f->reason |= KGENOME_FNP_R_NAME_AUTHOR;
	if (!(o->flags & KGENOME_FNP_OPT_LEGACY_EXCLUDE))
		name = 0;
	if (libdb) f->reason |= KGENOME_FNP_R_LIBDB;
	if (wrapper) f->reason |= KGENOME_FNP_R_WRAPPER;
	strong = name == 1 || libdb || libwin || wrapper;

	anchored = !(o->off & KGENOME_FNP_OFF_ENTRY_ORDER);
	if (is_entry) {
		f->reason |= KGENOME_FNP_R_STARTUP;
		f->cls = KGENOME_FNP_LIB;
	} else if (anchored && rq->link != KGENOME_FNP_LINK_UNKNOWN && st->main_off != KGENOME_BROKEN &&
		   f->off == st->main_off && name != 1) {
		/* the function the entry stub hands to the runtime is the program's own, by construction */
		f->reason |= KGENOME_FNP_R_MAIN;
		f->cls = KGENOME_FNP_AUTHOR;
	} else if (strong) {
		f->cls = KGENOME_FNP_LIB;
		if (rq->link == KGENOME_FNP_LINK_STATIC && st->main_off != KGENOME_BROKEN &&
		    f->off > st->main_off && !st->latched) {
			if (++st->seeds >= rq->opt.seeds_latch) {
				st->latched = 1;
				st->frontier = f->off;
			} else {
				f->reason |= KGENOME_FNP_R_PRE_SEED;
			}
		}
	} else if (thunk) {
		f->reason |= KGENOME_FNP_R_THUNK;
		f->cls = KGENOME_FNP_LIB;
	} else if (f->reason & KGENOME_FNP_R_UNDECODED) {
		f->cls = KGENOME_FNP_UNKNOWN;
	} else if (name == 2) {
		f->cls = KGENOME_FNP_AUTHOR;
	} else if (rq->link == KGENOME_FNP_LINK_DYNAMIC) {
		f->cls = KGENOME_FNP_AUTHOR;
		f->reason |= KGENOME_FNP_R_DYNAMIC;
	} else if (rq->link == KGENOME_FNP_LINK_STATIC) {
		if (st->main_off == KGENOME_BROKEN) {
			f->reason |= KGENOME_FNP_R_NO_MAIN;
		} else if (anchored && st->entry_off != KGENOME_BROKEN && f->off < st->entry_off) {
			f->cls = KGENOME_FNP_LIB;
			f->reason |= KGENOME_FNP_R_PRE_ENTRY;
		} else if (anchored && !st->latched && st->lib0 != KGENOME_BROKEN && st->lib0 > st->main_off &&
			   f->off >= st->lib0) {
			st->latched = 1;
			st->frontier = f->off;
			f->cls = KGENOME_FNP_LIB;
			f->reason |= KGENOME_FNP_R_BEYOND | KGENOME_FNP_R_LIB_START;
		} else if (st->latched) {
			f->cls = KGENOME_FNP_LIB;
			f->reason |= KGENOME_FNP_R_BEYOND;
		} else {
			f->cls = KGENOME_FNP_AUTHOR;
			f->reason |= KGENOME_FNP_R_BELOW;
		}
	} else {
		f->reason |= KGENOME_FNP_R_NO_FRONTIER;
	}
	f->weight = (f->reason & (KGENOME_FNP_R_TINY | KGENOME_FNP_R_UNDECODED | KGENOME_FNP_R_OVERLAP))
		    ? 0 : kgenome_fnprint_weight(o, f->cls, f->n_insn);
}
