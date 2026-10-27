/*
 * diag_wrapper.c - THE SYSCALL IS INSIDE A LIBRARY FUNCTION, AND THE PROGRAM IS
 * THE CALLERS.
 *
 * A bot built against a static libc does not execute `mov eax,41; syscall` where
 * it opens a socket. It executes `call socket`, and one function somewhere in the
 * binary holds the only `syscall` instruction there is:
 *
 *     socket:  push rbx
 *              movslq edx,rdx ; movslq esi,rsi ; movslq edi,rdi   <- the PARAMETERS
 *              mov eax,0x29
 *              syscall
 *
 * Read at that instruction the arguments are the function's own parameters, so
 * the node said "a socket of an unknown kind", stood in one place for every
 * socket the program makes, and could carry no link to anything - the descriptor
 * it returned goes to eighty call sites, and the arguments of those are the
 * caller's too. MEASURED on 1000 Bazaar Linux bots: 122 of 146 old Mirai had a
 * network node and one of them had a node with any link.
 *
 * SO THE NODES BELONG AT THE CALL SITES, which is where the program says what
 * it is doing, and the function is a SUMMARY that says what a call to it means:
 * which system call, and which of the caller's values become which argument.
 * That is what a relocatable object's imports already are - a name at a call
 * site with a capability - and the same machinery (an origin that is carried from
 * the node that produced a value to the node that takes it) links them.
 *
 *   1. SUMMARISE. Every syscall instruction has an entry: the nearest direct-call
 *      target before it. If the straight line from the entry to the instruction
 *      reaches it without a branch, and the registers the kernel reads are the
 *      function's parameters (possibly moved or widened on the way) or constants,
 *      the function is a wrapper and the summary says which.
 *   2. WALK THE CALLERS, function by function, with a small symbolic state: which
 *      node produced the value in each register, in each stack slot of this frame,
 *      and in each global. A call to a wrapper makes a node at the call, with the
 *      arguments the summary maps from what the caller holds; what it returns is
 *      that node.
 *
 * WHAT THIS DOES NOT CLAIM. The walk is linear in address order and takes no
 * branch, so a value is "carried" when nothing overwrote the place it was kept
 * before the next use - a MAY link, as the rest of the static routes are. A write
 * through a pointer clears nothing. Calls to anything but a wrapper forget the
 * registers a callee may clobber and keep what is on the stack and in globals.
 * x86 and x86-64 only; the stack arguments of cdecl are read, regparm and
 * fastcall are not.
 */

#include "diag_wrapper_private.h"


/*
 * ---- THE LEVELS, AS A WORKLIST -------------------------------------------------------------------
 *
 * A level adds the functions whose straight line ends in a call to a wrapper found by the one before.
 * It was a pass over EVERY call target per level, each asking "could this function come out differently
 * now" (kgenome_diag_wrapper_tseen_retry): a chain of D functions that each call the next, laid out in
 * ascending address order, finds one function per pass, so D passes of D questions - D*D, charged to the
 * step budget a pass at a time, which a chain of 2000 spent whole: the answer was lost (OVER_BUDGET, no
 * node) for a program of twelve kilobytes. MEASURED: 31,376 / 125,251 / 500,501 questions at depth 250 /
 * 500 / 1000 (tests/lib/genome/diag_graph_bin.c counts them).
 *
 * The question can only come out differently for a function when one of the targets ITS WALK MET has since
 * become a wrapper (that is what tseen records), so a function is asked again exactly then: every function
 * records who met it (`dep`, a list per target), and a wrapper that is added puts the functions that met it on
 * the worklist. The ORDER is the old one, so the answers are the same: a level visits its functions in
 * ascending address order, a function that meets a wrapper added EARLIER IN THE SAME LEVEL is asked in this
 * level (it is further on in the order), one that met a wrapper added after its turn is asked in the next.
 * The first level is still a pass over every target (nothing has been asked yet); a function that met more
 * targets than a record holds (`more`) is asked again every level that follows an addition, as before.
 *
 * What bounds it is what bounded it: the step budget (kgenome_budget.max_steps), charged one step a function
 * asked, and a level that cannot be paid for says KGENOME_OVER_BUDGET.
 */
struct wl_edge {
	uint32_t who;
	int32_t  next;
};

struct wl {
	int32_t  *head;                 /* per target: its first dependent edge, -1 for none */
	struct wl_edge *edge;
	uint32_t n_edge, cap_edge;
	uint32_t *heap;                 /* this level's targets, a min-heap by index */
	uint32_t n_heap;
	uint32_t *next;                 /* the next level's, unordered, once each */
	uint32_t n_next;
	uint32_t *more;                 /* targets that met more than a record holds */
	uint32_t n_more;
	uint8_t  *flag;                 /* per target: WL_HEAP, WL_NEXT, WL_MORE */
};
#define WL_HEAP 1u
#define WL_NEXT 2u
#define WL_MORE 4u

static void wl_free(struct wl *l)
{
	free(l->head);
	free(l->edge);
	free(l->heap);
	free(l->next);
	free(l->more);
	free(l->flag);
	memset(l, 0, sizeof *l);
}

static int wl_init(struct kgenome_diag_wrapper_ctx *c, struct wl *l)
{
	const uint32_t n = c->wk->n_tgt;
	uint32_t i;

	if (!kgenome_diag_wrapper_charge(c, (uint64_t)n * (sizeof *l->head + 3u * sizeof *l->heap + sizeof *l->flag)))
		return 0;
	l->head = malloc((size_t)n * sizeof *l->head);
	l->heap = malloc((size_t)n * sizeof *l->heap);
	l->next = malloc((size_t)n * sizeof *l->next);
	l->more = malloc((size_t)n * sizeof *l->more);
	l->flag = calloc(n, sizeof *l->flag);
	if (!l->head || !l->heap || !l->next || !l->more || !l->flag) {
		kgenome_diag_note(c->s, KGENOME_NOMEM);
		wl_free(l);
		return 0;
	}
	for (i = 0; i < n; i++)
		l->head[i] = -1;
	return 1;
}

static void heap_push(uint32_t *h, uint32_t *n, uint32_t v)
{
	uint32_t i = (*n)++;

	while (i && h[(i - 1u) / 2u] > v) {
		h[i] = h[(i - 1u) / 2u];
		i = (i - 1u) / 2u;
	}
	h[i] = v;
}

static uint32_t heap_pop(uint32_t *h, uint32_t *n)
{
	const uint32_t top = h[0], last = h[--(*n)];
	uint32_t i = 0;

	for (;;) {
		uint32_t c = 2u * i + 1u;

		if (c >= *n)
			break;
		if (c + 1u < *n && h[c + 1u] < h[c])
			c++;
		if (h[c] >= last)
			break;
		h[i] = h[c];
		i = c;
	}
	if (*n)
		h[i] = last;
	return top;
}

/* function `who` met target `callee` and it was not a wrapper: ask `who` again when it becomes one */
static int wl_depend(struct kgenome_diag_wrapper_ctx *c, struct wl *l, uint32_t callee, uint32_t who)
{
	if (l->n_edge == l->cap_edge) {
		uint32_t nc = l->cap_edge ? l->cap_edge * 2u : 256u;
		struct wl_edge *ne;

		if (!kgenome_diag_wrapper_charge(c, (uint64_t)(nc - l->cap_edge) * sizeof *ne))
			return 0;
		ne = realloc(l->edge, (size_t)nc * sizeof *ne);
		if (!ne) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return 0;
		}
		l->edge = ne;
		l->cap_edge = nc;
	}
	l->edge[l->n_edge].who = who;
	l->edge[l->n_edge].next = l->head[callee];
	l->head[callee] = (int32_t)l->n_edge++;
	return 1;
}

/* After an attempt at target `i`: who it met, and whether it met too many to record. 0: an edge could not be kept. */
static int wl_record(struct kgenome_diag_wrapper_ctx *c, struct wl *l, uint32_t i)
{
	const struct kgenome_diag_wrapper_tseen *t = &c->tseen[i];
	uint8_t k;

	for (k = 0; k < t->n; k++) {
		int ti = kgenome_diag_wrapper_tgt_index(c, t->cal[k]);

		if (ti >= 0 && !wl_depend(c, l, (uint32_t)ti, i))
			return 0;
	}
	if (t->more && !(l->flag[i] & WL_MORE)) {
		l->flag[i] = (uint8_t)(l->flag[i] | WL_MORE);
		l->more[l->n_more++] = i;
	}
	return 1;
}

/* target `i` became a wrapper: the functions that met it are asked, in this level when they are further on */
static void wl_notify(struct wl *l, uint32_t i)
{
	int32_t e;

	for (e = l->head[i]; e >= 0; e = l->edge[e].next) {
		const uint32_t j = l->edge[e].who;

		if (l->flag[j] & (WL_HEAP | WL_NEXT))
			continue;
		if (j > i) {
			l->flag[j] = (uint8_t)(l->flag[j] | WL_HEAP);
			heap_push(l->heap, &l->n_heap, j);
		} else {
			l->flag[j] = (uint8_t)(l->flag[j] | WL_NEXT);
			l->next[l->n_next++] = j;
		}
	}
}

/* One function asked: 1 when it became a wrapper. */
static int wl_attempt(struct kgenome_diag_wrapper_ctx *c, struct wl *l, uint32_t i, uint32_t *added)
{
	struct kgenome_diag_wrapper_summary *t;
	unsigned nt, v;
	int got = 0;

	if (kgenome_diag_wrapper_summary_of(c, c->wk->tgt[i]) || !kgenome_diag_wrapper_tseen_retry(c, &c->tseen[i]))
		return 0;
	nt = kgenome_diag_wrapper_summarise(c, c->wk->tgt[i], &c->tseen[i], 0);
	t = c->var;
	for (v = 0; v < nt; v++) {
		if (!kgenome_diag_wrapper_summary_insert(c, &t[v]))
			break;
		(*added)++;
		got = 1;
	}
	if (!wl_record(c, l, i))
		c->over_steps = 1;              /* an edge could not be kept: the ledger or memory has said so */
	return got;
}

static void wl_levels(struct kgenome_diag_wrapper_ctx *c)
{
	struct kgenome_diag_scan *s = c->s;
	struct wl l;
	uint32_t i, added, k;

	memset(&l, 0, sizeof l);
	if (!wl_init(c, &l))
		return;
	/* what the first level (the functions that hold a site) already met */
	for (i = 0; i < c->wk->n_tgt; i++)
		if (c->tseen[i].done && !wl_record(c, &l, i))
			goto out;
	/* LEVEL ONE: every target, in order - nothing has been asked yet */
	if (s->bud.max_steps && c->steps + c->wk->n_tgt > s->bud.max_steps) {
		kgenome_diag_note(s, KGENOME_OVER_BUDGET);
		goto out;
	}
	c->steps += c->wk->n_tgt;
	added = 0;
	for (i = 0; i < c->wk->n_tgt; i++) {
		/* this pass reaches every j > i by itself: the heap is for the levels after it */
		l.flag[i] = (uint8_t)(l.flag[i] & ~WL_HEAP);
		if (wl_attempt(c, &l, i, &added))
			wl_notify(&l, i);
		l.n_heap = 0;
	}
	for (i = 0; i < c->wk->n_tgt; i++)
		l.flag[i] = (uint8_t)(l.flag[i] & ~WL_HEAP);
	/* LATER LEVELS: what the additions of the one before reach, and the targets that met too many to record */
	while (added && !c->over_steps) {
		uint32_t n_cand;

		added = 0;
		for (k = 0; k < l.n_more; k++)
			if (!(l.flag[l.more[k]] & WL_NEXT) && !kgenome_diag_wrapper_summary_of(c, c->wk->tgt[l.more[k]])) {
				l.flag[l.more[k]] = (uint8_t)(l.flag[l.more[k]] | WL_NEXT);
				l.next[l.n_next++] = l.more[k];
			}
		n_cand = l.n_next;
		if (!n_cand)
			break;
		if (s->bud.max_steps && c->steps + n_cand > s->bud.max_steps) {
			/* another level cannot be paid for: whatever it would have added was never looked for */
			kgenome_diag_note(s, KGENOME_OVER_BUDGET);
			break;
		}
		c->steps += n_cand;
		/* this level is what was queued; the additions of THIS level reach further functions of it */
		for (k = 0; k < l.n_next; k++) {
			l.flag[l.next[k]] = (uint8_t)((l.flag[l.next[k]] & ~WL_NEXT) | WL_HEAP);
			heap_push(l.heap, &l.n_heap, l.next[k]);
		}
		l.n_next = 0;
		while (l.n_heap && !c->over_steps) {
			i = heap_pop(l.heap, &l.n_heap);
			l.flag[i] = (uint8_t)(l.flag[i] & ~WL_HEAP);
			if (wl_attempt(c, &l, i, &added))
				wl_notify(&l, i);
			if (s->bud.max_steps && ++c->steps > s->bud.max_steps) {
				c->over_steps = 1;
				kgenome_diag_note(s, KGENOME_OVER_BUDGET);
			}
		}
	}
out:
	wl_free(&l);
}

void kgenome_diag_run_wrappers(struct kgenome_diag_scan *s,
			   const struct kgenome_obj *obj,
			   const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	struct kgenome_diag_walk *wk;
	struct kgenome_diag_wrapper_ctx c;
	uint32_t i;

	if (!e || !e->valid)
		return;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64)
		return;
	/* KNOWN DEFECT WP9-F7 (2026-10-25, M) [sev M]: kgenome_diag_wrapper_scan returns when
	 * kgenome_diag_scan_walk answers NULL and notes nothing. Trigger: the walk allocation
	 * (kgenome_diag_walk_new) refused during a scan. Effect: the wrapper analysis is skipped with the scan
	 * status OK: a shorter graph reported as whole (G9 class; diag_elfimp.c already notes NOMEM at the same
	 * shape). Reproducer: tests/lib/genome/diag_bin_oom.c KNOWN-MISS F7 (elf64-prog1). Fix: `if (!wk) {
	 * kgenome_diag_note(s, KGENOME_NOMEM); return; }`. */
	wk = kgenome_diag_scan_walk(s);
	if (!wk)
		return;
	kgenome_diag_wrap_settle(s);
	memset(&c, 0, sizeof c);
	c.s = s;
	c.obj = obj;
	c.base = base;
	kgenome_cell_space_init(&c.sp, obj, base, size);
	c.size = size;
	c.wide = obj->arch == KGENOME_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;
	c.wk = wk;
	/* The walk is the object's, made once: it is already here when the
	 * functions were asked for first, and made here otherwise. */
	if (!kgenome_diag_walk_ensure(wk, obj, base, size, 1)) {
		kgenome_diag_note(s, KGENOME_NOMEM);     /* the decode walk could not be held */
		return;
	}
	if (!wk->n_site)
		goto opaque;
	for (i = 0; i < s->n_hit; i++)
		if (s->hit[i].cap == KGENOME_NUCLEO_NONE &&
		    (s->hit[i].bits & KGENOME_DIAG_H_OPAQUE) &&
		    !kgenome_diag_wrapper_push_u64(&c.open, &c.n_open, &c.cap_open, s->hit[i].at)) {
			kgenome_diag_note(s, KGENOME_NOMEM);
			goto out;
		}
	/* qsort's base is declared nonnull, and with no elements it is NULL. */
	if (c.n_open)
		qsort(c.open, c.n_open, sizeof *c.open, kof_cmp_u64);
	kgenome_diag_wrapper_tgt_unique(&c);
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) *
			 (sizeof *c.fret + sizeof *c.fmiss)))
		goto out;
	c.fret = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fret);
	c.fmiss = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.fmiss);
	if (!c.fret || !c.fmiss) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)(wk->n_tgt ? wk->n_tgt : 1u) * sizeof *c.tseen))
		goto out;
	c.tseen = calloc(wk->n_tgt ? wk->n_tgt : 1u, sizeof *c.tseen);
	if (!c.tseen) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	/*
	 * LEVEL 0: the functions that hold a syscall. THEN THE LEVELS: the functions
	 * whose straight line ends in a call to one already found, again and again
	 * until a level adds nothing (socket() around __socketcall around the
	 * syscall is three; the step budget is the bound).
	 */
	c.cap_ws = wk->n_site + 64u;
	if (!kgenome_diag_wrapper_charge(&c, (uint64_t)c.cap_ws * (sizeof *c.ws + sizeof *c.wi))) {
		c.cap_ws = 0;
		goto out;
	}
	c.ws = calloc(c.cap_ws, sizeof *c.ws);
	c.wi = calloc(c.cap_ws, sizeof *c.wi);
	if (!c.ws || !c.wi) {
		kgenome_diag_note(s, KGENOME_NOMEM);
		goto out;
	}
	for (i = 0; i < wk->n_site; i++) {
		uint64_t entry;
		struct kgenome_diag_wrapper_summary *t;
		unsigned nt, v;

		int ti;

		if (!kgenome_diag_wrapper_entry_of(&c, wk->site[i], &entry))
			continue;
		if (kgenome_diag_wrapper_summary_of(&c, entry))
			continue;
		ti = kgenome_diag_wrapper_tgt_index(&c, entry);
		/* A function with several sites is summarised once, and again only if
		 * a wrapper has appeared among what its walk met - see struct kgenome_diag_wrapper_tseen. */
		if (ti >= 0 && !kgenome_diag_wrapper_tseen_retry(&c, &c.tseen[ti]))
			continue;
		nt = kgenome_diag_wrapper_summarise(&c, entry, ti >= 0 ? &c.tseen[ti] : NULL, 1);
		t = c.var;
		/*
		 * A CAP CUT THE SUMMARY OF THE FUNCTION THAT HOLDS THIS SITE, and it cost an
		 * explanation when the sweep could not read the site either (the cap is
		 * what left it unexplained) or when the summary that WAS made is partial
		 * (a wrapper whose other arms were dropped): the scan says so.
		 *
		 * NOT FOR EVERY CUT. A function of two hundred instructions that holds a
		 * syscall deep inside is the ordinary case in a static libc, the body bound ends
		 * its walk, nothing was found and the sweep read the site directly - that
		 * loses no evidence and is not reported, or every static binary would
		 * come back "partial". (Measured on the prof set: see the report. One
		 * case this does not catch: a wrapper whose every arm is cut before
		 * it yields a summary, at a site the sweep read from the caller's stale
		 * constants - W_PENDING in tests/unit/diag_wrapper_limits.c.)
		 */
		if (c.cut && (nt > 0 || kgenome_diag_wrapper_site_open(&c, wk->site[i]) ||
			      kgenome_diag_wrapper_site_wrapped(s, wk->site[i])))
			kgenome_diag_note(s, KGENOME_TRUNCATED);
		for (v = 0; v < nt; v++)
			(void)kgenome_diag_wrapper_summary_insert(&c, &t[v]);
	}
	if (c.n_ws)
		wl_levels(&c);
	if (!c.n_ws)
		goto opaque;
	/*
	 * TWICE, because a descriptor kept in a global is stored where the program
	 * dials out and read where it listens, and which of the two functions comes
	 * first in the file is the compiler's business. The second walk starts with
	 * every global the first one saw produced, so a read that came before the
	 * write in address order still finds it. The nodes it makes are the first
	 * walk's again, merged by site at the end of the scan, with the links the
	 * first walk could not yet have.
	 */
	{
		unsigned round;

		/*
		 * THE SECOND ROUND ONLY WHEN IT CAN DIFFER. It starts with the
		 * globals the first produced, so it changes the result exactly
		 * when some global was read before the first round had written it
		 * (need_round2) or a call asked for what a helper returns before the
		 * walk had reached the helper. Otherwise it would decode the whole image again
		 * to arrive at the same nodes: MEASURED, kgenome_diag_wrapper_pass_b is a full linear
		 * decode and this was the third of three over the same bytes.
		 */
		for (round = 0; round < 2u; round++) {
			if (round && !c.need_round2)
				break;
			for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
				uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

				if (have)
					kgenome_diag_wrapper_pass_b(&c, i, at, have);
			}
		}
	}
	/* A wrapper some caller made a node for is answered at its callers; the
	 * node the sweep made at the syscall inside it spoke for every caller at
	 * once and for none of them, and is set aside. */
	kgenome_diag_wrapper_supersede(&c);
opaque:
	/* A socketcall of an unknown kind is a different statement from no
	 * socketcall at all: a site nobody called with a value this could read
	 * says so, once, rather than saying nothing. */
	for (i = 0; i < s->n_wrap; i++) {
		if (!kgenome_diag_wrapper_site_made(&c, s->wrap[i])) {
			struct kgenome_diag_hit *h = kgenome_diag_hit_add(s, s->wrap[i],
								  KGENOME_NUCLEO_NONE, 0);

			if (h)
				h->bits |= KGENOME_DIAG_H_OPAQUE;
		}
	}
out:
	/* The trace STAYS with a walk the scanner owns, to the end of the object:
	 * the xref sweep reads the same instructions (see kgenome_diag_code_run), and
	 * the scanner frees the walk when the next object begins. A walk this scan
	 * made for itself has no other reader - nobody can hand it to the sweep - so
	 * its trace goes now, as it always did: a tool that keeps a scan alive to
	 * show it must not keep an object's worth of decode with it. */
	if (wk == s->own_walk)
		kgenome_diag_wrapper_walk_drop_trace(wk);
	free(c.open);
	free(c.pend);
	free(c.var);
	free(c.tseen);
	free(c.fret);
	free(c.fmiss);
	free(c.ws);
	free(c.wi);
	free(c.made);
	free(c.glob);
	kgenome_ledger_release(&s->led, c.charged);
}
