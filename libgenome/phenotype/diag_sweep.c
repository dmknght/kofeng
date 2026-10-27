/*
 * diag_sweep.c - the sweep: windows around each candidate, a region, the ELF segments, and the syscall routine.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"
#include <genotype/image/elf_image.h>

/*
 * HOW MUCH CODE AROUND A CANDIDATE IS DECODED.
 *
 * LEAD is the run before it, and it exists to read the arguments: a syscall's
 * number and its six registers are set by the instructions immediately in
 * front of it. 256 bytes covers every stager measured here with room over -
 * msfvenom's longest argument set-up, in the i386 reverse shell, is 41 bytes.
 *
 * There is no fixed number for the run AFTER it, because what matters there
 * is not a distance but whether anything the syscall produced is still being
 * carried: the `jmp` into an mmap'd region may be two instructions later or
 * fifty. The walk continues while any register or stack slot holds an origin
 * and stops IDLE instructions after the last one is gone - which is a
 * property of the program and not a constant somebody picked.
 *
 * AND THIS IS WHERE THE WALK STOPS BEING A WHOLE-SEGMENT SWEEP, so the loss
 * has to be stated: a node established here and used a long way further on,
 * with nothing carrying it in between, is not seen. Nothing in the samples
 * measured does that - a pointer that is live is live in a register - but it
 * is a real difference from decoding the segment end to end, not a free one.
 */
#define DIAG_LEAD  256u
#define DIAG_IDLE   64u
/*
 * THE WIDER LEAD, and when it is used. A candidate whose syscall NUMBER, or an
 * argument that decides what the node IS (mmap's prot, a socket's type), was not
 * read in the 256-byte window AND WAS NOT WRITTEN IN IT is walked again from up
 * to 4096 bytes back, 16 times the lead, and the nodes of the first attempt are
 * dropped. Only such a candidate pays: one whose arguments resolved is walked
 * once, exactly as before, and a wider window can only turn "unread" into
 * "read", never move a value that was already read.
 *
 * "NOT WRITTEN IN IT" IS WHAT KEEPS THIS CHEAP. A static libc's wrapper loads
 * the number from its caller's register (`mov eax, edi`): eax was written, to
 * something that is not a constant, and no earlier constant can survive that. A
 * wider window there finds only an unrelated constant from the function before,
 * or nothing - and the wrapper analysis (diag_wrapper.c) is what resolves those
 * sites. MEASURED: retrying every unread site cost a static x86-64 bot 40% of its
 * scan (109.6M Ir to 152.5M, callgrind: 30 retries of 4 KB in 75 windows) for no
 * node it did not already have; retrying only the ones nothing wrote costs
 * nothing measurable. x86 only: the ARM ports' argument registers are not the
 * ones the mask is kept in. What it cannot do is reach past 4096: a
 * candidate still unread with the window clipped at that distance sets
 * KGENOME_TRUNCATED, because the argument may be set further back than anyone
 * looked. (The fixed 256 was KNOWN-MISS "PROT_EXEC set 300 bytes before the
 * syscall"; tests/unit/caps_sweep.c holds the boundary.)
 */
#define DIAG_LEAD_WIDE 4096u

/*
 * ONE WINDOW: the code from `at` through candidate `c` and on while anything it
 * produced is still carried - and what is left of it when it stops.
 *
 * `struct sweep_win` IS A WINDOW THAT CAN BE PUT DOWN AND PICKED UP: the cursor,
 * the value maps and the one instruction that was decoded and not yet acted on.
 *
 * THE SEAM, and why this is the fix and not "start the next window one
 * instruction earlier". A window ends when 65 instructions past its candidate
 * carried nothing. The old code threw its state away there and the next window
 * started at max(candidate - LEAD, where the last one stopped) with a fresh map:
 * the instruction it stopped on was in nobody's window, and - the half that a
 * one-instruction shift does not fix - neither were the VALUES the last window
 * had read in the instructions just before it. MEASURED (tests/unit/caps_sweep.c,
 * idle_seam; 11-byte filler per syscall): 7 of 120 placements lost the stager,
 * first at k=16, period 17, because the stager's `mov eax,9` was that
 * instruction. Moving the start only moved the loss to the filler before it
 * (its `xor eax,eax` was consumed and its number came out unread).
 *
 * So the window is SUSPENDED where it stops, with `in` held back, and the next
 * candidate whose lead reaches that point RESUMES it: the same linear read, as if
 * it had never broken - no instruction skipped, none read twice, every value
 * still known. A candidate whose lead does not reach it starts fresh at its own
 * lead, as before; the instructions in between were idle, which is what the
 * window ended for.
 */
struct sweep_win {
	struct kgenome_cell_cur k;
	struct kgenome_diag_orgs w;
	struct kgenome_cell_insn in;    /* decoded, not yet acted on (when `live`) */
	int live;                       /* suspended: `in` is the next instruction */
	uint16_t wrote;                 /* the registers written since the window began */
	uint8_t dead;                   /* the line ended just before: 1 a ret, 2 a jmp (see sweep_control_in) */
};

/* THE REGION A SWEEP WALKS, the same for every window of it: the scan, the
 * object, the bytes, the decoder's view of them, and the part of them to sweep
 * (`n` bytes from `off`). */
struct sweep_rgn {
	struct kgenome_diag_scan *s;
	const struct kgenome_obj *obj;
	const uint8_t *base;
	const struct kgenome_cell_space *sp;
	uint64_t off, n;
	struct sweep_joins *jn;         /* the pending joins, the region's */
	struct kgenome_diag_callees *ce; /* what the callees write: diag_origin.c reads them, the answers are remembered here */
	int has_syms;                   /* an ELF with a symbol table: its function starts are named, not guessed (tail_jmp) */
};

/*
 * ---- THE WALK IS A STRAIGHT LINE; THE PROGRAM IS NOT ----------------------------------------------
 *
 * The sweep reads code in address order and takes no branch, so the origin map it carries is right
 * inside one straight line and nowhere else. Four things end a line, and each of them used to be
 * ignored - the register that held a socket in one function was still "the socket" in the next one,
 * after a call that wrote it, and on the other arm of an `if`. MEASURED on hand-made programs
 * (tests/lib/genome/diag_graph_bin.c), every one of them a link reported PROVEN that the program
 * does not make. What each does now:
 *
 *   RET        the function is over. The code after it is reached by a jump from earlier in the same
 *              function (a JOIN, below) or it is another function: with no join the origins are
 *              forgotten, and the stack ring with them.
 *   JMP        likewise for the line, but the code after a jump can also be reached by a call or a
 *              backward branch later in the file (the jmp/call/pop idiom, a rotated loop), so with no
 *              join the origins are kept and become MAY: reached, not shown. A TAIL JUMP - to a function
 *              the symbol table names, from another one - is a ret for the line: what follows is that
 *              next function (tail_jmp). A file with no symbol table has no function starts to tell the
 *              two by, and keeps the rule above: a start found from the calls the code makes (a
 *              `call back` after the jmp is exactly the idiom) is a guess, and is not used.
 *   CALL       what the callee does to the registers (kgenome_diag_org_call, diag_origin.c, shared with
 *              the symbol route): a direct callee that is straight line to its `ret` is READ - a register
 *              it writes loses its origin, one it does not write keeps it - and any other callee, an
 *              indirect call, makes the registers the ABI lets a callee overwrite MAY. `call next` and a
 *              callee that begins by popping the return address are not calls: they fetch the program
 *              counter, and push the stack slot that pop takes back.
 *   JOIN       a forward branch (a `jcc`, or a `jmp`) is where a second path will arrive. The origin
 *              map as it was when the walk left is remembered at the target, and the walk that reaches
 *              the target merges it: two different producers are both kept (the second is a MAY link),
 *              and a producer only one path holds is MAY, because the other path has no such value.
 *
 *   BACK EDGE  a backward branch to a head inside the window is where a second path arrives at a point the
 *              walk has already passed: a value the body writes is what the head holds on the next pass,
 *              and every read in the body made from the first producer is a claim about the first pass
 *              only. The walk cannot merge into code it has read, so a window that meets such a branch
 *              (see back_edge: only one with a link in its body that comes from outside it, so that a
 *              loop that carries nothing costs nothing) is run a SECOND TIME with the origin map at the
 *              branch joined in at the head, and the first run's nodes are dropped. Two passes at most per
 *              window - the work is counted - so the state at the branch is the first pass's: a loop whose
 *              body only becomes different under the merge (an origin that appears on the second pass)
 *              is approximated, which is the limit. At most DIAG_BACK_MAX heads a window; one past it, a
 *              head the second pass found, a window with no table to remember them in, and a head before
 *              the window's start (an earlier window made those reads) demote the body's links from
 *              outside it to MAY and say so.
 *
 * A cap that fires reports: the table of pending joins holds DIAG_JOIN_MAX, and a
 * branch that cannot be remembered makes what is carried MAY and says KGENOME_TRUNCATED. A table the ledger
 * or the allocator refused is the same loss said by that refusal (over-budget, nomem): the walk is then the
 * straight line it was before, with its calls and returns handled.
 *
 * Why MAY and not nothing, where the walk does not know: a link is kept when the program can produce
 * it (the matcher does not read how sure a link is - see linked() in kofdiag.c), and the report says
 * how sure it is.
 */
#define DIAG_JOIN_MAX    256u
/* the loop heads one window remembers for its second pass; the work is bounded by the two passes, not by this */
#define DIAG_BACK_MAX     32u
/* what the tables of a region cost, charged once: the pending joins, the copy a resumed window is run again from, the loop heads */
#define JOIN_BYTES (2u * DIAG_JOIN_MAX * sizeof(struct sweep_join) + DIAG_BACK_MAX * sizeof(struct sweep_back))
/* A pending join farther ahead than this does not keep a window open: the walk would read a function to
 * reach it, and the window ends where the origins end (DIAG_IDLE) as it always did. */
#define DIAG_JOIN_REACH  4096u
/* a pending forward transfer: where it arrives and what the walk held when it left */
struct sweep_join {
	uint64_t at;
	uint8_t  empty;         /* the walk held no origin: nothing to copy */
	uint8_t  live;          /* counted in sweep_joins.live */
	struct kgenome_diag_orgs w;
};

/*
 * A LOOP HEAD AND THE ORIGIN MAP AT THE BACK EDGE THAT REACHES IT: what the second pass over a window merges in at
 * the head (see the note on back edges above sweep_window).
 */
struct sweep_back {
	uint64_t at;
	struct kgenome_diag_orgs w;
};

/* THE REGION'S, shared by its windows (a window that resumes another continues the same table; one that
 * starts fresh empties it). */
struct sweep_joins {
	struct sweep_join *e;   /* NULL: no memory (said by the ledger or the allocator): no joins are remembered */
	uint32_t n, live;
	uint64_t min_at;
	/* the table as a RESUMED window found it, so that the window can be run a second time (a fresh one just empties it) */
	struct sweep_join *e0;
	uint32_t n0, live0;
	uint64_t min_at0;
	int saved;
	/* the back edges the window's first pass found, for its second */
	struct sweep_back *bk;
	uint32_t nbk;
};

/* Is anything from an earlier node still being carried - or waiting at a join that is near enough to arrive? */
static int origins_live(const struct sweep_rgn *rg, const struct kgenome_diag_orgs *w)
{
	(void)rg;
	return w->carry_armed || w->carry_live || kgenome_diag_org_any(w);
}

static void joins_reset(struct sweep_joins *jn)
{
	if (!jn)
		return;
	jn->n = 0;
	jn->live = 0;
	jn->min_at = UINT64_MAX;
}

/* A forward branch: remember the walk's origin map at its target. */
static void join_add(const struct sweep_rgn *rg, struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in)
{
	struct sweep_joins *jn = rg->jn;
	struct sweep_join *e;
	const int any = kgenome_diag_org_any(w);

	if (!jn || !jn->e)
		return;         /* no table: the walk is the straight line it was, and the refusal is already said (over-budget, nomem) */
	if (jn->n >= DIAG_JOIN_MAX) {
		/* the DoS bound, and the loss is said: the merge at this target will not be made */
		kgenome_diag_note(rg->s, KGENOME_TRUNCATED);
		kgenome_diag_org_demote(w, 0xffffu);
		return;
	}
	e = &jn->e[jn->n++];
	e->at = in->target;
	e->empty = !any;
	e->live = 0;
	if (any) {
		e->w = *w;
		if (e->at - in->at <= DIAG_JOIN_REACH) {
			e->live = 1;
			jn->live++;
		}
	}
	if (e->at < jn->min_at)
		jn->min_at = e->at;
}

/* The function a file offset is in, from the symbol table's set (sorted by offset), or NULL. */
static const struct kgenome_func *func_at(const struct kgenome_func_set *fg, uint64_t off)
{
	uint32_t lo = 0, hi = fg->n;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fg->v[mid].off <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || off >= fg->v[lo - 1u].off + fg->v[lo - 1u].len)
		return NULL;
	return &fg->v[lo - 1u];
}

/*
 * A DIRECT JMP FROM ONE NAMED FUNCTION TO ANOTHER is a tail call: the line ends as it does at a ret, and the code
 * after the jmp is the next function, which nothing here reaches. Only a function the symbol table names counts
 * (`shndx`): the functions of a stripped file are the entries the code is seen to call, and the jmp/call/pop idiom
 * calls the code it jumped over, which would make every such idiom look like a tail call and take its origins
 * away. The table is read when the first direct jmp asks and is the scan's one set (kgenome_diag_funcs).
 */
static int tail_jmp(const struct sweep_rgn *rg, const struct kgenome_cell_insn *in)
{
	const struct kgenome_func_set *fg;
	const struct kgenome_func *a, *b;

	if (!rg->has_syms || (in->flags & KGENOME_CELL_F_INDIRECT) || in->target == KGENOME_BROKEN)
		return 0;
	fg = kgenome_diag_funcs(rg->s, rg->obj);
	if (!fg || !fg->n)
		return 0;
	a = func_at(fg, in->at);
	b = func_at(fg, in->target);
	return a && b && a != b && a->shndx && b->shndx;
}

/* ---- BACK EDGES: the second pass ----------------------------------------------------------------------- */

/* Put the pending joins as a RESUMED window found them (the table is the region's and the first pass changed it). */
static void jn_save(struct sweep_joins *jn)
{
	jn->saved = 0;
	if (!jn->e || !jn->e0)
		return;
	memcpy(jn->e0, jn->e, (size_t)jn->n * sizeof *jn->e);
	jn->n0 = jn->n;
	jn->live0 = jn->live;
	jn->min_at0 = jn->min_at;
	jn->saved = 1;
}

static void jn_restore(struct sweep_joins *jn)
{
	memcpy(jn->e, jn->e0, (size_t)jn->n0 * sizeof *jn->e);
	jn->n = jn->n0;
	jn->live = jn->live0;
	jn->min_at = jn->min_at0;
}

/* A loop head, with the map the back edge reached it with, becomes a join that arrives when the walk is at the head.
 * The second pass makes the same nodes in the same order as the first (the constant map decides which, the origin
 * map only what they link), so the node numbers in the map it merges are the numbers it will give - a link to a node
 * the pass did not make would be a link out of the node array, which tests/lib/genome/diag_graph_bin.c checks for
 * every scan it makes. */
static void back_register(const struct sweep_rgn *rg, const struct sweep_back *b)
{
	struct sweep_joins *jn = rg->jn;
	struct sweep_join *e;

	if (jn->n >= DIAG_JOIN_MAX) {
		kgenome_diag_note(rg->s, KGENOME_TRUNCATED);    /* the head will not be merged: said, as a forward join's is */
		return;
	}
	e = &jn->e[jn->n++];
	e->at = b->at;
	e->empty = !kgenome_diag_org_any(&b->w);
	e->live = 0;
	if (!e->empty)
		e->w = b->w;
	if (e->at < jn->min_at)
		jn->min_at = e->at;
}

/* The links of the hits from `first` on that come from a node before `first` (a producer outside the loop body) and
 * are PROVEN: the claims a second pass can take back. `demote` makes them MAY; the return is how many there are. */
static unsigned body_links(struct kgenome_diag_scan *s, uint32_t first, int demote)
{
	uint32_t j, n = s->n_hit;
	unsigned k, found = 0;

	for (j = first; j < n; j++) {
		struct kgenome_diag_hit *h = &s->hit[j];

		for (k = 0; k < h->n_in; k++)
			if (h->in[k].from < first && h->in[k].how != KGENOME_DIAG_LINK_MAY) {
				found++;
				if (demote)
					h->in[k].how = KGENOME_DIAG_LINK_MAY;
			}
	}
	return found;
}

/* A head the first pass of this window already remembered. */
static int back_known(const struct sweep_joins *jn, uint64_t head)
{
	uint32_t i;

	for (i = 0; i < jn->nbk; i++)
		if (jn->bk[i].at == head)
			return 1;
	return 0;
}

/*
 * A BACKWARD BRANCH to a head the window has read since it began. When some read in the loop body took its value from
 * a producer outside the body and the claim is PROVEN, that claim holds for the first pass only: the map at this
 * branch is remembered for a second pass (`*again`), or - the second pass is not possible - the claims become MAY.
 */
static void back_edge(const struct sweep_rgn *rg, const struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in,
		      uint64_t lo, uint32_t h0, int pass, int resumed)
{
	struct sweep_joins *jn = rg->jn;
	struct kgenome_diag_scan *s = rg->s;
	uint32_t first = h0, hi = s->n_hit;

	if ((in->op != KGENOME_CELL_JCC && in->op != KGENOME_CELL_JMP) || (in->flags & KGENOME_CELL_F_INDIRECT) ||
	    in->target == KGENOME_BROKEN || in->target >= in->at)
		return;
	if (in->target >= lo) {
		/* the first hit at or past the head: the walk's hits are in address order */
		while (first < hi) {
			const uint32_t mid = first + (hi - first) / 2u;

			if (s->hit[mid].at < in->target)
				first = mid + 1u;
			else
				hi = mid;
		}
		if (jn && pass && back_known(jn, in->target))
			return;                         /* the second pass met the head it was run for */
		if (!body_links(s, first, 0))
			return;                         /* nothing in the body takes its value from outside it */
		if (!pass && jn && jn->bk && jn->nbk < DIAG_BACK_MAX && (!resumed || jn->saved)) {
			jn->bk[jn->nbk].at = in->target;
			jn->bk[jn->nbk].w = *w;
			jn->nbk++;
			return;
		}
		/* not remembered, and said: the cap, a head the second pass found, no table to keep it in */
		if (jn && jn->bk)
			kgenome_diag_note(s, KGENOME_TRUNCATED);
	} else {
		/* the head is before this window began: the reads in that stretch were made by another window, and
		 * the hits from the head on are looked for in all of them */
		first = 0;
		hi = s->n_hit;
		while (first < hi) {
			const uint32_t mid = first + (hi - first) / 2u;

			if (s->hit[mid].at < in->target)
				first = mid + 1u;
			else
				hi = mid;
		}
		if (!body_links(s, first, 0))
			return;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
	}
	(void)body_links(s, first, 1);
}

/*
 * Take the registers and the stack slots of `snap` (the carry and the stack-pointer choice are the walk's own).
 *
 * THE WALK KEEPS ITS OWN DEPTH. The ring follows the stack pointer where the walk can compute it (push, pop,
 * add/sub of an immediate, leave, the frame pointer: see ring_follow in diag_origin.c), and where it cannot - a
 * move by a register, `alloca` - the depth is whatever the walk's own pushes and pops made it. Restoring the depth
 * the branch had would give the walk a depth it does not have there, so the slots below the walk's own depth are
 * the snapshot's - they are the same pushes - and the ones above it are not brought back: what a pop there would
 * have returned is lost. (Before the ring followed `add esp,N` the depth drifted by a slot for every cdecl call and
 * restoring it carried the drift to a hundred slots: 4 of 300 corpus files turned from whole to cut.)
 */
static void orgs_adopt(struct kgenome_diag_orgs *w, const struct kgenome_diag_orgs *snap)
{
	uint32_t i;

	memcpy(w->reg, snap->reg, sizeof w->reg);
	for (i = w->n_lost; i < w->n_stk; i++) {
		const unsigned k = i % KGENOME_DIAG_ORG_STK;

		if (i >= snap->n_lost && i < snap->n_stk) {
			w->stk[k] = snap->stk[k];
			memcpy(w->stk_alt_p1[k], snap->stk_alt_p1[k], sizeof w->stk_alt_p1[k]);
			w->stk_may[k] = snap->stk_may[k];
		} else {
			w->stk[k] = KGENOME_DIAG_ORG_NONE;
			memset(w->stk_alt_p1[k], 0, sizeof w->stk_alt_p1[k]);
			w->stk_may[k] = 0;
		}
	}
}

/* THE INSTRUCTION AT `in->at` IS WHERE SOME BRANCHES ARRIVE. `dead` is set when the walk's own line ended
 * just before (a ret or a jmp): then the target is reached by the branches alone. Returns 1 when one arrived. */
static int join_arrive(const struct sweep_rgn *rg, struct kgenome_diag_orgs *w,
		       const struct kgenome_cell_insn *in, uint8_t *dead)
{
	struct sweep_joins *jn = rg->jn;
	uint32_t i, k = 0;
	int arrived = 0;
	uint64_t min = UINT64_MAX;

	if (!jn || !jn->n || in->at < jn->min_at)
		return 0;
	for (i = 0; i < jn->n; i++) {
		struct sweep_join *e = &jn->e[i];

		if (e->at == in->at) {
			if (*dead && !arrived) {
				/* nothing flows in from the line before: the first path IS the state */
				if (e->empty) {
					kgenome_diag_org_kill(w, 0xffffu);
					(void)kgenome_diag_org_kill_stack(w);
				} else {
					orgs_adopt(w, &e->w);
				}
			} else if (kgenome_diag_org_merge(w, e->empty ? NULL : &e->w)) {
				kgenome_diag_note(rg->s, KGENOME_TRUNCATED);    /* a third producer was dropped */
			}
			arrived = 1;
		}
		if (e->at <= in->at) {
			if (e->live)
				jn->live--;
			continue;                       /* arrived, or passed: it will not arrive */
		}
		if (e->at < min)
			min = e->at;
		if (k != i)
			jn->e[k] = *e;
		k++;
	}
	jn->n = k;
	jn->min_at = min;
	if (arrived)
		*dead = 0;
	return arrived;
}

/* BEFORE the instruction runs: where a line that ended is resolved. */
static void sweep_control_in(const struct sweep_rgn *rg, struct kgenome_diag_orgs *w,
			     const struct kgenome_cell_insn *in, uint8_t *dead)
{
	const uint8_t how = *dead;

	if (join_arrive(rg, w, in, dead) || !how)
		return;
	if (in->op == KGENOME_CELL_NOP)
		return;                                 /* padding between a ret and the next label is not code */
	if (how == 1u) {
		/* after a ret, and nothing branches here: another function */
		kgenome_diag_org_kill(w, 0xffffu);
		(void)kgenome_diag_org_kill_stack(w);
	} else {
		/* after a jmp, and nothing branches here: reached by a call or a backward branch, not shown */
		kgenome_diag_org_demote(w, 0xffffu);
	}
	*dead = 0;
}

/* AFTER the instruction's own effect on the origin map. */
static void sweep_control_out(const struct sweep_rgn *rg, struct kgenome_diag_orgs *w,
			      const struct kgenome_cell_insn *in, uint8_t *dead)
{
	switch (in->op) {
	case KGENOME_CELL_JCC:
		if (in->target != KGENOME_BROKEN && in->target > in->at)
			join_add(rg, w, in);
		break;
	case KGENOME_CELL_JMP:
		if (!(in->flags & KGENOME_CELL_F_INDIRECT) && in->target != KGENOME_BROKEN && in->target > in->at)
			join_add(rg, w, in);
		*dead = tail_jmp(rg, in) ? 1u : 2u;     /* a tail call ends the line like a ret: see tail_jmp */
		break;
	case KGENOME_CELL_RET:
		*dead = 1u;
		break;
	case KGENOME_CELL_CALL:
		kgenome_diag_org_call(w, rg->ce, in, 0);
		break;
	default:
		break;
	}
}

static int sweep_window(const struct sweep_rgn *rg, uint64_t c, uint64_t at,
			const struct sweep_win *from, struct sweep_win *out,
			uint64_t *end, int *unread)
{
	struct kgenome_diag_scan *s = rg->s;
	const struct kgenome_obj *obj = rg->obj;
	const uint8_t *base = rg->base;
	const struct kgenome_cell_space *sp = rg->sp;
	const uint64_t off = rg->off, n = rg->n;
	struct sweep_joins *jn = rg->jn;
	const uint64_t lo = off + at;                   /* where this window begins reading */
	const uint32_t h0 = s->n_hit, u0 = s->n_unread; /* what the scan held when it began */
	const int resumed = from && from->live;
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	struct kgenome_diag_orgs w;
	uint32_t idle, r;
	uint16_t wrote;
	uint8_t dead;
	int pending, pass = 0;

	if (jn) {
		jn->nbk = 0;
		jn->saved = 0;
		if (resumed)
			jn_save(jn);                    /* so that the window can be read again: see back_edge */
	}
again:
	idle = 0;
	wrote = 0;
	dead = 0;
	pending = 0;
	*unread = 0;
	out->live = 0;
	if (resumed) {
		k = from->k;
		w = from->w;
		in = from->in;
		wrote = from->wrote;
		dead = from->dead;
		pending = 1;
		if (pass && jn && jn->saved)
			jn_restore(jn);
	} else {
		joins_reset(rg->jn);
		memset(&k, 0, sizeof k);
		memset(&w, 0, sizeof w);
		for (r = 0; r < 16u; r++)
			w.reg[r].node = KGENOME_DIAG_ORG_NONE;
		/* the stack pointer: r13 on ARM, x31 on AArch64 (not one of the sixteen tracked registers, so none is it);
		 * x86's is the default, 0 */
		w.sp = obj->arch == KGENOME_ARCH_ARM ? 13u : obj->arch == KGENOME_ARCH_ARM64 ? 31u : 0u;
		if (!kgenome_cell_seek(&k, off + at, 0))
			return 0;
	}
	/* the second pass: the loop heads the first one found are where another path arrives */
	if (pass && jn && jn->e)
		for (r = 0; r < jn->nbk; r++)
			back_register(rg, &jn->bk[r]);
	*end = at;
	for (;;) {
		if (pending)
			pending = 0;
		else if (!(k.at < off + n && kgenome_cell_next(&k, sp, &in)))
			break;
		/*
		 * PAST THE CANDIDATE, THE WALK RUNS ON WHAT IT IS
		 * STILL CARRYING - see the note on DIAG_IDLE.
		 */
		if (in.at >= off + c) {
			if (origins_live(rg, &w))
				idle = 0;
			else if (++idle > DIAG_IDLE) {
				/* The seam: this instruction is NOT taken. The window is
				 * put down with it held back - see struct sweep_win. */
				out->k = k;
				out->w = w;
				out->in = in;
				out->wrote = wrote;
				out->dead = dead;
				out->live = 1;
				*end = in.at - off;
				goto leave;
			}
		}
		sweep_control_in(rg, &w, &in, &dead);
		/*
		 * ARRIVING AT THE ARMED TARGET IS WHAT MAKES THE CARRY LIVE.
		 *
		 * The branch names where the success arm continues; the
		 * `syscall` that uses the left-behind zero is further on than
		 * that, with a pop or two in between. Comparing the armed
		 * address against the syscall's own address finds nothing -
		 * which it did, until this was split in two.
		 */
		if (w.carry_armed && in.at == w.carry_to) {
			w.carry_live = 1;
			w.carry_armed = 0;
		}
		/*
		 * `int 0x80` IS A SYSCALL AND THE DECODER DOES NOT SAY SO.
		 *
		 * KGENOME_CELL_SYSCALL is the `syscall` and `sysenter` instructions;
		 * i386 reaches the kernel through a software interrupt, which
		 * is KGENOME_CELL_INT and could be any vector. Reading only
		 * KGENOME_CELL_SYSCALL found ZERO nodes in every 32-bit payload here -
		 * msfvenom's i386 stagers are entirely `int 0x80`.
		 */
		if (kgenome_diag_kernel_entry(obj, in.op,
					  in.n_op && in.o[0].kind == KGENOME_CELL_O_IMM &&
					  in.o[0].imm == 0x80u,
					  base + in.at)) {
			const uint32_t n0 = s->n_hit;

			kgenome_diag_at_syscall(s, &k, &w, obj, &in);
			w.ax_stale = 1;
			/* THE CANDIDATE'S OWN site, and what it could not read is a
			 * value a wider window might find - see DIAG_LEAD_WIDE. */
			if (in.at == off + c && s->n_hit > n0 && !kgenome_diag_fixed_arch(obj)) {
				const struct kgenome_diag_hit *h = &s->hit[n0];
				const uint8_t *ar;
				int n_ar = kgenome_diag_arg_regs(obj, &ar), q;

				if (h->cap == KGENOME_NUCLEO_NONE &&
				    (h->bits & KGENOME_DIAG_H_OPAQUE)) {
					/* the NUMBER: only if nothing in the window wrote eax */
					if (!(wrote & (1u << KGENOME_CELL_REG_AX)))
						*unread = 1;
				} else if (h->bits & KGENOME_DIAG_H_ARG_UNKNOWN) {
					/* an argument that decides what the node IS - mmap's
					 * prot, a socket's type: only one nothing wrote */
					for (q = 0; q < 3 && q < n_ar; q++)
						if (!(wrote & (1u << ar[q])))
							*unread = 1;
				}
			}
		} else if (in.op == KGENOME_CELL_JCC) {
			/*
			 * ARM THE CARRY AT THE FIRST BRANCH AFTER A
			 * ZERO-ON-SUCCESS CALL, and do not let a later one
			 * take it - see the note on walk.carry_to for the
			 * three shapes measured.
			 */
			if (!w.carry_armed && s->n_hit &&
			    (s->hit[s->n_hit - 1u].bits & KGENOME_DIAG_H_ZERO_OK) &&
			    in.target != KGENOME_BROKEN && in.target > in.at) {
				w.carry_to = in.target;
				w.carry_armed = 1;
			}
		} else if ((in.op == KGENOME_CELL_JMP || in.op == KGENOME_CELL_CALL) &&
			   in.n_op && in.o[0].kind == KGENOME_CELL_O_REG) {
			/*
			 * AN INDIRECT BRANCH IS ONLY INTERESTING WHEN IT GOES
			 * SOMEWHERE THIS WALK WATCHED BEING MADE.
			 *
			 * Every vtable, every callback and every PLT-less
			 * call is `call reg`; MEASURED, 447 of them in one
			 * 1.1 MB sample and at least one in 834 of 846 clean
			 * binaries. Emitting a node for all of them would put
			 * this capability in nearly every file on a machine.
			 * A branch into a region an earlier node established
			 * is a different statement entirely.
			 */
			uint16_t t = kgenome_diag_org_of(&w, in.o[0].reg);

			if (t != KGENOME_DIAG_ORG_NONE) {
				struct kgenome_diag_hit *h =
					kgenome_diag_hit_add(s, in.at, KGENOME_NUCLEO_EXEC_REG, 0);

				kgenome_diag_org_link(s, h, &w, in.o[0].reg, KGENOME_DIAG_ROLE_TARGET,
				 KGENOME_DIAG_KIND_PRODUCED);
			}
		}
		if (in.wmask & (1ull << KGENOME_CELL_REG_AX))
			w.ax_stale = 0; /* something wrote it since */
		wrote |= (uint16_t)in.wmask;
		kgenome_diag_org_step(&w, &in);
		sweep_control_out(rg, &w, &in, &dead);
		back_edge(rg, &w, &in, lo, h0, pass, resumed);
		if (w.stk_cut) {
			w.stk_cut = 0;
			kgenome_diag_note(s, KGENOME_TRUNCATED);        /* an origin fell off the end of the stack ring */
		}
		if (s->halt)
			return 0;
	}
	*end = k.at > off ? k.at - off : 0;
leave:
	/* A BACK EDGE with a claim to take back: the same window again, from the same start, with the loop heads merged
	 * in - and what the first pass made dropped, as the wider-lead retry drops its first attempt's nodes. */
	if (!pass && jn && jn->nbk && !s->halt) {
		pass = 1;
		s->n_hit = h0;
		s->n_unread = u0;
		goto again;
	}
	return 1;
}

static void sweep_region(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, uint64_t off,
			 uint64_t n)
{
	struct kgenome_cell_space sp;
	struct sweep_win susp, nxt;
	struct sweep_rgn rg;
	struct kgenome_diag_callees ce;
	struct sweep_joins *jn;
	uint64_t c, done = 0;

	if (!n || off >= size)
		return;
	if (off + n > size)
		n = size - off;
	kgenome_cell_space_init(&sp, obj, base, size);
	/* The walk already decoded this code and kept it: read it from there. */
	kgenome_diag_walk_hold(&sp, s->walk);
	rg.s = s; rg.obj = obj; rg.base = base; rg.sp = &sp; rg.off = off; rg.n = n;
	kgenome_diag_callees_init(&ce, &sp, obj->arch, off, n);
	rg.ce = &ce;
	{
		const struct kgenome_elf_info *ei = obj->format == KGENOME_FMT_ELF ? kgenome_obj_elf(obj) : NULL;
		struct kgenome_elf_symtab st;

		rg.has_syms = ei && ei->valid && kgenome_elf_symtab_of(kof_buf_make(base, size), ei, KGENOME_ELF_SYMTAB_FULL, &st);
	}
	/*
	 * THE PENDING JOINS and what callees were read: charged to the scan's ledger and given back when the
	 * region is done. Without the table (a refusal the ledger or the allocator already reported) every
	 * forward branch makes what is carried MAY, which keeps the link and drops the claim.
	 */
	jn = calloc(1, sizeof *jn);
	if (!jn) {
		kgenome_diag_note(s, KGENOME_NOMEM);
	} else {
		if (kgenome_ledger_charge(&s->led, JOIN_BYTES)) {
			jn->e = malloc(DIAG_JOIN_MAX * sizeof *jn->e);
			jn->e0 = malloc(DIAG_JOIN_MAX * sizeof *jn->e0);
			jn->bk = malloc(DIAG_BACK_MAX * sizeof *jn->bk);
			if (!jn->e || !jn->e0 || !jn->bk) {
				free(jn->e); free(jn->e0); free(jn->bk);
				jn->e = NULL; jn->e0 = NULL; jn->bk = NULL;
				kgenome_ledger_release(&s->led, JOIN_BYTES);
				kgenome_diag_note(s, KGENOME_NOMEM);
			}
		}
		joins_reset(jn);
	}
	rg.jn = jn;
	memset(&susp, 0, sizeof susp);
	memset(&nxt, 0, sizeof nxt);

	/*
	 * ONE WINDOW PER CANDIDATE, AND THE NEXT ONE STARTS WHERE THIS ONE
	 * STOPPED. A candidate the previous window already walked over is
	 * not walked again - two syscalls a few instructions apart are one
	 * window, which is also the only way the second one sees what the
	 * first produced.
	 */
#define CAND(from) (kgenome_diag_fixed_arch(obj) ? kgenome_diag_cand_fixed(obj, base + off, off, (from), n) \
				    : kgenome_diag_cand_at(base + off, (from), n))
	for (c = CAND(0); c < n; c = CAND(c + 1u)) {
		uint64_t lead = DIAG_LEAD, at, end = done;
		const uint32_t hits0 = s->n_hit, unread0 = s->n_unread;
		int unread = 0, stop = 0;

		if (c < done)
			continue;       /* already walked, see above */
		for (;;) {
			const struct sweep_win *from = NULL;

			/* KNOWN DEFECT X10 (2026-10-24, M) [sev M]: the fresh window starts at c - lead, a byte and not an instruction boundary, so a
			 * decode from mid-instruction can swallow the candidate's own `0f 05`. Trigger: a syscall site not reached by an
			 * earlier window (a ret now ends it). Effect: the `execve` stub at 0x19ba12 of one libc is gone (4 files: cells 162,
			 * corp300 069/092/116); aligning finds 44 more nodes. Reproducer: /mnt/games/normtest/fix_gbin/repro. Fix: start at
			 * the first of the 15 bytes that lands ON the candidate (adds nodes: owner decision on identity). */
			at = c > lead ? c - lead : 0;
			/* A lead that reaches the point a window was put down at
			 * picks it up (struct sweep_win); one that does not starts
			 * fresh at its own lead. */
			if (susp.live && at <= done) {
				from = &susp;
				at = done;
			} else if (at < done) {
				at = done;
			}
			if (!sweep_window(&rg, c, at, from, &nxt, &end, &unread)) {
				stop = 1;       /* the node store is full, or no seek */
				break;
			}
			/* Read, or no wider window exists (it already starts at the
			 * end of the last one) - the answer stands. */
			if (!unread || lead >= DIAG_LEAD_WIDE || at <= done)
				break;
			/* Unread and clipped by the lead: again from further back, and
			 * the first attempt's nodes are dropped. */
			s->n_hit = hits0;
			s->n_unread = unread0;
			lead = DIAG_LEAD_WIDE;
		}
		if (stop)
			break;
		susp = nxt;             /* the window this candidate left, if any */
		/* STILL UNREAD AT THE WIDEST LEAD, with the window clipped by it:
		 * the argument may be set further back than anyone looked. */
		if (unread && lead >= DIAG_LEAD_WIDE && c > lead && at > done)
			kgenome_diag_note(s, KGENOME_TRUNCATED);
		done = end;
	}
#undef CAND
	if (jn) {
		if (jn->e) {
			free(jn->e);
			free(jn->e0);
			free(jn->bk);
			kgenome_ledger_release(&s->led, JOIN_BYTES);
		}
		free(jn);
	}
}

static void sweep_elf(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
		      const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	uint32_t i;

	if (!e || !e->valid)
		return;
	for (i = 0; i < kgenome_diag_extent_count(obj); i++) {
		uint64_t at, have = kgenome_diag_extent(obj, i, size, &at);

		if (!have)
			continue;
		sweep_region(s, obj, base, size, at, have);
		if (s->halt)
			return;
	}
}

void kgenome_diag_run_syscall(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size)
{
	/*
	 * THE EXECUTABLE SEGMENTS WHEN THERE ARE ANY, the whole object when
	 * there are not. A payload lifted out of a variable has no program
	 * header and is still code.
	 */
	if (obj->format == KGENOME_FMT_ELF) {
		sweep_elf(s, obj, base, size);
		/* The wrapper resolution reads x86 call sites and pushes. */
		if (!kgenome_diag_fixed_arch(obj) && (s->n_wrap || s->n_unread))
			kgenome_diag_run_wrappers(s, obj, base, size);
	} else
		sweep_region(s, obj, base, size, 0, size);
}
