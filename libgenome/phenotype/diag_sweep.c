/*
 * diag_sweep.c - the sweep: windows around each candidate, a region, the ELF segments, and the syscall routine.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

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
	struct sweep_joins *jn;         /* the pending joins and the callee answers, the region's */
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
 *              join the origins are kept and become MAY: reached, not shown. A tail jump into another
 *              function is not told apart from these - listed as a limit, not guessed.
 *   CALL       what the callee does to the registers. A direct callee that is straight line to its
 *              `ret` is READ (callee_scan): a register it writes loses its origin, one it does not
 *              write keeps it, one it pushes and pops is not written. A callee with a branch or a call
 *              in it, one outside the region, an indirect call: the registers the ABI lets a callee
 *              overwrite keep their origin as MAY and the rest are unchanged. `call next` and a callee
 *              that begins by popping the return address are not calls: they fetch the program counter.
 *   JOIN       a forward branch (a `jcc`, or a `jmp`) is where a second path will arrive. The origin
 *              map as it was when the walk left is remembered at the target, and the walk that reaches
 *              the target merges it: two different producers are both kept (the second is a MAY link),
 *              and a producer only one path holds is MAY, because the other path has no such value.
 *
 * BACK EDGES ARE NOT MODELLED (a value written in a loop body and read at the top of the next pass):
 * listed as a limit. A cap that fires reports: the table of pending joins holds DIAG_JOIN_MAX, and a
 * branch that cannot be remembered makes what is carried MAY and says KGENOME_TRUNCATED. A table the ledger
 * or the allocator refused is the same loss said by that refusal (over-budget, nomem): the walk is then the
 * straight line it was before, with its calls and returns handled.
 *
 * Why MAY and not nothing, where the walk does not know: a link is kept when the program can produce
 * it (the matcher does not read how sure a link is - see linked() in kofdiag.c), and the report says
 * how sure it is.
 */
#define DIAG_JOIN_MAX    256u
/* A pending join farther ahead than this does not keep a window open: the walk would read a function to
 * reach it, and the window ends where the origins end (DIAG_IDLE) as it always did. */
#define DIAG_JOIN_REACH  4096u
/* How far a callee is read for what it writes. Past it the callee is not known. */
#define DIAG_CALLEE_INSN 64u
#define DIAG_CALLEE_MEMO 64u

/* the registers a callee may overwrite, by the ABI of the architecture: eax/ecx/edx, the System V
 * integer registers, r0-r3 and r12, x0-x15 (x16 and x17 are not tracked) */
static uint16_t caller_saved(const struct kgenome_obj *obj)
{
	switch (obj->arch) {
	case KGENOME_ARCH_X86_64: return 0x0fc7u;
	case KGENOME_ARCH_ARM:    return 0x100fu;
	case KGENOME_ARCH_ARM64:  return 0xffffu;
	default:                  return 0x0007u;
	}
}

/* a pending forward transfer: where it arrives and what the walk held when it left */
struct sweep_join {
	uint64_t at;
	uint8_t  empty;         /* the walk held no origin: nothing to copy */
	uint8_t  live;          /* counted in sweep_joins.live */
	struct kgenome_diag_orgs w;
};

struct sweep_callee {
	uint64_t target;
	uint16_t writes;
	uint8_t  kind;          /* enum callee_kind, 0 for an empty slot */
};

/* THE REGION'S, shared by its windows (a window that resumes another continues the same table; one that
 * starts fresh empties it). */
struct sweep_joins {
	struct sweep_join *e;   /* NULL: no memory (said by the ledger or the allocator): no joins are remembered */
	uint32_t n, live;
	uint64_t min_at;
	struct sweep_callee memo[DIAG_CALLEE_MEMO];
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

/*
 * Take the registers and the stack slots of `snap` (the carry and the stack-pointer choice are the walk's own).
 *
 * THE WALK KEEPS ITS OWN DEPTH. The ring counts `push` and `pop` and nothing else, so a function that makes room
 * with `sub esp` or takes arguments back with `add esp` leaves a depth the program does not have, and it grows
 * with every cdecl call. The old walk lost that depth at every early epilogue (its pops ran the count down) and
 * so stayed shallow by accident; restoring the depth the branch had would carry the drift to a hundred slots and
 * make the ring overflow in a long window (MEASURED: 4 of 300 corpus files turned from whole to cut). So the
 * slots below the walk's own depth are the snapshot's - they are the same pushes - and the ones above it are
 * not brought back: what a pop there would have returned is lost, as it was.
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

enum callee_kind { CALLEE_NONE = 0, CALLEE_UNKNOWN, CALLEE_KNOWN, CALLEE_GETPC };

/*
 * WHAT A DIRECT CALLEE WRITES, read from its first instruction to the first `ret`. Only a straight line
 * is a statement: a branch or a call inside it makes the other paths unread, and "unknown" is the answer.
 * A register pushed before anything wrote it and popped back is not written (`push rbx; ...; pop rbx`).
 * The bound is DIAG_CALLEE_INSN and the answers are remembered per target (DIAG_CALLEE_MEMO), so a call
 * in a loop costs one reading.
 */
static int callee_scan(const struct sweep_rgn *rg, const struct kgenome_cell_insn *call, uint16_t *writes)
{
	struct sweep_joins *jn = rg->jn;
	struct kgenome_cell_cur kc;
	struct kgenome_cell_insn ci;
	uint16_t mask = 0, pushed = 0, restored = 0;
	unsigned i, slot = (unsigned)((call->target * 0x9e3779b97f4a7c15ull) >> 58);
	int kind = CALLEE_UNKNOWN;

	*writes = 0;
	if (call->target == call->at + call->len)
		return CALLEE_GETPC;                    /* `call next`: the address of the next instruction */
	if (jn && jn->memo[slot].kind && jn->memo[slot].target == call->target) {
		*writes = jn->memo[slot].writes;
		return jn->memo[slot].kind;
	}
	if (call->target < rg->off || call->target >= rg->off + rg->n)
		return CALLEE_UNKNOWN;
	memset(&kc, 0, sizeof kc);
	if (!kgenome_cell_seek(&kc, call->target, 0))
		return CALLEE_UNKNOWN;
	for (i = 0; i < DIAG_CALLEE_INSN; i++) {
		if (!(kc.at < rg->off + rg->n && kgenome_cell_next(&kc, rg->sp, &ci)))
			break;
		if (i == 0 && ci.op == KGENOME_CELL_POP) {
			kind = CALLEE_GETPC;            /* it takes its own return address off the stack */
			break;
		}
		if (ci.op == KGENOME_CELL_RET) {
			mask = (uint16_t)(mask & ~(pushed & restored));
			kind = CALLEE_KNOWN;
			break;
		}
		if (ci.op == KGENOME_CELL_CALL || ci.op == KGENOME_CELL_JMP || ci.op == KGENOME_CELL_JCC ||
		    ci.op == KGENOME_CELL_LOOP || ci.op == KGENOME_CELL_IRET)
			break;                          /* the paths are not all read */
		if (ci.op == KGENOME_CELL_PUSH && ci.n_op && ci.o[0].kind == KGENOME_CELL_O_REG && ci.o[0].reg < 16u &&
		    !(mask & (1u << ci.o[0].reg)))
			pushed = (uint16_t)(pushed | (1u << ci.o[0].reg));
		if (ci.op == KGENOME_CELL_POP && ci.n_op && ci.o[0].kind == KGENOME_CELL_O_REG && ci.o[0].reg < 16u &&
		    (pushed & (1u << ci.o[0].reg)))
			restored = (uint16_t)(restored | (1u << ci.o[0].reg));
		mask = (uint16_t)(mask | (uint16_t)(ci.wmask & 0xffffu));
	}
	*writes = kind == CALLEE_KNOWN ? mask : 0u;
	if (jn) {
		jn->memo[slot].target = call->target;
		jn->memo[slot].writes = *writes;
		jn->memo[slot].kind = (uint8_t)kind;
	}
	return kind;
}

/* A CALL, for the origin map: see the note above. */
static void sweep_call(const struct sweep_rgn *rg, struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in)
{
	const uint16_t cs = caller_saved(rg->obj);
	uint16_t live = 0, writes = 0;
	unsigned r;

	for (r = 0; r < 16u; r++)
		if ((cs & (1u << r)) && w->reg[r].node != KGENOME_DIAG_ORG_NONE)
			live = (uint16_t)(live | (1u << r));
	if (!live)
		return;
	if ((in->flags & KGENOME_CELL_F_INDIRECT) || in->target == KGENOME_BROKEN) {
		kgenome_diag_org_demote(w, live);
		return;
	}
	switch (callee_scan(rg, in, &writes)) {
	case CALLEE_GETPC:
		break;
	case CALLEE_KNOWN:
		kgenome_diag_org_kill(w, (uint16_t)(live & writes));
		break;
	default:
		kgenome_diag_org_demote(w, live);
		break;
	}
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
		*dead = 2u;
		break;
	case KGENOME_CELL_RET:
		*dead = 1u;
		break;
	case KGENOME_CELL_CALL:
		sweep_call(rg, w, in);
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
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	struct kgenome_diag_orgs w;
	uint32_t idle = 0, r;
	uint16_t wrote = 0;
	uint8_t dead = 0;
	int pending = 0;

	*unread = 0;
	out->live = 0;
	if (from && from->live) {
		k = from->k;
		w = from->w;
		in = from->in;
		wrote = from->wrote;
		dead = from->dead;
		pending = 1;
	} else {
		joins_reset(rg->jn);
		memset(&k, 0, sizeof k);
		memset(&w, 0, sizeof w);
		for (r = 0; r < 16u; r++)
			w.reg[r].node = KGENOME_DIAG_ORG_NONE;
		w.sp = obj->arch == KGENOME_ARCH_ARM ? 13u : 0u;
		if (!kgenome_cell_seek(&k, off + at, 0))
			return 0;
	}
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
				return 1;
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
		if (w.stk_cut) {
			w.stk_cut = 0;
			kgenome_diag_note(s, KGENOME_TRUNCATED);        /* an origin fell off the end of the stack ring */
		}
		if (s->halt)
			return 0;
	}
	*end = k.at > off ? k.at - off : 0;
	return 1;
}

static void sweep_region(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, uint64_t off,
			 uint64_t n)
{
	struct kgenome_cell_space sp;
	struct sweep_win susp, nxt;
	struct sweep_rgn rg;
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
	/*
	 * THE PENDING JOINS and what callees were read: charged to the scan's ledger and given back when the
	 * region is done. Without the table (a refusal the ledger or the allocator already reported) every
	 * forward branch makes what is carried MAY, which keeps the link and drops the claim.
	 */
	jn = calloc(1, sizeof *jn);
	if (!jn) {
		kgenome_diag_note(s, KGENOME_NOMEM);
	} else {
		if (kgenome_ledger_charge(&s->led, DIAG_JOIN_MAX * sizeof *jn->e)) {
			jn->e = malloc(DIAG_JOIN_MAX * sizeof *jn->e);
			if (!jn->e) {
				kgenome_ledger_release(&s->led, DIAG_JOIN_MAX * sizeof *jn->e);
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
			kgenome_ledger_release(&s->led, DIAG_JOIN_MAX * sizeof *jn->e);
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
