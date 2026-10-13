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

/* Is anything from an earlier node still being carried? */
static int origins_live(const struct kgenome_diag_orgs *w)
{
	uint32_t i;

	if (w->carry_armed || w->carry_live)
		return 1;
	for (i = 0; i < 16u; i++)
		if (w->reg[i].node != KGENOME_DIAG_ORG_NONE)
			return 1;
	for (i = 0; i < w->n_stk && i < KGENOME_DIAG_ORG_STK; i++)
		if (w->stk[i].node != KGENOME_DIAG_ORG_NONE)
			return 1;
	return 0;
}

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
};

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
	int pending = 0;

	*unread = 0;
	out->live = 0;
	if (from && from->live) {
		k = from->k;
		w = from->w;
		in = from->in;
		wrote = from->wrote;
		pending = 1;
	} else {
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
			if (origins_live(&w))
				idle = 0;
			else if (++idle > DIAG_IDLE) {
				/* The seam: this instruction is NOT taken. The window is
				 * put down with it held back - see struct sweep_win. */
				out->k = k;
				out->w = w;
				out->in = in;
				out->wrote = wrote;
				out->live = 1;
				*end = in.at - off;
				return 1;
			}
		}
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

				kgenome_diag_note_in(s, h, t, KGENOME_DIAG_ROLE_TARGET,
				 KGENOME_DIAG_KIND_PRODUCED);
			}
		}
		if (in.wmask & (1ull << KGENOME_CELL_REG_AX))
			w.ax_stale = 0; /* something wrote it since */
		wrote |= (uint16_t)in.wmask;
		kgenome_diag_org_step(&w, &in);
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
	uint64_t c, done = 0;

	if (!n || off >= size)
		return;
	if (off + n > size)
		n = size - off;
	kgenome_cell_space_init(&sp, obj, base, size);
	rg.s = s; rg.obj = obj; rg.base = base; rg.sp = &sp; rg.off = off; rg.n = n;
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
			return;
		susp = nxt;             /* the window this candidate left, if any */
		/* STILL UNREAD AT THE WIDEST LEAD, with the window clipped by it:
		 * the argument may be set further back than anyone looked. */
		if (unread && lead >= DIAG_LEAD_WIDE && c > lead && at > done)
			kgenome_diag_note(s, KGENOME_TRUNCATED);
		done = end;
	}
#undef CAND
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
