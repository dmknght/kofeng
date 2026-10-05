/*
 * kofdiag.c - the nodes an object holds, and what links them.
 *
 * WHAT THIS IS NOT. It is not a decompiler and it does not try to be. It
 * answers two questions about a piece of code and refuses the rest:
 *
 *   - this `syscall` instruction, or this call: which nucleo group is it?
 *   - this node's buffer, or its jump target: which earlier node did that
 *     value come from?
 *
 * Everything a decompiler exists for - the shape of the control flow, the
 * types, the names, a listing a person reads - is absent on purpose. The
 * two questions above are what a diagnose is written against, and nothing
 * else here has a caller.
 *
 * WHY A VALUE MODEL AT ALL, when kdis already keeps a constant map. The
 * constant map answers "what number is in this register"; this needs
 * "which NODE did this value come from", which is a different question and
 * survives where the first does not: a pointer stays a pointer through a
 * push and a pop whether or not anyone knows its address.
 */

#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofdiag.h"
#include "../../kofcore/kofmod/elf.h"
#include "../../analyzers/parsers/binaries/disasm/kdis.h"
#include "../../analyzers/parsers/binaries/disasm/nucleo.h"

/*
 * HOW MANY NODES ONE OBJECT MAY HOLD.
 *
 * A BOUND ON COST AND NOT ON EVIDENCE, which is the distinction rule 4 of
 * the tree's conventions turns on. Hitting it is reported - see
 * kof_diag_scan_full - so a caller asking "is this capability absent" gets
 * "cannot say" rather than "no". Measured: the largest object in the
 * sample set here produced 701 nodes, of which 447 were indirect calls
 * that resolve to nothing; a real shellcode region produces seven.
 */
#define DIAG_MAX_NODE 4096u

/* How many inputs of one node are recorded as coming from somewhere. A
 * read has two that matter (the buffer and the descriptor); nothing seen
 * has needed more than three. */
#define DIAG_MAX_IN 4u

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofdiag.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */

struct kof_diag_scan {
	struct kof_diag_hit *hit;
	uint32_t             n_hit;
	uint32_t             cap_hit;
	int                  full;      /* the bound above was reached */
};

static int hit_room(struct kof_diag_scan *s)
{
	struct kof_diag_hit *nv;
	uint32_t nc;

	if (s->n_hit < s->cap_hit)
		return 1;
	if (s->n_hit >= DIAG_MAX_NODE) {
		s->full = 1;
		return 0;
	}
	nc = s->cap_hit ? s->cap_hit * 2u : 64u;
	if (nc > DIAG_MAX_NODE)
		nc = DIAG_MAX_NODE;
	nv = realloc(s->hit, nc * sizeof *nv);
	if (!nv) {
		s->full = 1;
		return 0;
	}
	s->hit = nv;
	s->cap_hit = nc;
	return 1;
}

static struct kof_diag_hit *hit_add(struct kof_diag_scan *s, uint64_t at,
				    uint16_t cap, uint16_t flags)
{
	struct kof_diag_hit *h;

	if (!hit_room(s))
		return NULL;
	h = &s->hit[s->n_hit++];
	memset(h, 0, sizeof *h);
	h->at = at;
	h->cap = cap;
	h->flags = flags;
	return h;
}

/* ---- where a value came from ---------------------------------------------
 *
 * A SHADOW BESIDE kdis's CONSTANT MAP, not a replacement for it. The two
 * answer different questions and neither covers the other: the constant map
 * says WHAT NUMBER a register holds, this says WHICH NODE it came out of. A
 * pointer stays a pointer through a push and a pop whether or not anyone
 * knows its address, and a number can be known while coming from nowhere.
 */

#define ORG_NONE  0xffffu
#define ORG_STACK 0xfffeu

struct org {
	uint16_t node;          /* index, ORG_NONE, or ORG_STACK */
};

/* Small, because what travels this way is a handful of pointers across a
 * few dozen instructions. A deeper stack than this in a region that matters
 * has not been seen; overflowing it loses provenance, which degrades a link
 * to unknown rather than making one up. */
#define ORG_STK 32u

struct walk {
	struct org reg[16];
	struct org stk[ORG_STK];
	uint32_t   n_stk;
	/*
	 * THE ONE SLOT THAT CARRIES A SYSCALL NUMBER ACROSS A BRANCH.
	 *
	 * msfvenom writes `connect; jns L` and then a bare `syscall` at L
	 * with rax still holding connect's zero - which on x86-64 is `read`,
	 * because read is syscall 0 there. Reading straight down the
	 * addresses loses it: the FAILURE arm sits in between and clobbers
	 * rax. See kof_sys_zero_on_success, which nucleo.h already documents
	 * with this very sample.
	 *
	 * ONE SLOT, WRITTEN ONCE. Three shapes were measured. A full
	 * register snapshot at every branch target costs ~150 bytes per
	 * branch, is unbounded, and REMOVING IT LOST NOTHING - 9 of 9
	 * samples still matched. A table of carry flags by target works but
	 * is still a table. One slot that is OVERWRITTEN fails, because the
	 * `je` of the retry counter follows the `jns` and takes it. One slot
	 * WRITTEN ONCE and cleared when consumed matches all nine - and a
	 * dispatcher with two hundred arms still costs one slot, because the
	 * second branch does not overwrite.
	 */
	uint64_t   carry_to;
	int        carry_armed;         /* a target is waiting to be reached */
	int        carry_live;          /* the walk has arrived at it       */
	/*
	 * THE RESULT REGISTER HOLDS A RESULT, AND NOBODY KNOWS WHAT IT IS.
	 *
	 * kdis's constant map cannot know this: a `syscall` instruction does
	 * not WRITE rax as far as the decoder is concerned - the number goes
	 * in, and the kernel puts the answer back. That is an ABI fact and
	 * the decoder has no business holding one. So the map keeps whatever
	 * number went IN, and a later site reads it as if it were its own.
	 *
	 * MEASURED: reading straight down msfvenom's x86-64 stager, the
	 * `exit` on the failure arm leaves 0x3c in the map, and the `read`
	 * two instructions later came back as exit. Not missing - WRONG,
	 * which is the worse of the two.
	 */
	int        ax_stale;
};

static void org_clear(struct walk *w, uint8_t r)
{
	if (r < 16u)
		w->reg[r].node = ORG_NONE;
}

static uint16_t org_of(const struct walk *w, uint8_t r)
{
	return r < 16u ? w->reg[r].node : ORG_NONE;
}

static void org_set(struct walk *w, uint8_t r, uint16_t node)
{
	if (r < 16u)
		w->reg[r].node = node;
}

/*
 * FORGET WHAT EVERY REGISTER THIS INSTRUCTION WRITES CAME FROM, then put
 * back the one case this follows.
 *
 * `wmask` and not the first operand, for the reason kdis_track records: an
 * instruction writes registers it does not name, and names registers it
 * only reads. Getting that backwards on `mul` cost the i386 samples their
 * whole network half.
 */
static void org_step(struct walk *w, const struct kdis_insn *in)
{
	uint8_t r, d, e;

	if (in->op == KDIS_PUSH) {
		uint16_t v = ORG_NONE;

		if (in->n_op && in->o[0].kind == KDIS_O_REG)
			v = org_of(w, in->o[0].reg);
		if (w->n_stk < ORG_STK)
			w->stk[w->n_stk].node = v;
		w->n_stk++;
		return;
	}
	if (in->op == KDIS_POP) {
		uint16_t v = ORG_NONE;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk < ORG_STK)
				v = w->stk[w->n_stk].node;
		}
		if (in->n_op && in->o[0].kind == KDIS_O_REG)
			org_set(w, in->o[0].reg, v);
		return;
	}
	if (in->op == KDIS_XCHG && in->n_op > 1u &&
	    in->o[0].kind == KDIS_O_REG && in->o[1].kind == KDIS_O_REG) {
		uint16_t a;

		d = in->o[0].reg; e = in->o[1].reg;
		a = org_of(w, d);
		org_set(w, d, org_of(w, e));
		org_set(w, e, a);
		return;
	}
	if (in->op == KDIS_MOV && in->n_op > 1u &&
	    in->o[0].kind == KDIS_O_REG && in->o[0].size >= 4u) {
		if (in->o[1].kind == KDIS_O_REG) {
			/*
			 * A VALUE TAKEN FROM THE STACK POINTER IS A STACK
			 * ADDRESS, and that is a provenance of its own.
			 * msfvenom's i386 stager makes the stack executable
			 * and jumps into it; mprotect returns 0, so there is
			 * no pointer to follow from the allocation to the
			 * jump and the only thing that links them is that
			 * both addresses came off esp.
			 */
			org_set(w, in->o[0].reg,
				in->o[1].reg == KDIS_REG_SP ? ORG_STACK
				: org_of(w, in->o[1].reg));
			return;
		}
		org_clear(w, in->o[0].reg);
		return;
	}
	/*
	 * AND/SHR/SHL OVER A STACK ADDRESS IS STILL A STACK ADDRESS. The
	 * i386 stager rounds esp down to a page with `shr 0xc; shl 0xc`
	 * before handing it to mprotect; killing the provenance there breaks
	 * the only link that sample has.
	 */
	if ((in->op == KDIS_AND || in->op == KDIS_SHR || in->op == KDIS_SHL) &&
	    in->n_op && in->o[0].kind == KDIS_O_REG &&
	    org_of(w, in->o[0].reg) == ORG_STACK)
		return;

	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r))
			org_clear(w, r);
}

/* ---- the walk ------------------------------------------------------------ */

/*
 * THE ARGUMENT REGISTERS, per ABI, in order.
 *
 * Taken from nucleo's fxabi rather than written again here - a second copy
 * of "rdi, rsi, rdx, r10, r8, r9" is a second thing to get wrong when a
 * port is added, and the sweep that had its own copy is the reason this
 * rule exists.
 */
static int arg_regs(const struct kof_obj_ctx *ctx, const uint8_t **out)
{
	static const uint8_t x64[] = { KDIS_REG_DI, KDIS_REG_SI, KDIS_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t x86[] = { KDIS_REG_BX, KDIS_REG_CX, KDIS_REG_DX,
				       KDIS_REG_SI, KDIS_REG_DI, KDIS_REG_BP };

	if (ctx->arch == KOF_ARCH_X86_64) {
		*out = x64;
		return (int)(sizeof x64 / sizeof x64[0]);
	}
	if (ctx->arch == KOF_ARCH_X86) {
		*out = x86;
		return (int)(sizeof x86 / sizeof x86[0]);
	}
	*out = NULL;
	return 0;
}

/*
 * ONE SYSCALL SITE.
 *
 * The number comes out of the constant map, which is why this file needs
 * kdis at all. When it is not there the node is still emitted, as
 * KOF_CAP_NONE with KOF_DIAG_H_OPAQUE set - see the note on that flag. A
 * site dropped because its number could not be read is a site that makes
 * two different programs look alike.
 */
static void note_in(struct kof_diag_hit *h, uint16_t from, uint8_t role)
{
	if (!h || from == ORG_NONE || h->n_in >= 4u)
		return;
	h->in[h->n_in].from = from;
	h->in[h->n_in].role = role;
	h->in[h->n_in].how  = KOF_DIAG_LINK_PROVEN;
	h->n_in++;
}

static void at_syscall(struct kof_diag_scan *s, struct kof_kdis *k,
		       struct walk *w, const struct kof_obj_ctx *ctx,
		       uint64_t at)
{
	const uint8_t *ar;
	uint64_t nr = 0, arg[6];
	struct kof_diag_hit *h;
	const char *nm;
	uint16_t cap;
	uint8_t fl = 0;
	int n_ar, i, bits;
	unsigned have = 0;          /* which of arg[] came from a known register */

	bits = ctx->arch == KOF_ARCH_X86_64 ? 64 : 32;
	n_ar = arg_regs(ctx, &ar);
	if (w->ax_stale || !kof_kdis_reg(k, KDIS_REG_AX, &nr) ||
	    nr > 0xffffu) {
		/*
		 * THE NUMBER MAY STILL BE THERE, left by the syscall before
		 * it - see walk.carry_to. Only on x86-64, where `read` is
		 * zero and a zero-on-success return therefore IS a syscall
		 * number; on i386 read is 3 and the trick does not exist.
		 */
		if (bits == 64 && w->carry_live) {
			nr = 0;
			w->carry_live = 0;
		} else {
			h = hit_add(s, at, KOF_CAP_NONE, 0);
			if (h)
				h->bits |= KOF_DIAG_H_OPAQUE;
			return;
		}
	}
	/*
	 * WHICH ARGUMENTS WERE ACTUALLY READ, as a mask beside the values.
	 *
	 * Handing a zero for one that was not read is not a neutral default:
	 * nucleo refines a capability by testing bits in an argument, so an
	 * unread prot reads as "no PROT_EXEC" and an allocation about to
	 * hold code is recorded as an ordinary buffer. The mask is what lets
	 * the node say it does not know instead.
	 */
	for (i = 0; i < n_ar && i < 6; i++) {
		if (kof_kdis_reg(k, ar[i], &arg[i]))
			have |= 1u << i;
		else
			arg[i] = 0;
	}
	for (; i < 6; i++)
		arg[i] = 0;

	cap = kof_flow_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
	nm  = kof_sys_name((unsigned)bits, (uint32_t)nr);
	if (cap == KOF_CAP_NONE)
		return;                 /* a syscall the vocabulary has no word for */
	h = hit_add(s, at, cap, fl);
	if (!h)
		return;
	/*
	 * The third argument is the one that separates a code region from a
	 * buffer, and the first two separate a socket from a raw socket.
	 * Unread, the node says so rather than carrying the answer those
	 * bits would have given if they had been zero.
	 */
	if ((cap == KOF_CAP_ALLOC && !(have & (1u << 2))) ||
	    (cap == KOF_CAP_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KOF_DIAG_H_ARG_UNKNOWN;

	/*
	 * WHICH OF THIS CALL'S INPUTS CAME FROM AN EARLIER NODE.
	 *
	 * By ROLE and not by argument index, because the index differs
	 * between the syscall and the import that mean the same thing, and
	 * nothing above this should have to know which route it came by.
	 */
	if (n_ar >= 2 && nm &&
	    (!strcmp(nm, "read") || !strcmp(nm, "recv") ||
	     !strcmp(nm, "recvfrom") || !strcmp(nm, "write") ||
	     !strcmp(nm, "send"))) {
		note_in(h, org_of(w, ar[1]), KOF_DIAG_ROLE_BUFFER);
		note_in(h, org_of(w, ar[0]), KOF_DIAG_ROLE_FD);
	} else if (n_ar >= 1 && nm &&
		   (!strcmp(nm, "connect") || !strcmp(nm, "close") ||
		    !strcmp(nm, "dup2"))) {
		note_in(h, org_of(w, ar[0]), KOF_DIAG_ROLE_FD);
	}

	/*
	 * AND WHAT THIS CALL HANDS BACK, so the next node can be linked to
	 * it. mmap returns the region; mprotect returns ZERO and names the
	 * region in its first argument instead, which is why the two are
	 * not one case.
	 */
	if (nm && (!strcmp(nm, "mmap") || !strcmp(nm, "mmap2") ||
		   !strcmp(nm, "old_mmap")))
		org_set(w, KDIS_REG_AX, (uint16_t)(s->n_hit - 1u));
	else if (nm && !strcmp(nm, "mprotect")) {
		if (n_ar >= 1 && org_of(w, ar[0]) == ORG_STACK)
			h->bits |= KOF_DIAG_H_REGION_STACK;
		org_clear(w, KDIS_REG_AX);
	} else if (cap == KOF_CAP_NET_OPEN || cap == KOF_CAP_FILE_OPEN ||
		   cap == KOF_CAP_MEMFD)
		org_set(w, KDIS_REG_AX, (uint16_t)(s->n_hit - 1u));
	else
		org_clear(w, KDIS_REG_AX);

	/* Arm the carry for the next conditional branch - see walk.carry_to. */
	if (bits == 64 && nm && kof_sys_zero_on_success(nm))
		h->bits |= KOF_DIAG_H_ZERO_OK;
}

/*
 * ONE REGION OF CODE, read straight through.
 *
 * LINEAR AND NOT RECURSIVE. Following calls would need the call targets,
 * which needs the indirect ones resolved, which is the problem this is
 * underneath. A linear read of an executable region finds every syscall
 * instruction that is actually there; what it also finds is instructions
 * decoded out of data, and those produce nodes whose numbers do not
 * resolve - which come back as opaque rather than as silence.
 */
/*
 * ---- WHERE THE WALK HAS TO LOOK ------------------------------------------
 *
 * EVERY NODE IS BORN AT A SYSCALL, and that is what makes the rest of this
 * section legitimate. The two hit_add calls in at_syscall are the only ones
 * that put a FRESH index into the origin map; the third, the indirect
 * branch, fires only when the register it jumps through already carries one.
 * So an instruction with no syscall anywhere near it cannot contribute.
 *
 * The three encodings are the whole set this walk acts on - `0f 05` syscall,
 * `0f 34` sysenter, `cd 80` int 0x80 - see the KDIS_SYSCALL arm of class_of
 * and the int-0x80 test in the loop.
 *
 * A BYTE THAT IS NOT AN INSTRUCTION STILL COUNTS, and must. `0f 05` inside a
 * displacement answers yes and costs a window that finds nothing; that is a
 * wasted decode, not a missed node. The other direction would be a lie - an
 * instruction that is not in the bytes cannot be decoded out of them.
 *
 * WHY THE WHOLE-REGION TEST IS NOT ENOUGH, which is where this started.
 * Asking only "does this segment contain the bytes" was MEASURED on a frozen
 * copy of /usr/bin: it rejects 67% of the x86-64 files but only 7.4% of the
 * executable BYTES, because the big segments all contain the pair somewhere
 * by chance - at one in 65536 per position, a megabyte of code is certain to.
 * The same measurement counted 1491 candidate positions in 182.5 MB, so the
 * useful unit is the POSITION and not the segment.
 */
static uint64_t cand_at(const uint8_t *p, uint64_t from, uint64_t n)
{
	uint64_t i = from;

	while (i + 1u < n) {
		const uint8_t *q = memchr(p + i, 0x0f, (size_t)(n - 1u - i));
		const uint8_t *r = memchr(p + i, 0xcd, (size_t)(n - 1u - i));
		uint64_t at;

		if (!q && !r)
			break;
		if (!q || (r && r < q)) {
			at = (uint64_t)(r - p);
			if (p[at + 1u] == 0x80u)
				return at;
		} else {
			at = (uint64_t)(q - p);
			if (p[at + 1u] == 0x05u || p[at + 1u] == 0x34u)
				return at;
		}
		i = at + 1u;
	}
	return n;
}

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

/* Is anything from an earlier node still being carried? */
static int origins_live(const struct walk *w)
{
	uint32_t i;

	if (w->carry_armed || w->carry_live)
		return 1;
	for (i = 0; i < 16u; i++)
		if (w->reg[i].node != ORG_NONE)
			return 1;
	for (i = 0; i < w->n_stk && i < ORG_STK; i++)
		if (w->stk[i].node != ORG_NONE)
			return 1;
	return 0;
}

static void sweep_region(struct kof_diag_scan *s, const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size, uint64_t off,
			 uint64_t n)
{
	struct kof_kdis k;
	struct kdis_insn in;
	struct walk w;
	uint64_t c, done = 0;
	uint32_t r;

	if (!n || off >= size)
		return;
	if (off + n > size)
		n = size - off;

	/*
	 * ONE WINDOW PER CANDIDATE, AND THE NEXT ONE STARTS WHERE THIS ONE
	 * STOPPED. A candidate the previous window already walked over is
	 * not walked again - two syscalls a few instructions apart are one
	 * window, which is also the only way the second one sees what the
	 * first produced.
	 */
	for (c = cand_at(base + off, 0, n); c < n;
	     c = cand_at(base + off, c + 1u, n)) {
		uint64_t at = c > DIAG_LEAD ? c - DIAG_LEAD : 0;
		uint32_t idle = 0;

		if (at < done)
			at = done;
		if (c < done)
			continue;       /* already walked, see above */

		memset(&k, 0, sizeof k);
		memset(&w, 0, sizeof w);
		for (r = 0; r < 16u; r++)
			w.reg[r].node = ORG_NONE;
		if (!kof_kdis_seek(&k, off + at, 0))
			return;
		while (k.at < off + n &&
		       kof_kdis_next(&k, ctx, base, size, &in)) {
			/*
			 * PAST THE CANDIDATE, THE WALK RUNS ON WHAT IT IS
			 * STILL CARRYING - see the note on DIAG_IDLE.
			 */
			if (in.at >= off + c) {
				if (origins_live(&w))
					idle = 0;
				else if (++idle > DIAG_IDLE)
					break;
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
			 * KDIS_SYSCALL is the `syscall` and `sysenter` instructions;
			 * i386 reaches the kernel through a software interrupt, which
			 * is KDIS_INT and could be any vector. Reading only
			 * KDIS_SYSCALL found ZERO nodes in every 32-bit payload here -
			 * msfvenom's i386 stagers are entirely `int 0x80`.
			 */
			if (in.op == KDIS_SYSCALL ||
			    (in.op == KDIS_INT && in.n_op &&
			     in.o[0].kind == KDIS_O_IMM && in.o[0].imm == 0x80u)) {
				at_syscall(s, &k, &w, ctx, in.at);
				w.ax_stale = 1;
			} else if (in.op == KDIS_JCC) {
				/*
				 * ARM THE CARRY AT THE FIRST BRANCH AFTER A
				 * ZERO-ON-SUCCESS CALL, and do not let a later one
				 * take it - see the note on walk.carry_to for the
				 * three shapes measured.
				 */
				if (!w.carry_armed && s->n_hit &&
				    (s->hit[s->n_hit - 1u].bits & KOF_DIAG_H_ZERO_OK) &&
				    in.target != KOF_BROKEN && in.target > in.at) {
					w.carry_to = in.target;
					w.carry_armed = 1;
				}
			} else if ((in.op == KDIS_JMP || in.op == KDIS_CALL) &&
				   in.n_op && in.o[0].kind == KDIS_O_REG) {
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
				uint16_t t = org_of(&w, in.o[0].reg);

				if (t != ORG_NONE) {
					struct kof_diag_hit *h =
						hit_add(s, in.at, KOF_CAP_EXEC_REG, 0);

					note_in(h, t, KOF_DIAG_ROLE_TARGET);
				}
			}
			if (in.wmask & (1ull << KDIS_REG_AX))
				w.ax_stale = 0; /* something wrote it since */
			org_step(&w, &in);
			if (s->full)
				return;
		}
		done = k.at > off ? k.at - off : 0;
	}
}

/* ---- what counts as code ------------------------------------------------- */

/*
 * EXECUTABLE SEGMENTS, NOT SECTIONS.
 *
 * A section table is optional and a payload generator leaves it out:
 * msfvenom's ELF template has one PT_LOAD and no sections at all, so a
 * sweep that looked for ".text" or for an executable SHF flag would read
 * nothing out of every one of them. The program header is what the loader
 * itself reads, so it is what is here.
 */
static void sweep_elf(struct kof_diag_scan *s, const struct kof_obj_ctx *ctx,
		      const uint8_t *base, uint64_t size)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	uint32_t i;

	if (!e || !e->valid)
		return;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *g = &e->seg[i];
		uint64_t have, at = g->file_off;

		if (g->type != 1u || !(g->perm & KOF_PERM_X))
			continue;               /* PT_LOAD, executable */
		have = kof_clip_len(size, g->file_off, g->file_size);
		if (!have)
			continue;
		/*
		 * START AT THE ENTRY POINT WHEN IT IS IN THIS SEGMENT.
		 *
		 * An executable segment usually begins at file offset zero
		 * and therefore CONTAINS THE ELF HEADER - so reading it from
		 * the front decodes `7f E L F 02 01 01 ...` as instructions
		 * and carries whatever that desync produces into the real
		 * code. MEASURED on msfvenom's x86-64 stager: the mmap at
		 * +0x8d came back with its number unreadable, because the
		 * push that sets it had been swallowed by an instruction
		 * decoded across the header boundary.
		 *
		 * The entry is the one offset in a headerless object that is
		 * certainly the first byte of an instruction.
		 */
		if (ctx->entry_off >= g->file_off &&
		    ctx->entry_off < g->file_off + have) {
			have -= ctx->entry_off - g->file_off;
			at = ctx->entry_off;
		}
		sweep_region(s, ctx, base, size, at, have);
		if (s->full)
			return;
	}
}

/* ---- the surface --------------------------------------------------------- */

struct kof_diag_scan *kof_diag_scan(const struct kof_obj_ctx *ctx,
				    const uint8_t *base, uint64_t size)
{
	struct kof_diag_scan *s;

	if (!ctx || !base || !size)
		return NULL;
	if (ctx->arch != KOF_ARCH_X86 && ctx->arch != KOF_ARCH_X86_64)
		return NULL;            /* the value model is x86 only so far */
	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;
	if (ctx->format == KOF_FMT_ELF)
		sweep_elf(s, ctx, base, size);
	else
		sweep_region(s, ctx, base, size, 0, size);
	return s;
}

uint32_t kof_diag_scan_count(const struct kof_diag_scan *s)
{
	return s ? s->n_hit : 0u;
}

const struct kof_diag_hit *kof_diag_scan_at(const struct kof_diag_scan *s,
					    uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : NULL;
}

int kof_diag_scan_full(const struct kof_diag_scan *s)
{
	return s ? s->full : 0;
}

void kof_diag_scan_free(struct kof_diag_scan *s)
{
	if (!s)
		return;
	free(s->hit);
	free(s);
}

/* ---- matching ------------------------------------------------------------
 *
 * THE PARENT GENERATES THE CHILDREN. It does not filter them.
 *
 * The obvious shape - take every node matching each spec and try the
 * combinations - is a product of the pool sizes, and the pools are not
 * small: MEASURED, one 1.1 MB sample here holds 447 indirect calls, so a
 * three-node diagnose over two such pools is two hundred thousand tries.
 *
 * What makes the real shape cheap is that a node already records WHICH node
 * it took its value from. So a child is not looked for among all nodes of
 * its capability - it is looked for among the nodes that point AT THE
 * PARENT ALREADY BOUND, which is usually none or one. The walk is then the
 * size of the diagnose, once per candidate root, and the root is the rarest
 * node by construction - see the note on anchors in kofmod/kofdiag.h.
 */

/* A node satisfies a spec when it has the capability, carries every flag the
 * spec demands, and is not one whose meaning the walk could not read. The
 * last is the point of KOF_DIAG_H_ARG_UNKNOWN: a `mmap` whose prot could not
 * be followed is not evidence of a buffer OR of a code region. */
static int spec_ok(const struct kof_diag_hit *h,
		   const struct kof_diag_node *sp)
{
	if (h->cap != sp->cap)
		return 0;
	if ((h->flags & sp->flags) != sp->flags)
		return 0;
	if (h->bits & KOF_DIAG_H_ARG_UNKNOWN)
		return 0;
	return 1;
}

/*
 * IS THIS NODE LINKED TO THAT ONE, in the role the diagnose asked for.
 *
 * TWO WAYS, AND THE DIAGNOSE NAMES NEITHER. A value link - the child took
 * the parent's result - and a region link, where the parent established a
 * region and the child's address lies in it. msfvenom needs both and in the
 * same rule: on x86-64 `mmap` returns the pointer, on i386 `mprotect`
 * returns zero and names the region in an argument. A diagnose that had to
 * say which would need two copies of itself, so it says neither and this
 * accepts either.
 */
static int linked(const struct kof_diag_hit *child, uint16_t parent_idx,
		  const struct kof_diag_hit *parent, uint8_t role)
{
	uint8_t i;

	for (i = 0; i < child->n_in; i++) {
		if (child->in[i].role != role)
			continue;
		if (child->in[i].from == parent_idx)
			return 1;
		if (child->in[i].from == KOF_DIAG_FROM_STACK &&
		    (parent->bits & KOF_DIAG_H_REGION_STACK))
			return 1;
	}
	return 0;
}

/* Bind spec[k] and everything under it. `bound` holds the node index chosen
 * for each spec so far. Depth is the diagnose's own, which is a handful. */
static int bind_from(const struct kof_diag_scan *s, const struct kof_diag *d,
		     uint8_t k, uint16_t *bound)
{
	uint8_t c;
	uint32_t i;

	for (c = 0; c < d->n_node; c++) {
		if (d->node[c].parent != k)
			continue;
		for (i = 0; i < s->n_hit; i++) {
			if (!spec_ok(&s->hit[i], &d->node[c]))
				continue;
			if (!linked(&s->hit[i], bound[k], &s->hit[bound[k]],
				    d->node[c].role))
				continue;
			bound[c] = (uint16_t)i;
			if (bind_from(s, d, c, bound))
				goto next;
		}
		return 0;               /* a branch of the tree has no match */
next:
		;
	}
	return 1;
}

int kof_diag_match(const struct kof_diag_scan *s, const struct kof_diag *d,
		   uint16_t *bind_out, uint8_t *n_bind)
{
	uint16_t bound[256];
	uint32_t i;
	uint8_t root, k, n = 0;

	if (n_bind)
		*n_bind = 0;
	/* n_node is a uint8_t, so 255 is its ceiling already - the bound that
	 * matters is `bound[]` below holding one slot per node, and 256 is
	 * more than a uint8_t can index past. */
	if (!s || !d || !d->n_node)
		return 0;
	for (root = 0; root < d->n_node; root++)
		if (d->node[root].parent == KOF_DIAG_NO_PARENT)
			break;
	if (root == d->n_node)
		return 0;               /* no root: not a tree */

	for (i = 0; i < s->n_hit; i++) {
		if (!spec_ok(&s->hit[i], &d->node[root]))
			continue;
		memset(bound, 0xff, sizeof bound);
		bound[root] = (uint16_t)i;
		if (!bind_from(s, d, root, bound))
			continue;
		/*
		 * ONLY THE NODES THE DIAGNOSE OFFERED AS TOUCH POINTS come
		 * back. A diagnose that offers none answers in one bit, which
		 * is what nearly all of them do - see the note on the touch
		 * bit in kofmod/kofdiag.h. The cost of an answer is the size
		 * of the question.
		 */
		for (k = 0; k < d->n_node && bind_out; k++)
			if (d->node[k].bits & KOF_DIAG_B_TOUCH)
				bind_out[n++] = bound[k];
		if (n_bind)
			*n_bind = n;
		return 1;
	}
	return 0;
}

/* ---- loading -------------------------------------------------------------
 *
 * A .kdig FILE IS ONE DIAGNOSE and nothing else - no module, no pattern, no
 * blob. That is why it is a file beside the packs rather than a section
 * inside one: the pack header carries a fixed-size section table, so one
 * more section is a format change every database in existence has to be
 * rebuilt for, and none of what a pack exists to carry applies here.
 *
 * EVERYTHING IS BOUNDS CHECKED AGAINST THE FILE'S OWN LENGTH, and a file
 * that does not add up is refused whole rather than loaded in part. A
 * diagnose half read is a diagnose that matches something its author did
 * not write.
 */

int kof_diag_load(const uint8_t *b, uint64_t n, struct kof_diag *out,
		  struct kof_diag_node *node, uint8_t max_node,
		  char *name, uint32_t name_cap)
{
	uint32_t n_node, nlen, i;
	uint64_t at;

	if (!b || !out || !node || !name || n < 4u)
		return 0;
	n_node = (uint32_t)b[0] | ((uint32_t)b[1] << 8);
	nlen   = b[3];
	if (!n_node || n_node > max_node || nlen + 1u > name_cap)
		return 0;
	at = 4u + nlen;
	if (n < at || (n - at) / 8u < n_node)
		return 0;

	memcpy(name, b + 4, nlen);
	name[nlen] = 0;
	memset(out, 0, sizeof *out);
	out->via = b[2];
	out->n_node = (uint8_t)n_node;
	out->name = name;
	out->node = node;

	for (i = 0; i < n_node; i++) {
		const uint8_t *r = b + at;
		uint32_t alen;

		if ((uint64_t)(r - b) + 8u > n)
			return 0;
		node[i].cap    = (uint16_t)(r[0] | (r[1] << 8));
		node[i].flags  = (uint16_t)(r[2] | (r[3] << 8));
		node[i].parent = r[4];
		node[i].role   = r[5];
		node[i].bits   = r[6];
		node[i].attr_len = r[7];
		alen = r[7];
		at += 8u + alen;
		if (at > n)
			return 0;
		/*
		 * A PARENT THAT IS NOT A NODE HERE, or a node that is its own
		 * parent, is a file this build did not write. Refuse rather
		 * than clamp: a clamped index points at a real node, and the
		 * diagnose then quietly means something else.
		 */
		if (node[i].parent != KOF_DIAG_NO_PARENT &&
		    (node[i].parent >= n_node || node[i].parent == i))
			return 0;
		if (node[i].role >= KOF_DIAG_ROLE_COUNT)
			return 0;
	}
	/* Exactly one root, because the matcher descends from one. */
	{
		uint32_t roots = 0;

		for (i = 0; i < n_node; i++)
			if (node[i].parent == KOF_DIAG_NO_PARENT)
				roots++;
		if (roots != 1u)
			return 0;
	}
	return 1;
}
