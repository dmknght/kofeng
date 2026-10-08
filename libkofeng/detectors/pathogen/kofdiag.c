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
 * WHY A VALUE MODEL AT ALL, when celllysis already keeps a constant map. The
 * constant map answers "what number is in this register"; this needs
 * "which NODE did this value come from", which is a different question and
 * survives where the first does not: a pointer stays a pointer through a
 * push and a pop whether or not anyone knows its address.
 */

#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "../../kofcore/kofdebug.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/elf.h"
#include <celllysis/celllysis.h>
#include "../../analyzers/nucleo/nucleo.h"
#include <celllysis/space.h>

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

void kof_diag_org_clear(struct walk *w, uint8_t r)
{
	if (r < 16u) {
		w->reg[r].node = ORG_NONE;
		/* The symbol goes with it: all three fields answer the same
		 * question - where did this value come from - and leaving one
		 * behind would have a register naming a symbol it no longer
		 * holds. */
		w->reg[r].symoff = 0;
		w->reg[r].symadd = 0;
	}
}

uint16_t kof_diag_org_of(const struct walk *w, uint8_t r)
{
	return r < 16u ? w->reg[r].node : ORG_NONE;
}

void kof_diag_org_set(struct walk *w, uint8_t r, uint16_t node)
{
	if (r >= 16u)
		return;
	w->reg[r].node = node;
	/* One question, three fields - see struct org. A register that now
	 * holds what a node produced is no longer naming a symbol. */
	w->reg[r].symoff = 0;
	w->reg[r].symadd = 0;
}

/*
 * FORGET WHAT EVERY REGISTER THIS INSTRUCTION WRITES CAME FROM, then put
 * back the one case this follows.
 *
 * `wmask` and not the first operand, for the reason cell_track records: an
 * instruction writes registers it does not name, and names registers it
 * only reads. Getting that backwards on `mul` cost the i386 samples their
 * whole network half.
 */
void kof_diag_org_set_sym(struct walk *w, uint8_t r, uint32_t symoff,
			  int32_t symadd)
{
	if (!w || r >= 16u)
		return;
	w->reg[r].node = ORG_NONE;
	w->reg[r].symoff = symoff;
	w->reg[r].symadd = symadd;
}

uint32_t kof_diag_org_sym(const struct walk *w, uint8_t r, int32_t *add)
{
	if (!w || r >= 16u)
		return 0;
	if (add)
		*add = w->reg[r].symadd;
	return w->reg[r].symoff;
}

void kof_diag_org_step(struct walk *w, const struct cell_insn *in)
{
	uint8_t r, d, e;

	if (in->op == CELL_PUSH) {
		uint16_t v = ORG_NONE;

		if (in->n_op && in->o[0].kind == CELL_O_REG)
			v = kof_diag_org_of(w, in->o[0].reg);
		if (w->n_stk < ORG_STK)
			w->stk[w->n_stk].node = v;
		w->n_stk++;
		return;
	}
	if (in->op == CELL_POP) {
		uint16_t v = ORG_NONE;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk < ORG_STK)
				v = w->stk[w->n_stk].node;
		}
		/* A popped LIST names no operand; wmask has them all. */
		for (r = 0; r < 16u; r++)
			if (in->wmask & (1ull << r))
				kof_diag_org_clear(w, r);
		if (in->n_op && in->o[0].kind == CELL_O_REG)
			kof_diag_org_set(w, in->o[0].reg, v);
		return;
	}
	if (in->op == CELL_XCHG && in->n_op > 1u &&
	    in->o[0].kind == CELL_O_REG && in->o[1].kind == CELL_O_REG) {
		uint16_t a;

		d = in->o[0].reg; e = in->o[1].reg;
		a = kof_diag_org_of(w, d);
		kof_diag_org_set(w, d, kof_diag_org_of(w, e));
		kof_diag_org_set(w, e, a);
		return;
	}
	if (in->op == CELL_MOV && in->n_op > 1u &&
	    in->o[0].kind == CELL_O_REG && in->o[0].size >= 4u) {
		if (in->o[1].kind == CELL_O_REG) {
			/*
			 * A VALUE TAKEN FROM THE STACK POINTER IS A STACK
			 * ADDRESS, and that is a provenance of its own.
			 * msfvenom's i386 stager makes the stack executable
			 * and jumps into it; mprotect returns 0, so there is
			 * no pointer to follow from the allocation to the
			 * jump and the only thing that links them is that
			 * both addresses came off esp.
			 */
			kof_diag_org_set(w, in->o[0].reg,
				in->o[1].reg == (w->sp ? w->sp : CELL_REG_SP) ? ORG_STACK
				: kof_diag_org_of(w, in->o[1].reg));
			return;
		}
		kof_diag_org_clear(w, in->o[0].reg);
		return;
	}
	/*
	 * AND/SHR/SHL OVER A STACK ADDRESS IS STILL A STACK ADDRESS. The
	 * i386 stager rounds esp down to a page with `shr 0xc; shl 0xc`
	 * before handing it to mprotect; killing the provenance there breaks
	 * the only link that sample has.
	 */
	if ((in->op == CELL_AND || in->op == CELL_SHR || in->op == CELL_SHL) &&
	    in->n_op && in->o[0].kind == CELL_O_REG &&
	    kof_diag_org_of(w, in->o[0].reg) == ORG_STACK)
		return;

	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r))
			kof_diag_org_clear(w, r);
}

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofpathogen.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */


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

struct kof_diag_hit *kof_diag_hit_add(struct kof_diag_scan *s, uint64_t at,
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

void kof_diag_hit_nonblock(struct kof_diag_scan *s, uint64_t at, uint16_t open_idx)
{
	struct kof_diag_hit *n = kof_diag_hit_add(s, at, KOF_NUCLEO_FD_NONBLOCK, 0);

	if (n)
		kof_diag_note_in(n, open_idx, KOF_DIAG_ROLE_FD, KOF_DIAG_KIND_PRODUCED);
}

/* ---- where a value came from ---------------------------------------------
 *
 * A SHADOW BESIDE celllysis's CONSTANT MAP, not a replacement for it. The two
 * answer different questions and neither covers the other: the constant map
 * says WHAT NUMBER a register holds, this says WHICH NODE it came out of. A
 * pointer stays a pointer through a push and a pop whether or not anyone
 * knows its address, and a number can be known while coming from nowhere.
 */


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
	static const uint8_t x64[] = { CELL_REG_DI, CELL_REG_SI, CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t x86[] = { CELL_REG_BX, CELL_REG_CX, CELL_REG_DX,
				       CELL_REG_SI, CELL_REG_DI, CELL_REG_BP };

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
 * celllysis at all. When it is not there the node is still emitted, as
 * KOF_NUCLEO_NONE with KOF_DIAG_H_OPAQUE set - see the note on that flag. A
 * site dropped because its number could not be read is a site that makes
 * two different programs look alike.
 */

/*
 * ---- WHICH INPUT OF A CALL EACH ARGUMENT IS ------------------------------
 *
 * ONE TABLE. There were two - one in the routine that reads syscalls, one in
 * the routine that reads imports - because each grew the words it happened to
 * need. They agreed, today, by luck: nothing made them, and the question they
 * answer is the same question. A capability is what a syscall and the import
 * that means the same thing both resolve to, so the role is a property of the
 * capability and belongs with it, once.
 *
 * AND THE ROLES OF ONE CALL MUST BE DISTINCT, which is not a style rule but
 * the invariant kof_diag_note_in rests on. That function refuses a link whose
 * (parent, role, kind) it already holds, because a loop arriving at the same
 * site again has not found a second relation. If two arguments of one call wear
 * the same word, two DIFFERENT relations become indistinguishable and the
 * second is silently dropped - MEASURED on a hooked getdents, where
 * copy_to_user's kernel source and userspace destination were both called
 * `buffer` and one of them vanished.
 *
 * The invariant is checked rather than hoped for: see tests/unit/diag_roles.c,
 * which walks the whole capability space and fails if any capability assigns
 * one role twice.
 */
uint8_t kof_diag_role_of_arg(uint16_t cap, unsigned i)
{
	switch (cap) {
	/* Bytes through a descriptor: what is filled, and from where. */
	case KOF_NUCLEO_MEM_READ:
	case KOF_NUCLEO_READ:
	case KOF_NUCLEO_NET_READ:
		return i == 1u ? KOF_DIAG_ROLE_BUFFER
		     : i == 0u ? KOF_DIAG_ROLE_FD
			       : KOF_DIAG_ROLE_NONE;
	case KOF_NUCLEO_MEM_WRITE:
	case KOF_NUCLEO_WRITE:
	case KOF_NUCLEO_NET_WRITE:
		return i == 1u ? KOF_DIAG_ROLE_SOURCE
		     : i == 0u ? KOF_DIAG_ROLE_FD
			       : KOF_DIAG_ROLE_NONE;
	/* Across the user/kernel boundary: one buffer each way, and they are
	 * different objects - see KOF_DIAG_ROLE_SOURCE. */
	case KOF_NUCLEO_COPY_FROM_USER:
	case KOF_NUCLEO_COPY_TO_USER:
		return i == 0u ? KOF_DIAG_ROLE_BUFFER
		     : i == 1u ? KOF_DIAG_ROLE_SOURCE
			       : KOF_DIAG_ROLE_NONE;
	case KOF_NUCLEO_NET_CONNECT:
	case KOF_NUCLEO_NET_BIND:
	case KOF_NUCLEO_NET_LISTEN:
	case KOF_NUCLEO_NET_ACCEPT:
	case KOF_NUCLEO_FD_REDIR:
	case KOF_NUCLEO_FD_NONBLOCK:
	case KOF_NUCLEO_NET_HDRINCL:
		return i == 0u ? KOF_DIAG_ROLE_FD : KOF_DIAG_ROLE_NONE;
	case KOF_NUCLEO_EXEC_IMAGE:
		return i == 0u ? KOF_DIAG_ROLE_PATH : KOF_DIAG_ROLE_NONE;
	/* The credentials being installed are the ones that were built. */
	case KOF_NUCLEO_CRED_SET:
	/* Both halves of the probe take the same struct kprobe. */
	case KOF_NUCLEO_KPROBE_REG:
	case KOF_NUCLEO_KPROBE_UNREG:
	/* The list entry being taken out or put back. */
	case KOF_NUCLEO_LIST_HIDE:
		return i == 0u ? KOF_DIAG_ROLE_BUFFER : KOF_DIAG_ROLE_NONE;
	default:
		return KOF_DIAG_ROLE_NONE;
	}
}

struct kof_diag_hit *kof_diag_hit_of(struct kof_diag_scan *s, uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : 0;
}

void kof_diag_note_in(struct kof_diag_hit *h, uint16_t from, uint8_t role,
		      uint8_t kind)
{
	uint8_t i;

	if (!h || from == ORG_NONE || h->n_in >= 4u)
		return;
	/*
	 * THE SAME LINK TWICE IS ONE LINK.
	 *
	 * A run that goes round a loop arrives at the same call with the same
	 * value from the same producer; a sweep can reach one site from two
	 * windows. Neither has found a second relation. Recording it again
	 * would fill the four slots with copies and push out a real one -
	 * MEASURED before this was here: meter1_x86's retry loop produced ten
	 * copies of one link.
	 */
	/*
	 * THE SAME LINK IS (parent, role, KIND). Two relations between one
	 * pair of nodes are two links - see enum kof_diag_kind - and only a
	 * repeat of all three is the loop arriving again.
	 */
	for (i = 0; i < h->n_in; i++)
		if (h->in[i].from == from && h->in[i].role == role &&
		    h->in[i].kind == kind)
			return;
	h->in[h->n_in].from = from;
	h->in[h->n_in].role = role;
	h->in[h->n_in].how  = KOF_DIAG_LINK_PROVEN;
	h->in[h->n_in].kind = kind;
	h->n_in++;
}

/*
 * A SYSCALL WHOSE ARGUMENT THE WALK COULD NOT READ BECAUSE IT IS THE CALLER'S.
 * Kept as file offsets; the list grows with the input and is bounded by it,
 * since there cannot be more of these than there are `int 0x80` in the object.
 */
static void wrap_note(struct kof_diag_scan *s, uint64_t at)
{
	uint32_t i;

	for (i = 0; i < s->n_wrap; i++)
		if (s->wrap[i] == at)
			return;
	if (s->n_wrap == s->cap_wrap) {
		uint32_t nc = s->cap_wrap ? s->cap_wrap * 2u : 8u;
		uint64_t *nw = realloc(s->wrap, (size_t)nc * sizeof *nw);

		if (!nw)
			return;
		s->wrap = nw;
		s->cap_wrap = nc;
	}
	s->wrap[s->n_wrap++] = at;
}

/*
 * THE NODE A SYSCALL SITE BECOMES, once the number and arguments have been read
 * - which is the part that differs per architecture and stays with the caller.
 * What follows is the same everywhere: which inputs came from earlier nodes,
 * what the call hands back, and what that makes of the registers.
 *
 * `ar`/`n_ar` are the argument registers in order, `ret_reg` the register the
 * result comes back in, `nonblock` whether the socket was made non-blocking
 * and `carry` whether this architecture can leave a zero for the next call
 * to use (x86-64 only - see walk.carry_to).
 */
static void note_node(struct kof_diag_scan *s, struct walk *w, uint64_t at,
		      uint16_t cap, uint8_t fl, const char *nm,
		      const uint8_t *ar, int n_ar, unsigned have,
		      uint8_t ret_reg, int nonblock, int carry)
{
	struct kof_diag_hit *h;

	h = kof_diag_hit_add(s, at, cap, fl);
	if (!h)
		return;
	/*
	 * The third argument is the one that separates a code region from a
	 * buffer, and the first two separate a socket from a raw socket.
	 * Unread, the node says so rather than carrying the answer those
	 * bits would have given if they had been zero.
	 */
	if ((cap == KOF_NUCLEO_ALLOC && !(have & (1u << 2))) ||
	    (cap == KOF_NUCLEO_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KOF_DIAG_H_ARG_UNKNOWN;

	/*
	 * WHICH OF THIS CALL'S INPUTS CAME FROM AN EARLIER NODE.
	 *
	 * By ROLE and not by argument index, because the index differs
	 * between the syscall and the import that mean the same thing, and
	 * nothing above this should have to know which route it came by.
	 */
	{
		unsigned k;

		/*
		 * FROM kof_diag_role_of_arg AND NOT FROM A LIST OF NAMES.
		 *
		 * This was eight hardcoded names - read, recv, recvfrom,
		 * write, send, connect, close, dup2 - which is a second
		 * spelling of that function, and the narrower one: it answers
		 * by CAPABILITY, so every alias the vocabulary learns is
		 * covered the moment it is added, while a name list has to be
		 * edited too and silently makes no link until it is. The
		 * comment above this code already said the question is about
		 * the role and not the index.
		 *
		 * `close` was in that list and is not a capability at all, so
		 * no node was ever made for it and the branch could not fire.
		 */
		for (k = 0; k < (unsigned)n_ar && k < 6u; k++) {
			uint8_t role = kof_diag_role_of_arg(cap, k);

			if (role != KOF_DIAG_ROLE_NONE)
				kof_diag_note_in(h, kof_diag_org_of(w, ar[k]),
						 role, KOF_DIAG_KIND_PRODUCED);
		}
	}

	/*
	 * AND WHAT THIS CALL HANDS BACK, so the next node can be linked to
	 * it. mmap returns the region; mprotect returns ZERO and names the
	 * region in its first argument instead, which is why the two are
	 * not one case.
	 */
	if (kof_flow_hands_on(cap, nm)) {
		uint16_t made = (uint16_t)(s->n_hit - 1u);

		kof_diag_org_set(w, ret_reg, made);
		if ((cap == KOF_NUCLEO_NET_OPEN || cap == KOF_NUCLEO_NET_RAW) &&
		    nonblock)
			kof_diag_hit_nonblock(s, at, made);
	} else {
		/*
		 * mprotect is the capability that does NOT hand one back,
		 * and the one case where the region it was GIVEN still
		 * matters: a stack mapping made executable is a payload
		 * about to run off the stack.
		 */
		if ((cap == KOF_NUCLEO_ALLOC || cap == KOF_NUCLEO_ALLOC_EXEC ||
		     cap == KOF_NUCLEO_HEAP) && n_ar >= 1 &&
		    kof_diag_org_of(w, ar[0]) == ORG_STACK)
			h->bits |= KOF_DIAG_H_REGION_STACK;
		kof_diag_org_clear(w, ret_reg);
	}

	/* Arm the carry for the next conditional branch - see walk.carry_to. */
	if (carry && nm && kof_sys_zero_on_success(nm))
		h->bits |= KOF_DIAG_H_ZERO_OK;
}

/*
 * ---- THE FIXED-WIDTH PORTS ------------------------------------------------
 *
 * ARM and AArch64 reach the kernel through one instruction, `svc`, with the
 * number in a register the ABI names (r7, x8) and the arguments in the first
 * six. All of that is nucleo's fxabi - the same row the old whole-image sweep
 * read - so this is only the reading of it: no byte pattern to search for, no
 * second syscall encoding to tell apart, and none of the x86 special cases
 * (socketcall, the zero-on-success carry) because ARM has neither.
 *
 * OLD ARM ABI: `svc 0x9000NN` carries the number in the instruction itself and
 * r7 is not read. Both are seen in the static IoT builds, so both are handled.
 */
static int fixed_arch(const struct kof_obj_ctx *ctx)
{
	return ctx->arch == KOF_ARCH_ARM || ctx->arch == KOF_ARCH_ARM64;
}

#define ARM_OABI_BASE 0x900000u

static void at_syscall_fixed(struct kof_diag_scan *s, struct kof_cell_cur *k,
			     struct walk *w, const struct kof_obj_ctx *ctx,
			     const struct cell_insn *in)
{
	const struct fxabi *fx = kof_fx_abi_of(ctx->arch == KOF_ARCH_ARM
					       ? KOF_FLOW_A_ARM32
					       : KOF_FLOW_A_ARM64);
	uint8_t ar[6];
	uint64_t nr = 0, arg[6];
	struct kof_diag_hit *h;
	const char *nm;
	uint16_t cap;
	uint8_t fl = 0;
	unsigned have = 0;
	int i, n_ar = fx->n_arg < 6 ? fx->n_arg : 6;
	uint64_t imm = in->n_op && in->o[0].kind == CELL_O_IMM ? in->o[0].imm : 0;

	if (ctx->arch == KOF_ARCH_ARM && imm >= ARM_OABI_BASE &&
	    imm < ARM_OABI_BASE + 0x10000u) {
		nr = imm - ARM_OABI_BASE;
	} else if (!kof_cell_reg(k, fx->sel, &nr) || nr > 0xffffu) {
		/* The number is the caller's: a candidate wrapper, as on x86. */
		s->n_unread++;
		h = kof_diag_hit_add(s, in->at, KOF_NUCLEO_NONE, 0);
		if (h)
			h->bits |= KOF_DIAG_H_OPAQUE;
		return;
	}
	for (i = 0; i < n_ar; i++) {
		ar[i] = (uint8_t)(fx->arg0 + i);
		if (kof_cell_reg(k, ar[i], &arg[i]))
			have |= 1u << i;
		else
			arg[i] = 0;
	}
	if (!(have & 1u))
		s->n_unread++;
	cap = kof_flow_cap_of_syscall_abi(fx, (uint32_t)nr, arg, &fl);
	nm = kof_sys_name_abi(fx, (uint32_t)nr);
	if (cap == KOF_NUCLEO_NONE)
		return;
	note_node(s, w, in->at, cap, fl, nm, ar, n_ar, have, fx->ret,
		  (have & 2u) && (arg[1] & 0x800u) /* SOCK_NONBLOCK */, 0);
}

static void at_syscall(struct kof_diag_scan *s, struct kof_cell_cur *k,
		       struct walk *w, const struct kof_obj_ctx *ctx,
		       const struct cell_insn *in)
{
	const uint64_t at = in->at;

	const uint8_t *ar;
	uint64_t nr = 0, arg[6];
	struct kof_diag_hit *h;
	const char *nm;
	uint16_t cap;
	uint8_t fl = 0;
	int n_ar, i, bits;
	unsigned have = 0;          /* which of arg[] came from a known register */

	if (fixed_arch(ctx)) {
		at_syscall_fixed(s, k, w, ctx, in);
		return;
	}
	bits = ctx->arch == KOF_ARCH_X86_64 ? 64 : 32;
	n_ar = arg_regs(ctx, &ar);

	/*
	 * THE SYSCALL VOCABULARY IS LINUX'S, SO IT IS ONLY ASKED ABOUT LINUX.
	 *
	 * A `syscall` instruction in a PE carries a WINDOWS service number,
	 * and the number spaces have nothing to do with each other.
	 * kof_flow_cap_of_syscall only knows the Linux table, so handing it a
	 * Windows number does not fail - it ANSWERS, with the wrong word.
	 *
	 * MEASURED, and this is why the check is here rather than in a
	 * comment: a Hell's Gate shaped stub, `mov r10,rcx; mov eax,0x3b;
	 * syscall`, came back as `proc-start`, because 0x3b is execve on
	 * Linux x86-64. Nothing about that program starts a process. A second
	 * stub with 0x18 produced no node at all, because 0x18 is sched_yield
	 * and the vocabulary has no word for it - silence where there is a
	 * direct system call, which on Windows is the notable part.
	 *
	 * SO THE NODE IS STILL EMITTED, AND THE TWO CASES ARE KEPT APART.
	 * A number that WAS read is KOF_DIAG_H_RAW_SYSCALL - a program
	 * reaching the kernel without going through ntdll, which is what the
	 * hook-evading loaders do and the one thing this walk can say about a
	 * PE that the import table cannot. A number that was not read is
	 * OPAQUE, which is what `0f 05` in packed data looks like. Reporting
	 * both as opaque would bury the first in the second.
	 */
	if (ctx->format != KOF_FMT_ELF) {
		int got = !w->ax_stale &&
			  kof_cell_reg(k, CELL_REG_AX, &nr) && nr <= 0xffffu;

		h = kof_diag_hit_add(s, at, KOF_NUCLEO_NONE, 0);
		if (h)
			h->bits |= got ? KOF_DIAG_H_RAW_SYSCALL
				       : KOF_DIAG_H_OPAQUE;
		return;
	}

	if (w->ax_stale || !kof_cell_reg(k, CELL_REG_AX, &nr) ||
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
			/* The number is the CALLER'S too (a libc helper that takes
			 * it in a register or on the stack): a candidate wrapper,
			 * exactly as an argument that was not read is. */
			s->n_unread++;
			h = kof_diag_hit_add(s, at, KOF_NUCLEO_NONE, 0);
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
		if (kof_cell_reg(k, ar[i], &arg[i]))
			have |= 1u << i;
		else
			arg[i] = 0;
	}
	for (; i < 6; i++)
		arg[i] = 0;

	if (!(have & 1u))
		s->n_unread++;          /* a candidate wrapper - see diag_wrap.c */
	cap = kof_flow_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
	nm  = kof_sys_name((unsigned)bits, (uint32_t)nr);
	if (cap == KOF_NUCLEO_NONE) {
		/*
		 * i386's socketcall IS A MULTIPLEXER: the sub-call that says
		 * socket from connect from send is in ebx, and a libc that
		 * wraps it (uClibc, in the static IoT builds) loads ebx from
		 * its own PARAMETER - `mov edx,[esp+0x10]; xchg ebx,edx` - so
		 * at this instruction it is the caller's value and not the
		 * walk's. This used to return here without a word: MEASURED, 27
		 * of 30 static i386 bots had the instruction and not one net
		 * node. Remember the site; kof_diag_run_wrappers reads what every caller
		 * pushed.
		 */
		if (bits == 32 && nr == 102u && !(have & 1u))
			wrap_note(s, at);
		return;                 /* a syscall the vocabulary has no word for */
	}
	note_node(s, w, at, cap, fl, nm, ar, n_ar, have, CELL_REG_AX,
		  kof_flow_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have),
		  bits == 64);
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
 * `0f 34` sysenter, `cd 80` int 0x80 - see the CELL_SYSCALL arm of class_of
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
 * A32 `svc` AS LINUX USES IT, and not every word the instruction set allows.
 *
 * The bare mask (cond:1111 imm24) matched 159 words in one 190 KB Mirai
 * build, nearly all of them literal-pool data after a `bx lr` - 0x7f807f81 is
 * `svcvc 0x807f81` and is a pair of halfwords, not a call. Real code is
 * always-execute: EABI is `svc 0`, the old ABI is `svc 0x9000nn`, and the
 * ARM-private calls (cacheflush) are `svc 0x0f000n`. Anything else is data.
 */
static int svc_a32(uint32_t x)
{
	uint32_t imm = x & 0xffffffu;

	if ((x >> 24) != 0xefu)         /* cond AL, 1111 */
		return 0;
	return imm == 0 || (imm >> 16) == 0x90u || (imm >> 16) == 0x0fu;
}

/*
 * THE FIXED-WIDTH CANDIDATE: an aligned word that is an `svc`.
 *
 * No byte search: instructions sit on 4-byte boundaries, so every word is
 * looked at once. A64 `svc #0` is the one word 0xd4000001 - Linux passes no
 * immediate, and the 65536 other `svc` words are data far more often than code.
 * `off` is where `p` sits in the file, because alignment is the file's and not
 * the slice's.
 */
static uint64_t cand_fixed(const struct kof_obj_ctx *ctx, const uint8_t *p,
			   uint64_t off, uint64_t from, uint64_t n)
{
	uint64_t i = from + ((4u - ((off + from) & 3u)) & 3u);
	int be = ctx->arch == KOF_ARCH_ARM && ctx->format == KOF_FMT_ELF &&
		 ctx->file_header && ((const uint8_t *)ctx->file_header)[5] == 2u;

	for (; i + 4u <= n; i += 4u) {
		uint32_t x = be ? ((uint32_t)p[i] << 24 | (uint32_t)p[i + 1] << 16 |
				   (uint32_t)p[i + 2] << 8 | p[i + 3])
				: ((uint32_t)p[i + 3] << 24 | (uint32_t)p[i + 2] << 16 |
				   (uint32_t)p[i + 1] << 8 | p[i]);

		if (ctx->arch == KOF_ARCH_ARM ? svc_a32(x) : x == 0xd4000001u)
			return i;
	}
	return n;
}

/*
 * IS THIS INSTRUCTION A WAY INTO THE KERNEL ON *THIS* OBJECT.
 *
 * The three encodings are not interchangeable, and treating them as one set
 * accepts things that cannot execute:
 *
 *   0f 05  syscall    64-bit mode only. In a 32-bit image it is not a way
 *                     into the kernel on any system this engine targets.
 *   0f 34  sysenter   32-bit. Windows x86 uses it, but only inside ntdll;
 *                     Linux i386 reaches it through the vDSO.
 *   cd 80  int 0x80   LINUX's i386 entry, and nothing else's. On a PE it is
 *                     an interrupt into a vector Windows does not serve.
 *
 * MEASURED on 300 PE samples: the only three sites whose syscall number the
 * walk could read were a `cd 80` and an `0f 05` in a 32-bit image, and an
 * `0f 34` outside ntdll - all three coincidental bytes inside packed data,
 * and all three accepted because the test looked at the bytes and not at
 * what the object is. None of them can run.
 *
 * THIS IS NOT THE DIRECT-SYSCALL TEST, and must not be mistaken for one. A
 * Hell's Gate stub is `mov r10,rcx; mov eax,SSN; syscall` in a 64-bit PE,
 * which this accepts - as it should - along with every stray `0f 05` in a
 * 64-bit packed section. Telling those apart needs the r10 shape, and that
 * is a separate piece of work.
 */
static int kernel_entry(const struct kof_obj_ctx *ctx,
			const struct cell_insn *in, const uint8_t *p)
{
	int bits64 = ctx->arch == KOF_ARCH_X86_64;

	if (fixed_arch(ctx))
		return in->op == CELL_SYSCALL;
	if (in->op == CELL_SYSCALL)
		return p[0] == 0x0fu && p[1] == 0x05u ? bits64 : !bits64;
	if (in->op == CELL_INT && in->n_op &&
	    in->o[0].kind == CELL_O_IMM && in->o[0].imm == 0x80u)
		return ctx->format == KOF_FMT_ELF;
	return 0;
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
	struct kof_cell_cur k;
	struct cell_space sp;
	struct cell_insn in;
	struct walk w;
	uint64_t c, done = 0;
	uint32_t r;

	if (!n || off >= size)
		return;
	if (off + n > size)
		n = size - off;
	kof_cell_space_init(&sp, ctx, base, size);

	/*
	 * ONE WINDOW PER CANDIDATE, AND THE NEXT ONE STARTS WHERE THIS ONE
	 * STOPPED. A candidate the previous window already walked over is
	 * not walked again - two syscalls a few instructions apart are one
	 * window, which is also the only way the second one sees what the
	 * first produced.
	 */
#define CAND(from) (fixed_arch(ctx) ? cand_fixed(ctx, base + off, off, (from), n) \
				    : cand_at(base + off, (from), n))
	for (c = CAND(0); c < n; c = CAND(c + 1u)) {
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
		w.sp = ctx->arch == KOF_ARCH_ARM ? 13u : 0u;
		if (!kof_cell_seek(&k, off + at, 0))
			return;
		while (k.at < off + n &&
		       kof_cell_next(&k, &sp, &in)) {
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
			 * CELL_SYSCALL is the `syscall` and `sysenter` instructions;
			 * i386 reaches the kernel through a software interrupt, which
			 * is CELL_INT and could be any vector. Reading only
			 * CELL_SYSCALL found ZERO nodes in every 32-bit payload here -
			 * msfvenom's i386 stagers are entirely `int 0x80`.
			 */
			if (kernel_entry(ctx, &in, base + in.at)) {
				at_syscall(s, &k, &w, ctx, &in);
				w.ax_stale = 1;
			} else if (in.op == CELL_JCC) {
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
			} else if ((in.op == CELL_JMP || in.op == CELL_CALL) &&
				   in.n_op && in.o[0].kind == CELL_O_REG) {
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
				uint16_t t = kof_diag_org_of(&w, in.o[0].reg);

				if (t != ORG_NONE) {
					struct kof_diag_hit *h =
						kof_diag_hit_add(s, in.at, KOF_NUCLEO_EXEC_REG, 0);

					kof_diag_note_in(h, t, KOF_DIAG_ROLE_TARGET,
					 KOF_DIAG_KIND_PRODUCED);
				}
			}
			if (in.wmask & (1ull << CELL_REG_AX))
				w.ax_stale = 0; /* something wrote it since */
			kof_diag_org_step(&w, &in);
			if (s->full)
				return;
		}
		done = k.at > off ? k.at - off : 0;
	}
#undef CAND
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
/*
 * THE BYTES OF EXECUTABLE SEGMENT `i` THAT ARE CODE, or zero. One statement of
 * it, because the sweep and the wrapper resolution must agree on where code
 * begins - see the note on the entry point below.
 */
static uint64_t code_range(const struct kof_obj_ctx *ctx,
			   const struct kof_elf_info *e, uint32_t i,
			   uint64_t size, uint64_t *at)
{
	const struct kof_elf_seg *g = &e->seg[i];
	uint64_t have;

	if (g->type != 1u || !(g->perm & KOF_PERM_X))
		return 0;               /* PT_LOAD, executable */
	have = kof_clip_len(size, g->file_off, g->file_size);
	if (!have)
		return 0;
	*at = g->file_off;
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
		*at = ctx->entry_off;
	}
	return have;
}

static void sweep_elf(struct kof_diag_scan *s, const struct kof_obj_ctx *ctx,
		      const uint8_t *base, uint64_t size)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	uint32_t i;

	if (!e || !e->valid)
		return;
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		uint64_t at, have = code_range(ctx, e, i, size, &at);

		if (!have)
			continue;
		sweep_region(s, ctx, base, size, at, have);
		if (s->full)
			return;
	}
}


/* ---- the surface --------------------------------------------------------- */

/*
 * ---- THE SCENARIO TABLE ---------------------------------------------------
 *
 * One row per analysis routine - see KOF_DIAG_RUN_* in the header for why
 * they are separate at all. A row says which bit turns it on, what it is
 * called, and what it declines to run on; `fn` is then called with an object
 * it has already agreed applies to it.
 *
 * A TABLE AND NOT A CHAIN OF ifs, for the reason rule 5 gives everywhere
 * else: the next routine is a row, and nothing above has to be edited to add
 * it. The two that do not exist yet are listed with a null `fn` rather than
 * left out, so the names are in one place and `ran` can report honestly that
 * a routine was asked for and had nothing to run.
 */
typedef void (*diag_fn)(struct kof_diag_scan *, const struct kof_obj_ctx *,
			const uint8_t *, uint64_t);

struct diag_scenario {
	/* which row of the timing report this routine's cost lands in -
	 * is not an answer anybody can act on. */
	enum kof_time_slot slot;
	unsigned    bit;
	const char *name;
	diag_fn     fn;
};

void kof_diag_run_syscall(struct kof_diag_scan *s,
			  const struct kof_obj_ctx *ctx,
			  const uint8_t *base, uint64_t size)
{
	/*
	 * THE EXECUTABLE SEGMENTS WHEN THERE ARE ANY, the whole object when
	 * there are not. A payload lifted out of a variable has no program
	 * header and is still code.
	 */
	if (ctx->format == KOF_FMT_ELF) {
		sweep_elf(s, ctx, base, size);
		/* The wrapper resolution reads x86 call sites and pushes. */
		if (!fixed_arch(ctx) && (s->n_wrap || s->n_unread))
			kof_diag_run_wrappers(s, ctx, base, size);
	} else
		sweep_region(s, ctx, base, size, 0, size);
}

static const struct diag_scenario diag_scenarios[] = {
	{ KOF_T_DIAG_SYSCALL, KOF_DIAG_RUN_SYSCALL, "syscall",
	  kof_diag_run_syscall },
	{ KOF_T_DIAG_SYMBOL,  KOF_DIAG_RUN_SYMBOL,  "symbol",
	  kof_diag_run_symbol },
	{ KOF_T_DIAG_EMULATE, KOF_DIAG_RUN_EMULATE, "emulate",
	  kof_diag_run_emulate },
	{ KOF_T_DIAG_APIHASH, KOF_DIAG_RUN_APIHASH, "apihash",
	  kof_diag_run_apihash }
};

/*
 * ---- THE PRUNE THAT USED TO BE HERE, AND WHY IT IS NOT ------------------
 *
 * It dropped every node whose capability no loaded diagnose had named, and
 * the argument was sound while it held: a node nobody asked about cannot
 * end a link, so carrying it for the life of the object buys nothing. It
 * halved the graph - measured, 1200 nodes to 600 over 200 stagers.
 *
 * THE ARGUMENT DIED WHEN A VERDICT STARTED READING THE GRAPH. A verdict is
 * an algorithm, not a tree: it counts, it asks whether something is merely
 * PRESENT, and the things it asks about are exactly the ones no diagnose
 * names. Measured twice, both times as a detection quietly disappearing -
 * the cr0 write a syscall-table verdict needs is nobody's child so no tree
 * can name it, and the socket a stager verdict needs belongs to no
 * diagnose either. The second cost 28 detections across three corpora
 * before it was found.
 *
 * SO THE GRAPH IS KEPT WHOLE. What bounds it is the analysis not running -
 * see KOF_ENG_USE_PATHOGEN and the signs on a diagnose - and not what is
 * thrown away afterwards.
 */

/*
 * ONE SITE, ONE NODE - run after the routes, because only then is the whole
 * set of answers in.
 *
 * THE ROUTES OVERLAP AND THAT IS THE DESIGN. The syscall sweep reads every
 * `syscall` instruction in the executable segments; the emulator reaches
 * the ones a run arrives at, with the values it resolved. The same call is
 * therefore found twice, and each copy carries the edges ITS route could
 * prove - measured on meter1, where the swept copy of the read has the
 * buffer edge and the emulated copy has the buffer edge AND the descriptor
 * edge.
 *
 * LEAVING THE COPIES IN LOSES THE JOIN, which is the whole reason this is
 * here. A diagnose binds the first node that satisfies its tree, so the
 * memory tree bound the swept read and the socket tree bound the emulated
 * one - two records of ONE call at 0xf1, so a verdict asking whether the
 * two behaviours meet at the read got no, on a sample where they plainly
 * do.
 *
 * NOT MERGED BY `at` ALONE: a site the run produced rather than read has
 * at == KOF_BROKEN, and every one of those would fold into one node.
 */
/*
 * The bits that say a route did NOT know something, as against the ones
 * that say it saw something. See the fold below.
 */
#define DOUBT ((uint8_t)(KOF_DIAG_H_ARG_UNKNOWN | KOF_DIAG_H_OPAQUE))

static void merge_sites(struct kof_diag_scan *s)
{
	uint16_t *map, *rep;
	uint32_t i, j, n = 0;
	uint8_t k;

	if (!s || s->n_hit < 2u)
		return;
	map = malloc((size_t)s->n_hit * sizeof *map);
	rep = malloc((size_t)s->n_hit * sizeof *rep);
	if (!map || !rep) {
		free(map);
		free(rep);
		return;                 /* duplicates are worse, not fatal */
	}
	/* 1. which node each one becomes, and which old node speaks for it */
	for (i = 0; i < s->n_hit; i++) {
		for (j = 0; j < n; j++)
			if (s->hit[i].at != KOF_BROKEN &&
			    s->hit[rep[j]].at == s->hit[i].at &&
			    s->hit[rep[j]].cap == s->hit[i].cap)
				break;
		map[i] = (uint16_t)j;
		if (j == n)
			rep[n++] = (uint16_t)i;
	}
	if (n == s->n_hit) {            /* nothing to fold - the common case */
		free(map);
		free(rep);
		return;
	}
	/*
	 * 2. RENUMBER BEFORE FOLDING, not after.
	 *
	 * kof_diag_note_in refuses an edge whose (parent, role, kind) it
	 * already holds, and that test is only true when both sides are
	 * numbered the same way. Folding first and renumbering afterwards
	 * turned "from 1" and "from 7" into two copies of "from 1" - the
	 * dedup had already run and could not see them.
	 */
	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in; k++) {
			uint16_t f = s->hit[i].in[k].from;

			if (f < s->n_hit)
				s->hit[i].in[k].from = map[f];
		}
	/*
	 * 3. THE UNION OF WHAT THE ROUTES SAW. Flags and bits are
	 * observations, so either route seeing one is enough; the attribute
	 * is a value, so the first one that resolved it stands rather than
	 * being overwritten by a zero.
	 */
	for (i = 0; i < s->n_hit; i++) {
		struct kof_diag_hit *h = &s->hit[rep[map[i]]];

		if (rep[map[i]] == i)
			continue;
		h->flags |= s->hit[i].flags;
		/*
		 * NOT EVERY BIT IS AN OBSERVATION. OR-ing them all made a
		 * resolved node unresolved: the sweep cannot read a call's
		 * arguments and says so with ARG_UNKNOWN, the emulator reads
		 * them, and the union of "I could not tell" with "it is a
		 * socket" came out as "I could not tell" - spec_ok then
		 * refused the node as an anchor and the whole socket tree
		 * stopped matching on every i386 stager here.
		 *
		 * A DOUBT SURVIVES ONLY IF EVERY ROUTE HELD IT.
		 */
		h->bits = (uint8_t)(((h->bits | s->hit[i].bits) & ~DOUBT) |
				    (h->bits & s->hit[i].bits & DOUBT));
		/*
		 * AND EVERY FIELD A BIT SPEAKS FOR, or the bit outlives what
		 * it refers to. MEASURED: the symbol route reads an operand's
		 * relocation and the emulator does not, so folding only the
		 * bits left a node saying "an argument named a symbol" with
		 * the offset of that name still zero - and a diagnose about
		 * __this_module matched one rootkit and missed another for a
		 * reason that was not about either of them.
		 *
		 * First one that knows wins, as with the attribute: a route
		 * that resolved something is not corrected by one that did
		 * not.
		 */
		if (!h->attr)
			h->attr = s->hit[i].attr;
		if (!h->val)
			h->val = s->hit[i].val;
		if (!h->symref) {
			h->symref = s->hit[i].symref;
			h->symadd = s->hit[i].symadd;
		}
		for (k = 0; k < s->hit[i].n_in; k++)
			kof_diag_note_in(h, s->hit[i].in[k].from,
					 s->hit[i].in[k].role,
					 s->hit[i].in[k].kind);
	}
	/*
	 * 3b. THE NAMES FOLLOW THE NODES. Each kept name carries the index of
	 * the node of the call it was read at, and that index was the one
	 * before folding. Left alone, a name read at a node that was folded
	 * into another would point at whatever now sits in its old slot - a
	 * different call, or none - and nothing would say so: the name would
	 * simply stop belonging to the diagnose that matched its site.
	 *
	 * Rebuilt through kof_diag_str_add rather than patched in place, so two
	 * entries that become the same (capability, node, name) after the fold
	 * are one, which is the same rule the store keeps everywhere else.
	 */
	if (s->n_str) {
		struct kof_diag_str *old_str = malloc((size_t)s->n_str *
						      sizeof *old_str);
		uint32_t old_n = s->n_str, z;

		if (old_str) {
			memcpy(old_str, s->str, (size_t)old_n * sizeof *old_str);
			s->n_str = 0;
			memset(s->str_tab, 0,
			       ((size_t)s->str_tmask + 1u) * sizeof *s->str_tab);
			for (z = 0; z < old_n; z++) {
				uint16_t nd = old_str[z].node;

				if (nd < s->n_hit)
					nd = map[nd];
				kof_diag_str_add(s, old_str[z].cap, nd,
						 old_str[z].s);
			}
			free(old_str);
		}
	}
	/* 4. close the gaps */
	for (j = 0; j < n; j++)
		if (rep[j] != j)
			s->hit[j] = s->hit[rep[j]];
	s->n_hit = n;
	free(map);
	free(rep);
}

#undef DOUBT

struct kof_diag_scan *kof_diag_scan_with_inputs(const struct kof_obj_ctx *ctx,
						const uint8_t *base,
						uint64_t size, unsigned run,
						const struct kof_diag_inputs *in)
{
	struct kof_diag_scan *s;
	unsigned i;

	if (!ctx || !base || !size)
		return NULL;
	if (ctx->arch != KOF_ARCH_X86 && ctx->arch != KOF_ARCH_X86_64) {
		/*
		 * The value model reads x86 outside the syscall route; the
		 * fixed-width ports have that one only, so it is the one run.
		 */
		if (!fixed_arch(ctx))
			return NULL;
		run &= KOF_DIAG_RUN_SYSCALL;
	}
	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;
	s->base = base;
	s->size = size;
	s->relocs = in ? in->relocs : NULL;
	s->apihash = in ? in->apihash : NULL;
	for (i = 0; i < sizeof diag_scenarios / sizeof diag_scenarios[0]; i++) {
		const struct diag_scenario *d = &diag_scenarios[i];

		if (!(run & d->bit) || !d->fn)
			continue;
		KOF_TIME_BEGIN(d->slot);
		d->fn(s, ctx, base, size);
		KOF_TIME_END(d->slot);
		s->ran |= d->bit;
		if (s->full)
			break;
	}
	merge_sites(s);
	return s;
}

struct kof_diag_scan *kof_diag_scan_with(const struct kof_obj_ctx *ctx,
					 const uint8_t *base, uint64_t size,
					 unsigned run)
{
	return kof_diag_scan_with_inputs(ctx, base, size, run, NULL);
}

const struct kof_apihash *kof_diag_apihash(struct kof_diag_scan *s,
					   const struct kof_obj_ctx *ctx)
{
	if (!s->apihash && !s->apihash_done) {
		s->own_apihash = kof_apihash_run(ctx, s->base, s->size);
		s->apihash = s->own_apihash;
		/* NULL is an answer too - not asked for again */
		s->apihash_done = 1;
	}
	return s->apihash;
}

const struct kof_elf_relocs *kof_diag_relocs(struct kof_diag_scan *s,
					     const struct kof_obj_ctx *ctx,
					     unsigned kind)
{
	const struct kof_elf_info *ei = ctx && ctx->format == KOF_FMT_ELF
					? kof_elf(ctx) : NULL;
	kof_buf f;

	f.p = s->base;
	f.n = s->size;
	if (kind == KOF_ELF_RELOC_DATA) {
		if (!s->data_ready) {
			if (ei && ei->valid)
				(void)kof_elf_reloc_table(f, ei, KOF_ELF_RELOC_DATA,
							  &s->data_relocs);
			s->data_ready = 1;
		}
		return &s->data_relocs;
	}
	if (!s->relocs) {
		if (ei && ei->valid)
			(void)kof_elf_reloc_table(f, ei, KOF_ELF_RELOC_CODE,
						  &s->own_relocs);
		/* an empty table is still the answer, and is not asked for again */
		s->relocs = &s->own_relocs;
	}
	return s->relocs;
}

struct kof_diag_scan *kof_diag_scan(const struct kof_obj_ctx *ctx,
				    const uint8_t *base, uint64_t size)
{
	return kof_diag_scan_with(ctx, base, size, KOF_DIAG_RUN_DEFAULT);
}

unsigned kof_diag_scan_ran(const struct kof_diag_scan *s)
{
	return s ? s->ran : 0u;
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

/*
 * A BOUND ON COST, and a loud one: 1024 distinct names is far past anything
 * a module declares, and an object that reaches it is feeding the store
 * rather than using it. It is a limit on the work, not on what a verdict can
 * conclude - the scan is marked full, which a caller reading a list must
 * check before it says "none".
 */
#define DIAG_STR_LIMIT 1024u

/*
 * FNV-1a over the name, with the capability AND THE NODE mixed into the seed
 * so the same word handed to two different calls - or read at two different
 * places - is two different keys. 32 bits is enough
 * because every probe that matches on it then compares the bytes: a collision
 * costs one strcmp and cannot make a name appear.
 */
static uint32_t str_hash(uint16_t cap, uint16_t node, const char *s)
{
	uint32_t h = 2166136261u ^ ((uint32_t)cap * 0x9e3779b1u) ^
		     ((uint32_t)node * 0x85ebca6bu);

	while (*s) {
		h ^= (uint8_t)*s++;
		h *= 16777619u;
	}
	return h;
}

/* (Re)build the table for the current entry capacity. Failure leaves the old
 * one in place and the caller marks the scan full. */
static int str_table_build(struct kof_diag_scan *s)
{
	uint32_t sz = 2u * s->cap_str, i;
	uint16_t *t = calloc(sz, sizeof *t);

	if (!t)
		return 0;
	for (i = 0; i < s->n_str; i++) {
		uint32_t p = s->str[i].hash & (sz - 1u);

		while (t[p])
			p = (p + 1u) & (sz - 1u);
		t[p] = (uint16_t)(i + 1u);
	}
	free(s->str_tab);
	s->str_tab = t;
	s->str_tmask = sz - 1u;
	return 1;
}

int kof_diag_str_add(struct kof_diag_scan *s, uint16_t cap, uint16_t node,
		     const char *name)
{
	uint32_t h, p;
	size_t n;

	if (!s || !name || !*name)
		return 0;
	n = strlen(name);
	if (n > DIAG_STR_MAX)
		return 0;
	h = str_hash(cap, node, name);
	/* ALREADY HERE? One probe, where this was a strcmp against every entry. */
	if (s->str_tab)
		for (p = h & s->str_tmask; s->str_tab[p];
		     p = (p + 1u) & s->str_tmask) {
			const struct kof_diag_str *e =
				&s->str[s->str_tab[p] - 1u];

			if (e->hash == h && e->cap == cap && e->node == node &&
			    !strcmp(e->s, name))
				return 0;
		}
	if (s->n_str >= DIAG_STR_LIMIT) {
		s->full = 1;
		return 0;
	}
	if (s->n_str == s->cap_str) {
		uint32_t nc = s->cap_str ? s->cap_str * 2u : 16u;
		struct kof_diag_str *nv = realloc(s->str, nc * sizeof *nv);
		uint32_t old = s->cap_str;

		if (!nv) {
			s->full = 1;
			return 0;
		}
		s->str = nv;
		s->cap_str = nc;
		if (!str_table_build(s)) {
			s->cap_str = old;       /* the entries are fine; the
						 * new slot is not offered */
			s->full = 1;
			return 0;
		}
	}
	s->str[s->n_str].cap = cap;
	s->str[s->n_str].node = node;
	s->str[s->n_str].hash = h;
	memcpy(s->str[s->n_str].s, name, n + 1u);
	s->n_str++;
	for (p = h & s->str_tmask; s->str_tab[p]; p = (p + 1u) & s->str_tmask)
		;
	s->str_tab[p] = (uint16_t)s->n_str;
	return 1;
}

/* Was `name` read at THIS node, by a call of THIS capability. One probe. */
static int str_at_node(const struct kof_diag_scan *s, uint16_t cap,
		       uint16_t node, const char *name)
{
	uint32_t h, p;

	if (!s->str_tab)
		return 0;
	h = str_hash(cap, node, name);
	for (p = h & s->str_tmask; s->str_tab[p]; p = (p + 1u) & s->str_tmask) {
		const struct kof_diag_str *e = &s->str[s->str_tab[p] - 1u];

		if (e->hash == h && e->cap == cap && e->node == node &&
		    !strcmp(e->s, name))
			return 1;
	}
	return 0;
}

const char *kof_diag_str_at(const struct kof_diag_scan *s, uint16_t cap,
			    uint32_t i)
{
	uint32_t k;

	if (!s)
		return NULL;
	for (k = 0; k < s->n_str; k++)
		if (s->str[k].cap == cap && i-- == 0u)
			return s->str[k].s;
	return NULL;
}

uint32_t kof_diag_str_count(const struct kof_diag_scan *s, uint16_t cap)
{
	uint32_t k, n = 0;

	if (!s)
		return 0;
	for (k = 0; k < s->n_str; k++)
		if (s->str[k].cap == cap)
			n++;
	return n;
}

void kof_diag_scan_free(struct kof_diag_scan *s)
{
	if (!s)
		return;
	free(s->str_tab);
	free(s->str);
	free(s->adj_head);
	free(s->adj_edge);
	free(s->wrap);
	kof_apihash_free(s->own_apihash);
	kof_elf_reloc_table_free(&s->own_relocs);
	kof_elf_reloc_table_free(&s->data_relocs);
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
 * node by construction - see the note on anchors in kofmod/kofpathogen.h.
 */

/* A node satisfies a spec when it has the capability, carries every flag the
 * spec demands, and is not one whose meaning the walk could not read. The
 * last is the point of KOF_DIAG_H_ARG_UNKNOWN: a `mmap` whose prot could not
 * be followed is not evidence of a buffer OR of a code region. */
/* The NUL-terminated name a hit pointed at, or NULL. */
static const char *hit_sym(const struct kof_diag_scan *s,
			   const struct kof_diag_hit *h)
{
	uint64_t i;

	if (!s || !s->base || !(h->bits & KOF_DIAG_H_SYMREF) ||
	    h->symref >= s->size)
		return NULL;
	/* Terminated inside the object, or it is not a name. */
	for (i = h->symref; i < s->size; i++)
		if (!s->base[i])
			return (const char *)(s->base + h->symref);
	return NULL;
}

static int spec_ok(const struct kof_diag_scan *s,
		   const struct kof_diag_hit *h,
		   const struct kof_diag_node *sp)
{
	/*
	 * THE WORD THE RULE NAMED, OR ANY KIND OF IT. A rule saying mem-read
	 * is satisfied by net-recv, because net-recv IS a mem-read whose
	 * descriptor turned out to be a socket - see kof_flow_cap_generic.
	 * Comparing for equality made a rule stop matching whenever the
	 * engine learned something more about the program it described.
	 */
	if (h->cap != sp->cap) {
		uint16_t g = h->cap;
		int kind = 0;

		while ((g = kof_flow_cap_generic(g)) != KOF_NUCLEO_NONE)
			if (g == sp->cap) { kind = 1; break; }
		if (!kind)
			return 0;
	}
	if ((h->flags & sp->flags) != sp->flags)
		return 0;
	if (h->bits & (KOF_DIAG_H_ARG_UNKNOWN | KOF_DIAG_H_SUPERSEDED))
		return 0;
	/*
	 * AND THE VALUE, WHEN THE DIAGNOSE NAMED ONE - see KOF_DIAG_B_VAL.
	 *
	 * The node must have written a LITERAL and it must be that one. A
	 * node whose value the model never learnt does not match: "we could
	 * not tell" is not the same answer as "it wrote zero", and folding
	 * them would let an author who can lose the model write anything.
	 */
	if (sp->bits & KOF_DIAG_B_VAL) {
		if (!(h->bits & KOF_DIAG_H_VAL) || h->val != sp->val)
			return 0;
	}
	/*
	 * AND A FIELD OF THE NAMED SYMBOL - see KOF_DIAG_B_FIELD_OF. A FIELD,
	 * so offset zero does not count: that is the handle itself, which a
	 * module passes to the kernel all day.
	 */
	if (sp->bits & KOF_DIAG_B_FIELD_OF) {
		const char *nm = hit_sym(s, h);

		if (!nm || !sp->sym || !h->symadd ||
		    !kof_streq_(nm, sp->sym))
			return 0;
	}
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
		  const struct kof_diag_hit *parent, uint8_t role,
		  uint8_t want)
{
	uint8_t i;

	/*
	 * AND OF WHICH KIND, where the diagnose says - see KOF_DIAG_B_SHARED.
	 * Neither bit is "either", which is what a diagnose written before
	 * the kinds existed asked for and still asks for.
	 */
	want &= (uint8_t)(KOF_DIAG_B_PRODUCED | KOF_DIAG_B_SHARED);

	for (i = 0; i < child->n_in; i++) {
		if (child->in[i].role != role)
			continue;
		if (want) {
			uint8_t is = child->in[i].kind == KOF_DIAG_KIND_SHARED
				     ? (uint8_t)KOF_DIAG_B_SHARED
				     : (uint8_t)KOF_DIAG_B_PRODUCED;

			if (!(want & is))
				continue;
		}
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
			if (!spec_ok(s, &s->hit[i], &d->node[c]))
				continue;
			if (!linked(&s->hit[i], bound[k], &s->hit[bound[k]],
				    d->node[c].role, d->node[c].bits))
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

/*
 * ---- THE VALUE-FLOW GRAPH, AND REACHING ACROSS IT -----------------------
 *
 * A hit records its edges as "where each of my inputs came from", tagged
 * with a role. A join needs the transitive question - does the value a
 * socket read produced reach the region that was executed - and the bytes
 * do not have to arrive in one step: a stager may read into a scratch
 * buffer and copy that into the executable region, so the read and the
 * region are two hops apart with the copy between them. The old join asked
 * only whether one node was bound by both diagnoses, which is the zero-hop
 * case and the one a scratch buffer steps around.
 *
 * SO THE EDGES ARE TURNED INTO A DIRECTED GRAPH, once, and the join is a
 * walk. The direction is VALUE FLOW, which the role decides and which is
 * not the same as the in[] relation:
 *
 *   FD / SOURCE   the parent PRODUCED this value - it flows parent -> here
 *   TARGET        control goes to the parent region - its bytes are what
 *                 runs, so parent -> here (the region's value becomes the
 *                 execution)
 *   BUFFER        this call WRITES INTO the parent - the value flows the
 *                 other way, here -> parent (what we read/built lands in
 *                 that region)
 *
 * On a plain stager this makes net-open -> read -> region -> exec one
 * directed chain, and a read whose buffer is a scratch page instead of the
 * region extends it by exactly the copy node in between.
 */
static int diag_flow_build(struct kof_diag_scan *s)
{
	uint32_t i, e = 0;
	uint8_t k;

	if (s->adj_built)
		return s->adj_head != NULL;
	s->adj_built = 1;
	if (!s->n_hit)
		return 0;
	s->adj_head = calloc((size_t)s->n_hit + 1u, sizeof *s->adj_head);
	/* At most four edges a node, and the stack/none sentinels are not
	 * edges. */
	s->adj_edge = malloc((size_t)s->n_hit * 4u * sizeof *s->adj_edge);
	if (!s->adj_head || !s->adj_edge) {
		free(s->adj_head); free(s->adj_edge);
		s->adj_head = NULL; s->adj_edge = NULL;
		return 0;
	}
	/* Two passes: count per source, then fill. The source of an edge is
	 * not always `from` - a BUFFER edge runs from the writing node. */
	for (i = 0; i < s->n_hit; i++)
		for (k = 0; k < s->hit[i].n_in; k++) {
			uint16_t p = s->hit[i].in[k].from;
			uint8_t  ro = s->hit[i].in[k].role;

			if (p >= s->n_hit)
				continue;       /* NONE / STACK, not a node */
			if (ro == KOF_DIAG_ROLE_BUFFER)
				s->adj_head[i + 1u]++;      /* i -> p */
			else
				s->adj_head[p + 1u]++;      /* p -> i */
		}
	for (i = 0; i < s->n_hit; i++)
		s->adj_head[i + 1u] += s->adj_head[i];
	e = s->adj_head[s->n_hit];
	{
		uint32_t *cur = calloc((size_t)s->n_hit, sizeof *cur);

		if (!cur) {
			free(s->adj_head); free(s->adj_edge);
			s->adj_head = NULL; s->adj_edge = NULL;
			return 0;
		}
		for (i = 0; i < s->n_hit; i++)
			for (k = 0; k < s->hit[i].n_in; k++) {
				uint16_t p = s->hit[i].in[k].from;
				uint8_t  ro = s->hit[i].in[k].role;
				uint16_t from, to;

				if (p >= s->n_hit)
					continue;
				if (ro == KOF_DIAG_ROLE_BUFFER) {
					from = (uint16_t)i; to = p;
				} else {
					from = p; to = (uint16_t)i;
				}
				s->adj_edge[s->adj_head[from] + cur[from]++] = to;
			}
		free(cur);
	}
	(void)e;
	return 1;
}

/*
 * Does the value at `start` reach any node whose bit is set in `tgt`,
 * following value-flow edges. One O(V+E) walk over a reused frontier - the
 * visited set means a node is expanded once however many starts share it.
 */
static int diag_flow_reach(struct kof_diag_scan *s, uint16_t start,
			   const uint8_t *tgt, uint8_t *seen, uint16_t *stk)
{
	uint32_t sp = 0;

	if (start >= s->n_hit || (seen[start >> 3] & (1u << (start & 7u))))
		return 0;
	if (tgt[start >> 3] & (1u << (start & 7u)))
		return 1;
	seen[start >> 3] |= (uint8_t)(1u << (start & 7u));
	stk[sp++] = start;
	while (sp) {
		uint16_t u = stk[--sp];
		uint32_t j;

		for (j = s->adj_head[u]; j < s->adj_head[u + 1u]; j++) {
			uint16_t v = s->adj_edge[j];

			if (seen[v >> 3] & (1u << (v & 7u)))
				continue;
			if (tgt[v >> 3] & (1u << (v & 7u)))
				return 1;
			seen[v >> 3] |= (uint8_t)(1u << (v & 7u));
			stk[sp++] = v;
		}
	}
	return 0;
}

/*
 * DOES A NODE OF `cap` BOUND BY `b` REACH ANY NODE BOUND BY `a`.
 *
 * The join a verdict asks, as reachability rather than a shared node: the
 * bytes a socket read produced (a node of `cap`, bound by the net diagnose
 * `b`) flow - directly or through a copy - into the region the exec
 * diagnose `a` is about. `a_bind`/`b_bind` are the node sets the match
 * returned for each.
 */
int kof_diag_flow_join(struct kof_diag_scan *s, uint16_t cap,
		       const uint16_t *a_bind, uint8_t na,
		       const uint16_t *b_bind, uint8_t nb)
{
	uint8_t tgt[(DIAG_MAX_NODE + 7u) / 8u];
	uint8_t seen[(DIAG_MAX_NODE + 7u) / 8u];
	uint16_t *stk;
	uint8_t x;
	int hit = 0;

	if (!s || !diag_flow_build(s) || !a_bind || !b_bind)
		return 0;
	memset(tgt, 0, sizeof tgt);
	memset(seen, 0, sizeof seen);
	for (x = 0; x < na; x++)
		if (a_bind[x] < s->n_hit)
			tgt[a_bind[x] >> 3] |= (uint8_t)(1u << (a_bind[x] & 7u));
	stk = malloc((size_t)s->n_hit * sizeof *stk);
	if (!stk)
		return 0;
	for (x = 0; x < nb && !hit; x++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, b_bind[x]);

		if (h && h->cap == cap)
			hit = diag_flow_reach(s, b_bind[x], tgt, seen, stk);
	}
	free(stk);
	return hit;
}

/*
 * EVERY PLACE A TREE MATCHES, one call of `fn` for each, with the node each of
 * the diagnose's own nodes was bound to. `fn` returns zero to stop.
 *
 * THIS IS THE MATCHER; kof_diag_match is the first-instance reading of it.
 * It stopped at the first root that satisfied the tree and every later
 * question - the names a diagnose carries, in particular - was answered from
 * that one place. A module with two probes on two symbols has two matches of
 * the same tree, and a diagnose "carrying" a name from the second was a
 * diagnose the engine had never looked at.
 */
typedef int (*diag_inst_fn)(void *user, const uint16_t *bound, uint8_t n_node);

static void match_each(const struct kof_diag_scan *s, const struct kof_diag *d,
		       diag_inst_fn fn, void *user)
{
	uint16_t bound[256];
	uint32_t i;
	uint8_t root;

	/* n_node is a uint8_t, so 255 is its ceiling already - the bound that
	 * matters is `bound[]` below holding one slot per node, and 256 is
	 * more than a uint8_t can index past. */
	if (!s || !d || !d->n_node)
		return;
	for (root = 0; root < d->n_node; root++)
		if (d->node[root].parent == KOF_DIAG_NO_PARENT)
			break;
	if (root == d->n_node)
		return;                 /* no root: not a tree */

	for (i = 0; i < s->n_hit; i++) {
		if (!spec_ok(s, &s->hit[i], &d->node[root]))
			continue;
		memset(bound, 0xff, sizeof bound);
		bound[root] = (uint16_t)i;
		if (!bind_from(s, d, root, bound))
			continue;
		if (!fn(user, bound, d->n_node))
			return;
	}
}

struct first_match {
	uint16_t *out;
	uint8_t  *n_out;
	int       found;
};

static int first_cb(void *user, const uint16_t *bound, uint8_t n_node)
{
	struct first_match *f = user;
	uint8_t k, n = 0;

	/*
	 * EVERY BOUND NODE COMES BACK, not a declared subset.
	 *
	 * The diagnose used to mark the ones it offered as join points, and
	 * only those were returned. That put a fact about TWO behaviours
	 * inside the declaration of ONE - the author of the stager's read had
	 * to know the socket diagnose existed - and it silently lost the join
	 * whenever the mark was on the wrong node. The verdict names the
	 * capability it wants the two to meet at instead, so the engine has to
	 * hand back everything they bound.
	 */
	for (k = 0; k < n_node && f->out; k++)
		f->out[n++] = bound[k];
	if (f->n_out)
		*f->n_out = n;
	f->found = 1;
	return 0;                       /* the first instance is the answer */
}

int kof_diag_match(const struct kof_diag_scan *s, const struct kof_diag *d,
		   uint16_t *bind_out, uint8_t *n_bind)
{
	struct first_match f;

	if (n_bind)
		*n_bind = 0;
	f.out = bind_out;
	f.n_out = n_bind;
	f.found = 0;
	match_each(s, d, first_cb, &f);
	return f.found;
}

struct name_probe {
	const struct kof_diag_scan *s;
	const char *name;
	int         found;
};

/* Was the name read at ANY node this instance bound. */
static int name_cb(void *user, const uint16_t *bound, uint8_t n_node)
{
	struct name_probe *np = user;
	uint8_t k;

	for (k = 0; k < n_node; k++) {
		uint16_t b = bound[k];

		if (b < np->s->n_hit &&
		    str_at_node(np->s, np->s->hit[b].cap, b, np->name)) {
			np->found = 1;
			return 0;
		}
	}
	return 1;
}

int kof_diag_scan_name(const struct kof_diag_scan *s, const struct kof_diag *d,
		       const char *name)
{
	struct name_probe np;

	if (!s || !d || !name)
		return 0;
	np.s = s;
	np.name = name;
	np.found = 0;
	match_each(s, d, name_cb, &np);
	return np.found;
}

/* ---- loading -------------------------------------------------------------
 *
 * A RECORD IS ONE DIAGNOSE and nothing else - no module, no pattern, no blob.
 * The records of a database are carried in diag-<kind>.kdig packs (see
 * load_diagnoses in dbloader.c), which is a file beside the packs rather than a
 * section inside one: the pack header carries a fixed-size section table, so
 * one more section is a format change every database in existence has to be
 * rebuilt for, and none of what a pack exists to carry applies here.
 *
 * EVERYTHING IS BOUNDS CHECKED AGAINST THE RECORD'S OWN LENGTH, and a record
 * that does not add up is refused whole rather than loaded in part. A diagnose
 * half read is a diagnose that matches something its author did not write.
 */

int kof_diag_load(const uint8_t *b, uint64_t n, struct kof_diag *out,
		  struct kof_diag_node *node, uint8_t max_node,
		  char *name, uint32_t name_cap,
		  char *needs, uint32_t needs_cap)
{
	uint32_t n_node, nlen, i;
	/* How much of the string store a node attribute has taken - the
	 * signs below continue from here, because both are words this
	 * diagnose carries and one buffer is one thing to bound. */
	uint32_t nused = 0;
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
		at += 8u;
		if (at + alen > n)
			return 0;
		/*
		 * (kind, length, payload)*, and an unknown kind is skipped by
		 * its length rather than refused - that is what the length is
		 * for. A length that runs past the run refuses the record,
		 * like everything else here.
		 */
		{
			uint32_t k = 0;

			while (k + 2u <= alen) {
				uint32_t kind = b[at + k];
				uint32_t klen = b[at + k + 1u];

				k += 2u;
				if (k + klen > alen)
					return 0;
				/*
				 * THE NAME GOES IN THE DIAGNOSE'S OWN
				 * STRING STORE, beside the signs - it is the
				 * same kind of thing, a word this diagnose
				 * carries, and a second buffer would be a
				 * second thing to bound.
				 */
				if (kind == KDIG_ATTR_SYM && klen &&
				    needs && needs_cap) {
					if (nused + klen + 1u > needs_cap)
						return 0;
					memcpy(needs + nused, b + at + k, klen);
					needs[nused + klen] = 0;
					node[i].sym = needs + nused;
					nused += klen + 1u;
				}
				if (kind == KDIG_ATTR_VALUE && klen == 8u) {
					uint64_t v = 0;
					unsigned q;

					for (q = 0; q < 8u; q++)
						v |= (uint64_t)b[at + k + q]
						     << (q * 8u);
					node[i].val = v;
				}
				k += klen;
			}
		}
		at += alen;
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
	/*
	 * ---- THE SIGNS, IF THE PACK CARRIES ANY -------------------------
	 *
	 * A trailing section, so a pack written before they existed simply
	 * ends after its nodes and answers none. Refused WHOLE on anything
	 * that does not add up, like the rest of the record: a diagnose with
	 * half its signs read would be filtered by a condition nobody wrote.
	 */
	if (needs && needs_cap && at < n) {
		uint32_t cnt = b[at++], k, used = nused;

		/*
		 * THE NAMES AN OLDER PACK WROTE HERE ARE SKIPPED, not read: the
		 * sign is now a capability (KDIG_SEC_NEEDS), and a diagnose
		 * built before that simply has no sign, which is the cheaper
		 * kind of wrong - it runs where it could have been spared.
		 */
		if (cnt > KOF_DIAG_MAX_NEED)
			return 0;
		for (k = 0; k < cnt; k++) {
			uint32_t L;

			if (at >= n)
				return 0;
			L = b[at++];
			if (!L || L >= KOF_DIAG_NEED_LEN || at + L > n)
				return 0;
			at += L;
		}
		/*
		 * ---- AND THE TAGGED SECTIONS AFTER THEM ----------------
		 *
		 * An unknown tag is SKIPPED and not refused: the length is
		 * there so a later build can add a section without every
		 * reader having to be taught it first. A length that runs
		 * past the end is a different matter and refuses the whole
		 * record, like everything else here.
		 */
		while (at + 2u <= n) {
			uint32_t tag = b[at], len = b[at + 1u];

			at += 2u;
			if (at + len > n)
				return 0;
			/*
			 * (fact u16, value u64) pairs - see KOF_DIAG_WHEN.
			 * A FACT THIS BUILD DOES NOT KNOW REFUSES THE WHOLE
			 * RECORD: a condition silently dropped is a diagnose
			 * that runs on the files its author excluded, and it
			 * would do so quietly.
			 */
			if (tag == KDIG_SEC_SERVES && len == 1u)
				out->serves = b[at];
			/* The capabilities the object must import - u16 each. */
			if (tag == KDIG_SEC_NEEDS) {
				uint32_t q;

				if ((len & 1u) || len / 2u > KOF_DIAG_MAX_NEED)
					return 0;
				for (q = 0; q < len / 2u; q++)
					out->needcap[q] = (uint16_t)(b[at + 2u * q] |
							(b[at + 2u * q + 1u] << 8));
				out->n_needcap = (uint8_t)(len / 2u);
			}
			if (tag == KDIG_SEC_USERS && len >= 1u) {
				out->users_known = 1;
				out->n_users = b[at];
			}
			/*
			 * THE SYMBOLS THE CODE MUST REFER INTO - see
			 * KOF_DIAG_REFS. Same shape and the same string store as
			 * the signs, and refused whole on anything that does not
			 * add up, for the same reason: a diagnose with half its
			 * references read would be gated by a condition nobody
			 * wrote.
			 */
			if (tag == KDIG_SEC_REFS && len >= 1u && needs && needs_cap) {
				uint32_t cnt2 = b[at], z, p2 = at + 1u;

				if (cnt2 > KOF_DIAG_MAX_NEED)
					return 0;
				for (z = 0; z < cnt2; z++) {
					uint32_t L2;

					if (p2 >= at + len)
						return 0;
					L2 = b[p2++];
					if (!L2 || L2 >= KOF_DIAG_NEED_LEN ||
					    p2 + L2 > at + len ||
					    used + L2 + 1u > needs_cap)
						return 0;
					memcpy(needs + used, b + p2, L2);
					needs[used + L2] = 0;
					out->ref[z] = needs + used;
					used += L2 + 1u;
					p2 += L2;
				}
				out->n_ref = (uint8_t)cnt2;
			}
			if (tag == KDIG_SEC_WHEN) {
				uint32_t q;

				if (len % 10u)
					return 0;
				if (len / 10u > KOF_DIAG_MAX_WHEN)
					return 0;
				for (q = 0; q + 10u <= len; q += 10u) {
					const uint8_t *w = b + at + q;
					uint64_t v = 0;
					unsigned t;
					uint16_t fc = (uint16_t)(w[0] |
							 (w[1] << 8));

					if (!fc || fc >= KOF_FACT_COUNT)
						return 0;
					for (t = 0; t < 8u; t++)
						v |= (uint64_t)w[2 + t]
						     << (t * 8u);
					out->when[out->n_when].fact = fc;
					out->when[out->n_when].val = v;
					out->n_when++;
				}
			}
			at += len;
		}
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

static void gr_u64(uint8_t *p, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		p[i] = (uint8_t)(v >> (i * 8u));
}

static void gr_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

uint32_t kof_diag_graph_build(const struct kof_diag_scan *s, uint8_t *out,
			      uint32_t cap)
{
	uint32_t i, need;

	if (!s || !out || !s->n_hit)
		return 0;
	need = KOF_GR_HDRLEN + s->n_hit * KOF_GR_RECLEN;
	if (need > cap)
		return 0;       /* refused whole - a half graph answers wrong */
	memset(out, 0, need);
	out[KOF_GR_H_COUNT]      = (uint8_t)s->n_hit;
	out[KOF_GR_H_COUNT + 1u] = (uint8_t)(s->n_hit >> 8);
	out[KOF_GR_H_COUNT + 2u] = (uint8_t)(s->n_hit >> 16);
	out[KOF_GR_H_COUNT + 3u] = (uint8_t)(s->n_hit >> 24);
	for (i = 0; i < s->n_hit; i++) {
		const struct kof_diag_hit *h = &s->hit[i];
		uint8_t *r = out + KOF_GR_HDRLEN + i * KOF_GR_RECLEN;
		uint8_t k, nin = h->n_in > KOF_GR_IN_MAX
			       ? (uint8_t)KOF_GR_IN_MAX : h->n_in;

		gr_u64(r + KOF_GR_R_AT, h->at);
		gr_u64(r + KOF_GR_R_ATTR, h->attr);
		gr_u16(r + KOF_GR_R_CAP, h->cap);
		gr_u16(r + KOF_GR_R_FLAGS, h->flags);
		/* No bit is told to a rule yet: the one there was said `attr`
		 * is a name's offset, and names are no longer carried that
		 * way. The byte stays in the format at zero. */
		r[KOF_GR_R_BITS] = 0u;
		r[KOF_GR_R_NIN] = nin;
		for (k = 0; k < nin; k++) {
			uint8_t *p = r + KOF_GR_R_IN + k * KOF_GR_IN_STRIDE;

			gr_u16(p, h->in[k].from);
			p[2] = h->in[k].role;
			p[3] = h->in[k].kind == KOF_DIAG_KIND_SHARED
			     ? (uint8_t)KOF_DIAG_KIND_SHARED
			     : (uint8_t)KOF_DIAG_KIND_PRODUCED;
		}
	}
	return need;
}

