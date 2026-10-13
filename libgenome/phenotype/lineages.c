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

#include "lineages.h"
#include <kofdebug.h>
#include "diag_int.h"
#include <kofcore.h>
#include <celllysis/celllysis.h>
#include <celllysis/nucleo.h>
#include <celllysis/space.h>
#include <genotype/image/funcs.h>


/*
 * kgenome_diag_note sets a status on the scan: the one way a limit reports that
 * the answer is partial (kgenome_status.h). The ledger's own status (memory
 * refused) is merged in when the status is read.
 */
void kgenome_diag_note(struct kgenome_diag_scan *s, enum kgenome_status st)
{
	if (s)
		s->status = kgenome_status_merge(s->status, st);
}

void kgenome_diag_org_clear(struct kgenome_walk *w, uint8_t r)
{
	if (r < 16u) {
		w->reg[r].node = KGENOME_ORG_NONE;
		/* The symbol goes with it: all three fields answer the same
		 * question - where did this value come from - and leaving one
		 * behind would have a register naming a symbol it no longer
		 * holds. */
		w->reg[r].symoff = 0;
		w->reg[r].symadd = 0;
	}
}

uint16_t kgenome_diag_org_of(const struct kgenome_walk *w, uint8_t r)
{
	return r < 16u ? w->reg[r].node : KGENOME_ORG_NONE;
}

void kgenome_diag_org_set(struct kgenome_walk *w, uint8_t r, uint16_t node)
{
	if (r >= 16u)
		return;
	w->reg[r].node = node;
	/* One question, three fields - see struct kgenome_org. A register that now
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
void kgenome_diag_org_set_sym(struct kgenome_walk *w, uint8_t r, uint32_t symoff,
			  int32_t symadd)
{
	if (!w || r >= 16u)
		return;
	w->reg[r].node = KGENOME_ORG_NONE;
	w->reg[r].symoff = symoff;
	w->reg[r].symadd = symadd;
}

uint32_t kgenome_diag_org_sym(const struct kgenome_walk *w, uint8_t r, int32_t *add)
{
	if (!w || r >= 16u)
		return 0;
	if (add)
		*add = w->reg[r].symadd;
	return w->reg[r].symoff;
}

void kgenome_diag_org_step(struct kgenome_walk *w, const struct kgenome_cell_insn *in)
{
	uint8_t r, d, e;

	if (in->op == KGENOME_CELL_PUSH) {
		uint16_t v = KGENOME_ORG_NONE;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG)
			v = kgenome_diag_org_of(w, in->o[0].reg);
		if (w->n_stk < KGENOME_ORG_STK)
			w->stk[w->n_stk].node = v;
		w->n_stk++;
		return;
	}
	if (in->op == KGENOME_CELL_POP) {
		uint16_t v = KGENOME_ORG_NONE;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk < KGENOME_ORG_STK)
				v = w->stk[w->n_stk].node;
		}
		/* A popped LIST names no operand; wmask has them all. */
		for (r = 0; r < 16u; r++)
			if (in->wmask & (1ull << r))
				kgenome_diag_org_clear(w, r);
		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG)
			kgenome_diag_org_set(w, in->o[0].reg, v);
		return;
	}
	if (in->op == KGENOME_CELL_XCHG && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_REG) {
		uint16_t a;

		d = in->o[0].reg; e = in->o[1].reg;
		a = kgenome_diag_org_of(w, d);
		kgenome_diag_org_set(w, d, kgenome_diag_org_of(w, e));
		kgenome_diag_org_set(w, e, a);
		return;
	}
	if (in->op == KGENOME_CELL_MOV && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].size >= 4u) {
		if (in->o[1].kind == KGENOME_CELL_O_REG) {
			/*
			 * A VALUE TAKEN FROM THE STACK POINTER IS A STACK
			 * ADDRESS, and that is a provenance of its own.
			 * msfvenom's i386 stager makes the stack executable
			 * and jumps into it; mprotect returns 0, so there is
			 * no pointer to follow from the allocation to the
			 * jump and the only thing that links them is that
			 * both addresses came off esp.
			 */
			kgenome_diag_org_set(w, in->o[0].reg,
				in->o[1].reg == (w->sp ? w->sp : KGENOME_CELL_REG_SP) ? KGENOME_ORG_STACK
				: kgenome_diag_org_of(w, in->o[1].reg));
			return;
		}
		kgenome_diag_org_clear(w, in->o[0].reg);
		return;
	}
	/*
	 * AND/SHR/SHL OVER A STACK ADDRESS IS STILL A STACK ADDRESS. The
	 * i386 stager rounds esp down to a page with `shr 0xc; shl 0xc`
	 * before handing it to mprotect; killing the provenance there breaks
	 * the only link that sample has.
	 */
	if ((in->op == KGENOME_CELL_AND || in->op == KGENOME_CELL_SHR || in->op == KGENOME_CELL_SHL) &&
	    in->n_op && in->o[0].kind == KGENOME_CELL_O_REG &&
	    kgenome_diag_org_of(w, in->o[0].reg) == KGENOME_ORG_STACK)
		return;

	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r))
			kgenome_diag_org_clear(w, r);
}

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofpathogen.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */


static int hit_room(struct kgenome_diag_scan *s)
{
	struct kgenome_diag_hit *nv;
	uint32_t nc;

	if (s->n_hit < s->cap_hit)
		return 1;
	if (s->n_hit >= kgenome_diag_node_limit(s)) {
		/* THE NODE LIMIT: the walk stops, every node found is kept and the
		 * answer says it is partial (see the note at KGENOME_MAX_INDEX and
		 * kgenome_budget_default for how the limit scales). */
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return 0;
	}
	nc = s->cap_hit ? s->cap_hit * 2u : 64u;
	if (nc > kgenome_diag_node_limit(s))
		nc = kgenome_diag_node_limit(s);
	if (!kgenome_ledger_charge(&s->led, (uint64_t)(nc - s->cap_hit) * sizeof *nv)) {
		s->halt = 1;            /* the ledger noted KGENOME_OVER_BUDGET */
		return 0;
	}
	nv = realloc(s->hit, nc * sizeof *nv);
	if (!nv) {
		kgenome_ledger_release(&s->led, (uint64_t)(nc - s->cap_hit) * sizeof *nv);
		s->halt = 1;
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	s->hit = nv;
	s->cap_hit = nc;
	return 1;
}

struct kgenome_diag_hit *kgenome_diag_hit_add(struct kgenome_diag_scan *s, uint64_t at,
				    uint16_t cap, uint16_t flags)
{
	struct kgenome_diag_hit *h;

	if (!hit_room(s))
		return NULL;
	h = &s->hit[s->n_hit++];
	memset(h, 0, sizeof *h);
	h->at = at;
	h->cap = cap;
	h->flags = flags;
	return h;
}

void kgenome_diag_hit_nonblock(struct kgenome_diag_scan *s, uint64_t at, uint16_t open_idx)
{
	struct kgenome_diag_hit *n = kgenome_diag_hit_add(s, at, KGENOME_NUCLEO_FD_NONBLOCK, 0);

	if (n)
		kgenome_diag_note_in(s, n, open_idx, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED);
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
 * Taken from nucleo's kgenome_fxabi rather than written again here - a second copy
 * of "rdi, rsi, rdx, r10, r8, r9" is a second thing to get wrong when a
 * port is added, and the sweep that had its own copy is the reason this
 * rule exists.
 */
static int arg_regs(const struct kgenome_obj *obj, const uint8_t **out)
{
	static const uint8_t x64[] = { KGENOME_CELL_REG_DI, KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t x86[] = { KGENOME_CELL_REG_BX, KGENOME_CELL_REG_CX, KGENOME_CELL_REG_DX,
				       KGENOME_CELL_REG_SI, KGENOME_CELL_REG_DI, KGENOME_CELL_REG_BP };

	if (obj->arch == KGENOME_ARCH_X86_64) {
		*out = x64;
		return (int)(sizeof x64 / sizeof x64[0]);
	}
	if (obj->arch == KGENOME_ARCH_X86) {
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
 * KGENOME_NUCLEO_NONE with KGENOME_DIAG_H_OPAQUE set - see the note on that flag. A
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
 * the invariant kgenome_diag_note_in rests on. That function refuses a link whose
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
uint8_t kgenome_diag_role_of_arg(uint16_t cap, unsigned i)
{
	switch (cap) {
	/* Bytes through a descriptor: what is filled, and from where. */
	case KGENOME_NUCLEO_MEM_READ:
	case KGENOME_NUCLEO_READ:
	case KGENOME_NUCLEO_NET_READ:
		return i == 1u ? KGENOME_DIAG_ROLE_BUFFER
		     : i == 0u ? KGENOME_DIAG_ROLE_FD
			       : KGENOME_DIAG_ROLE_NONE;
	case KGENOME_NUCLEO_MEM_WRITE:
	case KGENOME_NUCLEO_WRITE:
	case KGENOME_NUCLEO_NET_WRITE:
		return i == 1u ? KGENOME_DIAG_ROLE_SOURCE
		     : i == 0u ? KGENOME_DIAG_ROLE_FD
			       : KGENOME_DIAG_ROLE_NONE;
	/* Across the user/kernel boundary: one buffer each way, and they are
	 * different objects - see KGENOME_DIAG_ROLE_SOURCE. */
	case KGENOME_NUCLEO_COPY_FROM_USER:
	case KGENOME_NUCLEO_COPY_TO_USER:
		return i == 0u ? KGENOME_DIAG_ROLE_BUFFER
		     : i == 1u ? KGENOME_DIAG_ROLE_SOURCE
			       : KGENOME_DIAG_ROLE_NONE;
	case KGENOME_NUCLEO_NET_CONNECT:
	case KGENOME_NUCLEO_NET_BIND:
	case KGENOME_NUCLEO_NET_LISTEN:
	case KGENOME_NUCLEO_NET_ACCEPT:
	case KGENOME_NUCLEO_FD_REDIR:
	case KGENOME_NUCLEO_FD_NONBLOCK:
	case KGENOME_NUCLEO_NET_HDRINCL:
		return i == 0u ? KGENOME_DIAG_ROLE_FD : KGENOME_DIAG_ROLE_NONE;
	case KGENOME_NUCLEO_EXEC_IMAGE:
		return i == 0u ? KGENOME_DIAG_ROLE_PATH : KGENOME_DIAG_ROLE_NONE;
	/* The credentials being installed are the ones that were built. */
	case KGENOME_NUCLEO_CRED_SET:
	/* Both halves of the probe take the same struct kprobe. */
	case KGENOME_NUCLEO_KPROBE_REG:
	case KGENOME_NUCLEO_KPROBE_UNREG:
	/* The list entry being taken out or put back. */
	case KGENOME_NUCLEO_LIST_HIDE:
		return i == 0u ? KGENOME_DIAG_ROLE_BUFFER : KGENOME_DIAG_ROLE_NONE;
	default:
		return KGENOME_DIAG_ROLE_NONE;
	}
}

struct kgenome_diag_hit *kgenome_diag_hit_of(struct kgenome_diag_scan *s, uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : 0;
}

void kgenome_diag_note_in(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
		      uint16_t from, uint8_t role, uint8_t kind)
{
	uint8_t i;

	if (!h || from == KGENOME_ORG_NONE)
		return;
	/*
	 * THE SAME LINK TWICE IS ONE LINK.
	 *
	 * A run that goes round a loop arrives at the same call with the same
	 * value from the same producer; a sweep can reach one site from two
	 * windows. Neither has found a second relation. Recording it again
	 * would fill the four slots with copies and push out a real one -
	 * MEASURED before this was here: meter1's retry loop produced ten
	 * copies of one link.
	 */
	/*
	 * THE SAME LINK IS (parent, role, KIND). Two relations between one
	 * pair of nodes are two links - see enum kgenome_diag_kind - and only a
	 * repeat of all three is the loop arriving again.
	 */
	for (i = 0; i < h->n_in; i++)
		if (h->in[i].from == from && h->in[i].role == role &&
		    h->in[i].kind == kind)
			return;
	/*
	 * FOUR INPUTS A NODE - a read has two that matter (the buffer and the
	 * descriptor) and nothing measured has needed more than three. A fifth
	 * DISTINCT link is not kept and is not silent: it sets KGENOME_TRUNCATED.
	 * The slot count is not raised because the graph block the modules read
	 * (kofpathogen.h, KOF_GR_IN_MAX) has four, and a fifth kept here would be
	 * cut there without a word - a limit moved to a boundary nobody reads.
	 * This test used to come first, so a repeat of a link was refused as
	 * "full" on a node that was; it now says "full" only for a real fifth.
	 */
	if (h->n_in >= 4u) {
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return;
	}
	h->in[h->n_in].from = from;
	h->in[h->n_in].role = role;
	h->in[h->n_in].how  = KGENOME_DIAG_LINK_PROVEN;
	h->in[h->n_in].kind = kind;
	h->n_in++;
}

/*
 * A SYSCALL WHOSE ARGUMENT THE WALK COULD NOT READ BECAUSE IT IS THE CALLER'S.
 * Kept as file offsets; the list grows with the input and is bounded by it,
 * since there cannot be more of these than there are `int 0x80` in the object.
 */
static void wrap_note(struct kgenome_diag_scan *s, uint64_t at)
{
	uint32_t i;

	for (i = 0; i < s->n_wrap; i++)
		if (s->wrap[i] == at)
			return;
	if (s->n_wrap == s->cap_wrap) {
		uint32_t nc = s->cap_wrap ? s->cap_wrap * 2u : 8u;
		uint64_t *nw;

		if (!kgenome_ledger_charge(&s->led,
					   (uint64_t)(nc - s->cap_wrap) * sizeof *nw))
			return;         /* noted: KGENOME_OVER_BUDGET */
		nw = realloc(s->wrap, (size_t)nc * sizeof *nw);
		if (!nw) {
			kgenome_ledger_release(&s->led,
					       (uint64_t)(nc - s->cap_wrap) * sizeof *nw);
			kgenome_diag_note(s, KGENOME_NOMEM);
			return;
		}
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
static void note_node(struct kgenome_diag_scan *s, struct kgenome_walk *w, uint64_t at,
		      uint16_t cap, uint8_t fl, const char *nm,
		      const uint8_t *ar, int n_ar, unsigned have,
		      uint8_t ret_reg, int nonblock, int carry)
{
	struct kgenome_diag_hit *h;

	h = kgenome_diag_hit_add(s, at, cap, fl);
	if (!h)
		return;
	/*
	 * The third argument is the one that separates a code region from a
	 * buffer, and the first two separate a socket from a raw socket.
	 * Unread, the node says so rather than carrying the answer those
	 * bits would have given if they had been zero.
	 */
	if ((cap == KGENOME_NUCLEO_ALLOC && !(have & (1u << 2))) ||
	    (cap == KGENOME_NUCLEO_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KGENOME_DIAG_H_ARG_UNKNOWN;

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
		 * FROM kgenome_diag_role_of_arg AND NOT FROM A LIST OF NAMES.
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
			uint8_t role = kgenome_diag_role_of_arg(cap, k);

			if (role != KGENOME_DIAG_ROLE_NONE)
				kgenome_diag_note_in(s, h, kgenome_diag_org_of(w, ar[k]),
						 role, KGENOME_DIAG_KIND_PRODUCED);
		}
	}

	/*
	 * AND WHAT THIS CALL HANDS BACK, so the next node can be linked to
	 * it. mmap returns the region; mprotect returns ZERO and names the
	 * region in its first argument instead, which is why the two are
	 * not one case.
	 */
	if (kgenome_flow_hands_on(cap, nm)) {
		uint16_t made = (uint16_t)(s->n_hit - 1u);

		kgenome_diag_org_set(w, ret_reg, made);
		if ((cap == KGENOME_NUCLEO_NET_OPEN || cap == KGENOME_NUCLEO_NET_RAW) &&
		    nonblock)
			kgenome_diag_hit_nonblock(s, at, made);
	} else {
		/*
		 * mprotect is the capability that does NOT hand one back,
		 * and the one case where the region it was GIVEN still
		 * matters: a stack mapping made executable is a payload
		 * about to run off the stack.
		 */
		if ((cap == KGENOME_NUCLEO_ALLOC || cap == KGENOME_NUCLEO_ALLOC_EXEC ||
		     cap == KGENOME_NUCLEO_HEAP) && n_ar >= 1 &&
		    kgenome_diag_org_of(w, ar[0]) == KGENOME_ORG_STACK)
			h->bits |= KGENOME_DIAG_H_REGION_STACK;
		kgenome_diag_org_clear(w, ret_reg);
	}

	/* Arm the carry for the next conditional branch - see walk.carry_to. */
	if (carry && nm && kgenome_sys_zero_on_success(nm))
		h->bits |= KGENOME_DIAG_H_ZERO_OK;
}

/*
 * ---- THE FIXED-WIDTH PORTS ------------------------------------------------
 *
 * ARM and AArch64 reach the kernel through one instruction, `svc`, with the
 * number in a register the ABI names (r7, x8) and the arguments in the first
 * six. All of that is nucleo's kgenome_fxabi - the same row the old whole-image sweep
 * read - so this is only the reading of it: no byte pattern to search for, no
 * second syscall encoding to tell apart, and none of the x86 special cases
 * (socketcall, the zero-on-success carry) because ARM has neither.
 *
 * OLD ARM ABI: `svc 0x9000NN` carries the number in the instruction itself and
 * r7 is not read. Both are seen in the static IoT builds, so both are handled.
 */
static int fixed_arch(const struct kgenome_obj *obj)
{
	return obj->arch == KGENOME_ARCH_ARM || obj->arch == KGENOME_ARCH_ARM64;
}

#define ARM_OABI_BASE 0x900000u

static void at_syscall_fixed(struct kgenome_diag_scan *s, struct kgenome_cell_cur *k,
			     struct kgenome_walk *w, const struct kgenome_obj *obj,
			     const struct kgenome_cell_insn *in)
{
	const struct kgenome_fxabi *fx = kgenome_fx_abi_of(obj->arch == KGENOME_ARCH_ARM
					       ? KGENOME_FLOW_A_ARM32
					       : KGENOME_FLOW_A_ARM64);
	uint8_t ar[6];
	uint64_t nr = 0, arg[6];
	struct kgenome_diag_hit *h;
	const char *nm;
	uint16_t cap;
	uint8_t fl = 0;
	unsigned have = 0;
	int i, n_ar = fx->n_arg < 6 ? fx->n_arg : 6;
	uint64_t imm = in->n_op && in->o[0].kind == KGENOME_CELL_O_IMM ? in->o[0].imm : 0;

	if (obj->arch == KGENOME_ARCH_ARM && imm >= ARM_OABI_BASE &&
	    imm < ARM_OABI_BASE + 0x10000u) {
		nr = imm - ARM_OABI_BASE;
	} else if (!kgenome_cell_reg(k, fx->sel, &nr) || nr > 0xffffu) {
		/* The number is the caller's: a candidate wrapper, as on x86. */
		s->n_unread++;
		h = kgenome_diag_hit_add(s, in->at, KGENOME_NUCLEO_NONE, 0);
		if (h)
			h->bits |= KGENOME_DIAG_H_OPAQUE;
		return;
	}
	for (i = 0; i < n_ar; i++) {
		ar[i] = (uint8_t)(fx->arg0 + i);
		if (kgenome_cell_reg(k, ar[i], &arg[i]))
			have |= 1u << i;
		else
			arg[i] = 0;
	}
	if (!(have & 1u))
		s->n_unread++;
	cap = kgenome_flow_cap_of_syscall_abi(fx, (uint32_t)nr, arg, &fl);
	nm = kgenome_sys_name_abi(fx, (uint32_t)nr);
	if (cap == KGENOME_NUCLEO_NONE)
		return;
	note_node(s, w, in->at, cap, fl, nm, ar, n_ar, have, fx->ret,
		  (have & 2u) && (arg[1] & 0x800u) /* SOCK_NONBLOCK */, 0);
}

static void at_syscall(struct kgenome_diag_scan *s, struct kgenome_cell_cur *k,
		       struct kgenome_walk *w, const struct kgenome_obj *obj,
		       const struct kgenome_cell_insn *in)
{
	const uint64_t at = in->at;

	const uint8_t *ar;
	uint64_t nr = 0, arg[6];
	struct kgenome_diag_hit *h;
	const char *nm;
	uint16_t cap;
	uint8_t fl = 0;
	int n_ar, i, bits;
	unsigned have = 0;          /* which of arg[] came from a known register */

	if (fixed_arch(obj)) {
		at_syscall_fixed(s, k, w, obj, in);
		return;
	}
	bits = obj->arch == KGENOME_ARCH_X86_64 ? 64 : 32;
	n_ar = arg_regs(obj, &ar);

	/*
	 * THE SYSCALL VOCABULARY IS LINUX'S, SO IT IS ONLY ASKED ABOUT LINUX.
	 *
	 * A `syscall` instruction in a PE carries a WINDOWS service number,
	 * and the number spaces have nothing to do with each other.
	 * kgenome_flow_cap_of_syscall only knows the Linux table, so handing it a
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
	 * A number that WAS read is KGENOME_DIAG_H_RAW_SYSCALL - a program
	 * reaching the kernel without going through ntdll, which is what the
	 * hook-evading loaders do and the one thing this walk can say about a
	 * PE that the import table cannot. A number that was not read is
	 * OPAQUE, which is what `0f 05` in packed data looks like. Reporting
	 * both as opaque would bury the first in the second.
	 */
	if (obj->format != KGENOME_FMT_ELF) {
		int got = !w->ax_stale &&
			  kgenome_cell_reg(k, KGENOME_CELL_REG_AX, &nr) && nr <= 0xffffu;

		h = kgenome_diag_hit_add(s, at, KGENOME_NUCLEO_NONE, 0);
		if (h)
			h->bits |= got ? KGENOME_DIAG_H_RAW_SYSCALL
				       : KGENOME_DIAG_H_OPAQUE;
		return;
	}

	if (w->ax_stale || !kgenome_cell_reg(k, KGENOME_CELL_REG_AX, &nr) ||
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
			h = kgenome_diag_hit_add(s, at, KGENOME_NUCLEO_NONE, 0);
			if (h)
				h->bits |= KGENOME_DIAG_H_OPAQUE;
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
		if (kgenome_cell_reg(k, ar[i], &arg[i]))
			have |= 1u << i;
		else
			arg[i] = 0;
	}
	for (; i < 6; i++)
		arg[i] = 0;

	if (!(have & 1u))
		s->n_unread++;          /* a candidate wrapper - see diag_wrap.c */
	cap = kgenome_flow_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
	nm  = kgenome_sys_name((unsigned)bits, (uint32_t)nr);
	if (cap == KGENOME_NUCLEO_NONE) {
		/*
		 * i386's socketcall IS A MULTIPLEXER: the sub-call that says
		 * socket from connect from send is in ebx, and a libc that
		 * wraps it (uClibc, in the static IoT builds) loads ebx from
		 * its own PARAMETER - `mov edx,[esp+0x10]; xchg ebx,edx` - so
		 * at this instruction it is the caller's value and not the
		 * walk's. This used to return here without a word: MEASURED, 27
		 * of 30 static i386 bots had the instruction and not one net
		 * node. Remember the site; kgenome_diag_run_wrappers reads what every caller
		 * pushed.
		 */
		if (bits == 32 && nr == 102u && !(have & 1u))
			wrap_note(s, at);
		return;                 /* a syscall the vocabulary has no word for */
	}
	note_node(s, w, at, cap, fl, nm, ar, n_ar, have, KGENOME_CELL_REG_AX,
		  kgenome_flow_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have),
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
 * `0f 34` sysenter, `cd 80` int 0x80 - see the KGENOME_CELL_SYSCALL arm of class_of
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
static uint64_t cand_fixed(const struct kgenome_obj *obj, const uint8_t *p,
			   uint64_t off, uint64_t from, uint64_t n)
{
	uint64_t i = from + ((4u - ((off + from) & 3u)) & 3u);
	int be = obj->arch == KGENOME_ARCH_ARM && obj->format == KGENOME_FMT_ELF &&
		 obj->file_header && ((const uint8_t *)obj->file_header)[5] == 2u;

	for (; i + 4u <= n; i += 4u) {
		uint32_t x = be ? ((uint32_t)p[i] << 24 | (uint32_t)p[i + 1] << 16 |
				   (uint32_t)p[i + 2] << 8 | p[i + 3])
				: kof_ld_le32(p + i);

		if (obj->arch == KGENOME_ARCH_ARM ? svc_a32(x) : x == 0xd4000001u)
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
 * ONE TEST FOR EVERY WALK. The sweep below and the wrapper analysis's walk
 * (diag_wrap.c) each had their own copy; they agreed on every ELF the engine
 * walks (the wrapper walk only runs on x86 ELF), but one of them could have
 * drifted. `vec80` is "this is a software interrupt with vector 0x80", which
 * each caller reads from its own form of the instruction.
 *
 * THIS IS NOT THE DIRECT-SYSCALL TEST, and must not be mistaken for one. A
 * Hell's Gate stub is `mov r10,rcx; mov eax,SSN; syscall` in a 64-bit PE,
 * which this accepts - as it should - along with every stray `0f 05` in a
 * 64-bit packed section. Telling those apart needs the r10 shape, and that
 * is a separate piece of work.
 */
int kgenome_diag_kernel_entry(const struct kgenome_obj *obj, unsigned op,
			  int vec80, const uint8_t *p)
{
	int bits64 = obj->arch == KGENOME_ARCH_X86_64;

	if (fixed_arch(obj))
		return op == KGENOME_CELL_SYSCALL;
	if (op == KGENOME_CELL_SYSCALL)
		return p[0] == 0x0fu && p[1] == 0x05u ? bits64 : !bits64;
	if (op == KGENOME_CELL_INT && vec80)
		return obj->format == KGENOME_FMT_ELF;
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
 * or nothing - and the wrapper analysis (diag_wrap.c) is what resolves those
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
static int origins_live(const struct kgenome_walk *w)
{
	uint32_t i;

	if (w->carry_armed || w->carry_live)
		return 1;
	for (i = 0; i < 16u; i++)
		if (w->reg[i].node != KGENOME_ORG_NONE)
			return 1;
	for (i = 0; i < w->n_stk && i < KGENOME_ORG_STK; i++)
		if (w->stk[i].node != KGENOME_ORG_NONE)
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
	struct kgenome_walk w;
	struct kgenome_cell_insn in;    /* decoded, not yet acted on (when `live`) */
	int live;                       /* suspended: `in` is the next instruction */
	uint16_t wrote;                 /* the registers written since the window began */
};

static int sweep_window(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			const uint8_t *base, const struct kgenome_cell_space *sp,
			uint64_t off, uint64_t n, uint64_t c, uint64_t at,
			const struct sweep_win *from, struct sweep_win *out,
			uint64_t *end, int *unread)
{
	struct kgenome_cell_cur k;
	struct kgenome_cell_insn in;
	struct kgenome_walk w;
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
			w.reg[r].node = KGENOME_ORG_NONE;
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

			at_syscall(s, &k, &w, obj, &in);
			w.ax_stale = 1;
			/* THE CANDIDATE'S OWN site, and what it could not read is a
			 * value a wider window might find - see DIAG_LEAD_WIDE. */
			if (in.at == off + c && s->n_hit > n0 && !fixed_arch(obj)) {
				const struct kgenome_diag_hit *h = &s->hit[n0];
				const uint8_t *ar;
				int n_ar = arg_regs(obj, &ar), q;

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

			if (t != KGENOME_ORG_NONE) {
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
	uint64_t c, done = 0;

	if (!n || off >= size)
		return;
	if (off + n > size)
		n = size - off;
	kgenome_cell_space_init(&sp, obj, base, size);
	memset(&susp, 0, sizeof susp);
	memset(&nxt, 0, sizeof nxt);

	/*
	 * ONE WINDOW PER CANDIDATE, AND THE NEXT ONE STARTS WHERE THIS ONE
	 * STOPPED. A candidate the previous window already walked over is
	 * not walked again - two syscalls a few instructions apart are one
	 * window, which is also the only way the second one sees what the
	 * first produced.
	 */
#define CAND(from) (fixed_arch(obj) ? cand_fixed(obj, base + off, off, (from), n) \
				    : cand_at(base + off, (from), n))
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
			if (!sweep_window(s, obj, base, &sp, off, n, c, at, from, &nxt,
					  &end, &unread)) {
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
 * THE EXECUTABLE BYTES OF SEGMENT `i`: PT_LOAD with PF_X, clipped to what the
 * object holds. Zero for anything else. The ONE statement of what the loader
 * maps as code; every reader gets it through kgenome_diag_code_range, which moves
 * the start past the headers.
 */
static uint64_t kof_diag_code_seg(const struct kgenome_elf_info *e, uint32_t i,
				  uint64_t size, uint64_t *at)
{
	const struct kgenome_elf_seg *g = &e->seg[i];
	uint64_t have, off;

	if (!kgenome_elf_seg_is_code(g))
		return 0;               /* PT_LOAD, executable */
	have = kgenome_elf_seg_extent(g, size, &off);
	if (have)
		*at = off;
	return have;
}

/*
 * THE CODE RANGES OF AN ELF: THE BYTES OF EXECUTABLE SEGMENT `i` THAT CAN BE
 * INSTRUCTIONS - the segment, clipped to the object, past the ELF header and the
 * program headers when the segment holds them. Zero for a segment that is not
 * code. The ONE definition, and everything that reads an ELF's code starts from
 * it: the xref sweep (when the object has no executable section) reads it as it
 * is, and kgenome_diag_walk_range below refines its start for the walks that decode
 * every byte.
 *
 * THE HEADERS ARE NOT CODE. A segment usually begins at file offset zero and so
 * holds the ELF header and the program headers; read from the front,
 * `7f E L F 02 01 01 ...` is decoded as instructions. MEASURED on msfvenom's
 * x86-64 stager: the mmap at +0x8d came back with its number unreadable, because
 * the push that sets it had been swallowed by an instruction decoded across the
 * header boundary. They end at e_phoff + e_phnum * e_phentsize (never before the
 * ELF header itself).
 */
uint64_t kgenome_diag_code_range(const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at)
{
	uint64_t have = kof_diag_code_seg(e, i, size, at);
	uint64_t hdr = e->elf_class == KGENOME_ELFCLASS_64 ? 64u : 52u;
	uint64_t pend = e->phoff + (uint64_t)e->phnum * e->phentsize;

	if (!have)
		return 0;
	if (pend > hdr && pend >= e->phoff)             /* no wrap */
		hdr = pend;
	if (*at < hdr && hdr - *at < have) {
		have -= hdr - *at;
		*at = hdr;
	}
	return have;
}

/*
 * WHERE A WALK THAT DECODES EVERY BYTE OF THE SEGMENT BEGINS. A linear sweep is
 * alignment sensitive: bytes that are not instructions, decoded as if they were,
 * carry their desync into the real code after them, so the start of the walk has
 * to be a place the object says instructions are. The three things that say so,
 * each used for what it is:
 *
 *   THE LINKER'S SECTION TABLE, WHERE THERE IS ONE: the first executable
 *   section inside the segment. This is the one place the segment walks need the
 *   section view, and for a reason the segments cannot give: a segment holds
 *   .interp, .dynsym, .rela, the section header table and, in a Go binary, 4 KiB
 *   of both before .text, and only the section table says none of it is code.
 *   The rule before this one started at the entry point and lost everything
 *   before it: gcc -O2 puts main in .text.startup ahead of _start (main =
 *   0x401040, _start = 0x401070 in a measured binary), a Go binary's .text starts
 *   340 KiB before its entry, a static libc has code before it too. MEASURED over
 *   the 1239 ELF files here, the nodes of 27 change and every change is code the
 *   old start never read.
 *
 *   THE ENTRY POINT, WHERE THE SECTIONS SAY NOTHING - a sectionless payload, a
 *   packer's output, a table that marks nothing in this segment executable. It is
 *   the one offset certain to be the first byte of an instruction, and everything
 *   before it is unknown: compressed data, filler, a header the code lives in.
 *   Starting after the headers instead was tried, and the unit test "deep in a
 *   big segment" (a payload after 8 KiB of bytes that are not instructions, as a
 *   packer leaves them) loses its whole node tree, because the filler's desync
 *   swallows the stub. It is also the lower bound when the entry precedes the
 *   first executable section: a table that hides the code.
 *
 *   THE HEADERS, always: kgenome_diag_code_range.
 *
 * What this cannot do: a sectionless ordinary binary whose main sits before
 * _start still loses it - nothing in the object says where its code begins, and
 * the entry is the only start that does not risk the desync. The xref sweep reads
 * the unrefined range instead (see xref_runs) because its budget counts from the
 * front and it must not report "complete" for code it never read.
 */
uint64_t kgenome_diag_walk_range(const struct kgenome_obj *obj,
			     const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at)
{
	uint64_t have = kgenome_diag_code_range(e, i, size, at);
	uint64_t seg, from, first = UINT64_MAX, eo = obj ? obj->entry_off : KGENOME_BROKEN;
	uint32_t k;

	if (!have)
		return 0;
	seg = *at;
	from = seg;
	for (k = 0; k < e->sec_count && k < KGENOME_ELF_MAX_SECTIONS; k++) {
		uint64_t sat, shave;

		if (!kgenome_elf_sec_is_code(&e->sec[k]))
			continue;
		shave = kgenome_elf_sec_extent(&e->sec[k], size, &sat);
		if (shave && sat >= seg && sat - seg < have && sat < first)
			first = sat;
	}
	if (first != UINT64_MAX)
		from = first;
	/* The entry, when the table has no start here - or starts after it. */
	if (eo >= seg && eo - seg < have && (first == UINT64_MAX || eo < first))
		from = eo;
	have -= from - seg;
	*at = from;
	return have;
}

/*
 * THE EXECUTABLE BYTES OF AN OBJECT, which is what a budget scales its limits
 * from: the loadable executable segments of an ELF as the walks read them
 * (kgenome_diag_walk_range), the code sections of a PE, and the whole object for
 * anything else - a payload lifted out of a variable has no header and is all
 * code. Never zero for a non-empty object.
 */
uint64_t kgenome_diag_code_bytes(const struct kgenome_obj *obj, uint64_t size)
{
	uint64_t total = 0;
	uint32_t i;

	if (!obj || !size)
		return size;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		if (e && e->valid) {
			for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
				uint64_t at;

				total += kgenome_diag_walk_range(obj, e, i, size, &at);
			}
		}
	} else if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		if (p && p->valid) {
			for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
				uint64_t at;

				if (kgenome_pe_sec_is_code(&p->sec[i]))
					total += kgenome_pe_sec_extent(&p->sec[i], size, &at);
			}
		}
	} else {
		return size;
	}
	return total ? total : size;
}

static void sweep_elf(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
		      const uint8_t *base, uint64_t size)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
	uint32_t i;

	if (!e || !e->valid)
		return;
	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		uint64_t at, have = kgenome_diag_walk_range(obj, e, i, size, &at);

		if (!have)
			continue;
		sweep_region(s, obj, base, size, at, have);
		if (s->halt)
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
typedef void (*diag_fn)(struct kgenome_diag_scan *, const struct kgenome_obj *,
			const uint8_t *, uint64_t);

struct diag_scenario {
	/* which row of the timing report this routine's cost lands in -
	 * is not an answer anybody can act on. */
	enum kof_time_slot slot;
	unsigned    bit;
	const char *name;
	diag_fn     fn;
};

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
		if (!fixed_arch(obj) && (s->n_wrap || s->n_unread))
			kgenome_diag_run_wrappers(s, obj, base, size);
	} else
		sweep_region(s, obj, base, size, 0, size);
}

static const struct diag_scenario diag_scenarios[] = {
	{ KOF_T_DIAG_SYSCALL, KGENOME_DIAG_RUN_SYSCALL, "syscall",
	  kgenome_diag_run_syscall },
	{ KOF_T_DIAG_SYMBOL,  KGENOME_DIAG_RUN_SYMBOL,  "symbol",
	  kgenome_diag_run_symbol },
	{ KOF_T_DIAG_EMULATE, KGENOME_DIAG_RUN_EMULATE, "emulate",
	  kgenome_diag_run_emulate },
	{ KOF_T_DIAG_APIHASH, KGENOME_DIAG_RUN_APIHASH, "apihash",
	  kgenome_diag_run_apihash }
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
 * at == KGENOME_BROKEN, and every one of those would fold into one node.
 */
/*
 * The bits that say a route did NOT know something, as against the ones
 * that say it saw something. See the fold below.
 */
#define DOUBT ((uint8_t)(KGENOME_DIAG_H_ARG_UNKNOWN | KGENOME_DIAG_H_OPAQUE))

static void merge_sites(struct kgenome_diag_scan *s)
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
		kgenome_diag_note(s, KGENOME_NOMEM);    /* the copies stay: said */
		return;                 /* duplicates are worse, not fatal */
	}
	/* 1. which node each one becomes, and which old node speaks for it */
	for (i = 0; i < s->n_hit; i++) {
		for (j = 0; j < n; j++)
			if (s->hit[i].at != KGENOME_BROKEN &&
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
	 * kgenome_diag_note_in refuses an edge whose (parent, role, kind) it
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
		struct kgenome_diag_hit *h = &s->hit[rep[map[i]]];

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
			kgenome_diag_note_in(s, h, s->hit[i].in[k].from,
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
	 * Rebuilt through kgenome_diag_str_add rather than patched in place, so two
	 * entries that become the same (capability, node, name) after the fold
	 * are one, which is the same rule the store keeps everywhere else.
	 */
	if (s->n_str) {
		struct kgenome_diag_str *old_str = malloc((size_t)s->n_str *
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
				kgenome_diag_str_add(s, old_str[z].cap, nd,
						 old_str[z].s);
			}
			free(old_str);
		} else {
			/* The names keep the OLD node numbers: some now point at the
			 * wrong node. Said, not hidden. */
			kgenome_diag_note(s, KGENOME_NOMEM);
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

struct kgenome_diag_scan *kgenome_diag_scan_with_inputs(const struct kgenome_obj *obj,
						const uint8_t *base,
						uint64_t size, unsigned run,
						const struct kgenome_diag_inputs *in)
{
	struct kgenome_diag_scan *s;
	unsigned i;

	if (!obj || !base || !size)
		return NULL;
	if (obj->arch != KGENOME_ARCH_X86 && obj->arch != KGENOME_ARCH_X86_64) {
		/*
		 * The value model reads x86 outside the syscall route; the
		 * fixed-width ports have that one only, so it is the one run.
		 */
		if (!fixed_arch(obj))
			return NULL;
		run &= KGENOME_DIAG_RUN_SYSCALL;
	}
	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;
	/*
	 * THE BUDGET: the caller's, with every field it left at zero filled by the
	 * default for THIS object. The scan never reads engine state to find a limit.
	 */
	{
		struct kgenome_budget dflt;
		const struct kgenome_budget *b = in ? in->budget : NULL;

		kgenome_budget_default(&dflt, b && b->obj_size ? b->obj_size : size,
				       b && b->code_bytes ? b->code_bytes
							  : kgenome_diag_code_bytes(obj, size));
		s->bud = dflt;
		if (b) {
			if (b->max_bytes)
				s->bud.max_bytes = b->max_bytes;
			if (b->max_insn)
				s->bud.max_insn = b->max_insn;
			if (b->max_insn_resolve)
				s->bud.max_insn_resolve = b->max_insn_resolve;
			if (b->max_steps)
				s->bud.max_steps = b->max_steps;
			if (b->max_nodes)
				s->bud.max_nodes = b->max_nodes;
			if (b->max_names)
				s->bud.max_names = b->max_names;
			s->bud.deadline_ms = b->deadline_ms;
		}
		/* The indexes are 16 bits: a width, not a choice (KGENOME_MAX_INDEX). */
		if (s->bud.max_nodes > KGENOME_MAX_INDEX)
			s->bud.max_nodes = KGENOME_MAX_INDEX;
		if (s->bud.max_names > KGENOME_MAX_INDEX)
			s->bud.max_names = KGENOME_MAX_INDEX;
		kgenome_ledger_init(&s->led, s->bud.max_bytes);
	}
	s->base = base;
	s->size = size;
	s->relocs = in ? in->relocs : NULL;
	s->funcs = in ? in->funcs : NULL;
	s->walk = in ? in->walk : NULL;
	kgenome_diag_walk_bind(s->walk, &s->led);
	s->apihash = in ? in->apihash : NULL;
	s->imports = in ? in->imports : NULL;
	s->seq = in ? in->seq : NULL;
	s->n_seq = in ? in->n_seq : 0;
	for (i = 0; i < sizeof diag_scenarios / sizeof diag_scenarios[0]; i++) {
		const struct diag_scenario *d = &diag_scenarios[i];

		if (!(run & d->bit) || !d->fn)
			continue;
		KOF_TIME_BEGIN(d->slot);
		d->fn(s, obj, base, size);
		KOF_TIME_END(d->slot);
		s->ran |= d->bit;
		if (s->halt)
			break;
	}
	merge_sites(s);
	return s;
}

struct kgenome_diag_scan *kgenome_diag_scan_with(const struct kgenome_obj *obj,
					 const uint8_t *base, uint64_t size,
					 unsigned run)
{
	return kgenome_diag_scan_with_inputs(obj, base, size, run, NULL);
}

const struct kgenome_apihash *kgenome_diag_apihash(struct kgenome_diag_scan *s,
					   const struct kgenome_obj *obj)
{
	if (!s->apihash && !s->apihash_done) {
		s->own_apihash = kgenome_apihash_run(obj, s->base, s->size,
						 kgenome_diag_imports(s, obj), &s->bud);
		s->apihash = s->own_apihash;
		/* NULL is an answer too - not asked for again */
		s->apihash_done = 1;
	}
	return s->apihash;
}

/*
 * THE FUNCTIONS, ONE SET. The scanner's, when it handed one over; otherwise built
 * on first use from the object this scan was given and kept - the same two
 * shapes the relocation table has, and for the same reason: a route must not
 * care who produced what it reads, and nobody lists them twice.
 */
/*
 * THE FUNCTIONS OF AN OBJECT: its symbols' extents, and - only when it has none -
 * the ones its code enters, found by the wrapper analysis's own walk. One call
 * for the scanner, the diagnose routes and the viewer, so the answer cannot
 * differ between them.
 */
void kgenome_diag_funcs_with_walk(const struct kgenome_obj *obj, const uint8_t *data,
			      uint64_t data_n, struct kgenome_diag_walk *walk,
			      int want_trace, struct kgenome_func_set *out)
{
	struct kgenome_diag_walk *own = NULL;
	const uint64_t *ent;
	uint32_t n;

	kgenome_funcs_build(obj->format, data, data_n, obj->file_header, out);
	if (out->n || out->status != KGENOME_OK || obj->format != KGENOME_FMT_ELF || !obj->file_header)
		return;
	if (!walk)
		walk = own = kgenome_diag_walk_new();
	if (kgenome_diag_walk_ensure(walk, obj, data, data_n, want_trace)) {
		ent = kgenome_diag_walk_entries(walk, &n);
		if (n)
			kgenome_elf_funcs_from_entries(kof_buf_make(data, data_n),
						   obj->file_header, obj->entry_off,
						   ent, n, out);
	}
	kgenome_diag_walk_free(own);
}

void kgenome_diag_funcs_of(const struct kgenome_obj *obj, const uint8_t *data,
		       uint64_t data_n, struct kgenome_func_set *out)
{
	kgenome_diag_funcs_with_walk(obj, data, data_n, NULL, 0, out);
}

/*
 * THE FUNCTIONS OF A NORMALISED VIEW - the parent's, found again in the view's
 * bytes. One call for every tool that lists or scores the view's units, so the
 * sequence (the parent's own functions, then kgenome_funcs_remap over the view) is
 * written once. `parent_funcs` is the parent's set when the caller already
 * holds it; NULL builds it here.
 */
void kgenome_diag_funcs_of_view(const struct kgenome_obj *parent_obj, kof_buf parent,
			    const struct kgenome_func_set *parent_funcs, kof_buf view,
			    struct kgenome_func_set *out)
{
	struct kgenome_func_set own;

	memset(out, 0, sizeof *out);
	if (!parent_obj || !parent.p || !view.p)
		return;
	memset(&own, 0, sizeof own);
	if (!parent_funcs) {
		kgenome_diag_funcs_of(parent_obj, parent.p, parent.n, &own);
		parent_funcs = &own;
	}
	kgenome_funcs_remap(parent.p, parent.n, parent_funcs, view.p, view.n, out);
	kgenome_funcs_free(&own);
}

const struct kgenome_func_set *kgenome_diag_funcs(struct kgenome_diag_scan *s,
					  const struct kgenome_obj *obj)
{
	if (!s->funcs) {
		if (obj && obj->file_header) {
			kgenome_diag_funcs_with_walk(obj, s->base, s->size,
						 kgenome_diag_scan_walk(s), 0,
						 &s->own_funcs);
			/* The set is built by the part that knows the object, so it is
			 * charged when it is done: past the allowance the scan says
			 * KGENOME_OVER_BUDGET (the set is kept - it is the answer the
			 * routes read - and the caller's budget is what to raise). */
			(void)kgenome_ledger_charge(&s->led, (uint64_t)s->own_funcs.n *
						    sizeof *s->own_funcs.v);
			if (s->own_funcs.status != KGENOME_OK)
				kgenome_diag_note(s, s->own_funcs.status);
		}
		s->funcs = &s->own_funcs;
	}
	return s->funcs;
}

const struct kgenome_elf_relocs *kgenome_diag_relocs(struct kgenome_diag_scan *s,
					     const struct kgenome_obj *obj,
					     unsigned kind)
{
	const struct kgenome_elf_info *ei = obj && obj->format == KGENOME_FMT_ELF
					? kgenome_obj_elf(obj) : NULL;
	kof_buf f;

	f.p = s->base;
	f.n = s->size;
	if (kind == KGENOME_ELF_RELOC_DATA) {
		if (!s->data_ready) {
			if (ei && ei->valid)
				(void)kgenome_elf_reloc_table(f, ei, KGENOME_ELF_RELOC_DATA,
							  &s->data_relocs);
			s->data_ready = 1;
		}
		return &s->data_relocs;
	}
	if (!s->relocs) {
		if (ei && ei->valid)
			(void)kgenome_elf_reloc_table(f, ei, KGENOME_ELF_RELOC_CODE,
						  &s->own_relocs);
		/* an empty table is still the answer, and is not asked for again */
		s->relocs = &s->own_relocs;
	}
	return s->relocs;
}

struct kgenome_diag_scan *kgenome_diag_scan(const struct kgenome_obj *obj,
				    const uint8_t *base, uint64_t size)
{
	return kgenome_diag_scan_with(obj, base, size, KGENOME_DIAG_RUN_DEFAULT);
}

unsigned kgenome_diag_scan_ran(const struct kgenome_diag_scan *s)
{
	return s ? s->ran : 0u;
}

uint32_t kgenome_diag_scan_count(const struct kgenome_diag_scan *s)
{
	return s ? s->n_hit : 0u;
}

const struct kgenome_diag_hit *kgenome_diag_scan_at(const struct kgenome_diag_scan *s,
					    uint32_t i)
{
	return (s && i < s->n_hit) ? &s->hit[i] : NULL;
}

enum kgenome_status kgenome_diag_scan_status(const struct kgenome_diag_scan *s)
{
	if (!s)
		return KGENOME_BAD_INPUT;
	return kgenome_status_merge(s->status, s->led.status);
}

uint32_t kgenome_diag_scan_refused(const struct kgenome_diag_scan *s)
{
	return s ? s->n_str_refused : 0u;
}

uint64_t kgenome_diag_scan_bytes(const struct kgenome_diag_scan *s, uint64_t *peak)
{
	if (peak)
		*peak = s ? s->led.peak : 0;
	return s ? s->led.used : 0;
}

/* THIN WRAPPER over kgenome_diag_scan_status - see lineages.h. */
int kgenome_diag_scan_full(const struct kgenome_diag_scan *s)
{
	return s && kgenome_diag_scan_status(s) != KGENOME_OK;
}

/*
 * HOW MANY DISTINCT NAMES ARE KEPT - kgenome_budget.max_names: max(1024, the
 * node limit), at most 65534 (the table's 16-bit index). The fixed 1024 was a
 * bound on a result: it sat above anything a module declares (0 to ~25) but
 * below what a big object's call sites read, and the 1025th name was dropped.
 * It scales with the nodes now, because a name is read at a call site and an
 * object cannot have more of them than it has nodes. Reaching it is a bound on
 * cost, not a statement about the object, and it is not silent: the name is
 * counted (kgenome_diag_scan_refused), the status is KGENOME_TRUNCATED, and a
 * caller reading a list must check it before it says "none".
 */

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
 * one in place and the caller notes the status. The table is charged to the
 * ledger: the new one is charged before the old one is given back. */
static int str_table_build(struct kgenome_diag_scan *s)
{
	uint32_t sz = 2u * s->cap_str, i;
	uint16_t *t;
	uint64_t old_bytes = s->str_tab ? ((uint64_t)s->str_tmask + 1u) * sizeof *t : 0;

	if (!kgenome_ledger_charge(&s->led, (uint64_t)sz * sizeof *t))
		return 0;
	t = calloc(sz, sizeof *t);
	if (!t) {
		kgenome_ledger_release(&s->led, (uint64_t)sz * sizeof *t);
		kgenome_diag_note(s, KGENOME_NOMEM);
		return 0;
	}
	kgenome_ledger_release(&s->led, old_bytes);
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

int kgenome_diag_str_add(struct kgenome_diag_scan *s, uint16_t cap, uint16_t node,
		     const char *name)
{
	uint32_t h, p;
	size_t n;

	if (!s || !name || !*name)
		return 0;
	n = strlen(name);
	if (n > KGENOME_DIAG_STR_MAX) {
		/* Refused, COUNTED, and said: a diagnose reading this name cannot
		 * match it, which is "cannot say" and not "absent". */
		s->n_str_refused++;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return 0;
	}
	h = str_hash(cap, node, name);
	/* ALREADY HERE? One probe, where this was a strcmp against every entry. */
	if (s->str_tab)
		for (p = h & s->str_tmask; s->str_tab[p];
		     p = (p + 1u) & s->str_tmask) {
			const struct kgenome_diag_str *e =
				&s->str[s->str_tab[p] - 1u];

			if (e->hash == h && e->cap == cap && e->node == node &&
			    !strcmp(e->s, name))
				return 0;
		}
	if (s->n_str >= kgenome_diag_name_limit(s)) {
		s->n_str_refused++;
		kgenome_diag_note(s, KGENOME_TRUNCATED);
		return 0;
	}
	if (s->n_str == s->cap_str) {
		uint32_t nc = s->cap_str ? s->cap_str * 2u : 16u;
		struct kgenome_diag_str *nv;
		uint32_t old = s->cap_str;
		uint64_t grow = (uint64_t)(nc - old) * sizeof *nv;

		if (!kgenome_ledger_charge(&s->led, grow)) {
			s->n_str_refused++;
			return 0;
		}
		nv = realloc(s->str, nc * sizeof *nv);
		if (!nv) {
			kgenome_ledger_release(&s->led, grow);
			kgenome_diag_note(s, KGENOME_NOMEM);
			s->n_str_refused++;
			return 0;
		}
		s->str = nv;
		s->cap_str = nc;
		if (!str_table_build(s)) {
			/* The entries are fine; the new slots are not offered, and
			 * the array goes back to what the ledger still charges. */
			s->cap_str = old;
			if (old) {
				void *back = realloc(s->str, old * sizeof *nv);

				if (back)
					s->str = back;
			} else {
				free(s->str);
				s->str = NULL;
			}
			kgenome_ledger_release(&s->led, grow);
			s->n_str_refused++;
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
int kgenome_diag_str_at_node(const struct kgenome_diag_scan *s, uint16_t cap,
		       uint16_t node, const char *name)
{
	uint32_t h, p;

	if (!s->str_tab)
		return 0;
	h = str_hash(cap, node, name);
	for (p = h & s->str_tmask; s->str_tab[p]; p = (p + 1u) & s->str_tmask) {
		const struct kgenome_diag_str *e = &s->str[s->str_tab[p] - 1u];

		if (e->hash == h && e->cap == cap && e->node == node &&
		    !strcmp(e->s, name))
			return 1;
	}
	return 0;
}

const char *kgenome_diag_str_at(const struct kgenome_diag_scan *s, uint16_t cap,
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

uint32_t kgenome_diag_str_count(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t k, n = 0;

	if (!s)
		return 0;
	for (k = 0; k < s->n_str; k++)
		if (s->str[k].cap == cap)
			n++;
	return n;
}

void kgenome_diag_scan_free(struct kgenome_diag_scan *s)
{
	if (!s)
		return;
	free(s->str_tab);
	free(s->str);
	free(s->adj_head);
	free(s->adj_edge);
	free(s->wrap);
	/* The walk may outlive this scan (it is the object's): let go of the ledger
	 * it was charging before the ledger is gone. */
	kgenome_diag_walk_bind(s->walk, NULL);
	kgenome_apihash_free(s->own_apihash);
	kgenome_pe_imptab_free(&s->own_imports);
	kgenome_elf_reloc_table_free(&s->own_relocs);
	kgenome_funcs_free(&s->own_funcs);
	kgenome_diag_walk_free(s->own_walk);
	kgenome_elf_reloc_table_free(&s->data_relocs);
	free(s->hit);
	free(s);
}

