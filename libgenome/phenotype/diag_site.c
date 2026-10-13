/*
 * diag_site.c - one syscall site: the node it makes, the fixed-width (ARM) ports, and the x86 reading.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

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
 * `ar`/`n_ar` are the argument registers in order, `have` the mask of the
 * arguments that were read, `ret_reg` the register the result comes back in,
 * `nonblock` whether the socket was made non-blocking and `carry` whether this
 * architecture can leave a zero for the next call to use (x86-64 only - see
 * walk.carry_to).
 */
struct node_site {
	uint64_t at;
	uint16_t cap;
	uint8_t fl;
	const char *nm;
	const uint8_t *ar;
	int n_ar;
	unsigned have;
	uint8_t ret_reg;
	int nonblock, carry;
};

static void note_node(struct kgenome_diag_scan *s, struct kgenome_diag_orgs *w,
		      const struct node_site *x)
{
	const uint64_t at = x->at;
	const uint16_t cap = x->cap;
	const char *nm = x->nm;
	const uint8_t *ar = x->ar;
	const int n_ar = x->n_ar, nonblock = x->nonblock, carry = x->carry;
	const unsigned have = x->have;
	const uint8_t ret_reg = x->ret_reg;
	struct kgenome_diag_hit *h;

	h = kgenome_diag_hit_add(s, at, cap, x->fl);
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
	if (kgenome_nucleo_hands_on(cap, nm)) {
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
		    kgenome_diag_org_of(w, ar[0]) == KGENOME_DIAG_ORG_STACK)
			h->bits |= KGENOME_DIAG_H_REGION_STACK;
		kgenome_diag_org_clear(w, ret_reg);
	}

	/* Arm the carry for the next conditional branch - see walk.carry_to. */
	if (carry && nm && kgenome_nucleo_sys_zero_on_success(nm))
		h->bits |= KGENOME_DIAG_H_ZERO_OK;
}

#define ARM_OABI_BASE 0x900000u

static void at_syscall_fixed(struct kgenome_diag_scan *s, struct kgenome_cell_cur *k,
			     struct kgenome_diag_orgs *w, const struct kgenome_obj *obj,
			     const struct kgenome_cell_insn *in)
{
	const struct kgenome_nucleo_abi *fx = kgenome_nucleo_abi_of(obj->arch == KGENOME_ARCH_ARM
					       ? KGENOME_NUCLEO_A_ARM32
					       : KGENOME_NUCLEO_A_ARM64);
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
	cap = kgenome_nucleo_cap_of_syscall_abi(fx, (uint32_t)nr, arg, &fl);
	nm = kgenome_nucleo_sys_name_abi(fx, (uint32_t)nr);
	if (cap == KGENOME_NUCLEO_NONE)
		return;
	{
		const struct node_site x = { in->at, cap, fl, nm, ar, n_ar, have, fx->ret,
					     (have & 2u) && (arg[1] & 0x800u) /* SOCK_NONBLOCK */, 0 };

		note_node(s, w, &x);
	}
}

void kgenome_diag_at_syscall(struct kgenome_diag_scan *s, struct kgenome_cell_cur *k,
		       struct kgenome_diag_orgs *w, const struct kgenome_obj *obj,
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

	if (kgenome_diag_fixed_arch(obj)) {
		at_syscall_fixed(s, k, w, obj, in);
		return;
	}
	bits = obj->arch == KGENOME_ARCH_X86_64 ? 64 : 32;
	n_ar = kgenome_diag_arg_regs(obj, &ar);

	/*
	 * THE SYSCALL VOCABULARY IS LINUX'S, SO IT IS ONLY ASKED ABOUT LINUX.
	 *
	 * A `syscall` instruction in a PE carries a WINDOWS service number,
	 * and the number spaces have nothing to do with each other.
	 * kgenome_nucleo_cap_of_syscall only knows the Linux table, so handing it a
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
		s->n_unread++;          /* a candidate wrapper - see diag_wrapper.c */
	cap = kgenome_nucleo_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
	nm  = kgenome_nucleo_sys_name((unsigned)bits, (uint32_t)nr);
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
	{
		const struct node_site x = { at, cap, fl, nm, ar, n_ar, have, KGENOME_CELL_REG_AX,
					     kgenome_nucleo_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have),
					     bits == 64 };

		note_node(s, w, &x);
	}
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
