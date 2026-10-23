/*
 * diag_hit.c - the hits of a scan: adding one, the roles of a call's arguments, and what is noted on a hit.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

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
 * Taken from nucleo's kgenome_nucleo_abi rather than written again here - a second copy
 * of "rdi, rsi, rdx, r10, r8, r9" is a second thing to get wrong when a
 * port is added, and the sweep that had its own copy is the reason this
 * rule exists.
 */
int kgenome_diag_arg_regs(const struct kgenome_obj *obj, const uint8_t **out)
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
 * The invariant is checked rather than hoped for: see tests/lib/genome/diag_roles.c,
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
	/* A script's decode and eval: the first argument is the value they act on - see KGENOME_DIAG_ROLE_VALUE. */
	case KGENOME_NUCLEO_DECODE:
	case KGENOME_NUCLEO_EVAL:
	case KGENOME_NUCLEO_CREATE:
		return i == 0u ? KGENOME_DIAG_ROLE_VALUE : KGENOME_DIAG_ROLE_NONE;
	/* A data-call's first argument is the CALLEE: what the call runs is chosen by it, which is a target and not a value it acts on.
	 * The same for what a data-load loads: the name is what decides. */
	case KGENOME_NUCLEO_DYNCALL:
	case KGENOME_NUCLEO_DYNLOAD:
		return i == 0u ? KGENOME_DIAG_ROLE_TARGET : KGENOME_DIAG_ROLE_NONE;
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
	kgenome_diag_note_in_how(s, h, from, role, kind, KGENOME_DIAG_LINK_PROVEN);
}

/*
 * A LINK THE RUN SAW ARRIVE. The run (the emulate route) and the code-only routes can find the same relation,
 * and kgenome_diag_note_in_how keeps the FIRST statement of it: a sweep that said MAY (two arms joined, or a
 * callee that was not read) would keep the run's proof out. A link the run demonstrated is PROVEN, and
 * replaces a MAY that is already there. Only the fold of two nodes at one site asks for it (merge_sites, where
 * the run's node meets the sweep's); a route recording its own links keeps the first statement, as the
 * script route's oracle (tests/lib/genome/diag_text_sum_gen.c) holds.
 */
int kgenome_diag_note_in_seen(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			      uint16_t from, uint8_t role, uint8_t kind)
{
	uint8_t i;

	if (h && from != KGENOME_DIAG_ORG_NONE)
		for (i = 0; i < h->n_in; i++)
			if (h->in[i].from == from && h->in[i].role == role && h->in[i].kind == kind) {
				h->in[i].how = KGENOME_DIAG_LINK_PROVEN;
				return 0;
			}
	return kgenome_diag_note_in_how(s, h, from, role, kind, KGENOME_DIAG_LINK_PROVEN);
}

int kgenome_diag_note_in_how(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			  uint16_t from, uint8_t role, uint8_t kind, uint8_t how)
{
	uint8_t i;

	if (!h || from == KGENOME_DIAG_ORG_NONE)
		return 0;
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
			return 0;
	/*
	 * FOUR INPUTS A NODE - a read has two that matter (the buffer and the
	 * descriptor) and nothing measured has needed more than three. A fifth
	 * DISTINCT link is not kept and is not silent: it sets KGENOME_TRUNCATED.
	 * The graph block the modules read (kofdiagtree.h) holds two links a record
	 * (KOF_GR_IN_FIT); kof_diag_graph_build writes the first two of a node's and
	 * notes the cut on the scan, so a node's third and fourth input are in this
	 * scan and not in the block - said, not dropped at the boundary.
	 * This test used to come first, so a repeat of a link was refused as
	 * "full" on a node that was; it now says "full" only for a real fifth.
	 */
	if (h->n_in >= 4u) {
		kgenome_diag_note(s, KGENOME_TRUNCATED);        /* the same for every link, as for the text route's */
		return 1;
	}
	h->in[h->n_in].from = from;
	h->in[h->n_in].role = role;
	h->in[h->n_in].how  = how;
	h->in[h->n_in].kind = kind;
	h->n_in++;
	return 0;
}
