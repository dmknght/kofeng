/*
 * diag_int.h - what one analysis routine needs from the scan it is filling.
 *
 * NOT PART OF THE SURFACE. kofdiag.h is what a caller reads; this is what the
 * routines behind it share, and it exists because they are in separate files
 * ON PURPOSE - see KOF_DIAG_RUN_* for why each one has to be switchable off
 * on its own. A routine that cannot be compiled apart from the others cannot
 * be disabled apart from them either.
 *
 * The scan is opaque to callers and open to the routines; that is the whole
 * division this header draws.
 */
#ifndef KOFENG_DIAG_INT_H
#define KOFENG_DIAG_INT_H

#include <stdint.h>

#include "kofdiag.h"
#include "../../analyzers/parsers/binaries/disasm/kdis.h"
#include "../../kofcore/kofmod/kdis.h"

struct kof_diag_scan {
	struct kof_diag_hit *hit;
	uint32_t             n_hit;
	uint32_t             cap_hit;
	int                  full;      /* the bound was reached */
	/* Which analysis routines actually ran - see KOF_DIAG_RUN_* and the
	 * scenario table. Asked for and not written counts as not run. */
	unsigned             ran;
	/*
	 * THE OBJECT THE SCAN WAS MADE FROM, so a matcher can read a name a
	 * node pointed at - see KOF_DIAG_H_SYMREF. Carried rather than
	 * copied: the bytes are the caller's and outlive the scan, which is
	 * the same contract every other offset in a hit is under.
	 */
	const uint8_t       *base;
	uint64_t             size;
	/*
	 * ---- THE LINKS AS A GRAPH, BUILT ONCE --------------------------
	 *
	 * The hits carry their edges as kof_diag_in[] - up to four parents
	 * each, with a role. That is enough to ask "where did THIS node come
	 * from", but a join asks the other question, "does this node's value
	 * REACH that one", and answering it by rescanning every hit per step
	 * is quadratic. So the value-flow edges are turned once into a
	 * forward adjacency (CSR: head[node] .. head[node+1] index into
	 * edge[]) and every reachability query is then one O(V+E) walk.
	 *
	 * DIRECTED BY VALUE, not by the in[] relation - see diag_flow_build
	 * for why a BUFFER edge runs the opposite way from an FD edge. Built
	 * lazily because only a scan a verdict joins on ever needs it.
	 */
	uint32_t            *adj_head;  /* n_hit + 1 offsets, or NULL       */
	uint16_t            *adj_edge;  /* flattened successors             */
	int                  adj_built;
};

/*
 * Add a node, or NULL when the scan is full. `at` is an offset into the
 * object, because that is what every other accessor in the engine takes.
 */
struct kof_diag_hit *kof_diag_hit_add(struct kof_diag_scan *s, uint64_t at,
				      uint16_t cap, uint16_t flags);

/* A node already in the scan, to add to. NULL for an index it does not
 * hold. The public reader hands back a const pointer, which is right for a
 * caller and wrong for the routine still filling it in. */
struct kof_diag_hit *kof_diag_hit_of(struct kof_diag_scan *s, uint32_t i);

/* Record that one of `h`'s inputs came from node `from`, in `role`. A link
 * already recorded is not recorded twice - a loop that arrives at the same
 * call again has not found a second link. */
void kof_diag_note_in(struct kof_diag_hit *h, uint16_t from, uint8_t role,
		      uint8_t kind);

/*
 * ---- THE ORIGIN MAP, WHICH EVERY STATIC ROUTINE NEEDS --------------------
 *
 * Which earlier node, if any, a register is carrying the value of. It is the
 * whole of the static link model, and it is here rather than in one routine
 * because the second routine - imported calls instead of syscalls - needs
 * exactly the same answer about exactly the same registers. Two copies would
 * be two things to keep right against one corpus.
 */
#define ORG_NONE  0xffffu
#define ORG_STACK 0xfffeu
#define ORG_STK   32u

struct org {
	uint16_t node;          /* index, ORG_NONE, or ORG_STACK */
	/*
	 * ---- OR THE REGISTER NAMES A SYMBOL ----------------------------
	 *
	 * A THIRD KIND OF PROVENANCE, beside "a node made this" and "this
	 * came off the stack": the value is the address of a symbol the
	 * relocation table named, at `symadd` bytes into it.
	 *
	 * IT IS THE ONLY WAY TO READ A RELOCATABLE OBJECT'S OPERANDS. A .ko
	 * is unlinked, so `mov rdi, &__this_module->list` assembles as
	 * `48 c7 c7 00 00 00 00` - the operand is a HOLE, and the symbol and
	 * the offset live in the relocation beside it. Without this the walk
	 * sees a register loaded with zero.
	 *
	 * `symoff` is the file offset of the symbol's NAME, zero for none -
	 * the same carrier a string capture uses, and for the same reason:
	 * the bytes are already in the buffer.
	 */
	uint32_t symoff;
	int32_t  symadd;
};

struct walk {
	struct org reg[16];
	struct org stk[ORG_STK];
	uint32_t   n_stk;
	uint64_t   carry_to;
	uint8_t    carry_armed, carry_live, ax_stale;
};

void     kof_diag_org_clear(struct walk *w, uint8_t r);
uint16_t kof_diag_org_of(const struct walk *w, uint8_t r);
void     kof_diag_org_set(struct walk *w, uint8_t r, uint16_t node);
/* The register holds the address of a named symbol - see struct org. */
void     kof_diag_org_set_sym(struct walk *w, uint8_t r, uint32_t symoff,
			      int32_t symadd);
uint32_t kof_diag_org_sym(const struct walk *w, uint8_t r, int32_t *add);
void     kof_diag_org_step(struct walk *w, const struct kdis_insn *in);

/*
 * Which input of a call each argument is - ONE statement of it, in kofdiag.c,
 * because the question is the same whichever routine is asking. The roles of
 * one capability are distinct, and tests/unit/diag_roles.c fails the build
 * if they stop being: kof_diag_note_in's refusal of a repeated (parent, role)
 * is only correct while they are.
 */
uint8_t kof_diag_role_of_arg(uint16_t cap, unsigned i);
extern const uint8_t kof_diag_sysv_arg[6];

/* The routines. One per KOF_DIAG_RUN_* bit, each in its own file. */
void kof_diag_run_syscall(struct kof_diag_scan *s,
			  const struct kof_obj_ctx *ctx,
			  const uint8_t *base, uint64_t size);
void kof_diag_run_symbol(struct kof_diag_scan *s,
			 const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size);
void kof_diag_run_emulate(struct kof_diag_scan *s,
			  const struct kof_obj_ctx *ctx,
			  const uint8_t *base, uint64_t size);

#endif /* KOFENG_DIAG_INT_H */
