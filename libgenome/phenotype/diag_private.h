/*
 * diag_private.h - what one analysis routine needs from the scan it is filling.
 *
 * NOT PART OF THE SURFACE. kofdiag.h is what a caller reads; this is what the
 * routines behind it share, and it exists because they are in separate files
 * ON PURPOSE - see KOF_DIAG_RUN_* for why each one has to be switchable off
 * on its own. A routine that cannot be compiled apart from the others cannot
 * be disabled apart from them either.
 *
 * The scan is opaque to callers (diag_scan.h) and open to the routines and the
 * matcher (diag_scan_state.h, public); this header is what the routines share
 * beyond that.
 */
#ifndef KGENOME_DIAG_PRIVATE_H
#define KGENOME_DIAG_PRIVATE_H

#include <stdint.h>

#include "diag_scan_state.h"

/* The limits in force: the scan's budget, and the floors where it was never filled
 * - a scan built by hand (a test) has a zeroed budget, and zero means "the
 * default", as everywhere in kgenome_budget. */
static inline uint32_t kgenome_diag_node_limit(const struct kgenome_diag_scan *s)
{
	return s->bud.max_nodes ? s->bud.max_nodes : KGENOME_NODES_MIN;
}
static inline uint32_t kgenome_diag_name_limit(const struct kgenome_diag_scan *s)
{
	return s->bud.max_names ? s->bud.max_names : KGENOME_NAMES_MIN;
}

/* Keep a name for `cap`. Returns 1 when it was new. A name refused - too long,
 * the store at its limit, the ledger or memory out - is COUNTED and sets the
 * scan's status, never silently - see kgenome_diag_scan_status. */
int kgenome_diag_str_add(struct kgenome_diag_scan *s, uint16_t cap, uint16_t node,
		     const char *name);

/*
 * Add a node, or NULL when the scan is full. `at` is an offset into the
 * object, because that is what every other accessor in the engine takes.
 */
struct kgenome_diag_hit *kgenome_diag_hit_add(struct kgenome_diag_scan *s, uint64_t at,
				      uint16_t cap, uint16_t flags);

/* A node already in the scan, to add to. NULL for an index it does not
 * hold. The public reader hands back a const pointer, which is right for a
 * caller and wrong for the routine still filling it in. */
struct kgenome_diag_hit *kgenome_diag_hit_of(struct kgenome_diag_scan *s, uint32_t i);

/* Record that one of `h`'s inputs came from node `from`, in `role`. A link
 * already recorded is not recorded twice - a loop that arrives at the same
 * call again has not found a second link. A node holds four; the module ABI's
 * graph block record has room for two (KOF_GR_IN_FIT), and the block builder
 * (kof_diag_graph_build) says so on the scan when a node has more. A fifth
 * DISTINCT link sets the scan's status to KGENOME_TRUNCATED, which is why the
 * scan is an argument. */
/* The second node a socket call makes when its type says SOCK_NONBLOCK: a
 * non-blocking mark on descriptor `open_idx`, at the same instruction. */
void kgenome_diag_hit_nonblock(struct kgenome_diag_scan *s, uint64_t at, uint16_t open_idx);
void kgenome_diag_note_in(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
		      uint16_t from, uint8_t role, uint8_t kind);

/*
 * ---- THE ORIGIN MAP, WHICH EVERY STATIC ROUTINE NEEDS --------------------
 *
 * Which earlier node, if any, a register is carrying the value of. It is the
 * whole of the static link model, and it is here rather than in one routine
 * because the second routine - imported calls instead of syscalls - needs
 * exactly the same answer about exactly the same registers. Two copies would
 * be two things to keep right against one corpus.
 */
#define KGENOME_DIAG_ORG_NONE  0xffffu
#define KGENOME_DIAG_ORG_STACK 0xfffeu
#define KGENOME_DIAG_ORG_STK   32u

struct kgenome_diag_org {
	uint16_t node;          /* index, KGENOME_DIAG_ORG_NONE, or KGENOME_DIAG_ORG_STACK */
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

struct kgenome_diag_orgs {
	struct kgenome_diag_org reg[16];
	/*
	 * THE PUSHED VALUES' ORIGINS, as a ring of the newest KGENOME_DIAG_ORG_STK pushes: slot i of the
	 * stack is stk[i % KGENOME_DIAG_ORG_STK]. A pop takes the TOP, so what a deep stack loses is
	 * the oldest slots, the ones that are popped last - the table used to drop the NEWEST pushes
	 * once it was full, which are the ones popped first. Slots below `n_lost` have been
	 * overwritten; popping one answers "no origin", and overwriting a slot that held one sets
	 * `stk_cut` for the caller to report.
	 */
	uint16_t   stk[KGENOME_DIAG_ORG_STK];
	uint32_t   n_stk, n_lost;
	uint8_t    stk_cut;
	uint64_t   carry_to;
	uint8_t    carry_armed, carry_live, ax_stale;
	/*
	 * WHICH REGISTER IS THE STACK POINTER, when it is not x86's, or 0.
	 *
	 * Zero means "the default", KGENOME_CELL_REG_SP, so a walk that was only ever
	 * zero-initialised by an x86 routine keeps meaning what it meant. Register
	 * 4 is rsp on x86 and r4 - an ordinary callee-saved register - on ARM:
	 * reading it as the stack made every `mov r0, r4` a stack address, and
	 * the descriptors those calls take came back linked to the stack.
	 */
	uint8_t    sp;
};

void     kgenome_diag_org_clear(struct kgenome_diag_orgs *w, uint8_t r);
uint16_t kgenome_diag_org_of(const struct kgenome_diag_orgs *w, uint8_t r);
void     kgenome_diag_org_set(struct kgenome_diag_orgs *w, uint8_t r, uint16_t node);
/* The register holds the address of a named symbol - see struct kgenome_diag_org. */
void     kgenome_diag_org_set_sym(struct kgenome_diag_orgs *w, uint8_t r, uint32_t symoff,
			      int32_t symadd);
uint32_t kgenome_diag_org_sym(const struct kgenome_diag_orgs *w, uint8_t r, int32_t *add);
void     kgenome_diag_org_step(struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in);

/*
 * Which input of a call each argument is - ONE statement of it, in kofdiag.c,
 * because the question is the same whichever routine is asking. The roles of
 * one capability are distinct, and tests/lib/genome/diag_roles.c fails the build
 * if they stop being: kgenome_diag_note_in's refusal of a repeated (parent, role)
 * is only correct while they are.
 */
uint8_t kgenome_diag_role_of_arg(uint16_t cap, unsigned i);
extern const uint8_t kgenome_diag_sysv_arg[6];

/* The routines. One per KOF_DIAG_RUN_* bit, each in its own file. */
void kgenome_diag_run_syscall(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size);
void kgenome_diag_run_symbol(struct kgenome_diag_scan *s,
			 const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size);
/* The object's relocation table of one kind (KOF_ELF_RELOC_*): for CODE the
 * borrowed one, else built on first use; DATA is built on first use. */
const struct kgenome_func_set *kgenome_diag_funcs(struct kgenome_diag_scan *s,
					  const struct kgenome_obj *obj);
const struct kgenome_elf_relocs *kgenome_diag_relocs(struct kgenome_diag_scan *s,
					     const struct kgenome_obj *obj,
					     unsigned kind);

/*
 * THE CALL SITES OF A RELOCATABLE OBJECT, derived ONCE per scan from its CODE
 * relocations (kgenome_elf_relcalls) and read by every route that wants them: the
 * symbol route (a node per call of a named capability) and the emulate route's gap
 * walk (what to step over). `at` is a file offset (kgenome_elf_reloc_call_at),
 * `target` non-zero for a call into code this object defines, `cap` the
 * capability the callee's NAME stands for (KGENOME_NUCLEO_NONE for an internal
 * call or an unknown name) and `name` its id (kgenome_nucleo_name_id) when `cap`
 * is known. NULL with *n = 0 when there are none or memory was refused (noted on
 * the scan, which is also halted). Owned by the scan.
 */
struct kgenome_diag_rcall {
	uint64_t at, target;
	uint16_t cap;
	uint16_t name;
};
const struct kgenome_diag_rcall *kgenome_diag_relcalls(struct kgenome_diag_scan *s,
						   const struct kgenome_obj *obj,
						   uint32_t *n);

/* The symbol route's PE half: calls through the import address table. */
/* Syscall wrappers of a static libc: nodes at their callers, linked - see
 * diag_wrapper_walk.c. */
int kgenome_diag_kernel_entry(const struct kgenome_obj *obj, unsigned op,
			  int vec80, const uint8_t *p);
int kgenome_diag_walk_ensure(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, int want_trace);
struct kgenome_diag_walk *kgenome_diag_scan_walk(struct kgenome_diag_scan *s);
/* A scan takes the walk (its ledger is charged for the trace), or lets go of it
 * (NULL) - see diag_wrapper_walk.c. */
void kgenome_diag_walk_bind(struct kgenome_diag_walk *wk, struct kgenome_ledger *lg);
const uint64_t *kgenome_diag_walk_entries(const struct kgenome_diag_walk *wk, uint32_t *n);
void kgenome_diag_wrap_settle(struct kgenome_diag_scan *s);   /* the socketcall site list: once each, plus a sorted copy */
void kgenome_diag_run_wrappers(struct kgenome_diag_scan *s, const struct kgenome_obj *obj,
			   const uint8_t *base, uint64_t size);
void kgenome_diag_run_apihash(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size);
const struct kgenome_pe_imptab *kgenome_diag_imports(struct kgenome_diag_scan *s,
					     const struct kgenome_obj *obj);
void kgenome_diag_run_pe_symbol(struct kgenome_diag_scan *s,
			    const struct kgenome_obj *obj,
			    const uint8_t *base, uint64_t size);
void kgenome_diag_run_emulate(struct kgenome_diag_scan *s,
			  const struct kgenome_obj *obj,
			  const uint8_t *base, uint64_t size);

/*
 * HOW MANY NODES ONE OBJECT MAY HOLD - kgenome_budget.max_nodes, and not a
 * constant: max(4096, code_bytes / 8), at most 65534 (the 16-bit node index; see
 * KGENOME_MAX_INDEX).
 *
 * THE FIXED 4096 WAS A BOUND ON EVIDENCE. A measured case: the nodes of a stager
 * that come after the 4096th are dropped, so the diagnose is not matched on a big
 * binary that carries one. It is now scaled with the input - the bound rule 4
 * allows - and what remains is a bound on cost: reaching it stops the walk, keeps
 * every node found and sets KGENOME_TRUNCATED (KGENOME_OVER_BUDGET when the
 * ledger refused the memory), so a caller asking "is this capability absent" gets
 * "cannot say" rather than "no". Measured: the largest object in the sample set
 * produced 701 nodes, of which 447 were indirect calls that resolve to nothing;
 * a real shellcode region produces seven.
 */

/*
 * THE ONE ITERATION over an object's code extents, ELF segments and PE sections
 * alike (see diag_code.c): the count of candidates and the Nth one's bytes, 0
 * for a candidate that is not code. Every walk that goes over the code of an
 * object goes through these.
 */
uint32_t kgenome_diag_extent_count(const struct kgenome_obj *obj);
uint64_t kgenome_diag_extent(const struct kgenome_obj *obj, uint32_t i, uint64_t size,
			 uint64_t *at);

#endif /* KGENOME_DIAG_PRIVATE_H */
