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
#ifndef KGENOME_DIAG_INT_H
#define KGENOME_DIAG_INT_H

#include <stdint.h>

#include "lineages.h"
#include "../kgenome_budget.h"
#include <celllysis/celllysis.h>
#include <celllysis/cell.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>

struct kgenome_diag_scan {
	struct kgenome_diag_hit *hit;
	uint32_t             n_hit;
	uint32_t             cap_hit;
	/*
	 * SYSCALLS WHOSE ARGUMENT IS THE CALLER'S, found by the sweep and
	 * answered after it - see resolve_wrap. File offsets of the `int 0x80`.
	 */
	uint64_t            *wrap;
	uint32_t             n_wrap, cap_wrap;
	/* Syscall sites whose first argument was not a constant the sweep could
	 * read - the candidates for a wrapper. See kgenome_diag_run_wrappers. */
	uint32_t             n_unread;
	/*
	 * THE RELOCATIONS OF THIS OBJECT, one table for every route - see
	 * struct kgenome_elf_relocs. Borrowed when the caller built it for the object
	 * already (the scanner does, for its gate), built here on first use and
	 * owned otherwise.
	 */
	const struct kgenome_apihash    *apihash;           /* see kgenome_diag_apihash */
	struct kgenome_apihash          *own_apihash;
	int                          apihash_done;
	const struct kgenome_pe_imptab  *imports;           /* PE: see kgenome_diag_inputs */
	struct kgenome_pe_imptab         own_imports;       /* built here when not handed over */
	int                          imports_done;
	const struct kgenome_diag_seq   *seq;               /* see kgenome_diag_inputs */
	uint32_t                     n_seq;
	const struct kgenome_elf_relocs *relocs;            /* CODE relocations */
	struct kgenome_elf_relocs        own_relocs;
	struct kgenome_elf_relocs        data_relocs;       /* DATA: the image builder's alone */
	int                          data_ready;
	/*
	 * THE OBJECT'S FUNCTIONS, one set for every route - see kgenome_diag_funcs.
	 * Borrowed from the scanner's product when it passed one, built here on
	 * first use and owned otherwise, exactly as the relocations beside it.
	 */
	const struct kgenome_func_set   *funcs;
	struct kgenome_func_set          own_funcs;
	/* THE WALK, one per object - see struct kgenome_diag_walk. Borrowed from the
	 * scanner's latch when it passed one, owned here otherwise. */
	struct kgenome_diag_walk        *walk;
	struct kgenome_diag_walk        *own_walk;
	/*
	 * WHETHER THE ANSWER IS WHOLE - see kgenome_status.h. Every limit that fires
	 * in any routine of this scan notes a value here (kgenome_diag_note), and
	 * kgenome_diag_scan_status reads it together with the ledger's. It replaces
	 * `int full`, which was set in six places, read by tests alone and answered
	 * "something stopped" for a name that was too long and for a dead
	 * allocation alike.
	 */
	enum kgenome_status  status;
	/*
	 * THE WALK MUST STOP: the node store cannot take another node (its limit, the
	 * ledger, or memory). The only part of the old `full` the loops ever needed -
	 * they stop when no node can be added, and not for a name refused or a link
	 * dropped, which lose one item and not the rest. Always accompanied by a
	 * status.
	 */
	int                  halt;
	/*
	 * WHAT THIS SCAN MAY COST, and what it has charged: the caller's budget as
	 * given (every zero field filled with the default for this object - see
	 * kgenome_budget_default) and the ledger the products below are charged to
	 * (nodes, names, the name table, the graph, the wrapper list). Owned by the
	 * scan, not shared across threads.
	 */
	struct kgenome_budget bud;
	struct kgenome_ledger led;
	uint32_t             n_str_refused;     /* names refused: too long, or the store full */
	uint64_t             emu_charged;       /* guest pages charged for a live emulator */
	/* Which analysis routines actually ran - see KOF_DIAG_RUN_* and the
	 * scenario table. Asked for and not written counts as not run. */
	unsigned             ran;
	/*
	 * THE OBJECT THE SCAN WAS MADE FROM, so a matcher can read a name a
	 * node pointed at - see KGENOME_DIAG_H_SYMREF. Carried rather than
	 * copied: the bytes are the caller's and outlive the scan, which is
	 * the same contract every other offset in a hit is under.
	 */
	const uint8_t       *base;
	uint64_t             size;
	/*
	 * ---- THE LINKS AS A GRAPH, BUILT ONCE --------------------------
	 *
	 * The hits carry their edges as kgenome_diag_in[] - up to four parents
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
	/*
	 * ---- THE NAMES A CALL WAS GIVEN, KEPT IN THE ENGINE ------------
	 *
	 * COPIES, read out of the guest's memory, and tagged with the
	 * capability of the call that was handed them. A module asking what
	 * was declared to the kernel asks THIS and does not look in the object.
	 *
	 * IT WAS AN OFFSET INTO THE FILE BEFORE - a hit's attr, flagged
	 * ATTR_STR - and that is the one thing a name cannot be. A name an
	 * object builds at run time is decoded into a buffer that is not in
	 * the file at all; and a name sitting in the file may be encoded
	 * there and only meaningful after the code has run over it. Both are
	 * only ever right in the emulator's memory, so that is where they are
	 * read and a copy is what is kept.
	 *
	 * DEDUPLICATED per (capability, name): four calls handing the same
	 * resolver the same word are one statement.
	 */
	struct kgenome_diag_str *str;
	uint32_t             n_str, cap_str;
	/*
	 * AN OPEN-ADDRESSING TABLE OVER THE ENTRIES, of 1-based indices (zero is
	 * empty), twice the entry capacity and always a power of two. Kept for
	 * the two questions that are asked of the whole list - "is this name
	 * already here" on every insert, and "is this name here" from a verdict
	 * - which were a scan of every entry and are now one probe.
	 *
	 * AT THE SIZES A REAL MODULE REACHES (0 to ~25 names) IT IS NO FASTER:
	 * measured, a linear scan and the table are both ~20 ns there, and below
	 * about a dozen the scan wins. It earns its place at the BOUND - 1024
	 * names, which only a hostile object feeds the store - where the scan
	 * costs 470 to 890 ns a query and the table 27 to 29, and where the
	 * duplicate check on insert would otherwise make filling it quadratic.
	 * Entries stay in an array, in the order they were first seen, because a
	 * caller walking the list wants that order.
	 */
	uint16_t            *str_tab;
	uint32_t             str_tmask;
	uint32_t            *adj_head;  /* n_hit + 1 offsets, or NULL       */
	uint16_t            *adj_edge;  /* flattened successors             */
	int                  adj_built;
};

/*
 * A name longer than this is refused before it is stored, and the refusal is
 * COUNTED and sets KGENOME_TRUNCATED (kgenome_diag_scan_refused). 64 was the
 * first measurement (every module name seen was shorter) and a C++ mangled
 * symbol a diagnose might be asked about is well past it; 256 is the record's
 * size, not a judgement about what a symbol is. The entry holds the name inline,
 * so this is also what the table costs per entry, and the table is charged to
 * the ledger.
 */
#define KGENOME_DIAG_STR_MAX 256u

struct kgenome_diag_str {
	uint16_t cap;                   /* the call that was handed it      */
	/*
	 * THE NODE OF THAT CALL, which is what makes a name FOLLOW a diagnose.
	 *
	 * A name used to be tagged with the capability alone, and a diagnose's
	 * names were "the ones handed to calls of the capabilities my nodes
	 * name". Two diagnoses with a node of the same capability then shared
	 * every name, including those from calls the other had never matched -
	 * a verdict asking what ONE of them carried was answered from both.
	 *
	 * With the node, a diagnose owns the names read at the call sites its
	 * tree actually BOUND, and nothing else. 0xffff means the call has no
	 * node, which is kept so the list stays whole and is owned by no one.
	 */
	uint16_t node;
	uint32_t hash;                  /* of (cap, node, name) - see str_hash */
	char     s[KGENOME_DIAG_STR_MAX + 1u];
};

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
 * call again has not found a second link. A node holds four (the module ABI's
 * graph block has four slots, KOF_GR_IN_MAX, so a fifth kept here would be cut
 * silently at the next boundary); a fifth DISTINCT link sets the scan's status
 * to KGENOME_TRUNCATED, which is why the scan is an argument. */
/* The second node a socket call makes when its type says SOCK_NONBLOCK: a
 * non-blocking mark on descriptor `open_idx`, at the same instruction. */
void kgenome_diag_hit_nonblock(struct kgenome_diag_scan *s, uint64_t at, uint16_t open_idx);
void kgenome_diag_note_in(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
		      uint16_t from, uint8_t role, uint8_t kind);

/* A limit fired: say so on the scan. The one way a routine reports that its
 * answer is partial - see kgenome_status.h. */
void kgenome_diag_note(struct kgenome_diag_scan *s, enum kgenome_status st);

/*
 * ---- THE ORIGIN MAP, WHICH EVERY STATIC ROUTINE NEEDS --------------------
 *
 * Which earlier node, if any, a register is carrying the value of. It is the
 * whole of the static link model, and it is here rather than in one routine
 * because the second routine - imported calls instead of syscalls - needs
 * exactly the same answer about exactly the same registers. Two copies would
 * be two things to keep right against one corpus.
 */
#define KGENOME_ORG_NONE  0xffffu
#define KGENOME_ORG_STACK 0xfffeu
#define KGENOME_ORG_STK   32u

struct kgenome_org {
	uint16_t node;          /* index, KGENOME_ORG_NONE, or KGENOME_ORG_STACK */
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

struct kgenome_walk {
	struct kgenome_org reg[16];
	struct kgenome_org stk[KGENOME_ORG_STK];
	uint32_t   n_stk;
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

void     kgenome_diag_org_clear(struct kgenome_walk *w, uint8_t r);
uint16_t kgenome_diag_org_of(const struct kgenome_walk *w, uint8_t r);
void     kgenome_diag_org_set(struct kgenome_walk *w, uint8_t r, uint16_t node);
/* The register holds the address of a named symbol - see struct kgenome_org. */
void     kgenome_diag_org_set_sym(struct kgenome_walk *w, uint8_t r, uint32_t symoff,
			      int32_t symadd);
uint32_t kgenome_diag_org_sym(const struct kgenome_walk *w, uint8_t r, int32_t *add);
void     kgenome_diag_org_step(struct kgenome_walk *w, const struct kgenome_cell_insn *in);

/*
 * Which input of a call each argument is - ONE statement of it, in kofdiag.c,
 * because the question is the same whichever routine is asking. The roles of
 * one capability are distinct, and tests/unit/diag_roles.c fails the build
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

/* The symbol route's PE half: calls through the import address table. */
/* Syscall wrappers of a static libc: nodes at their callers, linked - see
 * diag_wrap.c. */
int kgenome_diag_kernel_entry(const struct kgenome_obj *obj, unsigned op,
			  int vec80, const uint8_t *p);
int kgenome_diag_walk_ensure(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size, int want_trace);
struct kgenome_diag_walk *kgenome_diag_scan_walk(struct kgenome_diag_scan *s);
/* A scan takes the walk (its ledger is charged for the trace), or lets go of it
 * (NULL) - see diag_wrap.c. */
void kgenome_diag_walk_bind(struct kgenome_diag_walk *wk, struct kgenome_ledger *lg);
/*
 * THE INSTRUCTIONS OF ONE RUN OF AN OBJECT'S CODE, handed to an observer: the
 * file bytes [off, off + n), read as a linear sweep that starts at `off` and
 * decodes each instruction as if it ran at `va` + (its offset - off), on a
 * window that ends with the run. `wk` is the object's walk and may be NULL; when
 * it holds a live trace for these bytes the instructions the trace holds are
 * served from it, every other position is decoded - the answer is the same
 * either way (see "THE INSTRUCTIONS OF ONE RUN" in diag_wrap.c). `st` may be
 * NULL; it counts where the instructions came from.
 */
struct kgenome_code_run_stats {
	uint64_t from_trace, decoded, skipped;
};
void kgenome_diag_code_run(struct kgenome_diag_walk *wk, const struct kgenome_obj *obj,
		       const uint8_t *base, uint64_t size, uint64_t off,
		       uint64_t n, uint64_t va, kgenome_cell_insn_fn fn, void *user,
		       struct kgenome_code_run_stats *st);
const uint64_t *kgenome_diag_walk_entries(const struct kgenome_diag_walk *wk, uint32_t *n);
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

/* Does the node `b` of capability `cap` carry the name `name`: a place that name
 * was seen. The matcher asks it; the scan owns the table it reads. */
int kgenome_diag_str_at_node(const struct kgenome_diag_scan *s, uint16_t cap, uint16_t node,
			 const char *name);

struct kgenome_elf_info;
/*
 * THE CODE RANGES OF AN ELF - see the two definitions in nodes.c.
 *
 *   kgenome_diag_code_range  the executable segment's bytes past the headers: the
 *                        one definition of where code can be. The xref sweep
 *                        reads it as it is.
 *   kgenome_diag_walk_range  the same with the start moved to where the object says
 *                        instructions begin (its first executable section, else
 *                        its entry point), for the walks that decode every byte:
 *                        pass_a, pass_b and the syscall sweep.
 *
 * Each returns the length, 0 for a segment that is not code, and writes the
 * offset to `*at`.
 */
uint64_t kgenome_diag_code_range(const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at);
uint64_t kgenome_diag_walk_range(const struct kgenome_obj *obj,
			     const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at);

#endif /* KGENOME_DIAG_INT_H */
