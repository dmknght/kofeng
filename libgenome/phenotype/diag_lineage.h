/*
 * diag_lineage.h - the lineage stages of the diagnose scan: what object a program is, and which of
 * the algorithms that link its nodes pay for that kind of object.
 *
 * THE CLASS of an object is a handful of facts the engine already holds in the parse - the format, how it
 * is linked, whether it kept a name table for its code, the width - folded once into flags
 * (kgenome_diag_class_of). THE PLAN is the table that says, per class, which stages run
 * (kgenome_diag_lineage_plan): data, one row per kind of object, each with the measurement that put the
 * stage there or took it away. The scan reads the plan; nothing in the engine chooses an algorithm by an
 * `if` on the format.
 *
 * WHICH STAGES RUN ON WHICH CODE is not decided by the class. The class says what is possible at all (the plan); inside it the
 * stages are a CHAIN over each function: FLOW runs first, everywhere, and every input it cannot account for is an
 * obligation with a reason (below). A row of the table in diag_lineage_chain.c says which reason a stage discharges
 * and on which blocks (by what the block holds: a cell beyond the frame, a call to a function of the object, a
 * node, a block no walk reached - predicates read off the decode that is made once); the function is solved again with the
 * stages whose rows its obligations match, and not otherwise. What nothing discharges is reported, not guessed.
 *
 * WHAT THE STAGES ARE, in the order they were built, and what each adds to the one before:
 *
 *   FLOW  the substrate: the registers and the stack slots of ONE function, followed over its control
 *         flow with the paths joined (the linear walk of the syscall-wrapper analysis follows address
 *         order and takes no branch). A link is MUST when every path to the argument yields one producer,
 *         MAY when several do.
 *   LOCS  stage 1: the places beyond the frame - a global at a fixed address, a field of an object a
 *         node produced - are kept by the same walk, so a descriptor stored in a struct and read back is
 *         followed.
 *   SUMM  stage 2: what a call to a function of the object means, computed callee first: the value it
 *         returns, and which of its parameters reach which node. A producer in one function reaches a node
 *         in another. Most of what it finds is MAY (several callers, several producers).
 *   SEED  stage 3: code no walk from a function's entry reaches (what an indirect jump leaves behind, a
 *         function the partition cut in two) is walked as an entry of its own. What it finds passes through
 *         an entry nothing proved, and is MAY.
 *
 * (The nodes of a linked ELF are not a stage: they are the symbol route's, diag_elfimp.c.)
 */
#ifndef KGENOME_DIAG_LINEAGE_H
#define KGENOME_DIAG_LINEAGE_H

#include <stdint.h>
#include <genotype/image/obj.h>

/* ---- the class of an object ---- */
#define KGENOME_CLASS_ELF      (1u << 0)
#define KGENOME_CLASS_PE       (1u << 1)
#define KGENOME_CLASS_REL      (1u << 2)   /* a relocatable ELF (a kernel module): its calls are relocations */
#define KGENOME_CLASS_DYNAMIC  (1u << 3)   /* an ELF with a PT_INTERP: it imports its libc */
#define KGENOME_CLASS_SYMBOLS  (1u << 4)   /* an ELF with a .symtab; a PE with a debug directory */
#define KGENOME_CLASS_WIDE     (1u << 5)   /* 64-bit */
#define KGENOME_CLASS_X86      (1u << 6)   /* x86 or x86-64: the arch the stages read */
#define KGENOME_CLASS_MANAGED  (1u << 7)   /* a PE whose code is managed (.NET): no native code to follow */
#define KGENOME_CLASS_NOSECT   (1u << 8)   /* an ELF with no section header table (packed, hand-made): its code is found by its segments */

unsigned kgenome_diag_class_of(const struct kgenome_obj *obj);

/* ---- the stages ---- */
#define KGENOME_LINEAGE_S_FLOW 1u
#define KGENOME_LINEAGE_S_LOCS 2u
#define KGENOME_LINEAGE_S_SUMM 4u
#define KGENOME_LINEAGE_S_SEED 8u
#define KGENOME_LINEAGE_S_ALL  (KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | \
				KGENOME_LINEAGE_S_SUMM | KGENOME_LINEAGE_S_SEED)
/* Not a stage: run every stage the plan names on every function and block (the reference the selection is measured
 * and tested against - the links must be the same, only the cost differs). */
#define KGENOME_LINEAGE_S_EAGER 16u
/* Not in S_ALL and in no class's plan: read, after all, a function that was left unread (nothing in it or below it is useful) when
 * a caller's result from it reaches a consumer. Measured to add 0 to 8 links per 100-file cell and, in the static ELF with symbols, to
 * cost half again as many instructions (diag_class.c): off wherever the class table is. */
#define KGENOME_LINEAGE_S_DEMAND 32u

/* Which stages MAY run for a class: zero when none does. The coarse filter: what runs on a function and on a block
 * is chosen from what the code of that function says (diag_lineage_chain.c). */
unsigned kgenome_diag_lineage_plan(unsigned cls);

/*
 * ---- THE OBLIGATIONS ----
 *
 * An INPUT of a consumer node (an argument a role names) the stages could not account for is an OBLIGATION, and the
 * reason it is unknown is a bit of `why`. The stages are a chain: each hands the obligations it could not discharge to
 * the next whose predicate they match (LOCS takes W_MEM, SUMM takes W_CALL, SEED the producers in unreached code);
 * what is left at the end is the UNRESOLVED SET, one record per input, kept on the scan for whoever wants a
 * stronger and dearer reading of just that span (the emulator, on demand). An input a constant or a producer
 * accounts for completely is not one.
 */
/*
 * A reason names the LIMIT that made the input unknown: knowledge the model lacks (coverage) or the reach of the algorithm
 * that was running (scope). The table below the codes says which stage reads the limit away - or that none exists, which is
 * a coverage or scope limit to list (and where a dearer reading would start).
 */
#define KGENOME_LINEAGE_W_CONST    0x00001u   /* a constant or a frame address: resolved, not an obligation */
#define KGENOME_LINEAGE_W_ENTRY    0x00002u   /* a register at the function's entry: a parameter (or never set) - the callers are not read (SUMM) */
#define KGENOME_LINEAGE_W_MEM      0x00004u   /* a global or a field the run did not follow (LOCS) */
#define KGENOME_LINEAGE_W_CALL     0x00008u   /* a function's return the run did not apply (SUMM) */
#define KGENOME_LINEAGE_W_EXT      0x00010u   /* the result of a call the stages cannot see into: an import with no node, a pointer */
#define KGENOME_LINEAGE_W_STACK    0x00020u   /* the stack pointer was not known where the value is kept (an i386 callee that pops an unknown count) */
#define KGENOME_LINEAGE_W_OPAQUE   0x00040u   /* an instruction the transfer function has no rule for (a decode or model gap) */
#define KGENOME_LINEAGE_W_UNREACH  0x00080u   /* the consumer is in code no walk from an entry reached (SEED) */
#define KGENOME_LINEAGE_W_RET      0x00100u   /* a function of the object returns something no token names */
#define KGENOME_LINEAGE_W_SKIP     0x00200u   /* returned by a function of the object that was not read (nothing in it, nothing useful below it) */
#define KGENOME_LINEAGE_W_LIMIT    0x00400u   /* more producers than a value holds, or a bound of the stages fired */
#define KGENOME_LINEAGE_W_ADDR     0x00800u   /* loaded through a pointer that is neither a frame address nor a producer: an array element, a field of a parameter */
#define KGENOME_LINEAGE_W_COMPUTED 0x01000u   /* the result of arithmetic or logic: an index, pointer arithmetic, a decoded or hashed value */
#define KGENOME_LINEAGE_W_CLOBBER  0x02000u   /* a register a call destroyed: the program did not keep the value there */
#define KGENOME_LINEAGE_W_NARROW   0x04000u   /* a part of a register or a byte/word access: the model keeps whole words */
#define KGENOME_LINEAGE_W_SLOT     0x08000u   /* a stack slot this function never wrote: a buffer, array or struct filled through a pointer or by a callee */
#define KGENOME_LINEAGE_W_CELL     0x10000u   /* a global or field this function never wrote: set elsewhere, or initial data */
#define KGENOME_LINEAGE_W_NOCALLER 0x20000u   /* a parameter of a function with no direct caller: entered through a pointer or from outside */
#define KGENOME_LINEAGE_W_STATUS   0x40000u   /* the result of a node whose capability hands no handle on (a byte count, a status) */
#define KGENOME_LINEAGE_W_N        19u

/* The stage that reads the limit of reason bit number `bit` away, or 0 when none exists (coverage or scope to list; an
 * emulator reading would start there). Data: the table in diag_lineage_chain.c. */
unsigned kgenome_diag_oblig_next_stage(unsigned bit);

struct kgenome_diag_oblig {
	uint32_t node;          /* the consumer */
	uint8_t  role;          /* which input (KGENOME_DIAG_ROLE_*) */
	uint8_t  partial;       /* 1: some producers are known (the links are MAY) and the rest is not; 0: none is */
	uint32_t why;           /* KGENOME_LINEAGE_W_* */
	uint64_t fn_va;         /* the entry of the function the consumer is in (0 when the object names none) */
};

struct kgenome_diag_scan;
uint32_t kgenome_diag_oblig_count(const struct kgenome_diag_scan *s);
const struct kgenome_diag_oblig *kgenome_diag_oblig_at(const struct kgenome_diag_scan *s, uint32_t i);

/* What the selection did on the last scan: how much of the code each stage ran on, against all of it. */
struct kgenome_diag_lineage_stats {
	uint64_t fns;                   /* functions solved */
	uint64_t runs;                  /* solves of them: a function whose obligations match a stage's row is solved again with it */
	uint64_t fns_stage[4];          /* functions whose final run had the stage: [FLOW, LOCS, SUMM, SEED] */
	uint64_t blocks;                /* blocks of the functions solved */
	uint64_t blocks_stage[4];       /* blocks the stage was active on in the final run (its predicate held there) */
	uint64_t inputs;                /* inputs of consumer nodes the stages looked at */
	uint64_t must, may;             /* inputs that ended as one producer / several producers and nothing else, / not all */
	uint64_t unresolved;            /* inputs left in the unresolved set, none or some of the producers known */
	uint64_t demanded;              /* ... of which read after all, because a caller's result reached a consumer */
	uint64_t skipped;               /* functions not read: no node in them and nothing useful in what they call */
	uint64_t bounded[4];          /* times a bound of the stages fired: [token set of a value, token set of a consumer, steps of one function, rounds of a recursive group] */
	uint64_t dropped;               /* MAY links that did not fit: a node holds four links; the scan IS flagged (kgenome_diag_note_in_how sets KGENOME_TRUNCATED on the fifth distinct link) */
	uint64_t fd_inputs, fd_unresolved;  /* the same for the inputs that are descriptors (KGENOME_DIAG_ROLE_FD): the buffers and paths
					 * of the other roles are rarely a node's result, so their count says little about the stages */
	uint64_t why[KGENOME_LINEAGE_W_N]; /* ... by reason (an input can carry several) */
	/* Of the unresolved inputs, by the next stage of their reasons: one the plan allows and the function's last run did not have
	 * (a pipeline gap), one the class switched off, one that ran and left the input unresolved, none that exists (a limit). */
	uint64_t next_missing, next_off, next_ran, next_none;
};
int kgenome_diag_lineage_stats_of(const struct kgenome_diag_scan *s, struct kgenome_diag_lineage_stats *out);

#endif /* KGENOME_DIAG_LINEAGE_H */
