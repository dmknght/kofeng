/*
 * diag_scan_state.h - the open state of a diagnose scan: the object the routines fill and the
 * matcher reads.
 *
 * diag_scan.h is what a caller reads and treats the scan as opaque. The state is here, and public,
 * because two readers outside the routines need the fields: the engine's matcher (the hits, the
 * object bytes a node's name points into, the value-flow graph it builds on the scan and charges to
 * the scan's ledger) and the tests that build a scan by hand. diag_private.h is what the ROUTINES
 * share beyond this: the walk, the origin tracking, the prototypes of one routine offered to
 * another.
 */
#ifndef KGENOME_DIAG_SCAN_STATE_H
#define KGENOME_DIAG_SCAN_STATE_H

#include <stdint.h>

#include "diag_scan.h"
#include "diag_lineage.h"
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
	/* The same sites, sorted and without repeats, made by kgenome_diag_wrap_settle for
	 * the membership question (kgenome_diag_wrapper_site_wrapped); NULL until then. */
	uint64_t            *wrap_sorted;
	uint32_t             n_wrap_sorted;
	/* Syscall sites whose first argument was not a constant the sweep could
	 * read - the candidates for a wrapper. See kgenome_diag_run_wrappers. */
	uint32_t             n_unread;
	/*
	 * THE RELOCATIONS OF THIS OBJECT, one table for every route - see
	 * struct kgenome_elf_relocs. Borrowed when the caller built it for the object
	 * already (the scanner does, for its gate), built here on first use and
	 * owned otherwise.
	 */
	const struct kgenome_diag_apihash_set    *apihash;           /* see kgenome_diag_apihash */
	struct kgenome_diag_apihash_set          *own_apihash;
	int                          apihash_done;
	const struct kgenome_pe_imptab  *imports;           /* PE: see kgenome_diag_inputs */
	struct kgenome_pe_imptab         own_imports;       /* built here when not handed over */
	int                          imports_done;
	const struct kgenome_diag_seq   *seq;               /* see kgenome_diag_inputs */
	uint32_t                     n_seq;
	/* KGENOME_LINEAGE_S_*: the stages to run, or 0 for the class's plan - see kgenome_diag_inputs. */
	unsigned                     lineage_stages;
	const struct kgenome_elf_relocs *relocs;            /* CODE relocations */
	struct kgenome_elf_relocs        own_relocs;
	struct kgenome_elf_relocs        data_relocs;       /* DATA: the image builder's alone */
	struct kgenome_diag_rcall       *rcall;             /* the call sites, see kgenome_diag_relcalls */
	uint32_t                         n_rcall;
	int                              rcall_done;
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
	/* KGENOME_DIAG_OWN_*: what this scan had to build itself because the caller
	 * did not hand it over - see kgenome_diag_scan_own. */
	unsigned                     own;
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
	uint32_t             eval_cut;          /* expressions the constant evaluator left unread because one of its bounds fired (nesting, alias depth, value size, work; kgenome_dtx_ev_cut in diag_text_eval.c) */
	uint64_t             emu_charged;       /* guest pages charged for a live emulator */
	/* The token arena of the relocatable-object walk: producers whose node index is below
	 * `rel_tok_lim` have a page of their own, `rel_tok_span` pages are mapped. Set where the
	 * image is built, from the node count and the page budget. */
	uint32_t             rel_tok_lim, rel_tok_span;
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
	/* THE LINEAGE STAGES' RESULT besides the links: the inputs they could not account for, each with its reason, and what
	 * the selection did (diag_lineage.h). Owned by the scan. */
	uint64_t                         *noret_at;   /* the calls (offsets, ascending) to an import that never returns: exit, abort ... */
	uint32_t                          n_noret, cap_noret;
	struct kgenome_diag_oblig        *oblig;
	uint32_t                          n_oblig;
	struct kgenome_diag_lineage_stats lstats;
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

#endif /* KGENOME_DIAG_SCAN_STATE_H */
