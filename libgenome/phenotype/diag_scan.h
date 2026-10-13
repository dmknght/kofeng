/*
 * libgenome/phenotype/diag_scan.h - the nodes an object holds: what the
 * genotyping of code finds, before anything is matched against it.
 *
 * This is the analysis half of what used to be one header. The nodes, their
 * inputs and the scan that fills them are facts about the object and carry no
 * verdict; the matcher that walks a diagnose over them is
 * detectors/linkage/kofdiag.h, which includes this one. The FORMAT a diagnose
 * is stored in is module ABI and lives in kofmod/kofdiagtree.h.
 */

#ifndef KGENOME_DIAG_SCAN_H
#define KGENOME_DIAG_SCAN_H

#include <genotype/image/funcs.h>
#include <stdint.h>
#include "../kgenome_budget.h"   /* struct kgenome_budget, enum kgenome_status */

#include <genotype/image/obj.h>   /* struct kgenome_obj */
#include <kofcore.h>            /* kof_buf */
#include <phenotype/diag_vocab.h>   /* KOF_DIAG_ROLE_*, KOF_DIAG_LINK_* */
#include <celllysis/capability.h>   /* KOF_NUCLEO_*, KOF_FLOWF_* */
#include <celllysis/celllysis.h>    /* kgenome_cell_insn_fn */

/*
 * ONE NODE FOUND IN AN OBJECT.
 *
 * `in[]` IS WHY THIS IS NOT THE SAME STRUCT AS kof_diag_node. A node in a
 * DIAGNOSE has one parent, because a diagnose is a tree. A node in an
 * OBJECT may take values from several places at once - a `read` has both a
 * buffer and a descriptor, and each came from somewhere - so what is found
 * is a small set of inputs and the diagnose selects among them.
 */

/*
 * THE STACK IS AN ORIGIN WITH NO NODE.
 *
 * msfvenom's i386 payloads make the stack executable and then jump into
 * it: `mprotect(esp & ~0xfff, len, RWX)` returns 0, not a pointer, so
 * there is no value to follow from the allocation to the jump. What the
 * two share is that both addresses are derived from the stack pointer, and
 * that is enough to link them - MEASURED, it is the only thing that links
 * them, and without it one rule cannot cover both architectures.
 */
#define KGENOME_DIAG_FROM_STACK 0xfffeu

/*
 * WHICH OF TWO RELATIONS A LINK IS.
 *
 * The model had one: the parent returned the value the child's input holds.
 * That is provenance, and it is not the only way two calls are related.
 *
 *   PRODUCED  kzalloc hands back a buffer and copy_from_user is given it;
 *             prepare_creds hands back credentials and commit_creds
 *             installs them. The child holds what the parent MADE.
 *   SHARED    both halves of the kprobe pair are handed the same struct
 *             kprobe. Neither made it - it is a module global - and what
 *             relates them is that it is the SAME OBJECT. The same is true
 *             of the two copies in a hooked getdents: the listing is read
 *             into a buffer and the same buffer is written back out, and
 *             the editing in between is the whole of the hook.
 *
 * WITH ONE KIND FOR BOTH they collide. A buffer produced once and received
 * twice put three nodes in the table, and an argument came back with two
 * parents wearing one role - so the code picked one, which meant recording
 * a RECEIVER as the producer of a buffer something else had produced. That
 * was tidying the output, not describing the program.
 *
 * Kept apart, both are said: copy_to_user holds what kzalloc produced AND
 * holds the same object copy_from_user filled, and neither statement has to
 * be dropped for the other.
 */
enum kgenome_diag_kind {
	KGENOME_DIAG_KIND_PRODUCED = 0,
	KGENOME_DIAG_KIND_SHARED
};

struct kgenome_diag_in {
	uint16_t from;          /* index of the origin node, or the two above */
	uint8_t  role;          /* enum kgenome_diag_role                         */
	uint8_t  how;           /* enum kgenome_diag_link                         */
	uint8_t  kind;          /* enum kgenome_diag_kind                         */
};

/* Bits in kgenome_diag_hit.bits. */
/*
 * THE NUMBER COULD NOT BE READ, and the node is emitted anyway.
 *
 * A `syscall` whose number is computed, or left in a register by an
 * earlier call, or simply decoded out of data. Dropping it would make a
 * program with unreadable syscalls indistinguishable from one with none -
 * and the first of those is the more interesting object. It is also a
 * discriminator in its own right: measured, 24 of 103 syscall sites in one
 * real sample came back this way.
 */
#define KGENOME_DIAG_H_OPAQUE (1u << 0)
/*
 * THE REGION THIS NODE ESTABLISHED IS THE STACK.
 *
 * mprotect names its region in an argument and returns zero, so a later
 * node cannot be linked to it by following a value. When the argument came
 * off the stack pointer, "the same stack" is what links them - and MEASURED
 * on msfvenom's i386 stagers it is the ONLY thing that does. Without it one
 * diagnose cannot cover both architectures.
 */
#define KGENOME_DIAG_H_REGION_STACK (1u << 1)
/* This call returns zero when it succeeds, so the number for the NEXT
 * syscall may already be in the result register - see kgenome_nucleo_sys_zero_on_success. */
#define KGENOME_DIAG_H_ZERO_OK (1u << 2)
/*
 * AN ARGUMENT THAT DECIDES WHAT THIS CALL MEANS COULD NOT BE READ.
 *
 * mmap's prot is the case that matters: with PROT_EXEC it is a region
 * about to hold code, without it a buffer, and the vocabulary has a
 * different word for each. An unreadable prot is NEITHER of those - but
 * the refinement is written as "upgrade when the bit is set", so an
 * unknown argument silently produces the no-execute answer.
 *
 * MEASURED on msfvenom's x86_nonalpha payload: the engine called its
 * mprotect a plain allocation and the stager shape did not match, because
 * a value the decoder could not follow had been read as a zero. Saying
 * nothing would have been right; saying "no execute permission" was not.
 */
#define KGENOME_DIAG_H_ARG_UNKNOWN (1u << 3)
/*
 * A DIRECT SYSTEM CALL WHOSE NUMBER WAS READ AND WHOSE VOCABULARY DOES NOT
 * APPLY - which today means a `syscall` in a PE.
 *
 * NOT THE SAME AS OPAQUE, and keeping them apart is the whole point. Opaque
 * says the number could not be read; this says it could, and that the
 * engine refuses to name it because the number space is not the one the
 * vocabulary knows. A Windows service number resolved through the Linux
 * table does not fail, it ANSWERS - measured, a Hell's Gate shaped stub
 * with `mov eax,0x3b` came back as proc-start, because 0x3b is execve on
 * Linux x86-64.
 *
 * AND A READ NUMBER IS ITSELF THE SIGNAL on Windows. A program that reaches
 * the kernel without going through ntdll is doing the thing hook-evading
 * loaders do; a `0f 05` sitting in packed data is not. Folded into OPAQUE
 * the two are one answer, and the interesting one is lost in the noise -
 * MEASURED on 300 PE samples, where every site was opaque, so a real
 * direct call would have had nothing to stand out against.
 */
#define KGENOME_DIAG_H_RAW_SYSCALL (1u << 4)

/*
 * BIT 5 WAS KOF_DIAG_H_ATTR_STR - `attr` held the OFFSET IN THE FILE of a name
 * a call was handed. It is gone, and the number is left unused rather than
 * reused so nothing built against it reads a different bit.
 *
 * A name cannot be an offset into the file: one built at run time is not in
 * the file, and one that is there may be encoded until the code in front of
 * the call has run over it. Names are now copies read out of the emulator's
 * memory and kept in the scan - see kgenome_diag_str_at.
 */

/*
 * `val` HOLDS THE VALUE THIS NODE WROTE, and it was a constant in the
 * instruction rather than something the run worked out.
 *
 * ONLY A LITERAL COUNTS. A value that arrived in a register is one the
 * model may have lost track of, and "zero because we could not tell" and
 * "zero because the program wrote zero" are the same bit pattern - the
 * second is evidence and the first is the absence of it. What Diamorphine
 * needs is `mov QWORD PTR [rax+0x4],0x0`, where the zero is four bytes of
 * the instruction.
 */
/*
 * THE NODE AT A WRAPPER'S OWN SYSCALL, once its callers have nodes of their own.
 * One node there spoke for every caller at once and for none of them; it stays
 * in the list (a dump should show what the sweep saw) and is not matched.
 */
#define KGENOME_DIAG_H_SUPERSEDED (1u << 5)
#define KGENOME_DIAG_H_VAL (1u << 6)

/*
 * AN ARGUMENT OF THIS CALL NAMED A SYMBOL - `symref` is the file offset of
 * that symbol's name and `symadd` how far into it the address pointed.
 *
 * THE ONLY WAY TO READ A RELOCATABLE OBJECT'S OPERANDS, and the reason is in
 * the file format: a .ko is unlinked, so an operand naming a symbol is a
 * hole, and the name is in the relocation beside the instruction. See
 * struct kgenome_diag_org.
 *
 * WHY THE OFFSET INTO THE SYMBOL IS KEPT SEPARATELY. It is the whole of the
 * claim in the case this was written for: a module hands THIS_MODULE to the
 * kernel all day long, and reaching into a FIELD of it is a different act.
 */
#define KGENOME_DIAG_H_SYMREF (1u << 7)

struct kgenome_diag_hit {
	uint64_t at;            /* where, as an offset into the object      */
	/*
	 * THE CONSTANT THAT NAMES WHICH PART OF AN OBJECT, and 0 when the
	 * node is not about one.
	 *
	 * A node used to be able to say "something was read out of the thing
	 * that call produced" and no more. The number is the whole of the
	 * meaning in every case measured here:
	 *
	 *   cred + 8, +0x10, +0x18, +0x20   the uid and gid fields - the
	 *                                   difference between copying
	 *                                   credentials and taking root
	 *   kp + 0x2d                       the probe's resolved address -
	 *                                   the reason the probe exists
	 *   dirent + 0x10                   d_reclen, the record length a
	 *                                   rootkit edits to splice an entry
	 *                                   out of a directory listing
	 *   table + 0x270, 0x6c8, 0x1f0     which syscall is being hooked
	 *
	 * It is a VALUE and not a class, which kofdiag.h's note on attributes
	 * says belongs in a report rather than in matching - and that note is
	 * about a value the AUTHOR chose, like a path or an address. A
	 * structure offset is chosen by the kernel's ABI and is as fixed as a
	 * syscall number.
	 */
	uint64_t attr;
	/* The constant this node wrote - see KGENOME_DIAG_H_VAL. */
	uint64_t val;
	/* The symbol an argument named, and how far into it - see
	 * KGENOME_DIAG_H_SYMREF. */
	uint64_t symref;
	int32_t  symadd;
	uint16_t cap;           /* enum kgenome_nucleo_cap, or KGENOME_NUCLEO_NONE       */
	uint16_t flags;         /* KOF_FLOWF_* observed at this site        */
	uint8_t  bits;          /* KOF_DIAG_H_*                             */
	uint8_t  n_in;
	struct kgenome_diag_in in[4];
};

struct kgenome_diag_scan;

/*
 * ---- THE ANALYSIS ROUTINES, ONE BIT EACH ----------------------------------
 *
 * Reading an object's nodes is not one algorithm and should never have been
 * written as one. A userspace stager is found by sweeping for syscalls; a
 * kernel module makes none and is found by its imports; a value that passes
 * through memory is found by neither and needs the interpreter. The three
 * cost different amounts, apply to different objects, and break in different
 * ways.
 *
 * SO THEY ARE SEPARATE ROUTINES BEHIND SEPARATE BITS, and the reason is not
 * tidiness: it is that one of them must be switchable off without the others
 * changing their answer. A scenario that cannot be disabled cannot be
 * measured - there is nothing to compare its output against - and a bug in it
 * is a bug in the whole walk.
 *
 * The bits are the same question KOF_DIAG_ANALYSIS_* asks of a diagnose, from the
 * other side: via says which routine COULD satisfy a rule, this says which
 * one a caller is willing to pay for.
 */
#define KGENOME_DIAG_RUN_SYSCALL (1u << 0)  /* sweep code for syscall sites   */
#define KGENOME_DIAG_RUN_SYMBOL  (1u << 1)  /* imports and their call sites   */
#define KGENOME_DIAG_RUN_EMULATE (1u << 2)  /* run the gaps, to link nodes    */
#define KGENOME_DIAG_RUN_APIHASH (1u << 3)  /* name what a PE resolves itself */
#define KGENOME_DIAG_RUN_ALL     (KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL | \
			      KGENOME_DIAG_RUN_EMULATE | KGENOME_DIAG_RUN_APIHASH)
/*
 * WHAT kgenome_diag_scan RUNS, WHICH IS NOT EVERYTHING THAT EXISTS.
 *
 * EMULATE is written and is NOT in here, for two reasons that are both
 * measured and both about to be fixed rather than argued with:
 *
 *   IT DOUBLES THE NODES. It reports what a RUN called, in call order; the
 *   syscall routine reports what the CODE contains, at file offsets. The two
 *   describe the same mmap and have no way yet to say so, so a scan with both
 *   on returns it twice.
 *   IT REPEATS A LOOP. meter1_x86 retries connect ten times and the run logs
 *   all ten - thirty nodes where the file has three sites.
 *
 * Until a node from a run and a node from a sweep can be recognised as one,
 * turning this on by default would make every count wrong. It is reachable
 * through kgenome_diag_scan_with, which is what it was built switchable for.
 */
#define KGENOME_DIAG_RUN_DEFAULT (KGENOME_DIAG_RUN_SYSCALL | KGENOME_DIAG_RUN_SYMBOL)

/*
 * READ AN OBJECT'S NODES. NULL when there is nothing this can read - a
 * format with no code regions, or an architecture the value model does not
 * have. That is NOT the same as an object with no nodes, and a caller must
 * not treat it as such.
 *
 * kgenome_diag_scan runs every routine that applies. kgenome_diag_scan_with runs the
 * ones named, and is how a measurement isolates one.
 */
struct kgenome_diag_scan *kgenome_diag_scan(const struct kgenome_obj *obj,
				    const uint8_t *base, uint64_t size);
/*
 * ---- THERE IS NO CAPABILITY FILTER, AND THERE CANNOT BE ONE -------------
 *
 * This took a `want` set - the capabilities some loaded diagnose named -
 * on the argument that a node nobody asked about cannot end a link. The
 * argument is the retired prune's argument word for word, and it died the
 * same way: A VERDICT IS NOT A TREE. It counts, it asks whether something
 * is merely present, and the things it asks about are exactly the ones no
 * diagnose names - the cr0 write a syscall-table verdict needs is nobody's
 * child, so no diagnose can mention it, and filtering it out takes the
 * detection with it.
 *
 * The parameter survived the prune's removal, was stored on the scan and
 * READ BY NOTHING, while three comments went on describing a graph that
 * had been filtered. A scanner was still paying a loop per object to build
 * the set.
 *
 * WHAT BOUNDS THE COST IS THE DEMAND GATE - see KOF_ENG_USE_DIAGNOSE. An
 * object no rule asks about pays nothing at all, which is a bigger saving
 * than any filter inside the walk, and it is the only one that cannot cost
 * a detection.
 */
struct kgenome_diag_scan *kgenome_diag_scan_with(const struct kgenome_obj *obj,
					 const uint8_t *base, uint64_t size,
					 unsigned run);

/*
 * ---- WHAT A CALLER MAY HAND OVER, BECAUSE IT HAS IT ALREADY ---------------
 *
 * Each is an input the routes would otherwise derive, and each is BORROWED and
 * must outlive the scan. NULL is the ordinary answer: the first route that needs
 * one builds it, and the scan owns what it built.
 *
 *   relocs  - the object's relocation table; the scanner builds it for its gate
 *             and every route reads the same one.
 *   imports - the PE's import table; the symbol block spells it as records and
 *             the PE route matches call sites against its slots, one walk.
 *   apihash - what a PE resolves for itself - see struct kgenome_diag_apihash_set. An
 *             ANALYSIS RESULT, computed once per object and read by the graph
 *             and by the object's symbols alike.
 */
struct kgenome_elf_relocs;
/*
 * THE WALK - every instruction of the executable segments, decoded once: the
 * call targets (the entries), the kernel-entry sites and, for whoever reads the
 * code again, the decode trace. An analysis result of the object, like the
 * relocations beside it; opaque, made by kgenome_diag_walk_new and filled by the
 * first reader that needs it.
 */
struct kgenome_diag_walk;
struct kgenome_diag_walk *kgenome_diag_walk_new(void);
void kgenome_diag_walk_free(struct kgenome_diag_walk *);
struct kgenome_pe_imptab;
/* A head, and the two calls it is made of - see KOF_DIAG_DECLARE_SEQUENCE. */
struct kgenome_diag_seq {
	uint16_t made;
	uint16_t first;
	uint16_t then;
};
struct kgenome_diag_inputs {
	const struct kgenome_elf_relocs *relocs;
	const struct kgenome_diag_apihash_set    *apihash;
	/* The PE's import table, walked once for the symbol block and read here
	 * for the slots - see kgenome_pe_imptab. NULL: the PE route walks its own. */
	const struct kgenome_pe_imptab  *imports;
	/* The object's functions - see funcs.h. The scanner builds them once beside
	 * its symbol block; a caller with none leaves this NULL and the first route
	 * that needs them builds its own. */
	const struct kgenome_func_set   *funcs;
	/* The object's walk - an empty one is filled by the first route that
	 * needs it, and every later reader (the functions, the wrapper
	 * resolution) reads that one. NULL: the scan owns one. */
	struct kgenome_diag_walk        *walk;
	/*
	 * THE HEADS THE ENGINE BUILDS OUT OF TWO CALLS - one per diagnose that
	 * declared a sequence and whose gate is open. Without one, no such node
	 * is made: it exists because something asked for it.
	 */
	const struct kgenome_diag_seq   *seq;
	uint32_t                     n_seq;
	/*
	 * WHAT THE SCAN MAY COST, from the caller - see kgenome_budget.h. NULL is
	 * the ordinary answer for a tool: the limits are then the defaults for this
	 * object (kgenome_budget_default over its size and its code). A field of
	 * the struct left at zero is filled the same way, so a caller that only
	 * knows its memory allowance sets max_bytes and nothing else.
	 */
	const struct kgenome_budget     *budget;
};
struct kgenome_diag_scan *kgenome_diag_scan_with_inputs(const struct kgenome_obj *obj,
						const uint8_t *base,
						uint64_t size, unsigned run,
						const struct kgenome_diag_inputs *in);

/*
 * ---- THE APIS A PE RESOLVES FOR ITSELF - see diag_apihash.c ---------------
 *
 * The product of an analysis and not of a route: the calls a program makes
 * through a resolver of its own, found by running that resolver against the
 * modelled loader, so no hash, seed or rotation appears here.
 */
struct kgenome_diag_apihash_call {
	uint64_t site;          /* the address of the call, in the image  */
	uint64_t arg[4];
	uint64_t ret;
	char     api[40];       /* "VirtualAlloc"                          */
	char     dll[16];       /* "kernel32.dll"                          */
};

struct kgenome_diag_apihash_set {
	uint64_t *peb;          /* file offsets of the reads that led to it */
	uint32_t  n_peb, cap_peb;
	uint32_t  n_ldr;        /* ...of which a load of PEB.Ldr followed   */
	struct kgenome_diag_apihash_call *call;
	uint32_t  n_call;
	uint64_t  end_rip;      /* where the run ended, and the instruction */
	uint64_t  end_from;     /* that last transferred control            */
	/*
	 * KGENOME_OK, or why the list may be short: KGENOME_TRUNCATED when the run
	 * was stopped while it was still going (the instruction ceiling or after a
	 * silence), KGENOME_OVER_BUDGET when the caller's instruction budget ended
	 * it, KGENOME_NOMEM when the result could not be held. Read by the graph
	 * (the scan's status) and by the symbols (truncated). It was an `int
	 * budget` that only said "stopped"; the status says which limit.
	 */
	enum kgenome_status status;
};

/*
 * Analyse a PE. NULL for anything that is not one or on allocation failure;
 * otherwise a product whose n_call may be zero - a program that does not read
 * the loader data costs a decode and is never run.
 */
/* `imports` is the object's import table (kgenome_pe_imptab, walked once by whoever
 * asked first); the run's emulator reads its IAT from it. NULL: it builds one.
 * `budget` bounds the run (max_insn, deadline_ms); NULL is the default for this
 * object. */
struct kgenome_diag_apihash_set *kgenome_diag_apihash_run(const struct kgenome_obj *obj,
				    const uint8_t *base, uint64_t size,
				    const struct kgenome_pe_imptab *imports,
				    const struct kgenome_budget *budget);
void kgenome_diag_apihash_free(struct kgenome_diag_apihash_set *a);
/*
 * The DISTINCT APIs of a product - once each however many places call it - as
 * parallel arrays the caller sized to a->n_call. Returns how many. The one
 * place that decides what "the same API" means, read by a module that reports them
 * (oc_api_resolved), which is the one way they reach the symbol block.
 */
uint32_t kgenome_diag_apihash_distinct(const struct kgenome_diag_apihash_set *a, const char **dll,
			      const char **name);
/* The product the scan reads: handed over by the caller, else built once and
 * owned by the scan. NULL for a non-PE. */
const struct kgenome_diag_apihash_set *kgenome_diag_apihash(struct kgenome_diag_scan *s,
					   const struct kgenome_obj *obj);

/* Which routines actually ran on this object - a caller asking "is this
 * capability absent" must know whether the routine that would have found it
 * was among them. */
unsigned kgenome_diag_scan_ran(const struct kgenome_diag_scan *);

uint32_t kgenome_diag_scan_count(const struct kgenome_diag_scan *);
const struct kgenome_diag_hit *kgenome_diag_scan_at(const struct kgenome_diag_scan *,
					    uint32_t i);

/*
 * THE NAMES CALLS OF `cap` WERE GIVEN, in the order they were first seen.
 * `i` runs from zero; NULL past the end. The string is the scan's and lives
 * until kgenome_diag_scan_free.
 */
const char *kgenome_diag_str_at(const struct kgenome_diag_scan *, uint16_t cap,
			    uint32_t i);
uint32_t    kgenome_diag_str_count(const struct kgenome_diag_scan *, uint16_t cap);

/*
 * WHETHER THE SCAN'S ANSWER IS WHOLE. KGENOME_OK, or the worst status any
 * limit that fired set - nodes, names, links, windows, the wrapper walk, the
 * emulated run, the ledger. A caller asking "is this capability absent" must
 * read this first and answer "cannot say" for anything but KGENOME_OK.
 * A NULL scan is KGENOME_BAD_INPUT.
 */
enum kgenome_status kgenome_diag_scan_status(const struct kgenome_diag_scan *);
/* Names refused because they were too long or the store was at its limit. */
uint32_t kgenome_diag_scan_refused(const struct kgenome_diag_scan *);
/* Bytes charged to the scan's ledger now (the most it held: *peak). A caller
 * charges its own scan for them. */
uint64_t kgenome_diag_scan_bytes(const struct kgenome_diag_scan *, uint64_t *peak);
/* The executable bytes of an object - the `code_bytes` of its budget. */
uint64_t kgenome_diag_code_bytes(const struct kgenome_obj *obj, uint64_t size);
/* THIN WRAPPER, kept for the callers that only ask "did a limit fire": non-zero
 * when kgenome_diag_scan_status is not KGENOME_OK. */
int kgenome_diag_scan_full(const struct kgenome_diag_scan *);

void kgenome_diag_scan_free(struct kgenome_diag_scan *);

void kgenome_diag_funcs_of(const struct kgenome_obj *obj, const uint8_t *data,
		       uint64_t data_n, struct kgenome_func_set *out);
/* The same, reading the entries from `walk` (filled here when it is empty;
 * `want_trace` when the caller will read the code again - see
 * kgenome_diag_walk_ensure). */
void kgenome_diag_funcs_with_walk(const struct kgenome_obj *obj, const uint8_t *data,
			      uint64_t data_n, struct kgenome_diag_walk *walk,
			      int want_trace, struct kgenome_func_set *out);
void kgenome_diag_funcs_of_view(const struct kgenome_obj *parent_obj, kof_buf parent,
			    const struct kgenome_func_set *parent_funcs, kof_buf view,
			    struct kgenome_func_set *out);

/*
 * THE INSTRUCTIONS OF ONE RUN OF AN OBJECT'S CODE, handed to an observer: the
 * file bytes [off, off + n), read as a linear sweep that starts at `off` and
 * decodes each instruction as if it ran at `va` + (its offset - off), on a
 * window that ends with the run. `wk` is the object's walk and may be NULL; when
 * it holds a live trace for these bytes the instructions the trace holds are
 * served from it, every other position is decoded - the answer is the same
 * either way (see "THE INSTRUCTIONS OF ONE RUN" in diag_wrapper_walk.c). `st` may be
 * NULL; it counts where the instructions came from.
 */
struct kgenome_diag_code_run_stats {
	uint64_t from_trace, decoded, skipped;
};
/*
 * ONE RUN, as a request: the object and its bytes, the run's window and address,
 * the observer, and the two things the caller keeps - the object's walk (the
 * trace to serve from; NULL for none) and the stats ledger (NULL for none).
 */
struct kgenome_diag_code_req {
	/* the object */
	const struct kgenome_obj           *obj;
	const uint8_t                      *base;
	uint64_t                            size;
	/* the run: file bytes [off, off + n), decoded as if at `va` */
	uint64_t                            off;
	uint64_t                            n;
	uint64_t                            va;
	/* the observer */
	kgenome_cell_insn_fn                fn;
	void                               *user;
	/* the caller's */
	struct kgenome_diag_walk           *wk;
	struct kgenome_diag_code_run_stats *st;
};
void kgenome_diag_code_run(const struct kgenome_diag_code_req *rq);
struct kgenome_elf_info;
/*
 * THE CODE RANGE OF AN ELF SEGMENT: the executable segment `i`'s bytes past the
 * headers, clipped to the object - the one definition of where code can be. The
 * xref sweep reads it as it is. Returns the length, 0 for a segment that is not
 * code, and writes the offset to `*at`.
 */
uint64_t kgenome_diag_code_range(const struct kgenome_elf_info *e, uint32_t i,
			     uint64_t size, uint64_t *at);

/* A limit fired: say so on the scan. The one way a routine reports that its
 * answer is partial - see kgenome_status.h. */
void kgenome_diag_note(struct kgenome_diag_scan *s, enum kgenome_status st);

/* Does the node `b` of capability `cap` carry the name `name`: a place that name
 * was seen. The matcher asks it; the scan owns the table it reads. */
int kgenome_diag_str_at_node(const struct kgenome_diag_scan *s, uint16_t cap, uint16_t node,
			 const char *name);

#endif /* KGENOME_DIAG_SCAN_H */
