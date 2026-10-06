/*
 * detectors/pathogen/kofdiag.h - the engine side of a diagnose.
 *
 * The FORMAT a diagnose is stored in is module ABI and lives in
 * kofmod/kofpathogen.h, beside the vocabulary it is made of. What is here is
 * what reads an object: the nodes found in it, and the matcher that walks
 * a diagnose tree over them.
 *
 * SEPARATE FROM OVERLORD, which is the other half of detection: overlord
 * asks what the BYTES are - a declared pattern, a block's similarity, the
 * object's geometry - and pathogen asks what the CODE DOES. They fail in
 * different places, which is the only reason to carry both: a recompile
 * defeats the first and leaves the second; a packer defeats the second and
 * leaves the first once the payload is out.
 */

#ifndef KOFENG_PATHOGEN_KOFDIAG_H
#define KOFENG_PATHOGEN_KOFDIAG_H

#include <stdint.h>

#include "../../kofeng.h"
#include "../../kofcore/kofmod/kofsig.h"   /* struct kof_obj_ctx */
#include "../../kofcore/kofmod/kofpathogen.h"

/*
 * ONE NODE FOUND IN AN OBJECT.
 *
 * `in[]` IS WHY THIS IS NOT THE SAME STRUCT AS kof_diag_node. A node in a
 * DIAGNOSE has one parent, because a diagnose is a tree. A node in an
 * OBJECT may take values from several places at once - a `read` has both a
 * buffer and a descriptor, and each came from somewhere - so what is found
 * is a small set of inputs and the diagnose selects among them.
 */

/* The number of an input whose origin is not a node here. */
#define KOF_DIAG_FROM_NONE  0xffffu
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
#define KOF_DIAG_FROM_STACK 0xfffeu

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
enum kof_diag_kind {
	KOF_DIAG_KIND_PRODUCED = 0,
	KOF_DIAG_KIND_SHARED
};

struct kof_diag_in {
	uint16_t from;          /* index of the origin node, or the two above */
	uint8_t  role;          /* enum kof_diag_role                         */
	uint8_t  how;           /* enum kof_diag_link                         */
	uint8_t  kind;          /* enum kof_diag_kind                         */
};

/* Bits in kof_diag_hit.bits. */
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
#define KOF_DIAG_H_OPAQUE (1u << 0)
/*
 * THE REGION THIS NODE ESTABLISHED IS THE STACK.
 *
 * mprotect names its region in an argument and returns zero, so a later
 * node cannot be linked to it by following a value. When the argument came
 * off the stack pointer, "the same stack" is what links them - and MEASURED
 * on msfvenom's i386 stagers it is the ONLY thing that does. Without it one
 * diagnose cannot cover both architectures.
 */
#define KOF_DIAG_H_REGION_STACK (1u << 1)
/* This call returns zero when it succeeds, so the number for the NEXT
 * syscall may already be in the result register - see kof_sys_zero_on_success. */
#define KOF_DIAG_H_ZERO_OK (1u << 2)
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
#define KOF_DIAG_H_ARG_UNKNOWN (1u << 3)
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
#define KOF_DIAG_H_RAW_SYSCALL (1u << 4)

/*
 * BIT 5 WAS KOF_DIAG_H_ATTR_STR - `attr` held the OFFSET IN THE FILE of a name
 * a call was handed. It is gone, and the number is left unused rather than
 * reused so nothing built against it reads a different bit.
 *
 * A name cannot be an offset into the file: one built at run time is not in
 * the file, and one that is there may be encoded until the code in front of
 * the call has run over it. Names are now copies read out of the emulator's
 * memory and kept in the scan - see kof_diag_str_at.
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
#define KOF_DIAG_H_VAL (1u << 6)

/*
 * AN ARGUMENT OF THIS CALL NAMED A SYMBOL - `symref` is the file offset of
 * that symbol's name and `symadd` how far into it the address pointed.
 *
 * THE ONLY WAY TO READ A RELOCATABLE OBJECT'S OPERANDS, and the reason is in
 * the file format: a .ko is unlinked, so an operand naming a symbol is a
 * hole, and the name is in the relocation beside the instruction. See
 * struct org.
 *
 * WHY THE OFFSET INTO THE SYMBOL IS KEPT SEPARATELY. It is the whole of the
 * claim in the case this was written for: a module hands THIS_MODULE to the
 * kernel all day long, and reaching into a FIELD of it is a different act.
 */
#define KOF_DIAG_H_SYMREF (1u << 7)

struct kof_diag_hit {
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
	/* The constant this node wrote - see KOF_DIAG_H_VAL. */
	uint64_t val;
	/* The symbol an argument named, and how far into it - see
	 * KOF_DIAG_H_SYMREF. */
	uint64_t symref;
	int32_t  symadd;
	uint16_t cap;           /* enum kof_flow_cap, or KOF_NUCLEO_NONE       */
	uint16_t flags;         /* KOF_FLOWF_* observed at this site        */
	uint8_t  bits;          /* KOF_DIAG_H_*                             */
	uint8_t  n_in;
	struct kof_diag_in in[4];
};

struct kof_diag_scan;

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
 * The bits are the same question KOF_DIAG_VIA_* asks of a diagnose, from the
 * other side: via says which routine COULD satisfy a rule, this says which
 * one a caller is willing to pay for.
 */
#define KOF_DIAG_RUN_SYSCALL (1u << 0)  /* sweep code for syscall sites   */
#define KOF_DIAG_RUN_SYMBOL  (1u << 1)  /* imports and their call sites   */
#define KOF_DIAG_RUN_EMULATE (1u << 2)  /* run the gaps, to link nodes    */
#define KOF_DIAG_RUN_ALL     (KOF_DIAG_RUN_SYSCALL | KOF_DIAG_RUN_SYMBOL | \
			      KOF_DIAG_RUN_EMULATE)
/*
 * WHAT kof_diag_scan RUNS, WHICH IS NOT EVERYTHING THAT EXISTS.
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
 * through kof_diag_scan_with, which is what it was built switchable for.
 */
#define KOF_DIAG_RUN_DEFAULT (KOF_DIAG_RUN_SYSCALL | KOF_DIAG_RUN_SYMBOL)

/*
 * READ AN OBJECT'S NODES. NULL when there is nothing this can read - a
 * format with no code regions, or an architecture the value model does not
 * have. That is NOT the same as an object with no nodes, and a caller must
 * not treat it as such.
 *
 * kof_diag_scan runs every routine that applies. kof_diag_scan_with runs the
 * ones named, and is how a measurement isolates one.
 */
struct kof_diag_scan *kof_diag_scan(const struct kof_obj_ctx *ctx,
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
 * WHAT BOUNDS THE COST IS THE DEMAND GATE - see KOF_ENG_USE_PATHOGEN. An
 * object no rule asks about pays nothing at all, which is a bigger saving
 * than any filter inside the walk, and it is the only one that cannot cost
 * a detection.
 */
struct kof_diag_scan *kof_diag_scan_with(const struct kof_obj_ctx *ctx,
					 const uint8_t *base, uint64_t size,
					 unsigned run);

/* Which routines actually ran on this object - a caller asking "is this
 * capability absent" must know whether the routine that would have found it
 * was among them. */
unsigned kof_diag_scan_ran(const struct kof_diag_scan *);

uint32_t kof_diag_scan_count(const struct kof_diag_scan *);
const struct kof_diag_hit *kof_diag_scan_at(const struct kof_diag_scan *,
					    uint32_t i);

/*
 * THE NAMES CALLS OF `cap` WERE GIVEN, in the order they were first seen.
 * `i` runs from zero; NULL past the end. The string is the scan's and lives
 * until kof_diag_scan_free.
 */
const char *kof_diag_str_at(const struct kof_diag_scan *, uint16_t cap,
			    uint32_t i);
uint32_t    kof_diag_str_count(const struct kof_diag_scan *, uint16_t cap);
/*
 * DOES THIS DIAGNOSE CARRY EVERY ONE OF THESE NAMES - the names read at the
 * call sites its tree BOUND, across every place the tree matched, and no
 * others.
 *
 * ACROSS INSTANCES, not within one: a module that places a probe on two
 * symbols has two matches of the same tree with a name each, and "carries
 * both" means both were seen, not that one call was handed both. A diagnose
 * that did not match at all carries nothing.
 *
 * kof_diag_str_at and _count are the ones that walk the list by capability,
 * for a caller that wants the list itself; THIS is the one a verdict reaches.
 */
int         kof_diag_scan_names(const struct kof_diag_scan *,
				const struct kof_diag *,
				const char *const *strs, uint32_t n);

/* Non-zero when the walk stopped at its bound. A caller asking "is this
 * capability absent" must read this and answer "cannot say" instead. */
int kof_diag_scan_full(const struct kof_diag_scan *);

void kof_diag_scan_free(struct kof_diag_scan *);

/*
 * DOES THIS OBJECT CARRY THIS DIAGNOSE. 1 or 0, and on 1 the node each of
 * the diagnose's nodes bound to is written to `bind_out`, in the order the
 * diagnose declares them. That is what a signature joins two diagnoses on -
 * see the note on kof_diag_share, which asks for a node of a given
 * capability that both of them bound.
 *
 * `bind_out` must have room for the diagnose's node count; NULL asks for the
 * bit alone, which is what kof_diag() costs.
 */
/*
 * DOES A NODE OF `cap` BOUND BY `b` REACH ANY NODE BOUND BY `a`, following
 * value-flow links - the transitive join a verdict asks. See the note in
 * kofdiag.c. The bind arrays are what kof_diag_match returned.
 */
int kof_diag_flow_join(struct kof_diag_scan *, uint16_t cap,
		       const uint16_t *a_bind, uint8_t na,
		       const uint16_t *b_bind, uint8_t nb);

int kof_diag_match(const struct kof_diag_scan *, const struct kof_diag *,
		   uint16_t *bind_out, uint8_t *n_bind);

/*
 * SERIALISE THE GRAPH INTO THE RECORD BLOCK A RULE READS - see
 * kofmod/kofpathogen.h. Returns the bytes written, or 0.
 *
 * A COPY, and deliberately: the engine's node array is its own working state
 * and grows while the analysis runs, while a rule reads a block that does not
 * move under it. The cost is bounded by the DATABASE rather than the object -
 * the graph has already been pruned to the capabilities some diagnose named.
 */
uint32_t kof_diag_graph_build(const struct kof_diag_scan *s, uint8_t *out,
			      uint32_t cap);

/*
 * READ ONE .kdig FILE. 1 on success, 0 when the bytes do not add up - and a
 * file that does not add up is refused WHOLE. The caller owns `node` and
 * `name`; nothing here allocates, so a load cannot fail halfway and leave
 * something to free.
 */
int kof_diag_load(const uint8_t *b, uint64_t n, struct kof_diag *out,
		  struct kof_diag_node *node, uint8_t max_node,
		  char *name, uint32_t name_cap,
		  char *needs, uint32_t needs_cap);

#endif /* KOFENG_PATHOGEN_KOFDIAG_H */
