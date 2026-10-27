/*
 * range_facts.h - WHAT ONE BYTE RANGE OF A PARSED ELF OR PE IMAGE LOOKS LIKE, as facts that tell whether it could be code.
 *
 * A caller that wants to know whether a variable, a section tail or a gap could be executed asks about ONE range and gets
 * numbers, not a verdict: who refers to it from the object's own instructions (by kind, counted), how much of it decodes as
 * instructions of the object's architecture and whether one of them is a system call, how random it is, and what shape its
 * bytes have. Any caller can use it (the engine, a diagnose, a tool); it knows nothing about who asks or why.
 *
 *   kgenome_range_xref_build   the reference map of the object's OWN code, built once for any number of ranges. It is the
 *                              xref sweep of celllysis/xref.h fed by the one decoder (kgenome_cell_decode): no second walk.
 *   kgenome_range_facts        the facts of one range, read from the map and the bytes.
 *
 * ADDRESSES. `va` is the address instructions name the range by: an ELF's virtual address, a PE's image base plus RVA.
 *
 * WHAT IS BOUNDED, and says so. The caller's budget (kgenome_budget, from the caller, never from the engine) bounds the work
 * in steps; here a step is one byte read:
 *   - budget.max_steps (zero: KGENOME_RANGE_BYTES) is the most bytes of the RANGE read for entropy, decode and shape. A longer
 *     range is judged by its first bytes, `analysed` says how many, and the status is TRUNCATED (the default bound) or
 *     OVER_BUDGET (the caller's own).
 *   - budget.max_steps for kgenome_range_xref_build is the most bytes of code swept (zero: KGENOME_XREF_MAX); more code is
 *     TRUNCATED and the map is partial. The map itself keeps 512 distinct addresses (celllysis/xref.h): when it is full the
 *     refs of a range are "none SEEN", not "none".
 *   - the data-pointer count reads at most KGENOME_RANGE_PTR_SCAN bytes of the object's non-executable image bytes.
 * Architectures: the reference sweep tracks x86 and x86-64 instructions only (any other answers UNSUPPORTED and no map; the
 * facts then say refs are unknown); decode runs for the architectures kgenome_cell_decode has a decoder for (x86, x86-64,
 * ARM, AArch64, MIPS), `decodes` is 0 for the rest.
 *
 * On a damaged object: a range or an offset outside the file is BAD_INPUT with nothing computed; a size that runs past the
 * end is clipped to the file and counted in `analysed`.
 */
#ifndef KGENOME_CELLLYSIS_RANGE_FACTS_H
#define KGENOME_CELLLYSIS_RANGE_FACTS_H

#include <stdint.h>

#include <kofcore.h>
#include <kgenome_budget.h>
#include <kgenome_status.h>
#include <genotype/image/obj.h>
#include <celllysis/xref.h>

/* The most bytes of a range read when the caller's budget does not say. 8192 is the largest payload the shellcode finder
 * of the examiner looks at (KOFSCFIND_SIZE_MAX); an executable segment may be megabytes, and its first 8 KiB is enough to
 * tell code from a table. */
#define KGENOME_RANGE_BYTES     8192u
/* The most bytes of non-executable image the data-pointer count reads. A whole .data of an ordinary program is under 64 KiB
 * (/bin/ls: 6 KiB); 1 MiB is far above that and costs about 0.1 ms a range. */
#define KGENOME_RANGE_PTR_SCAN  (1u << 20)

/*
 * THE SHAPE of the bytes, decided from the bytes alone; the first rule that holds wins. Thresholds are constants with the
 * measurement that chose them (see range_facts.c); none of them is a verdict about malice.
 */
enum kgenome_range_shape {
	KGENOME_RANGE_EMPTY = 1,     /* every byte the same */
	KGENOME_RANGE_TEXT,          /* printable characters */
	KGENOME_RANGE_RANDOM,        /* entropy near 8 bits a byte: encrypted or compressed */
	KGENOME_RANGE_TABLE,         /* repeating pointer-sized words that are small integers or addresses near each other */
	KGENOME_RANGE_CODE_LIKE,     /* the object's architecture decodes (nearly) all of it, with a control transfer and little junk; on ARM, AArch64 and MIPS only when code refers to it */
	KGENOME_RANGE_MIXED          /* none of those */
};

struct kgenome_range_req {
	const struct kgenome_obj      *obj;      /* a parsed ELF or PE */
	kof_buf                        file;     /* the object's bytes */
	uint64_t                       off;      /* the range: file offset ... */
	uint64_t                       size;     /* ... and length */
	uint64_t                       va;       /* the address instructions name it by (see above) */
	struct kgenome_xref           *xref;     /* from kgenome_range_xref_build; NULL: references are not asked */
	enum kgenome_status            xref_status;   /* that build's status, so a cut map says "partial" */
	const struct kgenome_budget   *budget;   /* NULL: the defaults */
};

struct kgenome_range_facts {
	/* References from the object's instructions, by kind (xref.h): `read` is a load or an address taken, `arg` the address in a
	 * register at a call. Zero when `refs_known` is 0 or when none was seen. */
	struct kgenome_xref_refs refs;
	uint32_t refs_known;     /* a map was given and its sweep ran: the counts mean something */
	uint32_t refs_partial;   /* the map was cut or full: a zero count is "none seen" */
	uint32_t refs_ptr;       /* pointer-sized words in the object's data that hold an address inside the range */
	uint32_t decodes;        /* the architecture has a decoder here */
	uint32_t decode_pct;     /* 0..100: share of the analysed bytes that decode as instructions (a byte that does not is skipped) */
	uint32_t insns, flow, junk;   /* instructions decoded; of them those that transfer control; those of a kind ordinary code rarely uses */
	uint32_t syscall;        /* a system-call instruction decoded: syscall, sysenter, int 0x80, svc */
	uint32_t text_pct, zero_pct;  /* share of printable bytes and of zero bytes, 0..100 */
	uint32_t entropy_centi;  /* Shannon bits a byte times 100, of the analysed bytes (kentropy_hist_centi) */
	uint32_t shape;          /* enum kgenome_range_shape */
	uint64_t analysed;       /* bytes of the range read */
};

/*
 * Build the reference map of the object's own code. Returns KGENOME_OK, TRUNCATED/OVER_BUDGET (more code than the bound, or
 * the map full: partial), UNSUPPORTED (an architecture the sweep does not track: *out is NULL), BAD_INPUT (not a parsed ELF
 * or PE) or NOMEM. The caller frees a non-NULL map with kgenome_xref_free.
 */
enum kgenome_status kgenome_range_xref_build(const struct kgenome_obj *obj, kof_buf file, const struct kgenome_budget *budget,
					     struct kgenome_xref **out);

/* The facts of one range. `*f` is written whole. BAD_INPUT for a range outside the file; otherwise OK, or the cut status. */
enum kgenome_status kgenome_range_facts(const struct kgenome_range_req *rq, struct kgenome_range_facts *f);

#endif /* KGENOME_CELLLYSIS_RANGE_FACTS_H */
