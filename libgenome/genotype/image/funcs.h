#ifndef KGENOME_IMAGE_FUNCS_H
#define KGENOME_IMAGE_FUNCS_H

/*
 * NOTE ON WHERE THIS LIVES: the function extents are an analysis of the
 * executable and are in libgenome/image; the KSYM block builders that the note
 * below calls "the same step" (sym_any.c, elf_sym.c, pe_sym.c) are the
 * engine's. libkofeng/analyzers/parsers/binaries/funcs.h includes this header
 * and adds the block builder kof_syms_build_grow.
 */

/*
 * funcs.h - the functions an object's symbols name, as file extents.
 *
 * A PRODUCT BESIDE THE SYMBOL BLOCK, built by the same step for the same reason:
 * which format's table feeds it is one decision (sym_any.c), made once, and
 * every consumer reads the result. The diagnose routes, the similarity carve
 * and anything after them used to each walk the symbol table for the functions
 * themselves - three loops growing an array of (address, size), three places
 * for the cap, the zero-size rule and the alias rule to differ.
 *
 * IT IS NOT THE SYMBOL BLOCK, and cannot be read out of it: the block is capped
 * at KOF_SYM_MAX_RECS records as a cost bound, and 24 of 272 measured objects
 * hold more symbols than that - the large static binaries, which are exactly
 * the ones with the most functions. This is built from the table itself, in
 * the file's own coordinates, with no cap but the table's own length.
 *
 * ELF: THE FUNCTIONS OF THE SYM_EXP REGION - the defined symbols the symbol block
 * already separates from the undefined ones. PE: the RUNTIME_FUNCTION table of an
 * x64 image (.pdata), which is the only place a PE states where a function ends
 * - exports carry no size - with the chained fragments left out. A 32-bit PE has
 * no such table, so it has no functions, like a stripped ELF. There is one list:
 * a consumer that wants fewer filters it, the list does not carry a second
 * opinion about which of its entries count.
 *
 * `off` is a FILE offset. A function the segments cannot place, a symbol with no
 * size (it names a place, not a body), and a label inside another body are not
 * listed; two names for one address are one function and the longer extent
 * stands. Sorted by offset. An object with no symbols is an empty set, which is
 * the answer: the functions of a stripped file are not known.
 */

#include <stdint.h>
#include <kofcore.h>
#include "../../kgenome_status.h"

struct kgenome_func {
	uint64_t off, len;
	/* The symbol this function is, as the symbol block records it - its value and
	 * section - so a tool shows the name from the block and not from here. Zero
	 * for a function with no symbol (PE: .pdata names nothing). */
	uint64_t value;
	uint16_t shndx;
	/* WHAT THE ENTRY IS MADE OF (appended: positional initialisers of the fields above still
	 * mean what they meant). Zero is "not said", which is what a table built by a caller
	 * that knows no more than off and len holds. */
	uint8_t kind;           /* enum kgenome_fn_kind */
	uint8_t end_source;     /* enum kgenome_fn_end: where `len` comes from */
	uint8_t isa_mode;       /* enum kgenome_fn_isa: how the body is decoded */
	uint8_t source;         /* KGENOME_FN_S_*: every evidence that named this start */
	uint16_t flags;         /* KGENOME_FN_F_* */
};

/* What a start is. A symbol typed STT_GNU_IFUNC names a RESOLVER, a function whose body is code like any other. */
enum kgenome_fn_kind {
	KGENOME_FN_FUNC = 0,
	KGENOME_FN_IFUNC = 1,
	KGENOME_FN_THUNK = 2,           /* PE: an import stub, `jmp [iat slot]`: a body of its own that no author wrote */
	KGENOME_FN_FRAGMENT = 3         /* PE x64: a chained unwind entry (a cold part of ANOTHER function): a mask for the merge, never in a finished table */
};

/* Where an entry's END comes from. NEXT_START is NOT an establishment of the end: it is the best the evidence allows (flag KGENOME_FN_F_END_OPEN). */
enum kgenome_fn_end {
	KGENOME_FN_E_NONE = 0,          /* not said (a caller's own table) */
	KGENOME_FN_E_SYMBOL = 1,        /* st_size of the symbol: exact by construction */
	KGENOME_FN_E_UNWIND = 2,        /* the length of the FDE / the RUNTIME_FUNCTION: exact */
	KGENOME_FN_E_NEXT_START = 3,    /* the next start, or the end of the code extent */
	KGENOME_FN_E_TRIMMED = 4,       /* the same, less the run of padding instructions in front of the next start */
	KGENOME_FN_E_INSN = 5,          /* the body IS one decoded instruction (an import stub): exact by decode */
	KGENOME_FN_E_REACH = 6          /* the end of the last block its entry reaches (PE x86/x64, fntab_reach.c): inferred, not declared; exact when the code has no switch table, no unwind-only block and no data */
};

enum kgenome_fn_isa {
	KGENOME_FN_ISA_DEFAULT = 0,
	KGENOME_FN_ISA_THUMB = 1        /* ARM: the symbol had bit 0 set; `off` is the even address */
};

/* The evidence that named a start. Several bits when several agree. */
#define KGENOME_FN_S_SYMTAB 0x01u
#define KGENOME_FN_S_DYNSYM 0x02u
#define KGENOME_FN_S_FDE    0x04u
#define KGENOME_FN_S_WALK   0x08u       /* a direct call target or a `jmp X` thunk the walk's decode found */
#define KGENOME_FN_S_ENTRY  0x10u       /* the object's entry point */
#define KGENOME_FN_S_PDATA  0x20u
#define KGENOME_FN_S_EXPORT 0x40u       /* PE: an entry of an address table the image declares: the export address table, the load configuration's call-target and handler lists */
#define KGENOME_FN_S_COFF   0x80u       /* PE: a function symbol of the COFF symbol table */
/* (the TLS callbacks are loader entry points like the image entry: KGENOME_FN_S_ENTRY) */

#define KGENOME_FN_F_END_OPEN 0x0001u   /* the end is the next start (not established) */
#define KGENOME_FN_F_SIZE0    0x0002u   /* a symbol that names a place and declares no size */
#define KGENOME_FN_F_DISAGREE 0x0004u   /* two sources gave this start and disagree on the end: the entry holds the better-ranked one */
#define KGENOME_FN_F_CLIPPED  0x0008u   /* PE: the declared end lay past the section's raw bytes: the entry ends where the file's bytes do */
#define KGENOME_FN_F_GAP      0x0010u   /* PE: a start made from the first code byte of a gap behind a body (fntab_reach.c, source WALK: the decode saw it); the bytes were checked to be code that ends */
/* What the REACH step could say of an entry whose end no source declared (fntab_reach.c); none of these set means it ended the entry (end_source REACH) */
#define KGENOME_FN_F_REACH_INDIRECT 0x0020u     /* a reachable jump through a register or an indexed table (a switch): code behind it may be reached only through the table, so the reached part is a lower bound and the end stays the next start */
#define KGENOME_FN_F_REACH_NONE     0x0040u     /* no graph: the trace holds no decode of the entry, the bytes do not decode, the reached code has undecodable bytes in it, or a bound of cost fired: the end stays the next start */
#define KGENOME_FN_F_REACH_OPEN     0x0080u     /* the reached code runs on into the next start (no terminator before it): the next start may be inside this function, or the call before it does not return */

/*
 * HOW COMPLETE THE ANSWER IS, as a value (never a silent "none"): COMPLETE means the sources the object has were read to
 * the end and nothing the object declares is missing from the table; PARTIAL says what is missing (`partial` bits);
 * OVER_BUDGET says a bound of cost cut the table (KGENOME_FNTAB_P_CAP in `partial`).
 */
enum kgenome_fntab_state {
	KGENOME_FNTAB_COMPLETE = 0,
	KGENOME_FNTAB_PARTIAL = 1,
	KGENOME_FNTAB_OVER_BUDGET = 2
};

#define KGENOME_FNTAB_P_STARTS 0x01u    /* starts are call targets only: a function nothing calls directly is missing */
#define KGENOME_FNTAB_P_ENDS   0x02u    /* some ends are the next start (KGENOME_FN_F_END_OPEN) */
#define KGENOME_FNTAB_P_NO_TABLE 0x04u  /* the format has a table for this and the object has none (a PE of a machine the walk does not decode) */
#define KGENOME_FNTAB_P_SYMTAB 0x08u    /* the unwind table names starts the symbol table lacks */
#define KGENOME_FNTAB_P_CAP    0x10u    /* the entry cap fired (KGENOME_FNTAB_MAX) */
#define KGENOME_FNTAB_P_BAD_FDE 0x20u   /* some unwind records were refused (out of range, a bad CIE pointer, an encoding not read; PE: a bad unwind info or range) */
#define KGENOME_FNTAB_P_MANAGED 0x40u   /* a managed (.NET) image: its code is IL and no native function table is defined for it */
#define KGENOME_FNTAB_P_NO_CODE 0x80u   /* the code is not in the file: every executable section of a PE has no raw bytes (the image is built at run time: a packer's output), so the table is empty because there is nothing to read */

/* The case the selector chose (fntab.h): which sources the object has and which strategies read them. */
enum kgenome_fntab_case {
	KGENOME_FNTAB_C_NONE = 0,       /* not an ELF/PE image, or invalid */
	KGENOME_FNTAB_C_ELF_SYMTAB,
	KGENOME_FNTAB_C_ELF_DYNSYM,
	KGENOME_FNTAB_C_ELF_FDE,
	KGENOME_FNTAB_C_ELF_WALK,
	KGENOME_FNTAB_C_PE_PDATA,
	KGENOME_FNTAB_C_PE_NONE,
	KGENOME_FNTAB_C_PE_CLR,         /* managed image */
	KGENOME_FNTAB_C_PE_COFF,        /* no exception table, a COFF symbol table with functions */
	KGENOME_FNTAB_C_PE_WALK,        /* x86 / x64 with neither: the walk, the exports, the TLS callbacks */
	KGENOME_FNTAB_C_PE_NOCODE,      /* no executable section holds a byte of the file: nothing to table (P_NO_CODE) */
	KGENOME_FNTAB_C_PE_ARM          /* ARM64 or Thumb-2: the packed exception table (exact), the exports, the TLS callbacks; the walk does not decode this machine's PE (see fntab_pe_select.c) */
};

struct kgenome_func_set {
	struct kgenome_func *v;     /* malloc'd; NULL when n is zero */
	uint32_t n;
	/* KGENOME_OK, or KGENOME_NOMEM: short for want of memory, not for want of
	 * functions. (It was `int oom`; a status says the same thing in the lib's
	 * one vocabulary, and nothing else in this table is capped.) */
	enum kgenome_status status;
	/* THE FUNCTION TABLE'S OWN STATE (appended; a zeroed set reads COMPLETE / C_NONE). */
	uint8_t ccase;              /* enum kgenome_fntab_case */
	uint8_t state;              /* enum kgenome_fntab_state */
	uint16_t partial;           /* KGENOME_FNTAB_P_* */
	uint32_t n_disagree;        /* starts two sources gave with different ends */
	uint32_t n_extra;           /* starts a source named that the table does not carry (a check only, or inside a body) */
};

/* The one decision about which format's symbols feed it - see kof_syms_build. */
void kgenome_funcs_build(uint32_t format, const uint8_t *data, uint64_t data_n,
		     const void *info, struct kgenome_func_set *out);

void kgenome_funcs_free(struct kgenome_func_set *s);

/*
 * THE ONE LOOKUP IN THE TABLE (O(log n) over the entries, which are sorted by `off`). Every consumer that asks "which function
 * holds this offset" or "which function starts here" asks these two; five private copies of the question (the lineage, the sweep,
 * the code notes, the CFG view, the viewer's disassembly) were measured to disagree on overlapping extents.
 *
 *   kgenome_funcs_at     the index of the function whose extent holds file offset `off`, or KGENOME_FUNCS_NONE. When two kept
 *                        extents overlap without one holding the other (the merge keeps both), the one that ends first
 *                        answers, as the one the offset is nearest the start of.
 *   kgenome_funcs_start  the index of the function that STARTS at `off` (the merge keeps one per start), or KGENOME_FUNCS_NONE.
 *
 * `fs` may be NULL (answers NONE).
 */
#define KGENOME_FUNCS_NONE UINT32_MAX
uint32_t kgenome_funcs_at(const struct kgenome_func_set *fs, uint64_t off);
uint32_t kgenome_funcs_start(const struct kgenome_func_set *fs, uint64_t off);

/*
 * THE FUNCTIONS OF A VIEW, from the object it is a view of.
 *
 * A normalised view is its parent with padding collapsed and the static
 * library moved to the tail, so its headers cannot name the functions - and
 * the functions themselves are untouched: measured over 40 Mirai samples,
 * 5067 of 5076 unit extents (99.82%) are byte-identical in the view, and the
 * nine that are not each hold a zero run the collapse shortened. So each
 * function of the parent is looked for, as bytes, in the view - forward from
 * where the last one was found, since the view keeps the order, and only a
 * little way (the library was cut out, not shuffled). A function not found
 * there is not in the set: the library's, or one the collapse rewrote.
 * Offsets are the view's. `value` and `shndx` come along so a tool still
 * names it.
 */
void kgenome_funcs_remap(const uint8_t *par, uint64_t par_n,
		     const struct kgenome_func_set *pf, const uint8_t *view,
		     uint64_t view_n, struct kgenome_func_set *out);

/*
 * The same, for a view whose byte order was changed (endian.h): each function is
 * looked for as the plan leaves it. A function that straddles nothing the plan
 * claims is found exactly as in kgenome_funcs_remap.
 */
struct kgenome_endian_plan;
void kgenome_funcs_remap_endian(const uint8_t *par, uint64_t par_n,
			    const struct kgenome_func_set *pf,
			    const struct kgenome_endian_plan *plan, const uint8_t *view,
			    uint64_t view_n, struct kgenome_func_set *out);


/*
 * The builder of the PE format, which kgenome_funcs_build chooses (the ELF one is kgenome_fntab_symtab, fntab.h):
 * the RUNTIME_FUNCTION table of an x64 image.
 */
struct kgenome_pe_info;
void kgenome_pe_funcs_build(kof_buf file, const struct kgenome_pe_info *p,
			struct kgenome_func_set *out);

#endif /* KGENOME_IMAGE_FUNCS_H */
