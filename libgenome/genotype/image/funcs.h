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
	uint16_t source;        /* KGENOME_FN_S_*: every evidence that named this start (16 bits since 2026-11-16: the metadata-only sources needed three more) */
	uint16_t flags;         /* KGENOME_FN_F_* */
	/* A SCRIPT'S OWN DECLARATION NAME (kgenome_script_funcs_build only - the identifier between
	 * "function" and "(" that the shape match already walks past, captured where it is already
	 * found, no second pass): an (off, len) span into the OBJECT'S OWN BYTES, exactly as
	 * `value`/`shndx` above name a function without holding a copied string either. Zero for
	 * every ELF/PE entry (kof_func_name never reads these unless `kind` is KGENOME_FN_SCRIPT and
	 * the symbol lookup found nothing - there is no symbol lookup for a script anyway) and for a
	 * script entry whose shape match found no name (an anonymous closure, `function (...) {}`,
	 * is valid PHP): kof_func_name then names it `block_<line>` from this entry's own `off`
	 * (sym_any.c, 2026-11-06) - never the binary's own fcn_<offset>, which a script has no
	 * "function" word to imply. */
	uint32_t name_off, name_len;
	/* HOW FAR THE ENTRY CAN BE TRUSTED (enum kgenome_fn_trust; appended 2026-11-16, partition from metadata only): set by the function table's
	 * ends step from where the start and the end came from, and by the derivation (fntab_derive.c) for a function it derived. Zero is "not said" (a caller's own table, a script's). */
	uint8_t trust;
};

/*
 * THE TRUST OF AN ENTRY (owner 2026-11-16: the partition is made from loader/ABI metadata only). One carrier: this field.
 *   HIGH    an exact source declared start AND size (a symbol with a size, an FDE, a .pdata entry, a COFF symbol with an aux size, the Go function table).
 *   (MEDIUM, a start from a table closed at the next start, was removed in round 4: such a start is a DECLARED START of the gap that holds it.)
 *   DERIVED (phase 2, 2026-11-16, fntab_derive.c) a function in code no metadata declares, found by recursive descent from the declared starts of that code: its
 *           start is a declared start (source DERIVED_SEED), the target of a direct call the descent read (DERIVED_CALL) or of a tail jump across other code (DERIVED_JUMP); its extent is the union of the blocks
 *           its entry reaches without entering another function's entry (several ranges when they are not contiguous, kgenome_funcs_range), end_source REACH. Never
 *           HIGH: no format declared it. Flags INCOMPLETE (an indirect jump, or a path that ran out of the code), BROKEN (bytes that do not decode as this path
 *           reads them), ASSUMED_RET (a callee resolved as returning by assumption), SHARED (code another derived function's entry reaches too).
 *   NONE    code no metadata declares and no descent reached: a gap between declared and derived functions (P_UNDECLARED) or, with no metadata at all and no
 *           declared start, the whole extent (P_NO_META); source UNDECLARED. Not a function: it is not split by the entry point or by anything else. A consumer that needs a
 *           function (a frame, a solve, a signature) does not treat it as one.
 */
enum kgenome_fn_trust {
	KGENOME_FN_TRUST_UNSAID = 0,
	KGENOME_FN_TRUST_NONE = 1,
	/* 2 was MEDIUM (a start from a table, end = the next start): REMOVED in round 4 - no format declares that end (design, "Research"); a start-only
	 * source now gives a declared START (kgenome_funcs_starts_in). The value is not reused: HIGH keeps 3 for the readers that print it. Not an ABI
	 * move: the enum is the lib's own (no module or pack carries it). */
	KGENOME_FN_TRUST_HIGH = 3,
	KGENOME_FN_TRUST_DERIVED = 4
};

/* The one spelling of a trust value ("-", "none", "high", "derived"; "?" for a value the enum does not hold, 2 included). */
const char *kgenome_fn_trust_name(uint8_t trust);

/* What a start is. A symbol typed STT_GNU_IFUNC names a RESOLVER, a function whose body is code like any other. */
enum kgenome_fn_kind {
	KGENOME_FN_FUNC = 0,
	KGENOME_FN_IFUNC = 1,
	KGENOME_FN_THUNK = 2,           /* PE: an import stub, `jmp [iat slot]`: a body of its own that no author wrote */
	KGENOME_FN_FRAGMENT = 3,        /* PE x64: a chained unwind entry (a cold part of ANOTHER function): a mask for the merge, never in a finished table */
	KGENOME_FN_SCRIPT = 4           /* a function found in a script's own text (kgenome_script_funcs_build, celllysis): no machine code, no CFG - kgenome_mutation_signature answers WINDOWS for this kind alone, never CFG */
};

/* Where an entry's END comes from. NEXT_START is NOT an establishment of the end: it is the best the evidence allows (flag KGENOME_FN_F_END_OPEN). */
enum kgenome_fn_end {
	KGENOME_FN_E_NONE = 0,          /* not said (a caller's own table) */
	KGENOME_FN_E_SYMBOL = 1,        /* st_size of the symbol: exact by construction */
	KGENOME_FN_E_UNWIND = 2,        /* the length of the FDE / the RUNTIME_FUNCTION: exact */
	KGENOME_FN_E_NEXT_START = 3,    /* the next start, or the end of the code extent */
	KGENOME_FN_E_TRIMMED = 4,       /* the same, less the run of padding instructions in front of the next start */
	KGENOME_FN_E_INSN = 5,          /* the body IS one decoded instruction (an import stub): exact by decode */
	KGENOME_FN_E_REACH = 6,         /* the end of what its entry reaches: inferred, not declared. A DERIVED function (fntab_derive.c): the union of its blocks (its ranges). (The disabled fntab_reach.c used it for PE x86/x64: exact when a switch table in it either had no entry at all or was resolved, and there was no unwind-only block and no data.) */
	KGENOME_FN_E_SCRIPT = 7,        /* the closing brace a script's own declaration shape matched (kgenome_script_funcs_build): exact, unless KGENOME_FN_F_END_OPEN says the input ended first */
	KGENOME_FN_E_PCTAB = 8          /* the Go function table (.gopclntab): the entry of the next row, the range the Go runtime itself looks a PC up in (fntab_elf_gopcln.c): exact by the format */
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
#define KGENOME_FN_S_INITARR 0x100u     /* ELF: an entry of .init_array / .fini_array / .preinit_array (the loader calls it) */
#define KGENOME_FN_S_EXIDX   0x200u     /* ELF ARM: the start of an .ARM.exidx index row (the EHABI unwind index: starts only) */
#define KGENOME_FN_S_GOPCLN  0x400u     /* the Go function table (.gopclntab): entry and end */
#define KGENOME_FN_S_UNDECLARED 0x800u  /* NOT a source: code of an extent that no metadata declares (trust NONE, "not declared by metadata"): a gap between declared functions, or the whole extent of an object with no metadata */
#define KGENOME_FN_S_DERIVED_SEED 0x1000u       /* trust DERIVED: the descent started at this declared start (its own source bits stay beside this one) */
#define KGENOME_FN_S_DERIVED_CALL 0x2000u       /* trust DERIVED: the target of a direct call the descent read */
#define KGENOME_FN_S_DERIVED_JUMP 0x4000u       /* trust DERIVED: the target of a direct unconditional jump across code of something else (a tail call to a function no call names; fntab_derive.c promote_jumps) */
/* A script entry (kind KGENOME_FN_SCRIPT) leaves `source` 0: every bit above names a binary's own
 * evidence (a symbol table, an unwind table, a decode), none of which a script has, and `kind`
 * already says enough - there is exactly one source for a script today. */

#define KGENOME_FN_F_END_OPEN 0x0001u   /* the end is the next start (not established) */
#define KGENOME_FN_F_SIZE0    0x0002u   /* a symbol that names a place and declares no size */
#define KGENOME_FN_F_DISAGREE 0x0004u   /* two sources gave this start and disagree on the end: the entry holds the better-ranked one */
#define KGENOME_FN_F_CLIPPED  0x0008u   /* PE: the declared end lay past the section's raw bytes: the entry ends where the file's bytes do */
#define KGENOME_FN_F_GAP      0x0010u   /* PE: a start made from the first code byte of a gap behind a body (fntab_reach.c, source WALK: the decode saw it); the bytes were checked to be code that ends */
/* What the REACH step could say of an entry whose end no source declared (fntab_reach.c); none of these set means it ended the entry (end_source REACH) */
#define KGENOME_FN_F_REACH_INDIRECT 0x0020u     /* a reachable jump through a register or an indexed table (a switch) that fntab_reach.c's own resolver could NOT resolve against a real table (cfg.h's NAMED LIMITS: no table found, a second hop, a refused read): code behind it may be reached only through the table, so the reached part is a lower bound and the end stays the next start. A RESOLVED switch is not this flag: its case targets are real edges (switch_reach_extend) and the entry's end_source may still be REACH */
#define KGENOME_FN_F_REACH_NONE     0x0040u     /* no graph: the trace holds no decode of the entry, the bytes do not decode, the reached code has undecodable bytes in it, or a bound of cost fired: the end stays the next start */
#define KGENOME_FN_F_REACH_OPEN     0x0080u     /* the reached code runs on into the next start (no terminator before it): the next start may be inside this function, or the call before it does not return */
#define KGENOME_FN_F_NOTYPE        0x0200u     /* ELF: the entry is a NOTYPE symbol with a size (round 3, PMA-3): a NOTYPE declares no function, so its size is not an exact end; an FDE at the same start is (fntab_private.h kgenome_fntab_exact) */
#define KGENOME_FN_F_EVAL_ISLAND    0x0100u     /* kind KGENOME_FN_SCRIPT only: found inside an eval()-literal island (kgenome_script_funcs_build, PHP only) - its off/len are still a span of the OBJECT'S OWN BYTES (the string literal's value), not a copy; the flag only says where the evidence came from */
/* What the descent could not establish about a DERIVED function (fntab_derive.c): */
#define KGENOME_FN_F_INCOMPLETE  0x0400u        /* a block of it ends in an indirect jump (a switch, a tail call through a register) or its path ran out of the code it may read: code reached only that way is not in it */
#define KGENOME_FN_F_BROKEN      0x0800u        /* a path of it runs into bytes that decode as nothing, or into the middle of an instruction another path read */
#define KGENOME_FN_F_ASSUMED_RET 0x1000u        /* it was resolved as RETURNING by assumption: whether it returns depends on a recursion cycle (celllysis/cfg.h, B_ASSUMED) */
#define KGENOME_FN_F_SHARED      0x2000u        /* a block its entry reaches is reached by another derived function's entry too; the block is the one of them with the lower entry */

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

#define KGENOME_FNTAB_P_STARTS 0x01u    /* the sources of the case do not name every function (.dynsym, an unwind table that skips leaves, the start-only loader tables): a function no table declares is missing (inside the entry before it) */
#define KGENOME_FNTAB_P_ENDS   0x02u    /* some ends are the next start (KGENOME_FN_F_END_OPEN): not set since round 4 (a start-only source gives a declared start, not an end) */
#define KGENOME_FNTAB_P_NO_TABLE 0x04u  /* the format has a table for this and the object has none (a PE of a machine the walk does not decode) */
#define KGENOME_FNTAB_P_SYMTAB 0x08u    /* the unwind table names starts the symbol table lacks */
#define KGENOME_FNTAB_P_CAP    0x10u    /* the entry cap fired (KGENOME_FNTAB_MAX) */
#define KGENOME_FNTAB_P_BAD_FDE 0x20u   /* some unwind records were refused (out of range, a bad CIE pointer, an encoding not read; PE: a bad unwind info or range) */
#define KGENOME_FNTAB_P_MANAGED 0x40u   /* a managed (.NET) image: its code is IL and no native function table is defined for it */
#define KGENOME_FNTAB_P_NO_CODE 0x80u   /* the code is not in the file: every executable section of a PE has no raw bytes (the image is built at run time: a packer's output), so the table is empty because there is nothing to read */
#define KGENOME_FNTAB_P_UNDECLARED 0x400u /* "not declared by metadata": n_undeclared runs of code lie between the declared functions and are entries of trust NONE (source UNDECLARED) */
#define KGENOME_FNTAB_P_NO_META 0x200u  /* "no function metadata": the object declares no function anywhere (no symbol, unwind, loader or Go table; the entry point alone does not split it), so each code extent is ONE unpartitioned entry of trust NONE (owner 2026-11-16: no guessing) */
#define KGENOME_FNTAB_P_DERIVE_CAP 0x800u /* a bound of the derivation fired: its memory (KGENOME_FNTAB_DERIVE_BYTES, fntab.h) or its passes of tail-jump promotion (fntab_derive.c): the derived functions are what was read before it, a cut
					   * body is flagged INCOMPLETE, the rest of the undeclared code stays NONE (state OVER_BUDGET) */
#define KGENOME_FNTAB_P_EVAL_SKIP 0x100u /* kgenome_script_funcs_build (PHP): an eval()-literal argument was recognised but NOT followed as a nested island - the recursion depth cap (EVAL_LIT_DEPTH) fired, its own braces did not balance, or an allocation failed; the bytes stay ordinary STRING data, as they were before this feature - never a silent truncation (rule 4) */

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
	KGENOME_FNTAB_C_PE_ARM,         /* ARM64 or Thumb-2: the packed exception table (exact), the exports, the TLS callbacks; the walk does not decode this machine's PE (see fntab_pe_select.c) */
	KGENOME_FNTAB_C_SCRIPT,         /* a script's own declaration shape (kgenome_script_funcs_build, celllysis/script_funcs.c); PHP only today, every other language is C_NONE */
	KGENOME_FNTAB_C_ELF_META,       /* ELF with no exact source: the start-only loader/ABI tables (init/fini arrays, .ARM.exidx, the entry point) */
	KGENOME_FNTAB_C_ELF_GO,         /* ELF with no symbol table and a Go function table (.gopclntab): exact */
	KGENOME_FNTAB_C_PE_META,        /* PE x86 / x64 with no exact source: the start-only tables (exports, TLS callbacks, CF guard / SafeSEH, the entry point) */
	KGENOME_FNTAB_C_NO_META         /* no function metadata at all: one unpartitioned entry of trust NONE per code extent (P_NO_META) */
};
/* (KGENOME_FNTAB_C_ELF_WALK and KGENOME_FNTAB_C_PE_WALK name the cases of the entry walk, DISABLED by the owner 2026-11-16: no selector row answers them; kept so the numbering of the others does not move.) */

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
	/* THE FURTHER RANGES OF A FUNCTION (appended 2026-11-16): a chained .pdata part that does not continue its function's body (a cold part far from it) is a
	 * range of the function its chain roots at. `rng` holds those parts sorted by `off`; `rng_by_fn` the same indices sorted by (fn, off). Range 0 of a
	 * function is its own (off, len). Read them through kgenome_funcs_n_ranges / kgenome_funcs_range; kgenome_funcs_at answers a part's function too. */
	struct kgenome_func_range *rng;
	uint32_t *rng_by_fn;
	uint32_t n_rng;
	struct kgenome_func_start *st;  /* the declared starts (round 4), sorted by off; read through kgenome_funcs_starts_in */
	uint32_t n_st;
	uint32_t n_undeclared;      /* entries of trust NONE made for code no metadata declares (P_UNDECLARED); every byte of a code extent is in one entry */
	uint32_t n_rng_orphan;      /* chained parts whose root is no function of the table (the chain was not resolved, or its root was refused): counted, not kept */
	/* THE DERIVATION (phase 2, appended 2026-11-16, fntab_derive.c) */
	uint32_t n_derive_into_high;        /* direct branch or call targets the descent met inside an exact (HIGH) body and not at its start: dropped */
	uint32_t n_derive_skipped;          /* declared starts in undeclared code that derived nothing: another instruction set (an ARM Thumb start), bytes that are not code, an architecture with no control-flow rules */
};

/* A DECLARED START (round 4): a start-only source named it (entry, init/fini/preinit arrays, exports, TLS, SafeSEH, CF guard, .ARM.exidx, a size-0 or NOTYPE
 * symbol) and no source declared its end. It lies in undeclared code and does not cut it; since phase 2 the descent derives a function from it (trust DERIVED,
 * which then starts there) when its bytes are code it can read, and it stays in a unit of trust NONE otherwise. */
struct kgenome_func_start {
	uint64_t off;
	uint64_t value;             /* the symbol's value and section, when a symbol named it (for its name), else 0 */
	uint16_t shndx;
	uint16_t source;            /* KGENOME_FN_S_* */
	uint8_t isa_mode;           /* enum kgenome_fn_isa (an ARM Thumb start) */
	uint8_t kind;               /* enum kgenome_fn_kind */
};

/* The declared starts inside the first range of entry `i` (a NONE unit; a DERIVED unit, whose own start is one when the descent began there; a HIGH unit
 * holds none, its own start is its sources): their count, and in *first the index of the first in fs->st (sorted by off). 0 for an index out of the set. */
uint32_t kgenome_funcs_starts_in(const struct kgenome_func_set *fs, uint32_t i, uint32_t *first);

struct kgenome_func_range {
	uint64_t off, len;
	uint32_t fn;                /* the index of the function in the set */
};

/* The ranges of function `i`: 1 + its further parts (0 for an index out of the set). Range 0 is v[i].off / v[i].len; range k > 0 is the k-th part by offset.
 * kgenome_funcs_range answers {0, 0, KGENOME_FUNCS_NONE} for a range that does not exist. */
uint32_t kgenome_funcs_n_ranges(const struct kgenome_func_set *fs, uint32_t i);
struct kgenome_func_range kgenome_funcs_range(const struct kgenome_func_set *fs, uint32_t i, uint32_t k);

/* Attach the parts to the set: `parts` (off, len, fn) in any order, `n` of them; takes no ownership. 1, or 0 when memory was refused (the set's status says NOMEM). */
int kgenome_funcs_set_ranges(struct kgenome_func_set *fs, const struct kgenome_func_range *parts, uint32_t n);

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
 *                        answers, as the one the offset is nearest the start of. An offset in no first range but in a further
 *                        range of a function (a chained .pdata part) answers that function.
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
