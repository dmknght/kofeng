#ifndef KGENOME_IMAGE_FNTAB_H
#define KGENOME_IMAGE_FNTAB_H

/*
 * fntab.h - THE FUNCTION TABLE OF AN OBJECT, built once, case by case.
 *
 * The product is struct kgenome_func_set (funcs.h): entries (off, len, kind, source, end_source, isa_mode, flags), sorted
 * by off, and the state of the answer (complete / partial and what is missing / over budget). This header is the part
 * that does not need the walk's decode: the TYPES the cases share and the pieces they are made of.
 *
 * CASES ARE DECIDED ONE BY ONE (owner, 2026-11-03: "tự quyết theo từng case, đặc thù từng trường hợp, không phải tự sửa
 * toàn bộ cấu trúc một hàm"). The shape is fixed so that a new case is a new row and a new function, touching none that exists:
 *
 *   1. a PROBE reads cheap metadata of the object into a plain struct (kgenome_fntab_meta), nothing is decoded;
 *   2. the SELECTOR (kgenome_fntab_select) is a pure function of that struct: it answers the case, which strategies run and
 *      which of them only CHECK (their entries that nothing else names are counted, not kept). Tested on its own;
 *   3. each STRATEGY is one function from the object to entries appended to a kgenome_fntab_list, in its own file, with its
 *      own END rule, tests and limits: symtab (funcs.c, the exact one, wrapped and not rewritten), FDE (fntab_fde.c),
 *      .pdata (fntab_pe_pdata.c), the Go table (fntab_elf_gopcln.c), the loader arrays (fntab_elf_initarr.c), .ARM.exidx
 *      (fntab_elf_exidx.c), the PE start tables (export, TLS, CFG / SafeSEH, COFF), the entry point (fntab_entry.c). A strategy
 *      never calls another strategy, and NONE decodes code (owner 2026-11-16: the partition is made from loader/ABI metadata only;
 *      the entry walk, the import stubs and the REACH / GAPS / padding steps are DISABLED, see phenotype/fntab_build.c);
 *   4. the MERGE (fntab_merge.c) is the one place two sources meet: it ranks, drops what lies inside an exact body,
 *      records disagreement, and applies the check-only mask;
 *   5. the ENDS step (fntab_ends.c) gives an entry that no source could close an end from the next start or the end of its code
 *      extent, and every entry its TRUST (funcs.h). An object for which no source gives an entry is one unit of trust NONE per
 *      code extent (fntab_build.c, P_NO_META);
 *   6. PHASE 2, after the table above is made (phenotype/fntab_derive.c): the NONE units are read by one recursive descent from the declared starts
 *      in them, and what it reaches becomes functions of trust DERIVED. It is the one step that decodes; no strategy above does.
 * OPEN CASES (listed, not implemented): the relative relocations that fill a PIE's init array slot; a PE's Go table; DT_INIT / DT_FINI
 * (single pointers, not arrays: not in the design's list); PE of machines other than x86 / x64 / ARM64 / Thumb-2 (their exception tables).
 * THE PE CASES (phase A2) are rows of the same table: a managed image (CLR), x64 with an exception table (PDATA), a COFF symbol table (COFF), x86 / x64
 * with neither (META: the start-only tables), ARM64 / Thumb-2 (ARM) and any other machine (NONE: the start-only tables); see fntab_pe_select.c.
 */

#include <stdint.h>
#include <kofcore.h>
#include "funcs.h"

struct kgenome_elf_info;
struct kgenome_pe_info;

/* A DoS bound, not a table size: the entries of ONE build. A hit is reported (KGENOME_FNTAB_P_CAP, state OVER_BUDGET),
 * never silent. 2^20 entries are 32 MiB (sizeof struct kgenome_func is 32); the largest measured binary holds 7.7e4 functions (exp_fnsize corpus). */
#define KGENOME_FNTAB_MAX (1u << 20)
/* A DoS bound, not a table size: what the derivation's one descent may hold (phase 2, phenotype/fntab_derive.c: five bytes per byte of undeclared code and
 * 32 per instruction read, celllysis/cfg.h). An honest object stays under it by an order of magnitude (a 7 MB stripped static binary holds ~80 MB); a hit is
 * reported (KGENOME_FNTAB_P_DERIVE_CAP, state OVER_BUDGET) and keeps what was read before it. */
#define KGENOME_FNTAB_DERIVE_BYTES (128ull << 20)

/* Entries a strategy appends; the orchestrator owns it. `partial` and `bad` are the strategy's own report. */
struct kgenome_fntab_list {
	struct kgenome_func *v;
	uint32_t n, cap;
	uint16_t partial;               /* KGENOME_FNTAB_P_* the strategy itself knows */
	uint32_t n_bad;                 /* records the strategy refused */
	enum kgenome_status status;     /* KGENOME_NOMEM: the list is short for want of memory */
};

/* Append `f`; 0 when it does not fit (no memory, or KGENOME_FNTAB_MAX: then P_CAP is set). */
int kgenome_fntab_list_add(struct kgenome_fntab_list *l, const struct kgenome_func *f);
void kgenome_fntab_list_free(struct kgenome_fntab_list *l);

/* ---- the selector ---------------------------------------------------------------------------------------------- */

#define KGENOME_FNTAB_X_SYMTAB 0x01u
#define KGENOME_FNTAB_X_DYNSYM 0x02u
#define KGENOME_FNTAB_X_FDE    0x04u
#define KGENOME_FNTAB_X_WALK   0x08u
#define KGENOME_FNTAB_X_PDATA  0x10u
#define KGENOME_FNTAB_X_PE_EXPORT 0x20u
#define KGENOME_FNTAB_X_PE_TLS    0x40u
#define KGENOME_FNTAB_X_PE_COFF   0x80u
#define KGENOME_FNTAB_X_PE_THUNK  0x100u        /* the import stubs the walk decoded (needs the walk) */
#define KGENOME_FNTAB_X_PE_CFG    0x400u        /* the load configuration's function tables (CF targets, safe exception handlers) */
#define KGENOME_FNTAB_X_PE_ARMPDATA 0x800u      /* the exception table of an ARM64 / Thumb-2 image: 8-byte entries, packed or with an xdata record (fntab_pe_pdata_arm.c) */
#define KGENOME_FNTAB_X_PE_REACH  0x200u        /* the REACH step after the merge (needs the walk's trace and padding runs): the end of an entry is the end of what it reaches, and the starts in the gaps behind bodies */
/* (WALK, PE_THUNK and PE_REACH are decode-derived: DISABLED by the owner 2026-11-16, no selector row sets them; see the head of phenotype/fntab_build.c) */
#define KGENOME_FNTAB_X_ENTRY     0x1000u       /* the object's entry point (the header's field): a start, run only when another source named a function (an entry alone does not split an object) */
#define KGENOME_FNTAB_X_INITARR   0x2000u       /* ELF .init_array / .fini_array / .preinit_array (fntab_elf_initarr.c): starts */
#define KGENOME_FNTAB_X_EXIDX     0x4000u       /* ELF ARM .ARM.exidx (fntab_elf_exidx.c): starts */
#define KGENOME_FNTAB_X_GOPCLN    0x8000u       /* the Go function table .gopclntab (fntab_elf_gopcln.c): start and end */

struct kgenome_fntab_meta {
	uint8_t format;         /* KGENOME_FMT_* */
	uint8_t elf_rel;        /* ET_REL: an object file, no loadable segments */
	uint8_t has_symtab;     /* a SHT_SYMTAB of non-zero size */
	uint8_t has_dynsym;     /* a SHT_DYNSYM of non-zero size */
	uint8_t has_unwind;     /* an .eh_frame the strategy can read (section or PT_GNU_EH_FRAME) */
	uint8_t symtab_empty;   /* the orchestrator tried the symbol table and it held no function */
	uint8_t dynsym_empty;   /* the same for .dynsym */
	uint8_t pe_x64_pdata;   /* a PE32+ x64 image with an exception directory */
	uint8_t pe_x86;         /* machine i386 or amd64: the walk decodes it (x86 and x64 are one decoder) */
	uint8_t pe_clr;         /* a CLI header: a managed image */
	uint8_t pe_coff;        /* a COFF symbol table that the file holds (an image from a toolchain that keeps it) */
	uint8_t pdata_empty;    /* the orchestrator read the exception table and it held no function */
	uint8_t coff_empty;     /* the same for the COFF symbols */
	uint8_t pe_nocode;      /* a PE with no executable section that holds a byte of the file */
	uint8_t pe_arm;         /* machine ARM64 (0xaa64) or Thumb-2 (0x1c2, 0x1c4) */
	uint8_t has_initarr;    /* ELF: an .init_array, .fini_array or .preinit_array section, or (no section table) their DT_ tags in PT_DYNAMIC */
	uint8_t has_exidx;      /* ELF: an .ARM.exidx section (SHT_ARM_EXIDX) or a PT_ARM_EXIDX segment */
	uint8_t has_gopcln;     /* ELF: a section named .gopclntab */
};

struct kgenome_fntab_plan {
	uint8_t ccase;          /* enum kgenome_fntab_case */
	uint16_t run;           /* KGENOME_FNTAB_X_*: strategies to run */
	uint16_t check_only;    /* KGENOME_FN_S_* (source bits, as kgenome_fntab_merge reads them): the sources that only CHECK */
};

/* Pure. The decision table is written at the definition (fntab_select.c). */
struct kgenome_fntab_plan kgenome_fntab_select(const struct kgenome_fntab_meta *m);

/* The probe: cheap metadata of an object. `info` is the format's info (struct kgenome_elf_info / kgenome_pe_info). */
void kgenome_fntab_probe(uint32_t format, kof_buf file, const void *info, struct kgenome_fntab_meta *m);

/* ---- the strategies that need no decode ------------------------------------------------------------------------ */

/* The symbol table (`dyn` 0: .symtab, 1: .dynsym) - the exact one: start and END from st_size. */
void kgenome_fntab_symtab(kof_buf file, const struct kgenome_elf_info *e, int dyn, struct kgenome_fntab_list *out);

/* The unwind table (.eh_frame): start and length of every FDE that validates. Read from the section when the object has it,
 * from PT_GNU_EH_FRAME otherwise. Hostile-safe: bounded by the section, every CIE pointer checked, encodings it does not
 * read are counted (out->n_bad), never followed. */
void kgenome_fntab_fde(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out);

/* .pdata of an x64 PE (fntab_pe_pdata.c): RUNTIME_FUNCTION entries with the unwind info checked (version, flags, bounds); a chained entry is a FRAGMENT
 * (kind) of the function it names; an entry that does not validate is counted (out->n_bad, P_BAD_FDE) and refused. Exact start and end. */
void kgenome_fntab_pdata(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The export address table (fntab_pe_export.c): every entry that is an address in a code section, named or by ordinal; a forwarder (an RVA inside the
 * export directory) and a data export are counted in out->n_bad and left out. Starts only. */
void kgenome_fntab_pe_export(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The TLS callbacks (fntab_pe_tls.c): the loader calls them before the entry point. Starts only; the array is bounded (KGENOME_FNTAB_TLS_MAX, said). */
#define KGENOME_FNTAB_TLS_MAX 256u
void kgenome_fntab_pe_tls(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The load configuration's function tables (fntab_pe_cfg.c): the Control Flow Guard target list and, on x86, the safe exception handlers: exact starts, addresses the program takes. */
void kgenome_fntab_pe_cfg(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The COFF symbol table (fntab_pe_coff.c): function-typed symbols with a section number. The length is the aux record's TotalSize when the toolchain wrote
 * one (exact); otherwise the entry has no end (flag SIZE0) and the ends step closes it. */
void kgenome_fntab_pe_coff(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The exception table of an ARM64 / Thumb-2 PE (fntab_pe_pdata_arm.c): see the file. Exact start and end of every function that has an entry. */
void kgenome_fntab_pdata_arm(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out);

/* The ELF loader's arrays of function pointers (fntab_elf_initarr.c): .init_array, .fini_array, .preinit_array - by section, or through PT_DYNAMIC's DT_*_ARRAY / DT_*_ARRAYSZ when
 * the file has no section table. Starts only (source INITARR). A zero or all-ones slot (a PIE's slot the loader fills from a relocation; the old .ctors sentinel) is counted in
 * out->n_bad and not followed: the relocations are not read (limit). */
void kgenome_fntab_initarr(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out);

/* The ARM EHABI index table (fntab_elf_exidx.c): .ARM.exidx by section or PT_ARM_EXIDX. The first word of every 8-byte row is a prel31 offset to the start of a function. Starts only
 * (source EXIDX): the row covers up to the next row's start, which is the table's END rule (the ends step), not a declared size. */
void kgenome_fntab_exidx(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out);

/* The Go function table (fntab_elf_gopcln.c): the section .gopclntab of an ELF, versions 1.2, 1.16, 1.18 and 1.20 of its header. Start and end of every function (end = the entry
 * of the next row, end_source PCTAB: the range the Go runtime looks a PC up in). */
void kgenome_fntab_gopcln(kof_buf file, const struct kgenome_elf_info *e, struct kgenome_fntab_list *out);

/* The object's entry point (fntab_entry.c), `entry_off` the file offset of the header's entry field (kgenome_obj.entry_off; NA and BROKEN are no entry). Source ENTRY, a start.
 * `thumb`: an ARM ELF whose e_entry has bit 0 set: the start is the even offset and isa THUMB. */
void kgenome_fntab_entry(uint64_t entry_off, int thumb, struct kgenome_fntab_list *out);

/* ---- merge and ends -------------------------------------------------------------------------------------------- */

/*
 * THE ONE PLACE TWO SOURCES MEET. `l` holds every strategy's entries (unsorted). Sorts, keeps one function per start and
 * no label inside another body of the same rank, ranks the sources (exact ends before open ones: SYMTAB > PDATA > DYNSYM >
 * FDE > WALK/ENTRY), drops a lower-ranked start that lies inside an exact body, and where two exact sources give one start
 * with different ends keeps the better rank and records it (flag DISAGREE, set->n_disagree). An entry whose only sources
 * are in `check_only` is counted in set->n_extra and not kept. Takes `l->v` (frees it when nothing is kept).
 */
void kgenome_fntab_merge(struct kgenome_fntab_list *l, uint32_t check_only, struct kgenome_func_set *out);   /* check_only: KGENOME_FN_S_* bits */

struct kgenome_fntab_extent { uint64_t at, len; };

/* The run [from, to) of padding instructions (`pad`: the walk's pairs, ascending, `n_pad` of them) that ends exactly at `to`: 1 and `from`, or 0. */
int kgenome_fntab_pad_before(const uint64_t *pad, uint32_t n_pad, uint64_t to, uint64_t *from);

/* A run of padding instructions that starts exactly at `at`: 1 and its start, or 0. */
int kgenome_fntab_pad_at(const uint64_t *pad, uint32_t n_pad, uint64_t at, uint64_t *from);

/* The end an open entry runs to when nothing narrower is known: the next start of the table or the end of the code extent that holds it, whichever is first (the extent is the bound
 * against swallowing the data that follows the code). 0 when `s->v[i]` is in no extent or the bound is not past its start. The ends step and the REACH step read the same bound. */
uint64_t kgenome_fntab_bound(const struct kgenome_func_set *s, uint32_t i, const struct kgenome_fntab_extent *ext, uint32_t n_ext);

/*
 * THE ENDS: every entry an exact source closed is a unit of trust HIGH. An entry whose end no source declared (a start-only table, the
 * entry point, a size-0 symbol) becomes a declared start of the set (round 4: no format declares its end) and its bytes stay in the
 * NONE unit of their gap. `pad` / `n_pad` (the walk's padding runs) are NOT read: the
 * padding trim is DISABLED by the owner 2026-11-16 (decode-derived); the parameters stay for its re-enabling (fntab_ends.c).
 */
void kgenome_fntab_ends(struct kgenome_func_set *s, const struct kgenome_fntab_extent *ext, uint32_t n_ext,
		    const uint64_t *pad, uint32_t n_pad);

#endif /* KGENOME_IMAGE_FNTAB_H */
