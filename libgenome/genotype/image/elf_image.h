/*
 * elf_image.h - the structure of an ELF, as libgenome reads it.
 *
 * The body of what elf_parse.h declared: the parse, the symbol table reader,
 * the import / relocation walks and the address translation. The scan-region
 * partition and the names for tools stay with the engine (elf_parse.h), which
 * includes this header, so every name below is still reachable from there.
 * The original notes follow, with the declarations they describe.
 */

#ifndef KGENOME_IMAGE_ELF_IMAGE_H
#define KGENOME_IMAGE_ELF_IMAGE_H

#include <genotype/image/elf_types.h>
#include <genotype/image/obj.h>
#include <kofcore.h>
#include "../../kgenome_status.h"

/*
 * p_type of the segment that MAPS, which is the only kind an address can be
 * resolved through.
 *
 * Here rather than in elf_parse.c because a second reader appeared: the
 * disinfect stage turns a saved entry point back into a file offset and needs
 * the same test the parser makes - see kgenome_image_addr_to_off. The value is the
 * ELF standard's; what must not be duplicated is the DECISION that this is
 * the segment kind to walk.
 */
#define KGENOME_ELF_PT_LOAD 1u

/* A segment that maps file bytes: PT_LOAD with a file half. .bss-only and
 * non-loadable segments are not one. The ONE spelling of the test every
 * translation and every walk over the mapped file applies. */
static inline int kgenome_elf_seg_is_load(const struct kgenome_elf_seg *g)
{
	return g->type == KGENOME_ELF_PT_LOAD && g->file_size != 0;
}

/* The section types and flags the engine side reads as well. The ELF
 * standard's values; here so that the partition and the parse test the same
 * constants. */
#define KGENOME_ELF_SHT_NULL	0
#define KGENOME_ELF_SHT_PROGBITS 1
/* SHT_DYNSYM is the linked object's symbol table, SHT_SYMTAB the one a
 * relocatable object keeps; the table walkers read both and the relocations
 * that name their entries. */
#define KGENOME_ELF_SHT_SYMTAB	2
#define KGENOME_ELF_SHT_STRTAB	3
#define KGENOME_ELF_SHT_RELA	4
#define KGENOME_ELF_SHT_NOBITS	8
#define KGENOME_ELF_SHT_REL	9
#define KGENOME_ELF_SHT_DYNSYM	11
#define KGENOME_ELF_SHF_WRITE	0x1
/* SHF_ALLOC is the one that decides whether a section becomes part of the
 * process image, which is what separates KGENOME_SCAN_ELF_NOLOAD from the rest:
 * .comment, .debug_* and .symtab are all kept in the file without it. */
#define KGENOME_ELF_SHF_ALLOC	0x2
#define KGENOME_ELF_SHF_EXEC	0x4
/* SHN_UNDEF as a section index: no section (as a shstrndx, no name table). */
#define KGENOME_ELF_SHN_UNDEF	0
/* p_flags bits */
#define KGENOME_ELF_PF_X	1
#define KGENOME_ELF_PF_W	2
#define KGENOME_ELF_PF_R	4

/*
 * The parse itself: the body of kof_elf_parse (elf_parse.h), which calls this
 * and then attaches the engine's region resolver. Same contract - see there.
 * It sets obj->obj_size, entry_off, arch, subtype, format and file_header,
 * and does not touch the engine's region resolver (the adapter owns it).
 */
int kgenome_elf_image_parse(kof_buf file, struct kgenome_elf_info *info,
			struct kgenome_obj *obj);

/*
 * ---- THE TABLES, WALKED ON DEMAND -----------------------------------------
 *
 * The parse fills a FIXED view: the facts every caller needs, that cost
 * nothing to carry. Imports, relocations and function symbols are none of
 * those - an object has hundreds of each and most objects are never asked -
 * so they are walked when somebody asks, and each entry is handed to a
 * visitor rather than written into an array the caller had to size.
 *
 * WHY THEY LIVE HERE AT ALL. They were in the chain detector for several
 * revisions: five hundred lines of directory walking, r_info unpacking and
 * string reading, sitting next to the vocabulary that interprets the result -
 * and calling back into this file for section bounds while it did. kofexamine
 * had grown a third reader of the same tables.
 *
 * THE LINE IS NAME AND ADDRESS versus MEANING. These answer "what is called,
 * and from where". What `commit_creds` MEANS is a vocabulary, and belongs to
 * whoever is detecting; a parser that knew about capabilities would be a
 * parser nobody else could call.
 *
 * WHY A VISITOR AND NOT AN OUT ARRAY. The caller filters - the sweep kept the
 * one import in fifty it has a word for - so an array would have to be sized
 * for every entry in the file to deliver the few that matter, and an array
 * that fills up drops entries by position in the file rather than by what the
 * caller wanted. The visitor has no size to get wrong.
 *
 * Each returns how many entries it reported.
 */

/*
 * ---- ONE READER FOR THE SYMBOL TABLE --------------------------------------
 *
 * Elf64_Sym is name,info,other,shndx,value,size and Elf32_Sym is
 * name,value,size,info,other,shndx: the same six fields in two orders, at two
 * widths, in either endianness. That is twelve ways to spell one record, and
 * it had been written out three times - once to build the KSYM block, once to
 * find function boundaries, once to read a relocation's symbol.
 *
 * This is the only place that knows the layout. What a caller does with a
 * symbol is its own business: the KSYM encoding, the printable-character
 * policy and the `_start` search all stayed in elf_sym.c, because none of
 * them is a fact about ELF.
 */
enum kgenome_elf_symtab_want {
	KGENOME_ELF_SYMTAB_BEST = 0,    /* .symtab, or .dynsym when stripped */
	KGENOME_ELF_SYMTAB_FULL = 1,    /* .symtab only                      */
	KGENOME_ELF_SYMTAB_DYN  = 2     /* .dynsym only                      */
};

/*
 * Where a table is, in the file's own numbers.
 *
 * `n` is how many records the FILE HOLDS and `n_decl` how many sh_size
 * CLAIMS. They differ on a truncated or hostile object, and both are
 * reported because they answer different questions: walk to `n`, and say the
 * block was cut short when `n_decl` is larger.
 *
 * `strn` IS ZERO WHEN THE STRING SECTION IS GONE, and the table is still
 * returned. A caller that wants names must test it; a caller that wants
 * addresses, sizes or types does not need to care.
 */
struct kgenome_elf_symtab {
	uint64_t off, n, n_decl;
	uint64_t str, strn;         /* the string table, unclipped       */
	uint32_t recsize;
	uint8_t  elf64, be;
	uint8_t  origin;            /* kof_sym_origin's numbering        */
	/*
	 * An ELF64 MIPS object, whose relocation record is not the class's: r_info is
	 * a 32-bit symbol index then FOUR BYTES (r_ssym, r_type3, r_type2, r_type),
	 * the same bytes in either byte order - so read as one 64-bit word it gives
	 * the right symbol in a big-endian object and the type where the symbol is
	 * in a little-endian one. APPENDED.
	 */
	uint8_t  mips64;
};

int kgenome_elf_symtab_of(kof_buf f, const struct kgenome_elf_info *p,
		      enum kgenome_elf_symtab_want want,
		      struct kgenome_elf_symtab *t);

/* One record, in the order and width this file was built with. Zero when it
 * could not be read whole, which ends a walk. */
struct kgenome_elf_symbol {
	uint64_t value, size;
	uint32_t nameoff;
	uint16_t shndx;
	uint8_t  info, other;
};

int kgenome_elf_symbol_at(kof_buf f, const struct kgenome_elf_symtab *t, uint64_t i,
		      struct kgenome_elf_symbol *s);

/* How much of a symbol's name is reported. A name longer than this is cut, not skipped, and the
 * cut is REPORTED (kgenome_elf_relcalls' status): it was 64 and silent, which made a long
 * mangled import look like a different symbol. */
#define KGENOME_SYMNAME_MAX 4096u

/*
 * A CALL RELOCATION IN A RELOCATABLE OBJECT, which is what a loadable kernel
 * module is. A .ko has no dynamic section, no GOT and no PLT - what it has is
 * `.rela.text` against `.symtab`.
 *
 * `at` is the address a DECODER will compute for the branch. An unlinked call
 * has a hole where its displacement goes, so its target reads as the next
 * instruction - which is the only address the two sides can agree on without
 * the caller knowing the encoding.
 *
 * `target` is non-zero when the symbol is one this object DEFINES: the call is
 * internal, and that is where it goes. Zero when the symbol is undefined, and
 * then `name` is all that is known about it.
 */
typedef void (*kgenome_elf_relcall_fn)(void *user, uint64_t at, uint64_t target,
				   const char *name);


/*
 * EVERY RELOCATION OF A RELOCATABLE OBJECT, DERIVED ONCE AND KEPT.
 *
 * A relocation says which SYMBOL an instruction's operand really names, which
 * is the only way to know that `mov rdi, 0x0` is `&__this_module->list`: the
 * bytes in the file are a hole, and the name is in the relocation beside them.
 * It also says what to patch into an image that has to RUN. Three readers need
 * it - the gate that asks whether the code refers into a symbol, the walk that
 * gives a register the name its operand stood for, and the builder of an
 * emulated image - and they used to walk the relocation sections of the same
 * object one each, with a bound of their own in two of them. The table is the
 * one derivation; it is built once per object and read by all of them.
 *
 * SORTED BY `where`, so "the relocation inside this instruction" is a binary
 * search and not a scan of every record per decoded instruction.
 *
 * NOT CAPPED. The table is as long as the object's relocation sections are,
 * which the file's own size bounds; a limit on the RESULT is a limit on
 * evidence. (One of the consumers carried a 512-record limit and quietly
 * dropped every relocation after that - the clean corpus has modules with
 * hundreds of thousands.)
 *
 * `where` is the file offset of the bytes to patch, `sym` the file offset the
 * symbol resolves to and `defined` whether it resolves here at all. `nameoff`
 * is the file offset of the symbol's NAME, or zero when it has none - an
 * offset and not the string, because the string is already in the buffer the
 * caller handed in. `code` says whether the section patched holds code: a call
 * or a load of an address, as against a function pointer in a table or the name
 * a probe object carries. RELA only: a REL section carries no addend, and a
 * caller applying a relocation needs one.
 *
 * It used to be one filter, silently, and the filter was "the target is
 * executable". That made every pointer in .data and .rodata vanish from an
 * emulated image: a struct kprobe the object fills in statically read back as
 * zeros, and the name inside it with it. Both kinds are kept and say which
 * they are; a reader takes the kind it wants.
 */
struct kgenome_elf_reloc {
	uint64_t where;
	uint64_t sym;
	uint64_t nameoff;
	int64_t  addend;
	uint32_t type;
	uint8_t  defined;
	uint8_t  code;
	uint8_t  call;          /* the relocation a call compiles to - see
				 * kgenome_elf_relcalls */
};

struct kgenome_elf_relocs {
	struct kgenome_elf_reloc *v;
	uint32_t              n;
	/* APPENDED. KGENOME_OK, or KGENOME_NOMEM when the table could not be allocated:
	 * `n` is then zero and that is "could not build", not "no relocations". A
	 * caller that folds the answer into a scan notes it (kgenome_diag_note). */
	enum kgenome_status   status;
};

/*
 * WHICH KINDS. A reader that wants the symbol an INSTRUCTION's operand names
 * wants the first and would be handed, and would sort, thousands of table
 * entries it cannot use by the second; a builder of a runnable image needs
 * both. MEASURED on 100 kernel modules, building both kinds for every object
 * put 9.6% on the whole scan, nearly all of it data relocations that the gate
 * and the symbol walk never read. So the kinds are asked for, and each is built
 * by the first reader that needs it and by no one else.
 */
#define KGENOME_ELF_RELOC_CODE 1u
#define KGENOME_ELF_RELOC_DATA 2u

/* Build the table for `p`, of the kinds in `want`. Returns the record count;
 * zero with `out` empty when the object has no RELA relocations of those kinds
 * or no symbol table to name them by. */
uint32_t kgenome_elf_reloc_table(kof_buf f, const struct kgenome_elf_info *p,
			     unsigned want, struct kgenome_elf_relocs *out);
void     kgenome_elf_reloc_table_free(struct kgenome_elf_relocs *t);

/*
 * THE CALL SITES of a relocatable object, read out of its CODE table and not
 * out of the file again: the sites are the records flagged `call`, which the
 * builder decided once, in order of `where`. None for a table built without
 * KGENOME_ELF_RELOC_CODE.
 *
 * `at` is kgenome_elf_reloc_call_at. `target` is non-zero when the symbol is one
 * this object DEFINES: the call is internal, and that is where it goes (a file
 * offset). Zero when the symbol is undefined, and then `name` is all that is
 * known about it. Returns how many it reported. `status`, when not NULL, is KGENOME_TRUNCATED
 * when a name was longer than KGENOME_SYMNAME_MAX and was handed over cut.
 *
 * RELA ONLY, like the table. It used to walk SHT_REL sections as well, which
 * is how an i386 or ARM module's relocations are written; its two callers both
 * return before this for anything but x86-64, whose psABI has no REL form.
 */
uint32_t kgenome_elf_relcalls(kof_buf f, const struct kgenome_elf_info *p,
			  const struct kgenome_elf_relocs *t,
			  kgenome_elf_relcall_fn fn, void *user,
			  enum kgenome_status *status);

/*
 * The CODE relocation, with a name, whose patched bytes lie inside the
 * instruction at [at, at+len) - or NULL. A call's own relocation patches the
 * displacement inside the branch and is found like any other; a caller that
 * does not want a branch target read as a loaded address looks at the operand.
 */
const struct kgenome_elf_reloc *kgenome_elf_reloc_in(const struct kgenome_elf_relocs *t,
					     uint64_t at, uint8_t len);

/*
 * An address a LINKED object is read at, as the file offset holding it.
 *
 * Through the loadable segments' FILE halves, so what the file does not hold
 * (.bss) is not placed, and an extent that runs past the half it starts in is
 * refused rather than clipped. One translation: the library finder and the
 * function list both place a symbol by it, and two copies of "which segment" are
 * two sets of rules that drift.
 */
int kgenome_elf_va_to_off(const struct kgenome_elf_info *e, uint64_t va, uint64_t sz,
		      uint64_t *off);

const struct kgenome_elf_seg *kgenome_elf_load_at_off(const struct kgenome_elf_info *e,
						  uint64_t off);

/*
 * Does this object look like ELF at all?
 *
 * Magic only, and deliberately separate from the parse: identifying an object
 * must not need the view buffer, because the view is what gets allocated once the
 * format is known. Reading four bytes to decide is what keeps a scanner that only
 * ever sees one format from carrying every other format's view.
 */
int kgenome_elf_sniff(kof_buf file);

#endif /* KGENOME_IMAGE_ELF_IMAGE_H */
