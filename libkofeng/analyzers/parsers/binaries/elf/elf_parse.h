/*
 * elf_parse.h - ELF collector entry point.
 *
 * Fills both tiers in one call: the common scan context and the ELF specific
 * view. Keeping it in one function means one place knows how an ELF fact maps
 * onto a common one - e_machine to kof_arch, e_entry to entry_off - instead of
 * that mapping being duplicated by every caller.
 *
 * Handles ELF32 and ELF64, little and big endian, and never fails: on hostile
 * or truncated input it reports what it recovered plus an anomaly bitmask.
 */

#ifndef KOFENG_ELF_PARSE_H
#define KOFENG_ELF_PARSE_H

#include <kofmod/elf.h>
#include <kofmod/kofsig.h>
#include "../../../../kofcore/kofcore.h"

/*
 * p_type of the segment that MAPS, which is the only kind an address can be
 * resolved through.
 *
 * Here rather than in elf_parse.c because a second reader appeared: the
 * disinfect stage turns a saved entry point back into a file offset and needs
 * the same test the parser makes - see kof_pz_addr_to_off. The value is the
 * ELF standard's; what must not be duplicated is the DECISION that this is
 * the segment kind to walk.
 */
#define KOF_ELF_PT_LOAD 1u

/*
 * Returns non-zero if the object is ELF at all (magic matched), zero otherwise.
 *
 * On a non-zero return, ctx->fmt points at info and ctx->format is
 * KOF_FMT_ELF. A non-zero return does not mean the facts are complete: check
 * info->anomalies. On a zero return both structs are zeroed and safe to read,
 * ctx->fmt is NULL, and ctx->format is left KOF_FMT_UNKNOWN for whoever
 * identifies the object next.
 *
 * ctx->src_type is not set here: only the caller knows where the bytes came
 * from.
 */
int kof_elf_parse(kof_buf file, struct kof_elf_info *info,
		  struct kof_obj_ctx *ctx);

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
enum kof_elf_symtab_want {
	KOF_ELF_SYMTAB_BEST = 0,    /* .symtab, or .dynsym when stripped */
	KOF_ELF_SYMTAB_FULL = 1,    /* .symtab only                      */
	KOF_ELF_SYMTAB_DYN  = 2     /* .dynsym only                      */
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
struct kof_elf_symtab {
	uint64_t off, n, n_decl;
	uint64_t str, strn;         /* the string table, unclipped       */
	uint32_t recsize;
	uint8_t  elf64, be;
	uint8_t  origin;            /* kof_sym_origin's numbering        */
};

int kof_elf_symtab_of(kof_buf f, const struct kof_elf_info *p,
		      enum kof_elf_symtab_want want,
		      struct kof_elf_symtab *t);

/* One record, in the order and width this file was built with. Zero when it
 * could not be read whole, which ends a walk. */
struct kof_elf_symbol {
	uint64_t value, size;
	uint32_t nameoff;
	uint16_t shndx;
	uint8_t  info, other;
};

int kof_elf_symbol_at(kof_buf f, const struct kof_elf_symtab *t, uint64_t i,
		      struct kof_elf_symbol *s);

/* How much of a symbol's name is reported. A name longer than this is cut,
 * not skipped: every caller so far compares against known words, and the
 * longest in the kernel ABI is nowhere near it. */
#define KOF_SYMNAME_MAX 64u

/* An address, and the name of whatever the object expects to be there. The
 * string is borrowed for the duration of the call: copy what you keep. */
typedef void (*kof_elf_name_fn)(void *user, uint64_t addr, const char *name);

/*
 * THE DYNAMIC IMPORTS.
 *
 * A GLOB_DAT or JUMP_SLOT relocation says "this slot will hold that symbol",
 * which is the promise the code was compiled against, and nothing needs the
 * dynamic linker to have run.
 *
 * AND THEN THE PLT STUBS, because a compiler calls the STUB and not the slot.
 * Both are reported, with the stub carrying the name of the slot it jumps
 * through, so a caller that resolved an address to either one gets an answer
 * without having to know which spelling of PLT the build used.
 */
uint32_t kof_elf_imports(kof_buf f, const struct kof_elf_info *p,
			 kof_elf_name_fn fn, void *user);

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
typedef void (*kof_elf_relcall_fn)(void *user, uint64_t at, uint64_t target,
				   const char *name);

uint32_t kof_elf_relcalls(kof_buf f, const struct kof_elf_info *p,
			  kof_elf_relcall_fn fn, void *user);

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
struct kof_elf_reloc {
	uint64_t where;
	uint64_t sym;
	uint64_t nameoff;
	int64_t  addend;
	uint32_t type;
	uint8_t  defined;
	uint8_t  code;
};

struct kof_elf_relocs {
	struct kof_elf_reloc *v;
	uint32_t              n;
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
#define KOF_ELF_RELOC_CODE 1u
#define KOF_ELF_RELOC_DATA 2u

/* Build the table for `p`, of the kinds in `want`. Returns the record count;
 * zero with `out` empty when the object has no RELA relocations of those kinds
 * or no symbol table to name them by. */
uint32_t kof_elf_reloc_table(kof_buf f, const struct kof_elf_info *p,
			     unsigned want, struct kof_elf_relocs *out);
void     kof_elf_reloc_table_free(struct kof_elf_relocs *t);

/*
 * The CODE relocation, with a name, whose patched bytes lie inside the
 * instruction at [at, at+len) - or NULL. A call's own relocation patches the
 * displacement inside the branch and is found like any other; a caller that
 * does not want a branch target read as a loaded address looks at the operand.
 */
const struct kof_elf_reloc *kof_elf_reloc_in(const struct kof_elf_relocs *t,
					     uint64_t at, uint8_t len);

/* Where each function begins and how long it is, as the symbol table states
 * it. A function nothing calls can be found no other way. */
typedef void (*kof_elf_func_fn)(void *user, uint64_t va, uint64_t size,
				const char *name);

uint32_t kof_elf_funcs(kof_buf f, const struct kof_elf_info *p,
		       kof_elf_func_fn fn, void *user);

/*
 * Does this object look like ELF at all?
 *
 * Magic only, and deliberately separate from the parse: identifying an object
 * must not need the view buffer, because the view is what gets allocated once the
 * format is known. Reading four bytes to decide is what keeps a scanner that only
 * ever sees one format from carrying every other format's view.
 */
int kof_elf_sniff(kof_buf file);

/* Names for the region and anomaly bits. See the note in pe_parse.h: a module
 * cannot print, so these are for tools and live on the internal side. */
const char *kof_elf_region_name(uint32_t bit);
const char *kof_elf_anomaly_name(unsigned index);

/*
 * Every region bit the format defines, in bit order.
 *
 * Exported because three separate callers had each written this list out by hand -
 * the examiner, the partition test and the fuzzer - and a list written three times
 * is a list where adding a region silently stops it being dumped and stops it being
 * checked. The same shape of copy in the signature compiler once made every PE
 * signature fail to compile. Here it is defined once, beside the name function, and
 * both are generated from the same list.
 */
/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
/*
 * The regions, once. The bit list and the names are both generated from it, so
 * they cannot disagree and adding a region is one line.
 */
#define ELF_REGIONS(X)          \
	X(KOF_SCAN_ELF_HEADERS)   \
	X(KOF_SCAN_ELF_CODE)      \
	X(KOF_SCAN_ELF_DATA)      \
	X(KOF_SCAN_ELF_NOLOAD)    \
	X(KOF_SCAN_ELF_UNCLAIMED) \
	X(KOF_SCAN_ELF_SLIB_CODE) \
	X(KOF_SCAN_ELF_SLIB_DATA)

extern const uint32_t kof_elf_region_bits[];
#define KOF_ELF_REGION_COUNT 7u   /* asserted against the array in the .c */

#endif /* KOFENG_ELF_PARSE_H */
