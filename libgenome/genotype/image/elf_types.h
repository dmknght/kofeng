/*
 * elf_types.h - the structure of an ELF object, as kgenome reads it.
 *
 * DEFINED BY libgenome: what the parser recovers from the headers (segments,
 * sections, the anomaly bits, the scan-region partition) is the analysis of
 * the executable. The engine re-exports it as <kofmod/elf.h>, which adds only
 * what a module needs on top - the kof_elf() accessor over a context and the
 * subtype-name resolver.
 *
 * Values are normalised: every field is 64 bit regardless of ELF class, and in
 * host byte order. ELF32 and big endian objects are widened and swapped on read
 * by two small readers in the parser, so all logic above this line is written
 * once. Parsing lives in libkofeng/analyzers/parsers/binaries.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KGENOME_ELF_TYPES_H
#define KGENOME_ELF_TYPES_H

#include <stdint.h>

#define KGENOME_ELF_INFO_VERSION 1

/* ELF class and byte order, as normalised by the parser. */
enum {
	KGENOME_ELFCLASS_NONE = 0,
	KGENOME_ELFCLASS_32   = 1,
	KGENOME_ELFCLASS_64   = 2
};

enum {
	KGENOME_ELFDATA_NONE = 0,
	KGENOME_ELFDATA_LE   = 1,
	KGENOME_ELFDATA_BE   = 2
};

/*
 * Every region except the complement.
 *
 * Here rather than in the collector because this is where a region is added, and
 * a list of regions kept anywhere else is a list someone will forget to extend.
 * UNCLAIMED is what is left when all of these are taken, so it is defined by this
 * and cannot be in it.
 */
#define KGENOME_SCAN_ELF_CLAIMED (KGENOME_SCAN_ELF_HEADERS | KGENOME_SCAN_ELF_CODE |	\
			      KGENOME_SCAN_ELF_DATA | KGENOME_SCAN_ELF_NOLOAD)

/*
 * WHAT EACH REGION IS ANCHORED ON
 *
 * A boundary is worth what the field defining it is worth, and a file can lie
 * about some fields for free. See the same note in pe.h for the three tiers.
 *
 *   CODE, DATA   tier 1. PT_LOAD and its permission bits; the kernel must read
 *                these or the file does not run.
 *   HEADERS      tier 1 for the ELF header and program header table; tier 3 for
 *                the section header table it also covers.
 *   NOLOAD       tier 3, entirely. It is defined by the section header table,
 *                which nothing is required to read. A signature narrowed to
 *                NOLOAD finds nothing on a binary whose section table was
 *                stripped - and stripping it leaves the binary running.
 *                Demonstrated: zeroing e_shoff, e_shentsize and e_shnum in
 *                /bin/ls leaves it working, leaves CODE and DATA identical to
 *                the byte, and takes NOLOAD from 7076 bytes to nothing.
 *   UNCLAIMED    inherits the weakest tier of whatever it is the complement of.
 *
 * There is no resource region here and that is not an oversight. ELF has no
 * structural equivalent of a data directory: GResource arrives as sections named
 * .gresource.*, which is tier 3, and measures 1.4% of section bytes across 401
 * binaries against 61.3% for resources in a GUI PE. Neither the anchor nor the
 * payoff is there.
 */

/*
 * Region permissions. Not in kofsig.h because what carries them differs by
 * format: here it is a PT_LOAD segment, in PE it is a section.
 */
enum {
	KGENOME_PERM_X = 1u << 0,
	KGENOME_PERM_W = 1u << 1,
	KGENOME_PERM_R = 1u << 2
};

/*
 * Array bounds.
 *
 * Measured over 556 objects in /usr/bin and /usr/lib: program headers reach a
 * maximum of 15 and section headers a maximum of 38, with p99 at 15 and 34.
 * Neither has a long tail, unlike symbol counts, which run from a median of 76
 * to a maximum of 43912 - which is why symbols are not stored here at all and
 * are reached through an accessor instead.
 *
 * The bound is also the clamp: a forged count cannot drive iteration, and
 * hitting it sets the matching anomaly rather than failing.
 */
#define KGENOME_ELF_MAX_SEGMENTS 64
#define KGENOME_ELF_MAX_SECTIONS 128

/*
 * Section names are copied in rather than pooled, so comparing and printing both
 * work without a string table and without handing out a pointer.
 *
 * Sized from 17214 section names across /usr/bin and /usr/lib: p50 is 9, p99 is
 * 18, and the longest is 25 (".gresource.widget_factory"). 20 was tried first
 * and truncated two real binaries.
 *
 * Correctness does not depend on this number. name_hash is computed over the
 * full name from the string table, not over the stored copy, so a comparison
 * stays right even when the copy is cut short; truncation only affects what gets
 * printed, and it sets an anomaly so it is visible.
 */
#define KGENOME_ELF_SECNAME_MAX 32

/*
 * How far name_hash will read before it stops, and why there has to be a stop.
 *
 * The hash covers the whole name so that two names sharing the first 32 bytes
 * still differ - but "the whole name" is a run of the string table that ends at a
 * NUL, and the string table's size is a field the file chose. A section whose name
 * offset points into a megabytes-long table with no NUL makes the hash scan the
 * whole table, once per section: measured, a 200MB file with 128 such sections
 * took 22 seconds and 26 billion iterations to parse. That is a denial of service
 * out of one malformed header, and it grows with the file.
 *
 * So the scan stops here, and a name that reaches it is marked truncated - the same
 * anomaly a name longer than the stored copy already raises. The bound is far above
 * anything real: the longest section name measured across /usr/bin and /usr/lib was
 * 25 bytes, and this is ten times that. A name between 256 bytes and the size of a
 * hostile string table is not a name.
 */
#define KGENOME_ELF_SECNAME_SCAN 256u

/*
 * Anomalies.
 *
 * Facts, not failures. The parser never refuses to describe an object: it
 * reports what it recovered and what was wrong with it. Refusing would go blind
 * on exactly the inputs worth looking at, and it would discard signal, since a
 * malformed header is itself evidence.
 *
 * Anything conditional on e_type is qualified here, because an unconditional
 * bit that fires on half of a clean corpus discriminates nothing. Both
 * entry_zero and no_load_segment started out unconditional and were measured to
 * fire on 42% of /usr/bin and /usr/lib before being restricted.
 */
enum {
	KGENOME_ELF_ANOM_BAD_MAGIC        = 1ull << 0,
	KGENOME_ELF_ANOM_BAD_CLASS        = 1ull << 1,
	KGENOME_ELF_ANOM_BAD_ENDIAN       = 1ull << 2,
	KGENOME_ELF_ANOM_BAD_VERSION      = 1ull << 3,
	KGENOME_ELF_ANOM_TRUNCATED_HEADER = 1ull << 4,
	KGENOME_ELF_ANOM_PHOFF_PAST_EOF   = 1ull << 5,
	KGENOME_ELF_ANOM_PHENTSIZE_ODD    = 1ull << 6,
	KGENOME_ELF_ANOM_PHNUM_CLAMPED    = 1ull << 7,
	KGENOME_ELF_ANOM_SHOFF_PAST_EOF   = 1ull << 8,
	KGENOME_ELF_ANOM_SHNUM_CLAMPED    = 1ull << 9,
	KGENOME_ELF_ANOM_SEG_PAST_EOF     = 1ull << 10,
	KGENOME_ELF_ANOM_SEG_FILESZ_GT_MEM= 1ull << 11,
	KGENOME_ELF_ANOM_SEG_OVERLAP      = 1ull << 12,
	KGENOME_ELF_ANOM_NO_LOAD_SEGMENT  = 1ull << 13, /* ET_EXEC and ET_DYN only */
	KGENOME_ELF_ANOM_ENTRY_ZERO       = 1ull << 14, /* ET_EXEC only */
	KGENOME_ELF_ANOM_ENTRY_UNMAPPED   = 1ull << 15,
	KGENOME_ELF_ANOM_ENTRY_ZEROFILL   = 1ull << 16, /* mapped, absent from file */
	KGENOME_ELF_ANOM_ENTRY_NOT_EXEC   = 1ull << 17,
	KGENOME_ELF_ANOM_SHENTSIZE_ODD    = 1ull << 18,
	KGENOME_ELF_ANOM_SHSTRNDX_BAD     = 1ull << 19,
	KGENOME_ELF_ANOM_SEC_PAST_EOF     = 1ull << 20,
	KGENOME_ELF_ANOM_SECNAME_UNREAD   = 1ull << 21, /* name outside the strtab */
	KGENOME_ELF_ANOM_SECNAME_TRUNC    = 1ull << 22, /* longer than we keep */
	KGENOME_ELF_ANOM_SECTAB_MISSING   = 1ull << 23  /* stripped: no usable shdr */
};

/* How many of the above there are, so the name table cannot fall behind
 * them - three of 7z's bits went unnamed until a checklist pass found it. */
#define KGENOME_ELF_ANOM_COUNT 24


struct kgenome_elf_seg {
	uint64_t file_off, file_size;
	uint64_t mem_addr, mem_size;
	uint32_t type;
	uint32_t perm;       /* KOF_PERM_* */

	/* The bytes this segment owns in the region partition. See the note on
	 * the same pair in struct kgenome_elf_sec. */
	uint64_t claim_off, claim_len;
};

/*
 * e_type, as the prefilter's subtype axis.
 *
 * These ARE the values in the header - ET_NONE through ET_CORE - and not an
 * interpretation of them. That distinction is the point of naming them this way: a
 * shared library and a position independent executable are both ET_DYN and nothing
 * in the header separates them, so an enum offering LIBRARY and EXECUTABLE would be
 * offering a guess. Measured over 709 ET_DYN binaries, splitting them by whether a
 * PT_INTERP is present gives 553 and 156 - a plausible split, and still a guess.
 *
 * A module wanting a distinction the header does not make reads the view and says
 * so in its own code, where it is visible as reasoning rather than hidden in a
 * constant. A kernel module is the case that matters and it needs nothing more
 * from this axis: a .ko is ET_REL where an ordinary binary is ET_EXEC or ET_DYN,
 * so REL alone takes 7221 objects down to 60. Whoever wants the 33 of those that
 * are really modules tests for a section name in their own module, after the
 * prefilter has already done the cheap part.
 */
/* X(NAME, value). One list: the enum below, the words the build tool accepts in
 * KOF_TARGET_SUBTYPE, and the set an editor offers all come from it. The build
 * script used to keep a copy of its own and match it as a substring. */
/* The prefix is a parameter so the same list is read with two spellings: KGENOME_ELF_TYPE_LIST(X) below
 * hands the enumerators their own name, and the ABI list KGENOME_ELF_TYPE_LIST(X) in <kofmod/elf.h>
 * hands a consumer that STRINGIFIES the name the word a signature source writes. */
#define KGENOME_ELF_TYPE_LIST_(P, X)                                                 \
	X(P##ELF_NONE, 0)                                                   \
	X(P##ELF_REL,  1)                                                   \
	X(P##ELF_EXEC, 2)                                                   \
	X(P##ELF_DYN,  3)                                                   \
	X(P##ELF_CORE, 4)
#define KGENOME_ELF_TYPE_LIST(X) KGENOME_ELF_TYPE_LIST_(KGENOME_, X)

enum kgenome_elf_type {
#define KGENOME_ELF_TYPE_X(name, val) name = val,
	KGENOME_ELF_TYPE_LIST(KGENOME_ELF_TYPE_X)
#undef KGENOME_ELF_TYPE_X
	KGENOME_ELF_TYPE_COUNT = 5
};



struct kgenome_elf_sec {
	uint64_t file_off, file_size;
	uint64_t mem_addr;
	uint64_t flags;
	uint32_t type;
	uint32_t name_hash;  /* of the full name, so comparison survives truncation */
	char     name[KGENOME_ELF_SECNAME_MAX];

	/*
	 * The bytes this section owns in the region partition, which is not
	 * always what it declared.
	 *
	 * Nothing in ELF stops a segment and a section describing the same file
	 * bytes - in a normal object they do, which is the point of having both -
	 * so no assignment of bytes to regions can be faithful to every
	 * declaration and disjoint at the same time. Ownership is settled once at
	 * parse time in offset order, with the earlier claimant keeping the bytes.
	 *
	 * Modules reading what the file said want file_off and file_size. The scan
	 * regions use these.
	 */
	uint64_t claim_off, claim_len;
};

/*
 * The ELF view.
 *
 * file_size and entry_off are not repeated here: they mean the same thing for
 * every object and live in the common tier. entry_addr does stay, because a
 * virtual address is only meaningful against this format's load layout.
 *
 * Segments are the ground truth for what executes: the kernel loader needs only
 * the program headers, so a stripped or forged section table can sit on a
 * perfectly runnable object. Sections are published too, but a module reasoning
 * about executable content should prefer segments and treat disagreement between
 * the two as signal.
 */
struct kgenome_elf_info {
	uint32_t version;      /* KGENOME_ELF_INFO_VERSION the parser filled */
	uint32_t valid;        /* non-zero if the magic matched; facts may still
				* be partial, see anomalies */

	uint8_t  elf_class;    /* KOF_ELFCLASS_* */
	uint8_t  elf_data;     /* KOF_ELFDATA_* */
	uint8_t  os_abi;
	uint8_t  abi_version;

	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;


	uint64_t entry_addr;   /* virtual address, as declared */
	uint32_t entry_perm;   /* KOF_PERM_* of the containing segment, 0 if none */

	/* What the header structures own after settling: the front block, and the
	 * section header table, which a hostile object can put inside a segment. */
	uint64_t hdr_claim_off, hdr_claim_len;
	uint64_t shtab_claim_off, shtab_claim_len;

	uint64_t phoff;
	uint16_t phentsize;
	uint16_t phnum;         /* after clamping */
	uint16_t phnum_claimed; /* what the header said */

	uint64_t shoff;
	uint16_t shentsize;
	uint16_t shnum;         /* after clamping */
	uint16_t shnum_claimed;
	uint16_t shstrndx;

	uint32_t load_count;   /* PT_LOAD segments seen */
	uint64_t min_vaddr;    /* lowest PT_LOAD vaddr, KGENOME_NA if none */
	uint64_t max_vaddr;    /* highest PT_LOAD vaddr + memsz */

	uint32_t seg_count;
	uint32_t sec_count;

	uint64_t anomalies;    /* KOF_ELF_ANOM_* */

	struct kgenome_elf_seg seg[KGENOME_ELF_MAX_SEGMENTS];
	struct kgenome_elf_sec sec[KGENOME_ELF_MAX_SECTIONS];
};

/*
 * WHAT IS EXECUTABLE IN AN ELF, AND WHERE ITS BYTES ARE - TWO VIEWS, EACH
 * DEFINED ONCE.
 *
 * ELF carries the fact twice, in two tables that do not agree on purpose, and
 * every consumer used to spell one of the two rules for itself (the CODE region,
 * the normaliser, the xref sweep, the diagnose sweep, the emulator gate, three
 * places in the parser). They are exposed here so that choosing a view is a
 * call, not a re-derivation.
 *
 *   SEGMENT view, the LOADER's: kgenome_elf_seg_is_code is a PT_LOAD with PF_X.
 *   What the kernel maps executable, and the only table a stripped or
 *   section-less object (msfvenom's template) has. A segment holds more than
 *   instructions - a linker puts .rodata in it beside .text - so this is the
 *   right view for "which bytes can run" (the CODE region, the emulator's
 *   density gate, the diagnose sweep) and the wrong one for "which bytes are
 *   instructions". Measured: 153 alloc sections of the 300-file
 *   subset's 95 ELFs (800 over the 252 of the ELF-255 set) lie inside an
 *   executable segment without being executable themselves - .rodata,
 *   .eh_frame - and none is the other way round, so the views DO differ
 *   and neither can stand in for the other.
 *
 *   SECTION view, the LINKER's: kgenome_elf_sec_is_code is SHT_PROGBITS with
 *   SHF_EXECINSTR: the bytes that are instructions, and absent when the
 *   section table is. The type is part of it because SHT_NOBITS occupies no
 *   file bytes and its offset says nothing; every SHF_EXECINSTR section in the
 *   subset and the ELF-255 set is SHT_PROGBITS (the nine that are not belong to
 *   one object whose section table is string data).
 *
 * Where a walk that decodes every byte of a segment needs both views - the
 * segment says which bytes can run, only the section table says which of them
 * are instructions - the answer is kgenome_diag_walk_range in
 * libgenome/phenotype/nodes.c, documented where it is defined; the
 * segment view past the headers is kgenome_diag_code_range beside it. The xref sweep
 * keeps the section view for its run cut, for the reason given at xref_runs in
 * scanners/objctx.c.
 *
 * The extent helpers return the part of the declared range that is really in
 * an object of `obj_size` bytes (0 when none is) and its file offset in *off.
 * A header field is a claim, not a size; see kof_clip_len. The partition used
 * by the scan regions is a third thing again - claim_off/claim_len, settled so
 * that regions never overlap - and stays with the region resolver.
 */
int kgenome_elf_seg_is_code(const struct kgenome_elf_seg *g);
uint64_t kgenome_elf_seg_extent(const struct kgenome_elf_seg *g, uint64_t obj_size,
			    uint64_t *off);
int kgenome_elf_sec_is_code(const struct kgenome_elf_sec *s);
uint64_t kgenome_elf_sec_extent(const struct kgenome_elf_sec *s, uint64_t obj_size,
			    uint64_t *off);

/*
 * The parts of an ELF object a search can be scoped to.
 *
 * These five partition the object: every byte belongs to exactly one, checked over
 * 319 ELF files. That is what makes OR-ing them cheap - a union scans no byte twice.
 * Their share of 157MB of ELF content: code 60.0%, data 35.7%, noload 2.6%,
 * unclaimed 1.2%, headers 0.6%.
 *
 * Values start at 1 and collide with another format's bits, which is safe for the
 * same reason the cast above is safe: naming one requires including this header, and
 * the build rejects a module that includes a format header without declaring that
 * format as its target.
 *
 * Absent is normal. A stripped static binary has no section table, so NOLOAD is
 * absent while CODE and DATA are present; searching an absent region finds nothing
 * rather than falling back to the whole object.
 */
enum kgenome_scan_elf {
	/* The three header tables: ehdr, phdr, shdr. One bit, not three, because
	 * nothing wants one table and not the others. Rarely the right thing to
	 * search - every field of all three is already parsed into this struct, so
	 * this exists for checksums and raw byte comparison over structure a packer
	 * may have written distinctively. */
	KGENOME_SCAN_ELF_HEADERS   = 1u << 1,

	/* Loaded content, split by PF_X. Both come from the program headers, so both
	 * survive stripping and neither can be removed from a working file. CODE is
	 * for opcode patterns, DATA for string constants; together they are 95.7% of
	 * the corpus by bytes, so searching the wrong one is not a small waste. */
	KGENOME_SCAN_ELF_CODE      = 1u << 2,  /* PT_LOAD with PF_X */
	KGENOME_SCAN_ELF_DATA      = 1u << 3,  /* PT_LOAD without PF_X */

	/* Sections the linker kept and the loader ignores - no SHF_ALLOC. In practice
	 * .comment, .debug_*, .symtab, .strtab. Derived from the flag, not from
	 * section names, so it stays a range on the file. Absent on a stripped
	 * object, and most of the file on a debug build. */
	KGENOME_SCAN_ELF_NOLOAD    = 1u << 4,

	/* Bytes no header table, segment or section accounts for: the padding cave
	 * between the front headers and the first section, end-of-segment alignment
	 * padding, and data appended past everything.
	 *
	 * The one region where matching at all is the signal rather than a narrower
	 * place to look. It is 1.2% of the corpus by bytes, and on /usr/bin/ls, gcc,
	 * python3 and bash every byte of it was zero - normally present and normally
	 * blank, so any non-zero byte here is already anomalous.
	 *
	 * Note it grows when structure is damaged, not shrinks: zeroing e_shoff leaves
	 * the .comment and .symtab bytes in place while removing what claimed them, so
	 * they move from NOLOAD to here. */
	KGENOME_SCAN_ELF_UNCLAIMED = 1u << 5,
	/*
	 * WHERE THE STATIC LIBRARY WENT, IN A NORMALISED VIEW.
	 *
	 * The view exists to be the object's own content, so the toolchain's
	 * bytes come out of it - and taken out and thrown away they become a
	 * blindspot: nothing can look at them, no rule can be written about
	 * them, and a reader comparing the view with the file cannot account
	 * for the difference.
	 *
	 * So they are not thrown away. They are moved to the end of the view
	 * and given a region of their own, named after the one they were cut
	 * from: what came out of CODE is SLIB_CODE and what came out of DATA
	 * is SLIB_DATA. The partition still holds - every byte of the view is
	 * in exactly one region - and the thing the cut was for still holds
	 * too, because a measure or a block anchored to CODE no longer reaches
	 * them.
	 *
	 * ONLY EVER ON A VIEW. A file's own region table never carries these:
	 * there the library bytes are still inside CODE and DATA, which is
	 * where the loader put them.
	 */
	KGENOME_SCAN_ELF_SLIB_CODE = 1u << 6,
	KGENOME_SCAN_ELF_SLIB_DATA = 1u << 7
};

#endif /* KGENOME_ELF_TYPES_H */
