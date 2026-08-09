/*
 * elf.h - the ELF view of an object.
 *
 * Including this header declares that the module targets ELF, and a module may
 * include exactly one format header. The build script enforces that, and the
 * reason is the accessor below: kof_elf() casts ctx->fmt, and the cast is sound
 * only because the host does not call a module for a format the module did not
 * declare. Making the module check at runtime would move the guarantee from one
 * place that can be tested to N places that can each forget.
 *
 * So the prefilter is not a performance feature here. It is what makes the cast
 * safe. A detection that spans formats - "ELF with X, or PE with Y" - is written
 * as two modules with two targets and joined at the record layer, which also
 * prefilters better than one module that runs on both.
 *
 * Values are normalised: every field is 64 bit regardless of ELF class, and in
 * host byte order. ELF32 and big endian objects are widened and swapped on read
 * by two small readers in the parser, so all logic above this line is written
 * once. Parsing lives in libkofeng/kofparsers/elf.
 *
 * Layout rule: append only. New fields go at the end, existing fields never
 * move or change meaning.
 */

#ifndef KOFENG_ELF_H
#define KOFENG_ELF_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_ELF_INFO_VERSION 1

/* ELF class and byte order, as normalised by the parser. */
enum {
	KOF_ELFCLASS_NONE = 0,
	KOF_ELFCLASS_32   = 1,
	KOF_ELFCLASS_64   = 2
};

enum {
	KOF_ELFDATA_NONE = 0,
	KOF_ELFDATA_LE   = 1,
	KOF_ELFDATA_BE   = 2
};

/*
 * Every region except the complement.
 *
 * Here rather than in the collector because this is where a region is added, and
 * a list of regions kept anywhere else is a list someone will forget to extend.
 * UNCLAIMED is what is left when all of these are taken, so it is defined by this
 * and cannot be in it.
 */
#define KOF_SCAN_ELF_CLAIMED (KOF_SCAN_ELF_HEADERS | KOF_SCAN_ELF_CODE |	\
			      KOF_SCAN_ELF_DATA | KOF_SCAN_ELF_NOLOAD)

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
	KOF_PERM_X = 1u << 0,
	KOF_PERM_W = 1u << 1,
	KOF_PERM_R = 1u << 2
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
#define KOF_ELF_MAX_SEGMENTS 64
#define KOF_ELF_MAX_SECTIONS 128

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
#define KOF_ELF_SECNAME_MAX 32

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
	KOF_ELF_ANOM_BAD_MAGIC        = 1ull << 0,
	KOF_ELF_ANOM_BAD_CLASS        = 1ull << 1,
	KOF_ELF_ANOM_BAD_ENDIAN       = 1ull << 2,
	KOF_ELF_ANOM_BAD_VERSION      = 1ull << 3,
	KOF_ELF_ANOM_TRUNCATED_HEADER = 1ull << 4,
	KOF_ELF_ANOM_PHOFF_PAST_EOF   = 1ull << 5,
	KOF_ELF_ANOM_PHENTSIZE_ODD    = 1ull << 6,
	KOF_ELF_ANOM_PHNUM_CLAMPED    = 1ull << 7,
	KOF_ELF_ANOM_SHOFF_PAST_EOF   = 1ull << 8,
	KOF_ELF_ANOM_SHNUM_CLAMPED    = 1ull << 9,
	KOF_ELF_ANOM_SEG_PAST_EOF     = 1ull << 10,
	KOF_ELF_ANOM_SEG_FILESZ_GT_MEM= 1ull << 11,
	KOF_ELF_ANOM_SEG_OVERLAP      = 1ull << 12,
	KOF_ELF_ANOM_NO_LOAD_SEGMENT  = 1ull << 13, /* ET_EXEC and ET_DYN only */
	KOF_ELF_ANOM_ENTRY_ZERO       = 1ull << 14, /* ET_EXEC only */
	KOF_ELF_ANOM_ENTRY_UNMAPPED   = 1ull << 15,
	KOF_ELF_ANOM_ENTRY_ZEROFILL   = 1ull << 16, /* mapped, absent from file */
	KOF_ELF_ANOM_ENTRY_NOT_EXEC   = 1ull << 17,
	KOF_ELF_ANOM_SHENTSIZE_ODD    = 1ull << 18,
	KOF_ELF_ANOM_SHSTRNDX_BAD     = 1ull << 19,
	KOF_ELF_ANOM_SEC_PAST_EOF     = 1ull << 20,
	KOF_ELF_ANOM_SECNAME_UNREAD   = 1ull << 21, /* name outside the strtab */
	KOF_ELF_ANOM_SECNAME_TRUNC    = 1ull << 22, /* longer than we keep */
	KOF_ELF_ANOM_SECTAB_MISSING   = 1ull << 23  /* stripped: no usable shdr */
};

struct kof_elf_seg {
	uint64_t file_off, file_size;
	uint64_t mem_addr, mem_size;
	uint32_t type;
	uint32_t perm;       /* KOF_PERM_* */

	/* The bytes this segment owns in the region partition. See the note on
	 * the same pair in struct kof_elf_sec. */
	uint64_t claim_off, claim_len;
};

struct kof_elf_sec {
	uint64_t file_off, file_size;
	uint64_t mem_addr;
	uint64_t flags;
	uint32_t type;
	uint32_t name_hash;  /* of the full name, so comparison survives truncation */
	char     name[KOF_ELF_SECNAME_MAX];

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
struct kof_elf_info {
	uint32_t version;      /* KOF_ELF_INFO_VERSION the parser filled */
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
	uint64_t min_vaddr;    /* lowest PT_LOAD vaddr, KOF_NA if none */
	uint64_t max_vaddr;    /* highest PT_LOAD vaddr + memsz */

	uint32_t seg_count;
	uint32_t sec_count;

	uint64_t anomalies;    /* KOF_ELF_ANOM_* */

	struct kof_elf_seg seg[KOF_ELF_MAX_SEGMENTS];
	struct kof_elf_sec sec[KOF_ELF_MAX_SECTIONS];
};

/*
 * The ELF view of a context.
 *
 * A plain cast, not a checked one. Returning NULL on mismatch would only move
 * the fault: a module that forgot to check would dereference NULL instead of
 * reading the wrong struct. The guarantee comes from two things that can be
 * verified once rather than per module - the build script rejects a module that
 * includes more than one format header, and the host does not invoke a module
 * whose declared target does not cover the object in hand.
 */
static inline const struct kof_elf_info *
kof_elf(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_elf_info *)ctx->file_header;
}

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
enum kof_scan_elf {
	/* The three header tables: ehdr, phdr, shdr. One bit, not three, because
	 * nothing wants one table and not the others. Rarely the right thing to
	 * search - every field of all three is already parsed into this struct, so
	 * this exists for checksums and raw byte comparison over structure a packer
	 * may have written distinctively. */
	KOF_SCAN_ELF_HEADERS   = 1u << 1,

	/* Loaded content, split by PF_X. Both come from the program headers, so both
	 * survive stripping and neither can be removed from a working file. CODE is
	 * for opcode patterns, DATA for string constants; together they are 95.7% of
	 * the corpus by bytes, so searching the wrong one is not a small waste. */
	KOF_SCAN_ELF_CODE      = 1u << 2,  /* PT_LOAD with PF_X */
	KOF_SCAN_ELF_DATA      = 1u << 3,  /* PT_LOAD without PF_X */

	/* Sections the linker kept and the loader ignores - no SHF_ALLOC. In practice
	 * .comment, .debug_*, .symtab, .strtab. Derived from the flag, not from
	 * section names, so it stays a range on the file. Absent on a stripped
	 * object, and most of the file on a debug build. */
	KOF_SCAN_ELF_NOLOAD    = 1u << 4,

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
	KOF_SCAN_ELF_UNCLAIMED = 1u << 5
};

#endif /* KOFENG_ELF_H */
