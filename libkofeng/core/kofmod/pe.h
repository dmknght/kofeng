/*
 * pe.h - the PE view of an object.
 *
 * Including this header declares that the module targets PE, and a module may
 * include exactly one format header. The build script enforces that, and the
 * reason is the accessor below: kof_pe() casts ctx->file_header, and the cast is
 * sound only because the host does not call a module for a format the module did
 * not declare.
 *
 * Values are normalised: every field is 64 bit whether the image is PE32 or
 * PE32+, and in host byte order. All logic above this line is written once.
 * Parsing lives in libkofeng/kofparsers/binaries.
 *
 * Layout rule: append only. New fields go at the end, existing fields never move
 * or change meaning.
 *
 *
 * HOW THIS DIFFERS FROM THE ELF VIEW, AND WHY IT MATTERS
 *
 * ELF has two independent descriptions of one file - program headers, which the
 * kernel maps, and section headers, which the linker wrote - and disagreement
 * between them is signal. PE has one: the section table is what the loader maps,
 * and there is no second description to check it against.
 *
 * The nearest substitute is in the optional header. BaseOfCode, SizeOfCode,
 * SizeOfInitializedData and SizeOfUninitializedData are the linker's summary of
 * what the section table spells out in detail, so they are published here for a
 * module to compare. A summary that disagrees with the detail is the PE analogue
 * of a section claiming to be executable with no PT_LOAD over it.
 *
 * The other difference is that almost everything in PE is an RVA - the entry
 * point, all sixteen data directories, imports, exports - and turning one into a
 * file offset needs the section table. kof_pe_rva_to_off below is that, and it
 * answers KOF_BROKEN rather than guessing when an RVA lands in no section, which
 * is a thing hostile files arrange on purpose.
 */

#ifndef KOFENG_PE_H
#define KOFENG_PE_H

#include <stdint.h>
#include <kofmod/kofsig.h>

#define KOF_PE_INFO_VERSION 1

/*
 * Scan regions.
 *
 * The five ELF regions plus one. The extra is OVERLAY, and it exists because the
 * same idea has a different value in the two formats: on ELF, the bytes no
 * structure claimed measured 100% zero fill across a real corpus, while on PE the
 * equivalent tail routinely carries real content and is where installers,
 * self-extractors and appended payloads live. A region that is always empty and a
 * region that is usually interesting should not share a name.
 *
 * What the ELF view calls NOLOAD is called SIGNATURE here, because in PE it holds
 * one thing. ELF's NOLOAD is symtab, strtab and debug - toolchain traces worth
 * searching. PE keeps those inside sections; the only thing genuinely in the file
 * and not mapped is the attribute certificate table. Borrowing the ELF name would
 * have described the shape and hidden the content.
 *
 * SIGNATURE is separate from OVERLAY for a reason that is not tidiness. The
 * Authenticode digest deliberately excludes the certificate block, so data
 * appended inside it does not break the signature - a real technique, and one
 * Microsoft shipped a fix for. Folding it into OVERLAY would mean every signed
 * binary appears to carry a large overlay, and the one region worth looking at
 * would be noise on exactly the files that are supposed to be trustworthy.
 *
 * Measured on the corpus in tests/PE_FILES: of two files with a non-empty tail,
 * one is a signed binary whose entire "overlay" is its certificate, and the other
 * has 26KB of real appended data and no signature at all. The split tells those
 * two apart; a single region cannot.
 *
 * No region is named after a section name. `.text` is a string whoever built the
 * file chose - UPX writes UPX0 and UPX1, and nothing stops a packer calling its
 * code section `.data`. CODE means IMAGE_SCN_MEM_EXECUTE, which is what the
 * loader acts on. Same choice ELF made in partitioning by PT_LOAD permission.
 *
 * The six regions partition the object: every byte is in exactly one, so OR-ing
 * masks scans nothing twice.
 */
enum kof_scan_pe {
	KOF_SCAN_PE_HEADERS   = 1u << 1,  /* [0, e_lfanew) plus the PE signature,
					   * COFF header, optional header with its
					   * data directories, and section table */
	/*
	 * CODE and DATA keep the names a signature author already thinks in - the
	 * string is in the data, the call is in the code - while the definition
	 * below is what actually selects them. PE has no "code segment"; it has
	 * sections, and this is the set of them the loader will execute.
	 *
	 * Selected by IMAGE_SCN_MEM_EXECUTE, never by name. A section called .text
	 * with characteristics 0xc0000040 - writable, not executable - is in this
	 * corpus, so the distinction is not hypothetical. Tier 1.
	 */
	KOF_SCAN_PE_CODE      = 1u << 2,  /* sections with MEM_EXECUTE */
	KOF_SCAN_PE_DATA      = 1u << 3,  /* sections with file bytes, not executable,
					   * less whatever RESOURCE takes */
	KOF_SCAN_PE_SIGNATURE = 1u << 4,  /* the attribute certificate table */
	KOF_SCAN_PE_OVERLAY   = 1u << 5,  /* past the last claimed byte */
	KOF_SCAN_PE_UNCLAIMED = 1u << 6,  /* the complement: alignment slack, gaps,
					   * anything a directory points outside a
					   * section */

	/*
	 * What DataDirectory[RESOURCE] covers, carved out of the non-executable
	 * sections it normally sits inside.
	 *
	 * Appended rather than renumbered: a region bit ends up in the .meta
	 * record of every blob already built, so changing an existing value would
	 * silently repoint every signature that names one.
	 *
	 * This is the one region where narrowing changes the order of the cost
	 * rather than trimming it. Measured on the corpus: resources are 61.3% of
	 * a GUI binary's bytes and 0.5% of a console one's, and a single sample
	 * (radmin.exe) is 87.5% resource. Scoping a search to the code of such a
	 * file, or to the resources of it, is the difference between reading most
	 * of the file and reading almost none.
	 *
	 * Tier 2 (see the note on anchors below): nothing has to read this
	 * directory for the image to load, so a file can lie about it without
	 * failing to run. When the range does not resolve, the region is empty and
	 * the bytes stay with the section - never a guess.
	 */
	KOF_SCAN_PE_RESOURCE  = 1u << 7
};

/*
 * WHAT A REGION BOUNDARY IS ANCHORED ON
 *
 * A boundary is worth exactly as much as the field that defines it, and fields
 * differ enormously in how freely a file can lie about them. Three tiers, and
 * every region below says which one it stands on:
 *
 *   tier 1  the loader must read it correctly or the file does not run.
 *           e_lfanew, the COFF and optional headers, the section table with its
 *           Characteristics. A lie here changes what executes.
 *   tier 2  the system reads it later, or only for some feature. The data
 *           directories. A lie breaks a feature, not the load.
 *   tier 3  nothing is required to read it. Section names, and in ELF the
 *           entire section header table. A lie is free.
 *
 * Demonstrated rather than asserted: removing the section header table from a
 * working binary leaves it running, leaves CODE and DATA identical to the byte,
 * and makes every tier 3 region vanish.
 *
 * Regions are built from tier 1 wherever possible. Tier 2 is used when the payoff
 * is large and the structure unambiguous. Tier 3 is never a boundary - it is
 * evidence, and evidence belongs in the view and the anomaly bits.
 */

/*
 * Every region except the complement.
 *
 * Here rather than in the collector because this is where a region is added, and
 * a list of regions kept anywhere else is a list someone will forget to extend.
 * UNCLAIMED is what is left when all of these are taken, so it is defined by this
 * and cannot be in it.
 */
#define KOF_SCAN_PE_CLAIMED (KOF_SCAN_PE_HEADERS | KOF_SCAN_PE_CODE |	\
			     KOF_SCAN_PE_DATA | KOF_SCAN_PE_RESOURCE |	\
			     KOF_SCAN_PE_SIGNATURE | KOF_SCAN_PE_OVERLAY)

/* Section permissions, from IMAGE_SCN_MEM_*. Same bit meanings as the ELF view's
 * KOF_PERM_*, which is why they are spelled the same way. */
enum {
	KOF_PE_PERM_X = 1u << 0,
	KOF_PE_PERM_W = 1u << 1,
	KOF_PE_PERM_R = 1u << 2
};

/*
 * Array bound.
 *
 * NOT measured, unlike the ELF equivalents, and that is worth stating rather than
 * hiding: the corpus available here is eight files, where ELF's numbers came from
 * 556. Observed section counts run 3 to 7, which says nothing about the tail.
 *
 * 96 is used because it is the Windows loader's own limit on the number of
 * sections in an image, so a clamp there cannot truncate a file that would load.
 * A bound taken from the format beats a bound guessed from a small sample.
 */
#define KOF_PE_MAX_SECTIONS 96

/*
 * A section name is eight bytes in an image, and is not required to be NUL
 * terminated when it uses all eight. Nine bytes therefore holds every possible
 * name with room for a terminator we add, so unlike ELF there is no truncation
 * case and no anomaly for it.
 *
 * Object files may use a "/12" form pointing into a COFF string table. Images may
 * not, so seeing one means this is not an image, and that is an anomaly rather
 * than something to resolve.
 */
#define KOF_PE_SECNAME_MAX 9

/* The sixteen data directories, by their index in the optional header. */
enum {
	KOF_PE_DIR_EXPORT       = 0,
	KOF_PE_DIR_IMPORT       = 1,
	KOF_PE_DIR_RESOURCE     = 2,
	KOF_PE_DIR_EXCEPTION    = 3,
	KOF_PE_DIR_SECURITY     = 4,   /* file offset, not an RVA - see below */
	KOF_PE_DIR_BASERELOC    = 5,
	KOF_PE_DIR_DEBUG        = 6,
	KOF_PE_DIR_ARCHITECTURE = 7,
	KOF_PE_DIR_GLOBALPTR    = 8,
	KOF_PE_DIR_TLS          = 9,
	KOF_PE_DIR_LOAD_CONFIG  = 10,
	KOF_PE_DIR_BOUND_IMPORT = 11,
	KOF_PE_DIR_IAT          = 12,
	KOF_PE_DIR_DELAY_IMPORT = 13,
	KOF_PE_DIR_COM_DESCRIPTOR = 14,
	KOF_PE_DIR_RESERVED     = 15,
	KOF_PE_DIR_COUNT        = 16
};

/*
 * Anomalies.
 *
 * Facts, not failures. The parser never refuses to describe an object: it reports
 * what it recovered and what was wrong with it. Refusing would go blind on exactly
 * the inputs worth looking at, and a malformed header is itself evidence.
 *
 * Every bit here is unqualified for now, which is the thing to fix first once
 * there is a corpus to measure against. The ELF set learned this the expensive
 * way: two bits fired on 42% of clean binaries before being restricted, and an
 * anomaly that fires on half a clean corpus discriminates nothing.
 */
enum {
	KOF_PE_ANOM_BAD_MZ            = 1ull << 0,
	KOF_PE_ANOM_LFANEW_PAST_EOF   = 1ull << 1,
	KOF_PE_ANOM_BAD_PE_SIG        = 1ull << 2,
	KOF_PE_ANOM_TRUNCATED_HEADER  = 1ull << 3,
	KOF_PE_ANOM_BAD_OPT_MAGIC     = 1ull << 4,
	KOF_PE_ANOM_OPTSIZE_ODD       = 1ull << 5,  /* too small for its magic */
	KOF_PE_ANOM_NSEC_ZERO         = 1ull << 6,
	KOF_PE_ANOM_NSEC_CLAMPED      = 1ull << 7,
	KOF_PE_ANOM_SECTAB_PAST_EOF   = 1ull << 8,
	KOF_PE_ANOM_SEC_PAST_EOF      = 1ull << 9,
	KOF_PE_ANOM_SEC_OVERLAP       = 1ull << 10, /* two sections claim file bytes */
	KOF_PE_ANOM_SEC_RAW_GT_VIRT   = 1ull << 11,
	KOF_PE_ANOM_SEC_ZERO_RAW      = 1ull << 12, /* no file bytes, large virtual:
						     * what a packer leaves behind */
	KOF_PE_ANOM_SEC_WRITE_EXEC    = 1ull << 13,
	KOF_PE_ANOM_SECNAME_OBJFORM   = 1ull << 14, /* "/12": an object, not an image */
	KOF_PE_ANOM_SIZEOFHDR_ODD     = 1ull << 15, /* disagrees with the computed end */
	KOF_PE_ANOM_ENTRY_ZERO        = 1ull << 16,
	KOF_PE_ANOM_ENTRY_UNMAPPED    = 1ull << 17, /* RVA in no section */
	KOF_PE_ANOM_ENTRY_NOT_EXEC    = 1ull << 18,
	KOF_PE_ANOM_ENTRY_ZEROFILL    = 1ull << 19, /* mapped, absent from the file */
	KOF_PE_ANOM_CERT_PAST_EOF     = 1ull << 20,
	KOF_PE_ANOM_DIR_COUNT_ODD     = 1ull << 21, /* NumberOfRvaAndSizes not 16 */
	KOF_PE_ANOM_STUB_OVERSIZED    = 1ull << 22, /* the gap before the NT headers */
	KOF_PE_ANOM_STUB_NONSTANDARD  = 1ull << 23,
	KOF_PE_ANOM_SUMMARY_MISMATCH  = 1ull << 24, /* SizeOfCode against the sections */
	KOF_PE_ANOM_DEBUG_OUTSIDE_SEC = 1ull << 25,

	/*
	 * The resource directory does not begin where a section does.
	 *
	 * In every file measured it starts exactly at the front of its section,
	 * which is what lets the region be carved out by a front trim. One that
	 * starts mid-section is describing bytes a section already owns; the
	 * section keeps them, the region comes back empty, and this says why.
	 */
	KOF_PE_ANOM_RSRC_UNALIGNED    = 1ull << 26
};

struct kof_pe_sec {
	uint64_t file_off, file_size;   /* PointerToRawData, SizeOfRawData */

	/*
	 * The bytes this section owns in the region partition, which is not always
	 * what it declared.
	 *
	 * A well formed image has these equal to file_off and file_size. A hostile
	 * one can point two sections at the same bytes, or point one into the
	 * headers, and then no assignment of bytes to regions can be both faithful
	 * to every declaration and disjoint. Ownership is settled once here, in
	 * offset order with the earlier claimant keeping the bytes, so the regions
	 * stay a partition and the disagreement is visible as an anomaly instead of
	 * as two regions returning the same offset.
	 *
	 * Modules reading what the file said want file_off and file_size. The scan
	 * regions use these.
	 */
	uint64_t claim_off, claim_len;
	uint64_t mem_rva, mem_size;     /* VirtualAddress, VirtualSize */
	uint32_t characteristics;
	uint32_t perm;                  /* KOF_PE_PERM_* */
	uint32_t name_hash;             /* of the eight name bytes as written */
	char     name[KOF_PE_SECNAME_MAX];
	uint8_t  _pad[3];
};

struct kof_pe_dir {
	uint64_t rva;   /* a file offset for KOF_PE_DIR_SECURITY - see the note */
	uint64_t size;
};

/*
 * The PE view.
 *
 * file_size and entry_off are not repeated here: they mean the same thing for
 * every object and live in the common tier. entry_rva does stay, because an RVA
 * is only meaningful against this format's load layout.
 */
struct kof_pe_info {
	uint32_t version;      /* KOF_PE_INFO_VERSION the parser filled */
	uint32_t valid;        /* non-zero if MZ and PE\0\0 both matched; facts may
				* still be partial, see anomalies */

	uint8_t  pe32_plus;    /* 1 for PE32+, 0 for PE32 */
	uint8_t  _pad0[3];

	uint16_t machine;
	uint16_t characteristics;
	uint32_t timestamp;

	uint64_t lfanew;       /* where the NT headers start */
	uint64_t stub_len;     /* lfanew - 0x40, the gap the loader ignores */

	uint16_t opt_magic;
	uint16_t opt_size;     /* SizeOfOptionalHeader, as declared */
	uint16_t nsec;         /* after clamping */
	uint16_t nsec_claimed; /* what the header said */

	uint64_t entry_rva;
	uint32_t entry_sec;    /* index into sec[], or nsec if none contains it */
	uint32_t entry_perm;   /* KOF_PE_PERM_* of that section, 0 if none */

	uint64_t image_base;
	uint64_t size_of_image;
	uint64_t size_of_headers;   /* as declared */
	uint64_t header_end;        /* as computed from lfanew and nsec */

	uint64_t section_align, file_align;

	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint32_t n_dirs;            /* NumberOfRvaAndSizes, after clamping */

	/*
	 * The linker's summary. Published so a module can hold it against the
	 * section table, which is the only cross-check PE offers - see the note at
	 * the top of this file.
	 */
	uint64_t base_of_code, size_of_code;
	uint64_t size_of_init_data, size_of_uninit_data;

	/*
	 * The certificate table, already resolved. Its directory entry stores a
	 * file offset where every other directory stores an RVA, and that single
	 * exception is exactly the kind of thing every caller would otherwise have
	 * to remember.
	 */
	uint64_t cert_off, cert_len;

	/* Past the last byte any section, header or certificate claimed. */
	uint64_t overlay_off, overlay_len;

	/* The resource directory as a file range, already resolved from its RVA.
	 * Zero length when the directory is absent or does not resolve. */
	uint64_t res_off, res_len;

	uint64_t anomalies;

	uint32_t sec_count;
	uint32_t _pad1;
	struct kof_pe_dir dir[KOF_PE_DIR_COUNT];
	struct kof_pe_sec sec[KOF_PE_MAX_SECTIONS];
};

/*
 * The PE view of the object under scan.
 *
 * Sound because the module declared KOF_FMT_PE and the host does not run a module
 * against a format its target does not cover.
 */
static inline const struct kof_pe_info *kof_pe(const struct kof_obj_ctx *ctx)
{
	return (const struct kof_pe_info *)ctx->file_header;
}

/*
 * Turn an RVA into a file offset.
 *
 * KOF_BROKEN when no section contains it, which is a thing hostile files arrange
 * deliberately: a directory pointing outside every section, or sections whose
 * virtual ranges leave holes. Answering with a guess would make every caller's
 * bounds check meaningless, so this answers that it does not know.
 *
 * An RVA inside a section's virtual range but past its raw size is also
 * KOF_BROKEN: those bytes exist at runtime and are absent from the file, so there
 * is no offset to give.
 */
static inline uint64_t kof_pe_rva_to_off(const struct kof_pe_info *p, uint64_t rva)
{
	uint32_t i;

	if (!p || !p->valid)
		return KOF_BROKEN;
	for (i = 0; i < p->sec_count; i++) {
		const struct kof_pe_sec *s = &p->sec[i];
		uint64_t span = s->mem_size > s->file_size ? s->mem_size
							   : s->file_size;
		if (rva < s->mem_rva || rva - s->mem_rva >= span)
			continue;
		if (rva - s->mem_rva >= s->file_size)
			return KOF_BROKEN;      /* mapped, not present in the file */
		return s->file_off + (rva - s->mem_rva);
	}
	return KOF_BROKEN;
}

#endif /* KOFENG_PE_H */