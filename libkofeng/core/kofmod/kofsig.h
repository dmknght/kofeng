/*
 * kofsig.h - the ABI between the host and a signature module.
 *
 * Including this header declares the translation unit to be a signature module.
 * A module:
 *
 *   - exports exactly one entry point, kof_scan()
 *   - reaches the engine only through the scan context it is handed
 *   - never refers to anything outside its own blob by symbol
 *   - has no writable data (.data / .bss)
 *   - is position independent
 *
 * No external symbols means nothing to resolve at load time, so loading is a copy
 * and an mprotect. No writable data means one mapped copy serves every thread.
 * build.sh enforces all of it on the object.
 *
 * A consequence to know before writing a module: string literals are fine, arrays
 * of pointers to them are not - those land in .data.rel.ro with relocations against
 * them. Where a list is needed, use one NUL separated literal.
 *
 * Format specific facts come from a format header (elf.h, later pe.h), and a module
 * may include exactly one: see kof_elf() in elf.h.
 */

#ifndef KOFENG_KOFSIG_H
#define KOFENG_KOFSIG_H

#include <stdint.h>

/*
 * ABI version. Append only: slots are never removed, reordered, or given new
 * meaning. The host refuses a module built against a newer version than its
 * own, which is why a module never has to check this itself - by the time it
 * runs, the guarantee already holds.
 */
#define KOFSIG_ABI_VERSION 1

/*
 * How strongly a finding is asserted.
 *
 * A level rather than a separate verdict, because the difference between "this is
 * the family" and "this looks like it" is a property of the finding and not of the
 * control flow. Both are reported the same way and named the same way, so there is
 * one mechanism and one table instead of two that must agree.
 */
enum kof_level {
	KOF_LVL_SUSPECT = 0, /* worth noting; not a detection */
	KOF_LVL_INFECT  = 1  /* the family is identified */
};

/*
 * Two sentinels for scalar facts, kept distinct because they lead to different
 * decisions. A script has no entry point at all, which is unremarkable; an ELF
 * that declares one the parser cannot resolve is a strong signal. A single
 * "unknown" value would throw that difference away.
 */
#define KOF_NA     UINT64_MAX          /* concept does not apply to this object */
#define KOF_BROKEN (UINT64_MAX - 1)    /* applies, but could not be determined */

/*
 * What the object is. Selects which format header's view applies, if any.
 *
 * Named for the format and not for where the bytes came from, because those are
 * different questions and only the first one is a module's business. An ELF in a
 * process image and an ELF on disk are the same format; the byte accessors
 * abstract over the source, so a module reading offsets works on either without
 * knowing which it got. Where they genuinely differ - a memory image has no
 * overlay, a file has no materialised .bss - the collector normalises coordinates,
 * and both answers are correct for the thing actually being scanned.
 *
 * Combining the two axes into values like MEM_ELF and FILE_ELF would multiply the
 * enum by source and force a new value per format for every source.
 */
enum kof_format {
	KOF_FMT_UNKNOWN = 0,
	KOF_FMT_ELF     = 1,
	KOF_FMT_PE      = 2,
	KOF_FMT_MACHO   = 3,
	KOF_FMT_SCRIPT  = 4,
	KOF_FMT_TEXT    = 5
};

/*
 * Architecture, normalised across formats.
 *
 * This is the only place a module can ask about architecture without importing
 * a format header, so the values must mean the same thing everywhere. Format
 * specific machine constants (EM_AARCH64, IMAGE_FILE_MACHINE_ARM64) stay in
 * their own headers: they are not comparable across formats, and pretending
 * otherwise would produce a shared enum that is wrong for every member.
 *
 * Width is derivable from the value, which is why there is no separate bits
 * field: arch implies width, width does not imply arch.
 */
enum kof_arch {
	KOF_ARCH_ANY     = 0,  /* does not apply: script, text, bytecode */
	KOF_ARCH_X86     = 1,
	KOF_ARCH_X86_64  = 2,
	KOF_ARCH_ARM     = 3,
	KOF_ARCH_ARM64   = 4,
	KOF_ARCH_RISCV64 = 5,
	KOF_ARCH_MIPS    = 6,
	KOF_ARCH_PPC64   = 7,
	KOF_ARCH_OTHER   = 255 /* recognised format, architecture not in this list */
};

/*
 * Names for the two common enums, next to the enums themselves.
 *
 * Here because more than one place needs them and they are the only correct spelling:
 * a finding is labelled with them and so is a fact dump, and two copies drift. They
 * were duplicated in the scanner and in kofdump before this.
 *
 * Inline rather than a .c file: they are switch statements over an enum this header
 * already declares, so anything that has the enum has all it needs.
 */
static inline const char *kof_format_name(uint8_t fmt)
{
	switch (fmt) {
	case KOF_FMT_ELF:    return "ELF";
	case KOF_FMT_PE:     return "PE";
	case KOF_FMT_MACHO:  return "MachO";
	case KOF_FMT_SCRIPT: return "Script";
	case KOF_FMT_TEXT:   return "Text";
	default:             return "Unknown";
	}
}

static inline const char *kof_arch_name(uint8_t arch)
{
	switch (arch) {
	case KOF_ARCH_X86:     return "x86";
	case KOF_ARCH_X86_64:  return "x86_64";
	case KOF_ARCH_ARM:     return "arm";
	case KOF_ARCH_ARM64:   return "arm64";
	case KOF_ARCH_RISCV64: return "riscv64";
	case KOF_ARCH_MIPS:    return "mips";
	case KOF_ARCH_PPC64:   return "ppc64";
	case KOF_ARCH_ANY:     return "any";
	default:               return "other";
	}
}

/*
 * Which part of the object to search.
 *
 * A module names a region and never computes a range, which removes the class of bug
 * where an expression like "sec->file_size - 0x40" underflows on a small section.
 *
 * Only KOF_SCAN_ALL is defined here: it is the only region that means the same thing
 * for every input. The rest are named by the format header, because the parts of an
 * object are a property of its format - ELF has three header structures at both ends
 * of the file, a PE has a DOS stub and NT headers, and one shared "header" name
 * would have to be re-read as something different per format.
 *
 * Each format numbers its own bits from 1, so values collide between formats. Safe
 * for the same reason the kof_elf() cast is safe: naming KOF_SCAN_ELF_* requires
 * including elf.h, and the build rejects a module that includes a format header
 * without declaring that format as its target.
 *
 * Region ids are bits, so they compose: KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA is the
 * union. The host resolves a mask to ranges sorted and coalesced, so a pattern lying
 * across the join between two adjacent regions is found. A format should define its
 * regions as a partition of the object; then OR-ing any set of bits scans no byte
 * twice and leaves none unreachable. Bits with no region behind them are ignored,
 * because the mask reaches the host as bytes out of a database.
 *
 * The ranges are filled by whichever parser identified the object, since working out
 * where the code is is format specific work and the parser already has the tables.
 */

/* A resolved range. len == 0 means the extent is empty. */
struct kof_range {
	uint64_t off;
	uint64_t len;
};

/*
 * Resolving a mask produces a list of ranges, not one range: a single bounding range
 * was measured at 89% of the file for data on a modern four-load layout, which made
 * it a superset of code.
 *
 * Nothing is stored. Ranges are computed from the parsed segment and section tables
 * on each call - those are already resident and hold every fact needed, so a stored
 * copy would be a cache able to disagree with its source. Computing also lets the
 * buffer be sized to the format's worst case, so extents are never merged to fit.
 *
 * This is the bound on that buffer. A resolver that would exceed it must coalesce,
 * never drop: overshooting a range loses precision, dropping one loses a detection.
 */
#define KOF_SCAN_MAX_EXTENTS 256

/* The whole object. The host answers this without a parser, so a module naming only
 * this region works on input nothing has identified. */
#define KOF_SCAN_ALL (1u << 0)

/*
 * Bounded reads over the object under scan, addressed by offset from its start.
 *
 * Deliberately not a pointer to the bytes:
 *
 *   - a module cannot read out of bounds through a call that checks, so the
 *     untrusted surface collapses to these few functions
 *   - the addressing model survives a change of source: when input arrives as a
 *     stream the host implements these differently and no module changes
 *   - hot loops stay on the host side, optimised once
 *
 * An out of range read yields zero rather than faulting. A module that needs to tell
 * "zero byte" from "past the end" compares against obj_size first.
 */
struct kof_obj_ctx;

struct kof_content {
	uint8_t  (*rd8) (const struct kof_obj_ctx *, uint64_t off);
	uint16_t (*rd16)(const struct kof_obj_ctx *, uint64_t off);
	uint32_t (*rd32)(const struct kof_obj_ctx *, uint64_t off);
	uint64_t (*rd64)(const struct kof_obj_ctx *, uint64_t off);

	int      (*memeq)(const struct kof_obj_ctx *, uint64_t off,
			  const void *pat, uint32_t len);

	/*
	 * Look for a declared string in a declared range. Non-zero if present.
	 *
	 * Both arguments are indices the build assigned to KOF_DEFINE_STR and
	 * KOF_DEFINE_RANGE, so the pattern bytes are neither here nor in the blob:
	 * the host holds them in the record beside it. Reached through kof_find_str.
	 *
	 * A call rather than a precomputed bit, so the host is free to answer from a
	 * table it filled in one batched pass or to search on the spot and remember.
	 * The module cannot tell, so batching stays a host side decision.
	 */
	int (*find_str)(const struct kof_obj_ctx *, uint32_t str_id,
			uint32_t range_id);

	uint32_t (*csum)(const struct kof_obj_ctx *, uint64_t off, uint32_t len);
};

/*
 * Everything a module knows about the object it was asked about.
 *
 * The common tier holds only what means the same thing for every kind of
 * object. entry_off qualifies: it is an offset into the object for anything
 * executable and KOF_NA for anything that is not. e_type does not, because
 * ET_DYN is an ELF concept, so it lives in the ELF view.
 *
 */
struct kof_obj_ctx {
	uint8_t  format;      /* enum kof_format */
	uint8_t  arch;        /* enum kof_arch */
	uint8_t  reserved[2];

	uint64_t obj_size;
	uint64_t entry_off;   /* KOF_NA if not applicable, KOF_BROKEN if unresolved */

	/*
	 * Turn a region mask into the ranges it names: sorted by offset, touching or
	 * overlapping ranges coalesced, clipped to the object. Returns how many were
	 * written, 0 if the mask names nothing present.
	 *
	 * Set by whichever parser identified the object, and reached through this
	 * pointer so the host never dispatches on format. NULL when nothing
	 * identified the object; only KOF_SCAN_ALL is answerable then, and the host
	 * answers that itself. Unrecognised bits are ignored, not refused.
	 */
	uint32_t (*resolve_scan)(const struct kof_obj_ctx *ctx, uint32_t scan_mask,
				 struct kof_range *out, uint32_t max_out);

	/*
	 * The parsed structure for format, or NULL if the format has none.
	 * A void pointer so that adding a format neither widens this struct nor
	 * puts a pointer in front of every module that will never use it.
	 * Modules do not name it: they call the accessor their format header
	 * provides, so its type and layout stay internal.
	 */
	const void *file_header;

	/* Byte level access to the object. */
	const struct kof_content *content;



	/*
	 * Attach a finding: a level, and an index into the name table the build
	 * emitted beside the blob.
	 *
	 * The name string never enters the blob. A family gets renamed on
	 * reclassification far more often than its logic changes, and resolving
	 * through a table fails visibly - a stale table yields "unknown" rather than
	 * some other family's name. The authored name is only the family part; the
	 * host prefixes the format and architecture it already established.
	 *
	 * Called through KOF_MATCH, so reporting and returning cannot come apart.
	 */
	void (*report)(const struct kof_obj_ctx *ctx, uint32_t level,
		       uint32_t name_id);

	/* Host state the accessors need. Opaque, and no module has any reason to
	 * touch it; it is here so the accessors can take the context rather than
	 * reach for a global, which keeps them usable from more than one thread. */
	const void *priv;
};

/*
 * Entry point. Defined by the module, called by the loader.
 *
 * The linker script places it first, so its offset inside the blob is zero and
 * the loader needs no symbol table at runtime. Other module roles will follow
 * the same pattern with their own header and their own entry: kof_unpack() from
 * kofunp.h, kof_cure() from kofcure.h.
 */
/*
 * Entry point. Defined by the module, called by the loader.
 *
 * Returns nothing. A module's output is what it reports, so there is no verdict
 * to return, and a module with nothing to say simply ends - which is why no
 * trailing "return clean" has to be written. Bailing out early is a bare return.
 *
 * The linker script places this first, so its offset inside the blob is zero and
 * the loader needs no symbol table at runtime.
 */
void kof_scan(const struct kof_obj_ctx *ctx);

/*
 * Look for a declared string in a declared range.
 *
 *     if (kof_find_str(ctx, busybox, loaded)) ...
 *
 * Both names resolve through identifiers the generator defines from the
 * KOF_DEFINE_STR and KOF_DEFINE_RANGE declarations, which the build injects. A name
 * that was never declared is an undefined identifier at compile time rather than a
 * lookup that quietly returns false - the failure mode to want, since a signature
 * that silently never matches looks exactly like one that works.
 *
 * No search happens in the module: the host owns the literals and answers this,
 * which is what allows one pass over the object to serve every module.
 */
#define KOF_PASTE2(a, b) a##b
#define KOF_PASTE(a, b)  KOF_PASTE2(a, b)

#define kof_find_str(ctx, str_name, range_name)                    \
	((ctx)->content->find_str((ctx),                           \
		KOF_PASTE(kof_strid_, str_name),                   \
		KOF_PASTE(kof_rangeid_, range_name)))

/*
 * Declare which object formats this module applies to.
 *
 *     KOF_TARGET(KOF_FMT_ELF);
 *
 * Expands to nothing; the build reads it out of the source and the host will not
 * invoke a module for an object outside its target. That is what lets a module skip
 * checking the magic itself.
 *
 * Separate from including a format header: those answer different questions - what
 * the module applies to, and whether it reads that format's parsed facts. More than
 * one format may be named only when no format header is included, because kof_elf()
 * casts ctx->file_header and a module that never casts has nothing to get wrong.
 */
#define KOF_TARGET(mask)

/*
 * Declared preconditions: things the host can check without running the module.
 *
 *     KOF_FILESIZE_MIN(1024);
 *     KOF_REQUIRE_ARCH(KOF_ARCH_X86_64 | KOF_ARCH_ARM_BIT);
 *
 * Both expand to nothing and both work the same way KOF_TARGET does: the build
 * reads them out of the source into the record beside the blob, and the host
 * evaluates them against facts the collector already produced. A module whose
 * preconditions fail is never entered, so it costs a few integer comparisons
 * against an index entry instead of a call and a scan.
 *
 * Declaring rather than coding the check is what makes it a filter. The same test
 * written inside kof_scan is correct and useless for filtering: the host has to run
 * the module to reach it, which is the cost the filter exists to avoid. This is the
 * distinction between pre-use and in-use filtering, and it is the reason a
 * precondition has to live outside the code.
 *
 * The consequence is that a declared precondition must not also be written in the
 * body. Two copies of one condition are two things that can disagree, and the
 * declaration is the one the host trusts. The build rejects a body check that
 * duplicates a declaration where it can recognise one.
 *
 * Only cheap, always-available facts belong here - size, format, architecture.
 * Anything that needs bytes read or a decision made stays in kof_scan, where the
 * full language is available. A precondition language rich enough to express real
 * logic would be a second, worse programming language, which is the trap this whole
 * design exists to avoid.
 */
/*
 * Preconditions the host checks without running the module, so a module that fails
 * one costs a few integer comparisons against an index entry instead of a call.
 * Declaring rather than coding the check is what makes it a filter: the same test
 * inside kof_scan is correct and useless, because reaching it costs what filtering
 * saves.
 *
 * Both are optional, and declaring nothing constrains nothing. The default has to
 * fall that way: an unconstrained module runs, so a missing declaration costs time,
 * while a wrongly assumed constraint costs detections silently.
 *
 * A minimum size only, and no maximum, deliberately. A file cannot be smaller than
 * the content it carries, so a lower bound holds however a sample is built; an upper
 * bound is escaped by appending bytes nothing reads, which would turn padding into a
 * way to have the module skipped entirely. A module that wants an upper bound writes
 * it against ctx->obj_size in its own body, where it reads as its own logic rather
 * than as engine level filtering.
 */
#define KOF_FILESIZE_MIN(min)
#define KOF_REQUIRE_ARCH(mask)

/*
 * How a declared string is compared.
 *
 * Both states are named, including the default, because a call site that spells out
 * "exact" is readable on its own while one that relies on a zero has to be checked
 * against the header. The names are the ones a signature author already knows from
 * other engines rather than the ones the implementation uses internally.
 */
enum kof_str_case {
	KOF_CASE_EXACT = 0,   /* bytes compared as written */
	KOF_CASE_ICASE = 1    /* ASCII A-Z and a-z treated as equal */
};

/*
 * Whether a match has to stand alone.
 *
 * A word byte is [A-Za-z0-9_], the same class other engines use. KOF_WORD_FULLWORD
 * requires that the bytes on both sides of a match are not word bytes, so
 * "/bin/sh" does not match inside "/bin/shX".
 *
 * "Word" is a text notion and an object under scan is not text, so the reason this
 * works at all in a binary is that C strings are NUL separated and NUL is not a
 * word byte. Where that does not hold - a length prefixed string, a packed table -
 * KOF_WORD_FULLWORD will behave in ways that are correct by this definition and
 * surprising in context.
 *
 * The edge of the searched region counts as a boundary. Without that rule the
 * obvious implementation reads the byte before the match, which at offset zero
 * reads outside the object.
 */
enum kof_str_word {
	KOF_WORD_SUBSTRING = 0,  /* match anywhere */
	KOF_WORD_FULLWORD  = 1   /* neither neighbour is a word byte */
};

/*
 * Name a set of regions.
 *
 *     KOF_DEFINE_RANGE(loaded, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);
 *
 * Named so the build can turn it into an index, which is what lets kof_find_str
 * paste both ids from identifiers - it could not do that from an expression like
 * "A | B". A plain #define would work and read as a local implementation detail
 * rather than part of the declared shape of the signature.
 */
#define KOF_DEFINE_RANGE(name, scan_mask)

/*
 * Declare a string this module looks for.
 *
 *     KOF_DEFINE_STR(busybox, "/bin/busybox", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);
 *
 *     if (kof_find_str(ctx, busybox, loaded)) ...
 *
 * The literal and its comparison options are properties of the string, so they live
 * here. Where to look is not: the same marker can be worth looking for in different
 * places, so the range stays at the call site.
 *
 * Declaring the literal is what moves the search to the host. Three things follow:
 * the options compose instead of multiplying into one macro per combination; the
 * pattern bytes stay out of the blob, so retuning a literal is a data edit and
 * "strings" on a blob reveals nothing; and the host knows every pattern before it
 * runs anything, so it can answer all of them - across every module - in one pass
 * rather than one pass per module. Nothing about a module holding its own pattern
 * bytes can be batched away.
 *
 * At most KOF_MAX_STR_PER_MODULE strings and KOF_MAX_RANGE_PER_MODULE ranges.
 */
#define KOF_DEFINE_STR(name, lit, casing, word)

/*
 * Report a finding and stop.
 *
 *     KOF_MATCH(ctx, "Mirai.Generic", KOF_LVL_INFECT);
 *
 * The name id is the source line, which is why the string can be dropped from the
 * expansion: the build scans this source, reads the literal, and writes
 * "<line> <name>" into a table the host loads beside the blob. Same mechanism as
 * patterns, and the same failure mode - a table out of step with the blob shows up
 * as a missing name, never as a wrong one.
 *
 * Write only the family part. The host prefixes format and architecture, so
 * "Mirai.Generic" is reported as "ELF.x86_64.Mirai.Generic" without this module
 * naming a format it cannot be sure of.
 *
 * The report and the return are one statement so neither half can be forgotten.
 */
#define KOF_MATCH(ctx, name, level)                                    \
	do {                                                           \
		(ctx)->report((ctx), (uint32_t)(level), (uint32_t)__LINE__); \
		return;                                                \
	} while (0)

/*
 * ---------------------------------------------------------------------------
 * Compiled pattern format.
 *
 * Here rather than in a header of its own because it is the vocabulary of what a
 * declared pattern can be - literal now, hex with wildcards and gaps later - and that
 * vocabulary is part of what a signature is written in. The generator writes this form
 * and the matcher reads it; a module never sees it, because a module holds an index and
 * the host owns the bytes.
 *
 * Nothing in a compiled set is a pointer: fragments refer to their bytes by offset from
 * the start of the array. Today's generator emits only the simplest case. The rest is
 * defined now because changing a format later means changing every built blob, and
 * because multi-pattern search - one pass answering many strings - needs a shape to
 * carry them in.
 */

#define KOF_PAT_FORMAT_VERSION 1

/*
 * Caps on what one module may declare.
 *
 * The reason is the host's search memo, which is n_str x n_rng bytes per module: a
 * product, so both factors have to be bounded or one module with many of each costs
 * more than the rest of the database. At 64 each that is 4KB in the worst case and two
 * bytes in the common one.
 *
 */
#define KOF_MAX_STR_PER_MODULE   64
#define KOF_MAX_RANGE_PER_MODULE 64

/* Per-pattern flags. */
enum {
	KOF_PATF_IGNORE_CASE = 1u << 0, /* fold ASCII case on both sides */
	KOF_PATF_HAS_MASK    = 1u << 1, /* fragment data is val[] then mask[] */
	KOF_PATF_NEGATE      = 1u << 2, /* reserved: see note below */
	KOF_PATF_FULLWORD    = 1u << 3  /* neighbours must not be [A-Za-z0-9_] */
};

/*
 * KOF_PATF_NEGATE is reserved, not implemented. Declaring a pattern as must-not-match
 * lets the matcher stop the moment it finds one, which "!kof_find_str(...)" cannot
 * express - that has to scan the whole region to prove absence. Reserved now so
 * adding it later is not a format change.
 */

/*
 * Layout, all little endian, offsets from the start of the array:
 *
 *   0   u8    version        KOF_PAT_FORMAT_VERSION
 *   1   u8    npat           1 .. KOF_PAT_MAX_IN_SET
 *   2   u16   total_len      size of the whole array, for a self-check
 *   4   struct kof_pat_desc[npat]
 *   ..  struct kof_pat_frag[sum of nfrag]
 *   ..  fragment bytes
 *
 * Both tables are fixed size records so the matcher can index them without
 * walking, and a truncated or forged array fails the bounds check rather than
 * being followed.
 */
struct kof_pat_hdr {
	uint8_t  version;
	uint8_t  npat;
	uint16_t total_len;
};

struct kof_pat_desc {
	uint8_t  flags;      /* KOF_PATF_* */
	uint8_t  nfrag;
	uint16_t frag_off;   /* offset of this pattern's first kof_pat_frag */
};

/*
 * gap_min/gap_max are the distance allowed between the end of the previous
 * fragment and the start of this one. Both zero for the first fragment, and for
 * a plain literal, which is one fragment with no gap.
 */
struct kof_pat_frag {
	uint16_t gap_min;
	uint16_t gap_max;
	uint16_t data_off;   /* offset of this fragment's bytes */
	uint16_t data_len;   /* bytes of val; doubled on disk if HAS_MASK */
};

#endif /* KOFENG_KOFSIG_H */
