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
 * ksigbuilder enforces all of it on the object.
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
#define KOFSIG_ABI_VERSION 2

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
	KOF_LVL_INFECT  = 1, /* the family is identified */
	/*
	 * A shape clean software does not have, with nothing identified.
	 *
	 * Reported only by a heuristic rule - see kofmod/heur.h - and a detector
	 * that tried would be refused by the build. The value matches
	 * KOF_LEVEL_HEUR in kofeng.h because the host passes the module's level
	 * straight through; the two enums are one enum written twice, once for
	 * each side of the ABI.
	 */
	KOF_LVL_HEUR    = 2
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
	KOF_FMT_TEXT    = 5,
	KOF_FMT_GZIP    = 6,

	/*
	 * A document, and which encoding it arrived in.
	 *
	 * Two values rather than one with a sub-kind field, because the two are not
	 * one format written two ways - they differ in where the document's own
	 * structure lives. A DOCOLE holds its parts as streams INSIDE one object, so
	 * the parts are regions of it. A DOCZIP holds its parts as separate archive
	 * entries, so the parts are child objects and the discriminator is an entry
	 * name. A module written for one cannot run against the other, and format is
	 * what the prefilter rules on - so they are separate formats.
	 *
	 * DOCOLE is CFB, which is also what MSI and Outlook messages are. The name is
	 * narrower than the container on purpose: a format id is a prefilter gate,
	 * not the identity of a parser, so a future KOF_FMT_MSI can share every line
	 * of the CFB parse and still be ruled in and out on its own.
	 */
	KOF_FMT_DOCOLE  = 7,
	KOF_FMT_ZIP     = 8,
	KOF_FMT_DOCZIP  = 9,

	/*
	 * An archive with no compression in it at all.
	 *
	 * Its own format rather than a kind of ZIP because nothing about reading it
	 * is shared: no central directory, no methods, no end record - a stream of
	 * fixed blocks. It is here almost entirely because of what it arrives inside:
	 * 268 of 295 gzip files in the measured collection hold one.
	 */
	KOF_FMT_TAR     = 10,

	/*
	 * The archive that compresses its own file list.
	 *
	 * Its own format because nothing about reading it resembles the others: the
	 * layout is four numbers in a 32 byte header, the entries are described in a
	 * second header at the far end of the file, and that second header is itself
	 * put through a coder - so a parser can describe the container and not its
	 * contents. See sevenzip.h.
	 */
	KOF_FMT_7Z      = 11,

	/*
	 * The largest container in this collection by bytes, and two formats behind
	 * one magic.
	 *
	 * RAR keeps its file list in the clear the way a zip does - so names, sizes,
	 * ratios and the encryption flag all cost nothing - but compresses content
	 * with an algorithm this engine does not implement. RAR3 and RAR5 share the
	 * first six bytes and nothing else; which one an object is sits in
	 * ctx->subtype. See rar.h.
	 */
	KOF_FMT_RAR     = 12,

	/*
	 * The container that came free with a decoder written for another one.
	 *
	 * xz codes its blocks with LZMA2, which this engine grew in order to reach
	 * 7z content - so what was missing was never the decoding, only the twelve
	 * bytes at each end that say where the blocks are. See xz.h.
	 */
	KOF_FMT_XZ      = 13,

	/*
	 * The first format here that is syntax rather than structure.
	 *
	 * RTF has no offsets: where anything sits is decided by reading forward
	 * through braces and control words. What makes it worth reading is what it
	 * carries - an embedded object arrives hex encoded after \objdata, and
	 * decoding it usually yields a compound file this engine already opens.
	 * See rtf.h.
	 */
	KOF_FMT_RTF     = 14,
	KOF_FMT_PDF     = 15,

	/*
	 * WHAT A DOCUMENT DRAWS WITH, AND WHY THESE TWO ARE FORMATS AT ALL.
	 *
	 * A format is one value per kind of thing a rule can be written about -
	 * that is the line this enum is drawn on, and it is why an event is in
	 * here. A rasteriser program and a compressed bitmap are both things a
	 * rule can be written about: a malicious OpenType file is a real
	 * object, and so is a JBIG2 stream aimed at a decoder bug.
	 *
	 * THEY EXIST SO THAT NOTHING OPENS THEM UNTIL SOMETHING WANTS TO, and
	 * that follows from what a format already does rather than from any new
	 * policy. A format GATES: a module is offered an object only when
	 * target_mask names its format. So a child declared KOF_FMT_FONT with
	 * no rule in the database targeting fonts is a child that will be
	 * produced - inflated, copied, charged to the budget - and then handed
	 * to nobody. The gate has already said no; fmt_wanted below is that
	 * same no, asked before the work instead of after it.
	 *
	 * THE DAY SOMEBODY WRITES THE RULE, the work starts happening again,
	 * with no engine change and no policy table anywhere: one
	 * KOF_TARGET_FORMAT(KOF_FMT_FONT) in a signature source is the whole
	 * of it. That is the difference between this and a skip list - a skip
	 * list has to be edited by whoever notices, and this is answered by the
	 * database that would have done the looking.
	 *
	 * MEASURED, on an ordinary 302KB document: 267KB of it - 88% - is font
	 * programs, and every byte was being inflated and scanned for rules
	 * that could not match. Images are the same argument and larger still;
	 * see KOF_SCAN_PDF_RESOURCE_IMAGE in kofmod/pdf.h for that measurement.
	 *
	 * A PARSER DECLARES THESE, and only from its own structure - /Subtype
	 * /Image says it, a /FontFile reference says it. Where the structure
	 * does not say, the answer stays KOF_FMT_UNKNOWN, which means "I will
	 * not say" and is always opened. Guessing here would hide a payload by
	 * calling it a picture, which is the one mistake this must not make.
	 */
	KOF_FMT_IMAGE   = 16,
	KOF_FMT_FONT    = 17,

	/*
	 * ONE COLLECTED EVENT, not a file.
	 *
	 * The object is one collected event - what a collector saw happen, with
	 * the submitted content inside it.
	 *
	 * The engine does not read that record's layout and cannot: it belongs
	 * to libkoforbit, which sits outside. What reaches a parser here is a
	 * buffer plus the caller's word for where the content is - see
	 * amsi_parse.h. It is a format here for the same
	 * reason every other value is: format is what the prefilter rules on, so
	 * a rule written about a script submission is never offered an ELF and
	 * an ELF rule is never offered an event.
	 *
	 * It is DECLARED, NOT SNIFFED. Every format above is recognised from its
	 * bytes; a record has no magic, and guessing "this 512 bytes is an
	 * event" from plausible-looking fields would claim arbitrary data as
	 * one. Whoever has the record knows what it is - the client that read it
	 * off the channel, the viewer that opened the log - and says so.
	 *
	 * AMSI rather than EVENT because the regions are AMSI's: a submission
	 * and the fields around it. A verb with a different shape worth writing
	 * rules against gets its own value and its own regions, the same way
	 * DOCOLE and DOCZIP are two formats rather than one with a sub-kind.
	 * A NetRecv rule, for instance, is a comparison of ADDRESSES rather
	 * than a search through bytes, so it wants a different shape again.
	 *
	 *
	 * KOF_EVT_ AND NOT KOF_FMT_, AND THE NAME IS NOT COSMETIC.
	 *
	 * This sits in enum kof_format because format is the axis the prefilter
	 * rules on - one value per kind of thing a rule can be written about,
	 * so an event is never offered to an ELF module and an ELF is never
	 * offered to this one. That is the mechanism and it does not change.
	 *
	 * But what an author DECLARES is the kind of event, so that is what
	 * they write. A signature reading KOF_TARGET_EVENT(KOF_EVT_AMSI) says
	 * what it is about; the same rule spelled as a "format" would be asking
	 * an author to call a submission a file format.
	 *
	 * NOT TO BE CONFUSED WITH KOF_EVT_AMSI_SCAN, which is a VERB - what one
	 * record says happened. This is what a RULE targets. They are one to
	 * one today and they are not the same axis: verbs are the collector's
	 * vocabulary and grow as it learns event ids, targets grow only when
	 * there is a shape worth writing rules against.
	 *
	 * WHO MAPS ONE TO THE OTHER is the CLIENT, not the engine. A verb is
	 * libkoforbit's vocabulary and this is the engine's; whoever holds a
	 * record and wants it scanned knows both, and it is the only side that
	 * does. The engine deliberately cannot name a verb - see the note in
	 * amsi_parse.h on which way that arrow points.
	 */
	KOF_EVT_AMSI    = 19,

	/*
	 * One past the last FILE FORMAT, so a host can size a per-format table.
	 * Not a format: nothing is ever this.
	 *
	 * It stops at the file formats on purpose. Event targets are numbered
	 * above them - see KOF_TARGET_FIRST_EVENT - so this is no longer the
	 * width of the axis, and anything sizing an array by target value wants
	 * KOF_TARGET_BITS instead.
	 */
	KOF_FMT_COUNT   = 18
};

/*
 * WHERE EVENT TARGETS START, AND WHY THE BOUNDARY IS DECLARED.
 *
 * An event target's value IS its verb - KOF_EVT_AMSI is KOF_EVT_AMSI_SCAN, the
 * same number - so the byte a client filters records on is the byte the
 * prefilter rules modules on, and the two cannot drift apart because they are
 * one number.
 *
 * That only works while no verb collides with a file format, and verbs start at
 * 1: KOF_EVT_PROC_START would be KOF_FMT_ELF. So the low half of the axis
 * belongs to file formats and the high half to verbs, and every event target
 * asserts that it is above the line (see kofevt.h). A verb below it simply
 * cannot be given a target until the boundary moves.
 *
 * THE AXIS IS 32 VALUES WIDE AND THAT IS A HARD CEILING: a module's target is a
 * uint32 MASK in the pack, because a module may target more than one thing.
 * Eighteen are spent on file formats and fourteen are left for events - which is
 * ample, because a target is needed per RULE SHAPE and not per verb, and most
 * verbs will never have one.
 *
 * THE LINE MOVED ONCE, 16 to 18, when KOF_FMT_IMAGE and KOF_FMT_FONT were
 * added. What that costs is two of the fourteen values left for verbs, and
 * what it requires is that no event target is below the new line: the only one
 * is KOF_EVT_AMSI at 19, and every event target asserts it is above the line
 * (see kofevt.h), so moving it is checked rather than assumed. Moving it again
 * is the same two steps.
 */
#define KOF_TARGET_FIRST_EVENT 18u
#define KOF_TARGET_BITS        32u

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
/*
 * THE LIST, ONCE.
 *
 * Written as a macro rather than an enum body because four things need it and
 * only one of them is the enum: a finding prints the short word, a signature
 * source writes KOF_ARCH_X86_64 and the builder has to turn that back into a
 * value, an editor offers the set to pick from, and the build script used to
 * keep an eleventh-hand copy of its own.
 *
 * That copy is why this is a macro now. It listed the architectures in order
 * and matched them as substrings, so KOF_ARCH_X86 - a PREFIX of KOF_ARCH_X86_64
 * - set both bits, and every x86-64-only rule also ran on x86 objects. It had
 * also stopped three architectures short of this list. Neither could be caught
 * by a compiler while the list existed twice.
 *
 * X(NAME, value, short word). The short words are kept to the width of the
 * thing they describe rather than spelled out; x86 and x64 keep their
 * conventional spellings because those are what everyone already reads, and the
 * rest follow the same shape so the set can be scanned at a glance.
 */
#define KOF_ARCH_LIST(X)                                                     \
	X(KOF_ARCH_ANY,     0,  "any")   /* script, text, bytecode */        \
	X(KOF_ARCH_X86,     1,  "x86")                                       \
	X(KOF_ARCH_X86_64,  2,  "x64")                                       \
	X(KOF_ARCH_ARM,     3,  "a32")                                       \
	X(KOF_ARCH_ARM64,   4,  "a64")                                       \
	X(KOF_ARCH_RISCV64, 5,  "r64")                                       \
	X(KOF_ARCH_MIPS,    6,  "m32")                                       \
	X(KOF_ARCH_PPC64,   7,  "p64")                                       \
	X(KOF_ARCH_MIPS64,  8,  "m64")                                       \
	X(KOF_ARCH_PPC,     9,  "p32")                                       \
	X(KOF_ARCH_RISCV32, 10, "r32")

enum kof_arch {
#define KOF_ARCH_X_ENUM(name, val, word) name = val,
	KOF_ARCH_LIST(KOF_ARCH_X_ENUM)
#undef KOF_ARCH_X_ENUM
	KOF_ARCH_OTHER   = 255 /* recognised format, architecture not in this list */
};

/* How many the list names, which is not the largest value: OTHER is outside it
 * on purpose. A mask has one bit per member, so this is also its width. */
#define KOF_ARCH_COUNT 11u

/* strcmp, spelled out: this header is included by rule sources that get no
 * libc, and one identifier comparison does not justify the dependency. */
static inline int kof_streq_(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

/*
 * Names for the two common enums, next to the enums themselves.
 *
 * Here because more than one place needs them and they are the only correct spelling:
 * a finding is labelled with them and so is a fact dump, and two copies drift. They
 * were duplicated in the scanner and in the examiner before this.
 *
 * Inline rather than a .c file: they are switch statements over an enum this header
 * already declares, so anything that has the enum has all it needs.
 */
/*
 * THE WAY BACK: the identifier a signature source writes, to its value.
 *
 * The sibling of kof_arch_from_name and kof_maltype_from_name, and it was the
 * one missing. Its absence had a cost that was not obvious: the database
 * builder needed format identifiers resolved, could not ask the engine, and
 * so read this header with sed - a shell regex over C source, learning enum
 * values by matching "KOF_FMT_\([A-Z0-9_]*\) *= *\([0-9]*\)". That works
 * until a value is written as an expression, a comment mentions one, or the
 * enum is reformatted, and it fails by producing a WRONG MASK rather than an
 * error.
 *
 * KOF_FMT_ANY is not here. It is not a format, it is every format at once, and
 * the caller that accepts it has to turn it into a mask rather than a value.
 */
static inline int kof_format_from_name(const char *s, uint8_t *out)
{
#define KOF_FMT_X_FROM(name, val)                                           \
	if (kof_streq_(s, #name)) { *out = (uint8_t)(val); return 1; }
	KOF_FMT_X_FROM(KOF_FMT_UNKNOWN, KOF_FMT_UNKNOWN)
	KOF_FMT_X_FROM(KOF_FMT_ELF,     KOF_FMT_ELF)
	KOF_FMT_X_FROM(KOF_FMT_PE,      KOF_FMT_PE)
	KOF_FMT_X_FROM(KOF_FMT_MACHO,   KOF_FMT_MACHO)
	KOF_FMT_X_FROM(KOF_FMT_SCRIPT,  KOF_FMT_SCRIPT)
	KOF_FMT_X_FROM(KOF_FMT_TEXT,    KOF_FMT_TEXT)
	KOF_FMT_X_FROM(KOF_FMT_GZIP,    KOF_FMT_GZIP)
	KOF_FMT_X_FROM(KOF_FMT_DOCOLE,  KOF_FMT_DOCOLE)
	KOF_FMT_X_FROM(KOF_FMT_ZIP,     KOF_FMT_ZIP)
	KOF_FMT_X_FROM(KOF_FMT_DOCZIP,  KOF_FMT_DOCZIP)
	KOF_FMT_X_FROM(KOF_FMT_TAR,     KOF_FMT_TAR)
	KOF_FMT_X_FROM(KOF_FMT_7Z,      KOF_FMT_7Z)
	KOF_FMT_X_FROM(KOF_FMT_RAR,     KOF_FMT_RAR)
	KOF_FMT_X_FROM(KOF_FMT_XZ,      KOF_FMT_XZ)
	KOF_FMT_X_FROM(KOF_FMT_RTF,     KOF_FMT_RTF)
	KOF_FMT_X_FROM(KOF_FMT_PDF,     KOF_FMT_PDF)
	KOF_FMT_X_FROM(KOF_FMT_IMAGE,   KOF_FMT_IMAGE)
	KOF_FMT_X_FROM(KOF_FMT_FONT,    KOF_FMT_FONT)
	KOF_FMT_X_FROM(KOF_EVT_AMSI,    KOF_EVT_AMSI)
#undef KOF_FMT_X_FROM
	return 0;
}

static inline const char *kof_format_name(uint8_t fmt)
{
	switch (fmt) {
	case KOF_FMT_ELF:    return "ELF";
	case KOF_FMT_PE:     return "PE";
	case KOF_FMT_MACHO:  return "MachO";
	case KOF_FMT_SCRIPT: return "Script";
	case KOF_FMT_TEXT:   return "Text";
	case KOF_FMT_GZIP:   return "Gzip";
	case KOF_FMT_DOCOLE: return "DocOLE";
	case KOF_FMT_ZIP:    return "Zip";
	case KOF_FMT_DOCZIP: return "DocZip";
	case KOF_FMT_TAR:    return "Tar";
	case KOF_FMT_7Z:     return "7z";
	case KOF_FMT_RAR:    return "RAR";
	case KOF_FMT_XZ:     return "xz";
	case KOF_EVT_AMSI:   return "AMSI";
	case KOF_FMT_RTF:    return "RTF";
	case KOF_FMT_PDF:    return "PDF";
	case KOF_FMT_IMAGE:  return "Image";
	case KOF_FMT_FONT:   return "Font";
	/*
	 * "Raw", not "Unknown", and the two are different answers.
	 *
	 * KOF_FMT_UNKNOWN is what an object HAS when no format header claimed
	 * it - a decrypted payload, a carved blob, the image an unpacker handed
	 * back. That is a bare binary, and it is a thing a rule can be written
	 * for. "Unknown" reads as "the engine could not tell", which is the
	 * default below: a format id this build has no name for, which is a
	 * fault rather than a fact.
	 *
	 * PDF was falling through to that default and reporting Unknown, so a
	 * PDF finding and a formatless one were spelled the same in a name and
	 * in a pack's filename.
	 */
	case KOF_FMT_UNKNOWN: return "Raw";
	default:             return "Unknown";
	}
}

/*
 * Short, and systematic: a letter for the family and the width.
 *
 * These end up in a finding, which is read in a log next to a path, so they are
 * kept to the width of the thing they describe rather than spelled out. x86 and x64
 * keep their conventional spellings because those are what everyone already reads;
 * the rest follow the same shape so the set can be scanned at a glance.
 */
static inline const char *kof_arch_name(uint8_t arch)
{
	switch (arch) {
#define KOF_ARCH_X_NAME(name, val, word) case name: return word;
	KOF_ARCH_LIST(KOF_ARCH_X_NAME)
#undef KOF_ARCH_X_NAME
	default: return "other";
	}
}

/*
 * The way back: the identifier a signature source writes, to its value.
 *
 * Whole names only - `s` must be the identifier and nothing more. Substring
 * matching is what broke this before, KOF_ARCH_X86 being a prefix of
 * KOF_ARCH_X86_64, so the comparison here is strcmp and the caller splits its
 * own tokens.
 *
 * Returns 1 and sets *out on a hit, 0 on an unknown name - never a sentinel
 * value, because every value in the enum is a legal architecture and there is
 * none left over to mean "no".
 */
static inline int kof_arch_from_name(const char *s, uint8_t *out)
{
#define KOF_ARCH_X_FROM(name, val, word)                                     \
	if (kof_streq_(s, #name)) { *out = (uint8_t)(val); return 1; }
	KOF_ARCH_LIST(KOF_ARCH_X_FROM)
#undef KOF_ARCH_X_FROM
	return 0;
}

/*
 * ---- WHAT A NAME MAY HOLD, AND WHAT A COMMENT MAY HOLD -------------------
 *
 * Both are here because both are part of the signature contract, and because
 * three places need each of them: ksigbuilder, which compiles a source and is
 * the authority; kofviewer, which writes one; and kofeditor, which reads one
 * back. A rule the panel accepts and the builder refuses is a file the tool
 * reported as written and nothing can load.
 */

/*
 * A FAMILY OR VARIANT NAME.
 *
 * Letters, digits, hyphen and underscore. Nothing else, and that is not
 * conservatism for its own sake: the name reaches a filesystem path (the
 * generated source is named after the family), a C string literal, and a
 * verdict line a person reads out. A dot used to be allowed, which put ".."
 * one keystroke from a path - the filename derivation strips it today, so this
 * closes the hole at the source rather than downstream of it.
 *
 * The length is the shortest of the three buffers that carry it, so a name any
 * one of them accepts is a name all of them accept.
 */
#define KOF_NAME_MAX 63u

static inline int kof_name_char(int c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static inline int kof_name_ok(const char *s)
{
	uint32_t n;

	if (!s || !s[0])
		return 0;
	for (n = 0; s[n]; n++) {
		if (n >= KOF_NAME_MAX)
			return 0;
		if (!kof_name_char((unsigned char)s[n]))
			return 0;
	}
	return 1;
}

/*
 * TEXT BOUND FOR A C COMMENT.
 *
 * `*` and `/` are refused outright rather than the pair `*​/` being looked for,
 * because C HAS NO ESCAPE FOR IT: a comment ends at the first `*​/` and nothing
 * a writer can emit prevents that. Guarding the pair is also not enough on its
 * own - anything that truncates the text, or that joins two pieces of it, can
 * put the two characters next to each other after the check has run.
 *
 * What goes through here is not the author's prose alone. It is the sample's
 * name, taken from a path on the command line; the researcher, taken from
 * $USER; and the "Created" date, which is READ BACK OUT OF a file's own comment
 * when a rule is reopened - so a crafted source can carry a payload that only
 * becomes code the next time the rule is generated.
 */
static inline int kof_comment_char(int c)
{
	return c >= 0x20 && c < 0x7f && c != '*' && c != '/';
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
/*
 * How many extents one region resolve may return.
 *
 * Sized from the worst real container rather than from what looked generous. It was
 * 256, which is ample for an executable - an ELF's CODE is a handful of ranges -
 * and nowhere near enough for an archive: a zip stores each entry's name between
 * two pieces of header, twice over, so its NAMES and HEADERS regions fragment at
 * roughly two runs per entry EACH. Measured over 280 archives the largest holds 991
 * entries, which is about four thousand runs, and at 256 the regions of nineteen of
 * them did not cover the file at all.
 *
 * The buffers this sizes live in the scanner rather than on the stack, which is what
 * makes a number this large affordable - see kof_scanner.
 *
 * It is still a bound, and a hostile archive will still exceed it. That is handled
 * rather than assumed away: a resolve that fills the buffer records a limit, so a
 * region that could not be described in full is never quietly searched in part.
 */
#define KOF_SCAN_MAX_EXTENTS 4096

/* The whole object. The host answers this without a parser, so a module naming only
 * this region works on input nothing has identified. */
#define KOF_SCAN_ALL (1u << 0)

/*
 * THE SYMBOL RECORDS, IN TWO HALVES - and unlike every region above, these are
 * not bytes of the file.
 *
 * kof_syms() hands back a block the host BUILT while parsing and cached for the
 * object (see kof_scanner). Naming it here is what lets a signature match a
 * symbol rather than match some bytes that happen to spell one, which is the
 * whole reason the KSYM layout exists: "inflateEnd" searched in DATA is any
 * occurrence of that string anywhere in the data, and searched in SYM_EXP it is
 * the claim that this file EXPORTS inflateEnd. The second is a far narrower
 * statement about the same ten bytes, and narrower is what a signature is for.
 *
 * Shared like KOF_SCAN_ALL rather than named per format, and for the same
 * reason: the block means the same thing for every input that has one. Both
 * builders fill one layout, so a rule scoped to SYM_IMP reads an ELF undefined
 * symbol and a PE import as the one claim they both are.
 *
 * FROM THE TOP, because format regions number upward from bit 1 and these must
 * never collide with a region a format adds later. The highest bit a format
 * uses today is 9 - PDF, whose stream regions are split by what the bytes ARE
 * rather than by how they are coded. It was 7 when this was written, so the
 * number is worth re-reading rather than trusting.
 *
 * The split is on KOF_SYM_F_UNDEFINED, and the extents cover RECORDS ONLY - the
 * block's own header is not searched. Its count and `_start` index change with
 * the file, so a pattern over them would be matching the host's bookkeeping
 * rather than anything the object says.
 */
/*
 * A FILE THIS OBJECT CARRIES AS A FILE - SHARED, BECAUSE IT IS NOT ONE
 * FORMAT'S IDEA.
 *
 * A PDF attaches an executable through /EF. A doczip IS a zip and every entry
 * in it is a carried file. An ELF can hold another ELF that a compiler put
 * there. The containers have nothing in common and the question does: "is this
 * a passenger rather than part of the document", and a rule that wants
 * passengers should not have to name one region per format to ask.
 *
 * Shared like KOF_SCAN_ALL and KOF_SCAN_SYM_*, and for the reason those give:
 * it means the same thing for every input that has one.
 *
 * INSIDE THE PARTITION, WHICH IS THE DIFFERENCE FROM SYM. The symbol halves
 * are an overlay - the host BUILT that block and its bytes are not the
 * object's, so nothing double counts when a mask names them beside a region.
 * A carried file's bytes ARE the object's, and they are already in one of its
 * regions. So this is not an overlay on top of those: it is the bit a format
 * assigns to its OWN carried-file class, through the same *_cls_bit[] table
 * that maps every other class to a region. One bit, one class per format, no
 * byte in two regions - which is the property every mask in this engine rests
 * on and an overlay would have quietly broken.
 *
 * FROM THE TOP for the same reason the symbol halves are: format regions
 * number upward from bit 1 and this must never collide with one a format adds
 * later.
 */
#define KOF_SCAN_EMBEDDED (1u << 29)

#define KOF_SCAN_SYM_IMP (1u << 30)
#define KOF_SCAN_SYM_EXP (1u << 31)
#define KOF_SCAN_SYM     (KOF_SCAN_SYM_IMP | KOF_SCAN_SYM_EXP)

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

/*
 * A region measured rather than read. See `region_shape` below.
 *
 * `widest` and `widest_off` describe ONE contiguous run and not the region: a
 * region is usually several, and the difference between "60% of this file is
 * unclaimed" and "60% of this file is unclaimed IN ONE PIECE" is the whole
 * signal. The first is true of ordinary binaries full of alignment padding; the
 * second is not true of any of them.
 */
struct kof_region_shape {
	uint64_t bytes;       /* every byte the region covers */
	uint64_t widest;      /* the longest single run in it */
	uint64_t widest_off;  /* where that run starts, in the object */
	uint32_t runs;        /* how many runs the region is */
	uint32_t reserved;
};

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
	 * KOF_TARGET_RANGE, so the pattern bytes are neither here nor in the blob:
	 * the host holds them in the record beside it. Reached through kof_find_str.
	 *
	 * A call rather than a precomputed bit, so the host is free to answer from a
	 * table it filled in one batched pass or to search on the spot and remember.
	 * The module cannot tell, so batching stays a host side decision.
	 */
	int (*find_str)(const struct kof_obj_ctx *, uint32_t str_id,
			uint32_t range_id);

	/*
	 * The same declared string, at an offset the module worked out.
	 *
	 * A different operation from find_str and priced differently: find_str_at
	 * is one comparison the length of the pattern, find_str_in searches an
	 * ad-hoc window. Neither resolves a region and neither is memoised, because
	 * the offset is a runtime value and there is nothing constant to key on.
	 *
	 * Both bounds check against the object. A module may hand over any offset -
	 * one read out of the file, one computed from it - and a comparison that
	 * walks off the mapping is the failure this layer exists to prevent.
	 */
	int (*find_str_at)(const struct kof_obj_ctx *, uint32_t str_id,
			   uint64_t off);
	int (*find_str_in)(const struct kof_obj_ctx *, uint32_t str_id,
			   uint64_t off, uint64_t len);

	uint32_t (*csum)(const struct kof_obj_ctx *, uint64_t off, uint32_t len);

	/*
	 * PRODUCING CHILD OBJECTS - unpack modules only.
	 *
	 * Both are NULL for a detector, the same way resolve_scan is NULL when
	 * nothing identified the object. A detect module that calls one gets
	 * nothing rather than a special case somewhere in the host, and the rule
	 * that only an unpacker produces is a property of the pointers rather than
	 * a check that could be forgotten.
	 *
	 * window() is the cheap one: a child that is already a contiguous range of
	 * this object - an overlay, a stored archive entry - costs no copy and no
	 * memory, because it is the parent's mapping seen through a different
	 * offset. It spends no byte budget, since nothing was produced; depth and
	 * the child count are what bound it.
	 *
	 * emit() is for bytes that did not exist before: decompressed output.
	 * It returns zero once the budget is gone, and a module must stop when it
	 * does. The budget is the host's and is checked here, at the write, rather
	 * than after a buffer has already been filled - by then the memory has been
	 * spent, which is the whole failure being prevented. Whether the output
	 * ends up in memory or in an unnamed temporary file is decided here too,
	 * and a module cannot tell.
	 *
	 * child() closes the object being emitted and starts the next.
	 *
	 * inflate() is emit() with a decoder in front of it: the module names a
	 * DEFLATE stream inside this object and the host decodes it straight into
	 * the sink. Output never crosses back into the module, so a bomb is refused
	 * by the same code that refuses an ordinary emit and the decoder stops the
	 * moment it is. Returns bytes produced.
	 *
	 * A host service for the reason find_str is one: the module supplies the
	 * decision - THIS range, THIS format - and the host does the work over the
	 * bytes. A decoder inside a module would pull its input one byte at a time
	 * through rd8, an indirect call per byte of a compressed stream, and every
	 * module that met a DEFLATE stream would carry its own copy of the decoder.
	 *
	 * Standard and shared belongs here; a transform peculiar to one family - an
	 * XOR key, a bespoke run encoding, a packer's own scheme - is the module's
	 * own business and is written with emit. That is why both exist.
	 */
	int (*window)(const struct kof_obj_ctx *, uint64_t off, uint64_t len);
	int (*emit)(const struct kof_obj_ctx *, const void *bytes, uint32_t n);
	int (*child)(const struct kof_obj_ctx *);

	/*
	 * `out_hint` is what the container SAYS the output will be, and it is a
	 * hint in the strict sense: it sizes a buffer and bounds nothing. The
	 * bounds are the host's budgets, which never read it.
	 *
	 * It exists because not every decoder can stream. DEFLATE bounds a back
	 * reference at 32KB, so inflate runs in fixed memory and ignores this.
	 * NRV2 bounds it at nothing - a match may reach any byte already produced
	 * - so its output has to be addressable in full while it decodes, and
	 * something has to decide how large that is before the first byte. A
	 * container that states the size is the only party that knows; a container
	 * that lies gets a buffer of the size it asked for, clamped to what the
	 * ceiling allows, and a decode that stops when it fills.
	 */
	uint64_t (*unpack)(const struct kof_obj_ctx *, uint32_t method,
			   uint64_t off, uint64_t len, uint64_t out_hint,
			   uint32_t form);

	/*
	 * Decode the front of a stream into the module's own buffer.
	 *
	 * The same decoders as `unpack`, writing where the caller can read
	 * instead of into the object being produced. It exists for the case
	 * where a container's layout is described by a header the container
	 * itself compressed: UPX writes a chain of blocks whose first one is
	 * the original ELF header and its program headers, and where the later
	 * blocks belong is written there and nowhere else. Without this a
	 * module can produce those bytes but never read them, so it can only
	 * lay the blocks end to end - which is wrong for every ELF whose
	 * segments are not adjacent.
	 *
	 * Bounded by `cap`, which is the caller's own buffer: nothing is
	 * allocated, so a length out of the object cannot size anything here.
	 * A back reference reaches only bytes already produced, so the first
	 * `cap` bytes decode the same whether or not the rest ever does.
	 *
	 * Returns bytes written - less than `cap` when the stream ends first,
	 * zero when nothing could be decoded.
	 */
	uint32_t (*unpack_peek)(const struct kof_obj_ctx *, uint32_t method,
				uint64_t off, uint64_t len,
				void *out, uint32_t cap);

	/* Where a declared string is, rather than whether. KOF_BROKEN if absent. */
	/*
	 * WHAT THE NEXT CHILD IS, when the producer knows.
	 *
	 * The companion of name_next and it works the same way: declared just
	 * before the child is made, consumed by the making, cleared whatever
	 * happens - so a claim can never be worn by the child after.
	 *
	 * A CLAIM AND NOT A GUESS. A container declares what its own structure
	 * told it: a PDF knows a stream is page content because /Contents said
	 * so. It must NOT declare what it would have to guess - the contents of
	 * an attachment are the sniff chain's business, and a wrong declaration
	 * runs the wrong parse and hides what the sniff would have found.
	 *
	 * KOF_FMT_UNKNOWN is a legitimate thing to declare and means exactly
	 * that: I will not say. It is also what happens if this is never
	 * called.
	 */
	void (*child_format)(const struct kof_obj_ctx *, uint8_t fmt);

	/*
	 * WHAT THE NEXT CHILD IS FOR - enum kof_entry_kind.
	 *
	 * Beside child_format and NOT the same thing. A format GATES: it decides
	 * which modules are offered the object, so naming one too precisely
	 * takes the object away from rules that would have seen it. A kind gates
	 * nothing. It says what the thing is for, which is what a policy reads
	 * and what a reader needs - and it is safe to state even when a format
	 * would not be.
	 *
	 * IT IS ALSO THE CHILD'S NAME WHEN NOTHING NAMED IT. name_next takes a
	 * range in the object, because a name is text the file already contains
	 * and a module has nowhere to build one - but most things a container
	 * carries have no name in them at all. A PDF page stream is not called
	 * anything; neither is a font program. Measured on one document, 12 of
	 * 14 recovered objects arrived anonymous, and a reader saw a column of
	 * identical rows. The kind is the honest name for those: not what it is
	 * called, but what it is.
	 */
	void (*child_kind)(const struct kof_obj_ctx *, uint32_t kind);

	/*
	 * WHICH ENTRY THE NEXT CHILD IS THE CONTENT OF.
	 *
	 * The third of the three declarations a producer makes before handing a
	 * child over, and the one that ties it back to what the parse said. A
	 * host can then show ONE row for a stream rather than two - the coded
	 * extent and the decoded content are one thing in two states, and
	 * without this nothing could tell that.
	 *
	 * The entry's OWN index, which is kof_entry.index - the format's number
	 * for it, not a position in the table. Producers that are not opening a
	 * declared entry - an emulator writing a payload, a packer peeling a
	 * stub - simply do not call this, and the child reports
	 * KOF_ENTRY_NONE.
	 */
	void (*child_entry)(const struct kof_obj_ctx *, uint32_t index);

	/*
	 * RUN AN ENTRY'S WHOLE CODING CHAIN AND HAND BACK THE CHILD.
	 *
	 * The host side of kof_entry.coding, and the reason that field is an
	 * array. A module cannot do this itself: a chain needs a buffer between
	 * its steps, and a module has no writable memory by design.
	 *
	 * `index` is the entry's OWN index - kof_entry.index, the format's
	 * number for it - not a position in the table.
	 *
	 * It refuses rather than half-decodes. An entry flagged
	 * KOF_ENT_F_CODED_UNKNOWN has a step this build cannot express, and
	 * running the steps it CAN express would produce bytes that are neither
	 * the coded form nor the original - so it reports UNSUPPORTED and makes
	 * nothing. Returns the bytes produced, zero when it produced none.
	 */
	uint64_t (*unpack_chain)(const struct kof_obj_ctx *, uint32_t index);

	uint64_t (*find_str_where)(const struct kof_obj_ctx *, uint32_t str_id,
				   uint64_t off, uint64_t len);

	/*
	 * Copy a named region into the object being produced, joined up.
	 *
	 * For the formats that scatter one logical thing across the file. A CFB
	 * stream is a chain of sectors in whatever order the allocator left them, so
	 * the region that names it is a list of extents rather than a range - and a
	 * pattern lying across the join between two of them is in neither extent. The
	 * only way to find it is to have the bytes contiguous, and the only way to
	 * have them contiguous is to copy.
	 *
	 * The module supplies the decision - THIS region - and the host does the work,
	 * for the same reason unpack() is shaped that way. Every byte goes through
	 * emit(), so the copy is charged to the same budget and stopped by the same
	 * ceiling as a decompression; there is no second pool and no way for a module
	 * to gather more than the host allows.
	 *
	 * `cap` is the module's own limit, applied on top of the host's and never
	 * above it: a format knows what an honest instance of it costs, and 4MB of
	 * macros is already far past anything a document has a reason to hold. Zero
	 * means the host's ceiling alone.
	 *
	 * Returns bytes emitted, which is short of the region when a cap bound. The
	 * module closes it with kof_child() - gathering does not, because a module may
	 * want more than one region in one child.
	 */
	uint64_t (*gather)(const struct kof_obj_ctx *, uint32_t region_mask,
			   uint64_t cap);

	/*
	 * Name the NEXT child this module produces.
	 *
	 * Given as a range in THIS object, never as a string: the name is already in
	 * the file - an archive entry name, a stored filename - so a module says
	 * where it is and the host reads it, which is the same idiom unpack() and
	 * find_str_where() use. A module has no writable data to build a string in
	 * anyway.
	 *
	 * One call rather than a named variant of each producer, because there are
	 * two ways to make a child - a window and an emit - and a format that stores
	 * some entries and compresses others uses both for entries that are named the
	 * same way. Stamping the next child covers both and covers whatever producer
	 * is added later.
	 *
	 * The host SANITISES what it reads, and that is not decoration. The name was
	 * written by whoever built the file and it ends up in a report, a log, maybe
	 * a web page: a terminal escape inside it can forge an entire output line,
	 * and a newline splits one record into two. A scanner that prints archive
	 * names verbatim is a scanner whose report is written by the thing it is
	 * scanning.
	 *
	 * Cleared once used, and cleared when the module returns - a name set for a
	 * child that was never produced does not drift onto the next one.
	 */
	void (*name_next)(const struct kof_obj_ctx *, uint64_t off, uint64_t len);

	/*
	 * "I stopped before I was finished."
	 *
	 * Every other way an object becomes incomplete is something the host can
	 * see: a budget spent, a ceiling reached, a decoder reporting a corrupt
	 * stream. This is the one it cannot - a module that met a compression
	 * method it does not implement, or a structure it stopped trusting, and
	 * returned early. Without it that object is reported CLEAN, which is the
	 * one verdict it must never get: the container was opened, part of it was
	 * read, and the rest was never looked at.
	 *
	 * It is deliberately not an error and does not stop anything. A module says
	 * what it managed and what it did not, and the host decides what that means
	 * for the object.
	 *
	 * The reason is the module's to give because the module is the only thing
	 * that knows it: the host can see a budget run out, and it cannot see that
	 * a packer used a compression method this build has never heard of.
	 */
	void (*incomplete)(const struct kof_obj_ctx *, uint32_t reason);

	/*
	 * Decode one entry of this object into the object being produced.
	 *
	 * Gather and decompress in one call, and the two are together because
	 * neither half is usable alone: `unpack` reads a CONTIGUOUS range of the
	 * object, and an entry's bytes are a chain - measured over 1322 streams in
	 * real documents, 23.6% are not consecutive. Joining first and decoding
	 * after would need somewhere to put the joined bytes, and the only place a
	 * module has is the child it is building, which is the output.
	 *
	 * `index` is into the format's own entry table, so what it means is the
	 * format's business; the host asks resolve_entry above and never reads a
	 * view itself.
	 *
	 * Returns bytes produced, and does not close the child - a module joining
	 * two entries into one object is a legitimate thing to want.
	 */
	uint64_t (*unpack_entry)(const struct kof_obj_ctx *, uint32_t method,
				 uint32_t index, uint64_t out_hint);

	/*
	 * The object's symbol records, in the KSYM layout kofmod/kofsym.h fixes,
	 * or NULL when it has none.
	 *
	 * A POINTER, not a reader like rd8 above, and the difference is
	 * deliberate. rd8 exists because the object's bytes may be mapped,
	 * spilled or windowed and a module must not hold a pointer into them.
	 * This block is neither: it is built on demand into storage the scanner
	 * owns for the length of the object, so handing it over directly costs
	 * nothing and lets a rule walk records with plain array indexing -
	 * which is the whole point of a fixed record length.
	 *
	 * Built at most once per object, and only if something asks.
	 */
	const uint8_t *(*syms)(const struct kof_obj_ctx *, uint32_t *nbytes);

	/*
	 * WHAT THE CODE DOES WITH A DATA ADDRESS.
	 *
	 * Built at most once per object, and only if something asks - one
	 * linear sweep of the executable sections, no more.
	 */
	uint32_t (*data_xref)(const struct kof_obj_ctx *, uint64_t va,
			      uint64_t size);

	/*
	 * WOULD ANYTHING LOOK INSIDE A CHILD OF THIS FORMAT.
	 *
	 * Asked by a producer BEFORE it spends the work, and it is the whole of
	 * smart deep scan on the engine's side.
	 *
	 * IT IS NOT A POLICY, IT IS THE GATE ASKED EARLY. A module is offered
	 * an object only when its target_mask names the object's format, so a
	 * child of a format no loaded rule targets is a child that will be
	 * produced and handed to nobody. The engine already knew that before
	 * the inflate started; this is how a producer can know it too. There is
	 * no list of kinds to open anywhere in the engine, and nothing to edit
	 * when a format is added - the answer comes from the DATABASE, so
	 * writing the rule is what turns the work back on.
	 *
	 * KOF_FMT_UNKNOWN IS ALWAYS WANTED, and that is the case that matters
	 * most rather than an exception to be tidied away. A carried file's
	 * contents are not known until it is opened, so refusing to open it
	 * because nothing targets "unknown" would be refusing to look at
	 * exactly the thing a container is used to hide.
	 *
	 * EVIDENCE OVERRIDES IT. A heuristic that fired on THIS object may ask
	 * for everything it carries to be opened - KOF_ENG_OPEN_CARRIED in
	 * kofmod/heur.h - and then this answers yes whatever the database
	 * targets. A document with an /OpenAction a rule recognised is worth
	 * opening the pictures of; a clean one is not. The ask is per object
	 * and cannot leak into the next, because it is recomputed from that
	 * object's own findings.
	 *
	 * ADVICE AND NOT A GATE: nothing refuses a child whose format this
	 * answered no for. A producer that asks saves its own work; one that
	 * does not spends it. Enforcing it at the push would be the bug this
	 * engine already had once - decompress everything, then drop the
	 * results on the floor - which is what --heur 0 used to do.
	 *
	 * Answers 1 when there is no answer to give (no database loaded), so a
	 * tool with no rules at all still opens what it finds.
	 */
	int (*fmt_wanted)(const struct kof_obj_ctx *, uint8_t fmt);

	/*
	 * THE SHAPE OF A REGION, WITHOUT ITS BYTES.
	 *
	 * Every other way a module reaches a region hands it the CONTENT - a
	 * string search through it, a gather of it into a child. This hands it
	 * the GEOMETRY, and the two answer different questions: "is this marker
	 * in the data section" against "how much of this file is data at all,
	 * and is it in one piece".
	 *
	 * The second question is one a module could not ask before, and
	 * re-deriving it is not a fair alternative: the ranges come out of the
	 * parser's tables through the settle and complement machinery in
	 * rangelist.h, and a module computing its own complement would be a
	 * second implementation of the partition - which would be wrong on
	 * exactly the hostile files that make the answer interesting.
	 *
	 * WHAT IT IS FOR, measured. The largest single unclaimed run in 4526
	 * clean ELF objects is 4095 bytes, which is what alignment padding can
	 * be and no more; in 3775 malware objects, 723 have one larger than a
	 * page. A run that big is a file somebody appended, and `widest_off` is
	 * where it starts - so nothing has to be searched for.
	 *
	 * Returns 0 and leaves *out zeroed when the object has no regions -
	 * an unidentified object, or a mask naming nothing present.
	 */
	int (*region_shape)(const struct kof_obj_ctx *, uint32_t region_mask,
			    struct kof_region_shape *out);

	/*
	 * HOW RANDOM A REGION'S BYTES ARE, in eighths of a bit - 0 to 64.
	 *
	 * Beside region_shape and for the same reason: a rule could ask what a
	 * region CONTAINS and how big it is, and could not ask what KIND of
	 * bytes they are. That is the cheapest fact there is about a region and
	 * the one most heuristics reach for second - padding sits near 0, text
	 * and tables between 1 and 4, code near 6, and compressed or encrypted
	 * data above 7.5.
	 *
	 * A rule could not compute it either. The bytes of a region are
	 * scattered, the accessors hand them over one at a time, and a module
	 * has no writable data to keep a histogram in - so the answer had to
	 * come from the host or not at all.
	 *
	 * OVER THE WHOLE REGION, every range of it, because that is what the
	 * mask names. A caller that wants one run measures it with the offset
	 * and length region_shape returned.
	 *
	 * Zero for an empty region, which reads as "nothing to measure" rather
	 * than as "uniform".
	 */
	uint32_t (*region_entropy)(const struct kof_obj_ctx *,
				   uint32_t region_mask);

	/*
	 * THE SAME, OVER ONE EXTENT THE CALLER NAMES.
	 *
	 * The general form, and region_entropy is the convenience: a region is
	 * scattered and its entropy is that of all its ranges together, which
	 * is the right answer to "what kind of bytes is this region" and the
	 * WRONG answer to "what kind of bytes are in that one run".
	 *
	 * Measured, and this is why both exist: the unclaimed region of one
	 * carrier sample is three runs - 3576 bytes of zero padding, one byte,
	 * and a 31968-byte ELF. Over the region it reads 4.5 bits; over the
	 * run that matters it reads 4.5 and over another sample's 6.0, while
	 * the padding dilutes a third down to 4.1. A gate written on the region
	 * measures the padding as much as the payload.
	 *
	 * Clipped to the object, so an extent that runs past the end measures
	 * what is there. Zero for an empty or out-of-range extent.
	 */
	uint32_t (*entropy_at)(const struct kof_obj_ctx *, uint64_t off,
			       uint64_t len);
};

/*
 * Which decoder kof_unpack_at should run.
 *
 * Named here rather than taken from each format's own numbering because the
 * service is one call: a module that has read UPX's method byte maps it to one of
 * these, and a module reading some other container's maps to the same set. The
 * host does not learn a container's numbering, and a new container does not need a
 * new entry point.
 *
 * NRV2 carries its bit width in the id because the width is part of the coding
 * rather than a variant of it - see kof_nrv2_bits for what that cost to learn.
 */
/*
 * What the unpacked bytes are, so the host knows whether to reassemble them.
 *
 * RAW is the ordinary answer and means the output is already a file - a gzip
 * member, a UPX packed ELF, anything the packer restores whole.
 *
 * PE_IMAGE means the output is a mapped image: it begins at the first section's
 * virtual address and carries the original PE header somewhere inside. The host
 * finds that header and writes the file the loader would have read. Without it the
 * child of an unpacked PE is a buffer of code that nothing recognises.
 */
enum kof_unp_form {
	KOF_FORM_RAW = 0,
	KOF_FORM_PE_IMAGE = 1
};

enum kof_unp_method {
	KOF_UNP_DEFLATE = 1,   /* RFC 1951; streams, needs no size hint */

	/*
	 * MS-OVBA 2.4.1, the coding an Office document holds its macros in.
	 *
	 * Streams like DEFLATE and needs no size hint, for a reason worth stating:
	 * a back reference is measured from the start of the current 4096 byte
	 * chunk and cannot reach past it, so the window is fixed however long the
	 * stream runs.
	 */
	KOF_UNP_OVBA = 2,

	/*
	 * LZMA2: LZMA cut into chunks that say what to carry over.
	 *
	 * No parameters in the id, unlike KOF_UNP_LZMA: an LZMA2 stream carries its
	 * own properties and may change them part way through, so there is nothing
	 * for a caller to pass. It is what 7-Zip writes its content with - measured
	 * over 369 archives, every folder that could be located uses it and none use
	 * plain LZMA.
	 */
	KOF_UNP_LZMA2 = 3,

	/*
	 * Hex text back into bytes, which is how RTF carries an embedded object.
	 *
	 * Not compression and named as a coding anyway, because it sits in exactly
	 * the same place: a module points at a range and gets an object out. The
	 * decoder skips whitespace, which is not politeness - splitting the hex
	 * with spaces is how a blob is kept from matching a fixed prefix.
	 */
	KOF_UNP_HEXTEXT = 4,

	/*
	 * LZMA2 with the x86 branch transform undone afterwards.
	 *
	 * One method rather than a second argument, on the same reasoning that put
	 * LZMA's properties in its id: a filter is meaningless for eight of nine
	 * codings, and an argument that is ignored almost everywhere is worse than
	 * an id that says what it is. Measured over the 7z archives here, 77 folders
	 * need it and 334 do not.
	 */
	KOF_UNP_LZMA2_BCJ_X86 = 5,

	/*
	 * RAR 2.9/3.x, the LZ half.
	 *
	 * RAR picks between LZ and PPMd per block and says which in the first bit of
	 * each block header. Measured over 13971 compressed entries here, 92.6% of
	 * blocks are LZ; a PPM block is refused rather than guessed at, and the
	 * caller is told which happened.
	 */
	KOF_UNP_RAR3 = 6,

	/*
	 * 7z's four stream x86 filter, driven by entry index rather than by a range.
	 *
	 * BCJ2 does not read one run of bytes: it merges a main stream, a stream of
	 * call targets, a stream of jump targets and a range coder that says which
	 * candidate opcodes were converted. Which packed stream is which comes from
	 * the folder's bind pairs, so only the host can resolve it - see
	 * kof_unpack_entry.
	 */
	KOF_UNP_BCJ2 = 7,

	/*
	 * RAR 5, which shares a name with RAR3 and no code.
	 *
	 * A separate id and not a parameter of the RAR3 one: the two formats agree
	 * on nothing below the signature - different block framing, different table
	 * encoding, different slot arithmetic, different filters - so the host picks
	 * a decoder here rather than branching inside one.
	 */
	KOF_UNP_RAR5 = 8,
	/*
	 * RFC 1950 - the same DEFLATE data behind two bytes of framing.
	 *
	 * Its own method rather than two lines in every caller, because zlib
	 * framing is not peculiar to any one format: a PDF's /FlateDecode uses
	 * it, and so does anything else that reached for the obvious library.
	 * The rule kofsig.h states for the whole unpack surface applies to it -
	 * standard and shared belongs in the host - and the first module to meet
	 * it had open-coded the header check, which is one copy away from every
	 * later one getting it subtly different.
	 *
	 * The framing is CHECKED, not assumed: a stream that does not carry a
	 * valid zlib header is decoded as raw DEFLATE from its first byte, which
	 * is what a producer that emitted RFC 1951 under a zlib name meant. So a
	 * caller that is unsure which it has can name this one and be right
	 * either way.
	 */
	KOF_UNP_ZLIB = 9,

	/*
	 * ASCII85 back into bytes: five printable characters carry four.
	 *
	 * Not compression, and named as a coding for the reason HEXTEXT is - it
	 * sits in exactly the same place, a range in, an object out. PDF writes
	 * it IN FRONT OF a Flate to make a stream survive a text-only channel,
	 * so its whole importance is that it appears in a CHAIN: a decoder
	 * handed the Flate half alone inflates ASCII85 text and fails, which is
	 * how a clean document came to be reported as one the engine could not
	 * finish.
	 *
	 * Output is at most four fifths of input, which is what makes it usable
	 * as an INTERMEDIATE step - see the chain runner. A step whose output
	 * cannot be bounded from its input has nowhere to be put.
	 */
	KOF_UNP_ASCII85 = 10,

	/*
	 * The other two transport codings, and see kofdecomp/textcode.h for
	 * why the three belong together.
	 *
	 * ASCIIHEX is bounded by its input like ASCII85, so it can be a middle
	 * step of a chain. RUNLENGTH expands up to 128x and cannot be sized
	 * from its input, so it can only be a last step - the host reports a
	 * chain that asks for more rather than guessing a buffer.
	 *
	 * Both are rare, and that is a reason to have them rather than not:
	 * reaching for an old or unusual coding is how a file gets past a
	 * parser that only implemented the common one.
	 */
	KOF_UNP_ASCIIHEX = 11,
	KOF_UNP_RUNLENGTH = 12,

	/*
	 * LZW as PDF and TIFF write it - most-significant-bit first, which is
	 * NOT the GIF variant. See kofdecomp/lzw.h.
	 *
	 * Worth having because it was superseded: a filter nobody expects is a
	 * filter a parser was never taught, and that is a cheap way to put
	 * ordinary content past one.
	 *
	 * Output is unbounded, so it streams and can only be the LAST step of a
	 * chain - like DEFLATE and for the same reason.
	 */
	KOF_UNP_LZW = 13,

	KOF_UNP_NRV2B_8 = 16, KOF_UNP_NRV2B_16, KOF_UNP_NRV2B_32,
	KOF_UNP_NRV2D_8,      KOF_UNP_NRV2D_16, KOF_UNP_NRV2D_32,
	KOF_UNP_NRV2E_8,      KOF_UNP_NRV2E_16, KOF_UNP_NRV2E_32,

	/*
	 * LZMA carries three parameters, so the id carries them.
	 *
	 * lc, lp and pb decide the shape of the probability model and there is no
	 * default that works - a stream decoded with the wrong three produces
	 * plausible bytes that are not the file. They ride in the method id rather
	 * than in a fourth argument because every other coding needs no parameters
	 * and a parameter that is meaningless for eight of nine methods is worse
	 * than an id that says what it is.
	 *
	 * Use KOF_UNP_LZMA_PROPS to build one. The packing is the specification's
	 * own: lc + 9*lp + 45*pb, which fits 0..224 above the base.
	 */
	KOF_UNP_LZMA = 64
};

/*
 * What the LZMA specification allows for each parameter.
 *
 * Module facing because a module is what reads them out of a container and has to
 * refuse the ones that are out of range - they size the decoder's probability
 * model, so an unchecked value is an allocation chosen by whoever wrote the file.
 * The decoder checks them again on its own side; this is so a module can say it
 * could not finish rather than being refused with nothing to report.
 */
#define KOF_LZMA_MAX_LC 8u
#define KOF_LZMA_MAX_LP 4u
#define KOF_LZMA_MAX_PB 4u

#define KOF_UNP_LZMA_PROPS(lc, lp, pb)                                      \
	((uint32_t)KOF_UNP_LZMA + (uint32_t)(lc) + 9u * (uint32_t)(lp) +    \
	 45u * (uint32_t)(pb))

/*
 * WHERE IT IS WORTH LOOKING FOR A FILE NOBODY DECLARED.
 *
 * Set by a parser on its context; read by the engine when it descends. Three
 * answers, and the third is not the same as "no answer" - which is the whole
 * reason this is an enumeration rather than a mask with zero meaning something.
 */
enum kof_embed_search {
	/*
	 * Nothing declared a scope, so search the whole object.
	 *
	 * The value zero deliberately, so an object with no parse at all gets
	 * the full search by simply saying nothing. That is today's behaviour
	 * and it is the correct behaviour for those objects: a raw buffer or a
	 * bytecode block has no structure to consult and no region to narrow
	 * to, and a whole PE inside one is exactly what a search is for.
	 */
	KOF_EMBED_ANYWHERE = 0,

	/*
	 * The structure names its carried files, so do not search at all.
	 *
	 * For a format whose entry table IS the answer: PDF /EF, a zip central
	 * directory, a CFB directory, a MIME part list. Searching such an
	 * object cannot find anything the parser did not already declare, and
	 * measurably does find the same bytes a second time - one attachment,
	 * two children, and the second one scanned again for nothing.
	 */
	KOF_EMBED_DECLARED = 1,

	/*
	 * Search, but only inside the regions named in ctx->embed_scope.
	 *
	 * For a format that CANNOT declare its carried files but does know
	 * where one could be. An ELF's embedded blob is in its data, never in
	 * .text; a PE's is in its overlay or its resources. Narrowing is not
	 * only cheaper - a magic-shaped run of bytes inside executable code is
	 * a false child, and not looking there is how it stops being one.
	 *
	 * It gives up the rare file hidden somewhere unexpected. That is the
	 * trade, stated rather than hidden.
	 */
	KOF_EMBED_SCOPED = 2
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
/*
 * WHAT A CONTAINER SAYS IS INSIDE IT, AND WHO ACTS ON THAT.
 *
 * A region says which bytes are what KIND. This says which bytes are a THING -
 * a file, a script, a picture - and the difference is the whole of why both
 * exist.
 *
 * WHY A REGION IS NOT ENOUGH, measured rather than argued. A PDF carrying 25
 * images has them in one IMAGE region of 1.3MB, and every question about one
 * image is unanswerable there: which of the 25 matched, where that one starts,
 * whether a PE was appended to the end of one of them. Worse, the region is a
 * UNION - kof_rl_normalise merges ranges that touch - so two files laid end to
 * end become one range and a pattern can match across the seam between them,
 * which is a finding about neither file. A region is the right answer for the
 * parts of ONE thing: a PE's code across several sections is code, and a
 * pattern spanning two of them is a real pattern. It is the wrong answer for a
 * SET of independent things.
 *
 * WHY THE PARSER DECLARES AND DOES NOT ACT. A parser knows where an entry is,
 * what it is, and how it is coded; it has no business deciding whether opening
 * it is worth the budget, and it cannot know - that depends on which rules are
 * loaded, which is the host's knowledge and changes per scan. So the parser
 * fills this in and the host decides. Before this, that decision lived in the
 * unpacker MODULES, which are compiled blobs shipped in a database: skipping
 * images meant editing a blob and rebuilding it, and the policy was per format
 * rather than per engine.
 *
 * WHY THE HOST AND NOT THE MODULE PRODUCES THE CHILD. A module can emit bytes,
 * and that is all it can say about them - so every child arrived untyped and
 * was then guessed at by the sniff chain. Measured on one document: 32 children
 * were produced, 1386 rule evaluations were considered against them, and NONE
 * ran, because an unidentified child is a child no rule targets. Declaring the
 * format here is what makes the work worth doing.
 *
 * Layout rule: append only, like every other structure in this header.
 */

/*
 * What an entry IS, in terms every container shares.
 *
 * Deliberately not a format: a picture is a picture whether it arrives as JPEG
 * in a PDF or as PNG in a zip, and a host deciding whether to spend a
 * decompression on it is asking the same question either way. `format` below is
 * the separate, stronger claim a parser may or may not be able to make.
 */
enum kof_entry_kind {
	KOF_ENT_UNKNOWN = 0,
	KOF_ENT_CONTENT,      /* the container's own presentation data */
	KOF_ENT_SCRIPT,       /* code meant to run when the file is opened */
	KOF_ENT_METADATA,     /* what the file says about itself */
	KOF_ENT_IMAGE,        /* pixels */
	KOF_ENT_FONT,         /* a program for a rasteriser */
	KOF_ENT_EMBEDDED,     /* a file the container carries AS a file */
	KOF_ENT_STRUCTURE,    /* the container's own index or graph, coded */
	KOF_ENT_KIND_COUNT
};

/*
 * What an entry IS, as a word.
 *
 * Beside the enum it names, and it exists for the reason kof_format_name does:
 * every host that shows an entry needs this, and the alternative is each one
 * carrying its own table - which is how kofexamine and kofviewer came to
 * disagree about region labels.
 *
 * SHORT WORDS, because they go in a column beside a length. And UPPER CASE, so
 * a kind cannot be mistaken for a NAME read out of the file, which sits in the
 * same cell and is whatever somebody wrote there.
 *
 * The default is "?" and not "UNKNOWN": UNKNOWN is a real kind - the parser
 * found a thing and declines to say what it is - while a value outside the
 * enumeration is this build not recognising it, which is a fault and not a
 * fact. Spelling them the same would hide the second behind the first.
 */
/*
 * What a coding IS, as a word.
 *
 * Here for the reason kof_entry_kind_name is here: a host that shows an entry
 * has to show its chain, and the alternative is each host inventing a
 * shorthand. One did - the viewer printed a bare "z" for "there is a coding"
 * - and a single letter with no legend anywhere is not a label, it is a thing
 * the reader has to come and ask about.
 *
 * The LZMA ids carry their parameters, so they are a range rather than a
 * value and are named by the range. The NRV2 variants differ only in bit
 * width, which is not worth a column, so they are named by family.
 */
static inline const char *kof_unp_method_name(uint32_t m)
{
	if (m >= KOF_UNP_LZMA && m <= KOF_UNP_LZMA + 224u)
		return "lzma";
	if (m >= KOF_UNP_NRV2B_8 && m <= KOF_UNP_NRV2B_32)
		return "nrv2b";
	if (m >= KOF_UNP_NRV2D_8 && m <= KOF_UNP_NRV2D_32)
		return "nrv2d";
	if (m >= KOF_UNP_NRV2E_8 && m <= KOF_UNP_NRV2E_32)
		return "nrv2e";
	switch (m) {
	case 0:                     return "";        /* nothing to undo */
	case KOF_UNP_DEFLATE:       return "deflate";
	case KOF_UNP_ZLIB:          return "zlib";
	case KOF_UNP_ASCII85:       return "ascii85";
	case KOF_UNP_ASCIIHEX:      return "asciihex";
	case KOF_UNP_RUNLENGTH:     return "runlength";
	case KOF_UNP_LZW:           return "lzw";
	case KOF_UNP_OVBA:          return "ovba";
	case KOF_UNP_LZMA2:         return "lzma2";
	case KOF_UNP_LZMA2_BCJ_X86: return "lzma2+bcj";
	case KOF_UNP_HEXTEXT:       return "hex";
	case KOF_UNP_RAR3:          return "rar3";
	case KOF_UNP_RAR5:          return "rar5";
	case KOF_UNP_BCJ2:          return "bcj2";
	default:                    return "?";
	}
}

static inline const char *kof_entry_kind_name(uint32_t kind)
{
	switch (kind) {
	case KOF_ENT_UNKNOWN:   return "UNKNOWN";
	case KOF_ENT_CONTENT:   return "CONTENT";
	case KOF_ENT_SCRIPT:    return "SCRIPT";
	case KOF_ENT_METADATA:  return "METADATA";
	case KOF_ENT_IMAGE:     return "IMAGE";
	case KOF_ENT_FONT:      return "FONT";
	case KOF_ENT_EMBEDDED:  return "EMBEDDED";
	case KOF_ENT_STRUCTURE: return "STRUCTURE";
	default:                return "?";
	}
}
/*
 * The bytes are not one range: ask resolve_entry with this entry's `index`.
 *
 * A FLAG AND NOT A ZERO LENGTH, which is how this was first written. An
 * in-band sentinel is the shape hostile input abuses - a declared length of
 * zero then means two different things and the reader has to guess which. A
 * compound file stream is a chain rather than a range, and over 1322 streams
 * in real documents 23.6% are not consecutive, so this is the ordinary case
 * for a whole format and not an edge.
 */
#define KOF_ENT_F_SCATTERED  (1u << 0)

/*
 * THE CODING CHAIN IS INCOMPLETE: something the container declared is not in
 * `coding`, so running `coding` does NOT arrive at the original bytes.
 *
 * Two shapes of the same thing, and the flag covers both. The chain can be
 * EMPTY because the first coding was inexpressible - and an empty chain
 * otherwise means stored, which is the opposite of the truth. Or it can be
 * PARTIAL: every method in it is real and there was one more step the parser
 * could not name, so running it produces bytes that are neither the coded
 * form nor the original.
 *
 * enum kof_unp_method has no value for "a coding that exists and which I
 * cannot perform", and it should not have one: every value in it names a
 * decoder that is present. So the absence has to be said some other way, and
 * without a way to say it the absence is indistinguishable from stored.
 *
 * That is not a cosmetic difference. /Filter [/ASCII85Decode /FlateDecode]
 * reduces to no expressible chain, an empty chain reads as stored, and the
 * host would then window raw ASCII85 AS THOUGH IT WERE THE ORIGINAL BYTES -
 * a rule written against the decoded content matches nothing, and one written
 * against a fixed prefix matches the wrong thing. Reporting the range as
 * present-but-unopenable is the difference between a known gap and a silent
 * wrong answer.
 *
 * Set by the parser when it read the container's declared coding and could
 * not express all of it. THE HOST MUST CHECK IT BEFORE IT CHECKS `coding`,
 * because a partial chain looks perfectly runnable, and report
 * KOF_UNP_UNSUPPORTED - the honest answer: a coding this build lacks is a gap
 * a later build closes, and it is not the same thing as damage.
 */
#define KOF_ENT_F_CODED_UNKNOWN  (1u << 1)

struct kof_entry {
	/*
	 * Where the bytes are, when they are one range. Meaningless when
	 * KOF_ENT_F_SCATTERED is set, and the host must not read it then.
	 */
	uint64_t off, len;

	/* The name, as a range in THIS object and never as a string, for the
	 * reason name_next gives: the name is already in the file, and a parser
	 * has nowhere to build one. Zero length when nothing named it. */
	uint64_t name_off, name_len;

	/* What the decoded bytes should come to, when the container declares it.
	 * Zero when it does not. A hint and never a bound - the host's ceiling
	 * is what bounds, and this must never be an allocation size. */
	uint64_t out_hint;

	/*
	 * THE FORMAT'S OWN INDEX FOR THIS ENTRY, which is not its position in
	 * this array.
	 *
	 * resolve_entry takes the format's index, and a parser may build this
	 * table as a PROJECTION of something else - PDF does, from its object
	 * table, where only the rows that carry a stream become entries. So the
	 * two numbers differ, and assuming they are the same reads the wrong
	 * entry's ranges. That is a correctness bug and not a tidiness point.
	 */
	uint32_t index;

	uint32_t kind;        /* enum kof_entry_kind */
	uint32_t flags;       /* KOF_ENT_F_* */

	/*
	 * HOW TO GET BACK TO THE ORIGINAL BYTES, IN ORDER.
	 *
	 * A CHAIN and not one method, because containers have chains: PDF
	 * writes /Filter [/ASCII85Decode /FlateDecode] and the two are applied
	 * in that order. Held as a single value, a parser had to name one of
	 * them and the order was lost - PDF stored a BITMASK, said so in its
	 * own header, and the decompressor then guessed. Measured: on 1 of 3
	 * real documents that guess fails twice, reaches
	 * kof_unp_broken(KOF_UNP_UNSUPPORTED), and a clean file is reported as
	 * one the engine could not finish.
	 *
	 * Applied [0] first. A zero terminates - and a FULL array has no
	 * terminator, so a host reads at most four whatever it finds in [3].
	 *
	 * Four, because no real chain is longer and a bound is what stops a
	 * hostile one multiplying. A chain that needed a fifth is reported
	 * through KOF_ENT_F_CODED_UNKNOWN and not quietly cut to four, which
	 * is what happened while the bound sat in the loop condition instead.
	 *
	 * All zero means STORED - the bytes are already what they are - but
	 * ONLY when KOF_ENT_F_CODED_UNKNOWN is clear. Set, it means the
	 * container declared a coding that this build cannot express, and the
	 * bytes must not be handed on as if they were the original.
	 *
	 * The host stops at the first method it does not know and reports
	 * KOF_UNP_UNSUPPORTED, which is the honest answer: a coding this build
	 * lacks is a gap a later build closes. It must never carry on with the
	 * rest of the chain, since every step after a missed one decodes
	 * refuse.
	 */
	/*
	 * uint16_t AND NOT uint8_t, which is what this was.
	 *
	 * A method id does not fit in a byte. KOF_UNP_LZMA is 64 and CARRIES
	 * ITS PARAMETERS IN THE ID - lc + 9*lp + 45*pb, 0..224 above the base -
	 * so the ids run to 288, and KOF_UNP_LZMA_PROPS builds one as a
	 * uint32_t for that reason. Stored in a byte, LZMA(8,4,4) truncates to
	 * 32, which is not an invalid value that something would catch: it is
	 * KOF_UNP_NRV2E_32, a real decoder, and the entry would then name a
	 * coding the container never declared. Exactly the class of silent
	 * wrong answer KOF_ENT_F_CODED_UNKNOWN exists to prevent, arriving
	 * through the width of the field instead.
	 *
	 * No parser fills an LZMA chain yet - PDF has no LZMA - so this is
	 * fixed while it costs four bytes and nothing else. A 7z or xz entry
	 * table is where it would have been found the hard way.
	 */
	uint16_t coding[4];   /* enum kof_unp_method each, [0] applied first */

	/*
	 * The format the parser is WILLING TO DECLARE about the decoded bytes,
	 * or KOF_FMT_UNKNOWN when it will not.
	 *
	 * A claim and not a guess. A PDF knows a content stream is a content
	 * stream because /Contents said so, and it does NOT know what is inside
	 * an /EmbeddedFile - so it declares the first and leaves the second to
	 * the sniff chain, which is what the sniff chain is for. Declaring
	 * wrongly is worse than declaring nothing: the parse named by it runs
	 * instead of the one the bytes deserve.
	 */
	uint8_t  format;
	uint8_t  reserved[3];  /* to 64 bytes; the assert below is the check */
};

/*
 * 64 bytes, and it is not tidiness: a format's view holds an ARRAY of these -
 * PDF's is 1024 long - so padding is multiplied by the entry count and paid on
 * every parse. Widening coding from 8 to 16 bits fitted in the space the
 * reserved bytes already held; the next field that does not will show up here
 * rather than as 8KB more view per document.
 */
_Static_assert(sizeof(struct kof_entry) == 64, "entry record grew padding");

struct kof_obj_ctx {
	uint8_t  format;      /* enum kof_format */
	uint8_t  arch;        /* enum kof_arch */

	/*
	 * What KIND of thing this format holds, in the format's own vocabulary.
	 *
	 * A third prefilter axis beside format and architecture, and the reason it is
	 * an axis rather than more format values is the test that separated DOCOLE
	 * from DOCZIP: those are different formats because a document's parts live in
	 * different PLACES in each, so a module written for one cannot run against the
	 * other. A shared library and an executable are read identically - same
	 * parser, same view, same regions - so they are one format and two kinds.
	 *
	 * Deliberately NOT normalised across formats, unlike arch. The value is
	 * whatever the format's own header field says: for ELF it is e_type verbatim,
	 * for PE it is composed from the DLL characteristic and the subsystem, and
	 * those two are no more comparable than EM_AARCH64 is to
	 * IMAGE_FILE_MACHINE_ARM64. So the values are declared in elf.h and pe.h and
	 * the numbers COLLIDE between formats - KOF_ELF_REL and KOF_PE_DLL are both 1.
	 *
	 * That is safe rather than sloppy, because target_mask is tested first: the
	 * subtype test is only ever reached for an object of a format the module
	 * already declared. The build refuses a module that names one format's
	 * subtypes while targeting another, so the collision cannot be reached by
	 * accident.
	 *
	 * Zero for a format with no such notion, which is every container.
	 */
	uint8_t  subtype;
	uint8_t  reserved;

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
	 * Where the bytes of ONE entry are, for a format that has entries.
	 *
	 * The same shape as resolve_scan and answering the other question. A region
	 * is what a byte IS; an entry is what a byte BELONGS TO, and the two are not
	 * interchangeable: a compound file's macro region is every VBA stream at
	 * once, while decompressing is a thing done to one stream. Joining the region
	 * gives a concatenation with no boundaries in it, which is why this exists.
	 *
	 * The ranges are in object coordinates and are NOT settled: a stream is a
	 * chain and its sectors arrive in the order the chain gives, which is the
	 * order its bytes go back together in. Sorting them would corrupt the stream.
	 *
	 * NULL for a format whose entries have no bytes of their own, and for every
	 * format that has no entries.
	 */
	uint32_t (*resolve_entry)(const struct kof_obj_ctx *ctx, uint32_t index,
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
	 * Called through KOF_SCAN_MATCH, so reporting and returning cannot come apart.
	 */
	void (*report)(const struct kof_obj_ctx *ctx, uint32_t level,
		       uint32_t name_id);

	/*
	 * The same thing said without deciding anything: what the module worked
	 * out, for whoever is watching.
	 *
	 * A finding changes a verdict and ends the module. A note changes nothing
	 * and the module carries on - "this is UPX 1.3 with NRV2E", "the block
	 * chain stopped after four of them" - which is the difference between an
	 * answer and the reasoning behind it. Nothing in a normal scan looks at
	 * these; a host that wants them says so, and a host that does not pays one
	 * NULL test per note.
	 *
	 * Named through the same table a finding uses, so note text never enters
	 * the blob either, and a note carries one number because the interesting
	 * ones are nearly always "which version" or "how many".
	 *
	 * Called through kof_debug, which does not return - and is spelled in lower
	 * case for that reason. The upper case macros in this header are the ones
	 * that change control flow; KOF_SCAN_MATCH reports AND returns, and a reader
	 * should be able to tell the two apart without looking either of them up.
	 */
	void (*debug)(const struct kof_obj_ctx *ctx, uint32_t name_id,
		      uint64_t value);

	/* Host state the accessors need. Opaque, and no module has any reason to
	 * touch it; it is here so the accessors can take the context rather than
	 * reach for a global, which keeps them usable from more than one thread. */
	const void *priv;

	/*
	 * WHAT THIS OBJECT CONTAINS, as the parse found it. See struct kof_entry.
	 *
	 * Sets *out to a table the PARSE owns - it lives in the view, so it is
	 * valid as long as the view is - and returns how many entries are in it.
	 * NULL for a format with no entries, which is most of them, and returning
	 * zero is the same answer as not having the pointer.
	 *
	 * Read by the host to decide what to open, and by a tool to show what is
	 * inside without opening anything. Those were two separate walks before,
	 * and the viewer's own was built by scraping the scan's callback - which
	 * is how one missing initialiser deleted the root object from its tree and
	 * took every region row with it.
	 */
	uint32_t (*entries)(const struct kof_obj_ctx *ctx,
			    const struct kof_entry **out);

	/*
	 * HOW THIS OBJECT'S CARRIED FILES ARE FOUND. See enum kof_embed_search.
	 *
	 * The other half of carried files, and it is a SEPARATE FIELD from the
	 * mask below because it has three answers and a mask has only two.
	 *
	 * A PE or an ELF can hold a file that was read in at compile time -
	 * //go:embed, an #included blob, a resource the linker placed in
	 * .rodata - and NOTHING in the structure says so: the section table
	 * says ".rodata, 2MB, read-only data", not that some range of it is a
	 * ZIP. A parser cannot declare that without guessing, and guessing is
	 * the one thing it must not do. So the engine searches for magic and
	 * validates a header, which is format independent and belongs in one
	 * place.
	 *
	 * What is NOT format independent is where looking is worthwhile, and
	 * that is all these two fields say.
	 *
	 * WHY NOT A MASK ALONE, which is how this was first written: the
	 * comment then claimed zero meant BOTH "the whole object" and "the
	 * opt-out", which cannot both be true. An object with NO PARSE AT ALL
	 * carries a zeroed context - a raw buffer, an AMSI bytecode block,
	 * anything the sniff chain declined - and that object is the single
	 * most important one to search, since a raw dropper's payload is found
	 * no other way. A PDF is the opposite: /EF already said where every
	 * attachment is, and searching anyway is what made one document produce
	 * the same attachment twice. Spelling both as zero makes one of them
	 * wrong whichever way the default goes.
	 */
	uint8_t  embed_search;   /* enum kof_embed_search */
	uint8_t  embed_pad[3];

	/*
	 * The regions to search, read ONLY when embed_search is
	 * KOF_EMBED_SCOPED. Meaningless otherwise, and the engine does not look
	 * at it - so a parser that sets a mask and forgets the policy gets
	 * today's behaviour rather than a silent narrowing.
	 */
	uint32_t embed_scope;
};

/*
 * Entry point. Defined by the module, called by the loader - through
 * KOF_DEFINE_SCAN below, which is what puts `ctx` in scope for the macros.
 *
 * Returns nothing. A module's output is what it reports, so there is no verdict
 * to return, and a module with nothing to say simply ends - which is why no
 * trailing "return clean" has to be written. Bailing out early is a bare return.
 *
 * The linker script places this first, so its offset inside the blob is zero and
 * the loader needs no symbol table at runtime. Other module roles will follow the
 * same pattern with their own header and their own entry: kof_unpack() from
 * kofunp.h, kof_cure() from kofcure.h.
 */
void kof_scan(const struct kof_obj_ctx *ctx);

/*
 * The other entry point: yield the objects inside this one.
 *
 * A module exports exactly one of kof_scan and kof_unpack, and which one it is
 * decides the kind of the pack it is built into - the build derives that from the
 * exported symbol rather than from a declaration, because a declaration can
 * disagree with the code and an exported symbol cannot.
 *
 * The two are dispatched from different points and never see each other's records:
 * detectors run while an object is being scanned, unpackers afterwards, once the
 * engine has a verdict on the container itself. That ordering is what lets an
 * archive already identified as an exploit be left unopened.
 */
void kof_unpack(const struct kof_obj_ctx *ctx);

/*
 * SEARCHING FOR DECLARED STRINGS
 *
 *     if (kof_find_str(loaded, busybox)) ...
 *     if (kof_find_str_all(code, prologue, marker)) ...
 *     if (kof_find_str_any(data, irc_who, irc_pong, irc_nick)) ...
 *     if (kof_find_str_multi(data, m1, m2, m3, m4) >= 2) ...
 *
 * Range first, then the strings, because the range is the one thing every form
 * shares and the strings are the part that varies in number. The other order
 * cannot express the variadic forms at all: a trailing range after a list of
 * strings is not something a macro can pick out.
 *
 * Every name resolves through an identifier the build defines from the
 * KOF_DEFINE_STR and KOF_TARGET_RANGE declarations in this source. A name that was
 * never declared is an undefined identifier at compile time rather than a lookup
 * that quietly returns false - the failure mode to want, since a signature that
 * silently never matches looks exactly like one that works.
 *
 * No search happens in the module. The host owns the literals and answers these,
 * which is what allows one pass over the object to serve every module, and what
 * makes asking the same question twice free: an answer is memoised per (string,
 * range) for the object, so a module may ask in whatever order reads best.
 *
 *
 * WHERE ctx WENT
 *
 * These take no context argument. It is not passed by some hidden channel - the
 * expansion simply names `ctx`, which is in scope because the entry point takes it
 * and KOF_DEFINE_SCAN below names it that.
 *
 * That is a trade worth stating rather than discovering. What it buys is a call
 * that says only what the author decided - a range and some strings - instead of
 * repeating a parameter that is the same at every call site in the module and can
 * never be anything else. What it costs is that a helper function inside a module
 * must call its context parameter `ctx` too. That costs a compile error naming an
 * undeclared identifier, not a wrong answer, which is the only kind of cost this
 * layer is allowed to have.
 *
 * The C level accessors keep taking it: ctx->obj_size, kof_elf(ctx),
 * ctx->content->rd32(ctx, off). Those are plain C reading a plain struct, and
 * hiding the subject of a field access would be hiding the wrong thing. The line is
 * between the declarative layer, which turns names the build assigned into a
 * question about the object under scan, and the struct underneath it.
 */
#define KOF_PASTE2(a, b) a##b
#define KOF_PASTE(a, b)  KOF_PASTE2(a, b)

/*
 * Define the entry point.
 *
 *     KOF_DEFINE_SCAN
 *     {
 *             ...
 *     }
 *
 * Expands to the prototype the loader calls, which is what guarantees `ctx` exists
 * and is spelled the way the search macros expect. Writing that prototype by hand
 * still works; this exists so the one name the DSL depends on is not a convention
 * anybody has to remember.
 *
 * It is also the only place the entry symbol is spelled. The kind of a module - a
 * detector or an unpacker - is derived at build time from which entry point it
 * exports, so a misspelling here is a module that packs as the wrong kind rather
 * than one that fails to link.
 */
#define KOF_DEFINE_SCAN void kof_scan(const struct kof_obj_ctx *ctx)

/*
 * Define an unpacker.
 *
 *     KOF_DEFINE_UNPACK
 *     {
 *             const struct kof_pe_info *pe = kof_pe(ctx);
 *
 *             if (pe->overlay_len)
 *                     kof_child_window(pe->overlay_off, pe->overlay_len);
 *     }
 *
 * Same shape as KOF_DEFINE_SCAN and the same reason: it is the only place the
 * entry symbol is spelled, so a misspelling is a link error rather than a module
 * that packs as the wrong kind.
 */
#define KOF_DEFINE_UNPACK void kof_unpack(const struct kof_obj_ctx *ctx)

/*
 * WHAT SORT OF UNPACKER THIS IS.
 *
 *     KOF_UNPACK_KIND(KOF_UNP_PACKER);      - UPX, Ezuri: it hid a program
 *     KOF_UNPACK_KIND(KOF_UNP_CONTAINER);   - zip, tar, rar: it carried files
 *
 * Required of every unpack module and meaningless on a detector.
 *
 * The distinction is not tidiness, it is EVIDENCE. A file that was wrapped in an
 * executable packer is saying something about itself: the wrapping exists to stop
 * the file being read, and a heuristic that weighs "this was packed" is weighing
 * that. A file that arrived inside a zip is saying nothing at all - archives are
 * how software is shipped - and counting a zip as a layer of packing is how a
 * heuristic ends up scoring an installer like a dropper.
 *
 * It also decides what "two layers deep" means. Depth through packers is a thing
 * worth multiplying by; depth through containers is a directory tree.
 *
 * DECLARED RATHER THAN GUESSED, and the guesses were tried. Naming children looked
 * like it separated the two - packers do not name what they produce - and it does
 * not: xz and overlay are containers by any reading and name nothing either. A
 * property that happens to correlate on today's eleven modules is a property that
 * misclassifies the twelfth silently, and this one feeds a score.
 */
#define KOF_UNP_CONTAINER 0
#define KOF_UNP_PACKER    1
#define KOF_UNPACK_KIND(k)

/*
 * One search, normalised to 0 or 1.
 *
 * The host already answers with 0 or 1, and the normalisation is here anyway
 * because kof_find_str_multi adds these together: were find_str ever to return some
 * other non-zero, a count would silently become a sum of arbitrary values, and a
 * threshold written against it would be wrong in a way no test would show. The
 * comparison costs nothing - it is folded at compile time - and it means the
 * counting form does not depend on a convention held somewhere else.
 */
#define KOF_FS_ONE(rng, s)                                                 \
	((ctx)->content->find_str((ctx),                                   \
		KOF_PASTE(kof_strid_, s),                                  \
		KOF_PASTE(kof_rangeid_, rng)) != 0)

/*
 * Fold one operator across a list of string names.
 *
 * An expression, not an array and a loop. A compound literal holding the ids would
 * be the obvious shape and is the wrong one here: a module is freestanding position
 * independent code that the build verifies has no relocations and no data sections,
 * and an initialised array is exactly how one appears. Folding to `a || b || c`
 * leaves nothing but calls.
 *
 * It also makes the short circuit the C operator's rather than something a helper
 * would have to reimplement: kof_find_str_any stops at the first string present,
 * kof_find_str_all at the first absent.
 *
 * Sixteen names in one call, which is well past readable; past that, write two
 * calls and join them. The cap shows up as an undefined KOF_FS_<n>, so it is a
 * compile error rather than a silently truncated list.
 */
#define KOF_FS_1(op, r, a)       KOF_FS_ONE(r, a)
#define KOF_FS_2(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_1(op, r, __VA_ARGS__))
#define KOF_FS_3(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_2(op, r, __VA_ARGS__))
#define KOF_FS_4(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_3(op, r, __VA_ARGS__))
#define KOF_FS_5(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_4(op, r, __VA_ARGS__))
#define KOF_FS_6(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_5(op, r, __VA_ARGS__))
#define KOF_FS_7(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_6(op, r, __VA_ARGS__))
#define KOF_FS_8(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_7(op, r, __VA_ARGS__))
#define KOF_FS_9(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_8(op, r, __VA_ARGS__))
#define KOF_FS_10(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_9(op, r, __VA_ARGS__))
#define KOF_FS_11(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_10(op, r, __VA_ARGS__))
#define KOF_FS_12(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_11(op, r, __VA_ARGS__))
#define KOF_FS_13(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_12(op, r, __VA_ARGS__))
#define KOF_FS_14(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_13(op, r, __VA_ARGS__))
#define KOF_FS_15(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_14(op, r, __VA_ARGS__))
#define KOF_FS_16(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_15(op, r, __VA_ARGS__))

#define KOF_NARG_(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,  \
		  _15, _16, N, ...) N
#define KOF_NARG(...) KOF_NARG_(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8,  \
				7, 6, 5, 4, 3, 2, 1)

#define KOF_FS_PICK(n, op, r, ...) KOF_PASTE(KOF_FS_, n)(op, r, __VA_ARGS__)
#define KOF_FS_FOLD(op, r, ...)                                                 \
	KOF_FS_PICK(KOF_NARG(__VA_ARGS__), op, r, __VA_ARGS__)

/* One string in one range. Non-zero if present. */
#define kof_find_str(rng, s) KOF_FS_ONE(rng, s)

/*
 * AT AN OFFSET THE MODULE WORKED OUT
 *
 *     if (kof_find_str_at(ctx->entry_off, stub)) ...
 *     if (kof_find_str_in(ctx->entry_off, 64, stub)) ...
 *
 * The offset is an ordinary expression, not a declaration, and that is the line the
 * whole design rests on: the PATTERN is metadata and belongs in the database, where
 * the host owns it, dedupes it and searches for many modules in one pass; the
 * OFFSET is logic and belongs here, because it depends on the object - an entry
 * point, a field read out of a header, arithmetic on either. Declaring a value that
 * is computed from the file is not something a build can do.
 *
 *     uint64_t target = kof_u32(ep + 1) + ep + 5;   
 *     if (kof_find_str_at(target, prologue)) ...    
 *
 * _at compares; _in searches. They are separate because they cost differently - one
 * comparison against a window - and a single call that did both would hide which
 * one a signature is paying for.
 *
 * Neither is memoised and neither consults the presence set. Both are bounds
 * checked by the host, so an offset past the end of the object is a zero answer and
 * never a read outside it.
 */
#define kof_find_str_at(off, s)                                            \
	((ctx)->content->find_str_at((ctx), KOF_PASTE(kof_strid_, s),      \
				     (uint64_t)(off)))

#define kof_find_str_in(off, len, s)                                       \
	((ctx)->content->find_str_in((ctx), KOF_PASTE(kof_strid_, s),      \
				     (uint64_t)(off), (uint64_t)(len)))

/*
 * READING SCALARS OUT OF THE OBJECT
 *
 *     if (kof_u16(0) == 0x5a4d) ...
 *     uint32_t rva = kof_u32(ep + 1);
 *
 * The byte accessors, spelled the way they are used. Reaching through the vtable by
 * hand - ctx->content->rd32(ctx, off) - names the context twice and the mechanism
 * once, for a read that is the most ordinary thing a module does.
 *
 * Little endian, and that is a statement about the accessors rather than about
 * every structure a module reads. A big endian ELF's own headers arrive through the
 * parsed view with the byte order already dealt with - but a PACKER'S structures do
 * not: UPX writes its l_info and b_info in the target's byte order, into a file the
 * collector has no reason to normalise, so a module reading them on a big endian
 * object has to swap. kof_bswap* below is for exactly that, and it needs no second
 * set of accessors: these hand over the bytes and the module says what they mean.
 *
 * An out of range read yields zero rather than faulting, so a module that must tell
 * "the bytes there are zero" from "there are no bytes there" asks first:
 *
 *     if (kof_in_obj(off, 4) && kof_u32(off) == 0) ...
 */
/*
 * Byte order, for the structures the accessors above cannot know about.
 *
 * A module that reads a packer's own header on a big endian object needs these; one
 * that reads a format's header does not, because the collector normalised that
 * already. Written out rather than taken from a system header, because a signature
 * module has no libc and cannot include one.
 */
static inline uint16_t kof_bswap16(uint16_t v)
{
	return (uint16_t)((v >> 8) | (v << 8));
}

static inline uint32_t kof_bswap32(uint32_t v)
{
	return ((v & 0xff000000u) >> 24) | ((v & 0x00ff0000u) >> 8) |
	       ((v & 0x0000ff00u) << 8)  | ((v & 0x000000ffu) << 24);
}

/*
 * The object's symbol records, and how many bytes of them.
 *
 * Named like the other content accessors so a rule reads the same way:
 *
 *     uint32_t n; const uint8_t *b = kof_syms(&n), *r;
 *     for (i = 0; (r = kof_sym_rec(b, n, i)); i++)
 *             if (r[KOF_SYM_R_TYPE] == 1 && r[KOF_SYM_R_BIND] == 1)
 *                     ...
 *
 * NULL and zero for an object with no symbols - a stripped file, or any
 * non-ELF - which is a normal answer and stops the loop on its first test.
 */
#define kof_syms(np) ((ctx)->content->syms ? \
		      (ctx)->content->syms((ctx), (np)) : 0)

/*
 * WHICH CODE REFERS TO THE DATA AT `va`, AND HOW.
 *
 *     if (kof_data_xref(sym_value, sym_size) & (KOF_XREF_CALL | KOF_XREF_JUMP))
 *             ...this variable is executed, whatever its bytes look like
 *
 * The question a rule looking for a payload actually wants answered. Asking
 * what the BYTES look like - how unprintable they are, whether a syscall
 * instruction is in them - is defeated by encoding the payload, which is the
 * first thing anyone does to it. An ordinary variable is read; a payload is
 * executed; and that difference is in the code, where no encoding of the data
 * reaches.
 *
 * FIVE MECHANICAL FACTS AND NO CONCLUSIONS. The engine says what the
 * instructions did; what that MEANS is composed in bases/, next to the rest of
 * the vocabulary of malware. A rule looking for a payload staged into a fresh
 * mapping wants KOF_XREF_ARG, one looking for a direct call wants
 * KOF_XREF_CALL, and neither needs a line changed here.
 *
 * A RANGE, because a blob is not referred to at its first byte - see
 * kof_xref_in in kofdisasm/xref.h for the three-load measurement that says so.
 * Pass the variable's own size; 0 asks about the one address.
 *
 * Zero for a range nothing referred to, and zero for an object with no code to
 * sweep. NOT an assertion that the variable is unused: see KOF_XREF_PARTIAL.
 */
#define kof_data_xref(va, size) ((ctx)->content->data_xref ?               \
				 (ctx)->content->data_xref((ctx),           \
							   (uint64_t)(va),  \
							   (uint64_t)(size)) : 0u)

/* Code forms this address, or loads from it. */
#define KOF_XREF_READ    (1u << 0)
/* Code stores to it. */
#define KOF_XREF_WRITE   (1u << 1)
/* It is the target of a CALL - direct or through a register. A direct call
 * usually names code, and names a variable exactly when a compiler could prove
 * the target constant, which is what -O2 does to a called function pointer. */
#define KOF_XREF_CALL    (1u << 2)
/* The same, for a JMP. */
#define KOF_XREF_JUMP    (1u << 3)
/* It was in a register when a CALL happened - an argument, as far as a sweep
 * that knows no calling convention can tell. */
#define KOF_XREF_ARG     (1u << 4)
/*
 * The sweep gave up before it had seen everything - too many distinct
 * addresses, or code it could not decode. A rule may still trust a bit that IS
 * set; it may not read the absence of one as "not referred to".
 */
#define KOF_XREF_PARTIAL (1u << 5)
/*
 * A REGION THAT REFERS TO IT ALSO MAKES AN INDIRECT CALL.
 *
 * Evidence about the neighbourhood rather than about the address, and it exists
 * because the address facts miss the shape that matters most: a payload copied
 * into a fresh mapping and called there is never called, jumped to, or even
 * passed anywhere - and yet one region of code reads it and transfers control.
 *
 * A REGION, not a function: the boundaries come from RET, because the files
 * this has to work on are stripped and have no function table to read.
 *
 * MEASURED 11.6% ON CLEAN BINARIES, which is why no rule gates on it alone.
 */
#define KOF_XREF_RGN_ICALL (1u << 6)
/* ...or the region directly calls a region that does. One level. Measured 3.3%
 * on clean binaries, and it fires on programs that only read a lookup table:
 * every dynamically linked binary calls __libc_start_main through the GOT, from
 * the region its entry point is in. */
#define KOF_XREF_RGN_NEAR  (1u << 7)
/*
 * SOMETHING OTHER THAN STARTUP CODE REFERS TO IT.
 *
 * Every ELF carries code nobody wrote - the entry stub, the PLT thunks, .init
 * and .fini, and whatever .init_array registers - and all of it references data
 * that no rule about a person's program is looking for. The startup set is
 * found from the ELF's own structure, not from symbols: 4 of 400 binaries in
 * /usr/bin still carry `_start` as a symbol, and every one of them has an entry
 * point and an .init_array.
 *
 * Absent means the only code that ever mentions it is code the compiler wrote.
 * Measured: 87% of sized variables in clean binaries are in that position.
 */
#define KOF_XREF_USER      (1u << 8)

#define kof_u8(off)  ((ctx)->content->rd8 ((ctx), (uint64_t)(off)))
#define kof_u16(off) ((ctx)->content->rd16((ctx), (uint64_t)(off)))
#define kof_u32(off) ((ctx)->content->rd32((ctx), (uint64_t)(off)))
#define kof_u64(off) ((ctx)->content->rd64((ctx), (uint64_t)(off)))

/*
 * Are n bytes at off inside the object?
 *
 * Written as "n <= size - off" after establishing "off <= size", so no addition
 * happens and nothing can wrap - both arguments may be values the file chose.
 *
 * A function under the macro rather than the comparison inline, because a module
 * asking about a constant offset - kof_in_obj(0, 4), which is how a magic check
 * reads - would otherwise trip -Wtype-limits on "0 <= unsigned". The signature
 * build treats warnings as errors, so that would make the natural spelling
 * unwritable.
 */
static inline int kof_range_in_obj(uint64_t obj_size, uint64_t off, uint64_t n)
{
	return off <= obj_size && n <= obj_size - off;
}

#define kof_in_obj(off, n)                                                 \
	kof_range_in_obj((ctx)->obj_size, (uint64_t)(off), (uint64_t)(n))

/* Compare bytes the module built at run time. kof_find_str_at is the one to reach
 * for when the bytes are a declared pattern; this is for bytes that are not. */
#define kof_memeq(off, p, n)                                               \
	((ctx)->content->memeq((ctx), (uint64_t)(off), (p), (uint32_t)(n)))

#define kof_csum(off, n)                                                   \
	((ctx)->content->csum((ctx), (uint64_t)(off), (uint32_t)(n)))

/*
 * YIELDING CHILD OBJECTS
 *
 *     kof_child_window(off, len)     a range of this object, no copy
 *     kof_emit(bytes, n)             bytes that did not exist before
 *     kof_child()                    close this child, start the next
 *
 * Every one returns zero when the engine will take no more - the budget is gone,
 * or the tree is as deep or as wide as it is allowed to get. A module must stop
 * when it sees that, and looping regardless costs nothing but achieves nothing:
 * the host has already stopped accepting.
 *
 * A decompressor therefore looks like this, and cannot be written to allocate
 * first and check afterwards:
 *
 *     while (more_input) {
 *             n = inflate_some(buf, sizeof buf);
 *             if (!kof_emit(buf, n))
 *                     return;              // budget gone; the scan says so
 *     }
 *     kof_child();
 */
#define kof_child_window(off, len)                                         \
	((ctx)->content->window ?                                          \
	 (ctx)->content->window((ctx), (uint64_t)(off), (uint64_t)(len)) : 0)

#define kof_emit(bytes, n)                                                 \
	((ctx)->content->emit ?                                            \
	 (ctx)->content->emit((ctx), (bytes), (uint32_t)(n)) : 0)

#define kof_child()                                                        \
	((ctx)->content->child ? (ctx)->content->child((ctx)) : 0)

/*
 * Join a scattered region into the object being produced. See `gather` above.
 *
 * Does not close the child: a module gathering two regions into one object is a
 * legitimate thing to want, so where the object ends stays the module's decision.
 */
#define kof_gather_max(region_mask, cap)                                   \
	((ctx)->content->gather ?                                          \
	 (ctx)->content->gather((ctx), (uint32_t)(region_mask),            \
				(uint64_t)(cap)) : 0)

/* Bounded by the host's ceiling alone. */
#define kof_gather(region_mask) kof_gather_max((region_mask), 0)

/*
 * Measure a region instead of reading it.
 *
 *     struct kof_region_shape u;
 *     if (kof_region_shape(KOF_SCAN_ELF_UNCLAIMED, &u) && u.widest >= 4096)
 *             ...  u.widest_off is where the run starts
 *
 * Non-zero when *out was filled. See `region_shape` in struct kof_content.
 */
#define kof_region_shape(mask, out)                                        \
	((ctx)->content->region_shape ?                                    \
	 (ctx)->content->region_shape((ctx), (uint32_t)(mask), (out)) : 0)

/*
 * How random that region's bytes are, in eighths of a bit - 0 to 64.
 *
 *     if (kof_region_entropy(KOF_SCAN_ELF_UNCLAIMED) >= 8u * 7u) ...
 *
 * Eighths and not a fraction: a module has no floating point. See
 * `region_entropy` in struct kof_content.
 */
#define kof_region_entropy(mask)                                           \
	((ctx)->content->region_entropy ?                                  \
	 (ctx)->content->region_entropy((ctx), (uint32_t)(mask)) : 0u)

/*
 * How random the bytes at [off, off+len) are, in eighths of a bit.
 *
 *     if (kof_entropy_at(u.widest_off, u.widest) >= 8u * 2u) ...
 *
 * The extent form, for a caller that has one run rather than a region - see
 * `entropy_at` in struct kof_content for why the two are not the same question.
 */
#define kof_entropy_at(off, len)                                           \
	((ctx)->content->entropy_at ?                                      \
	 (ctx)->content->entropy_at((ctx), (uint64_t)(off),                \
				    (uint64_t)(len)) : 0u)

/*
 * Name the next child, from bytes already in this object.
 *
 *     kof_name_next(e->name_off, e->name_len);
 *     kof_child_window(e->data_off, e->size);
 *
 * Reporting only. Nothing in the engine reads a child's name back, and nothing
 * ever opens a path built from one - see the note in objsrc.h on why the produced
 * objects have no filename at all.
 */
/*
 * Declare what the next child is, when the structure said.
 *
 *     kof_child_format(KOF_FMT_SCRIPT);
 *     kof_child_window(off, len);
 *
 * See child_format for when a module may say this and when it must not.
 */
/*
 * Decode an entry's whole coding chain into a child.
 *
 *     kof_unpack_chain(e->index)
 *
 * For a container that has an entry table: the chain, its order and its
 * bounds are all the host's, and what the module supplies is which entry.
 */
/*
 * Would anything look inside a child of this format - ask before decoding.
 *
 *     if (!kof_fmt_wanted(KOF_FMT_FONT))
 *             continue;               // nothing targets fonts
 *
 * See fmt_wanted for why this is the module's decision and not the engine's,
 * and why a yes for KOF_FMT_UNKNOWN is not a loophole. Answers 1 when the host
 * offers no opinion, so a producer that asks is never worse off than one that
 * does not.
 */
#define kof_fmt_wanted(fmt)                                                \
	((ctx)->content->fmt_wanted ?                                      \
	 (ctx)->content->fmt_wanted((ctx), (uint8_t)(fmt)) : 1)

#define kof_unpack_chain(index)                                            \
	((ctx)->content->unpack_chain ?                                    \
	 (ctx)->content->unpack_chain((ctx), (uint32_t)(index)) : 0u)

/*
 * Declare what the next child is FOR.
 *
 *     kof_child_kind(KOF_ENT_CONTENT);
 *     kof_child_window(off, len);
 *
 * Also names it, when name_next found nothing to name it with.
 */
/*
 * Declare which entry the next child is the content of.
 *
 *     kof_child_entry(e->index);
 *     kof_unpack_chain(e->index);
 */
#define kof_child_entry(index)                                             \
	((void)((ctx)->content->child_entry ?                               \
		((ctx)->content->child_entry((ctx), (uint32_t)(index)), 0) : 0))

#define kof_child_kind(kind)                                               \
	((void)((ctx)->content->child_kind ?                                \
		((ctx)->content->child_kind((ctx), (uint32_t)(kind)), 0) : 0))

#define kof_child_format(fmt)                                              \
	((void)((ctx)->content->child_format ?                              \
		((ctx)->content->child_format((ctx), (uint8_t)(fmt)), 0) : 0))

#define kof_name_next(off, len)                                            \
	((void)((ctx)->content->name_next ?                                \
		((ctx)->content->name_next((ctx), (uint64_t)(off),         \
					   (uint64_t)(len)), 0) : 0))

/*
 * Decompress a DEFLATE stream at off into the object being produced.
 *
 * `len` bounds the input, not the output: the stream ends where DEFLATE says it
 * does, which is usually sooner. Returns bytes produced - zero when nothing could
 * be decoded, which is the answer for a corrupt stream and for a budget that was
 * already gone.
 *
 * It does not close the child. A module may want to put more after the
 * decompressed bytes, or decompress two streams into one object, so kof_child()
 * stays the module's to call:
 *
 *     kof_unpack_deflate(gz->data_off, gz->data_len);
 *     kof_child();
 */
#define kof_unpack_form(method, off, len, out_hint, form)                  \
	((ctx)->content->unpack ?                                          \
	 (ctx)->content->unpack((ctx), (uint32_t)(method), (uint64_t)(off),\
				(uint64_t)(len), (uint64_t)(out_hint),     \
				(uint32_t)(form)) : 0)

/* The output is already a file, which is the ordinary case. */
#define kof_unpack_at(method, off, len, out_hint)                          \
	kof_unpack_form((method), (off), (len), (out_hint), KOF_FORM_RAW)

/*
 * Decode the front of a stream into `buf`, for a header that is compressed.
 *
 *     uint8_t hdr[512];
 *     n = kof_unpack_peek(KOF_UNP_NRV2E_8, off, len, hdr, sizeof hdr);
 *
 * Reads; produces nothing. See `unpack_peek` above for why it exists.
 */
#define kof_unpack_peek(method, off, len, buf, cap)                        \
	((ctx)->content->unpack_peek ?                                     \
	 (ctx)->content->unpack_peek((ctx), (uint32_t)(method),            \
				     (uint64_t)(off), (uint64_t)(len),     \
				     (buf), (uint32_t)(cap)) : 0u)

/* DEFLATE streams, so it needs no size: spelled out because a gzip or zip module
 * has nothing sensible to pass and should not have to invent one. */
#define kof_unpack_deflate(off, len)                                       \
	kof_unpack_at(KOF_UNP_DEFLATE, (off), (len), 0)

/* The same, for a stream that carries zlib framing - or might. The host checks
 * the header and falls back to raw DEFLATE when there is none, so a caller that
 * cannot tell the two apart names this one. Needs no size either. */
#define kof_unpack_zlib(off, len)                                          \
	kof_unpack_at(KOF_UNP_ZLIB, (off), (len), 0)

/*
 * Decode entry `index` of this object into the object being produced.
 *
 * For an entry whose bytes are scattered - a compound file stream is a chain, not
 * a range - which is why this takes an index and not an offset. See `unpack_entry`.
 *
 *     kof_name_next(e->name_off, e->name_len);
 *     if (kof_unpack_entry(KOF_UNP_OVBA, i, 0))
 *             kof_child();
 */
#define kof_unpack_entry(method, index, out_hint)                          \
	((ctx)->content->unpack_entry ?                                    \
	 (ctx)->content->unpack_entry((ctx), (uint32_t)(method),            \
				      (uint32_t)(index),                   \
				      (uint64_t)(out_hint)) : 0)

/*
 * Report that this object was not fully examined.
 *
 * For the case only the module knows about: a container it could open in part, a
 * compression method it does not implement, a structure that stopped making sense
 * part way through. Anything the host can see - budgets, ceilings, a corrupt
 * stream - it already records on its own.
 *
 * What it changes is the verdict: the object is reported as not fully examined
 * instead of as clean, with the reason given. Whether it also returns is the
 * caller's choice and is spelled by which of the two forms below is used.
 *
 *     KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);   - records and returns
 *     kof_unp_broken(KOF_UNP_DAMAGED);       - records and carries on
 */
/*
 * Reasons a module can give. The same set the host uses on its own account, so a
 * caller sees one vocabulary whoever noticed the problem.
 */
enum kof_unp_broken {
	KOF_UNP_LIMIT = 1,       /* a budget or ceiling stopped it */
	KOF_UNP_UNSUPPORTED = 2, /* a coding or version this build lacks */
	KOF_UNP_DAMAGED = 3,     /* the object's own structure is wrong */
	/*
	 * The content is encrypted and there is no key.
	 *
	 * Apart from UNSUPPORTED because they end differently: a coding this build
	 * lacks is a gap a later build closes, and this one never closes. Every
	 * container that carries encryption uses this value, so the reason reads the
	 * same whichever format noticed it.
	 */
	KOF_UNP_ENCRYPTED = 4
};

/*
 * Two forms, and the case is what tells them apart.
 *
 * KOF_UNP_BROKEN records the reason and RETURNS, which is what nearly every site
 * wants: the module has found out it cannot go on, and the `return` underneath was
 * a line that only ever said so again. Upper case because it changes control flow -
 * the same rule KOF_SCAN_MATCH follows, and the reason a reader can tell which
 * macros end a function without looking any of them up.
 *
 * kof_unp_broken records and carries on, for the module that has recovered
 * something and means to keep it. That is now the commoner of the two - 37 call
 * sites against 18 - and every one of them is in a module that walks entries,
 * exactly as this note predicted when there were none: an entry in a zip whose
 * compression method this build lacks is a reason to record and move to the NEXT
 * entry, not to abandon the entries already recovered.
 */
#define kof_unp_broken(reason)                                             \
	((void)((ctx)->content->incomplete ?                               \
		((ctx)->content->incomplete((ctx), (uint32_t)(reason)), 0) : 0))

#define KOF_UNP_BROKEN(reason)                                             \
	do {                                                               \
		kof_unp_broken(reason);                                    \
		return;                                                    \
	} while (0)

/*
 * Where a declared string is within a range the module computed.
 *
 * KOF_BROKEN when absent, the same "could not be determined" every other
 * offset-valued accessor answers with. For locating a structure rather than
 * detecting one: kof_find_str_in asks whether a marker is present, this asks where
 * it is so the rest can be read relative to it.
 */
#define kof_find_str_where(off, len, s)                                    \
	((ctx)->content->find_str_where ?                                  \
	 (ctx)->content->find_str_where((ctx), KOF_PASTE(kof_strid_, s),   \
					(uint64_t)(off), (uint64_t)(len))  \
	 : KOF_BROKEN)

/* Non-zero if at least one of them is present. Stops at the first hit. */
#define kof_find_str_any(rng, ...) (KOF_FS_FOLD(||, rng, __VA_ARGS__))

/* Non-zero only if every one of them is present. Stops at the first miss. */
#define kof_find_str_all(rng, ...) (KOF_FS_FOLD(&&, rng, __VA_ARGS__))

/*
 * How many of them are present: a threshold, written as one.
 *
 * Distinct strings, not occurrences. A marker appearing forty times in a file says
 * the same thing as one appearing once, so counting occurrences would let a single
 * repeated string clear a threshold meant to require several different ones - which
 * is the difference between "this file has four traits of the family" and "this file
 * mentions one thing a lot".
 */
#define kof_find_str_multi(rng, ...) (KOF_FS_FOLD(+, rng, __VA_ARGS__))

/*
 * What kind of malware a detection is, for the report string the host composes at
 * report time - see KOF_TARGET_NAME below for the declaration, and
 * kof_maltype_name just after this enum for the word a finding shows.
 *
 * Plain values, not a mask: a module names one type, never an OR of several, so
 * there is nothing here for a bit to buy. Unlike KOF_FMT_* and KOF_ARCH_*, whose
 * numbers are fixed because they are ORed into a mask stored in every pack, these are never
 * combined and never stored as a mask - so a new value is appended at the end and
 * costs nothing to add. Append only, though: an existing entry moving to a different
 * number would be silent everywhere a database built before the move is still read
 * against a build after it.
 */
/*
 * X(NAME, display word). Read like KOF_ARCH_LIST above: the enum, the word a
 * finding shows, and the parse a build tool needs to turn "KOF_MALTYPE_TROJAN"
 * in a source back into a value all come from here. ksigbuilder kept the parse
 * direction as a table of its own, with a comment admitting it was a second
 * copy that could only fail loudly once someone hit it.
 */
#define KOF_MALTYPE_LIST(X)                                                  \
	X(KOF_MALTYPE_VIRUS,    "Virus")                                     \
	X(KOF_MALTYPE_TROJAN,   "Trojan")    /* covers spyware */            \
	X(KOF_MALTYPE_ROOTKIT,  "Rootkit")                                   \
	X(KOF_MALTYPE_BOTNET,   "Botnet")                                    \
	X(KOF_MALTYPE_RANSOM,   "Ransom")                                    \
	X(KOF_MALTYPE_MINER,    "Miner")                                     \
	X(KOF_MALTYPE_ADWARE,   "Adware")                                    \
	X(KOF_MALTYPE_EXPLOIT,  "Exploit")                                   \
	X(KOF_MALTYPE_DROPPER,  "Dropper")   /* covers downloader */         \
	X(KOF_MALTYPE_HACKTOOL, "Hacktool")

enum kof_maltype {
#define KOF_MALTYPE_X_ENUM(name, word) name,
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_ENUM)
#undef KOF_MALTYPE_X_ENUM
	/* A terminator, not a bound anything indexes: every table of these is
	 * expanded from the list above, so none can disagree with it, and
	 * kof_maltype_name answers a value from outside with "Malware". */
	KOF_MALTYPE_COUNT
};

/*
 * The word a finding shows for one of the values above. Read at report time: the
 * pack stores the enum value and the family text once per module, not composed
 * into a string until a finding actually needs printing - see
 * struct kof_pack_mod in kofpack.h and finding_str in scan.c.
 */
static inline const char *kof_maltype_name(uint32_t maltype)
{
	switch (maltype) {
#define KOF_MALTYPE_X_NAME(name, word) case name: return word;
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_NAME)
#undef KOF_MALTYPE_X_NAME
	default: return "Malware";
	}
}

/*
 * The identifier a signature source writes for one of these - for a tool that
 * generates source, so the spelling comes from the list above rather than from
 * a second copy of it. kof_maltype_name gives the word a report shows.
 */
static inline const char *kof_maltype_ident(uint32_t maltype)
{
	switch (maltype) {
#define KOF_MALTYPE_X_IDENT(name, word) case name: return #name;
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_IDENT)
#undef KOF_MALTYPE_X_IDENT
	default: return "KOF_MALTYPE_VIRUS";
	}
}

/* The way back: the identifier a signature source writes, to its value. Whole
 * names only, for the reason kof_arch_from_name gives. */
static inline int kof_maltype_from_name(const char *s, int *out)
{
#define KOF_MALTYPE_X_FROM(name, word)                                       \
	if (kof_streq_(s, #name)) { *out = (int)(name); return 1; }
	KOF_MALTYPE_LIST(KOF_MALTYPE_X_FROM)
#undef KOF_MALTYPE_X_FROM
	return 0;
}

/*
 * Declare which object formats this module applies to.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_ELF);
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
#define KOF_TARGET_FORMAT(mask)

/*
 * Declare that this module targets a kind of EVENT rather than a file format.
 *
 *     KOF_TARGET_EVENT(KOF_EVT_AMSI);
 *
 * The same declaration as KOF_TARGET_FORMAT and read the same way - there is
 * one target axis and this is a second spelling of it, not a second axis. It
 * exists because an author writing a rule about a script submission should not
 * have to call it a format; see KOF_EVT_AMSI.
 *
 * A module may use one or the other and not both: they say the same thing, so
 * two of them is two answers to one question.
 */
#define KOF_TARGET_EVENT(mask)

/*
 * Declare what this module detects: a type from enum kof_maltype, and a family name
 * this module's author picks.
 *
 *     KOF_TARGET_NAME(KOF_MALTYPE_BOTNET, "Mirai");
 *
 * Expands to nothing, like KOF_TARGET_FORMAT - ksigbuilder reads it out of the
 * source and composes it into every detection name this file reports, so
 * KOF_SCAN_INFECT/KOF_SCAN_SUSPECT below need only say the variant.
 *
 * Exactly one per file, and required before the first KOF_SCAN_INFECT/SUSPECT call -
 * not merely before compile, but earlier in the source, because a module that never
 * calls either never reports a name and this declaration would constrain nothing for
 * it. That is also why this is not required for an unpack module: it has no findings
 * to name, only bytes to produce.
 *
 * The family string is free text for now - no character restrictions enforced yet.
 * That is a gap, not a decision: enforcing ASCII-only, no spaces, no separators is
 * planned but not built. A "." in the family would be indistinguishable from the
 * separator the composed name uses between type, family and variant, so avoid it
 * until the check exists to refuse it.
 */
#define KOF_TARGET_NAME(type, family)

/*
 * Which kinds of that format, as a mask over the format's own subtype values.
 *
 *     KOF_TARGET_FORMAT(KOF_FMT_ELF);
 *     KOF_TARGET_SUBTYPE(KOF_ELF_REL);        - relocatable objects only
 *
 * Absent means unconstrained, so every module written before this existed keeps
 * running against everything it used to. Expands to nothing, like the other
 * declarations: the build reads it out of the source into the record beside the
 * blob, and the host evaluates it against a fact the collector already produced.
 *
 * The values come from the format header the module includes, and naming one
 * format's values while targeting another is refused at build time - see the note
 * on ctx->subtype for why the numbers overlap.
 */
#define KOF_TARGET_SUBTYPE(mask)

/*
 * Preconditions the host checks without running the module.
 *
 *     KOF_TARGET_SIZE_MIN(1024);
 *     KOF_TARGET_ARCH(KOF_ARCH_X86_64);
 *
 * Both expand to nothing and both work the way KOF_TARGET_FORMAT does: the build reads them
 * out of the source into the record beside the blob, and the host evaluates them
 * against facts the collector already produced. A module that fails one costs a few
 * integer comparisons against that record instead of a call and a scan.
 *
 * Declaring rather than coding the check is what makes it a filter. The same test
 * written inside kof_scan is correct and useless for filtering, because reaching it
 * costs exactly what filtering saves. It follows that a declared precondition must
 * not also be written in the body: two copies of one condition are two things that
 * can disagree, and the declaration is the one the host trusts.
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
 *
 * Only cheap, always-available facts belong here - size, format, architecture.
 * Anything that needs bytes read or a decision made stays in kof_scan, where the full
 * language is available. A precondition language rich enough to express real logic
 * would be a second, worse programming language, which is the trap this whole design
 * exists to avoid.
 */
#define KOF_TARGET_SIZE_MIN(min)
#define KOF_TARGET_ARCH(mask)

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
 *     KOF_TARGET_RANGE(loaded, KOF_SCAN_ELF_CODE | KOF_SCAN_ELF_DATA);
 *
 * Named so the build can turn it into an index, which is what lets kof_find_str
 * paste both ids from identifiers - it could not do that from an expression like
 * "A | B". A plain #define would work and read as a local implementation detail
 * rather than part of the declared shape of the signature.
 */
#define KOF_TARGET_RANGE(name, scan_mask)

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
 * Declare a string the target holds as UTF-16LE.
 *
 *     KOF_DEFINE_STR_WIDE(iex, "IEX(New-Object", KOF_CASE_EXACT,
 *                         KOF_WORD_SUBSTRING);
 *
 * Written as the text a person reads; stored as the bytes the target has. A
 * PowerShell script block reaches AMSI as UTF-16, so "IEX" is 49 00 45 00 58 00
 * on the wire, and a rule that declared it as a plain literal would look for
 * three bytes that are never adjacent there.
 *
 * A BUILD-TIME EXPANSION, NOT A COMPARE MODE. The high bytes are interleaved
 * here and the result is an ordinary pool entry, so the matcher is unchanged
 * and the presence set still works - the wide form carries its own four
 * concrete bytes to key on. A runtime "wide" flag would have done neither: the
 * fast nocase path anchors inside memchr, and a compare mode that skipped
 * bytes could not use it.
 *
 * ASCII ONLY. Each character becomes one byte and a zero, which is UTF-16LE
 * for U+0000..U+007F and wrong for anything above it. A pattern with a byte
 * over 0x7F is refused rather than encoded incorrectly - a marker that is
 * silently the wrong bytes is a rule that silently never fires.
 *
 * KOF_WORD_FULLWORD WORKS, AND IS TESTED AT CHARACTER GRANULARITY - which is
 * the only way it can mean anything here.
 *
 * A byte-level fullword test asks what the neighbouring BYTES are. After a
 * wide match that is already right: the pattern ends with a zero high half, so
 * the next byte is the low half of the following character. Before it, it is
 * not: the previous byte is the zero high half of the preceding character, and
 * a zero is never a word byte - so the leading test would pass on every match
 * and "IEX" would match inside "PIEXY" while the source said it does not.
 *
 * So a wide literal carries KOF_STR_WIDE and the matcher steps back a whole
 * character on the leading side. See that flag for the exact test.
 */
#define KOF_DEFINE_STR_WIDE(name, lit, casing, word)

/*
 * Declare a byte pattern with wildcards, jumps and alternatives.
 *
 *     KOF_DEFINE_HEXSTR(call32,  "E8 ?? ?? ?? ?? 5D C3");
 *     KOF_DEFINE_HEXSTR(nibble,  "E8 ?4 4?");
 *     KOF_DEFINE_HEXSTR(spaced,  "6A 40 [4-6] 8D 4D");
 *     KOF_DEFINE_HEXSTR(anyjmp,  "6A 40 [-] 8D 4D");
 *     KOF_DEFINE_HEXSTR(opcodes, "( E8 | E9 ) ?? ?? ?? ??");
 *
 * The syntax is YARA's, because it is the one researchers already write and it
 * covers the cases that come up: "??" and "?4" are masks, "[4-6]" is a gap, and a
 * group is a set of alternatives. Used with kof_find_str and its _any / _all /
 * _multi forms exactly like a literal - the call site does not know which kind it
 * named, which is the point.
 *
 * Compiled at build time, so a malformed pattern is a build error naming a line
 * rather than a search that silently matches nothing. What the compiler refuses:
 *
 *   a gap inside an alternative      an alternative has to have a length
 *   a leading or trailing gap        that is not a pattern, it is a shorter pattern
 *   no concrete byte anywhere        it would match everything
 *   more parts than the caps allow   see hexprog.h; the bound is what keeps
 *                                    matching a hostile object affordable
 *
 * Case and word options do not apply. Folding case on a byte that may be a wildcard
 * means nothing, and a word boundary is a property of text.
 *
 * One thing worth knowing when writing them: the compiler searches for the longest
 * run of concrete bytes, and the presence set - which rules a pattern out for an
 * object without touching it - keys on four. A pattern whose longest run is shorter
 * than that is searched on every object of its format. The compiler prints the run
 * length for each pattern so this is visible at build time rather than in a profile.
 */
#define KOF_DEFINE_HEXSTR(name, hex)

/*
 * Report a finding and stop. The level is the macro, not a parameter - so a reader
 * sees what was decided without looking up a second argument.
 *
 *     KOF_SCAN_INFECT("Variant-42bb");     custom variant, this module's own text
 *     KOF_SCAN_INFECT(KOF_MALVAR_GENERIC); the family's one generic bucket
 *     KOF_SCAN_INFECT(KOF_MALVAR_AUTO);    variant derived from the guarding pattern
 *     KOF_SCAN_SUSPECT(...)                same three forms, KOF_LVL_SUSPECT instead
 *
 * The name id is the source line, which is why the argument can be dropped from the
 * expansion below: the build scans this source, resolves whichever of the three
 * forms was written, composes it with the KOF_TARGET_NAME this file declared, and
 * writes "<line> <name>" into a table the host loads beside the blob. Same mechanism
 * every declaration here uses, and the same failure mode - a table out of step with
 * the blob shows up as a missing name, never as a wrong one.
 *
 * KOF_MALVAR_GENERIC and KOF_MALVAR_AUTO need no #define to compile - the argument is
 * never evaluated, only read as text by the build - but are given self-referential
 * ones below so an editor does not flag them as undeclared.
 *
 * KOF_MALVAR_AUTO must directly guard - be the sole condition of the enclosing
 * if (kof_find_str_any/all/multi(...)) - because the variant it produces is a hash of
 * that call's region and patterns, not of anything KOF_SCAN_INFECT/SUSPECT itself is
 * given. That is what makes it stable across rebuilds without a registry: the same
 * patterns in the same region hash the same way every time, and a module compiled
 * next to a hundred others does not need to know what they are named.
 *
 * Takes no context, for the reason the search macros do not: it names `ctx`, which
 * KOF_DEFINE_SCAN put in scope. Leaving it explicit here while the searches beside it
 * are not would be the worst of both - a parameter that is sometimes required and
 * never meaningful.
 *
 * The report and the return are one statement so neither half can be forgotten.
 */
#define KOF_MALVAR_AUTO    KOF_MALVAR_AUTO
#define KOF_MALVAR_GENERIC KOF_MALVAR_GENERIC

#define KOF_SCAN_INFECT(variant)                                            \
	do {                                                                \
		(ctx)->report((ctx), (uint32_t)KOF_LVL_INFECT, (uint32_t)__LINE__); \
		return;                                                     \
	} while (0)

#define KOF_SCAN_SUSPECT(variant)                                           \
	do {                                                                \
		(ctx)->report((ctx), (uint32_t)KOF_LVL_SUSPECT, (uint32_t)__LINE__); \
		return;                                                     \
	} while (0)

/*
 * Say what was worked out, without deciding anything.
 *
 * KOF_SCAN_MATCH reports and returns; this reports and carries on. It is for the cases
 * where the useful information is not the verdict - which packer version was
 * recognised, how far a block chain got, which coding a stream used - and where
 * stopping would be wrong because the module has work left to do.
 *
 * The name is a literal, extracted at build time exactly as a detection name is,
 * so it costs the blob nothing. `value` is one number the module computed; pass
 * zero when there is nothing to say beyond the name.
 *
 *     kof_debug("UPX.PE.NRV2E", version);
 *
 * Invisible unless the host asked. Nothing in the scan path reads these and no
 * verdict depends on one, so leaving them in a shipped module costs a NULL test
 * per call - which is why they are meant to be left in.
 */
#define kof_debug(name, value)                                              \
	((void)((ctx)->debug ?                                              \
		((ctx)->debug((ctx), (uint32_t)__LINE__, (uint64_t)(value)), 0) : 0))

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

#endif /* KOFENG_KOFSIG_H */
