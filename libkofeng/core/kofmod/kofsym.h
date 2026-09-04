/*
 * kofsym.h - a file's symbol table, re-presented in one fixed layout.
 *
 * WHY RE-PRESENT IT AT ALL.
 *
 * The symbols are already in the file and already scannable: .symtab and .strtab
 * are non-ALLOC sections, so NOLOAD covers them and a signature can match their
 * bytes today. That is what makes the existing SCLoader rule fragile - it
 * matches "\0shellcode\0", which is a STRING TABLE byte run. Rename the variable
 * and the rule dies; a debug string elsewhere in NOLOAD that happens to spell
 * the same thing matches it for free.
 *
 * What a rule actually wants to say is "a GLOBAL OBJECT of 949 bytes", and the
 * file does hold that - as st_info's two nibbles and st_size, inside a 24-byte
 * Elf64_Sym. Matching THAT directly has two problems. The layout is ELF64's:
 * ELF32 packs the same fields in 16 bytes in a different order, and a PE export
 * table shares none of it. And the NAME is not there - st_name is an index into
 * another section - so name and attributes can never be one pattern.
 *
 * So the records below are OURS. Fixed stride, every field at a constant offset,
 * the name inline. A rule can then say type, bind, size and name in a single
 * pattern, and mean it about a symbol rather than about some bytes that happened
 * to spell it.
 *
 * THE VALUES ARE ELF'S, THOUGH, AND DELIBERATELY.
 *
 * type, bind and visibility carry the numbers ELF itself defines - STT_OBJECT is
 * 1 here because it is 1 in the ABI, STT_SECTION is 3 and STT_FILE is 4 in that
 * order because that is the order the standard fixed. Inventing a private
 * numbering would buy nothing and cost everyone who writes a rule a translation
 * table, and it would rot the first time a value was added. A format with its
 * own vocabulary - PE's export ordinals - maps INTO these, which is the same
 * direction kof_inspect_subtype_name already goes.
 *
 * AN EMPTY BLOCK IS A NORMAL ANSWER. A stripped binary has no .symtab, so the
 * count is zero and the block is a header alone. That is not a failure to
 * report: it is what the file says. NOLOAD behaves the same way and for the same
 * reason.
 */

#ifndef KOF_KOFSYM_H
#define KOF_KOFSYM_H

#include <stdint.h>
#include <kofmod/kofsig.h>   /* struct kof_range, KOF_SCAN_SYM_* */

/*
 * The block: one header, then `count` records of KOF_SYM_RECLEN bytes.
 *
 * reclen is in the header rather than assumed by the reader, so a record that
 * grows later is a version bump and not a silent misparse of every field after
 * the one that moved.
 */
#define KOF_SYM_MAGIC0  'K'
#define KOF_SYM_MAGIC1  'S'
#define KOF_SYM_MAGIC2  'Y'
#define KOF_SYM_MAGIC3  'M'
/*
 * 3.
 *
 * Version 1 put the name at 24 with the numeric fields in front of it; a reader
 * that trusted those offsets would decode every record wrong, so the number had
 * to move with the layout. Version 3 gives the two reserved header bytes a
 * meaning - the index of `_start` - which a version 2 reader would read as the
 * zero the contract promised. Records are untouched between 2 and 3.
 */
#define KOF_SYM_VERSION 3u
#define KOF_SYM_HDRLEN  16u
#define KOF_SYM_RECLEN  64u
#define KOF_SYM_NAMELEN 40u     /* inline, NUL-padded, truncated if longer */

/* Header field offsets. */
#define KOF_SYM_H_MAGIC     0u  /* 4  "KSYM"                                  */
#define KOF_SYM_H_VERSION   4u  /* 2  KOF_SYM_VERSION                         */
#define KOF_SYM_H_RECLEN    6u  /* 2  KOF_SYM_RECLEN                          */
#define KOF_SYM_H_COUNT     8u  /* 4  records that follow                     */
#define KOF_SYM_H_ORIGIN   12u  /* 1  KOF_SYM_ORIGIN_*                        */
#define KOF_SYM_H_TRUNC    13u  /* 1  1 when the cap stopped it short         */
/*
 * THE INDEX OF `_start`, or KOF_SYM_NO_START when the block has none.
 *
 * In the two bytes that were reserved, so the header stays sixteen and every
 * record offset is unchanged. Sixteen bits is enough by construction:
 * KOF_SYM_MAX_RECS is 4096, so no valid index needs more, and 0xffff cannot
 * collide with one.
 *
 * WHY THE BUILDER RECORDS IT. `_start` comes from crt1.o, which the link line
 * puts before the object a person wrote, so a program's own globals are emitted
 * after it. A rule looking for a payload in a global can therefore begin at
 * `_start` + 1 rather than at record zero - on the loaders measured that is 6
 * or 7 records to examine instead of 63 to 66.
 *
 * The builder is the only place this is free. It already reads every name to
 * copy it into the record, so noticing one costs a comparison it is
 * effectively already doing; a rule finding the same index would have to walk
 * the names itself, which is the search the index exists to avoid.
 *
 * WHAT IT IS NOT. This is a CONVENTION OF THE LINK, not a rule of the format.
 * ELF guarantees only that local symbols precede global ones - that is sh_info
 * - and says nothing about the order among globals. A static link, -nostartfiles,
 * a different libc or a linker that emits in another order can all put a global
 * before `_start`, and a rule that starts after it would not see that global.
 * So it is offered as a starting point, never as a bound: a rule that must not
 * miss anything walks from zero, and one that trades that for a shorter walk
 * does so knowingly.
 */
#define KOF_SYM_H_START    14u  /* 2  index of `_start`, or KOF_SYM_NO_START  */
#define KOF_SYM_NO_START  0xffffu

/*
 * RECORD FIELD OFFSETS, ORDERED FOR THE PATTERN THAT MATCHES THEM.
 *
 * Not ELF's order, and it never was - ELF has TWO orders, which is the whole
 * reason this layout exists. Elf64_Sym is name,info,other,shndx,value,size and
 * Elf32_Sym is name,value,size,info,other,shndx: the same fields in different
 * places, so neither can be the layout a rule is written against. What is taken
 * from the standard is the ENUM VALUES - STT_*, STB_*, STV_* below - because a
 * private numbering would cost every rule author a translation table.
 *
 * The order here is chosen so that WHAT A RULE MATCHES ON IS CONTIGUOUS.
 * Attributes first, then the name immediately after them, because the question
 * a rule asks is almost always some form of "a GLOBAL OBJECT called X": with
 * the numeric fields in between - as they were, twenty bytes of shndx,
 * reserved, value and size - that one question needed a hex pattern with a gap
 * step across all twenty, on every rule. Now the four attribute bytes and the
 * name are one run and the pattern has no gap in it at all.
 *
 * The numeric fields go last because they are READ far more often than they are
 * matched: an address and a size move with every build, so a rule that pinned
 * them would be a rule about one binary.
 *
 * ALIGNMENT IS DELIBERATELY NOT PRESERVED. value and size are at 54 and 46,
 * neither 8-aligned, and that is safe because nothing casts a pointer into a
 * record - every read goes through kof_rd_* or the viewer's own byte loop, both
 * of which assemble the value a byte at a time. Alignment would have cost the
 * contiguity above, which is the property that matters.
 *
 * The record stays 64 bytes rather than shrinking to the 62 the fields need.
 * A power of two keeps a record an exact number of hex rows - four at sixteen
 * bytes to the row, eight at eight - so record boundaries line up down the
 * pane instead of walking across it.
 */
#define KOF_SYM_R_TYPE      0u  /* 1  STT_*  - ELF's numbering                */
#define KOF_SYM_R_BIND      1u  /* 1  STB_*                                   */
#define KOF_SYM_R_VIS       2u  /* 1  STV_*                                   */
#define KOF_SYM_R_FLAGS     3u  /* 1  KOF_SYM_F_*                             */
#define KOF_SYM_R_NAME      4u  /* 40 NUL-padded - adjacent to the attributes */
#define KOF_SYM_R_SHNDX    44u  /* 2  section index; 0 is ELF's SHN_UNDEF,    */
                                /*    0xffff any reserved index (ABS, COMMON) */
#define KOF_SYM_R_SIZE     46u  /* 8  size, little endian                     */
#define KOF_SYM_R_VALUE    54u  /* 8  address, little endian                  */
#define KOF_SYM_R_RESERVED 62u  /* 2  zero                                    */

/* Which table the block was built from. */
enum kof_sym_origin {
	KOF_SYM_ORIGIN_NONE   = 0,
	KOF_SYM_ORIGIN_SYMTAB = 1,   /* ELF .symtab - full, removed by strip     */
	KOF_SYM_ORIGIN_DYNSYM = 2,   /* ELF .dynsym - what dynamic linking needs */
	/*
	 * A PE's import and export directories.
	 *
	 * A NEW VALUE IN AN EXISTING FIELD, not a new field, so the layout is
	 * unchanged and the version does not move: a reader that predates this
	 * sees a number it does not know and falls to its default, which is
	 * the same "unknown origin" it would have printed anyway.
	 *
	 * One value for both directories because they are one block, and which
	 * half a record came from is already in its flags - UNDEFINED is an
	 * import, DEFINED is an export. A second origin would say the same
	 * thing twice and let the two disagree.
	 */
	KOF_SYM_ORIGIN_PE_DIR = 3
};

/*
 * Facts the record states that the ELF fields only imply.
 *
 * DEFINED and UNDEFINED are st_shndx tested once here rather than by every rule
 * that cares, and IN_WRITABLE / IN_EXEC are the flags of the section the symbol
 * lands in - which is the question "is this data the program can jump to", and
 * the one a loader heuristic actually asks.
 */
enum kof_sym_flag {
	KOF_SYM_F_DEFINED     = 1u << 0,
	KOF_SYM_F_UNDEFINED   = 1u << 1,   /* an import                          */
	KOF_SYM_F_IN_WRITABLE = 1u << 2,
	KOF_SYM_F_IN_EXEC     = 1u << 3,
	KOF_SYM_F_HAS_SIZE    = 1u << 4
};

/* ELF's own values, repeated so a reader of this file need not go and get them.
 * They are the ABI's; do not renumber. */
enum { KOF_STT_NOTYPE = 0, KOF_STT_OBJECT = 1, KOF_STT_FUNC = 2,
       KOF_STT_SECTION = 3, KOF_STT_FILE = 4, KOF_STT_COMMON = 5,
       KOF_STT_TLS = 6 };
enum { KOF_STB_LOCAL = 0, KOF_STB_GLOBAL = 1, KOF_STB_WEAK = 2 };
enum { KOF_STV_DEFAULT = 0, KOF_STV_INTERNAL = 1, KOF_STV_HIDDEN = 2,
       KOF_STV_PROTECTED = 3 };

/*
 * How many records one block may hold.
 *
 * Symbol counts run to 43912 on real binaries - elf.h says so and that is why
 * the parse does not store them - and 43912 records is 2.8MB of block for a file
 * nobody asked a symbol question about. The cap bounds it; the header's
 * `truncated` byte says when it bit, so a reader is never quietly told a short
 * table is the whole one.
 */
#define KOF_SYM_MAX_RECS 4096u
#define KOF_SYM_MAX_BYTES (KOF_SYM_HDRLEN + KOF_SYM_MAX_RECS * KOF_SYM_RECLEN)

/*
 * Build the block for an ELF. Returns the bytes written - never less than the
 * header, so an empty answer is still a block a reader can parse. `cap` bounds
 * it; KOF_SYM_MAX_BYTES is enough for the record cap.
 */
/* ---- reading a block ------------------------------------------------------
 *
 * THE CANONICAL READERS. Everything that reads a KSYM block goes through these
 * - the engine, kofexamine, kofviewer and any module - because the alternative
 * is what was there first: three private copies of the same four lines, which
 * is three places to get the bounds wrong and three to forget when the layout
 * moves. The layout HAS moved once already (see the note on version 2).
 *
 * kof_sym_rec is the whole of the walk a rule needs. It answers the question
 * "is there a record i" with a pointer or NULL, so a loop is
 *
 *     for (i = 0; (r = kof_sym_rec(b, n, i)); i++)
 *             if (r[KOF_SYM_R_TYPE] == STT_OBJECT && ...)
 *
 * and cannot run past the block: the bound is checked from the header's own
 * count AND from the byte length, so a truncated or malformed block stops the
 * loop rather than reading into whatever follows.
 *
 * That loop is also why the record length is fixed. A rule steps
 * KOF_SYM_RECLEN from KOF_SYM_HDRLEN and tests three bytes per record - type
 * at +0, bind at +1, flags at +3 - instead of searching for anything.
 */
static inline uint32_t kof_sym_count(const uint8_t *b, uint32_t n)
{
	if (!b || n < KOF_SYM_HDRLEN)
		return 0;
	return (uint32_t)b[KOF_SYM_H_COUNT] |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 1] << 8) |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 2] << 16) |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 3] << 24);
}

static inline const uint8_t *kof_sym_rec(const uint8_t *b, uint32_t n, uint32_t i)
{
	uint64_t at = (uint64_t)KOF_SYM_HDRLEN + (uint64_t)i * KOF_SYM_RECLEN;

	if (i >= kof_sym_count(b, n) || at + KOF_SYM_RECLEN > (uint64_t)n)
		return 0;
	return b + at;
}

/* value and size, little endian whatever the host is. Byte at a time because
 * NEITHER IS ALIGNED - the layout puts contiguity before alignment, so a cast
 * would be a misaligned load on the architectures that care. */
static inline uint64_t kof_sym_u64(const uint8_t *r, uint32_t at)
{
	uint64_t v = 0;
	int k;

	for (k = 7; k >= 0; k--)
		v = (v << 8) | (uint64_t)r[at + (uint32_t)k];
	return v;
}

/*
 * Where a walk may begin, given what the block knows.
 *
 * Returns the record after `_start`, or zero when the block has no `_start` to
 * start after - so a caller writes `for (i = kof_sym_first(b, n); ...)` and
 * gets the short walk when one is available and the whole table when it is not,
 * without a branch of its own. See the note on KOF_SYM_H_START for what this
 * does and does not promise.
 */
static inline uint32_t kof_sym_first(const uint8_t *b, uint32_t n)
{
	uint32_t s;

	if (!b || n < KOF_SYM_HDRLEN)
		return 0;
	s = (uint32_t)b[KOF_SYM_H_START] |
	    ((uint32_t)b[KOF_SYM_H_START + 1] << 8);
	if (s == KOF_SYM_NO_START || s + 1u >= kof_sym_count(b, n))
		return 0;
	return s + 1u;
}

/*
 * ONE ANSWER TO "WHERE DOES A SYMBOL MASK POINT", FOR EVERY CALLER.
 *
 * Three places need it - the scan (kof_find_str), the marker pane
 * (kof_touch_object) and the draft panel (kofviewer) - and while each had its
 * own version they disagreed, which is exactly the shape of bug that is
 * invisible: the scan detected a marker in SYM_EXP, the panel called the same
 * marker absent, and the status line counted it as one of two. So the decision
 * lives here and the callers only run the matcher over what it returns.
 *
 * The extents index the BLOCK, not the object - the block is built, and none of
 * its records is a run of bytes in the file.
 *
 * LAST RECORD FIRST. A symbol table is written runtime-first, with the author's
 * own symbols at the end, so a rule scoped to a half is nearly always asking
 * about one of those. It cannot change an answer: kof_match_lookup reports
 * whether a pattern is PRESENT and stops at the first extent that has it, so
 * reversing the list reorders the work and not the result.
 *
 * Adjacent records of the SAME half coalesce into one run; a record of the
 * other half breaks it. That is deliberate: the halves are separate targets, so
 * a pattern is never matched across the join between them.
 *
 * Records only - the block's own header is not searched, because its count and
 * `_start` index are the host's bookkeeping rather than anything the object
 * says.
 */
static inline uint32_t kof_sym_extents(const uint8_t *b, uint32_t n,
				       uint32_t mask, struct kof_range *ext,
				       uint32_t cap)
{
	uint32_t k = 0, half;

	if (!b || !ext)
		return 0;
	for (half = 0; half < 2u; half++) {
		uint32_t bit = half ? KOF_SCAN_SYM_EXP : KOF_SCAN_SYM_IMP;
		uint32_t total, i, first = k;

		if (!(mask & bit))
			continue;
		total = kof_sym_count(b, n);
		for (i = total; i-- > 0; ) {
			const uint8_t *r = kof_sym_rec(b, n, i);
			uint64_t off;

			if (!r)
				continue;
			/* half 0 is the imports, which are the undefined ones. */
			if (((r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) != 0u)
			    == (half != 0u))
				continue;
			off = (uint64_t)KOF_SYM_HDRLEN +
			      (uint64_t)i * KOF_SYM_RECLEN;
			/* The record just above is the run being built, so the
			 * run grows downward. Only within this half - `first`
			 * is where this half's runs start. */
			if (k > first &&
			    ext[k - 1u].off == off + KOF_SYM_RECLEN) {
				ext[k - 1u].off = off;
				ext[k - 1u].len += KOF_SYM_RECLEN;
				continue;
			}
			if (k >= cap)
				return k;
			ext[k].off = off;
			ext[k].len = KOF_SYM_RECLEN;
			k++;
		}
	}
	return k;
}

/*
 * The block for an object, whichever builder its format has.
 *
 * The format picks the builder, not the caller: a rule asks for "this object's
 * symbols" and gets one layout whatever the file is, which is the whole reason
 * the layout exists. Defined in kofparsers/binaries/sym_any.c so that the
 * choice is made in one place too - it used to be made separately by the
 * scanner and by kofviewer.
 *
 * Returns the bytes written, or 0 when the format has no symbols to give.
 */
uint32_t kof_syms_build(uint32_t format, const uint8_t *data, uint64_t data_n,
			const void *info, uint8_t *out, uint32_t cap);

/* Which table it came from, or 0 when there is none. */
static inline uint8_t kof_sym_origin(const uint8_t *b, uint32_t n)
{
	return (b && n >= KOF_SYM_HDRLEN) ? b[KOF_SYM_H_ORIGIN] : 0u;
}

/* Did the cap stop the block short of the symbols the file has. */
static inline int kof_sym_truncated(const uint8_t *b, uint32_t n)
{
	return (b && n > KOF_SYM_H_TRUNC) ? b[KOF_SYM_H_TRUNC] != 0 : 0;
}

/*
 * THE BUILDER IS NOT DECLARED HERE, and that is the SDK boundary.
 *
 * This header is published to modules; kofparsers/binaries/elf_sym.h is not.
 * A module has no business walking a symbol table itself - it asks the host
 * through kof_syms(), which hands back a block the engine already built - and
 * declaring the builder here would have dragged kofcore.h into the SDK to get
 * kof_buf, which is exactly the reach the published header set exists to
 * prevent. Everything above this line is layout and readers, which is all a
 * rule needs.
 */

#endif /* KOF_KOFSYM_H */
