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
 * and the name in a pool the record points into - kept WHOLE, whatever its length.
 * A rule can then say type, bind, size and name in a single pattern, and mean it
 * about a symbol rather than about some bytes that happened to spell it: the
 * pattern is written against the pool entry, which begins with the four attribute
 * bytes and ends with the name and its NUL (see KOF_SYM_KEYLEN).
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
 * 4.
 *
 * Version 1 put the name at 24 with the numeric fields in front of it; a reader
 * that trusted those offsets would decode every record wrong, so the number had
 * to move with the layout. Version 3 gave the two reserved header bytes a
 * meaning - the index of `_start`. Version 4 moves the NAME out of the record: it
 * was 40 bytes inline, so a longer one was cut to 39 characters (a C++ or Rust
 * symbol, __x64_sys_...) and a rule could never match its tail. The record is now
 * KOF_SYM_RECLEN (32) bytes and holds an offset and a length into a pool of names
 * that follows the records; the pool is as long as its names. The header is
 * unchanged (16 bytes, the same fields): the pool starts at
 * KOF_SYM_HDRLEN + count * KOF_SYM_RECLEN and runs to the end of the block, so no
 * new field says where it is.
 */
#define KOF_SYM_VERSION 4u
#define KOF_SYM_HDRLEN  16u
#define KOF_SYM_RECLEN  32u
/*
 * THE LONGEST NAME ONE RECORD KEEPS, a DoS bound and not a design limit: a name
 * past it is cut here, and the record says so (KOF_SYM_R_NAMECUT) - never
 * silently. 4096 is far past any symbol measured (the longest mangled C++ and
 * Rust names are in the hundreds); the table's own size is what the block is
 * bounded by (KOF_SYM_ABS_MAX_BYTES).
 */
#define KOF_SYM_NAME_MAX 4096u
/*
 * WHAT A POOL ENTRY IS - and why it carries four bytes that are also in the
 * record.
 *
 * The signatures already written against the symbol halves are patterns of the
 * form "attributes, then the name", e.g. 04 00 00 01 'exploit.c': the four
 * attribute bytes and the name as one run, which is how a rule asks for "a GLOBAL
 * OBJECT called X". kof_sym_extents hands the matcher the RUNS the records name,
 * and a run has to be contiguous bytes, so the pool entry for a symbol is
 *
 *     type, bind, vis, flags, name..., 0
 *
 * - the same four bytes the record holds at +0..+3, copied by the one writer that
 * makes both (analyzers/parsers/binaries/sym_pool.c, which is the only place
 * a block is written) - and the NUL is what ends the name, as the padding did.
 * The record is the one authoritative carrier; the pool's four bytes are the
 * match view of it, and a test (tests/unit/caps_syms.c) compares them for every
 * record of a built block. The numeric fields are not in the run, as they were
 * not meant to be: an address and a size move with every build.
 */
#define KOF_SYM_KEYLEN  4u

/* The bits of the header's `truncated` byte. ROOM: the buffer the block was built
 * into ran out, so a larger one holds more (kof_syms_build_grow retries on it).
 * SOURCE: a bound of the walk that feeds the block cut the list (the export
 * directory's name bound, an import table that stopped short), so a larger buffer
 * changes nothing. Both say the block is not the file's whole table: any bit set
 * is `kof_sym_truncated`. */
#define KOF_SYM_TRUNC_ROOM   1u
#define KOF_SYM_TRUNC_SOURCE 2u

/* Header field offsets. */
#define KOF_SYM_H_MAGIC     0u  /* 4  "KSYM"                                  */
#define KOF_SYM_H_VERSION   4u  /* 2  KOF_SYM_VERSION                         */
#define KOF_SYM_H_RECLEN    6u  /* 2  KOF_SYM_RECLEN                          */
#define KOF_SYM_H_COUNT     8u  /* 4  records that follow                     */
#define KOF_SYM_H_ORIGIN   12u  /* 1  KOF_SYM_ORIGIN_*                        */
#define KOF_SYM_H_TRUNC    13u  /* 1  KOF_SYM_TRUNC_* bits, 0 when whole      */
/*
 * THE INDEX OF `_start`, or KOF_SYM_NO_START when the block has none.
 *
 * In the two bytes that were reserved, so the header stays sixteen and every
 * record offset is unchanged. Sixteen bits is enough by construction:
 * KOF_SYM_ABS_MAX_RECS is 65534, so no valid index needs more, and 0xffff cannot
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
 * What a rule matches on is contiguous, and it is the POOL ENTRY that holds it:
 * the four attribute bytes and then the name (see KOF_SYM_KEYLEN). With the
 * numeric fields in between - as they were, twenty bytes of shndx, reserved,
 * value and size - the one question "a GLOBAL OBJECT called X" needed a hex
 * pattern with a gap step across all twenty, on every rule. The record's own
 * fields are ordered the way they are READ: attributes, the name's place,
 * section, then the two numbers.
 *
 * The numeric fields are not in what a rule matches because they are READ far
 * more often than they are matched: an address and a size move with every build,
 * so a rule that pinned them would be a rule about one binary.
 *
 * ALIGNED NOW: value and size are at 24 and 16, both 8-aligned and the record is
 * 32 bytes, so the record array is. Nothing casts a pointer into a record all the
 * same - the reads go through kof_rd_* or kof_sym_u64, which assemble the value a
 * byte at a time, so the block can sit at any address.
 *
 * 32 bytes is a power of two: a record is an exact number of hex rows - two at
 * sixteen bytes to the row, four at eight - so record boundaries line up down the
 * pane instead of walking across it.
 */
#define KOF_SYM_R_TYPE      0u  /* 1  STT_*  - ELF's numbering                */
#define KOF_SYM_R_BIND      1u  /* 1  STB_*                                   */
#define KOF_SYM_R_VIS       2u  /* 1  STV_*                                   */
#define KOF_SYM_R_FLAGS     3u  /* 1  KOF_SYM_F_*                             */
/*
 * THE NAME: where it starts in the pool, and how long it is. The offset is from
 * the start of the POOL (not the block) and points at the first byte of the name;
 * the four attribute bytes of the entry are the KOF_SYM_KEYLEN before it, and the
 * NUL is the byte after the last. Read it with kof_sym_name, which checks all
 * three against the block's length and gives the whole name.
 */
#define KOF_SYM_R_NAMEOFF   4u  /* 4  offset of the name in the pool          */
#define KOF_SYM_R_NAMELEN   8u  /* 2  its length, the NUL not counted         */
#define KOF_SYM_R_SHNDX    10u  /* 2  section index; 0 is ELF's SHN_UNDEF,    */
                                /*    0xffff any reserved index (ABS, COMMON) */
/*
 * THE NAME WAS CUT - only by KOF_SYM_NAME_MAX now, which is a DoS bound: 1 when
 * the name in the source was longer than the bound and the pool holds its
 * beginning. A rule on a name that long cannot match its tail, and the block says
 * why. Not in the flags byte: that byte is part of the run a pattern matches, and
 * a new bit there would have changed what an existing pattern matches.
 */
#define KOF_SYM_R_NAMECUT  12u  /* 1  1 when the name was cut to the bound    */
#define KOF_SYM_R_RESERVED 13u  /* 3  zero                                    */
#define KOF_SYM_R_SIZE     16u  /* 8  size, little endian                     */
#define KOF_SYM_R_VALUE    24u  /* 8  address, little endian                  */

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
	KOF_SYM_ORIGIN_PE_DIR = 3,
	/*
	 * The directories PLUS names the program resolved for itself - see
	 * the engine's decrypt step. Said apart from PE_DIR because a reader who takes
	 * "directory" literally is told something false about those records.
	 */
	KOF_SYM_ORIGIN_PE_RESOLVED = 4
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
/* The two GNU values are in the OS range and they are ordinary in anything
 * built against glibc - an ifunc resolver is a FUNC that is not one, and a
 * unique object is a GLOBAL that is not one. A reader that stops at 6 and 2
 * prints "?" for them. */
enum { KOF_STT_NOTYPE = 0, KOF_STT_OBJECT = 1, KOF_STT_FUNC = 2,
       KOF_STT_SECTION = 3, KOF_STT_FILE = 4, KOF_STT_COMMON = 5,
       KOF_STT_TLS = 6, KOF_STT_GNU_IFUNC = 10 };
enum { KOF_STB_LOCAL = 0, KOF_STB_GLOBAL = 1, KOF_STB_WEAK = 2,
       KOF_STB_GNU_UNIQUE = 10 };
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
/*
 * 4096 is the size a caller that does not know better allocates (the examiner's
 * static buffer, the viewer's copy): the builders keep as many records as the
 * `cap` they are given holds, so for them nothing changed. It is NOT the engine's
 * bound any more. The engine sizes the block for the table the object has, up to
 * KOF_SYM_ABS_MAX_RECS - 24 of 272 measured ELF files have more than 4096, and a
 * symbol past the 4096th was not in the block, so a rule on it did not fire
 * (tests/unit/caps_syms.c: prepare_creds as the 4097th, commit_creds as the
 * 5900th). Past the ABSOLUTE bound the `truncated` byte is set and the engine
 * reads it (kof_scan_incomplete): an object whose symbols were cut is not
 * reported clean.
 *
 * The absolute bound is the index's: 0xffff is KOF_SYM_NO_START and is reserved,
 * so a record index is at most 65534. It is also what bounds the block (4 MB)
 * against a table whose declared size is hostile.
 */
#define KOF_SYM_MAX_RECS 4096u
/*
 * WHAT A BLOCK COSTS, in bytes: the records plus the pool. The pool is as long as
 * its names, so a size for `recs` records is a PLAN and not a promise -
 * KOF_SYM_POOL_PER_REC is the room planned for each name (its four attribute
 * bytes, a NUL and 43 characters: the mean over the 272 ELF files measured is a
 * third of that, a mangled C++ or Rust table is several times it). A block that
 * did not fit its plan says so in the header's `truncated` byte; the engine then
 * rebuilds it larger (kof_syms_build_grow), a caller with a fixed buffer
 * (KOF_SYM_MAX_BYTES: the viewer, the examiner) keeps what the buffer held and the
 * byte says it was cut.
 */
#define KOF_SYM_POOL_PER_REC 48u
#define KOF_SYM_BYTES_FOR(recs) \
	(KOF_SYM_HDRLEN + (recs) * (KOF_SYM_RECLEN + KOF_SYM_POOL_PER_REC))
#define KOF_SYM_MAX_BYTES KOF_SYM_BYTES_FOR(KOF_SYM_MAX_RECS)
#define KOF_SYM_ABS_MAX_RECS 65534u
/*
 * THE POOL'S DoS BOUND: the most name bytes one block holds, whatever the table
 * declares - 8 MB, which is 65534 names of 128 characters. A table that wants
 * more is built to the bound with `truncated` set, and the engine reads it
 * (kof_scan_incomplete): an object whose names were cut is not reported clean.
 */
#define KOF_SYM_ABS_MAX_POOL (8u << 20)
#define KOF_SYM_ABS_MAX_BYTES \
	(KOF_SYM_HDRLEN + KOF_SYM_ABS_MAX_RECS * KOF_SYM_RECLEN + KOF_SYM_ABS_MAX_POOL)

/*
 * Build the block for an ELF. Returns the bytes written - never less than the
 * header, so an empty answer is still a block a reader can parse. `cap` bounds
 * it; KOF_SYM_MAX_BYTES is enough for the record cap.
 */
/* ---- reading a block ------------------------------------------------------
 *
 * THE CANONICAL READERS. Everything that reads a KSYM block goes through these
 * - the engine, kofexaminer, kofviewer and any module - because the alternative
 * is what was there first: three private copies of the same four lines, which
 * is three places to get the bounds wrong and three to forget when the layout
 * moves. The layout HAS moved twice already (see the notes on versions 2 and 4).
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
 * at +0, bind at +1, flags at +3 - instead of searching for anything. The NAME
 * is the one thing a record does not hold: kof_sym_name(b, n, r, &len) returns it,
 * whole, from the pool.
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

/* A 16 or 32 bit field of a record, little endian whatever the host is. */
static inline uint32_t kof_sym_u32(const uint8_t *r, uint32_t at)
{
	return (uint32_t)r[at] | ((uint32_t)r[at + 1u] << 8) |
	       ((uint32_t)r[at + 2u] << 16) | ((uint32_t)r[at + 3u] << 24);
}

static inline uint32_t kof_sym_u16(const uint8_t *r, uint32_t at)
{
	return (uint32_t)r[at] | ((uint32_t)r[at + 1u] << 8);
}

/*
 * WHERE THE POOL STARTS, in the block: right after the last record. 0 when the
 * block is too short to say.
 */
static inline uint64_t kof_sym_pool_at(const uint8_t *b, uint32_t n)
{
	return (uint64_t)KOF_SYM_HDRLEN +
	       (uint64_t)kof_sym_count(b, n) * KOF_SYM_RECLEN;
}

/*
 * THE NAME OF A RECORD, WHOLE. Returns a NUL-terminated string inside the block
 * and its length in *len (NULL len is fine). A record whose offset, length or
 * terminator does not lie inside the block - a hostile or truncated block - has
 * the empty name, so a caller never reads outside it and never has to test.
 *
 * This is the one way to read a name. The pool is not at a constant offset in
 * the record, and a name is not any particular length.
 */
static inline const char *kof_sym_name(const uint8_t *b, uint32_t n,
				       const uint8_t *rec, uint32_t *len)
{
	uint64_t pool = kof_sym_pool_at(b, n);
	uint32_t off, l;

	if (len)
		*len = 0;
	if (!b || !rec || pool > (uint64_t)n)
		return "";
	off = kof_sym_u32(rec, KOF_SYM_R_NAMEOFF);
	l = kof_sym_u16(rec, KOF_SYM_R_NAMELEN);
	if (off < KOF_SYM_KEYLEN || pool + off + l + 1u > (uint64_t)n ||
	    b[pool + off + l] != 0)
		return "";
	if (len)
		*len = l;
	return (const char *)b + pool + off;
}

/*
 * THE RUN OF RECORD i: the bytes a pattern is matched against - the four
 * attribute bytes, the name and its NUL (see KOF_SYM_KEYLEN) - as an offset into
 * the block and a length. 0 when there is no such record or its run is not
 * inside the block.
 */
static inline int kof_sym_run(const uint8_t *b, uint32_t n, uint32_t i,
			      uint64_t *off, uint64_t *len)
{
	const uint8_t *r = kof_sym_rec(b, n, i);
	uint64_t at, l;
	uint32_t no;

	if (!r)
		return 0;
	no = kof_sym_u32(r, KOF_SYM_R_NAMEOFF);
	l = (uint64_t)KOF_SYM_KEYLEN + kof_sym_u16(r, KOF_SYM_R_NAMELEN) + 1u;
	if (no < KOF_SYM_KEYLEN)
		return 0;
	at = kof_sym_pool_at(b, n) + no - KOF_SYM_KEYLEN;
	if (at + l > (uint64_t)n)
		return 0;
	*off = at;
	*len = l;
	return 1;
}

/*
 * WHICH RECORD A RUN STARTS AT - the inverse of kof_sym_run, for a caller that
 * has an extent (kof_sym_extents) and wants the records in it. The runs lie in
 * the pool in record order, one after another, so this is a binary search.
 * Returns the index, or the record count when none starts at `off`.
 */
static inline uint32_t kof_sym_index_at(const uint8_t *b, uint32_t n,
					uint64_t off)
{
	uint32_t lo = 0, hi = kof_sym_count(b, n);
	const uint32_t none = hi;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		uint64_t at = 0, l = 0;

		if (!kof_sym_run(b, n, mid, &at, &l))
			return none;
		if (at == off)
			return mid;
		if (at < off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return none;
}

/*
 * HOW MANY RECORDS an extent covers, and which is the first: the extents
 * kof_sym_extents returns join adjacent records of one half, so one is a run of
 * consecutive records. 0 when it starts at no record.
 */
static inline uint32_t kof_sym_extent_recs(const uint8_t *b, uint32_t n,
					   const struct kof_range *ext,
					   uint32_t *first)
{
	uint32_t i = kof_sym_index_at(b, n, ext->off), k = 0;
	uint64_t end = ext->off + ext->len;

	if (i >= kof_sym_count(b, n))
		return 0;
	if (first)
		*first = i;
	for (;; i++, k++) {
		uint64_t at = 0, l = 0;

		if (!kof_sym_run(b, n, i, &at, &l) || at + l > end)
			break;
	}
	return k;
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
 * its records is a run of bytes in the file. A run is a record's POOL ENTRY
 * (attributes, name, NUL - see KOF_SYM_KEYLEN), not the 32-byte record: what a
 * pattern is written against is the name and what is said about it.
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
 * Pool entries only - the block's header and the record table are not searched,
 * because the count and `_start` index are the host's bookkeeping and the numeric
 * fields move with every build; neither is anything the object says by name.
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
		/*
		 * THE LOOP FOLLOWS THE BLOCK'S LENGTH, NOT THE COUNT IT STATES. The count
		 * is a 32-bit number in the block's own header and kof_sym_rec refuses
		 * every record the bytes do not hold, one at a time: a 16 byte block
		 * claiming 2^32-1 records spun 2^32 times per half. The most the n bytes
		 * can hold is (n - header) / record, so that bounds it
		 * (tests/unit/api_engine_modhelpers.c, sym_count_bomb).
		 */
		if (n < KOF_SYM_HDRLEN)
			total = 0;
		else if (total > (n - KOF_SYM_HDRLEN) / KOF_SYM_RECLEN)
			total = (n - KOF_SYM_HDRLEN) / KOF_SYM_RECLEN;
		for (i = total; i-- > 0; ) {
			const uint8_t *r = kof_sym_rec(b, n, i);
			uint64_t off, len;

			if (!r)
				continue;
			/* half 0 is the imports, which are the undefined ones. */
			if (((r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED) != 0u)
			    == (half != 0u))
				continue;
			if (!kof_sym_run(b, n, i, &off, &len))
				continue;
			/* The run just above is the one being built, so it grows
			 * downward - when this record's run ends exactly where it
			 * starts, which it does for adjacent records of the SAME
			 * half. Only within this half - `first` is where this
			 * half's runs start. */
			if (k > first && ext[k - 1u].off == off + len) {
				ext[k - 1u].off = off;
				ext[k - 1u].len += len;
				continue;
			}
			if (k >= cap)
				return k;
			ext[k].off = off;
			ext[k].len = len;
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
 * the layout exists. Defined in analyzers/parsers/binaries/sym_any.c so that the
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

/* Was this record's name cut at KOF_SYM_NAME_MAX - see KOF_SYM_R_NAMECUT. */
static inline int kof_sym_name_cut(const uint8_t *rec)
{
	return rec ? rec[KOF_SYM_R_NAMECUT] != 0 : 0;
}

/* Did the cap stop the block short of the symbols the file has. */
static inline int kof_sym_truncated(const uint8_t *b, uint32_t n)
{
	return (b && n > KOF_SYM_H_TRUNC) ? b[KOF_SYM_H_TRUNC] != 0 : 0;
}

/*
 * THE BUILDER IS NOT DECLARED HERE, and that is the SDK boundary.
 *
 * This header is published to modules; analyzers/parsers/binaries/elf/elf_sym.h is not.
 * A module has no business walking a symbol table itself - it asks the host
 * through kof_syms(), which hands back a block the engine already built - and
 * declaring the builder here would have dragged kofcore.h into the SDK to get
 * kof_buf, which is exactly the reach the published header set exists to
 * prevent. Everything above this line is layout and readers, which is all a
 * rule needs.
 */

#endif /* KOF_KOFSYM_H */
