/*
 * upx_elf.c - unpack a UPX packed ELF.
 *
 * 154 of 9482 samples in one Linux collection carry a UPX PackHeader in an ELF,
 * and the compressed original is the whole of what they are: the file on disk is a
 * decompression stub plus a blob, and every string, every symbol and every byte a
 * detection could match is inside the blob. Unpacked, the child is the original
 * ELF entire - so it identifies as ELF, parses, gets regions, and every module in
 * the database applies to it. That is the difference between one module that knows
 * UPX and every module knowing UPX.
 *
 *
 * THE FORMAT, AND WHERE EACH BOUND COMES FROM
 *
 * UPX/Linux writes a small ELF stub, then its own structures, then the blocks:
 *
 *     l_info   { checksum, "UPX!", lsize, version, format }
 *     p_info   { progid, filesize, blocksize }
 *     b_info   { sz_unc, sz_cpr, method, ftid, cto, unused }  followed by
 *              sz_cpr bytes of compressed data - repeated until the data runs out
 *
 * The chain has no count and no terminator. It ends where the packed data ends,
 * and the twelve bytes after that are whatever happened to follow - so the walk
 * stops at the first b_info that cannot be true rather than at a count it was
 * given. Everything read here is bounded against the object; nothing is bounded
 * against another value out of the same file.
 *
 *
 * WHAT THIS DOES NOT DO
 *
 * It does not reverse the CTO filter. UPX rewrites the targets of E8/E9 branches
 * before compressing, and the byte saying which filter was used is in each b_info.
 * Strings, imports and data are untouched by it, so they match as they are; hex
 * patterns written over filtered code would not. Reversing it is worth doing and
 * is not done here - it is recorded rather than left to be discovered by a pattern
 * that mysteriously fails.
 *
 * It does not handle LZMA. Measured on the same collection: 93% of UPX blocks are
 * NRV2 and 1.7% are LZMA, so this covers what is there and says so when it meets
 * what it does not - a block whose method is unknown ends the walk, and the object
 * is reported as not fully examined rather than as clean.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/*
 * The anchor. Declared rather than compared byte by byte, so the host searches
 * with the machinery it already has and this module carries no scan loop.
 *
 * UPX writes the same four bytes in two places - here in l_info, and again in the
 * PackHeader at the end of the file - so what is found first has to be the one
 * near the front, which is why the search is bounded to the stub rather than run
 * over the whole object.
 */
KOF_DEFINE_STR(upx_magic, "UPX!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

/*
 * l_info is twelve bytes with the magic four bytes in; p_info is the next twelve.
 *
 * Written as "step back to the start of l_info, then over both structures" rather
 * than as an offset from the magic. The first version added to the magic directly
 * and was four bytes short - the magic is four bytes LONG, so what follows it
 * begins eight past where it starts, not four. Deriving the structure's start makes
 * the arithmetic say what it means and the mistake unavailable.
 */
#define L_INFO_LEN      12u
#define L_INFO_MAGIC_AT  4u
/* Within l_info: checksum, magic, lsize, version, format. Absolute offsets are
 * taken from the magic, which is the only part that can be found. */
#define L_INFO_VERSION   6u   /* magic_at + this */
#define L_INFO_FORMAT    7u
#define P_INFO_LEN      12u
#define B_INFO_LEN      12u

/* How far into the object the stub's l_info can be. UPX's Linux stubs are a few
 * hundred bytes; this is generous and still bounded. */
#define STUB_SEARCH_LEN 8192u

/*
 * UPX method numbers, from its conf.h, mapped onto the engine's decoders.
 *
 * Each group of three is one coding at three bit-buffer widths - _LE32, _8, _LE16
 * in that order - not one coding with three filters. That distinction is the whole
 * of why this table exists rather than a subtraction.
 */
static uint32_t method_of(unsigned m)
{
	switch (m) {
	case 2:  return KOF_UNP_NRV2B_32;
	case 3:  return KOF_UNP_NRV2B_8;
	case 4:  return KOF_UNP_NRV2B_16;
	case 5:  return KOF_UNP_NRV2D_32;
	case 6:  return KOF_UNP_NRV2D_8;
	case 7:  return KOF_UNP_NRV2D_16;
	case 8:  return KOF_UNP_NRV2E_32;
	case 9:  return KOF_UNP_NRV2E_8;
	case 10: return KOF_UNP_NRV2E_16;
	default: return 0;              /* LZMA, or something new */
	}
}

/*
 * UPX's own number for LZMA, and the reason it is named rather than lumped in
 * with every other byte this module does not recognise.
 *
 * A method byte of 14 is a coding UPX really uses, so meeting one means there was
 * a block here and it was not decoded - the object is short by whatever that block
 * held. Any other unrecognised byte is not a coding at all: it is whatever followed
 * the last block, which for this format is the decompression stub. Measured over
 * 154 packed samples, of the 31 walks that stopped on an unrecognised byte, 29 had
 * already recovered 99% or more of the original - they had finished, and were
 * reading machine code.
 */
#define UPX_M_LZMA 14u

/*
 * Blocks followed before the chain is called a chain no longer.
 *
 * Measured over 763 real UPX samples: the median holds 3 and the largest holds 5.
 * Sixty-four is thirteen times the worst observed, so it never binds on anything
 * genuine - and it is the difference between a bounded walk and one whose length is
 * the file's own size divided by thirteen.
 *
 * That is not theoretical. A 64MB object filled with minimal b_info records walks
 * 4.47 MILLION of them, and each one allocates and initialises an LZMA probability
 * model before discovering it has nothing to decode: measured, 5.01 seconds against
 * the 45 milliseconds the same 64MB costs to scan otherwise, growing linearly with
 * the file. The cost per block is small, there are simply no limits on how many
 * blocks a file may claim.
 */
#define UPX_MAX_BLOCKS 64u

/*
 * UPX's LZMA blocks: the stream starts two bytes in, and those two bytes carry the
 * parameters.
 *
 * Worked out by decoding real blocks with every combination the specification
 * allows and keeping the ones that produced exactly the length the container
 * declared. 330 LZMA blocks across packed ELF and PE, three distinct headers:
 *
 *     18 03  ->  lc=3 pb=0        1a 03  ->  lc=3 pb=2        3c 07  ->  lc=7 pb=4
 *
 * so lc is the top of the first byte and pb the bottom three bits. Every block used
 * lp=0, so where lp lives is still not established and it is taken as zero - if a
 * build using another value appears, this decodes it wrongly.
 *
 * Being wrong about that is safe and deliberately so: the container states the
 * uncompressed length, the host reports what came out, and a mismatch is an object
 * marked not fully examined. A wrong guess costs a sample reported incomplete,
 * never one silently declared clean.
 */
#define UPX_LZMA_SKIP  2u
#define UPX_LZMA_LP    0u

static uint32_t upx_lzma_method(unsigned first_byte)
{
	unsigned lc = first_byte >> 3, pb = first_byte & 7u;

	/* Both come from the file, and both size or shape the decoder's model.
	 * Out of range is refused here so the module can say it did not finish,
	 * rather than being refused inside the host with nothing to report. */
	if (lc > KOF_LZMA_MAX_LC || pb > KOF_LZMA_MAX_PB)
		return 0;
	return KOF_UNP_LZMA_PROPS(lc, UPX_LZMA_LP, pb);
}


/*
 * UPX's own structures are in the TARGET's byte order, not the host's.
 *
 * The engine's accessors are little endian and say so, on the grounds that a
 * format's headers reach a module through a view that normalised them. l_info,
 * p_info and b_info are not a format's headers - they are the packer's, written
 * into the file as the target reads them - so on a big endian object every one of
 * these fields is the wrong way round.
 *
 * Measured before this existed: of 920 UPX packed ELF samples across two
 * collections, 240 could not be opened at all, and 203 of those were big endian
 * MIPS and PowerPC. Every one of the 203 parses when the fields are swapped. It was
 * not a second layout and not damaged files - it was the byte order, and the
 * earlier conclusion that these were mostly small corrupt samples came from a
 * 150-file subset in which they happened to be rare.
 */
#define RD32(off) (be ? kof_bswap32(kof_u32(off)) : kof_u32(off))

/*
 * The shapes this module knows how to walk.
 *
 * One row today, and the table exists because the alternative is worse. A packer's
 * layout varies by version and by target, so the honest question is not "does this
 * decode" but "is this a layout I have seen" - and a module without the question
 * answers the first by walking whatever it found and producing nothing, which looks
 * identical to a file that had nothing in it.
 *
 * Measured over both collections on this machine: 28 UPX packed ELF objects across
 * l_format 12, 22, 23, 30 and 137 at l_version 13 and 14, and every one of them
 * walks with this single row. They differ in target architecture and therefore in
 * byte order, which RD32 above already handles from the ELF header - the b_info
 * layout itself is the same across all of them.
 *
 * So the row is wide on purpose and the table is one entry. What earns it its place
 * is the ELSE: a version or format outside it is REPORTED rather than walked, so
 * the first genuine variant appears in a scan's statistics instead of quietly
 * yielding zero blocks. That is the signal that a second row is needed, and without
 * it there is no way to know.
 */
struct upx_shape {
	uint8_t ver_min, ver_max;
	uint32_t formats;        /* bit per l_format, low bit is format 0 */
	const char *what;
};

/*
 * The ELF formats this row covers, in two pieces because one byte does not fit a
 * mask: the low ones as bits, the high ones listed.
 *
 * OBSERVED to walk with this row: 12, 22, 23, 30, 42, 132 and 137, across 777
 * objects. The neighbours in the low range are admitted with them because they are
 * the same family and the same b_info layout, not because a sample of each was
 * seen - and that distinction is why the high ones are listed individually rather
 * than turned into a range.
 *
 * 42 and 132 are here because the table put them there. The first version of this
 * list had neither, and the twenty one objects carrying them came back as
 * unknown_shape on the next scan - so they were checked, they walked, and the list
 * grew. That is the mechanism working: a format nobody had thought of becomes a
 * number in a report rather than a silent zero.
 */
#define UPX_ELF_FORMATS                                                      \
	((1u << 12) | (1u << 13) | (1u << 14) | (1u << 15) |                 \
	 (1u << 22) | (1u << 23) | (1u << 24) | (1u << 25) |                 \
	 (1u << 27) | (1u << 28) | (1u << 30) | (1u << 31))

/* Above 31 and therefore not expressible in the mask. Listed, not ranged. */
static int upx_elf_format_high(unsigned fmt)
{
	return fmt == 42u || fmt == 132u || fmt == 137u;
}

static const struct upx_shape shapes[] = {
	{ 10, 20, UPX_ELF_FORMATS, "b_info chain, 12 byte records" }
};

/* ---- putting the original back together -----------------------------------
 *
 * The b_info chain does not hold the whole file, and laying its blocks end to
 * end does not reproduce one. Measured across every architecture in one
 * collection - ELF32 and ELF64, little and big endian, formats 12, 23, 30, 42,
 * 132 and 137 - the original is exactly:
 *
 *     chain blocks  +  the gaps between PT_LOADs  +  one further block
 *
 * and the sum equalled the size UPX recorded in all six, to the byte.
 *
 * The gaps are alignment between segments. UPX has no reason to store them -
 * nothing loads them - so they are reconstructed as zeros, and where they fall
 * is written in the original's program headers, which are the first thing UPX
 * compressed.
 *
 * The further block is the tail of the original: the padding before the section
 * header table, and the table itself. It sits near the end of the packed file
 * with its own b_info, after the loader's code, which is why walking the chain
 * forward never reaches it - the bytes after the last chain block are code, not
 * a record. The PackHeader at the very end says how large it is, and that is
 * the only thing that points at it.
 *
 *
 * NONE OF THIS IS TRUSTED
 *
 * Every number here came out of the object, and several of them come out of a
 * DECOMPRESSOR fed by the object, which is the same thing with more steps. So:
 *
 *   - the peek writes into a fixed buffer on the stack, and its bound is that
 *     buffer's size. Nothing an object declares sizes an allocation.
 *   - a program header table is clamped to what was actually peeked, and to a
 *     fixed number of entries.
 *   - the zero fill is capped per gap and in total. Without that a program
 *     header claiming a segment at 2^40 would have this emitting for a very
 *     long time before the host's budget noticed.
 *   - the tail is bounded by what a tail can be, and its compressed bytes must
 *     lie inside the object and end before the PackHeader they were described
 *     by.
 *   - the PackHeader is looked for in a bounded window at the end of the file,
 *     and is only believed when the size it states agrees with the one p_info
 *     stated at the front. Two independent structures agreeing is what makes it
 *     the file's own claim rather than a byte sequence somebody planted.
 */
/*
 * The peek buffer, and so the peek bound.
 *
 * Block one is the original ELF header and its program headers: 148 bytes on
 * the ELF32 samples and up to 624 on the ELF64 ones. Five hundred and twelve
 * cut the ELF64 tables in half and lost every PT_LOAD past the eighth, which
 * showed up as an architecture that got no gaps. A kilobyte covers the largest
 * seen with room over, and is still a fixed array on the stack.
 */
#define UPX_HDR_PEEK    1024u
#define UPX_MAX_LOADS   16u
/* An ELF with more program headers than this is not one UPX packed: the largest
 * in the collection has nine. Shared so the table walk and the magic repair
 * agree on what a plausible table is. */
#define UPX_MAX_PHNUM   64u

/*
 * The least of a cut-off block worth decoding.
 *
 * Below this there is no stream to speak of - LZMA alone spends two bytes on
 * UPX's parameter pair and five more initialising its range coder - and a
 * handful of bytes of output is not worth a decode or a child.
 */
#define UPX_MIN_CUT     32u
/*
 * What the reconstruction may invent.
 *
 * Real gaps are page alignment: the largest seen in the collection was under
 * two kilobytes. A megabyte in total is far past that and still small enough
 * that a lying program header buys nothing.
 */
#define UPX_MAX_PAD     (1u << 20)
#define UPX_MAX_GAP     (1u << 18)
/* The tail is padding plus a section header table. A thousand sections at 64
 * bytes is already absurd; this is more than that. */
#define UPX_TAIL_MAX    (1u << 20)
/* How far back from the end of the object a PackHeader may be, and how long it
 * is. Both fixed by the format rather than read from it. */
#define UPX_PH_WINDOW   4096u
#define UPX_PH_LEN      36u

struct upx_layout {
	uint64_t off[UPX_MAX_LOADS];
	uint64_t len[UPX_MAX_LOADS];
	uint32_t n;
};

static uint32_t rd_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rd_be32(const uint8_t *p)
{
	return (uint32_t)p[3] | ((uint32_t)p[2] << 8) |
	       ((uint32_t)p[1] << 16) | ((uint32_t)p[0] << 24);
}

static uint64_t rd_le64(const uint8_t *p)
{
	return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static uint64_t rd_be64(const uint8_t *p)
{
	return (uint64_t)rd_be32(p + 4) | ((uint64_t)rd_be32(p) << 32);
}

static uint32_t rd_u16(const uint8_t *p, int be)
{
	return be ? (uint32_t)((p[0] << 8) | p[1])
		  : (uint32_t)((p[1] << 8) | p[0]);
}

/*
 * Is the rest of e_ident what an ELF's would be?
 *
 * Everything except the three magic bytes, because those are the ones a packed
 * sample is found to have had scribbled on and the point of this is to judge a
 * header without them. Class and byte order each have two legal values and the
 * ident version has exactly one, which is nine bits of agreement that a run of
 * arbitrary bytes does not produce by accident - and the caller adds the
 * program header table's own arithmetic on top of it.
 */
static int upx_ident_ok(const uint8_t *h)
{
	return h[0] == 0x7fu &&
	       (h[4] == 1u || h[4] == 2u) &&
	       (h[5] == 1u || h[5] == 2u) &&
	       h[6] == 1u;
}

/*
 * The PT_LOAD table out of a decoded ELF header block.
 *
 * Bounded against `n` at every step, and `n` is what the peek actually wrote -
 * not what the header says it should have. Entries that do not fit are the end
 * of the table, not an error: a short peek is the ordinary case for a file with
 * many program headers, and the ones that were read are still usable.
 *
 * THE MAGIC IS NOT REQUIRED HERE. It used to be, and that is what made an
 * ARM64 sample come out short: two of the six format 42 samples measured store
 * a first block whose e_ident[1..3] is not "ELF" - 7f 0c 93 2b in one, 7f bc
 * 24 0d in another - so this returned an empty table for them, no gap was ever
 * found, and the object was missing its inter-segment padding. The bytes this
 * function actually reads are the program header table, and whether that table
 * can be walked has nothing to do with the three bytes at the front.
 */
static void upx_layout_of(const uint8_t *h, uint32_t n, struct upx_layout *L)
{
	uint32_t i, phentsize, phnum;
	uint64_t phoff;
	int be, is64;

	L->n = 0;
	if (n < 64u || !upx_ident_ok(h))
		return;
	is64 = h[4] == 2;
	be   = h[5] == 2;
	if (is64) {
		phoff     = be ? rd_be64(h + 0x20) : rd_le64(h + 0x20);
		phentsize = rd_u16(h + 0x36, be);
		phnum     = rd_u16(h + 0x38, be);
	} else {
		phoff     = be ? rd_be32(h + 0x1c) : rd_le32(h + 0x1c);
		phentsize = rd_u16(h + 0x2a, be);
		phnum     = rd_u16(h + 0x2c, be);
	}
	if (phentsize < (is64 ? 56u : 32u) || phnum == 0u || phnum > UPX_MAX_PHNUM)
		return;
	if (phoff >= (uint64_t)n)
		return;
	for (i = 0; i < phnum && L->n < UPX_MAX_LOADS; i++) {
		uint64_t e = phoff + (uint64_t)i * phentsize;
		uint64_t off, fsz;

		if (e + phentsize > (uint64_t)n)
			break;
		if ((be ? rd_be32(h + e) : rd_le32(h + e)) != 1u)
			continue;               /* PT_LOAD only */
		if (is64) {
			off = be ? rd_be64(h + e + 8) : rd_le64(h + e + 8);
			fsz = be ? rd_be64(h + e + 0x20)
				 : rd_le64(h + e + 0x20);
		} else {
			off = be ? rd_be32(h + e + 4) : rd_le32(h + e + 4);
			fsz = be ? rd_be32(h + e + 0x10)
				 : rd_le32(h + e + 0x10);
		}
		/*
		 * Ascending, non-overlapping, and no wider than the file it
		 * claims to describe. A table that is not in order is not one
		 * this can walk, so the walk stops rather than sorting bytes a
		 * hostile object chose the order of.
		 */
		if (off > UINT64_MAX - fsz)
			break;
		if (L->n && off < L->off[L->n - 1u] + L->len[L->n - 1u])
			break;
		L->off[L->n] = off;
		L->len[L->n] = fsz;
		L->n++;
	}
}

/*
 * Has this first block's ELF magic been scribbled on, and is putting it back
 * a repair rather than a guess?
 *
 *
 * WHAT WAS MEASURED
 *
 * Six format 42 (ARM64) samples in the collection. Four store a first block
 * whose compressed stream begins, in clear, 7f 45 4c 46. Two do not:
 *
 *     433d25d45026...   7f 0c 93 2b
 *     4fc702ad3feb...   7f bc 24 0d
 *
 * Two samples, two different values, so it is not a constant and not a cipher
 * anybody could undo. The first byte survives in both and everything after the
 * fourth is a correct e_ident - ELFCLASS64, little endian, version 1 - which is
 * the shape of three bytes overwritten rather than of a decode gone wrong.
 * Nothing else about those files is unusual: the same UPX version, the same
 * l_format, the same method, a compressed block a handful of bytes longer than
 * its neighbours, which is what compressing three fewer repeated bytes costs.
 *
 * It works because UPX's own runtime never reads them. The stub maps the
 * original's PT_LOADs from the program header table it just decompressed; the
 * magic is checked by loaders and by tools, not by the thing that starts this
 * program. So three bytes can be removed for free, and what they cost is every
 * tool downstream: the recovered image does not sniff as an ELF, so it is not
 * parsed, so no region exists, so nothing scoped to a region can match it.
 *
 *
 * WHY PUTTING THEM BACK IS NOT INVENTING EVIDENCE
 *
 * The claim being made is "this block is an ELF header", and it is settled
 * before the magic is touched, by arithmetic the tamperer did not get to
 * choose:
 *
 *   - the rest of e_ident is legal on all nine of its constrained bits;
 *   - e_phoff is exactly where the program header table goes for this class,
 *     and e_phentsize is exactly the size of one entry for it;
 *   - e_phoff + e_phnum * e_phentsize is exactly this block's uncompressed
 *     size, so the block is a header and its table and nothing else;
 *   - and that table walks: it has at least one PT_LOAD.
 *
 * For the sample above that is 64 + 9 * 56 = 568 = sz_unc, to the byte. A run
 * of bytes that was not an ELF header does not land on that.
 *
 * The repair is still reported. It is recorded as damage, because the object
 * WAS tampered with and that is a fact worth carrying, and it is named in the
 * debug stream so that a reader looking at the recovered image knows three of
 * its bytes came from here rather than from the file.
 */
static int upx_magic_tampered(const uint8_t *h, uint32_t n, uint32_t sz_unc)
{
	struct upx_layout L;
	uint32_t phentsize, phnum;
	uint64_t phoff;
	int be, is64;

	/* The whole block, not a truncated peek: the size test below is the
	 * evidence, and it means nothing against a partial buffer. */
	if (n < 64u || n != sz_unc || !upx_ident_ok(h))
		return 0;
	if (h[1] == 'E' && h[2] == 'L' && h[3] == 'F')
		return 0;               /* nothing to put back */

	is64 = h[4] == 2;
	be   = h[5] == 2;
	if (is64) {
		phoff     = be ? rd_be64(h + 0x20) : rd_le64(h + 0x20);
		phentsize = rd_u16(h + 0x36, be);
		phnum     = rd_u16(h + 0x38, be);
	} else {
		phoff     = be ? rd_be32(h + 0x1c) : rd_le32(h + 0x1c);
		phentsize = rd_u16(h + 0x2a, be);
		phnum     = rd_u16(h + 0x2c, be);
	}
	if (phoff != (is64 ? 64u : 52u))
		return 0;
	if (phentsize != (is64 ? 56u : 32u))
		return 0;
	if (phnum == 0u || phnum > UPX_MAX_PHNUM)
		return 0;
	if (phoff + (uint64_t)phnum * phentsize != (uint64_t)sz_unc)
		return 0;

	upx_layout_of(h, n, &L);
	return L.n != 0;
}

/*
 * The gap that belongs at `written`, if any, and only if it is a gap rather
 * than a claim.
 */
static uint64_t upx_gap_at(const struct upx_layout *L, uint64_t written)
{
	uint32_t i;

	for (i = 0; i + 1u < L->n; i++) {
		uint64_t end = L->off[i] + L->len[i];

		if (written == end && L->off[i + 1u] > end) {
			uint64_t g = L->off[i + 1u] - end;

			return g <= UPX_MAX_GAP ? g : 0;
		}
	}
	return 0;
}

/*
 * The tail block, described by the PackHeader at the end of the object.
 *
 * Fills `off`, `len` and `method` with where the compressed tail is and how
 * large it expands to. Returns zero when there is no PackHeader this can
 * believe, which is the ordinary answer for a truncated file and for anything
 * that is not really UPX.
 *
 * `want` is the original size p_info stated at the FRONT of the object. The
 * PackHeader states it again at the back, and the two agreeing is the whole
 * test: a planted byte sequence would have to match a number written by another
 * structure it does not control.
 */
static int upx_tail_of(const struct kof_obj_ctx *ctx, int be, uint64_t want,
		       uint64_t *out_off, uint64_t *out_len, uint32_t *out_m,
		       uint64_t *out_unc)
{
	uint64_t size = ctx->obj_size, ph, lo, at;

	if (size < UPX_PH_LEN)
		return 0;
	lo = size > UPX_PH_WINDOW ? size - UPX_PH_WINDOW : 0;

	/* The last one in the window: UPX writes its magic in several places
	 * and the PackHeader is the final one. */
	for (ph = size - UPX_PH_LEN + 1u; ph-- > lo; ) {
		uint64_t u_len, c_len, stated;
		uint32_t order;

		if (kof_u8(ph) != 'U' || kof_u8(ph + 1u) != 'P' ||
		    kof_u8(ph + 2u) != 'X' || kof_u8(ph + 3u) != '!')
			continue;

		/*
		 * Two field orders, and neither is assumed.
		 *
		 * The collection carries both - the sizes lead the checksums in
		 * some formats and follow them in others - and the samples do
		 * not separate that from endianness, since every file of one
		 * order was also of one byte order. Rather than encode a guess
		 * about which causes which, both are tried and the one whose
		 * stated original size matches p_info is taken.
		 */
		for (order = 0; order < 2u; order++) {
			uint64_t a = ph + (order ? 8u : 16u);

			u_len  = RD32(a);
			c_len  = RD32(a + 4u);
			stated = RD32(ph + 24u);
			if (stated != want || u_len == 0u || c_len == 0u)
				continue;
			if (u_len > UPX_TAIL_MAX || c_len > u_len)
				continue;

			/*
			 * Its b_info is somewhere between the loader's code and
			 * the PackHeader. Found by looking for the two sizes
			 * the PackHeader just gave, which is a bounded scan
			 * over bytes that are already in the object.
			 */
			for (at = ph > UPX_PH_WINDOW ? ph - UPX_PH_WINDOW : 0;
			     at + B_INFO_LEN <= ph; at++) {
				if (RD32(at) != u_len || RD32(at + 4u) != c_len)
					continue;
				if (at + B_INFO_LEN + c_len > ph)
					continue;   /* data past its own header */
				if (!kof_in_obj(at + B_INFO_LEN, c_len))
					continue;
				*out_off = at + B_INFO_LEN;
				*out_len = c_len;
				*out_m   = kof_u8(at + 8u);
				*out_unc = u_len;
				kof_debug("UPX.ELF.tail", u_len);
				return 1;
			}
		}
	}
	return 0;
}

/*
 * Which row describes this stub, or -1.
 *
 * A -1 is the useful answer as much as a match is: it means either a layout this
 * does not know or a magic that matched something which is not a stub, and from
 * here those are the same thing - the twelve bytes after it would be read as a
 * b_info either way.
 */
static int shape_of(unsigned ver, unsigned fmt)
{
	unsigned i;

	for (i = 0; i < sizeof shapes / sizeof shapes[0]; i++) {
		if (ver < shapes[i].ver_min || ver > shapes[i].ver_max)
			continue;
		if (fmt < 32u && !(shapes[i].formats & (1u << fmt)))
			continue;
		if (fmt >= 32u && !upx_elf_format_high(fmt))
			continue;
		return (int)i;
	}
	return -1;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_elf_info *elf = kof_elf(ctx);
	int be = elf->valid && elf->elf_data == KOF_ELFDATA_BE;
	uint64_t magic_at, at, want, got = 0;
	uint32_t blocks = 0;
	/* Zeroed here rather than by upx_layout_of, so a peek that fails leaves
	 * a layout that finds no gaps instead of one full of stack. */
	struct upx_layout L = { { 0 }, { 0 }, 0 };
	uint64_t padded = 0;
	/*
	 * The first block, kept because it may have to be written out from here
	 * rather than decoded into the child.
	 *
	 * hdr_len is non-zero only when the block was peeked whole AND its ELF
	 * magic had been scribbled on and has been put back; in every other case
	 * this is unused and block 0 goes down the ordinary decode path, byte for
	 * byte as it always did.
	 */
	uint8_t hdr[UPX_HDR_PEEK];
	uint32_t hdr_len = 0;

	/*
	 * Find the stub's magic. Bounded to the front of the object because the
	 * same four bytes appear again in the trailing PackHeader, and reading
	 * p_info relative to that one would read the wrong twelve bytes.
	 */
	magic_at = kof_find_str_where(0, STUB_SEARCH_LEN, upx_magic);
	if (magic_at == KOF_BROKEN)
		return;
	if (magic_at < L_INFO_MAGIC_AT)
		return;                 /* no room for the l_info it belongs to */

	/*
	 * How large the original was, from p_info. The second word of it, which
	 * starts where l_info ends.
	 *
	 * This is what makes "did I finish" answerable rather than guessed. The
	 * block chain has no terminator, so every reason the walk below stops looks
	 * the same from inside it - the end of the data and a corrupt length are
	 * both "the next twelve bytes are not a b_info". Comparing what was decoded
	 * against what the container says it packed is the only check that tells
	 * a complete unpack from a partial one.
	 */
	/*
	 * Which build of UPX wrote this, before anything is decided about it.
	 *
	 * The block chain's layout varies by version and by l_format, and this
	 * module follows one shape of it - so when the walk below stops early, the
	 * useful question is which shape it was looking at. Reported first, so it
	 * arrives even on the samples that go on to fail.
	 */
	{
		unsigned ver = kof_u8(magic_at + L_INFO_VERSION);
		unsigned fmt = kof_u8(magic_at + L_INFO_FORMAT);
		int shape;

		kof_debug("UPX.ELF.version", ver);
		kof_debug("UPX.ELF.format", fmt);

		shape = shape_of(ver, fmt);
		if (shape < 0) {
			/*
			 * Either a layout this does not know, or a magic that
			 * matched something that is not a stub at all - and from
			 * here the two are the same thing: the twelve bytes after
			 * it would be read as a b_info either way.
			 *
			 * Reported as unsupported rather than returned silently,
			 * because that is the difference between a variant that
			 * shows up in a scan's numbers and one that never does.
			 */
			kof_debug("UPX.ELF.unknown_shape", (fmt << 8) | ver);
			KOF_UNP_BROKEN(KOF_UNP_UNSUPPORTED);
		}
		kof_debug("UPX.ELF.shape", (unsigned)shape);
	}

	at = (magic_at - L_INFO_MAGIC_AT) + L_INFO_LEN;
	if (!kof_in_obj(at, P_INFO_LEN))
		return;
	want = RD32(at + 4);
	at += P_INFO_LEN;

	/*
	 * The layout, read from the first block before anything is produced.
	 *
	 * Peeked rather than remembered from the emit, because the emit goes
	 * into the child and a module cannot read the child back. A failure
	 * here is not fatal: L.n stays zero, no gap is ever found, and the
	 * result is what this module produced before - short, but no worse.
	 */
	{
		uint32_t sz_cpr, sz_unc0, method, decoder, skip = 0, got_hdr;

		if (kof_in_obj(at, B_INFO_LEN)) {
			sz_unc0 = RD32(at);
			sz_cpr = RD32(at + 4);
			method = kof_u8(at + 8);
			decoder = method_of(method);
			if (decoder == 0 && method == UPX_M_LZMA &&
			    sz_cpr > UPX_LZMA_SKIP) {
				decoder = upx_lzma_method(kof_u8(at +
								B_INFO_LEN));
				skip = UPX_LZMA_SKIP;
			}
			/*
			 * Decoded with the block's OWN declared size as the
			 * bound, not with the buffer's.
			 *
			 * NRV2 has no end marker: it stops when the output is
			 * full, so the size it is given is part of the decode
			 * rather than a safety net around it. A block larger
			 * than the buffer therefore cannot be peeked at all -
			 * the bound would differ from the one the real decode
			 * uses, and the bytes would be a different decode - so
			 * the layout is left empty rather than read out of
			 * them.
			 *
			 *
			 * FORMAT 42 AND THE THREE BYTES THAT ARE NOT THERE
			 *
			 * This peek used to be blamed for ARM64 coming out
			 * short. It reads 7f 0c 93 2b on one format 42 sample
			 * where an ELF header should start, and the conclusion
			 * drawn was that the decode was wrong.
			 *
			 * It is not. Those bytes are in the file: the block is
			 * NRV2B and its first literals appear in clear in the
			 * compressed stream, where they read 7f 0c 93 2b. Four
			 * of the six format 42 samples have 7f 45 4c 46 in the
			 * same place and decode to a header the walk below
			 * accepts; two have had their magic scribbled on before
			 * packing, with a different value each, and the walk
			 * rejected them for it. The peek was right the whole
			 * time and the magic test was the bug - see
			 * upx_magic_tampered above for what replaced it.
			 */
			if (decoder && sz_cpr > skip && sz_unc0 &&
			    sz_unc0 <= UPX_HDR_PEEK &&
			    kof_in_obj(at + B_INFO_LEN, sz_cpr)) {
				got_hdr = kof_unpack_peek(decoder,
							  at + B_INFO_LEN + skip,
							  sz_cpr - skip, hdr,
							  (uint32_t)sz_unc0);
				upx_layout_of(hdr, got_hdr, &L);
				if (upx_magic_tampered(hdr, got_hdr,
						       sz_unc0)) {
					hdr[1] = 'E';
					hdr[2] = 'L';
					hdr[3] = 'F';
					hdr_len = got_hdr;
					kof_debug("UPX.ELF.magic_repaired",
						  got_hdr);
					/* The object really was tampered with,
					 * and a caller deciding how much to
					 * trust this child should be told so
					 * rather than handed a clean-looking
					 * ELF that this module assembled. */
					kof_unp_broken(KOF_UNP_DAMAGED);
				}
			}
		}
		kof_debug("UPX.ELF.loads", L.n);
	}

	for (;;) {
		uint32_t sz_unc, sz_cpr, method, skip = 0;
		uint64_t n;
		uint32_t decoder;
		/* Set when this block's compressed data is cut off by the end of
		 * the object and only its front is being decoded. */
		int cut = 0;

		if (!kof_in_obj(at, B_INFO_LEN))
			break;
		sz_unc = RD32(at);
		sz_cpr = RD32(at + 4);
		method = kof_u8(at + 8);

		/*
		 * Is this a b_info at all, or the bytes that follow the last one?
		 *
		 * Three things say no, and each is a property of the object rather
		 * than a limit invented here: a block with no data, a block claiming
		 * to expand to nothing, and a block whose compressed form is larger
		 * than what it expands to - which is not compression and not
		 * something UPX writes.
		 */
		if (sz_cpr == 0 || sz_unc == 0)
			break;
		if (sz_cpr > sz_unc)
			break;

		/*
		 * A FOURTH CASE THAT IS NOT THE CHAIN ENDING: THE FILE ENDING.
		 *
		 * A record whose data runs past the end of the object used to be
		 * grouped with the three above and left silently, and that is the
		 * one of the four that is not "these bytes were never a b_info".
		 * The other three are decided by the record's own contents; this
		 * one is decided by how much file there is, and a well formed
		 * record naming a coding this module decodes, with self consistent
		 * sizes and no bytes behind it, is a truncated file rather than the
		 * end of a chain.
		 *
		 * Worth telling apart because the results differ completely. The
		 * chain ending is a finished unpack. A truncated file is a partial
		 * one - real output, correct as far as it goes, and short - and
		 * reported as a finished unpack it reads as though the original had
		 * been recovered. Measured on 251816206c8d..., a sample cut to
		 * 1198103 of the 2528130 bytes its own program header declares:
		 * blocks 0 and 1 decode exactly, block 2 wants 1837562 compressed
		 * bytes with 1111611 left in the file, and 393216 of 6154376 bytes
		 * came out. Reference upx 4.2.4 refuses the file outright.
		 *
		 * DAMAGED rather than LIMIT: nothing here ran out of budget, the
		 * object is missing bytes it says it has.
		 *
		 *
		 * AND THE PART THAT IS THERE IS STILL DECODED.
		 *
		 * This used to stop here and keep only the blocks behind it, on
		 * the reasoning that the finding is that the data is not there.
		 * That is right about the finding and wrong about the bytes: what
		 * is missing is the TAIL of the block, and the front of it is
		 * sitting in the file. Measured over 916 packed samples, 35 have
		 * a block cut off by the end of the file, and those cut blocks
		 * hold 6849668 of the 12796628 compressed bytes they declare -
		 * 53.5% of the payload, thrown away.
		 *
		 * On 06ed8158a168... the difference is the whole sample: the
		 * first block is the ELF header and the second is the program,
		 * cut at 245311 of 1020709 bytes. Stopping here recovered 624
		 * bytes - a header describing a file with nothing in it - and
		 * every string, every symbol and every marker in that sample sat
		 * in the block being discarded.
		 *
		 * Decoding a truncated stream is what the decoders are for: none
		 * of these codings needs an end marker, they stop when the input
		 * runs out and the host reports what came out. So the length is
		 * cut down to what the object holds, the block is decoded, and
		 * the walk stops after it - there is nothing behind a block that
		 * reaches the end of the file.
		 */
		if (!kof_in_obj(at + B_INFO_LEN, sz_cpr)) {
			uint64_t have = ctx->obj_size > at + B_INFO_LEN
					? ctx->obj_size - (at + B_INFO_LEN) : 0;

			/* Not a coding this module runs: these bytes were never
			 * a b_info, so nothing is wrong and nothing is said. */
			if (!method_of(method) && method != UPX_M_LZMA)
				break;
			kof_unp_broken(KOF_UNP_DAMAGED);
			if (have < UPX_MIN_CUT)
				break;
			sz_cpr = (uint32_t)have;
			cut = 1;
		}

		decoder = method_of(method);
		/*
		 * More blocks than any real archive has. Reported as a limit and
		 * not as damage: what is wrong is that the walk stopped, and the
		 * blocks behind it are real output worth keeping.
		 */
		if (blocks >= UPX_MAX_BLOCKS) {
			kof_unp_broken(KOF_UNP_LIMIT);
			break;
		}

		if (decoder == 0 && method == UPX_M_LZMA) {
			if (sz_cpr <= UPX_LZMA_SKIP)
				break;
			decoder = upx_lzma_method(kof_u8(at + B_INFO_LEN));
			if (decoder == 0) {
				/* Recorded and NOT returned: the blocks already
				 * decoded are real output and are kept. */
				kof_unp_broken(KOF_UNP_DAMAGED);
				break;
			}
			skip = UPX_LZMA_SKIP;
		} else if (decoder == 0) {
			break;          /* not a coding at all: the chain ended */
		}

		kof_debug("UPX.ELF.method", method);
		/*
		 * The first block, when its magic was repaired, is written from
		 * the buffer that holds the repair instead of being decoded a
		 * second time. Same bytes and the same count - it is the peek
		 * of this block, produced by this decoder with this block's own
		 * sz_unc - with three of them put back.
		 */
		if (blocks == 0 && hdr_len && hdr_len == sz_unc) {
			n = kof_emit(hdr, hdr_len) ? hdr_len : 0;
			if (!n)
				kof_unp_broken(KOF_UNP_LIMIT);
		} else {
			n = kof_unpack_at(decoder, at + B_INFO_LEN + skip,
					  sz_cpr - skip, sz_unc);
		}
		/*
		 * THIS block's output, not the running total.
		 *
		 * The total was what this tested, and against a chain it is the
		 * wrong question: once any block has produced something the sum is
		 * non-zero for good, so every block after it is decoded and its
		 * failure ignored however many there are. A block that yields
		 * nothing has ended the chain - the stream is not what the record
		 * said it was - and there is nothing to be gained by asking the
		 * next record the same question.
		 *
		 * The LZMA path did not ask at all, which is how a file of minimal
		 * records became millions of allocations.
		 */
		if (n == 0)
			break;
		got += n;
		blocks++;

		/*
		 * The alignment that follows this block, when it just filled a
		 * segment. Zeros, because that is what is between two PT_LOADs
		 * in the original and the reason UPX does not store it is that
		 * nothing loads it.
		 *
		 * Capped in total as well as per gap: the per gap bound stops
		 * one lying program header, the total stops sixteen of them.
		 */
		{
			uint64_t gap = upx_gap_at(&L, got);

			if (padded + gap > UPX_MAX_PAD)
				gap = 0;
			padded += gap;
			while (gap) {
				uint8_t zero[256];
				uint32_t k, step = gap > sizeof zero
						   ? (uint32_t)sizeof zero
						   : (uint32_t)gap;

				for (k = 0; k < step; k++)
					zero[k] = 0;
				if (!kof_emit(zero, step)) {
					kof_unp_broken(KOF_UNP_LIMIT);
					break;
				}
				got += step;
				gap -= step;
			}
		}

		if (cut)
			break;          /* the object ended inside that block */

		at += B_INFO_LEN + sz_cpr;
	}

	/*
	 * One child holding every block, in order.
	 *
	 * Not one child per block: the blocks are consecutive pieces of a single
	 * original file, and cutting between them would hand the scanner fragments
	 * that begin mid-structure - the same thing the object cap was changed to
	 * stop doing. Emitting them all and closing once yields the original ELF.
	 */
	/*
	 * The tail: the original's padding and its section header table.
	 *
	 * Not in the chain. It has its own b_info near the end of the object,
	 * after the loader's code, and only the PackHeader says where. Appended
	 * last because that is where it belongs - past the final segment - and
	 * the arithmetic then closes: chain + gaps + tail is the original size
	 * on every architecture measured.
	 */
	if (blocks) {
		uint64_t t_off, t_len, t_unc;
		uint32_t t_m, t_dec;

		if (upx_tail_of(ctx, be, want, &t_off, &t_len, &t_m, &t_unc)) {
			t_dec = method_of(t_m);
			if (t_dec == 0 && t_m == UPX_M_LZMA &&
			    t_len > UPX_LZMA_SKIP) {
				t_dec = upx_lzma_method(kof_u8(t_off));
				t_off += UPX_LZMA_SKIP;
				t_len -= UPX_LZMA_SKIP;
			}
			/*
			 * Bounded by what the PackHeader declared it expands
			 * to. Left unbounded it ran a byte or two past the end
			 * - NRV2 decodes until its input is exhausted, and the
			 * last few bits of a stream can yield one more symbol -
			 * so the recovered file came out longer than the
			 * original it was rebuilding.
			 */
			if (t_dec)
				got += kof_unpack_at(t_dec, t_off, t_len,
						     t_unc);
		}
	}

	kof_debug("UPX.ELF.blocks", blocks);
	/*
	 * How far short of the ORIGINAL FILE SIZE the blocks came, as a number to
	 * look at rather than a verdict.
	 *
	 * It is reported and not acted on, and that correction is worth recording.
	 * This module first treated "got < p_filesize" as proof it had stopped
	 * early, and it is not: p_filesize is the size of the file UPX packed,
	 * while the block chain covers only the parts that get loaded - the section
	 * headers and symbol table of the original are simply not in it. Measured
	 * over 154 samples, 54 recovered 99% or more of p_filesize and 24 more
	 * stopped between 50% and 90% having reached the end of their chain. The
	 * old test called nearly every one of them incomplete.
	 */
	kof_debug("UPX.ELF.shortfall", want > got ? want - got : 0);

	/*
	 * The handover is checked, like every container in this directory
	 * checks it.
	 *
	 * A packer's child is not one entry of many - it is the whole of what
	 * the file was hiding. Refused by the host (a ceiling reached, the child
	 * cap spent) and not reported, the module would be saying it unpacked
	 * the object while having produced nothing, which is the one answer a
	 * scan must never give about a packed sample.
	 */
	if (blocks) {
		if (!kof_child())
			kof_unp_broken(KOF_UNP_LIMIT);
	} else
		/* Opened it and recovered nothing. The block chain did not begin
		 * where this module looks, which on this corpus is a damaged file
		 * far more often than a layout nobody has met. */
		kof_unp_broken(KOF_UNP_DAMAGED);
}
