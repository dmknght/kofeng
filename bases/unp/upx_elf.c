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

KOF_DEFINE_UNPACK
{
	const struct kof_elf_info *elf = kof_elf(ctx);
	int be = elf->valid && elf->elf_data == KOF_ELFDATA_BE;
	uint64_t magic_at, at, want, got = 0;
	uint32_t blocks = 0;

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
	kof_debug("UPX.ELF.version", kof_u8(magic_at + L_INFO_VERSION));
	kof_debug("UPX.ELF.format", kof_u8(magic_at + L_INFO_FORMAT));

	at = (magic_at - L_INFO_MAGIC_AT) + L_INFO_LEN;
	if (!kof_in_obj(at, P_INFO_LEN))
		return;
	want = RD32(at + 4);
	at += P_INFO_LEN;

	for (;;) {
		uint32_t sz_unc, sz_cpr, method;
		uint32_t decoder;

		if (!kof_in_obj(at, B_INFO_LEN))
			break;
		sz_unc = RD32(at);
		sz_cpr = RD32(at + 4);
		method = kof_u8(at + 8);

		/*
		 * Is this a b_info at all, or the bytes that follow the last one?
		 *
		 * Four things say no, and each is a property of the object rather
		 * than a limit invented here: a block with no data, a block whose
		 * data runs past the end of the file, a block claiming to expand to
		 * nothing, and a block whose compressed form is larger than what it
		 * expands to - which is not compression and not something UPX
		 * writes.
		 */
		if (sz_cpr == 0 || sz_unc == 0)
			break;
		if (!kof_in_obj(at + B_INFO_LEN, sz_cpr))
			break;
		if (sz_cpr > sz_unc)
			break;

		decoder = method_of(method);
		if (decoder == 0 && method == UPX_M_LZMA) {
			uint32_t lz;

			if (sz_cpr <= UPX_LZMA_SKIP)
				break;
			lz = upx_lzma_method(kof_u8(at + B_INFO_LEN));
			if (lz == 0) {
				/* Recorded and NOT returned: the blocks already
				 * decoded are real output and are kept. */
				kof_unp_broken(KOF_UNP_DAMAGED);
				break;
			}
			kof_debug("UPX.ELF.method", method);
			got += kof_unpack_at(lz, at + B_INFO_LEN + UPX_LZMA_SKIP,
					     sz_cpr - UPX_LZMA_SKIP, sz_unc);
			blocks++;
			at += B_INFO_LEN + sz_cpr;
			continue;
		}
		if (decoder == 0)
			break;          /* not a coding at all: the chain ended */

		kof_debug("UPX.ELF.method", method);
		got += kof_unpack_at(decoder, at + B_INFO_LEN, sz_cpr, sz_unc);
		if (got == 0)
			break;          /* the host refused, or nothing decoded */
		blocks++;

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

	if (blocks)
		kof_child();
	else
		/* Opened it and recovered nothing. The block chain did not begin
		 * where this module looks, which on this corpus is a damaged file
		 * far more often than a layout nobody has met. */
		kof_unp_broken(KOF_UNP_DAMAGED);
}
