/*
 * upx_method.h - what UPX's method byte means, for the modules that read a UPX
 * header (upx_pe.c, upx_elf_00.c).
 *
 * Module-side helper, like pe_reassemble.h and ep_shape.h: a module includes it
 * after <kofmod/kofsig.h>, and it is freestanding. It was written out in both
 * modules, word for word; a module is a blob, so what two of them share is a
 * header and not a function in one of them.
 *
 * THE TWO FUNCTIONS ARE MACROS THAT DEFINE THEM, invoked where each module had
 * the function. A blob is linked with -ffunction-sections and its bytes follow
 * the order the functions were emitted in, so a plain static function moved up
 * into this header would reorder the blob (measured: the pack changed with no
 * change of behaviour). Defined where it always was, a module compiles to the
 * same bytes it did.
 */

#ifndef KOF_UPX_METHOD_H
#define KOF_UPX_METHOD_H

/*
 * UPX method numbers, from its conf.h, mapped onto the engine's decoders.
 *
 * Each group of three is one coding at three bit-buffer widths - _LE32, _8, _LE16
 * in that order - not one coding with three filters. Getting that wrong decodes
 * every _LE32 stream correctly and every _8 stream not at all, which is what it
 * did before it was measured.
 */
#define KOF_UPX_DEFINE_METHOD_OF()                                         \
static uint32_t upx_method_of(unsigned m)                                  \
{                                                                          \
	switch (m) {                                                       \
	case 2:  return KOF_UNP_NRV2B_32;                                  \
	case 3:  return KOF_UNP_NRV2B_8;                                   \
	case 4:  return KOF_UNP_NRV2B_16;                                  \
	case 5:  return KOF_UNP_NRV2D_32;                                  \
	case 6:  return KOF_UNP_NRV2D_8;                                   \
	case 7:  return KOF_UNP_NRV2D_16;                                  \
	case 8:  return KOF_UNP_NRV2E_32;                                  \
	case 9:  return KOF_UNP_NRV2E_8;                                   \
	case 10: return KOF_UNP_NRV2E_16;                                  \
	default: return 0;              /* LZMA, or something newer */     \
	}                                                                  \
}

/*
 * UPX's own number for LZMA, and the reason it is named rather than lumped in
 * with every other byte a module does not recognise.
 *
 * A method byte of 14 is a coding UPX really uses, so meeting one means there was
 * a block here and it was not decoded - the object is short by whatever that block
 * held. Any other unrecognised byte is not a coding at all: it is whatever followed
 * the last block, which for this format is the decompression stub. Measured over
 * 154 packed ELF samples, of the 31 walks that stopped on an unrecognised byte, 29
 * had already recovered 99% or more of the original - they had finished, and were
 * reading machine code.
 */
#define UPX_M_LZMA 14u

/*
 * UPX's LZMA blocks: the stream starts UPX_LZMA_SKIP bytes in, and those two bytes
 * carry lc and pb. lp is taken as zero (every one of 330 measured blocks used 0);
 * the measurement and what a wrong guess costs are written up in upx_pe.c.
 */
#define UPX_LZMA_SKIP  2u
#define UPX_LZMA_LP    0u

/*
 * lc and pb both come from the file, and both size or shape the decoder's model.
 * Out of range is refused here so the module can say it did not finish, rather
 * than being refused inside the host with nothing to report.
 */
#define KOF_UPX_DEFINE_LZMA_METHOD()                                       \
static uint32_t upx_lzma_method(unsigned first_byte)                       \
{                                                                          \
	unsigned lc = first_byte >> 3, pb = first_byte & 7u;               \
                                                                           \
	if (lc > KOF_LZMA_MAX_LC || pb > KOF_LZMA_MAX_PB)                  \
		return 0;                                                  \
	return KOF_UNP_LZMA_PROPS(lc, UPX_LZMA_LP, pb);                    \
}

#endif /* KOF_UPX_METHOD_H */
