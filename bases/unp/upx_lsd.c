/*
 * upx_lsd.c - UPX with its magic patched out.
 *
 * A packed file carries l_info near the front, and the four bytes in the middle
 * of it are the string "UPX!". They are the only thing an unpacker searches for
 * and they are four bytes, so they get changed. Measured on four samples of one
 * build - 3b74d5dd, 5fc47a22, 9f3d6298, e4f7493d - those four bytes read
 * "LSD!", and the thirty-two bytes around them are byte-identical across all
 * four and identical to what UPX writes:
 *
 *     l_checksum 0x83cb2675 | "LSD!" | l_lsize 2344 | l_version 13 | l_format 22
 *     p_progid 0 | p_filesize 6261568 | p_blocksize 6261568
 *     b_info: sz_unc 456, sz_cpr 151, method 8 (NRV2E_LE32)
 *
 * l_version 13 and l_format 22 are UPX's own numbers for a linux/amd64 ELF64
 * stub; sz_unc 456 is exactly 64 + 7 * 56, the original's ELF header and its
 * seven program headers. Nothing about the packer was modified. A byte patcher
 * was run over its output, and it defeated the whole unpacker.
 *
 *
 * WHY THIS IS A MODULE OF ITS OWN AND WHAT IT DOES
 *
 * It does not unpack anything: upx_elf.c already knows how, and a second copy
 * of a block-chain walk is a second place for a bug to live. What this module
 * has that the other cannot is the knowledge that these particular four bytes
 * were a magic - and the way one module hands work to another here is to
 * produce a child. So it puts "UPX!" back and emits the object; the engine
 * scans that child like any other, and upx_elf.c opens it.
 *
 * The repair is reported. Three bytes of the child came from this module rather
 * than from the file, and a reader looking at a recovered image is owed that.
 *
 *
 * WHY THE MARKER IS NOT ENOUGH ON ITS OWN
 *
 * "LSD!" is three letters and a bang; it occurs in ordinary text. What makes it
 * mean something here is WHERE it is: l_info sits immediately after the program
 * header table, and the magic sits four bytes into l_info. That position is
 * arithmetic on fields the collector has already read, so the test is "is the
 * marker exactly where a magic would be" rather than "is the marker present".
 * Everything after it is then checked against what UPX writes.
 */

#include <kofmod/kofsig.h>
#include <kofmod/elf.h>

KOF_UNPACK_KIND(KOF_UNP_PACKER);

KOF_TARGET_FORMAT(KOF_FMT_ELF);

/*
 * Declared so the host searches with the machinery it already has. Bounded to
 * the front of the object by the caller, because this is a header field and not
 * a string that could be anywhere.
 */
KOF_DEFINE_STR(lsd_magic, "LSD!", KOF_CASE_EXACT, KOF_WORD_SUBSTRING);

#define L_INFO_LEN       12u
#define L_INFO_MAGIC_AT   4u
#define L_INFO_VERSION    6u        /* magic_at + this */
#define L_INFO_FORMAT     7u
#define P_INFO_LEN       12u
#define B_INFO_LEN       12u
#define SEARCH_LEN     8192u
#define CHUNK          1024u

/* UPX's own numbers, and the same span upx_elf.c walks: versions 10 to 20 over
 * the ELF formats. Repeated as constants rather than shared, because a module
 * is a freestanding blob and cannot call into another one - and two constants
 * that must agree are cheaper to keep in step than two block-chain walks. */
#define VER_MIN 10u
#define VER_MAX 20u

static int format_ok(unsigned f)
{
	/* The same set upx_elf.c's UPX_ELF_FORMATS mask holds, plus the three
	 * above 31 it lists separately. Kept literal so a reader can compare
	 * the two lists by eye. */
	switch (f) {
	case 12: case 13: case 14: case 15:
	case 22: case 23: case 24: case 25:
	case 27: case 28: case 30: case 31:
	case 42: case 132: case 137:
		return 1;
	default:
		return 0;
	}
}

/* UPX's compression methods this engine decodes: the NRV family and LZMA. */
static int method_ok(unsigned m)
{
	return (m >= 2u && m <= 10u) || m == 14u;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_elf_info *elf = kof_elf(ctx);
	uint64_t l_info, magic_at, size, at;
	uint32_t f_size, b_size, sz_unc, sz_cpr;
	unsigned ver, fmt, method;
	uint8_t buf[CHUNK];

	if (!elf->valid || !elf->phnum || !elf->phentsize)
		return;

	/*
	 * Where l_info has to be, and then whether the marker is there.
	 *
	 * This order matters. Searching first and checking the position after
	 * would accept the string anywhere in the first eight kilobytes and
	 * then ask whether it happened to be in the right place; deriving the
	 * position first says what is being looked for.
	 */
	l_info = elf->phoff + (uint64_t)elf->phnum * elf->phentsize;
	magic_at = kof_find_str_where(0, SEARCH_LEN, lsd_magic);
	if (magic_at == KOF_BROKEN || magic_at != l_info + L_INFO_MAGIC_AT)
		return;
	if (!kof_in_obj(l_info, L_INFO_LEN + P_INFO_LEN + B_INFO_LEN))
		return;

	/*
	 * Everything the patcher had no reason to touch, and it all has to
	 * agree at once: a build of UPX this engine knows, a p_info whose two
	 * sizes are equal and non-zero, and a first block whose method it
	 * decodes and whose compressed length is neither zero nor larger than
	 * what it expands to.
	 */
	ver = kof_u8(magic_at + L_INFO_VERSION);
	fmt = kof_u8(magic_at + L_INFO_FORMAT);
	if (ver < VER_MIN || ver > VER_MAX || !format_ok(fmt))
		return;

	at     = l_info + L_INFO_LEN;
	f_size = kof_u32(at + 4u);
	b_size = kof_u32(at + 8u);
	if (!f_size || f_size != b_size)
		return;

	at     = l_info + L_INFO_LEN + P_INFO_LEN;
	sz_unc = kof_u32(at);
	sz_cpr = kof_u32(at + 4u);
	method = kof_u8(at + 8u);
	if (!sz_unc || !sz_cpr || sz_cpr > sz_unc || !method_ok(method))
		return;

	kof_debug("UPX.LSD.version", ver);
	kof_debug("UPX.LSD.format", fmt);
	kof_debug("UPX.LSD.method", method);
	kof_debug("UPX.LSD.orig_size", f_size);

	/*
	 * The object again, with the magic put back.
	 *
	 * A copy rather than a window, because a window cannot differ from what
	 * it looks at and the whole point is four bytes that must. Emitted
	 * through the host so it is charged to the same budget and stopped by
	 * the same ceiling as any decompression.
	 */
	size = ctx->obj_size;
	for (at = 0; at < size; ) {
		uint32_t n = 0;

		while (n < CHUNK && at + n < size) {
			uint64_t o = at + n;

			if (o >= magic_at && o < magic_at + 4u)
				buf[n] = (uint8_t)"UPX!"[o - magic_at];
			else
				buf[n] = kof_u8(o);
			n++;
		}
		if (!n || !kof_emit(buf, n))
			return;
		at += n;
	}
	kof_child();
}
