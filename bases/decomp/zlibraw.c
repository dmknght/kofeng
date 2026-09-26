/*
 * zlibraw.c - a raw zlib stream, opened as the object it holds.
 *
 * WHAT WAS MISSING. gzip.c opens a DEFLATE stream that carries a gzip frame -
 * the magic, the method byte, the name and the trailer. A zlib stream has none
 * of that: two header bytes and then the same DEFLATE. Nothing in the database
 * claimed one, so a payload stored that way arrived as an object the engine
 * could name nothing about and no rule could reach past its first byte.
 *
 * Found in a PE overlay: of 24 overlay children measured across 300 samples,
 * the engine could name three, and the largest of the rest opened "78 da" -
 * zlib, best compression, 10.4 MB of it.
 *
 * ANCHORED BY POSITION, NOT BY SEARCH, which is the whole difference between
 * this and a module that hunts for byte-shaped runs. The engine has already
 * decided this object is unidentified; the only question asked here is whether
 * it BEGINS with a zlib header. Searching for one would be the mistake
 * kofmod/kofsig.h warns about for base64 - two bytes are not evidence, and a
 * file large enough contains every pair somewhere.
 *
 * AND THE HEADER VALIDATES ITSELF, which is why two bytes are enough HERE:
 *
 *   CM must be 8. DEFLATE is the only method zlib ever defined, so anything
 *     else is not a zlib stream whatever else it is.
 *   CINFO must be at most 7. It is log2(window) - 8, and 32K is the largest
 *     window the format allows.
 *   FDICT must be clear. A stream that needs a preset dictionary cannot be
 *     decoded without it, and nothing here has it.
 *   THE CHECK MUST HOLD: (CMF << 8 | FLG) is a multiple of 31, which is the
 *     header's own five-bit checksum.
 *
 * Together those leave roughly one arbitrary pair in a thousand, and the
 * inflate behind them is the real test: kof_unpack_deflate returns zero for a
 * stream that does not decode, and a child is only closed when it produced
 * something.
 */
#include <kofmod/kofsig.h>

KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

/*
 * UNIDENTIFIED OBJECTS ONLY. A zlib stream inside a format the engine knows is
 * that format's business - a PNG's IDAT, a PDF's FlateDecode stream - and those
 * have parsers that say where their streams are. This is for the object that
 * arrived as nothing: an overlay, a carved run, a decoded blob.
 */
KOF_TARGET_FORMAT(KOF_FMT_UNKNOWN);

/* Below this there is no room for a header and a stream worth opening. */
#define MIN_LEN 64u

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	uint32_t cmf, flg;

	if (ctx->obj_size < MIN_LEN)
		return;

	cmf = kof_u8(0);
	flg = kof_u8(1);

	if ((cmf & 0x0fu) != 8u)            /* CM: DEFLATE                    */
		return;
	if ((cmf >> 4) > 7u)                /* CINFO: window at most 32K      */
		return;
	if (flg & 0x20u)                    /* FDICT: no preset dictionary    */
		return;
	if (((cmf << 8) | flg) % 31u)       /* the header's own check         */
		return;

	/*
	 * Past the two header bytes. The trailing Adler-32 is not skipped and
	 * does not need to be: DEFLATE says where it ends, and the four bytes
	 * after it are simply never read.
	 */
	if (!kof_unpack_deflate(2, ctx->obj_size - 2u))
		return;
	/*
	 * Every other module in this directory tests this and this one did
	 * not. kof_child() answering zero is the host refusing the child -
	 * the object budget is spent - and a module that ignores it reports
	 * an archive it opened as one that held nothing.
	 */
	if (!kof_child())
		KOF_UNP_BROKEN(KOF_UNP_LIMIT);

	/*
	 * ONE STREAM, AND THE REST IS LEFT WHERE IT IS.
	 *
	 * A concatenation is common - the sample this was written against is a
	 * Python bundle whose overlay holds 10.9 MB and whose first stream is
	 * 291 bytes of marshalled bytecode - and this opens only the first of
	 * them. That is a limit of the primitive and not a choice:
	 * kof_unpack_deflate answers with the bytes it PRODUCED, so there is no
	 * way from here to learn where the stream it read ended, and stepping
	 * forward by a guess would be searching for headers again.
	 *
	 * What holds a run of streams together is a format - a PyInstaller
	 * archive, a py2exe table - and that format's own module is where the
	 * second stream's offset is known rather than hunted for.
	 */
}
