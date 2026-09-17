/*
 * bz2.c - yield what a bzip2 stream holds as an object of its own.
 *
 * The same four lines gzip.c is, and for the same reason: the module's part is
 * the decision - this object is bzip2, its stream starts here, it is worth
 * opening - and the work is the host's. The decoder is one implementation
 * shared by everything that carries this coding, and the limits are the host's
 * sink refusing to take more.
 *
 * NO BOMB CHECK HERE, and bzip2 is the format where that is most tempting: it
 * reaches ratios deflate cannot, and the wrapper declares NOTHING - no output
 * size, no entry count - so there is not even a number to be suspicious of. A
 * bomb is still not a thing this module can recognise; it is a stream whose
 * output the host stops accepting, and by then this module has been told to
 * stop. The one number worth having is in the view for a detector to match on:
 * the level digit says how large a block the writer asked for.
 *
 * CONCATENATED STREAMS ARE ONE CHILD, not several. `bzip2 -c a b` writes two
 * complete streams end to end and every bzip2 decodes both into one output, so
 * that is what the decoder does and what a reader of the original file sees.
 * Splitting them here would invent a structure the format does not have.
 */

#include <kofmod/kofsig.h>
#include <kofmod/bz2.h>

KOF_TARGET_FORMAT(KOF_FMT_BZIP2);
/*
 * A CONTAINER, not a packer: a .bz2 carries a file that was separately there,
 * the way a gzip or a tar does. It hid nothing, so depth through it is a
 * directory tree rather than a layer of packing, and a heuristic that weighs
 * "this was packed" must not weigh this.
 */
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_bz2_info *bz = kof_bz2(ctx);

	if (!bz->valid || !bz->level || !bz->data_len)
		return;
	/*
	 * An empty stream holds nothing, and a child of nothing is a row in
	 * every report that says only that the file was empty - which the
	 * anomaly already says, in the place a reader looks for it.
	 */
	if (bz->anomalies & KOF_BZ2_ANOM_EMPTY)
		return;

	/*
	 * FROM ZERO, NOT FROM data_off, AND THAT IS THE CODING'S CONTRACT.
	 *
	 * A gzip module hands over the DEFLATE stream and keeps the wrapper,
	 * because deflate begins where the wrapper ends. bzip2 does not come
	 * apart that way: the level digit in the header states the block size
	 * the decoder has to know before it reads a bit, and what follows is
	 * not byte aligned. So the range is the whole object - see
	 * KOF_UNP_BZIP2.
	 *
	 * The length is an upper bound rather than a fact, since bzip2 states
	 * no compressed size anywhere. The decoder stops at its own end marker,
	 * which is what makes the bound safe to pass in - and it follows a
	 * second stream concatenated behind the first, which is why the bound
	 * is the object and not the first stream.
	 */
	if (!kof_unpack_at(KOF_UNP_BZIP2, 0, ctx->obj_size, 0))
		return;

	kof_child();
}
