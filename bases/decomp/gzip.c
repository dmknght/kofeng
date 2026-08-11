/*
 * unp_gzip.c - yield what a gzip holds as an object of its own.
 *
 * The first module that produces bytes which were not in the file. unp_overlay
 * yields a window - the parent's mapping at a different offset, costing nothing -
 * and this is the other kind: output that has to be decoded, held somewhere and
 * paid for out of a budget.
 *
 * It is four lines because the host does the work. The module's part is the
 * decision - this object is gzip, its stream starts here, it is worth opening -
 * and everything expensive or dangerous about the rest is the host's: the decoder
 * is one implementation shared by every format that carries DEFLATE, and the
 * limits are the host's sink refusing to take more. There is no bomb check here
 * because a bomb is not a thing this module can recognise; it is a stream whose
 * output the host stops accepting, and by then this module has already been told
 * to stop.
 *
 * Note what is NOT rejected. A stream flagged with a reserved bit, one whose
 * declared ratio is absurd, one whose header was cut short - all of them are
 * decoded anyway. RFC 1952 says a reader should refuse some of these, and a
 * scanner is not a reader: a file that is malformed in a way real tools tolerate
 * is a file worth looking inside, and a file that is malformed in a way they do
 * not is one somebody built by hand. The anomalies are recorded in the view for a
 * detector to match on; refusing to open them would be declining to look exactly
 * where looking pays.
 */

#include <kofmod/kofsig.h>
#include <kofmod/gzip.h>

KOF_TARGET_FORMAT(KOF_FMT_GZIP);

KOF_DEFINE_UNPACK
{
	const struct kof_gzip_info *gz = kof_gzip(ctx);

	if (!gz->valid || gz->method != KOF_GZIP_DEFLATE || !gz->data_len)
		return;

	/*
	 * data_len bounds the input and is an upper bound rather than a fact -
	 * gzip states no compressed size, so it is everything between the header
	 * and the trailer. The decoder stops at its own end-of-stream marker,
	 * which is what makes the guess safe to pass in.
	 */
	if (!kof_unpack_deflate(gz->data_off, gz->data_len))
		return;

	kof_child();
}
