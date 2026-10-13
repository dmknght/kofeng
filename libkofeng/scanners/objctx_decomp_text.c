/*
 * objctx_decomp_text.c - the codings that are text on the way in: RTF's hex,
 * ASCII85, ASCIIHex and RunLength.
 *
 * WHAT THIS SERVES: a document module that names one of these as the coding of
 * a range. They differ from the streaming codings in being bounded by their
 * input (two characters a byte, four fifths of a byte a character), which is
 * what lets a buffer be sized before the decode - see objctx_decomp.h.
 */


#include "objctx_decomp.h"
#include <stdlib.h>

/*
 * RTF's hex text, back to bytes.
 *
 * Its own function because it is an algorithm, not a dispatch: oc_unpack picks a
 * decoder and this decodes, and having the two in one place made oc_unpack a
 * hundred and forty lines that reached eight levels deep - all of the depth
 * being here, in the brace and control-word skipping this format needs.
 *
 * WHAT IT SKIPS AND WHY. \bin and its friends put arbitrary text between the
 * hex digits, and a group in braces can hold a whole document; both would
 * otherwise be read as data. The control word skip is the one that matters:
 * without it "\par" contributes an 'a' to the stream and every byte after it
 * is shifted by half a nibble.
 */
uint64_t oc_unpack_hextext(const struct kof_obj_ctx *ctx, kof_buf b,
			       uint64_t off, uint64_t len)
{
	uint64_t produced = 0;

	/*
	 * Hex to bytes, streamed through the sink like DEFLATE.
	 *
	 * No output buffer of its own and no size hint needed: two input
	 * characters are one output byte, so the length is known and the
	 * bytes can leave as they are made. Whitespace between digits is
	 * skipped - it is legal in RTF and is used to break a blob up so a
	 * fixed prefix does not match.
	 */
	uint8_t out[512];
	uint32_t n = 0;
	int hi = -1;
	uint64_t i;

	for (i = 0; i < len; i++) {
		uint8_t ch = b.p[off + i];
		int v;

		if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
			continue;
		/*
		 * A nested group is skipped WHOLE, not just its braces.
		 *
		 * Its content is a different destination and is not this
		 * object's data. Skipping only the braces decodes the junk
		 * inside as if it were payload, which on a real document
		 * produced 2875922 bytes against the correct 2875905 - the
		 * right length to look plausible and wrong from the first
		 * byte.
		 */
		if (ch == '{') {
			uint32_t d = 0;

			while (i < len) {
				uint8_t g = b.p[off + i];

				if (g == '\\') {
					i += 2u;
					continue;
				}
				if (g == '{') {
					d++;
				} else if (g == '}') {
					d--;
					if (d == 0)
						break;
				}
				i++;
			}
			continue;
		}
		if (ch == '}')
			continue;
		if (ch == '\\') {
			uint64_t k = i + 1u;
			int alpha = 0;

			/*
			 * A control WORD is letters; a control SYMBOL is
			 * one character that is not. Both have to be
			 * stepped over and the second is the one that
			 * catches a reader out - the ignorable destination
			 * marker is written "\*", so a decoder that skips
			 * only the backslash lands on the asterisk, finds
			 * it is not a hex digit, and stops. Measured on a
			 * real document that ended the decode after zero
			 * bytes of a 2.8MB payload.
			 */
			while (k < len) {
				uint8_t d = b.p[off + k];

				if (!((d >= 'a' && d <= 'z') ||
				      (d >= 'A' && d <= 'Z')))
					break;
				alpha = 1;
				k++;
			}
			if (!alpha) {
				i = k;            /* the symbol itself */
				continue;
			}
			if (k < len && b.p[off + k] == '-')
				k++;
			while (k < len && b.p[off + k] >= '0' &&
			       b.p[off + k] <= '9')
				k++;
			if (k < len && b.p[off + k] == ' ')
				k++;
			i = k - 1u;
			continue;
		}
		if (ch >= '0' && ch <= '9')       v = ch - '0';
		else if ((ch | 0x20) >= 'a' && (ch | 0x20) <= 'f')
			v = (ch | 0x20) - 'a' + 10;
		else
			continue;                 /* skipped, as the parser does */
		if (hi < 0) {
			hi = v;
			continue;
		}
		out[n++] = (uint8_t)((hi << 4) | v);
		hi = -1;
		if (n == sizeof out) {
			if (!oc_emit(ctx, out, n))
				return produced;
			produced += n;
			n = 0;
		}
	}
	if (n && oc_emit(ctx, out, n))
		produced += n;
	return produced;
}

/*
 * ASCII85 as a coding in its own right, not only as a step of a chain.
 *
 * Through a buffer and then one emit, rather than a streaming sink like
 * DEFLATE's: the decode is ONE PASS over input that is already addressable, and
 * the output is at most four fifths of it, so the buffer is bounded by
 * something the OS reported rather than by anything the file claims. That is
 * what makes malloc safe here where it would not be for an expanding coding.
 *
 * THE SAME a85_decode THE CHAIN USES. A second copy of the alphabet, the
 * padding rule and the overflow test would be a second thing that can be wrong
 * in a way the first is not, and only one of them would be under test - the
 * same reasoning kof_src_label's note gives for sanitising in one place.
 *
 * It existed only inside the chain runner before, which meant a stream whose
 * ONLY filter was /ASCII85Decode was named correctly, produced nothing, and
 * said nothing about why. A silent nothing is the one answer this engine must
 * not give, so the refusal paths below all report.
 */
uint64_t oc_unpack_textcode(const struct kof_obj_ctx *ctx, uint32_t method,
				kof_buf b, uint64_t off, uint64_t len)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	enum kuncoat_status st;
	uint64_t room, got = 0, at;
	uint8_t *buf;

	/*
	 * RunLength goes straight to the sink and never through a buffer,
	 * because its output cannot be sized from its input - see
	 * textcode.h. Answered first so the buffer below is only ever
	 * allocated for a coding that can be bounded.
	 */
	if (method == KOF_UNP_RUNLENGTH) {
		struct expand_sink snk;

		snk.ctx = ctx;
		snk.left = expand_limit(len, 0);
		st = kuncoat_rle_decode(b.p + off, len, oc_expand_sink_fn, &snk, &got);
		oc_stream_note(sc, st, STREAM_PARTIAL, &snk);
		return got;
	}

	room = oc_scan_room(sc);
	if (len > room) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	buf = malloc((size_t)len);
	if (!buf) {
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		return 0;
	}
	scan_charge(sc, len);

	st = method == KOF_UNP_ASCII85
	   ? kuncoat_a85_decode(b.p + off, len, buf, len, &got)
	   : kuncoat_ahx_decode(b.p + off, len, buf, len, &got);
	if (st != KUNCOAT_OK) {
		/* The container said this WAS the coding, so input that is not
		 * it is the file disagreeing with itself - damage, not a gap in
		 * the engine, and the two lead different places. Whatever
		 * decoded before the disagreement is still emitted below: those
		 * bytes are real, and the same judgement is made about a
		 * damaged archive. */
		oc_scan_broken(sc, oc_broken_of_status(st));
	}
	at = oc_emit_all(ctx, buf, got);
	free(buf);
	oc_scan_release(sc, len);
	return at;
}
