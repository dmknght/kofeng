/*
 * executables_esc.c - the escape pass of the decode: `\xNN` and `/xNN` runs. See kof_exe_unesc in
 * executables.h, and executables_decode.c for the rounds it runs in.
 *
 * TWO FORMS, NAMED, AND NOT A FAMILY OF THEM.
 *
 * `\xNN` is what C, Python and a shell's printf write; `/xNN` is the same shape with a slash, which
 * an IoT dropper's string table was found to carry (0afd9f52...: 18 runs in one .rodata, the first
 * two spelling "Self Rep Fucking NeTiS" and "uCkInG FoReHeAd"). `\NNN`, `&#NN;` and `0xNN,` are other
 * conventions with other delimiters and are not read here.
 *
 * WHY THE FLOOR IS EIGHT ESCAPES, AND IT IS MEASURED. Escapes of one separator, back to back, from a
 * run of any length down to two:
 *
 *                            2 escapes   3    4    8    16
 *     \xNN  6000 clean files        33   15    7    1     0   (hits; the 1 is a locale table that
 *                                                              really is escapes: X11 XLC_LOCALE)
 *     /xNN  6000 clean files         3    0    0    0     0
 *     /xNN  122 malware files     1304  304   32   32    32   (all 32 are 16 or longer)
 *
 * Under four escapes what is read is mostly a path - "/x86/x64" is two - and from four to seven nothing
 * was measured to decide on, so the floor sits where the clean files stop and the real runs begin to
 * be the only ones. A run below it stays as the author wrote it.
 *
 * WHAT MAKES A RUN, BYTE FOR BYTE - each of these is a refusal, not a repair:
 *
 *   - ONE SEPARATOR for the whole run. `\x41/x42` is two runs of one escape, and neither reaches the
 *     floor; what lies between two separators is not escapes.
 *   - EVERY ESCAPE WHOLE: the separator, a lower case `x`, two hex digits. The digits may be either
 *     case, and are within one run (the sample's first run writes `/x78/xA3/x69/x6A`). `\xZZ`, a cut
 *     `\x4` and `/x8r` (the sample's filler, which is not hex) end the run where they begin.
 *   - A BACKSLASH THAT IS ITSELF ESCAPED IS NOT A START. In `\\x41` the first backslash escapes the
 *     second and `x41` is text; the run begins only at a backslash with an even number of backslashes
 *     in front of it.
 *   - NOTHING IS READ PAST THE WINDOW the caller gave, as every pass here.
 *
 * WHAT IT DOES NOT ASK: that the bytes come out printable. The other passes need that to tell their
 * payload from a hash or a word; here the syntax is the evidence - eight whole escapes in a row are not
 * an accident - and a payload that is binary (shellcode, a table) is exactly what a hex rule is then
 * written against. A view carries it; the parent still holds the bytes as written.
 *
 * FOUND FROM THE `x`, which is rare: the search is a memchr, and what stands either side of one is
 * what decides. In place and length preserving like the others: four characters carry one byte, so the
 * write trails the read, and the vacated bytes are zeroed.
 */

#include <stdint.h>
#include <string.h>
#include <kofcore.h>
#include <uncoat.h>

#include "executables.h"
#include "executables_private.h"

/* Escapes in a row below which a run is not read. See the table above. */
#define ESC_RUN_MIN 8u

static int esc_whole(const uint8_t *p, uint64_t at, uint8_t sep)
{
	return p[at] == sep && p[at + 1u] == 'x' && kof_hex_val(p[at + 2u]) >= 0 &&
	       kof_hex_val(p[at + 3u]) >= 0;
}

/* Whether p[s] begins an escape: a separator, and for a backslash not one that is itself escaped. */
static int esc_starts(const uint8_t *p, uint64_t s)
{
	uint64_t k = 0;

	if (p[s] != '\\' && p[s] != '/')
		return 0;
	if (p[s] == '\\')
		while (k < s && p[s - 1u - k] == '\\')
			k++;
	return !(k & 1u);
}

int kof_exe_pass_esc(uint8_t *p, uint64_t n, uint64_t from, uint64_t to, struct dec_out *wrote)
{
	uint64_t pos = from;
	int changed = 0;

	if (!p || !n)
		return 0;
	if (to > n)
		to = n;
	while (pos + 4u <= to) {
		const uint8_t *z = memchr(p + pos + 1u, 'x', (size_t)(to - pos - 1u));
		uint64_t s, e, out_n;
		uint32_t count = 0;

		if (!z)
			break;
		s = (uint64_t)(z - p) - 1u;
		if (s + 4u > to || !esc_starts(p, s) || !esc_whole(p, s, p[s])) {
			pos = s + 1u;
			continue;
		}
		for (e = s; e + 4u <= to && esc_whole(p, e, p[s]); e += 4u)
			count++;
		if (count < ESC_RUN_MIN) {
			pos = e;
			continue;
		}
		if (wrote && wrote->probe) {
			changed = 1;
			break;
		}
		out_n = kof_exe_decode_run(KUNCOAT_ALGO_ESCAPE, 0, p[s], p + s, e - s);
		if (out_n) {
			memset(p + s + out_n, 0, (size_t)(e - s - out_n));
			kof_exe_dec_note_run(wrote, p, n, s, out_n, e);
			changed = 1;
		}
		/* A run that decoded to nothing is left exactly as written: zeroing it deleted the bytes and
		 * reported no change (norm_defect_engine N8). */
		pos = e;
	}
	return changed;
}

int kof_exe_unesc(uint8_t *p, uint64_t n)
{
	struct dec_out d;

	dec_out_init(&d, n, 0);
	return kof_exe_pass_esc(p, n, 0, n, &d);
}
