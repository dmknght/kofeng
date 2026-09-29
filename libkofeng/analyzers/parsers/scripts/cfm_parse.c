/*
 * cfm_parse.c - see cfm_parse.h.
 */

#include <string.h>

#include "../../../kofcore/kofcore.h"
#include "cfm_parse.h"
#include "scantext.h"

/* The tag names that are not statements. "<cfscript>" is handled apart. */
static int cfm_is_tag(kof_buf f, uint64_t at, uint64_t end)
{
	uint8_t c;

	if (at + 3u > end || !kof_txt_tag_at(f, at, "<cf", 3u))
		return 0;
	/* "<cf" has to be followed by a NAME. "<cf>" is not a tag and neither
	 * is the "<cf" that begins a word in prose. */
	c = f.p[at + 3u];
	return kof_is_alpha(c);
}

/*
 * THE END OF A TAG, past any quoted attribute.
 *
 * An attribute may hold a ">" - "arguments=\"/c dir > out.txt\"" is the shape a
 * shell in a page has - and a walk that stopped at the first one would cut the
 * tag in half and leave the rest of the command in the markup.
 */
static uint64_t cfm_tag_end(kof_buf f, uint64_t at, uint64_t end)
{
	uint64_t i = at;
	uint8_t q = 0;

	for (; i < end; i++) {
		uint8_t c = f.p[i];

		if (q) {
			if (c == q)
				q = 0;
			continue;
		}
		if (c == '"' || c == '\'') {
			q = c;
			continue;
		}
		if (c == '>')
			return i + 1u;
	}
	return end;
}

/* "<!--- ... --->", which is markup - see the header. Answers where it ends. */
static uint64_t cfm_comment_end(kof_buf f, uint64_t at, uint64_t end)
{
	uint64_t i = kof_txt_find(f, at + 5u, end, "--->", 4u);

	return i == KOF_TXT_NONE ? end : i + 4u;
}

/*
 * EVERY COLDFUSION TAG BEGINS WITH '<', so the bytes that are not '<' are
 * found a cache line at a time rather than one compare each.
 *
 * This walked the whole object asking `f.p[i] != '<'` per byte, which is the
 * same naive filter kof_txt_find exists to replace - and find_tag runs it over
 * every script object that is not PHP and not a server page, because the three
 * finders are asked in turn.
 *
 * `cap` clamps to the object as well as to `look`. The old loop read f.p[i]
 * bounded only by `look` and left every other read to be refused further in;
 * callers pass a `look` inside the object, so this changes nothing today and
 * stops the one raw read from being the exception.
 */
uint64_t kof_cfm_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	uint64_t i, cap = look < f.n ? look : f.n;

	if (!f.p || cap < 4u)
		return (uint64_t)-1;

	for (i = 0; i + 4u <= cap; i++) {
		if (f.p[i] != '<') {
			/* positions i .. cap - 4 remain, so cap - 3 - i >= 1 */
			const uint8_t *h = memchr(f.p + i, '<',
						  (size_t)(cap - 3u - i));

			if (!h)
				break;
			i = (uint64_t)(h - f.p);
		}
		if (kof_txt_tag_at(f, i, "<!---", 5u)) {
			i = cfm_comment_end(f, i, look) - 1u;
			continue;
		}
		if (!cfm_is_tag(f, i, look))
			continue;
		*taglen = (uint32_t)(cfm_tag_end(f, i, look) - i);
		return i;
	}
	return (uint64_t)-1;
}

void kof_cfm_islands(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	uint64_t i = from;

	while (i < f.n && info->n_island < KOF_SCRIPT_MAX_ISLAND) {
		uint64_t open, end;

		for (open = i; open + 4u <= f.n; open++) {
			if (f.p[open] != '<')
				continue;
			if (kof_txt_tag_at(f, open, "<!---", 5u)) {
				open = cfm_comment_end(f, open, f.n) - 1u;
				continue;
			}
			if (cfm_is_tag(f, open, f.n))
				break;
		}
		if (open + 4u > f.n)
			break;

		/*
		 * A SCRIPT BLOCK IS ONE ISLAND, opening tag through closing
		 * tag: what is between them is a program, and splitting it at
		 * its own statements would be carving code into code.
		 */
		if (kof_txt_tag_at(f, open, "<cfscript", 9u)) {
			uint64_t k;

			end = cfm_tag_end(f, open, f.n);
			/*
			 * ELEVEN BYTES FOR AN ELEVEN BYTE TAG.
			 *
			 * This read `k + 12u <= f.n` while "</cfscript>" is 11
			 * bytes long, so the one position where the tag ends on
			 * the object's last byte was never tried: a cfscript
			 * block closed at end of file stayed OPEN, and its body
			 * ran to f.n instead of stopping at the tag. Off by one
			 * in the only direction that loses a boundary.
			 *
			 * kof_txt_find refuses a window shorter than the tag on
			 * its own, so the length guard that used to stand here
			 * is gone with the bound it was protecting.
			 */
			k = kof_txt_find(f, end, f.n, "</cfscript>", 11u);
			if (k != KOF_TXT_NONE)
				end = k + 11u;
		} else {
			end = cfm_tag_end(f, open, f.n);
		}
		if (!kof_isl_add(info, open, end - open))
			break;
		i = end;
	}
	kof_isl_seal(info, f.n);
}
