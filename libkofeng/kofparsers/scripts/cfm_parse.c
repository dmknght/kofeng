/*
 * cfm_parse.c - see cfm_parse.h.
 */

#include <string.h>

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
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
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
	uint64_t i;

	for (i = at + 5u; i + 4u <= end; i++)
		if (kof_txt_tag_at(f, i, "--->", 4u))
			return i + 4u;
	return end;
}

uint64_t kof_cfm_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	uint64_t i;

	for (i = 0; i + 4u <= look; i++) {
		if (f.p[i] != '<')
			continue;
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
			for (k = end; k + 12u <= f.n; k++)
				if (kof_txt_tag_at(f, k, "</cfscript>", 11u)) {
					end = k + 11u;
					break;
				}
		} else {
			end = cfm_tag_end(f, open, f.n);
		}
		if (!kof_isl_add(info, open, end - open))
			break;
		i = end;
	}
	kof_isl_seal(info, f.n);
}
