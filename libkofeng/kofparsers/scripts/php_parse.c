/*
 * php_parse.c - see php_parse.h.
 */

#include <string.h>

#include "php_parse.h"
#include "scantext.h"

/*
 * THE TAGS, and only the ones that cannot be anything else.
 *
 * "<?php" is five bytes that do not occur in passing and "<?=" is the echo
 * shorthand. The bare "<?" short tag is NOT here: it is three quarters of
 * "<?xml", which is the opening of every XML document on the machine, and
 * telling the two apart needs a rule this has not been measured against.
 */
uint64_t kof_php_find_tag(kof_buf f, uint64_t look, uint32_t *taglen)
{
	uint64_t i;

	for (i = 0; i + 2u <= look; i++) {
		if (f.p[i] != '<')
			continue;
		if (kof_txt_tag_at(f, i, "<?php", 5u)) {
			*taglen = 5u;
			return i;
		}
		if (kof_txt_tag_at(f, i, "<?=", 3u)) {
			*taglen = 3u;
			return i;
		}
	}
	return (uint64_t)-1;
}

int kof_php_is_page(kof_buf f, uint64_t from)
{
	uint64_t i;

	for (i = from; i + 2u <= f.n; i++) {
		uint64_t j;

		if (f.p[i] != '?' || f.p[i + 1u] != '>')
			continue;
		for (j = i + 2u; j < f.n; j++)
			if (f.p[j] != '\n' && f.p[j] != '\r' &&
			    f.p[j] != ' ' && f.p[j] != '\t')
				return 1;
		return 0;
	}
	return 0;
}

/*
 * The walk. Over the WHOLE object and not just the sniff window: where a page's
 * code is is not a property of the first sixty-four kilobytes, and a shell at
 * the foot of a long template is the case that matters.
 *
 * An unterminated run takes the rest of the object, for the reason kof_isl_seal
 * gives about the cap.
 */
void kof_php_islands(kof_buf f, uint64_t from, struct kof_script_info *info)
{
	uint64_t i = from;
	int first = 1;

	while (i < f.n && info->n_island < KOF_SCRIPT_MAX_ISLAND) {
		uint64_t open, body, close;
		uint32_t o_len = 0;

		if (first) {
			/* The header took the opener; the code starts here. */
			open = body = from;
			first = 0;
		} else {
			/* Forward from where the last run ended, and not
			 * through kof_php_find_tag: that searches from the
			 * start of the object and would keep answering with a
			 * run this walk has already passed. */
			for (open = i; open + 3u <= f.n; open++) {
				if (kof_txt_tag_at(f, open, "<?php", 5u)) {
					o_len = 5u;
					break;
				}
				if (kof_txt_tag_at(f, open, "<?=", 3u)) {
					o_len = 3u;
					break;
				}
			}
			if (open + 3u > f.n)
				break;
			body = open + o_len;
		}
		for (close = body; close + 2u <= f.n; close++)
			if (f.p[close] == '?' && f.p[close + 1u] == '>')
				break;
		if (close + 2u > f.n) {
			kof_isl_add(info, open, f.n - open);
			break;
		}
		if (!kof_isl_add(info, open, close + 2u - open))
			break;
		i = close + 2u;
	}
	kof_isl_seal(info, f.n);
}

uint32_t kof_php_footer(kof_buf f, const struct kof_script_info *info)
{
	uint64_t e = f.n;

	if (info->n_island || f.n < 2u)
		return 0;
	while (e > 0 && (f.p[e - 1] == '\n' || f.p[e - 1] == '\r' ||
			 f.p[e - 1] == ' ' || f.p[e - 1] == '\t'))
		e--;
	if (e < 2u || f.p[e - 2] != '?' || f.p[e - 1] != '>')
		return 0;
	/* The whole of it has to sit after the header, or a file that is
	 * nothing but "<?php ?>" would have two regions claiming one byte. */
	if (e - 2u < info->tag_len)
		return 0;
	return (uint32_t)(f.n - (e - 2u));
}
