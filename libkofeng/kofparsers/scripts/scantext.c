/*
 * scantext.c - see scantext.h.
 */

#include <string.h>

#include "scantext.h"

int kof_txt_tag_at(kof_buf f, uint64_t at, const char *tag, uint32_t len)
{
	uint32_t i;

	if (at + len > f.n)
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t a = f.p[at + i], b = (uint8_t)tag[i];

		if (a >= 'A' && a <= 'Z')
			a = (uint8_t)(a + 32);
		if (b >= 'A' && b <= 'Z')
			b = (uint8_t)(b + 32);
		if (a != b)
			return 0;
	}
	return 1;
}

int kof_txt_has(kof_buf f, uint64_t look, const char *t)
{
	uint32_t len = 0;
	uint64_t i;

	while (t[len])
		len++;
	if (look < len)
		return 0;
	for (i = 0; i + len <= look; i++)
		if (kof_txt_tag_at(f, i, t, len))
			return 1;
	return 0;
}

int kof_isl_add(struct kof_script_info *info, uint64_t off, uint64_t len)
{
	if (info->n_island >= KOF_SCRIPT_MAX_ISLAND)
		return 0;
	if (!len)
		return 1;               /* nothing to record, and not full */
	info->island[info->n_island].off = (uint32_t)off;
	info->island[info->n_island].len = (uint32_t)len;
	info->n_island++;
	return 1;
}

void kof_isl_seal(struct kof_script_info *info, uint64_t size)
{
	uint16_t n = info->n_island;

	if (n != KOF_SCRIPT_MAX_ISLAND)
		return;
	if ((uint64_t)info->island[n - 1].off + info->island[n - 1].len < size)
		info->island[n - 1].len =
			(uint32_t)(size - info->island[n - 1].off);
}
