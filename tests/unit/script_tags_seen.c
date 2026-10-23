/*
 * script_tags_seen - kof_txt_tags_seen (scantext.c): which of up to 32 markers a window holds, in one walk, against the walk it replaced - written here, marker by marker, over
 * random marker lists and random text - and the two things the second and third byte tables must not change:
 *   - the answer: the bitmask seen, `decided`, and the veto's questions (which marker, at which offset: a veto that is asked a different question than the plain walk asks is a
 *     different test), for every `look` from 0 to past the end;
 *   - the edges: a marker one byte short of the window, a marker of one or two bytes (too short to have a second or third byte to test), upper and lower case of a letter, a byte
 *     of the text that is 0, markers that share a prefix, two groups with the deciding one (grp 0) late.
 * The lists are random in length (1 to 12 markers), marker length (1 to 7) and alphabet (4 letters in both cases and one symbol, so that markers overlap often); the text is drawn from the
 * same alphabet plus noise, so most windows hold some markers and not others.
 *
 * usage: script_tags_seen [rounds]   (default 4000)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/analyzers/parsers/scripts/scantext.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t rs = 1234567u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 8;
}

static const char ALPHA[] = "aAbBcC-";

/* the veto: asked at most once per (marker, offset) by either walk; it records what it was asked and refuses the offsets divisible by 3 */
struct vlog {
	uint64_t at[4096];
	uint32_t n;
};

static struct vlog vl;
static const struct kof_txt_tags *cur_ts;
static const struct kof_txt_tag *veto_tag_hint;

static int veto(kof_buf f, uint64_t at)
{
	(void)f;
	if (vl.n < 4096u)
		vl.at[vl.n++] = at;
	return at % 3u == 0;
}

/* the reference: the first walk, as it was before the tables - every candidate by first byte compared in full */
static uint32_t ref_seen(kof_buf f, uint64_t look, const struct kof_txt_tags *ts, int *decided)
{
	uint32_t seen = 0;
	uint64_t i, cap = look < f.n ? look : f.n;

	*decided = 0;
	for (i = 0; i < cap; i++) {
		uint32_t m = ts->first[f.p[i]] & ~seen;

		while (m) {
			uint32_t t = (uint32_t)__builtin_ctz(m);

			m &= m - 1u;
			if (i + ts->tag[t].len > cap)
				continue;
			if (!kof_txt_tag_at(f, i, ts->tag[t].s, ts->tag[t].len))
				continue;
			if (((1u << t) & ts->veto_mask) && ts->veto(f, i))
				continue;
			seen |= 1u << t;
			if (ts->tag[t].grp == 0) {
				*decided = 1;
				return seen;
			}
		}
	}
	return seen;
}

static uint8_t lower(uint8_t c)
{
	return (uint8_t)(c >= 'A' && c <= 'Z' ? c + 32 : c);
}

int main(int argc, char **argv)
{
	int rounds = argc > 1 ? atoi(argv[1]) : 4000, r;
	uint64_t windows = 0, decided_n = 0, vetoed = 0;

	for (r = 0; r < rounds; r++) {
		struct kof_txt_tag tag[12];
		char text_of[12][8];
		uint32_t first[256], n = 1u + rnd() % 12u, t, k, veto_mask = 0;
		struct kof_txt_tags ts;
		uint8_t buf[200];
		uint32_t len = rnd() % 180u, look;
		kof_buf f;

		memset(first, 0, sizeof first);
		for (t = 0; t < n; t++) {
			uint32_t l = 1u + rnd() % 7u;

			for (k = 0; k < l; k++)
				text_of[t][k] = ALPHA[rnd() % (sizeof ALPHA - 1u)];
			text_of[t][l] = 0;
			/* a marker is stored the way the tables hold them: the fold of the text is what is compared */
			tag[t].s = text_of[t];
			tag[t].len = (uint8_t)l;
			tag[t].grp = (uint8_t)(rnd() % 3u);
			if (rnd() % 3u == 0)
				veto_mask |= 1u << t;
			first[lower((uint8_t)text_of[t][0])] |= 1u << t;
			first[(uint8_t)(lower((uint8_t)text_of[t][0]) >= 'a' && lower((uint8_t)text_of[t][0]) <= 'z' ? lower((uint8_t)text_of[t][0]) - 32 : lower((uint8_t)text_of[t][0]))] |= 1u << t;
		}
		ts.tag = tag;
		ts.n = n;
		ts.first = first;
		ts.veto_mask = veto_mask;
		ts.veto = veto;
		cur_ts = &ts;
		(void)cur_ts;
		(void)veto_tag_hint;
		for (k = 0; k < len; k++) {
			uint32_t d = rnd() % 10u;

			buf[k] = d == 0 ? (uint8_t)rnd() : d == 1 ? 0u : (uint8_t)ALPHA[rnd() % (sizeof ALPHA - 1u)];
		}
		f.p = buf;
		f.n = len;
		for (look = 0; look <= len + 3u; look++) {
			int da, db;
			uint32_t sa, sb;
			struct vlog va, vb;

			vl.n = 0;
			sa = ref_seen(f, look, &ts, &da);
			va = vl;
			vl.n = 0;
			sb = kof_txt_tags_seen(f, look, &ts, &db);
			vb = vl;
			windows++;
			decided_n += (uint64_t)db;
			vetoed += vb.n;
			CK(sa == sb);
			CK(da == db);
			CK(va.n == vb.n && !memcmp(va.at, vb.at, va.n * sizeof va.at[0]));
			if (sa != sb || da != db || va.n != vb.n) {
				printf("  round %d look %u n=%u len=%u: seen %x vs %x decided %d vs %d vetoes %u vs %u\n", r, look, n, len, sa, sb, da, db, va.n, vb.n);
				return 1;
			}
		}
	}
	CK(windows > 100000u);
	CK(decided_n > 1000u);
	CK(vetoed > 1000u);
	printf("script_tags_seen: %llu windows, %llu decided, %llu veto questions, %s\n", (unsigned long long)windows, (unsigned long long)decided_n,
	       (unsigned long long)vetoed, fails ? "FAILED" : "ok");
	return fails != 0;
}
