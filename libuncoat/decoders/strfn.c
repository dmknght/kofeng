/*
 * strfn.c - the string functions a script uses to build a name or a payload out of pieces:
 * str_replace, strtr, substr, the case maps, trim, repeat, and the cut and the join of a list of strings. They are kept here and not in each caller
 * because the answer has to be the same one wherever it is asked for - the form that rewrites a call
 * on literals and the evaluator that follows a variable to its value read these bytes the same way.
 *
 * WHAT IS PHP'S AND WHAT IS NOT. Each routine is the byte semantics of the php function it is named
 * for ([Unverified] against php itself: no php is installed here, the cases in tests/lib/uncoat were
 * written from the documented behaviour). A script language that means something else by its function
 * of the same name does not get this one by the name; the language's table says which function it is.
 */

#define _GNU_SOURCE     /* kof_memmem's POSIX branch calls the real memmem */

#include "strfn.h"

#include <string.h>

#include <kofstrlist.h>
#include <kofcore.h>   /* kof_lower_byte: ASCII letters fold, every other byte is itself */
#include <kofplatform.h>   /* kof_memmem: a search whose worst case is linear in both texts */

#include "../transform_private.h"

/* One byte, if there is room. 0 when there is not. */
static int put(uint8_t *out, uint64_t cap, uint64_t *w, uint8_t c)
{
	if (*w >= cap)
		return 0;
	out[(*w)++] = c;
	return 1;
}

/*
 * THE WORK OF A SEARCH IS BOUNDED BY THE TEXTS, not by what they are (L11 of the lexer audit). Each position of the subject was compared with the whole of the search text, so a
 * subject of n bytes and a search of m cost n * m comparisons whatever the texts - "a" x n against "aaa...b" is the worst case, about 6 s a call at 1 MiB. Now
 *   - a search that keeps case is kof_memmem's: the platform's search, linear in n + m in the worst case (glibc's two-way; kofplatform.h says what the Windows side is), asked once for each
 *     occurrence and never again for the bytes before it;
 *   - a search that folds case, and the several keys of a map, are compared a byte at a time and every byte compared is charged to one allowance of 32 times what the two texts
 *     hold and a megabyte. A subject and a search whose near misses cost more than that answer KUNCOAT_OVER_BUDGET (the status the lib already gives for "the answer
 *     does not fit": what was written is a real prefix) and never a wrong value. A real script's compare stops at the first byte, a few bytes a position, far under it.
 */
#define STRFN_WORK_FLOOR (1ull << 20)

static uint64_t work_allowance(uint64_t n, uint64_t keys)
{
	return 32u * (n + keys) + STRFN_WORK_FLOOR;
}

/* Does `b` (len bytes) equal `a`, case folded when `icase`: 1, 0, or -1 when the allowance is spent (each byte looked at is charged). */
static int same_bytes(const uint8_t *a, const uint8_t *b, uint64_t len, int icase, uint64_t *left)
{
	uint64_t k;

	for (k = 0; k < len; k++) {
		if (!*left)
			return -1;
		(*left)--;
		if (icase ? kof_lower_byte(a[k]) != kof_lower_byte(b[k]) : a[k] != b[k])
			return 0;
	}
	return 1;
}

/* The first occurrence of key[0..klen) in in[from..n): 1 and its offset in `*at`, 0 for none, -1 when the allowance of a case-folding search is spent. klen >= 1. */
static int find_from(const uint8_t *in, uint64_t n, uint64_t from, const uint8_t *key, uint64_t klen, int icase, uint64_t *left, uint64_t *at)
{
	uint64_t i;

	if (from > n || klen > n - from)
		return 0;
	if (!icase) {
		const uint8_t *p = kof_memmem(in + from, (size_t)(n - from), key, (size_t)klen);

		if (!p)
			return 0;
		*at = (uint64_t)(p - in);
		return 1;
	}
	for (i = from; i + klen <= n; i++) {
		int r = same_bytes(in + i, key, klen, 1, left);

		if (r)
			return r < 0 ? -1 : (*at = i, 1);
	}
	return 0;
}

/* in[0..len) written as far as `cap` allows: 1 when all of it went. */
static int copy_out(uint8_t *out, uint64_t cap, uint64_t *w, const uint8_t *p, uint64_t len)
{
	uint64_t room = cap - *w, k = len < room ? len : room;

	if (k)
		memcpy(out + *w, p, (size_t)k);
	*w += k;
	return k == len;
}

static kuncoat_st_t replace_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
				uint8_t *out, uint64_t cap, uint64_t *w)
{
	const uint8_t *from = s->key, *to = s->key + s->k32;
	uint64_t flen = s->k32, tlen = s->key_len - s->k32, i = 0, left = work_allowance(n, s->key_len);
	int icase = (s->flags & KUNCOAT_F_ICASE) != 0, first = (s->flags & KUNCOAT_F_FIRST) != 0, done = 0;

	while (i < n) {
		uint64_t at = n;
		int r = done ? 0 : find_from(in, n, i, from, flen, icase, &left, &at);

		if (r < 0)
			return KUNCOAT_OVER_BUDGET;
		if (!r)
			at = n;
		if (!copy_out(out, cap, w, in + i, at - i))
			return KUNCOAT_OVER_BUDGET;
		if (!r)
			break;
		if (!copy_out(out, cap, w, to, tlen))
			return KUNCOAT_OVER_BUDGET;
		i = at + flen;
		done = first;
	}
	return KUNCOAT_OK;
}

#define TR_MAX 4096u

/* tr's SET: "x-y" is the range from x to y (x above y is an error), a "-" first or last is itself. Writes the bytes it names; their number, or -1. */
static int tr_expand(const uint8_t *set, uint32_t n, uint8_t *out)
{
	uint32_t i = 0, w = 0;

	while (i < n) {
		if (i + 2u < n && set[i + 1u] == '-') {
			unsigned c = set[i];

			if (set[i] > set[i + 2u])
				return -1;
			for (; c <= set[i + 2u]; c++) {
				if (w == TR_MAX)
					return -1;
				out[w++] = (uint8_t)c;
			}
			i += 3u;
		} else {
			if (w == TR_MAX)
				return -1;
			out[w++] = set[i++];
		}
	}
	return (int)w;
}

static kuncoat_st_t translate_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
				  uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint8_t map[256], from[TR_MAX], to[TR_MAX];
	uint32_t k, pairs = s->k32;
	const uint8_t *fp = s->key, *tp = s->key + s->k32;
	uint64_t i;

	if (s->flags & KUNCOAT_F_RANGES) {
		int nf = tr_expand(s->key, s->k32, from), nt = tr_expand(s->key + s->k32, s->key_len - s->k32, to);

		if (nf <= 0 || nf != nt)
			return KUNCOAT_BAD_ARG;
		pairs = (uint32_t)nf;
		fp = from;
		tp = to;
	}
	for (k = 0; k < 256u; k++)
		map[k] = (uint8_t)k;
	for (k = 0; k < pairs; k++)             /* in order, so the later pair wins */
		map[fp[k]] = tp[k];
	for (i = 0; i < n; i++)
		if (!put(out, cap, w, map[in[i]]))
			return KUNCOAT_OVER_BUDGET;
	return KUNCOAT_OK;
}

/* php's substr, in 64 bits so that no int32 pair can wrap. */
static kuncoat_st_t slice_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			      uint8_t *out, uint64_t cap, uint64_t *w)
{
	int64_t len = (int64_t)n, from = (int32_t)s->k32, cnt;

	if (from < 0)
		from = len + from < 0 ? 0 : len + from;
	if (from > len)
		return KUNCOAT_OK;
	cnt = (s->flags & KUNCOAT_F_TOEND) ? len - from : (int32_t)s->k32b;
	if (cnt < 0)
		cnt = len - from + cnt < 0 ? 0 : len - from + cnt;
	if (cnt > len - from)
		cnt = len - from;
	if ((uint64_t)cnt > cap - *w)
		return KUNCOAT_OVER_BUDGET;
	memcpy(out + *w, in + from, (size_t)cnt);
	*w += (uint64_t)cnt;
	return KUNCOAT_OK;
}

static kuncoat_st_t case_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			     uint8_t *out, uint64_t cap, uint64_t *w)
{
	int up = (s->k32 & 1u) != 0, first = (s->k32 & 2u) != 0;
	uint64_t i;

	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (!first || !i) {
			if (up && c >= 'a' && c <= 'z')
				c = (uint8_t)(c - 'a' + 'A');
			else if (!up && c >= 'A' && c <= 'Z')
				c = (uint8_t)(c - 'A' + 'a');
		}
		if (!put(out, cap, w, c))
			return KUNCOAT_OVER_BUDGET;
	}
	return KUNCOAT_OK;
}

/* The bytes a trim takes off: the step's key when it has one (the language's own set), else php's. */
static int is_trim(const struct kuncoat_step *s, uint8_t c)
{
	if (s->key)
		return s->key_len && memchr(s->key, c, s->key_len) != NULL;
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0 || c == 0x0b;
}

static kuncoat_st_t trim_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			     uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t b = 0, e = n;

	while ((s->k32 & 1u) && b < e && is_trim(s, in[b]))
		b++;
	while ((s->k32 & 2u) && e > b && is_trim(s, in[e - 1u]))
		e--;
	if (e - b > cap - *w)
		return KUNCOAT_OVER_BUDGET;
	memcpy(out + *w, in + b, (size_t)(e - b));
	*w += e - b;
	return KUNCOAT_OK;
}

/* k32 copies of the subject. The answer is checked against the room BEFORE any byte is written: a count of four billion over a long subject is a
 * refusal, not a loop, and 64 bits hold the product of two 32-bit numbers. */
static kuncoat_st_t repeat_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			       uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t k;

	if (!s->k32)
		return KUNCOAT_OK;
	if (n > (cap - *w) / s->k32)
		return KUNCOAT_OVER_BUDGET;
	for (k = 0; k < s->k32; k++) {
		memcpy(out + *w, in, (size_t)n);
		*w += n;
	}
	return KUNCOAT_OK;
}

/* One piece of a list, if there is room. */
static kuncoat_st_t put_piece(uint8_t *out, uint64_t cap, uint64_t *w, const uint8_t *p, uint64_t n)
{
	if (kof_strlist_size((uint32_t)n) > cap - *w)
		return KUNCOAT_OVER_BUDGET;
	kof_strlist_put(out, w, p, (uint32_t)n);
	return KUNCOAT_OK;
}

/*
 * The subject cut at every separator, as a list. The empty pieces are written; where the step says DROPTRAIL the ones at the END are not - and they are never written and then
 * taken back, because the room for an answer is the room for what is KEPT: a run of empty pieces waits (`pend`) until a piece that is not empty follows, and is written then.
 */
static kuncoat_st_t split_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			      uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t i = 0, from = 0, pend = 0, left = work_allowance(n, s->key_len), at = 0;
	int icase = (s->flags & KUNCOAT_F_ICASE) != 0, drop = (s->flags & KUNCOAT_F_DROPTRAIL) != 0;

	for (;;) {
		uint64_t end;
		int hit = find_from(in, n, i, s->key, s->key_len, icase, &left, &at);
		kuncoat_st_t st;

		if (hit < 0)
			return KUNCOAT_OVER_BUDGET;
		end = hit ? at : n;
		if (drop && end == from) {
			pend++;
		} else {
			for (; pend; pend--)
				if ((st = put_piece(out, cap, w, in, 0)) != KUNCOAT_OK)
					return st;
			if ((st = put_piece(out, cap, w, in + from, end - from)) != KUNCOAT_OK)
				return st;
		}
		if (!hit)
			break;
		i = at + s->key_len;
		from = i;
	}
	return KUNCOAT_OK;
}

/* The words of a tcl list written as text: the next one at in[*at..n), by white space. 0 at the end; -1 for an element tcl would read other than as its bytes (a brace, a quote, a
 * backslash). The one brace form read is `{}` standing alone: the empty element (`string map {x {}}`, `join {a {} b}`). */
static int ws_word(const uint8_t *in, uint64_t n, uint64_t *at, const uint8_t **p, uint32_t *l)
{
	uint64_t i = *at, b;

	while (i < n && kof_is_space_byte(in[i]))
		i++;
	if (i >= n) {
		*at = n;
		return 0;
	}
	if (in[i] == '{' && i + 1u < n && in[i + 1u] == '}' && (i + 2u >= n || kof_is_space_byte(in[i + 2u]))) {
		*p = in + i;
		*l = 0;
		*at = i + 2u;
		return 1;
	}
	for (b = i; i < n && !kof_is_space_byte(in[i]); i++)
		if (in[i] == '{' || in[i] == '}' || in[i] == '"' || in[i] == '\\')
			return -1;
	*p = in + b;
	*l = (uint32_t)(i - b);
	*at = i;
	return 1;
}

static kuncoat_st_t join_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			     uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t at = 0;
	const uint8_t *p;
	uint32_t l;
	int first = 1, broken = 0, got, ws = (s->flags & KUNCOAT_F_WSLIST) != 0;

	for (;;) {
		uint64_t need;

		if (ws) {                       /* the elements of a tcl list written as text */
			got = ws_word(in, n, &at, &p, &l);
			if (got < 0)
				return KUNCOAT_CORRUPT;
		} else {
			got = kof_strlist_next(in, n, &at, &p, &l, &broken);
		}
		if (got <= 0)
			break;
		need = (uint64_t)l + (first ? 0u : s->key_len);
		if (need > cap - *w)
			return KUNCOAT_OVER_BUDGET;
		if (!first && s->key_len) {
			memcpy(out + *w, s->key, s->key_len);
			*w += s->key_len;
		}
		if (l)
			memcpy(out + *w, p, l);
		*w += l;
		first = 0;
	}
	return broken ? KUNCOAT_CORRUPT : KUNCOAT_OK;
}

static kuncoat_st_t cut_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			    uint8_t *out, uint64_t cap, uint64_t *w, int tail)
{
	uint64_t b = 0, e = n;

	if (n >= s->key_len && !memcmp(tail ? in + n - s->key_len : in, s->key, s->key_len)) {
		if (tail)
			e = n - s->key_len;
		else
			b = s->key_len;
	}
	if (e - b > cap - *w)
		return KUNCOAT_OVER_BUDGET;
	memcpy(out + *w, in + b, (size_t)(e - b));
	*w += e - b;
	return KUNCOAT_OK;
}

static kuncoat_st_t length_run(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap, uint64_t *w)
{
	char d[24];
	uint32_t k = 0, i;
	uint64_t v = n;

	(void)in;
	do {
		d[k++] = (char)('0' + v % 10u);
		v /= 10u;
	} while (v);
	for (i = 0; i < k; i++)
		if (!put(out, cap, w, (uint8_t)d[k - 1u - i]))
			return KUNCOAT_OVER_BUDGET;
	return KUNCOAT_OK;
}

#define ARGS_MAX 64u

/* The arguments of a FORMAT, from its list: their number, or -1 when there are more than ARGS_MAX or the list is broken. */
static int format_args(const struct kuncoat_step *s, const uint8_t **p, uint32_t *l)
{
	uint64_t at = 0;
	int n = 0, broken = 0;

	while (s->key && n < (int)ARGS_MAX && kof_strlist_next(s->key, s->key_len, &at, &p[n], &l[n], &broken))
		n++;
	if (broken || (s->key && at < s->key_len))
		return -1;
	return n;
}

static kuncoat_st_t format_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			       uint8_t *out, uint64_t cap, uint64_t *w)
{
	const uint8_t *ap[ARGS_MAX];
	uint32_t al[ARGS_MAX], pass, passes = 1;
	uint64_t i, specs = 0;
	int na = format_args(s, ap, al);
	int esc = (s->flags & KUNCOAT_F_ESC) != 0, reuse = (s->flags & KUNCOAT_F_REUSE) != 0;

	if (na < 0)
		return KUNCOAT_BAD_ARG;
	for (i = 0; i < n; i++) {                       /* what the format may say, and how many arguments it takes */
		if (in[i] == '%') {
			if (i + 1u >= n || (in[i + 1u] != 's' && in[i + 1u] != '%'))
				return KUNCOAT_CORRUPT;
			specs += in[i + 1u] == 's';
			i++;
		} else if (in[i] == '\\') {
			if (!esc || i + 1u >= n || (in[i + 1u] != 'n' && in[i + 1u] != 't' && in[i + 1u] != '\\'))
				return KUNCOAT_CORRUPT;
			i++;
		}
	}
	if (!reuse && specs != (uint64_t)na)
		return KUNCOAT_CORRUPT;
	if (reuse && specs && na)
		passes = (uint32_t)(((uint64_t)na + specs - 1u) / specs);
	for (pass = 0; pass < passes; pass++) {
		uint64_t arg = (uint64_t)pass * specs;

		for (i = 0; i < n; i++) {
			uint8_t c = in[i];

			if (c == '%' && in[i + 1u] == 's') {
				uint64_t k;

				if (arg < (uint64_t)na) {
					if (al[arg] > cap - *w)
						return KUNCOAT_OVER_BUDGET;
					for (k = 0; k < al[arg]; k++)
						out[(*w)++] = ap[arg][k];
				}
				arg++;
				i++;
				continue;
			}
			if (c == '%' || c == '\\') {            /* "%%", or an escape */
				uint8_t d = in[++i];

				c = c == '%' ? '%' : d == 'n' ? '\n' : d == 't' ? '\t' : '\\';
			}
			if (!put(out, cap, w, c))
				return KUNCOAT_OVER_BUDGET;
		}
	}
	return KUNCOAT_OK;
}

#define PAIRS_MAX 64u

static kuncoat_st_t map_run(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			    uint8_t *out, uint64_t cap, uint64_t *w)
{
	const uint8_t *wp[2u * PAIRS_MAX];
	uint32_t wl[2u * PAIRS_MAX], nw = 0, k;
	uint64_t at = 0, i = 0, left = work_allowance(n, s->key_len);
	const uint8_t *p;
	uint32_t l;
	int r;

	while ((r = ws_word(s->key, s->key_len, &at, &p, &l)) > 0) {
		if (nw == 2u * PAIRS_MAX)
			return KUNCOAT_BAD_ARG;
		if (!l && !(nw & 1u))           /* an empty key: tcl skips it, and a match of nothing would not move on */
			return KUNCOAT_BAD_ARG;
		wp[nw] = p;
		wl[nw++] = l;
	}
	if (r < 0 || (nw & 1u) || !nw)
		return KUNCOAT_BAD_ARG;
	while (i < n) {
		int hit = 0;

		for (k = 0; k < nw && !hit; k += 2u) {
			int same = n - i >= wl[k] ? same_bytes(in + i, wp[k], wl[k], 0, &left) : 0;

			if (same < 0)
				return KUNCOAT_OVER_BUDGET;
			if (same) {
				if (wl[k + 1u] > cap - *w)
					return KUNCOAT_OVER_BUDGET;
				memcpy(out + *w, wp[k + 1u], wl[k + 1u]);
				*w += wl[k + 1u];
				i += wl[k];
				hit = 1;
			}
		}
		if (!hit && !put(out, cap, w, in[i++]))
			return KUNCOAT_OVER_BUDGET;
	}
	return KUNCOAT_OK;
}

enum kuncoat_status kuncoat_strfn(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
				  uint8_t *out, uint64_t cap, uint64_t *w)
{
	switch (s->algo) {
	case KUNCOAT_ALGO_REPLACE:
		return replace_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_TRANSLATE:
		return translate_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_SLICE:
		return slice_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_CASE:
		return case_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_TRIM:
		return trim_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_REPEAT:
		return repeat_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_SPLIT:
		return split_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_JOIN:
		return join_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_CUTHEAD:
		return cut_run(s, in, n, out, cap, w, 0);
	case KUNCOAT_ALGO_CUTTAIL:
		return cut_run(s, in, n, out, cap, w, 1);
	case KUNCOAT_ALGO_LENGTH:
		return length_run(in, n, out, cap, w);
	case KUNCOAT_ALGO_FORMAT:
		return format_run(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_MAP:
		return map_run(s, in, n, out, cap, w);
	default:
		return KUNCOAT_UNSUPPORTED;
	}
}
