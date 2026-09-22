/*
 * executables.c - see executables.h.
 *
 * ONE PASS, AND THE ORDER INSIDE IT IS DECIDED RATHER THAN INCIDENTAL.
 *
 * At each position the wide test runs before the zero test. In practice they
 * never both fire - the zeros inside a UTF-16 run are single bytes and the zero
 * rule needs eight in a row - but "never in practice" is the sort of thing that
 * stops being true, and a reader should not have to work out which wins.
 */

#include <string.h>

#include "executables.h"

/* Printable ASCII, which is what a widened marker is made of. Control bytes are
 * refused: a run of "02 00 03 00" is a table of small integers, and reading it
 * as text is how structure gets rewritten as prose. */
static int wide_char(uint8_t lo, uint8_t hi)
{
	return hi == 0u && lo >= 0x20u && lo < 0x7fu;
}

/* How many UTF-16LE characters start at `i`, counted in CHARACTERS. */
static uint64_t wide_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + 2u * k + 1u < n && wide_char(p[i + 2u * k], p[i + 2u * k + 1u]))
		k++;
	return k;
}

/* How many zero bytes start at `i`. */
static uint64_t zero_run(const uint8_t *p, uint64_t n, uint64_t i)
{
	uint64_t k = 0;

	while (i + k < n && p[i + k] == 0u)
		k++;
	return k;
}

/*
 * Open or extend a span.
 *
 * A COPY that follows a COPY is the same stretch seen twice - the walk emits a
 * byte at a time - so it is merged rather than recorded again. Without this a
 * file with no zero runs and no wide text would produce one span per byte,
 * which is the opposite of what the map is for.
 */
static int span_put(struct kof_exe_norm_span *spans, uint32_t cap, uint32_t *n,
		    uint8_t kind, uint64_t src_off, uint64_t src_len,
		    uint64_t dst_off, uint64_t dst_len)
{
	struct kof_exe_norm_span *s;

	if (!spans)
		return 1;                       /* the caller does not want them */
	if (*n && kind == KOF_EXE_NORM_COPY) {
		s = &spans[*n - 1u];
		if (s->kind == KOF_EXE_NORM_COPY &&
		    s->src_off + s->src_len == src_off &&
		    s->dst_off + s->dst_len == dst_off) {
			s->src_len += src_len;
			s->dst_len += dst_len;
			return 1;
		}
	}
	if (*n >= cap)
		return 0;
	s = &spans[(*n)++];
	s->src_off = src_off;
	s->src_len = src_len;
	s->dst_off = dst_off;
	s->dst_len = dst_len;
	s->kind    = kind;
	return 1;
}

uint64_t kof_exe_norm(const uint8_t *in, uint64_t n, uint32_t ops,
		  uint8_t *out, uint64_t cap,
		  struct kof_exe_norm_span *spans, uint32_t span_cap,
		  uint32_t *n_spans)
{
	uint64_t i = 0, o = 0;
	uint32_t ns = 0;
	int changed = 0;

	if (n_spans)
		*n_spans = 0;
	if (!in || !out || !n || cap < n || !ops)
		return 0;

	while (i < n) {
		uint64_t k;

		if ((ops & KOF_EXE_NORM_UNWIDE) &&
		    (k = wide_run(in, n, i)) >= KOF_EXE_NORM_WIDE_MIN) {
			uint64_t j;

			for (j = 0; j < k; j++)
				out[o + j] = in[i + 2u * j];
			if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_UNWIDENED,
				      i, 2u * k, o, k))
				return 0;
			i += 2u * k;
			o += k;
			changed = 1;
			continue;
		}
		if ((ops & KOF_EXE_NORM_NULLRUN) &&
		    (k = zero_run(in, n, i)) >= KOF_EXE_NORM_NULL_MIN) {
			/*
			 * TWO, NOT ONE, AND NOT NONE - see the safety note in
			 * executables.h. Two zeros keep every zero-free pattern
			 * answering exactly as it did on the original.
			 */
			out[o] = 0u;
			out[o + 1u] = 0u;
			if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_NULLS,
				      i, k, o, 2u))
				return 0;
			i += k;
			o += 2u;
			changed = 1;
			continue;
		}
		out[o] = in[i];
		if (!span_put(spans, span_cap, &ns, KOF_EXE_NORM_COPY, i, 1u, o, 1u))
			return 0;
		i++;
		o++;
	}

	if (!changed)
		return 0;               /* the common case - see executables.h */
	if (n_spans)
		*n_spans = ns;
	return o;
}

int kof_exe_norm_src_of(const struct kof_exe_norm_span *spans, uint32_t n_spans,
		    uint64_t dst, uint64_t *src)
{
	uint32_t lo = 0, hi = n_spans;

	if (!spans || !n_spans || !src)
		return 0;
	/* The spans cover the output with no holes and in order, so this is an
	 * ordinary binary search on dst_off. */
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;
		const struct kof_exe_norm_span *s = &spans[mid];

		if (dst < s->dst_off) {
			hi = mid;
		} else if (dst >= s->dst_off + s->dst_len) {
			lo = mid + 1u;
		} else {
			uint64_t k = dst - s->dst_off;

			switch (s->kind) {
			case KOF_EXE_NORM_UNWIDENED:
				*src = s->src_off + 2u * k;
				break;
			case KOF_EXE_NORM_NULLS:
				/* Every byte of the run is zero, so the head of
				 * it is as true an answer as any byte inside. */
				*src = s->src_off;
				break;
			default:
				*src = s->src_off + k;
				break;
			}
			return 1;
		}
	}
	return 0;
}
