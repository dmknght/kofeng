#define _GNU_SOURCE
/*
 * normalizer_transform - the byte transform of executables.c: narrowing, zero
 * collapse, the keep and drop maps, the boundary table and the span map.
 *
 * Every function here is asked the same two questions: does it do what the
 * header says on the inputs the header names (exactly seven, eight and nine
 * zeros; a wide run of seven and eight characters; a run that ends on the last
 * byte of the buffer, or starts on the first), and does it do the same as the
 * reference of normalizer_ref.h on thousands of generated objects - which has
 * no word-wide zero count, no memchr stretch and no cached bound, so a place
 * where an optimisation parts company with the contract shows as a difference.
 *
 *   kof_exe_unwide        layout (packed left, zero fill), the floor, the
 *                         alphabet (all 65536 byte pairs), alignment, idempotence
 *   kof_exe_norm          the floor at 7/8/9 zeros at every alignment of the
 *                         word the product counts by, ends of the buffer,
 *                         the ops separately, caps, the span map
 *   kof_exe_norm_masked   keep and drop maps (run does not straddle a kept byte,
 *                         drop beats keep, an emptied view is not "unchanged"),
 *                         the mark carry, `fired`
 *   kof_exe_norm_map      equals the mark carry of the same transform, and what
 *                         an offset inside a collapsed run answers
 *   kof_exe_norm_src_of   every output byte names the parent byte it came from
 *   identity              an object with nothing to normalise comes back as
 *                         "no view" and every pass leaves its bytes alone
 */

#include "normalizer_ref.h"

#define NMAX 12288u

static uint8_t in[NMAX], out[NMAX], ref_out[NMAX], tmp[NMAX];
static uint64_t mk[256], mk_got[256], mk_ref[256];
static uint8_t keepmap[NMAX / 8u + 16u], dropmap[NMAX / 8u + 16u];
static struct kof_exe_norm_span spans[NMAX];

/* ---- kof_exe_unwide -------------------------------------------------------------- */

/* The reference of the pass, from its header: a run of >= 8 printable-and-zero
 * pairs is packed left and the vacated half is zero. */
static int ref_unwide(const uint8_t *p, uint64_t n, uint8_t *o)
{
	uint64_t i = 0;
	int changed = 0;

	memcpy(o, p, n);
	while (i + 1u < n) {
		uint64_t k = nr_wide_run(p, n, i), j;

		if (k < 8u) {
			i++;
			continue;
		}
		for (j = 0; j < k; j++)
			o[i + j] = p[i + 2u * j];
		memset(o + i + k, 0, k);
		i += 2u * k;
		changed = 1;
	}
	return changed;
}

static size_t wide_of(uint8_t *b, const char *s, unsigned be)
{
	size_t i, o = 0;

	for (i = 0; s[i]; i++) {
		if (be) {
			b[o++] = 0;
			b[o++] = (uint8_t)s[i];
		} else {
			b[o++] = (uint8_t)s[i];
			b[o++] = 0;
		}
	}
	return o;
}

static void unwide_layout(void)
{
	unsigned chars, pre;

	for (chars = 1; chars <= 12; chars++) {
		for (pre = 0; pre < 4; pre++) {
			char s[16];
			size_t n = 0, w, i;
			int r;

			memset(s, 0, sizeof s);
			for (i = 0; i < chars; i++)
				s[i] = (char)('A' + i);
			memset(in, 0xc3, pre);                  /* non-zero bytes before */
			w = wide_of(in + pre, s, 0);
			n = pre + w;
			memset(in + n, 0xc3, 3);                /* and after */
			n += 3;
			memset(out, 0x77, sizeof out);
			r = kof_exe_unwide(in, n, out);
			NCKF((r != 0) == (chars >= 8u), "%u chars at +%u: returned %d", chars, pre, r);
			if (chars >= 8u) {
				/* packed to the left, the vacated half zero, nothing else moved */
				NCKF(!memcmp(out + pre, s, chars), "%u chars: text", chars);
				for (i = 0; i < chars; i++)
					NCK(out[pre + chars + i] == 0);
				NCK(!memcmp(out, in, pre));
				NCK(!memcmp(out + pre + w, in + pre + w, 3));
			} else {
				NCKF(!memcmp(out, in, n), "%u chars: copy", chars);
			}
			NCK(out[n] == 0x77);                   /* writes exactly n bytes */
		}
	}
}

/* UTF-16BE (zero first): the pass reads every offset, so a big-endian string
 * is a little-endian one that starts a byte later and loses its last character
 * - eight characters of it are seven pairs and are not narrowed, nine are. A byte
 * that is not printable ends any run. */
static void unwide_alphabet(void)
{
	unsigned lo, hi;
	size_t n;

	for (hi = 0; hi < 256u; hi++) {
		for (lo = 0; lo < 256u; lo++) {
			uint8_t *p = in;
			int want_run = nr_wide_char((uint8_t)lo, (uint8_t)hi);
			unsigned k;

			/* nine characters, the fifth the pair under test */
			for (k = 0; k < 9u; k++) {
				p[2u * k] = (uint8_t)('a' + k);
				p[2u * k + 1u] = 0;
			}
			p[8] = (uint8_t)lo;
			p[9] = (uint8_t)hi;
			n = 18;
			NCKF((kof_exe_unwide(p, n, out) != 0) == (want_run != 0),
			     "pair lo=%02x hi=%02x", lo, hi);
		}
	}
	/* big-endian text, followed by a byte that is not zero */
	n = wide_of(in, "ABCDEFGH", 1);
	in[n++] = 0xc3;
	NCK(kof_exe_unwide(in, n, out) == 0);
	n = wide_of(in, "ABCDEFGHI", 1);
	in[n++] = 0xc3;
	NCK(kof_exe_unwide(in, n, out) == 1);
	NCK(!memcmp(out + 1, "ABCDEFGH", 8));         /* the last one is the pair that is lost */
	/* a little-endian string after one extra byte is the same bytes shifted */
	n = wide_of(in + 1, "ABCDEFGHIJKL", 0);
	in[0] = 0xc3;
	NCK(kof_exe_unwide(in, n + 1u, out) == 1 && !memcmp(out + 1, "ABCDEFGHIJKL", 12));
	/* a zero between characters (two zeros in a row) ends the run */
	{
		static const char *const broken[] = { "ABCDEFG", "HIJKLMN" };
		size_t o = wide_of(in, broken[0], 0);

		in[o++] = 0;
		in[o++] = 0;
		o += wide_of(in + o, broken[1], 0);
		NCK(kof_exe_unwide(in, o, out) == 0);
	}
}

static void unwide_differential(void)
{
	struct nrng r;
	unsigned seed, changed = 0;

	for (seed = 1; seed <= 3000u; seed++) {
		size_t n;
		int a, b;

		nr_seed(&r, 0x100u + seed);
		n = nr_mix(&r, in, 1000u + nr_below(&r, 3000u));
		a = kof_exe_unwide(in, n, out);
		b = ref_unwide(in, n, ref_out);
		NCKF(a == b && !memcmp(out, ref_out, n), "seed %u", seed);
		changed += (unsigned)(a != 0);
		/* idempotent: the narrowed buffer has no run left to narrow */
		if (a) {
			memcpy(tmp, out, n);
			NCKF(kof_exe_unwide(tmp, n, out) == 0 && !memcmp(out, tmp, n),
			     "seed %u: second pass", seed);
		}
	}
	NCKF(changed > 1500u, "generator reach: %u narrowed", changed);
}

static void unwide_arguments(void)
{
	memset(out, 0x5a, 32);
	NCK(kof_exe_unwide(NULL, 16, out) == 0);
	NCK(kof_exe_unwide(in, 16, NULL) == 0);
	NCK(kof_exe_unwide(in, 0, out) == 0);
	NCK(out[0] == 0x5a);                     /* nothing was written */
	NCK(kof_exe_unwide(in, 1, out) == 0);
}

/* ---- kof_exe_norm: the floors ---------------------------------------------------------- */

static void shape(unsigned pre, unsigned zeros, unsigned post, size_t *n)
{
	size_t i;

	for (i = 0; i < pre; i++)
		in[i] = (uint8_t)(1u + (i * 7u) % 250u);
	memset(in + pre, 0, zeros);
	for (i = 0; i < post; i++)
		in[pre + zeros + i] = (uint8_t)(3u + (i * 11u) % 240u);
	*n = (size_t)pre + zeros + post;
}

/* exactly 7, 8, 9 zeros, at every alignment of the 8-byte word the product
 * counts by, with the run ending short of, on and past the buffer end. */
static void zero_floor_everywhere(void)
{
	unsigned pre, zeros, post;

	for (pre = 0; pre <= 24; pre++) {
		for (zeros = 0; zeros <= 40; zeros++) {
			for (post = 0; post <= 9; post++) {
				size_t n;
				uint64_t got, len;
				uint32_t ns = 99;
				int collapse = zeros >= KOF_EXE_NORM_NULL_MIN;

				shape(pre, zeros, post, &n);
				if (!n)
					continue;
				got = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN, out, n, spans, NMAX, &ns);
				len = n - (collapse ? zeros - 2u : 0u);
				NCKF(got == (collapse ? len : 0u),
				     "pre %u zeros %u post %u: got %llu want %llu", pre, zeros, post,
				     (unsigned long long)got, (unsigned long long)(collapse ? len : 0u));
				if (!collapse) {
					NCK(ns == 0);
					continue;
				}
				/* the bytes: both sides intact, exactly two zeros between */
				NCK(!memcmp(out, in, pre));
				NCK(out[pre] == 0 && out[pre + 1u] == 0);
				NCK(!memcmp(out + pre + 2u, in + pre + zeros, post));
				/* a run of 8 or 9 zeros leaves two; the count is the floor */
				NCK(got < n);
			}
		}
	}
}

static void norm_ops_and_caps(void)
{
	size_t n;
	uint32_t ns = 0;

	/* wide text AND a zero run: each op alone does only its own half */
	n = wide_of(in, "ABCDEFGHIJKL", 0);
	memset(in + n, 0, 20);
	n += 20;
	memset(in + n, 0x41, 5);
	n += 5;
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, out, n, spans, NMAX, &ns) == n - 12u);
	NCK(!memcmp(out, "ABCDEFGHIJKL", 12));
	NCK(!memcmp(out + 12, in + 24, 25));              /* the zeros stay: no collapse asked */
	/* the last character's zero high half joins the twenty zeros after it: 21 */
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN, out, n, spans, NMAX, &ns) == n - 19u);
	NCK(!memcmp(out, in, 23));                       /* the wide text is left wide */
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE | KOF_EXE_NORM_NULLRUN, out, n, spans,
			 NMAX, &ns) == n - 12u - 18u);
	NCK(kof_exe_norm(in, n, 0, out, n, spans, NMAX, &ns) == 0);
	NCK(ns == 0);
	/* the order inside the pass: the wide test runs before the zero test, so a
	 * wide run followed by zeros narrows and then collapses the rest */
	memset(in + 24, 0, 8);
	NCK(kof_exe_norm(in, 32, KOF_EXE_NORM_UNWIDE | KOF_EXE_NORM_NULLRUN, out, 32, spans,
			 NMAX, &ns) == 12u + 2u);

	/* a span that does not fit stops the pass, whichever kind of span it was */
	{
		uint8_t z[40], w[40];

		memset(z, 0, 12);
		memcpy(z + 12, "abcdefghijkl", 12);
		NCK(kof_exe_norm(z, 24, KOF_EXE_NORM_NULLRUN, out, 24, spans, 0, &ns) == 0 && ns == 0);
		NCK(kof_exe_norm(z, 24, KOF_EXE_NORM_NULLRUN, out, 24, spans, 1, &ns) == 0);
		NCK(kof_exe_norm(z, 24, KOF_EXE_NORM_NULLRUN, out, 24, spans, 2, &ns) == 14u && ns == 2u);
		wide_of(w, "ABCDEFGHIJ", 0);
		NCK(kof_exe_norm(w, 20, KOF_EXE_NORM_UNWIDE, out, 20, spans, 0, &ns) == 0 && ns == 0);
		NCK(kof_exe_norm(w, 20, KOF_EXE_NORM_UNWIDE, out, 20, spans, 1, &ns) == 10u && ns == 1u);
		memcpy(w, "ab", 2);
		w[2] = 0;
		NCK(kof_exe_norm(w, 3, KOF_EXE_NORM_UNWIDE | KOF_EXE_NORM_NULLRUN, out, 3, spans, 0, &ns) == 0);
	}
	/* caps: the output must fit, the spans must fit, and either failing is 0 */
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, out, n - 1u, spans, NMAX, &ns) == 0);
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, out, n, spans, 0, &ns) == 0 && ns == 0);
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, out, n, spans, 1, &ns) == 0 && ns == 0);
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, out, n, NULL, 0, NULL) == n - 12u);
	NCK(kof_exe_norm(NULL, n, KOF_EXE_NORM_UNWIDE, out, n, NULL, 0, NULL) == 0);
	NCK(kof_exe_norm(in, n, KOF_EXE_NORM_UNWIDE, NULL, n, NULL, 0, NULL) == 0);
	NCK(kof_exe_norm(in, 0, KOF_EXE_NORM_UNWIDE, out, 0, NULL, 0, &ns) == 0 && ns == 0);
}

/* ---- the span map ----------------------------------------------------------------------- */

static void span_map_holds(const uint8_t *src, size_t n, uint32_t ops, const char *what)
{
	uint32_t ns = 0, i;
	uint64_t len = kof_exe_norm(src, n, ops, out, n, spans, NMAX, &ns), d;

	if (!len) {
		NCK(ns == 0);
		return;
	}
	NCKF(ns > 0, "%s: no spans for a view", what);
	/* the spans cover the output exactly, adjacent and in order, and cover the
	 * input exactly too: nothing is removed without a span saying so */
	NCK(spans[0].dst_off == 0 && spans[0].src_off == 0);
	for (i = 0; i < ns; i++) {
		const struct kof_exe_norm_span *s = &spans[i];

		if (i) {
			NCKF(s->dst_off == spans[i - 1u].dst_off + spans[i - 1u].dst_len &&
			     s->src_off == spans[i - 1u].src_off + spans[i - 1u].src_len,
			     "%s: span %u not adjacent", what, i);
		}
		switch (s->kind) {
		case KOF_EXE_NORM_COPY:
			NCK(s->src_len == s->dst_len);
			break;
		case KOF_EXE_NORM_UNWIDENED:
			NCK(s->src_len == 2u * s->dst_len && s->dst_len >= KOF_EXE_NORM_WIDE_MIN);
			break;
		case KOF_EXE_NORM_NULLS:
			NCK(s->dst_len == 2u && s->src_len >= KOF_EXE_NORM_NULL_MIN);
			break;
		default:
			NCKF(0, "%s: kind %u", what, s->kind);
		}
		NCK(s->dst_len > 0);
		/* a COPY span never abuts another COPY span: they are merged */
		if (i && s->kind == KOF_EXE_NORM_COPY)
			NCK(spans[i - 1u].kind != KOF_EXE_NORM_COPY);
	}
	NCK(spans[ns - 1u].dst_off + spans[ns - 1u].dst_len == len);
	NCK(spans[ns - 1u].src_off + spans[ns - 1u].src_len == n);
	/* every output byte names the parent byte it came from */
	for (d = 0; d < len; d++) {
		uint64_t s0 = ~0ull;
		int ok = kof_exe_norm_src_of(spans, ns, d, &s0);

		NCKF(ok && s0 < n, "%s: out %llu has no source", what, (unsigned long long)d);
		if (!ok || s0 >= n)
			continue;
		NCKF(out[d] == src[s0], "%s: out[%llu] is not parent[%llu]", what,
		     (unsigned long long)d, (unsigned long long)s0);
	}
	{
		uint64_t s1 = 77;

		NCK(!kof_exe_norm_src_of(spans, ns, len, &s1) && s1 == 77u);
		NCK(!kof_exe_norm_src_of(spans, ns, ~0ull, &s1));
	}
}

static void span_map_everywhere(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 600u; seed++) {
		size_t n;

		nr_seed(&r, 0x500u + seed);
		n = nr_mix(&r, tmp, 600u + nr_below(&r, 1500u));
		span_map_holds(tmp, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE, "both");
		span_map_holds(tmp, n, KOF_EXE_NORM_NULLRUN, "nulls");
		span_map_holds(tmp, n, KOF_EXE_NORM_UNWIDE, "wide");
	}
}

/* offsets that do not fit in 32 bits, and ones that end at the top of the 64:
 * the lookup is plain arithmetic and must stay so. */
static void src_of_far_offsets(void)
{
	struct kof_exe_norm_span s[3];
	uint64_t src = 0;
	const uint64_t big = 1ull << 32;

	memset(s, 0, sizeof s);
	s[0].kind = KOF_EXE_NORM_COPY;
	s[0].src_off = 0; s[0].src_len = big + 10u; s[0].dst_off = 0; s[0].dst_len = big + 10u;
	s[1].kind = KOF_EXE_NORM_UNWIDENED;
	s[1].src_off = big + 10u; s[1].src_len = 2u * (big + 100u);
	s[1].dst_off = big + 10u; s[1].dst_len = big + 100u;
	s[2].kind = KOF_EXE_NORM_NULLS;
	s[2].src_off = 3u * big + 210u; s[2].src_len = 1ull << 40;
	s[2].dst_off = 2u * big + 110u; s[2].dst_len = 2u;
	NCK(kof_exe_norm_src_of(s, 3, big + 3u, &src) && src == big + 3u);
	NCK(kof_exe_norm_src_of(s, 3, big + 10u + big + 50u, &src) &&
	    src == big + 10u + 2u * (big + 50u));
	NCK(kof_exe_norm_src_of(s, 3, 2u * big + 111u, &src) && src == 3u * big + 210u);
	NCK(!kof_exe_norm_src_of(s, 3, 2u * big + 112u, &src));
	/* the largest span a 64-bit offset space holds without wrapping */
	s[0].kind = KOF_EXE_NORM_COPY;
	s[0].src_off = ~0ull - 100u; s[0].src_len = 100u;
	s[0].dst_off = ~0ull - 107u; s[0].dst_len = 100u;
	NCK(kof_exe_norm_src_of(s, 1, ~0ull - 107u + 99u, &src) && src == ~0ull - 100u + 99u);
	NCK(!kof_exe_norm_src_of(s, 1, ~0ull - 7u, &src));
	NCK(!kof_exe_norm_src_of(NULL, 1, 0, &src));
	NCK(!kof_exe_norm_src_of(s, 0, 0, &src));
	NCK(!kof_exe_norm_src_of(s, 1, 0, NULL));
}

/* ---- the masked transform, against the reference ------------------------------------------ */

static void masked(const uint8_t *src, size_t n, const uint8_t *keep, const uint8_t *drop,
		   uint32_t ops, const uint64_t *marks, uint32_t nm, uint64_t *got_len,
		   uint32_t *got_fired)
{
	const struct kof_exe_norm_req rq = { src, n, keep, drop, ops, marks, nm };
	struct kof_exe_norm_res rs = { out, n, mk_got, 0 };

	*got_len = kof_exe_norm_masked(&rq, &rs);
	*got_fired = rs.fired;
}

static void intervals(struct nrng *r, uint8_t *map, size_t n, unsigned count, unsigned maxlen)
{
	unsigned i;

	memset(map, 0, n / 8u + 16u);
	for (i = 0; i < count; i++) {
		uint64_t a = nr_below(r, (uint32_t)n), l = 1u + nr_below(r, maxlen);

		nr_bit_set(map, a, a + l < n ? a + l : n);
	}
}

static void masked_equals_reference(unsigned seeds, unsigned base, int with_marks)
{
	struct nrng r;
	unsigned seed, rewrote = 0, cut = 0, kept_runs = 0;

	for (seed = 1; seed <= seeds; seed++) {
		size_t n;
		uint64_t gl;
		uint32_t gf, nm = 0, i;
		const uint8_t *keep = NULL, *drop = NULL;
		uint32_t ops;
		struct nr_req rq;
		struct nr_out ro;

		nr_seed(&r, base + seed);
		n = nr_mix(&r, in, 400u + nr_below(&r, 3000u));
		if (nr_below(&r, 4u) == 0u) {           /* sometimes a very zero object */
			size_t k;

			for (k = 0; k < n; k++)
				if (nr_below(&r, 3u))
					in[k] = 0;
		}
		if (nr_below(&r, 3u)) {
			intervals(&r, keepmap, n, 1u + nr_below(&r, 12u), 400u);
			keep = keepmap;
			if (nr_below(&r, 5u) == 0u)     /* bits past the end, like a stale map */
				keepmap[n / 8u + 1u] = 0xff;
		}
		if (nr_below(&r, 3u) == 0u) {
			intervals(&r, dropmap, n, 1u + nr_below(&r, 6u), 300u);
			drop = dropmap;
		}
		ops = 1u + nr_below(&r, 3u);                      /* NULLRUN, UNWIDE or both */
		if (with_marks) {
			nm = nr_below(&r, 40u);
			for (i = 0; i < nm; i++)
				mk[i] = nr_below(&r, (uint32_t)n + 3u);
			for (i = 0; i < nm; i++)                  /* sorted, duplicates allowed */
				if (i && mk[i] < mk[i - 1u])
					mk[i] = mk[i - 1u];
		}
		masked(in, n, keep, drop, ops, mk, nm, &gl, &gf);
		rq.in = in; rq.n = n; rq.keep = keep; rq.drop = drop; rq.ops = ops;
		rq.mark = mk; rq.n_mark = nm;
		ro.out = ref_out; ro.mark_out = mk_ref;
		(void)nr_norm(&rq, &ro);
		free(ro.span);
		NCKF(gl == ro.len, "seed %u: length %llu vs %llu", seed, (unsigned long long)gl,
		     (unsigned long long)ro.len);
		NCKF(gf == ro.fired, "seed %u: fired %x vs %x", seed, gf, ro.fired);
		if (gl && gl == ro.len)
			NCKF(!memcmp(out, ref_out, gl), "seed %u: bytes", seed);
		if (with_marks)
			NCKF(!memcmp(mk_got, mk_ref, nm * sizeof mk[0]), "seed %u: marks", seed);
		rewrote += gl != 0;
		cut += (gf & KOF_EXE_NORM_CUTLIB) != 0;
		kept_runs += keep && gl;
	}
	NCKF(rewrote > seeds / 3u && cut > seeds / 20u && kept_runs > seeds / 5u,
	     "generator reach: %u rewrote, %u cut, %u kept+rewrote", rewrote, cut, kept_runs);
}

static void masked_semantics(void)
{
	uint64_t gl;
	uint32_t gf;

	/* a zero run that begins free and runs into a kept byte stops there: the
	 * kept zeros are copied, the free ones before them collapse */
	memset(in, 0x41, 64);
	memset(in + 10, 0, 40);                          /* zeros 10..49 */
	memset(keepmap, 0, sizeof keepmap);
	nr_bit_set(keepmap, 30, 64);                    /* 30..63 kept: 20 free zeros, 20 kept */
	masked(in, 64, keepmap, NULL, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 64u - 18u && gf == KOF_EXE_NORM_NULLRUN);
	{
		unsigned z;

		for (z = 10; z < 32; z++)               /* two collapsed, then the 20 kept zeros */
			NCK(out[z] == 0);
		NCK(out[32] == 0x41 && !memcmp(out, in, 10));
	}
	/* with fewer than eight free zeros nothing collapses, kept ones do not count */
	nr_bit_set(keepmap, 0, 64);
	masked(in, 64, keepmap, NULL, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 0 && gf == 0);
	memset(keepmap, 0, sizeof keepmap);
	nr_bit_set(keepmap, 17, 64);                    /* 7 free zeros */
	masked(in, 64, keepmap, NULL, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 0 && gf == 0);

	/* DROP beats KEEP where they overlap */
	memset(in, 0x41, 32);
	memset(keepmap, 0, sizeof keepmap);
	memset(dropmap, 0, sizeof dropmap);
	nr_bit_set(keepmap, 0, 32);
	nr_bit_set(dropmap, 8, 16);
	masked(in, 32, keepmap, dropmap, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 24u && gf == KOF_EXE_NORM_CUTLIB);
	NCK(!memcmp(out, in, 8) && !memcmp(out + 8, in + 16, 16));

	/* a view emptied by the cut is length 0 with CUTLIB fired: not "unchanged" */
	memset(dropmap, 0xff, sizeof dropmap);
	masked(in, 32, NULL, dropmap, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 0 && gf == KOF_EXE_NORM_CUTLIB);
	/* and a copy is length 0 with nothing fired */
	masked(in, 32, NULL, NULL, KOF_EXE_NORM_NULLRUN, NULL, 0, &gl, &gf);
	NCK(gl == 0 && gf == 0);

	/* `fired` is set on every call, including the ones that refuse */
	{
		const struct kof_exe_norm_req rq = { NULL, 10, NULL, NULL, 3u, NULL, 0 };
		struct kof_exe_norm_res rs = { out, 10, NULL, 0xffffu };

		NCK(kof_exe_norm_masked(&rq, &rs) == 0 && rs.fired == 0);
	}
	{
		const struct kof_exe_norm_req rq = { in, 10, NULL, NULL, 3u, NULL, 0 };
		struct kof_exe_norm_res rs = { out, 9, NULL, 0xffffu };

		NCK(kof_exe_norm_masked(&rq, &rs) == 0 && rs.fired == 0);       /* cap < n */
		rs.cap = 10;
		rs.out = NULL;
		rs.fired = 7;
		NCK(kof_exe_norm_masked(&rq, &rs) == 0 && rs.fired == 0);
	}
	{
		const struct kof_exe_norm_req rq = { in, 0, NULL, NULL, 3u, NULL, 0 };
		struct kof_exe_norm_res rs = { out, 0, NULL, 5u };

		NCK(kof_exe_norm_masked(&rq, &rs) == 0 && rs.fired == 0);
	}
}

/* marks: every kind of position, carried through a transform that moves bytes. */
static void marks_are_carried(void)
{
	uint64_t gl;
	uint32_t gf;
	static const uint64_t asks[] = { 0, 1, 9, 10, 11, 29, 30, 31, 60, 61, 62, 63, 64, 65, 1000 };
	uint32_t i;
	size_t n;

	/* zeros 10..29 collapse to two: a mark AT the run's start answers the start
	 * of what it became, a mark inside answers the position just past it */
	memset(in, 0x41, 64);
	memset(in + 10, 0, 20);
	n = 64;
	masked(in, n, NULL, NULL, KOF_EXE_NORM_NULLRUN, asks, sizeof asks / sizeof asks[0], &gl,
	       &gf);
	NCK(gl == 46u);
	{
		/* position by position: before the run identity; at 10 -> 10; inside
		 * 11..29 -> 12 (just past what the run became); at 30 -> 12; then
		 * everything after is 18 earlier; past the end is the view length */
		uint64_t w[15] = { 0, 1, 9, 10, 12, 12, 12, 13, 42, 43, 44, 45, 46, 46, 46 };

		for (i = 0; i < 15u; i++)
			NCKF(mk_got[i] == w[i], "mark %llu -> %llu, want %llu",
			     (unsigned long long)asks[i], (unsigned long long)mk_got[i],
			     (unsigned long long)w[i]);
	}
	/* kof_exe_norm_map answers the same for the unmasked transform */
	{
		uint64_t dst[15];

		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN, asks, dst, 15);
		NCK(!memcmp(dst, mk_got, sizeof dst));
	}
	/* no ops, no input and no places */
	{
		uint64_t d2[3] = { 7, 7, 7 };
		static const uint64_t s2[3] = { 1, 5, 9 };
		static const uint64_t past[2] = { 64, 1000 };
		uint64_t d3[2] = { 7, 7 };

		kof_exe_norm_map(in, n, 0, s2, d2, 3);
		NCK(d2[0] == 1 && d2[1] == 5 && d2[2] == 9);
		d2[0] = d2[1] = d2[2] = 7;
		/* no input: the view is empty, so every place is at the end of it */
		kof_exe_norm_map(in, 0, KOF_EXE_NORM_NULLRUN, s2, d2, 3);
		NCK(d2[0] == 0 && d2[1] == 0 && d2[2] == 0);
		/* a place at or past the end maps to the end of the view, whether or not an op ran */
		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN, past, d3, 2);
		NCK(d3[0] == 46u && d3[1] == 46u);
		d3[0] = d3[1] = 7;
		kof_exe_norm_map(in, n, 0, past, d3, 2);
		NCK(d3[0] == 64u && d3[1] == 64u);
		d2[0] = 7;
		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN, s2, d2, 0);
		NCK(d2[0] == 7);
		kof_exe_norm_map(NULL, n, KOF_EXE_NORM_NULLRUN, s2, d2, 3);
		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN, NULL, d2, 3);
		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN, s2, NULL, 3);
	}
	/* marks only: no mark_out means the marks are ignored */
	{
		const struct kof_exe_norm_req rq = { in, n, NULL, NULL, KOF_EXE_NORM_NULLRUN, asks,
						     15u };
		struct kof_exe_norm_res rs = { out, n, NULL, 0 };

		NCK(kof_exe_norm_masked(&rq, &rs) == 46u);
	}
	{
		const struct kof_exe_norm_req rq = { in, n, NULL, NULL, KOF_EXE_NORM_NULLRUN, NULL,
						     0 };
		struct kof_exe_norm_res rs = { out, n, mk_got, 0 };

		NCK(kof_exe_norm_masked(&rq, &rs) == 46u);
	}
}

/* norm_map is the same answer as the mark carry of the transform it replays. */
static void map_equals_transform(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 2500u; seed++) {
		size_t n;
		uint32_t nm, i, ops;
		uint64_t dst[64], gl;
		uint32_t gf;

		nr_seed(&r, 0x2000u + seed);
		n = nr_mix(&r, in, 300u + nr_below(&r, 2500u));
		ops = 1u + nr_below(&r, 3u);
		nm = nr_below(&r, 60u);
		for (i = 0; i < nm; i++)
			mk[i] = nr_below(&r, (uint32_t)n + 2u);
		for (i = 1; i < nm; i++)
			if (mk[i] < mk[i - 1u])
				mk[i] = mk[i - 1u];
		kof_exe_norm_map(in, n, ops, mk, dst, nm);
		masked(in, n, NULL, NULL, ops, mk, nm, &gl, &gf);
		NCKF(!nm || !memcmp(dst, mk_got, nm * sizeof dst[0]), "seed %u: map vs masked", seed);
		{
			struct nr_req rq = { in, n, NULL, NULL, ops, mk, nm };
			struct nr_out ro = { ref_out, mk_ref, 0, 0, NULL, 0 };

			(void)nr_norm(&rq, &ro);
			free(ro.span);
			NCKF(!nm || !memcmp(dst, mk_ref, nm * sizeof dst[0]), "seed %u: map vs reference",
			     seed);
		}
	}
}

/* kof_exe_norm and the masked form with no maps are one transform. */
static void norm_equals_masked_and_reference(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 2500u; seed++) {
		size_t n;
		uint32_t ops, ns = 0, gf;
		uint64_t a, b, gl;
		struct nr_req rq;
		struct nr_out ro;

		nr_seed(&r, 0x3000u + seed);
		n = nr_mix(&r, in, 300u + nr_below(&r, 3000u));
		ops = 1u + nr_below(&r, 3u);
		a = kof_exe_norm(in, n, ops, out, n, spans, NMAX, &ns);
		rq.in = in; rq.n = n; rq.keep = rq.drop = NULL; rq.ops = ops;
		rq.mark = NULL; rq.n_mark = 0;
		ro.out = ref_out; ro.mark_out = NULL;
		b = nr_norm(&rq, &ro);
		NCKF(a == b, "seed %u: %llu vs %llu", seed, (unsigned long long)a,
		     (unsigned long long)b);
		if (a && a == b) {
			uint32_t i;

			NCKF(!memcmp(out, ref_out, a), "seed %u: bytes", seed);
			NCKF(ns == ro.n_span, "seed %u: %u spans vs %u", seed, ns, ro.n_span);
			for (i = 0; i < ns && i < ro.n_span; i++)
				NCKF(spans[i].src_off == ro.span[i].src_off &&
				     spans[i].src_len == ro.span[i].src_len &&
				     spans[i].dst_off == ro.span[i].dst_off &&
				     spans[i].dst_len == ro.span[i].dst_len &&
				     spans[i].kind == ro.span[i].kind, "seed %u: span %u", seed, i);
		}
		masked(in, n, NULL, NULL, ops, NULL, 0, &gl, &gf);
		NCKF(gl == a, "seed %u: masked %llu vs plain %llu", seed, (unsigned long long)gl,
		     (unsigned long long)a);
		if (a && gl == a)
			NCKF(!memcmp(out, ref_out, a), "seed %u: masked bytes", seed);
		free(ro.span);
	}
}

/* a form of a form is the form: the collapse leaves no zero run of eight and the
 * narrowing leaves no wide run, so normalising the result changes nothing; and the
 * boundary table is monotone - a later place never lands earlier. */
static void idempotent_and_monotone(void)
{
	struct nrng r;
	unsigned seed, twice_changed = 0, made = 0;

	for (seed = 1; seed <= 2500u; seed++) {
		size_t n;
		uint64_t a, b;
		uint32_t nm = 40, i;

		nr_seed(&r, 0x5000u + seed);
		n = nr_mix(&r, in, 300u + nr_below(&r, 3000u));
		a = kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE, out, n, NULL, 0, NULL);
		if (!a)
			continue;
		made++;
		memcpy(tmp, out, a);
		b = kof_exe_norm(tmp, a, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE, out, a, NULL, 0, NULL);
		twice_changed += b != 0;
		if (b)
			NCKF(0, "seed %u: a second normalisation shortened %llu to %llu", seed,
			     (unsigned long long)a, (unsigned long long)b);
		for (i = 0; i < nm; i++)
			mk[i] = (n + 3u) * i / nm;
		kof_exe_norm_map(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE, mk, mk_got, nm);
		for (i = 1; i < nm; i++)
			NCKF(mk_got[i] >= mk_got[i - 1u], "seed %u: place %u lands before place %u", seed, i, i - 1u);
		NCKF(mk_got[nm - 1u] <= a, "seed %u: a place beyond the view", seed);
	}
	NCKF(made > 2000u, "generator reach: %u made a view", made);
	(void)twice_changed;
}

/* ---- identity: nothing to normalise, no view ----------------------------------------------------- */

static void identity_when_nothing_to_do(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 800u; seed++) {
		size_t n = 64u + (seed * 37u) % 3000u, i, since = 0;
		uint32_t ns = 5;
		struct kof_exe_decode_res d;
		uint64_t gl;
		uint32_t gf;

		nr_seed(&r, 0x4000u + seed);
		/* random bytes with isolated zeros: no run of eight, no wide run, and no
		 * text the decoders could read */
		for (i = 0; i < n; i++) {
			if (since >= 2u && nr_below(&r, 40u) == 0u) {
				in[i] = 0;
				since = 0;
			} else {
				in[i] = (uint8_t)(0x80u + nr_below(&r, 0x70u));
				since++;
			}
		}
		NCKF(kof_exe_norm(in, n, KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE, out, n, spans,
				  NMAX, &ns) == 0 && ns == 0, "seed %u: a view of nothing", seed);
		masked(in, n, NULL, NULL, 3u, NULL, 0, &gl, &gf);
		NCK(gl == 0 && gf == 0);
		NCK(kof_exe_unwide(in, n, out) == 0 && !memcmp(out, in, n));
		memcpy(tmp, in, n);
		NCK(kof_exe_decode_ex(tmp, n, &d) == 0 && !memcmp(tmp, in, n));
		NCK(d.rounds == 1u && d.limit == 0);
	}
	/* plain ASCII text of every flavour is not an encoded object either */
	{
		static const char text[] = "The quick brown fox jumps over the lazy dog 0123456789 "
					   "echo hello | cat; base64 is a word; deadbeef cafe 100%";
		size_t n = sizeof text - 1u;
		struct kof_exe_decode_res d;

		memcpy(in, text, n);
		NCK(kof_exe_norm(in, n, 3u, out, n, NULL, 0, NULL) == 0);
		memcpy(tmp, in, n);
		NCK(kof_exe_decode_ex(tmp, n, &d) == 0 && !memcmp(tmp, in, n));
	}
}

int main(void)
{
	unwide_layout();
	unwide_alphabet();
	unwide_differential();
	unwide_arguments();
	zero_floor_everywhere();
	norm_ops_and_caps();
	span_map_everywhere();
	src_of_far_offsets();
	masked_semantics();
	marks_are_carried();
	masked_equals_reference(2500u, 0x6000u, 0);
	masked_equals_reference(2500u, 0x8000u, 1);
	map_equals_transform();
	norm_equals_masked_and_reference();
	idempotent_and_monotone();
	identity_when_nothing_to_do();
	printf("normalizer_transform: %u checks, %u failed\n", nr_ok + nr_bad,
	       nr_bad);
	return nr_bad != 0;
}
