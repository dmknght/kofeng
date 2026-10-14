/*
 * mem_norm_probe - the normaliser works in ONE buffer, and a view is only built when one can
 * result.
 *
 * IN PLACE. kof_exe_norm_masked used to be called with the decoded copy as `in` and a second
 * object-sized buffer as `out`. It is now called with both the same buffer (o <= i in every
 * branch). The reference here is the old call - two distinct buffers - and the claim is that
 * the answer is the same on random input: the length, the ops that fired, the boundary marks
 * and every byte of the view. Where there are no kept/dropped bytes it is also compared with
 * a plain byte-at-a-time statement of the transform written in this file.
 *
 * PROBES. The normaliser takes its working buffer only when kof_exe_decode_would_change or
 * kof_exe_has_wide says a view can result. "No" must be exact: decode_would_change == 0 means
 * kof_exe_decode_ex changes nothing (and "yes" whenever it does), has_wide == 0 means no
 * wide run is narrowed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/analyzers/normalize/executables.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint64_t rs = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
	return (uint32_t)(rs >> 16);
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* A random object: noise, zero runs, wide text, and now and then an encoded payload. */
static uint64_t gen(uint8_t *b, uint64_t cap)
{
	uint64_t n = 0, want = rnd() % cap;

	while (n < want) {
		uint32_t kind = rnd() % 8u, k, i;

		switch (kind) {
		case 0: case 1:                         /* noise */
			k = rnd() % 40u;
			for (i = 0; i < k && n < cap; i++)
				b[n++] = (uint8_t)rnd();
			break;
		case 2: case 3:                         /* zeros, both short and long */
			k = rnd() % 3u ? rnd() % 20u : rnd() % 200u;
			for (i = 0; i < k && n < cap; i++)
				b[n++] = 0;
			break;
		case 4: case 5:                         /* wide text of 0..20 characters */
			k = rnd() % 21u;
			for (i = 0; i < k && n + 1u < cap; i++) {
				b[n++] = (uint8_t)(0x20u + rnd() % 0x5fu);
				b[n++] = 0;
			}
			break;
		case 6:                                 /* a base64 payload and its decoder */
			k = 16u + rnd() % 40u;
			if (n + k + 24u >= cap)
				break;
			b[n++] = ' ';
			for (i = 0; i < k; i++)
				b[n++] = (uint8_t)B64[rnd() % 64u];
			memcpy(b + n, " | base64 -d", 12);
			n += 12;
			break;
		default:                                /* a hex run, or a percent run */
			k = 12u + rnd() % 20u;
			if (n + 3u * k + 2u >= cap)
				break;
			b[n++] = ' ';
			if (rnd() & 1u) {
				for (i = 0; i < 2u * k; i++)
					b[n++] = (uint8_t)"0123456789abcdef"[rnd() % 16u];
			} else {
				for (i = 0; i < k; i++) {
					b[n++] = '%';
					b[n++] = (uint8_t)"0123456789ABCDEF"[2u + rnd() % 6u];
					b[n++] = (uint8_t)"0123456789ABCDEF"[rnd() % 16u];
				}
			}
			b[n++] = ' ';
			break;
		}
	}
	return n;
}

static void bitmap(uint8_t *m, uint64_t n)
{
	uint64_t i = 0;

	memset(m, 0, (size_t)((n + 7u) / 8u));
	while (i < n) {
		uint64_t k = 1u + rnd() % 300u, e = i + k > n ? n : i + k;

		if (rnd() % 3u == 0)
			for (; i < e; i++)
				m[i >> 3] |= (uint8_t)(1u << (i & 7u));
		else
			i = e;
	}
}

/* the transform as one would say it with no keep, no drop and no marks */
static uint64_t naive(const uint8_t *in, uint64_t n, uint8_t *out, uint32_t *fired)
{
	uint64_t i = 0, o = 0;

	*fired = 0;
	while (i < n) {
		uint64_t k = 0, z = 0;

		while (i + 2u * k + 1u < n && in[i + 2u * k + 1u] == 0 &&
		       (uint8_t)(in[i + 2u * k] - 0x20u) < 0x5fu)
			k++;
		if (k >= KOF_EXE_NORM_WIDE_MIN) {
			uint64_t j;

			for (j = 0; j < k; j++)
				out[o + j] = in[i + 2u * j];
			i += 2u * k;
			o += k;
			*fired |= KOF_EXE_NORM_UNWIDE;
			continue;
		}
		while (i + z < n && in[i + z] == 0)
			z++;
		if (z >= KOF_EXE_NORM_NULL_MIN) {
			out[o++] = 0;
			out[o++] = 0;
			i += z;
			*fired |= KOF_EXE_NORM_NULLRUN;
			continue;
		}
		out[o++] = in[i++];
	}
	return o;
}

#define CAP 6000u

static uint8_t obj[CAP], keepm[CAP / 8u + 8u], dropm[CAP / 8u + 8u];
static uint8_t a[CAP], b[CAP], c[CAP], r[CAP];

static void in_place(void)
{
	unsigned it, with_view = 0;

	for (it = 0; it < 3000; it++) {
		uint64_t n = gen(obj, CAP), na, nb, nr, mk[8], ma[8], mb[8];
		uint32_t nm = 0, q, fr;
		struct kof_exe_norm_req rq;
		struct kof_exe_norm_res ra, rb;
		int masks = it % 3u != 0;

		if (!n)
			continue;
		if (masks) {
			bitmap(keepm, n);
			bitmap(dropm, n);
		}
		for (q = 0; q < 8u; q++)
			mk[q] = rnd() % (n + 1u);
		for (q = 1; q < 8u; q++)             /* sorted, unique */
			if (mk[q] < mk[q - 1u])
				{ uint64_t t = mk[q]; mk[q] = mk[q - 1u]; mk[q - 1u] = t; }
		for (q = 0; q < 8u; q++)
			if (!q || mk[q] != mk[nm - 1u])
				mk[nm++] = mk[q];
		memset(ma, 0xee, sizeof ma);
		memset(mb, 0xee, sizeof mb);
		memset(&rq, 0, sizeof rq);
		rq.n = n;
		rq.keep = masks ? keepm : NULL;
		rq.drop = masks && (it % 2u) ? dropm : NULL;
		rq.ops = KOF_EXE_NORM_NULLRUN | KOF_EXE_NORM_UNWIDE;
		rq.mark = mk;
		rq.n_mark = nm;

		/* the old call: the input in one buffer, the answer in another */
		memcpy(a, obj, n);
		rq.in = a;
		memset(&ra, 0, sizeof ra);
		ra.out = b; ra.cap = n; ra.mark_out = ma;
		na = kof_exe_norm_masked(&rq, &ra);

		/* the new one: one buffer */
		memcpy(c, obj, n);
		rq.in = c;
		memset(&rb, 0, sizeof rb);
		rb.out = c; rb.cap = n; rb.mark_out = mb;
		nb = kof_exe_norm_masked(&rq, &rb);

		CK(na == nb);
		CK(ra.fired == rb.fired);
		CK(!memcmp(ma, mb, nm * sizeof ma[0]));
		/* the view is `n` bytes when nothing fired is reported as 0 and the buffer is the object */
		if (ra.fired) {
			CK(!memcmp(b, c, (size_t)na));
			with_view++;
		} else {
			CK(!memcmp(obj, c, (size_t)n));
		}
		if (!masks) {
			nr = naive(obj, n, r, &fr);
			if (fr) {
				CK(nr == na);
				CK(!memcmp(r, c, (size_t)nr));
			}
			CK(fr == ra.fired);
		}
	}
	CK(with_view > 500);                    /* the generator exercises the transform */
}

static void probes(void)
{
	unsigned it, dec = 0, wide = 0;

	for (it = 0; it < 4000; it++) {
		uint64_t n = gen(obj, CAP);
		int would, got, hw;
		struct kof_exe_decode_res dr;
		struct kof_exe_norm_req rq;
		struct kof_exe_norm_res res;

		if (!n)
			continue;
		memcpy(a, obj, n);
		would = kof_exe_decode_would_change(obj, n);
		got = kof_exe_decode_ex(a, n, &dr);
		if (got)
			CK(would);              /* a change is never answered "no" */
		if (!would)
			CK(!got && !memcmp(a, obj, (size_t)n) && !dr.limit);
		dec += got != 0;
		/* and the probe wrote nothing */
		memcpy(b, obj, n);
		(void)kof_exe_decode_would_change(b, n);
		CK(!memcmp(b, obj, (size_t)n));

		hw = kof_exe_has_wide(obj, n);
		memset(&rq, 0, sizeof rq);
		memcpy(c, obj, n);
		rq.in = c; rq.n = n; rq.ops = KOF_EXE_NORM_UNWIDE;
		memset(&res, 0, sizeof res);
		res.out = r; res.cap = n;
		(void)kof_exe_norm_masked(&rq, &res);
		if (res.fired & KOF_EXE_NORM_UNWIDE)
			CK(hw);
		wide += hw ? 1u : 0u;
	}
	CK(dec > 100 && wide > 100);            /* both answers occur */

	/* hand-made edges */
	{
		uint8_t w[64];
		unsigned i;

		memset(w, 'x', sizeof w);
		for (i = 0; i < 7u; i++) { w[2u * i] = 'A'; w[2u * i + 1u] = 0; }
		CK(!kof_exe_has_wide(w, sizeof w));            /* seven characters is not eight */
		w[14] = 'B'; w[15] = 0;
		CK(kof_exe_has_wide(w, sizeof w));
		CK(kof_exe_has_wide(w + 0, 16));
		CK(!kof_exe_has_wide(w, 15));                  /* the eighth is cut off */
		memset(w, 0, sizeof w);
		CK(!kof_exe_has_wide(w, sizeof w));
		CK(!kof_exe_decode_would_change(w, sizeof w));
		CK(!kof_exe_decode_would_change(NULL, 0));
	}
	{
		static const char s[] = "echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ= | base64 -d";
		uint8_t t[sizeof s];

		memcpy(t, s, sizeof s);
		CK(kof_exe_decode_would_change(t, sizeof s - 1u));
		CK(!memcmp(t, s, sizeof s));
	}
}

int main(void)
{
	in_place();
	probes();
	printf("mem norm probe: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
