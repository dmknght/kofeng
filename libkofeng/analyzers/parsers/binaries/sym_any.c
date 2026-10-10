/*
 * sym_any.c - the one place that decides WHICH symbol builder an object gets.
 *
 * ELF and PE each have their own, and both fill the single KSYM layout that
 * kofmod/kofsym.h fixes. The choice used to be made twice - once in the
 * scanner's content accessor and once in kofviewer - which is two places to
 * keep in step for a decision that has one right answer.
 */

#include <kofmod/kofsym.h>
#include "elf/elf_sym.h"
#include "pe/pe_sym.h"
#include "funcs.h"
#include <stdlib.h>
#include <string.h>

uint32_t kof_syms_build(uint32_t format, const uint8_t *data, uint64_t data_n,
			const void *info, uint8_t *out, uint32_t cap)
{
	kof_buf b = kof_buf_make(data, data_n);

	if (!info || !out || cap < KOF_SYM_HDRLEN)
		return 0;
	if (format == KOF_FMT_ELF)
		return kof_elf_syms(b, info, out, cap);
	if (format == KOF_FMT_PE)
		return kof_pe_syms(b, info, out, cap);
	/* Any other format has no symbols to give, which a reader takes as a
	 * count of zero - the same answer a stripped ELF gives. */
	return 0;
}

/*
 * THE FUNCTIONS, by the same decision. ELF only for now: a PE names its
 * functions through exports and the exception directory, and which of those is
 * the source is not settled - an empty set is what it answers until then.
 */
void kof_funcs_build(uint32_t format, const uint8_t *data, uint64_t data_n,
		     const void *info, struct kof_func_set *out)
{
	memset(out, 0, sizeof *out);
	if (!info)
		return;
	if (format == KOF_FMT_ELF)
		kof_elf_funcs_build(kof_buf_make(data, data_n), info, out);
	else if (format == KOF_FMT_PE)
		kof_pe_funcs_build(kof_buf_make(data, data_n), info, out);
}

static int func_cmp(const void *a, const void *b)
{
	const struct kof_func *x = a, *y = b;

	if (x->off != y->off)
		return x->off < y->off ? -1 : 1;
	/* the longer extent first, so it is the one that stands */
	return x->len < y->len ? 1 : x->len > y->len ? -1 : 0;
}

void kof_funcs_finish(struct kof_func *v, uint32_t n, struct kof_func_set *out)
{
	uint32_t i, k = 0;

	if (!n) {
		free(v);
		return;
	}
	qsort(v, n, sizeof *v, func_cmp);
	for (i = 0; i < n; i++) {
		/* One function per address, and no label inside another body. */
		if (k && v[i].off < v[k - 1u].off + v[k - 1u].len &&
		    v[i].off + v[i].len <= v[k - 1u].off + v[k - 1u].len)
			continue;
		v[k++] = v[i];
	}
	out->v = v;
	out->n = k;
}

void kof_funcs_free(struct kof_func_set *s)
{
	free(s->v);
	memset(s, 0, sizeof *s);
}

/* The first place `len` bytes at `pat` occur in [from, from + span) of `view`. */
static int find_bytes(const uint8_t *view, uint64_t view_n, uint64_t from,
		      uint64_t span, const uint8_t *pat, uint64_t len,
		      uint64_t *at)
{
	uint64_t end, i;

	if (!len || from >= view_n || len > view_n - from)
		return 0;
	end = from + span;
	if (end > view_n - len + 1u)
		end = view_n - len + 1u;
	for (i = from; i < end; i++) {
		const uint8_t *q = memchr(view + i, pat[0], (size_t)(end - i));

		if (!q)
			return 0;
		i = (uint64_t)(q - view);
		if (!memcmp(q, pat, (size_t)len)) {
			*at = i;
			return 1;
		}
	}
	return 0;
}

/* How far past the last function found the next may begin: collapsed padding
 * only - what was cut is the library's, and a library function is not wanted. */
#define REMAP_SLACK 4096u

void kof_funcs_remap(const uint8_t *par, uint64_t par_n,
		     const struct kof_func_set *pf, const uint8_t *view,
		     uint64_t view_n, struct kof_func_set *out)
{
	struct kof_func *v;
	uint64_t cursor = 0;
	uint32_t i, n = 0;

	memset(out, 0, sizeof *out);
	if (!par || !view || !pf || !pf->n)
		return;
	v = malloc(pf->n * sizeof *v);
	if (!v) {
		out->oom = 1;
		return;
	}
	for (i = 0; i < pf->n; i++) {
		const struct kof_func *f = &pf->v[i];
		uint64_t at;

		if (f->off >= par_n || f->len > par_n - f->off)
			continue;
		if (!find_bytes(view, view_n, cursor, f->len + REMAP_SLACK,
				par + f->off, f->len, &at))
			continue;
		v[n] = *f;
		v[n].off = at;
		n++;
		cursor = at + f->len;
	}
	if (!n) {
		free(v);
		return;
	}
	out->v = v;
	out->n = n;
}
