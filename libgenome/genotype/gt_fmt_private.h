/*
 * gt_fmt_private.h - the text builder the ARM state and AArch64 formatters share.
 * Private to genotype/: nothing outside includes it.
 *
 * ONE LINE IS A MNEMONIC AND ITS OPERANDS. A formatter picks the mnemonic with
 * kgenome_gt_fmt_mn and appends the operand text with kgenome_gt_fmt_op; the line
 * is put together once, in kgenome_gt_fmt_done: the mnemonic in capitals, padded to
 * KGENOME_GT_FMT_COL so the operands of consecutive lines start in one column (the
 * x86 formatter's layout), then the operands as they were written. Nothing is
 * written to the caller's buffer before that, so a buffer that is too small gives
 * a status and no half line.
 */
#ifndef KGENOME_GENOTYPE_GT_FMT_PRIVATE_H
#define KGENOME_GENOTYPE_GT_FMT_PRIVATE_H

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "genotype.h"

#define KGENOME_GT_FMT_COL 10u          /* width of the mnemonic column, as the x86 text has it */

struct kgenome_gt_fmt {
	char   mn[32];
	char   ops[224];
	size_t mn_n, ops_n;
	int    bad;                     /* something did not fit: the text is not complete */
};

static inline void kgenome_gt_fmt_init(struct kgenome_gt_fmt *f)
{
	f->mn[0] = 0;
	f->ops[0] = 0;
	f->mn_n = f->ops_n = 0;
	f->bad = 0;
}

static inline void kgenome_gt_fmt_vadd(char *dst, size_t cap, size_t *n, int *bad, const char *fmt, va_list ap)
{
	int w;

	if (*n >= cap) {
		*bad = 1;
		return;
	}
	w = vsnprintf(dst + *n, cap - *n, fmt, ap);
	if (w < 0 || (size_t)w >= cap - *n) {
		*bad = 1;
		*n = cap - 1u;
		return;
	}
	*n += (size_t)w;
}

/* The mnemonic, printf style: ("ld%s%s", "a", "xr"). */
static inline void kgenome_gt_fmt_mn(struct kgenome_gt_fmt *f, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static inline void kgenome_gt_fmt_mn(struct kgenome_gt_fmt *f, const char *fmt, ...)
{
	va_list ap;

	f->mn_n = 0;
	va_start(ap, fmt);
	kgenome_gt_fmt_vadd(f->mn, sizeof f->mn, &f->mn_n, &f->bad, fmt, ap);
	va_end(ap);
}

/* Append to the operand text (the commas are the caller's). */
static inline void kgenome_gt_fmt_op(struct kgenome_gt_fmt *f, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static inline void kgenome_gt_fmt_op(struct kgenome_gt_fmt *f, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	kgenome_gt_fmt_vadd(f->ops, sizeof f->ops, &f->ops_n, &f->bad, fmt, ap);
	va_end(ap);
}

/* Put the line in the caller's buffer. KGENOME_OK, or KGENOME_TRUNCATED with `cap` bytes of buf untouched past what fits. */
static inline enum kgenome_status kgenome_gt_fmt_done(const struct kgenome_gt_fmt *f, char *buf, size_t cap, size_t *len)
{
	size_t i, n = 0, pad;

	if (!cap) {
		*len = 0;
		return KGENOME_TRUNCATED;
	}
	pad = f->ops_n ? (f->mn_n < KGENOME_GT_FMT_COL ? KGENOME_GT_FMT_COL - f->mn_n : 1u) : 0;
	if (f->bad || f->mn_n + pad + f->ops_n + 1u > cap) {
		buf[0] = 0;
		*len = 0;
		return KGENOME_TRUNCATED;
	}
	for (i = 0; i < f->mn_n; i++)
		buf[n++] = (char)toupper((unsigned char)f->mn[i]);
	for (i = 0; i < pad; i++)
		buf[n++] = ' ';
	memcpy(buf + n, f->ops, f->ops_n);
	n += f->ops_n;
	buf[n] = 0;
	*len = n;
	return KGENOME_OK;
}

#endif /* KGENOME_GENOTYPE_GT_FMT_PRIVATE_H */
