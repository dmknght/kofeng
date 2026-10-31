/*
 * kx_identify - kof_inspect_identify against a parser table the test supplies (kof_parser_list is wrapped at link time), for the case
 * no real object reaches today: a row whose sniff accepts and whose parse REFUSES, followed by a row that accepts the same bytes. The
 * engine's identify (sx_identify, scan_facts.c) goes on to the second row; the examiner used to stop at the first refusal and answer
 * "no format" for a file the scanner names (EX-1; tests/unit/kx_inspect.c holds the agreement over real objects).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../kofexamine/kofinspect_private.h"

static int fails, checks;

#define CK(cond) do { checks++; if (!(cond)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

static int sniff_yes(kof_buf b) { (void)b; return 1; }
static int parse_no(kof_buf b, void *view, struct kof_obj_ctx *ctx)
{
	(void)b;
	memset(view, 0xee, 16);
	ctx->format = KOF_FMT_PE;          /* what a refusing parse may leave behind: it must not survive */
	ctx->entry_off = 77;
	return 0;
}
static int parse_yes(kof_buf b, void *view, struct kof_obj_ctx *ctx)
{
	(void)b;
	((uint8_t *)view)[0] = 1;
	ctx->format = KOF_FMT_TEXT;
	return 1;
}
static const char *no_name(uint32_t bit) { (void)bit; return NULL; }
static const char *no_anom(unsigned i) { (void)i; return NULL; }
static uint64_t no_bits(const void *view) { (void)view; return 0; }

static struct kof_parser rows[3];
static uint32_t n_rows;

const struct kof_parser *__real_kof_parser_list(uint32_t *n);
const struct kof_parser *__wrap_kof_parser_list(uint32_t *n);
const struct kof_parser *__wrap_kof_parser_list(uint32_t *n)
{
	*n = n_rows;
	return rows;
}

static void row(struct kof_parser *p, uint8_t fmt, int (*parse)(kof_buf, void *, struct kof_obj_ctx *))
{
	memset(p, 0, sizeof *p);
	p->format = fmt;
	p->view_size = 16;
	p->sniff = sniff_yes;
	p->parse = parse;
	p->region_name = no_name;
	p->anomaly_name = no_anom;
	p->anomalies = no_bits;
}

int main(void)
{
	uint8_t b[16] = { 0 };
	struct kof_obj_ctx ctx;
	void *view = NULL;
	const struct kof_parser *p;

	/* [refusing row][accepting row]: the second is the answer, and nothing of the first is in ctx */
	row(&rows[0], KOF_FMT_PE, parse_no);
	row(&rows[1], KOF_FMT_TEXT, parse_yes);
	n_rows = 2;
	p = kof_inspect_identify(kof_buf_make(b, sizeof b), &ctx, &view);
	CK(p == &rows[1]);
	CK(ctx.format == KOF_FMT_TEXT);
	CK(ctx.entry_off != 77);
	CK(view && ((uint8_t *)view)[0] == 1);
	kof_inspect_free(p, view);

	/* [refusing][refusing][accepting] */
	row(&rows[0], KOF_FMT_PE, parse_no);
	row(&rows[1], KOF_FMT_ELF, parse_no);
	row(&rows[2], KOF_FMT_TEXT, parse_yes);
	n_rows = 3;
	view = NULL;
	p = kof_inspect_identify(kof_buf_make(b, sizeof b), &ctx, &view);
	CK(p == &rows[2] && ctx.format == KOF_FMT_TEXT);
	kof_inspect_free(p, view);

	/* every row refuses: no format, no view, and ctx is clean */
	row(&rows[0], KOF_FMT_PE, parse_no);
	n_rows = 1;
	view = (void *)b;
	p = kof_inspect_identify(kof_buf_make(b, sizeof b), &ctx, &view);
	CK(p == NULL && view == NULL && ctx.format == 0 && ctx.entry_off != 77);

	printf("%d check(s), %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
