/*
 * container/parse - the parse entry points of the container formats, one adapter row each (one template, written out per format
 * so that each format's own functions are called by name): sniff, parse into a zeroed view with the caller's table room,
 * walk the view's rows, release.
 *
 * Seeds are the writers' archives of tests/lib/ctr_writers.h (tests/fuzz/container/ctr_seeds.h): valid, then each header lie the
 * format has a field for (declared size, count, offset, a cycle, a missing terminator, hostile names), every one with the field
 * map its writer published, so the mutators aim at the counts and offsets. gzip, bz2, xz, rtf, lnk and reg have no writer
 * with lies: their seeds are small literals.
 *
 * Held for every format: the sniff and the parse answer on every input (the guard buffer ends where the input ends); the
 * regions the parse declares partition the object and every extent lies inside it (partition_check.h, the same check
 * parser_fuzz.c makes on its own generated objects); the entry table is in range and does not amplify (entry_check.h); the
 * view's rows are as many as the account says and the walk is bounded; what the tables hold never passes the room the host
 * gave (`held <= room`); release gives it all back (the driver's leak check) and a second parse of the same bytes digests the
 * same (the driver's determinism check).
 */
#include <kofmod/kofsig.h>
#include "../../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../../libkofeng/analyzers/parsers/containers/zip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/tar_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/rar_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/lha_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/arj_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/cab_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/chm_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/sevenzip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/docole_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/pdf_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/gzip_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/bz2_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/xz_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/rtf_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/lnk_parse.h"
#include "../../../libkofeng/analyzers/parsers/containers/reg_parse.h"

#include "../../lib/ctr_check.h"
#include "ctr_seeds.h"

#define CP_ROOM (16u << 20)

struct cp {
	void                    *view;
	struct kof_obj_ctx       ctx;
	const struct kof_parser *p;
	uint64_t                 n;
};

static struct cp cp_state;

/* The checks every format's parse answers to (tests/lib/ctr_check.h: one copy, shared with tests/unit/ctr_cuts.c; the known
 * defects WP2-D9, D10 and D11 are carved out there per format and counted into the digest). */
static void cp_check(struct fz_ctx *c, struct cp *s, uint64_t n)
{
	struct cck_policy pol = cck_policy_of(s->p->format);
	uint64_t known = 0, rows = 0;
	const char *why = ctr_partition(&s->ctx, s->p, n, &pol, &known);

	FZ_CHECK(c, why == NULL, why ? why : "partition");
	why = ctr_entries(&s->ctx, n, &pol, &rows);
	FZ_CHECK(c, why == NULL, why ? why : "entries");
	fz_digest(c, known ? 0xD9u + known : n);
	fz_digest(c, rows << 8);
}

static void cp_account(struct fz_ctx *c, struct kof_view_mem *m, uint32_t rows_seen)
{
	FZ_CHECK(c, m->held <= m->room + 4096u, "the tables hold more than the room the host gave");
	FZ_CHECK(c, rows_seen <= m->rows + 1u || m->rows == 0, "the walk returned more rows than the account says");
	fz_digest(c, m->held + ((uint64_t)m->rows << 32) + rows_seen);
}

static int cp_begin(struct fz_ctx *c, struct cp *s, uint8_t fmt, const uint8_t *in, size_t n, int (*sniff)(kof_buf),
		    int (*parse)(kof_buf, void *, struct kof_obj_ctx *), struct kof_view_mem *(*mem)(void *), void (*release)(void *))
{
	kof_buf buf = kof_buf_make(in, n);

	memset(s, 0, sizeof *s);
	s->p = kof_parser_of(fmt);
	if (!s->p)
		return 0;
	s->n = n;
	s->view = calloc(1, s->p->view_size);
	if (!s->view)
		return 0;
	if (!sniff(buf)) {
		fz_digest(c, 0x51);
		free(s->view);
		s->view = NULL;
		return 0;
	}
	if (mem)
		mem(s->view)->room = CP_ROOM;
	if (!parse(buf, s->view, &s->ctx)) {
		fz_digest(c, 0x52);
		if (release)
			release(s->view);
		free(s->view);
		s->view = NULL;
		return 0;
	}
	return 1;
}

/* ---- zip ---- */
static int cp_zip_sniff(kof_buf f) { return kof_zip_sniff(f); }
static int cp_zip_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_zip_parse(f, v, x); }
static struct kof_view_mem *cp_zip_mem(void *v) { return kof_zip_mem(v); }
static void cp_zip_rel(void *v) { kof_zip_release(v); }

static void *cp_zip_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_ZIP, in, n, cp_zip_sniff, cp_zip_parse, cp_zip_mem, cp_zip_rel) ? &cp_state : NULL;
}

static void cp_zip_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_zip_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_zip_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_zip_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_zip_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_zip_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("zip"));
}

FZ_ADAPTER(cp_zip, .name = "container/parse_zip", .covers = "kof_zip_sniff kof_zip_parse kof_zip_mem kof_zip_row kof_zip_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_zip_seeds,
	   .parse = cp_zip_open, .walk = cp_zip_walk, .drop = cp_zip_drop);

/* ---- tar ---- */
static int cp_tar_sniff(kof_buf f) { return kof_tar_sniff(f); }
static int cp_tar_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_tar_parse(f, v, x); }
static struct kof_view_mem *cp_tar_mem(void *v) { return kof_tar_mem(v); }
static void cp_tar_rel(void *v) { kof_tar_release(v); }

static void *cp_tar_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_TAR, in, n, cp_tar_sniff, cp_tar_parse, cp_tar_mem, cp_tar_rel) ? &cp_state : NULL;
}

static void cp_tar_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_tar_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_tar_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_tar_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_tar_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_tar_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("tar"));
}

FZ_ADAPTER(cp_tar, .name = "container/parse_tar", .covers = "kof_tar_sniff kof_tar_parse kof_tar_mem kof_tar_row kof_tar_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_tar_seeds,
	   .parse = cp_tar_open, .walk = cp_tar_walk, .drop = cp_tar_drop);

/* ---- rar ---- */
static int cp_rar_sniff(kof_buf f) { return kof_rar_sniff(f); }
static int cp_rar_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_rar_parse(f, v, x); }
static struct kof_view_mem *cp_rar_mem(void *v) { return kof_rar_mem(v); }
static void cp_rar_rel(void *v) { kof_rar_release(v); }

static void *cp_rar_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_RAR, in, n, cp_rar_sniff, cp_rar_parse, cp_rar_mem, cp_rar_rel) ? &cp_state : NULL;
}

static void cp_rar_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_rar_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_rar_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_rar_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_rar_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_rar_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("rar"));
	csd_format(c, cw_find("rar5"));
}

FZ_ADAPTER(cp_rar, .name = "container/parse_rar", .covers = "kof_rar_sniff kof_rar_parse kof_rar_mem kof_rar_row kof_rar_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_rar_seeds,
	   .parse = cp_rar_open, .walk = cp_rar_walk, .drop = cp_rar_drop);

/* ---- lha ---- */
static int cp_lha_sniff(kof_buf f) { return kof_lha_sniff(f); }
static int cp_lha_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_lha_parse(f, v, x); }
static struct kof_view_mem *cp_lha_mem(void *v) { return kof_lha_mem(v); }
static void cp_lha_rel(void *v) { kof_lha_release(v); }

static void *cp_lha_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_LHA, in, n, cp_lha_sniff, cp_lha_parse, cp_lha_mem, cp_lha_rel) ? &cp_state : NULL;
}

static void cp_lha_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_lha_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_lha_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_lha_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_lha_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_lha_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("lha"));
}

FZ_ADAPTER(cp_lha, .name = "container/parse_lha", .covers = "kof_lha_sniff kof_lha_parse kof_lha_mem kof_lha_row kof_lha_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_lha_seeds,
	   .parse = cp_lha_open, .walk = cp_lha_walk, .drop = cp_lha_drop);

/* ---- arj ---- */
static int cp_arj_sniff(kof_buf f) { return kof_arj_sniff(f); }
static int cp_arj_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_arj_parse(f, v, x); }
static struct kof_view_mem *cp_arj_mem(void *v) { return kof_arj_mem(v); }
static void cp_arj_rel(void *v) { kof_arj_release(v); }

static void *cp_arj_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_ARJ, in, n, cp_arj_sniff, cp_arj_parse, cp_arj_mem, cp_arj_rel) ? &cp_state : NULL;
}

static void cp_arj_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_arj_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_arj_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_arj_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_arj_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_arj_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("arj"));
}

FZ_ADAPTER(cp_arj, .name = "container/parse_arj", .covers = "kof_arj_sniff kof_arj_parse kof_arj_mem kof_arj_row kof_arj_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_arj_seeds,
	   .parse = cp_arj_open, .walk = cp_arj_walk, .drop = cp_arj_drop);

/* ---- cab ---- */
static int cp_cab_sniff(kof_buf f) { return kof_cab_sniff(f); }
static int cp_cab_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_cab_parse(f, v, x); }
static struct kof_view_mem *cp_cab_mem(void *v) { return kof_cab_mem(v); }
static void cp_cab_rel(void *v) { kof_cab_release(v); }

static void *cp_cab_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_CAB, in, n, cp_cab_sniff, cp_cab_parse, cp_cab_mem, cp_cab_rel) ? &cp_state : NULL;
}

static void cp_cab_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_cab_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_cab_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_cab_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_cab_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_cab_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("cab"));
}

FZ_ADAPTER(cp_cab, .name = "container/parse_cab", .covers = "kof_cab_sniff kof_cab_parse kof_cab_mem kof_cab_row kof_cab_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_cab_seeds,
	   .parse = cp_cab_open, .walk = cp_cab_walk, .drop = cp_cab_drop);

/* ---- chm ---- */
static int cp_chm_sniff(kof_buf f) { return kof_chm_sniff(f); }
static int cp_chm_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_chm_parse(f, v, x); }
static struct kof_view_mem *cp_chm_mem(void *v) { return kof_chm_mem(v); }
static void cp_chm_rel(void *v) { kof_chm_release(v); }

static void *cp_chm_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_CHM, in, n, cp_chm_sniff, cp_chm_parse, cp_chm_mem, cp_chm_rel) ? &cp_state : NULL;
}

static void cp_chm_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_chm_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_chm_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_chm_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_chm_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_chm_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("chm"));
}

FZ_ADAPTER(cp_chm, .name = "container/parse_chm", .covers = "kof_chm_sniff kof_chm_parse kof_chm_mem kof_chm_row kof_chm_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_chm_seeds,
	   .parse = cp_chm_open, .walk = cp_chm_walk, .drop = cp_chm_drop);

/* ---- 7z ---- */
static int cp_7z_sniff(kof_buf f) { return kof_7z_sniff(f); }
static int cp_7z_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_7z_parse(f, v, x); }
static struct kof_view_mem *cp_7z_mem(void *v) { return kof_7z_mem(v); }
static void cp_7z_rel(void *v) { kof_7z_release(v); }

static void *cp_7z_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_7Z, in, n, cp_7z_sniff, cp_7z_parse, cp_7z_mem, cp_7z_rel) ? &cp_state : NULL;
}

static void cp_7z_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_7z_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_7z_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_7z_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_7z_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_7z_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("7z"));
}

FZ_ADAPTER(cp_7z, .name = "container/parse_7z", .covers = "kof_7z_sniff kof_7z_parse kof_7z_mem kof_7z_row kof_7z_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_7z_seeds,
	   .parse = cp_7z_open, .walk = cp_7z_walk, .drop = cp_7z_drop);

/* ---- docole ---- */
static int cp_docole_sniff(kof_buf f) { return kof_docole_sniff(f); }
static int cp_docole_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_docole_parse(f, v, x); }
static struct kof_view_mem *cp_docole_mem(void *v) { return kof_docole_mem(v); }
static void cp_docole_rel(void *v) { kof_docole_release(v); }

static void *cp_docole_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_DOCOLE, in, n, cp_docole_sniff, cp_docole_parse, cp_docole_mem, cp_docole_rel) ? &cp_state : NULL;
}

static void cp_docole_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_docole_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_docole_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_docole_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_docole_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_docole_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("ole"));
}

FZ_ADAPTER(cp_docole, .name = "container/parse_docole", .covers = "kof_docole_sniff kof_docole_parse kof_docole_mem kof_docole_row kof_docole_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_docole_seeds,
	   .parse = cp_docole_open, .walk = cp_docole_walk, .drop = cp_docole_drop);

/* ---- pdf ---- */
static int cp_pdf_sniff(kof_buf f) { return kof_pdf_sniff(f); }
static int cp_pdf_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_pdf_parse(f, v, x); }
static struct kof_view_mem *cp_pdf_mem(void *v) { return kof_pdf_mem(v); }
static void cp_pdf_rel(void *v) { kof_pdf_release(v); }

static void *cp_pdf_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_PDF, in, n, cp_pdf_sniff, cp_pdf_parse, cp_pdf_mem, cp_pdf_rel) ? &cp_state : NULL;
}

static void cp_pdf_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	{
		uint32_t cur = 0, rows = 0;
		const void *r;

		while ((r = kof_pdf_row(s->view, &cur)) != NULL && fz_step(&c->steps, 1)) {
			rows++;
			FZ_CHECK(c, cur > 0, "a row was returned and the cursor did not move");
		}
		cp_account(c, kof_pdf_mem(s->view), rows);
	}
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_pdf_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	kof_pdf_release(s->view);
	free(s->view);
	s->view = NULL;
}

static void cp_pdf_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("pdf"));
}

FZ_ADAPTER(cp_pdf, .name = "container/parse_pdf", .covers = "kof_pdf_sniff kof_pdf_parse kof_pdf_mem kof_pdf_row kof_pdf_release", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_pdf_seeds,
	   .parse = cp_pdf_open, .walk = cp_pdf_walk, .drop = cp_pdf_drop);

/* ---- gzip ---- */
static int cp_gzip_sniff(kof_buf f) { return kof_gzip_sniff(f); }
static int cp_gzip_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_gzip_parse(f, v, x); }

static void *cp_gzip_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_GZIP, in, n, cp_gzip_sniff, cp_gzip_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_gzip_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_gzip_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_gzip_seeds(struct fz_corpus *c)
{
	csd_format(c, cw_find("gzip"));
}

FZ_ADAPTER(cp_gzip, .name = "container/parse_gzip", .covers = "kof_gzip_sniff kof_gzip_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_gzip_seeds,
	   .parse = cp_gzip_open, .walk = cp_gzip_walk, .drop = cp_gzip_drop);

/* ---- bz2 ---- */
static int cp_bz2_sniff(kof_buf f) { return kof_bz2_sniff(f); }
static int cp_bz2_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_bz2_parse(f, v, x); }

static void *cp_bz2_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_BZIP2, in, n, cp_bz2_sniff, cp_bz2_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_bz2_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_bz2_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_bz2_seeds(struct fz_corpus *c)
{
	static const uint8_t b[] = { 'B', 'Z', 'h', '9', 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0, 0, 0, 0 };
	fz_corpus_add(c, "bz2-empty", b, sizeof b);
	fz_corpus_add(c, "bz2-bad-level", b, 3);
}

FZ_ADAPTER(cp_bz2, .name = "container/parse_bz2", .covers = "kof_bz2_sniff kof_bz2_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_bz2_seeds,
	   .parse = cp_bz2_open, .walk = cp_bz2_walk, .drop = cp_bz2_drop);

/* ---- xz ---- */
static int cp_xz_sniff(kof_buf f) { return kof_xz_sniff(f); }
static int cp_xz_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_xz_parse(f, v, x); }

static void *cp_xz_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_XZ, in, n, cp_xz_sniff, cp_xz_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_xz_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_xz_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_xz_seeds(struct fz_corpus *c)
{
	static const uint8_t b[] = { 0xfd, '7', 'z', 'X', 'Z', 0, 0, 0, 0, 0, 0, 0, 2, 0, 0x21, 1, 0, 0, 0, 0,
		0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
		0, 1, 28, 32, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 'Y', 'Z' };
	fz_corpus_add(c, "xz-one-block", b, sizeof b);
}

FZ_ADAPTER(cp_xz, .name = "container/parse_xz", .covers = "kof_xz_sniff kof_xz_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_xz_seeds,
	   .parse = cp_xz_open, .walk = cp_xz_walk, .drop = cp_xz_drop);

/* ---- rtf ---- */
static int cp_rtf_sniff(kof_buf f) { return kof_rtf_sniff(f); }
static int cp_rtf_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_rtf_parse(f, v, x); }

static void *cp_rtf_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_RTF, in, n, cp_rtf_sniff, cp_rtf_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_rtf_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_rtf_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_rtf_seeds(struct fz_corpus *c)
{
	static const char t[] = "{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata 01050000020000000a000000}}{\\pict\\bin8 ABCDEFGH}}";
	fz_corpus_add(c, "rtf-object", t, sizeof t - 1u);
}

FZ_ADAPTER(cp_rtf, .name = "container/parse_rtf", .covers = "kof_rtf_sniff kof_rtf_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_rtf_seeds,
	   .parse = cp_rtf_open, .walk = cp_rtf_walk, .drop = cp_rtf_drop);

/* ---- lnk ---- */
static int cp_lnk_sniff(kof_buf f) { return kof_lnk_sniff(f); }
static int cp_lnk_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_lnk_parse(f, v, x); }

static void *cp_lnk_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_LNK, in, n, cp_lnk_sniff, cp_lnk_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_lnk_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_lnk_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_lnk_seeds(struct fz_corpus *c)
{
	uint8_t b[76];
	static const uint8_t clsid[16] = { 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46 };
	memset(b, 0, sizeof b);
	b[0] = 0x4c;
	memcpy(b + 4, clsid, 16);
	fz_corpus_add(c, "lnk-header", b, sizeof b);
}

FZ_ADAPTER(cp_lnk, .name = "container/parse_lnk", .covers = "kof_lnk_sniff kof_lnk_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_lnk_seeds,
	   .parse = cp_lnk_open, .walk = cp_lnk_walk, .drop = cp_lnk_drop);

/* ---- reg ---- */
static int cp_reg_sniff(kof_buf f) { return kof_reg_sniff(f); }
static int cp_reg_parse(kof_buf f, void *v, struct kof_obj_ctx *x) { return kof_reg_parse(f, v, x); }

static void *cp_reg_open(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	return cp_begin(c, &cp_state, KOF_FMT_REG, in, n, cp_reg_sniff, cp_reg_parse, NULL, NULL) ? &cp_state : NULL;
}

static void cp_reg_walk(struct fz_ctx *c, void *h, const uint8_t *in, size_t n)
{
	struct cp *s = (struct cp *)h;
	(void)in;
	cp_check(c, s, n);
	fz_digest(c, s->p->anomalies ? s->p->anomalies(s->view) : 0u);
}

static void cp_reg_drop(void *h)
{
	struct cp *s = (struct cp *)h;

	free(s->view);
	s->view = NULL;
}

static void cp_reg_seeds(struct fz_corpus *c)
{
	static const char t[] = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\Software\\x]\r\n\"a\"=\"b\"\r\n\"run\"=hex:01,02,03\r\n";
	fz_corpus_add(c, "reg-export", t, sizeof t - 1u);
}

FZ_ADAPTER(cp_reg, .name = "container/parse_reg", .covers = "kof_reg_sniff kof_reg_parse", .shape = FZ_PARSE, .flags = FZ_MAY_HIT_CAP, .seeds = cp_reg_seeds,
	   .parse = cp_reg_open, .walk = cp_reg_walk, .drop = cp_reg_drop);
