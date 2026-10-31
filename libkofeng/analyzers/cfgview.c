/*
 * cfgview.c - kof_cfgview_build. See cfgview.h for what it is for and what it does not decide.
 *
 * ORDER OF WORK: validate the extent against the function table -> ONE decode of the function through kgenome_diag_code_run (the engine's
 * reader, with the object's byte order) into an array bounded by `max_bytes` -> kgenome_cfg_build -> kgenome_cfg_sign (with the labels) ->
 * kgenome_cfg_anchor -> kgenome_cfg_view_make -> kgenome_cfg_gv_make (the graph the viewer lays out and draws), then the calls and their names. Nothing is decoded twice and no block
 * is found twice: the instruction array is what build, sign and the view read.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <genotype/image/image_addr.h>
#include <phenotype/diag_scan.h>

#include "callnames.h"
#include "cfgsign.h"
#include "cfgview.h"
#include "genome_obj.h"
#include "parsers/binaries/funcs.h"

#define NAMED_CALLS KOF_CFGVIEW_XLINES

static void fail(struct kof_cfgview *out, enum kgenome_status st, const char *why)
{
	char line[160];

	out->status = kgenome_status_merge(out->status, st);
	snprintf(line, sizeof line, "CFG not made: %s (status %s)\n", why, kgenome_status_name(out->status));
	free(out->text);
	out->text = malloc(strlen(line) + 1u);
	if (out->text) {
		memcpy(out->text, line, strlen(line) + 1u);
		out->text_len = strlen(line);
		out->n_lines = 1;
	}
}

static const struct kgenome_func *func_at(const struct kgenome_func_set *fs, uint64_t off, uint64_t len)
{
	uint32_t lo = 0, hi = fs ? fs->n : 0;

	while (lo < hi) {
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (fs->v[mid].off < off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (; fs && lo < fs->n && fs->v[lo].off == off; lo++)
		if (fs->v[lo].len == len)
			return &fs->v[lo];
	return NULL;
}

/* The name of the function that starts at file offset `off`: kof_func_name when the table has an entry there (its symbol, or `fcn_<offset>`), else the made-up
 * name of the address alone. */
static void func_name(const struct kof_cfgview_req *rq, uint64_t off, char *out, size_t cap)
{
	uint32_t lo = 0, hi = rq->funcs ? rq->funcs->n : 0;

	while (lo < hi) {                       /* the first entry at `off`, whatever its length */
		const uint32_t mid = lo + (hi - lo) / 2u;

		if (rq->funcs->v[mid].off < off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (rq->funcs && lo < rq->funcs->n && rq->funcs->v[lo].off == off)
		(void)kof_func_name(&rq->funcs->v[lo], rq->sym, rq->sym_n, out, cap);
	else
		kof_fcn_name(off, out, cap);
}

/* The name of a call's callee, from the object's own tables only. `target` is a file offset or KGENOME_BROKEN. */
static void callee_name(const struct kof_cfgview_req *rq, const struct kof_cfgview_call *c, int direct, char *out, size_t cap)
{
	out[0] = 0;
	if (c->kind == KGENOME_CFG_CK_SYSCALL) {
		snprintf(out, cap, "syscall");
		return;
	}
	if (!direct) {
		if (rq->names)
			(void)kof_callnames_name(rq->names, rq->data, KOF_CALLNAME_VIA_SITE, c->at, out, cap);
		if (!out[0])
			snprintf(out, cap, "indirect");
		return;
	}
	if (c->target == KGENOME_BROKEN) {
		snprintf(out, cap, "outside the object");
		return;
	}
	if (rq->names && kof_callnames_name(rq->names, rq->data, KOF_CALLNAME_VIA_TARGET, c->target, out, cap))
		return;
	func_name(rq, c->target, out, cap);
}

/* The calls and system calls of the reachable blocks: block index in the view, offset, direct target, and a name for the first few. */
static int calls_make(const struct kof_cfgview_req *rq, struct kof_cfgview *out, const struct kgenome_cfg *g,
		      const struct kgenome_cell_insn *in, const struct kgenome_obj *gobj)
{
	uint32_t j, bi = 0, rank = 0;

	if (!g->n_call)
		return 1;
	out->call = calloc(g->n_call, sizeof *out->call);
	if (!out->call)
		return 0;
	for (j = 0; j < g->n_call; j++) {
		const struct kgenome_cfg_call *k = &g->call[j];
		struct kof_cfgview_call *c = &out->call[j];
		const struct kgenome_cell_insn *ci = &in[k->insn];

		while (bi < g->n_all && !(k->insn >= g->b[bi].first && k->insn - g->b[bi].first < g->b[bi].n_insn)) {
			rank += g->b[bi].reach;
			bi++;
		}
		c->blk = rank;
		c->kind = k->kind;
		c->at = ci->at;
		c->target = KGENOME_BROKEN;
		if (ci->op == KGENOME_CELL_CALL && !(ci->flags & KGENOME_CELL_F_INDIRECT) && ci->target_va != KGENOME_BROKEN) {
			const uint64_t t = out->mapped ? kgenome_image_addr_to_off(gobj, ci->target_va) : ci->target_va;

			if (t != KGENOME_BROKEN && t < rq->data.n)
				c->target = t;
		}
		if (j < NAMED_CALLS)
			callee_name(rq, c, ci->op == KGENOME_CELL_CALL && !(ci->flags & KGENOME_CELL_F_INDIRECT), c->name, sizeof c->name);
	}
	out->n_call = g->n_call;
	return 1;
}

static const char *kind_word(unsigned k)
{
	switch (k) {
	case KGENOME_CFG_CK_SYSCALL: return "syscall";
	case KGENOME_CFG_CK_INDIRECT: return "call indirect";
	default: return "call";
	}
}

/* One line of the facts text, appended; the text is the lines the dialog lists above and below the drawing (the graph itself is out->gv). */
struct facts {
	char  *buf;
	size_t n, cap;
	uint32_t lines;
	int bad;
};

static void fact(struct facts *f, const char *s)
{
	const size_t n = strlen(s);

	if (f->bad)
		return;
	if (f->n + n + 2u > f->cap) {
		size_t nc = f->cap ? f->cap * 2u : 1024u;
		char *p;

		while (nc < f->n + n + 2u)
			nc *= 2u;
		p = realloc(f->buf, nc);
		if (!p) {
			f->bad = 1;
			return;
		}
		f->buf = p;
		f->cap = nc;
	}
	memcpy(f->buf + f->n, s, n);
	f->buf[f->n + n] = '\n';
	f->n += n + 1u;
	f->buf[f->n] = 0;
	f->lines++;
}

/* The graph the dialog draws (the lib's filler), the calls as its notes and as the extra lines of the boxes, and the text of the facts. */
static int text_make(const struct kof_cfgview_req *rq, struct kof_cfgview *out)
{
	struct kgenome_cfg_gv_req gq;
	struct facts f;
	char t0[96], t1[160], line[KGENOME_GV_NOTE + 16];
	uint32_t i, held = out->n_call < KOF_CFGVIEW_NOTES ? out->n_call : KOF_CFGVIEW_NOTES, nx = 0, per_blk = 0, last_blk = 0xffffffffu;

	snprintf(t0, sizeof t0, "function %s", out->name);
	{
		char sk[40] = "";

		if (out->n_skip)
			snprintf(sk, sizeof sk, "  skipped-bytes=%llu", (unsigned long long)out->n_skip);
		snprintf(t1, sizeof t1, "extent  0x%llx +%llu bytes  %s %s  instructions=%u  calls=%u%s", (unsigned long long)out->func_off,
			 (unsigned long long)out->func_len, kgenome_arch_title(out->arch) ? kgenome_arch_title(out->arch) : "?",
			 out->be ? "big-endian" : "little-endian", out->n_insn, out->n_call, sk);
	}
	/* the extra lines of the boxes: the first KGENOME_GV_BOX_X calls of a block, the first KOF_CFGVIEW_XLINES of them in all; the rest is the box's `+N more` */
	for (i = 0; i < out->n_call && nx < KOF_CFGVIEW_XLINES; i++) {
		if (out->call[i].blk != last_blk) {
			last_blk = out->call[i].blk;
			per_blk = 0;
		}
		if (per_blk++ < KGENOME_GV_BOX_X)
			nx++;
	}
	memset(&gq, 0, sizeof gq);
	gq.v = &out->view;
	gq.title[0] = t0;
	gq.title[1] = t1;
	gq.anchor_min = out->anchor_min;
	gq.n_note = held;
	gq.n_xline = nx;
	(void)kgenome_cfg_gv_make(&gq, &out->gv);
	out->status = kgenome_status_merge(out->status, out->gv.status);
	for (i = 0; i < held && out->gv.note; i++) {
		const struct kof_cfgview_call *c = &out->call[i];

		out->gv.note[i].node = c->blk;
		snprintf(out->gv.note[i].text, KGENOME_GV_NOTE, "B%u 0x%llx %s%s%s", (unsigned)c->blk, (unsigned long long)c->at, kind_word(c->kind),
			 c->name[0] ? " -> " : "", c->name);
	}
	out->gv.note_total = out->n_call;
	snprintf(out->gv.note_title, sizeof out->gv.note_title, "calls: %u", (unsigned)out->n_call);
	{
		uint32_t k = 0;

		last_blk = 0xffffffffu;
		for (i = 0; i < out->n_call && k < out->gv.n_xline; i++) {
			const struct kof_cfgview_call *c = &out->call[i];

			if (c->blk != last_blk) {
				last_blk = c->blk;
				per_blk = 0;
			}
			if (per_blk++ >= KGENOME_GV_BOX_X)
				continue;
			out->gv.xline[k].node = c->blk;
			snprintf(out->gv.xline[k].text, KGENOME_GV_LINE, "%s%s%s", kind_word(c->kind), c->name[0] ? " " : "", c->name);
			k++;
		}
	}
	/* THE FACTS: the head (the function, the extent, the counts, the hashes, the anchor), the calls, the unreachable blocks. */
	memset(&f, 0, sizeof f);
	for (i = 0; i < out->gv.n_head; i++)
		fact(&f, out->gv.head[i]);
	out->n_top = out->gv.n_head < 3u ? out->gv.n_head : 3u;       /* the function, the extent and the counts stand above the drawing */
	if (out->gv.note_total) {
		uint32_t lim = out->gv.n_note < KOF_CFGVIEW_CALL_LINES ? out->gv.n_note : KOF_CFGVIEW_CALL_LINES;

		fact(&f, out->gv.note_title);
		for (i = 0; i < lim; i++) {
			snprintf(line, sizeof line, "  %s", out->gv.note[i].text);
			fact(&f, line);
		}
		if (out->gv.note_total > lim) {
			snprintf(line, sizeof line, "  ... %u more note(s) not listed", (unsigned)(out->gv.note_total - lim));
			fact(&f, line);
		}
	}
	if (out->gv.aside_title[0]) {
		if (!out->gv.n_aside) {
			if (out->gv.aside_none[0])
				fact(&f, out->gv.aside_none);
		} else {
			const uint32_t lim = out->gv.n_aside < KOF_CFGVIEW_ASIDE_LINES ? out->gv.n_aside : KOF_CFGVIEW_ASIDE_LINES;

			fact(&f, out->gv.aside_title);
			for (i = 0; i < lim; i++) {
				snprintf(line, sizeof line, "  %s", out->gv.aside[i].text);
				fact(&f, line);
			}
			if (out->gv.n_aside > lim) {
				snprintf(line, sizeof line, "  ... %u more", (unsigned)(out->gv.n_aside - lim));
				fact(&f, line);
			}
		}
	}
	if (f.bad) {
		free(f.buf);
		return 0;
	}
	out->text = f.buf ? f.buf : calloc(1, 1);
	out->text_len = f.n;
	out->n_lines = f.lines;
	(void)rq;
	return out->text != NULL;
}

int kof_cfgview_build(const struct kof_cfgview_req *rq, struct kof_cfgview *out)
{
	struct kgenome_obj gobj;
	struct kof_cfgsign cs;
	struct kof_cfgsign_host host;
	struct kof_cfgsign_req sr;
	struct kgenome_cfg_view_req vq;
	struct kgenome_budget bud;
	int made = 0;
	enum kgenome_status st;

	memset(out, 0, sizeof *out);
	memset(&cs, 0, sizeof cs);
	if (!rq || !rq->ctx || !rq->data.p) {
		fail(out, KGENOME_BAD_INPUT, "bad request");
		return 0;
	}
	out->func_off = rq->func_off;
	out->func_len = rq->func_len;
	out->arch = rq->ctx->arch;
	out->anchor_min = rq->anchor_min ? rq->anchor_min : KGENOME_CFG_ANCHOR_MIN;
	if (!rq->func_len || rq->func_off >= rq->data.n || rq->func_len > rq->data.n - rq->func_off) {
		fail(out, KGENOME_BAD_INPUT, "the extent is not inside the object");
		return 0;
	}
	if (rq->funcs && !func_at(rq->funcs, rq->func_off, rq->func_len)) {
		fail(out, KGENOME_BAD_INPUT, "the extent is not a function of this object");
		return 0;
	}
	func_name(rq, rq->func_off, out->name, sizeof out->name);
	kof_genome_obj(rq->ctx, &gobj);
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = rq->max_bytes ? rq->max_bytes : KOF_CFGVIEW_MAX_BYTES;
	/* THE ONE SIGNING FUNCTION: decode, graph, signature (with the labels), floor. The instructions, the graph and the labels are kept for the view. */
	memset(&host, 0, sizeof host);
	host.max_bytes = bud.max_bytes;
	memset(&sr, 0, sizeof sr);
	sr.ctx = rq->ctx;
	sr.data = rq->data;
	sr.off = rq->func_off;
	sr.len = rq->func_len;
	sr.floor = out->anchor_min;
	sr.keep = 1;
	sr.host = &host;
	(void)kof_cfgsign_function(&sr, &cs);
	out->be = cs.be;
	out->mapped = cs.mapped;
	out->func_va = cs.func_va;
	out->n_insn = cs.n_insn;
	out->n_skip = cs.n_skip;
	switch (cs.state) {
	case KOF_CFGSIGN_NOMEM:
		fail(out, KGENOME_NOMEM, "no memory for the graph");
		return 0;
	case KOF_CFGSIGN_OVER_BUDGET:
		fail(out, KGENOME_OVER_BUDGET, cs.n_insn && cs.status == KGENOME_OVER_BUDGET ? "the graph needs more memory than the allowance" :
		     "the function holds more instructions than the allowance");
		return 0;
	case KOF_CFGSIGN_UNSUPPORTED:
		fail(out, KGENOME_UNSUPPORTED, "no control-flow rules for this architecture");
		return 0;
	case KOF_CFGSIGN_UNDECODABLE:
		fail(out, KGENOME_BAD_INPUT, cs.n_insn ? "the lib built no graph" : "no instruction decodes at the function's offset");
		return 0;
	case KOF_CFGSIGN_SIGNED:
	case KOF_CFGSIGN_BELOW_FLOOR:
		break;
	}
	memset(&vq, 0, sizeof vq);
	vq.g = &cs.g;
	vq.sign = &cs.sign;
	vq.label = cs.label;
	vq.in = cs.in;
	vq.budget = &bud;
	st = kgenome_status_merge(cs.status, kgenome_cfg_view_make(&vq, &out->view));
	out->status = kgenome_status_merge(out->status, st);
	out->n_all = cs.g.n_all;
	out->n_site = cs.g.n_site;
	out->n_sys = cs.g.n_sys;
	out->anchor_pass = cs.state == KOF_CFGSIGN_SIGNED;
	if (!calls_make(rq, out, &cs.g, cs.in, &gobj)) {
		fail(out, KGENOME_NOMEM, "no memory for the call table");
		goto done;
	}
	if (!text_make(rq, out)) {
		fail(out, KGENOME_NOMEM, "no memory for the text");
		goto done;
	}
	made = 1;
done:
	kof_cfgsign_release(&cs, NULL);
	return made;
}

void kof_cfgview_free(struct kof_cfgview *v)
{
	if (!v)
		return;
	kgenome_gv_free(&v->gv, NULL);
	kgenome_cfg_view_free(&v->view, NULL);
	free(v->call);
	free(v->text);
	memset(v, 0, sizeof *v);
}
