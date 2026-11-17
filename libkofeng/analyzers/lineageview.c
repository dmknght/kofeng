/*
 * lineageview.c - kof_lineageview_build: see lineageview.h.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <celllysis/nucleo.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_vocab.h>

#include "lineageview.h"

#define KOF_LGV_NONE 0xffffffffu   /* local index: the record is not inside the caller's extent */

static int lgv_in_extent(const struct kof_diag_lineage_rec *r, uint64_t off, uint64_t len)
{
	return r->at >= off && r->at - off < len;
}

/* The NUL-terminated name a symref pointed at, or NULL - the same bounded scan kofdiag.c's own
 * hit_sym does (a different struct, the object's bytes are the only thing in common, not worth a
 * shared header for six lines). */
static const char *lgv_symname(const struct kof_lineageview_req *rq, uint64_t symref)
{
	uint64_t i;

	if (!rq->base || symref >= rq->size)
		return NULL;
	for (i = symref; i < rq->size; i++)
		if (!rq->base[i])
			return (const char *)(rq->base + symref);
	return NULL;
}

/* How many extra box lines record `r` needs (0-2: the value it wrote, the symbol it named) -
 * counted here and filled later with the same two conditions, so the two passes agree. */
static uint32_t lgv_xcount(const struct kof_diag_lineage_rec *r)
{
	uint32_t n = 0;

	if (r->bits & KGENOME_DIAG_H_VAL)
		n++;
	if (r->bits & KGENOME_DIAG_H_SYMREF)
		n++;
	return n;
}

/*
 * THE INPUTS OF RECORD i: every one (kof_result.lineage_in, the request's lin_in) when the request carries them and the record's
 * range lies inside them, else its four-input view in[]. The view is not the node's inputs - a system call's NUMBER is never in it
 * (diag_vocab.h, KGENOME_DIAG_ROLE_NUMBER) and nor is a fifth input - so a reader of the view drew cleartext's read at 0xf1 with no
 * link from the connect whose zero chose it (2026-11-14). *view is set when the view is what was read.
 */
static const struct kof_diag_lineage_in *lgv_inputs(const struct kof_lineageview_req *rq, uint32_t i, uint32_t *n, int *view)
{
	const struct kof_diag_lineage_rec *r = &rq->lin[i];

	if (rq->lin_in && r->n_all >= r->n_in && r->in_first <= rq->n_lin_in && r->n_all <= rq->n_lin_in - r->in_first) {
		*n = r->n_all;
		return rq->lin_in + r->in_first;
	}
	*view |= r->n_in != 0;
	*n = r->n_in < 4u ? r->n_in : 4u;
	return r->in;
}

/* kgenome_diag_link -> kgenome_gv_sure: a value the stage does not write is said as UNKNOWN (its row spells the raw value). */
static uint8_t lgv_sure(uint8_t how)
{
	switch (how) {
	case KGENOME_DIAG_LINK_PROVEN:  return KGENOME_GV_SURE;
	case KGENOME_DIAG_LINK_MAY:     return KGENOME_GV_SURE_MAY;
	case KGENOME_DIAG_LINK_BROKEN:  return KGENOME_GV_SURE_BROKEN;
	default:                        return KGENOME_GV_SURE_UNKNOWN;
	}
}

/* The words of a link's row: the engine spells them, the viewer prints the row as it is. */
static const char *lgv_how_word(uint8_t how, char *tmp, size_t cap)
{
	switch (how) {
	case KGENOME_DIAG_LINK_PROVEN:  return "proven";
	case KGENOME_DIAG_LINK_MAY:     return "may";
	case KGENOME_DIAG_LINK_UNKNOWN: return "unknown";
	case KGENOME_DIAG_LINK_BROKEN:  return "broken";
	default:
		snprintf(tmp, cap, "how-%u", (unsigned)how);
		return tmp;
	}
}

static const char *lgv_role_word(uint8_t role, char *tmp, size_t cap)
{
	static const char *const w[KGENOME_DIAG_ROLE_COUNT] = { "-", "buffer", "target", "fd", "path", "source", "value", "number", "content" };

	if (role < KGENOME_DIAG_ROLE_COUNT)
		return w[role];
	snprintf(tmp, cap, "role-%u", (unsigned)role);
	return tmp;
}

/* Where a link starts, as its row says it: a node of this function (L<n>), a node outside it, the stack, or a record that does not exist. */
static void lgv_from_text(const struct kof_lineageview_req *rq, const uint32_t *local, uint16_t from, char *out, size_t cap)
{
	if (from == KGENOME_DIAG_FROM_STACK) {
		snprintf(out, cap, "the stack");
	} else if (from >= rq->n_lin) {
		snprintf(out, cap, "record %u (none such)", (unsigned)from);
	} else if (local[from] == KOF_LGV_NONE) {
		snprintf(out, cap, "%s 0x%llx (outside)", kgenome_nucleo_cap_name(rq->lin[from].cap), (unsigned long long)rq->lin[from].at);
	} else {
		snprintf(out, cap, "L%u %s 0x%llx", (unsigned)local[from], kgenome_nucleo_cap_name(rq->lin[from].cap), (unsigned long long)rq->lin[from].at);
	}
}

struct lgv_tmp_edge {
	uint32_t from, to, link;
	uint8_t  sure, carry;
	char     label[KGENOME_GV_LABEL];
};

/* gview.h's contract: the edges are sorted by `from` (the drawing, kv_graph_walk_make, refuses a list that is not: the Lineage tab drew nothing until
 * 2026-11-14), then by `to`, then in the order of the rows, so one producer's links stand left to right as its consumers' rows are listed. */
static int lgv_edge_cmp(const void *a, const void *b)
{
	const struct lgv_tmp_edge *x = a, *y = b;

	if (x->from != y->from)
		return x->from < y->from ? -1 : 1;
	if (x->to != y->to)
		return x->to < y->to ? -1 : 1;
	return x->link < y->link ? -1 : x->link > y->link;
}

struct lgv_count {
	uint32_t node, edge, link, xline, how[4], outside;
	int      view;
};

static void head_lines(struct kgenome_gv *gv, const struct kof_lineageview_req *rq, const struct lgv_count *c)
{
	unsigned t;

#define HL(...) do { if (gv->n_head < KGENOME_GV_HEAD_MAX) snprintf(gv->head[gv->n_head++], KGENOME_GV_HEAD_COLS, __VA_ARGS__); } while (0)
	for (t = 0; t < 2u; t++)
		if (rq->title[t] && rq->title[t][0])
			HL("%s", rq->title[t]);
	HL("lineage  nodes=%u  links=%u  proven=%u may=%u unknown=%u broken=%u  from-outside=%u",
	   (unsigned)c->node, (unsigned)c->link, (unsigned)c->how[KGENOME_GV_SURE], (unsigned)c->how[KGENOME_GV_SURE_MAY],
	   (unsigned)c->how[KGENOME_GV_SURE_UNKNOWN], (unsigned)c->how[KGENOME_GV_SURE_BROKEN], (unsigned)c->outside);
	if (c->view)
		HL("links read from each node's four-input view: a system call's number and a fifth input are not in it");
#undef HL
}

/* The records inside, by (address, record index): the order they stand top to bottom. */
struct lgv_key {
	uint64_t at;
	uint32_t rec;
};

static int lgv_key_cmp(const void *a, const void *b)
{
	const struct lgv_key *x = a, *y = b;

	if (x->at != y->at)
		return x->at < y->at ? -1 : 1;
	return x->rec < y->rec ? -1 : x->rec > y->rec;
}

/*
 * PROGRAM ORDER. A node's index (L<n>) is its rank in the order of the ADDRESSES of the sites inside (a tie by record index), so the drawing stands
 * the program top to bottom (gview.h, `ordered`) and an L number says where it is: the records come in the order the routes made them, which
 * put an exec-memory node above the read that filled its region (cleartext, 2026-11-17). `ord[k]` is the record of node k.
 */
static enum kgenome_status lgv_order(const struct kof_lineageview_req *rq, uint32_t *local, uint32_t n, uint32_t *ord)
{
	struct lgv_key *ky = malloc((size_t)n * sizeof *ky);
	uint32_t i, k = 0;

	if (!ky)
		return KGENOME_NOMEM;
	for (i = 0; i < rq->n_lin; i++)
		if (local[i] != KOF_LGV_NONE) {
			ky[k].at = rq->lin[i].at;
			ky[k++].rec = i;
		}
	qsort(ky, n, sizeof *ky, lgv_key_cmp);
	for (k = 0; k < n; k++) {
		local[ky[k].rec] = k;
		ord[k] = ky[k].rec;
	}
	free(ky);
	return KGENOME_OK;
}

static void lgv_fill_nodes(const struct kof_lineageview_req *rq, const uint32_t *ord, struct kgenome_gv *out)
{
	uint32_t node_i, xline_i = 0;

	for (node_i = 0; node_i < out->n_node; node_i++) {
		const struct kof_diag_lineage_rec *r = &rq->lin[ord[node_i]];
		struct kgenome_gv_node *n = &out->node[node_i];

		n->off = r->at;
		snprintf(n->line[0], KGENOME_GV_LINE, "L%u %s", (unsigned)node_i, kgenome_nucleo_cap_name(r->cap));
		snprintf(n->line[1], KGENOME_GV_LINE, "0x%llx", (unsigned long long)r->at);
		n->xtotal = lgv_xcount(r);
		/*
		 * WHAT THIS NODE WROTE, AND WHAT IT NAMED - the two facts a hit carries beside its
		 * capability and its links (diag_scan.h: kgenome_diag_hit.val/attr/symref), shown
		 * only when the bit that says they are valid is set (a node with no write has no
		 * `val` to misreport as 0). The box's own generic renderer (kgenome_gv_box_line)
		 * draws these the same way it already draws a CFG block's call list - not a second
		 * rendering path for one job.
		 */
		if ((r->bits & KGENOME_DIAG_H_VAL) && xline_i < out->n_xline) {
			out->xline[xline_i].node = node_i;
			if (r->attr)
				snprintf(out->xline[xline_i].text, KGENOME_GV_LINE, "wrote +0x%llx = 0x%llx",
					 (unsigned long long)r->attr, (unsigned long long)r->val);
			else
				snprintf(out->xline[xline_i].text, KGENOME_GV_LINE, "wrote = 0x%llx", (unsigned long long)r->val);
			xline_i++;
		}
		if ((r->bits & KGENOME_DIAG_H_SYMREF) && xline_i < out->n_xline) {
			const char *nm = lgv_symname(rq, r->symref);

			out->xline[xline_i].node = node_i;
			if (nm)
				snprintf(out->xline[xline_i].text, KGENOME_GV_LINE, "@%s%+d", nm, r->symadd);
			else
				snprintf(out->xline[xline_i].text, KGENOME_GV_LINE, "@0x%llx%+d",
					 (unsigned long long)r->symref, r->symadd);
			xline_i++;
		}
	}
}

/* One row per input of every node inside, in node order and each node's inputs in their order; the ones whose producer is a node inside are
 * the edges, given to `te` with the row they belong to. */
static void lgv_fill_links(const struct kof_lineageview_req *rq, const uint32_t *local, const uint32_t *ord, struct kgenome_gv *out,
			   struct lgv_tmp_edge *te)
{
	uint32_t j, k, link_i = 0, edge_i = 0;
	int view = 0;

	for (j = 0; j < out->n_node; j++) {
		const uint32_t i = ord[j];
		const struct kof_diag_lineage_in *x;
		uint32_t nx;
		char to[16];

		x = lgv_inputs(rq, i, &nx, &view);
		snprintf(to, sizeof to, "L%u", (unsigned)local[i]);    /* its box says what and where it is */
		for (k = 0; k < nx && link_i < out->n_note; k++, link_i++) {
			struct kgenome_gv_note *nt = &out->note[link_i];
			char from[64], th[16], tr[16];
			const char *role = lgv_role_word(x[k].role, tr, sizeof tr);    /* ONE word for the row and the edge */

			lgv_from_text(rq, local, x[k].from, from, sizeof from);
			nt->node = local[i];
			snprintf(nt->text, KGENOME_GV_NOTE, "%-34.56s -> %-6.6s %-6.8s %-7.8s %.8s", from, to, role,
				 lgv_how_word(x[k].how, th, sizeof th), x[k].kind == KGENOME_DIAG_KIND_SHARED ? "shared" : "produced");
			/* a link the engine leaves to its use chain (KGENOME_DIAG_IN_UNDRAWN) is a row and no edge */
			if (x[k].from < rq->n_lin && local[x[k].from] != KOF_LGV_NONE && !(x[k].flags & KGENOME_DIAG_IN_UNDRAWN) && edge_i < out->n_edge) {
				te[edge_i].from = local[x[k].from];
				te[edge_i].to = local[i];
				te[edge_i].link = link_i;
				te[edge_i].sure = lgv_sure(x[k].how);
				/* the number of a system call is no argument: the producer's result chose which call this is (diag_vocab.h) */
				te[edge_i].carry = x[k].role == KGENOME_DIAG_ROLE_NUMBER ? KGENOME_GV_CARRY_CONTROL : KGENOME_GV_CARRY_VALUE;
				snprintf(te[edge_i].label, sizeof te[edge_i].label, "%.11s", role);   /* KGENOME_GV_LABEL - 1 */
				edge_i++;
			}
		}
	}
	qsort(te, edge_i, sizeof *te, lgv_edge_cmp);
	for (k = 0; k < edge_i; k++) {
		out->edge[k].from = te[k].from;
		out->edge[k].to = te[k].to;
		out->edge[k].sure = te[k].sure;
		out->edge[k].carry = te[k].carry;
		memcpy(out->edge[k].label, te[k].label, sizeof out->edge[k].label);
		/* the nodes stand in address order (`ordered`): a link into a site at or before its producer's goes back */
		out->edge[k].loop = te[k].to <= te[k].from ? KGENOME_GV_LOOP_RETREAT : KGENOME_GV_LOOP_NONE;
		out->note[te[k].link].link = k + 1u;
	}
}

enum kgenome_status kof_lineageview_build(const struct kof_lineageview_req *rq, struct kgenome_gv *out)
{
	uint32_t *local;   /* rq->n_lin entries: KOF_LGV_NONE, or the node's index in `out` */
	uint32_t *ord = NULL;      /* c.node entries: the record of node k (lgv_order) */
	struct lgv_tmp_edge *te = NULL;
	struct lgv_count c;
	uint64_t n_link = 0, n_edge = 0;
	uint32_t i, k;
	enum kgenome_status st;

	if (!out)
		return KGENOME_BAD_INPUT;
	memset(out, 0, sizeof *out);
	memset(&c, 0, sizeof c);
	if (!rq || (rq->n_lin && !rq->lin)) {
		out->status = KGENOME_BAD_INPUT;
		return out->status;
	}
	local = rq->n_lin ? calloc(rq->n_lin, sizeof *local) : NULL;
	if (rq->n_lin && !local) {
		out->status = KGENOME_NOMEM;
		head_lines(out, rq, &c);
		return out->status;
	}
	for (i = 0; i < rq->n_lin; i++) {
		if (lgv_in_extent(&rq->lin[i], rq->off, rq->len)) {
			local[i] = c.node++;
			c.xline += lgv_xcount(&rq->lin[i]);
		} else {
			local[i] = KOF_LGV_NONE;
		}
	}
	if (c.node && (!(ord = malloc((size_t)c.node * sizeof *ord)) || lgv_order(rq, local, c.node, ord) != KGENOME_OK)) {
		free(ord);
		free(local);
		out->status = KGENOME_NOMEM;
		head_lines(out, rq, &c);
		return out->status;
	}
	/* Counted before the allocation, as cfg_gv does: every input of a node inside is a row (a link), and one whose producer is a node inside is
	 * also an edge. Nothing is left out for its certainty: MAY, UNKNOWN and BROKEN are drawn, each its own way (the edge's `sure`). */
	for (i = 0; i < rq->n_lin; i++) {
		const struct kof_diag_lineage_in *x;
		uint32_t nx;

		if (local[i] == KOF_LGV_NONE)
			continue;
		x = lgv_inputs(rq, i, &nx, &c.view);
		n_link += nx;
		for (k = 0; k < nx; k++) {
			c.how[lgv_sure(x[k].how)]++;
			/* KNOWN DEFECT LV-D2 (2026-11-17, M) [sev L]: kof_lineageview_build counts every input that is no edge as `from-outside`: the stack (KGENOME_DIAG_FROM_STACK) and a record that does not exist too.
			 * Trigger: a node of the function with an input from the stack. Effect: the Overview's one row says from-outside=N for links that come from no other function.
			 * Reproducer: tests/unit/lineageview.c, the from-outside row (green until fixed). Fix: count the stack and the dangling `from` apart and say each in head_lines. */
			if (x[k].from < rq->n_lin && local[x[k].from] != KOF_LGV_NONE) {
				if (!(x[k].flags & KGENOME_DIAG_IN_UNDRAWN))
					n_edge++;
			} else {
				c.outside++;
			}
		}
	}
	c.link = n_link > 0xffffffffu ? 0xffffffffu : (uint32_t)n_link;
	c.edge = n_edge > 0xffffffffu ? 0xffffffffu : (uint32_t)n_edge;
	st = n_link > 0x7fffffffu ? KGENOME_OVER_BUDGET :   /* a DoS bound on the request, never met by a scan: a record's inputs are a few */
	     kgenome_gv_alloc(out, &(const struct kgenome_gv_size){ .n_node = c.node, .n_edge = c.edge, .n_xline = c.xline, .n_note = c.link },
			      NULL, &(const struct kgenome_cfg_mem){ 0 });
	if (st == KGENOME_OK && c.edge && !(te = calloc(c.edge, sizeof *te))) {
		kgenome_gv_free(out, NULL);
		st = KGENOME_NOMEM;
	}
	if (st != KGENOME_OK) {
		memset(out, 0, sizeof *out);
		out->id_prefix = 'L';
		out->status = st;
		head_lines(out, rq, &c);
		snprintf(out->head[out->n_head < KGENOME_GV_HEAD_MAX ? out->n_head : KGENOME_GV_HEAD_MAX - 1u], KGENOME_GV_HEAD_COLS,
			 "graph not drawn: %s", st == KGENOME_OVER_BUDGET ? "over budget" : "no memory");
		if (out->n_head < KGENOME_GV_HEAD_MAX)
			out->n_head++;
		free(ord);
		free(local);
		return out->status;
	}
	out->id_prefix = 'L';
	out->status = KGENOME_OK;
	out->ordered = 1;
	lgv_fill_nodes(rq, ord, out);
	lgv_fill_links(rq, local, ord, out, te);
	out->entry = 0;
	out->note_total = c.link;
	snprintf(out->note_title, sizeof out->note_title, "links: %u", (unsigned)c.link);
	head_lines(out, rq, &c);
	free(te);
	free(ord);
	free(local);
	return out->status;
}
