/*
 * scan_explain.c - where the markers and blocks of a matched detection form are, for the report (kscan_explain).
 *
 * THE THIRD LEVEL OF THE REPORT: diagnose, matcher, part (struct kof_diag_part). The first two are recorded while the form is
 * answered (objctx_diag_form.c); this is asked after, for a diagnose that matched, and only when the report is on - a scan that
 * nobody explains never gets here. Nothing is stored for it and nothing in the scan's own path calls it.
 *
 * A MARKER is located by the same matcher the scan used (kof_match_where over the extents of the regions the matcher names).
 * A BLOCK is a set of window hashes and the similarity matcher counts windows without positions, so its place is found by one more
 * walk over the object's units - the list the feed credits (kof_scan_mutation_units, cut as sx_feed_cut cuts it) - asking each unit
 * which of the block's hashes it holds (kgenome_mutation_member): the unit holding the most is the place. The percentage and the
 * count are the matcher's own (kof_mutation_pct, kof_mutation_matched), not recomputed.
 *
 * WHAT IT DOES NOT SAY: a block that lies across two units reports the one that holds more of it; an object fed whole by its
 * unpacker (from_packer) is one unit; a region the units list leaves out (a header) has no place and `place` is 0.
 */

#include "../kofcore/kofdebug.h"
#include "scan_int.h"
#include "objctx_int.h"
#include "../analyzers/parsers/kofformat.h"
#include "../analyzers/parsers/binaries/funcs.h"
#include "../detectors/mutations/kofmutation.h"
#include "../databases/pack/diagform.h"
#include "../databases/pack/dbtables.h"
#include "../analyzers/cfgsign.h"
#include <celllysis/mutation.h>
#include <celllysis/cfg.h>

#include <string.h>

struct xpend {
	const uint32_t *hash;
	uint32_t        n, mask, best;
	uint8_t         side;
	uint8_t         idx;            /* the part */
};

struct xwalk {
	struct kof_diag_report *out;
	struct xpend             p[KOF_DIAG_REPORT_PARTS];
	uint32_t                n_p;
	const uint8_t          *bytes;
	const uint8_t          *syms;
	uint32_t                n_syms;
	const struct kof_parser *fp;
	const struct kof_obj_ctx *ctx;
	uint64_t                n_bytes;
	const struct kof_cfgsign_host *cfg;
};

static const char *mname(const struct kof_parser *fp, uint32_t mask)
{
	if (mask == KOF_SCAN_ALL)
		return "ALL";
	if (fp && fp->region_name && mask && !(mask & (mask - 1u))) {
		const char *n = fp->region_name(mask), *q;

		/* "KOF_SCAN_ELF_CODE" is read as "CODE": the prefix says the format, which the report's reader knows. */
		if (n && !strncmp(n, "KOF_SCAN_", 9) && (q = strchr(n + 9, '_')) != NULL)
			return q + 1;
		return n;
	}
	return NULL;
}

static uint32_t popcount_bits(const uint8_t *b, uint32_t n_bits)
{
	uint32_t i, c = 0;

	for (i = 0; i < n_bits; i++)
		c += (uint32_t)((b[i >> 3] >> (i & 7u)) & 1u);
	return c;
}

/*
 * THE HOLD OF A FUNCTION UNIT against a block: the unit's CFG sketch (kof_cfgsign_function, the one signing function) against the block's keys, as the
 * matcher scored it (kgenome_cfg_overlap: hit of taken). Returns the hits (0 when the unit is not signed) and fills the unit's id, the fold of its keys as
 * --blocks prints it.
 */
static uint32_t func_hold(const struct xwalk *w, const struct xpend *p, const struct kgenome_func *first, uint32_t *id)
{
	struct kof_cfgsign cs;
	struct kof_cfgsign_req rq;
	struct kgenome_cfg_sign bs;
	uint32_t hit, taken;

	memset(&rq, 0, sizeof rq);
	rq.ctx = w->ctx;
	rq.data.p = w->bytes;
	rq.data.n = w->n_bytes;
	rq.off = first->off;
	rq.len = first->len;
	rq.host = w->cfg;
	rq.wk = kof_scan_of(w->ctx)->obj.diag.walk;     /* the table's decode and the object's frames, as the feed reads them */
	rq.fs = oc_funcs(w->ctx);
	rq.frames = oc_frames(w->ctx);
	*id = 0;
	if (kof_cfgsign_function(&rq, &cs) != KOF_CFGSIGN_SIGNED)
		return 0;
	*id = kof_mutation_fold(cs.sign.key, cs.sign.n_key);
	kgenome_cfg_keys_sign(&bs, p->hash, p->n);
	kgenome_cfg_overlap(&cs.sign, &bs, &hit, &taken);
	return hit;
}

static int unit_cb(void *user, uint32_t region, uint64_t off, uint64_t len, uint32_t side, const struct kgenome_func *first)
{
	struct xwalk *w = user;
	uint32_t k;

	for (k = 0; k < w->n_p; k++) {
		struct xpend *p = &w->p[k];
		uint8_t bits[(KOF_FORM_HASH_MAX + 7u) / 8u];
		uint32_t c, unit_id = 0;
		const uint32_t sig = kgenome_mutation_signature(first);
		struct kof_diag_part *part;

		if (side != p->side || !(p->mask & (region | KOF_SCAN_ALL)) || !len)
			continue;
		if (sig == KGENOME_MUTATION_SIG_CFG) {
			c = func_hold(w, p, first, &unit_id);
		} else {
			memset(bits, 0, sizeof bits);
			kgenome_mutation_member(p->hash, p->n, w->bytes + off, len, bits);
			c = popcount_bits(bits, p->n);
		}
		if (c <= p->best)
			continue;
		p->best = c;
		part = &w->out->part[p->idx];
		part->place = 1;
		part->off = off;
		part->plen = len;
		part->region = region;
		part->place_hits = c;
		if (sig == KGENOME_MUTATION_SIG_WINDOWS) {
			uint32_t blk[KGENOME_MUTATION_MINHASH_K], nb;

			/* The unit's own id, as --blocks prints it: a near match (70%) has a different block hash than the diagnose's, which is why the id
			 * of the diagnose's block cannot find the unit's row. */
			nb = kgenome_mutation_unit_minhash(first, w->bytes + off, len, blk);
			part->unit_id = nb >= kgenome_mutation_block_min(region) ? kof_mutation_fold(blk, nb) : 0u;
		} else {
			part->unit_id = unit_id;
		}
		part->region_name = mname(w->fp, region);
		part->func[0] = 0;
		if (first && w->syms)
			kof_sym_name_at(w->syms, w->n_syms, &first->value, -1, part->func, sizeof part->func);
	}
	return 0;
}

void oc_explain_parts(const struct kof_obj_ctx *ctx, uint32_t i, struct kof_diag_report *out)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_diag *d;
	const struct kof_form *f;
	const struct kof_parser *fp;
	struct xwalk w;
	uint32_t k, a, total = 0;

	out->n_part = 0;
	out->n_part_total = 0;
	if (!sc || !sc->eng || !sc->diag.xm || i >= sc->eng->n_diag || out->state != KOF_DIAG_ST_MATCH)
		return;
	d = &sc->eng->diag[i];
	f = d->form;
	if (!f)
		return;
	fp = kof_parser_of(ctx->format);
	memset(&w, 0, sizeof w);
	w.out = out;
	w.fp = fp;
	w.ctx = ctx;
	for (k = 0; k < f->n_match && k < KOF_DIAG_REPORT_MATCH; k++) {
		const struct kof_form_match *m = &f->match[k];

		if (sc->diag.xm[i][k].result == KDET_M_NOT_ASKED)
			continue;
		if (m->kind == KOF_FORM_M_FIND && m->rule == KOF_FORM_R_AT)
			continue;               /* a marker at an offset: the matcher's answer is the place; not listed */
		for (a = 0; a < m->n; a++) {
			struct kof_diag_part *part;

			total++;
			if (out->n_part >= KOF_DIAG_REPORT_PARTS)
				continue;
			part = &out->part[out->n_part];
			memset(part, 0, sizeof *part);
			part->matcher = (uint8_t)k;
			if (m->kind == KOF_FORM_M_FIND) {
				const struct kof_form_str *s = &f->str[m->arg[a]];
				struct kof_str_ent e;
				const uint8_t *bytes = f->pool + s->off;
				struct kof_ext_buf *eb = kof_scan_ext_buf(sc, 0);
				uint32_t n, j, nosym = m->mask & ~KOF_SCAN_SYM;

				memset(&e, 0, sizeof e);
				e.len = s->len;
				e.kind = s->kind;
				e.flags = s->flags;
				part->kind = KDET_P_MARKER;
				part->id = m->arg[a];
				part->n = s->len;
				part->mask = m->mask;
				part->mask_name = mname(fp, m->mask);
				n = nosym ? kof_scan_resolve_range(ctx, nosym, eb) : 0u;
				for (j = 0; j < n && !part->place; j++) {
					uint64_t at = kof_match_where(&sc->match.m, eb->v[j].off, eb->v[j].len, bytes, e.len, e.kind, e.flags);

					if (at != KGENOME_BROKEN) {
						part->place = 1;
						part->off = at;
						part->plen = e.len;
						part->region = 0;
					}
				}
				part->hit = (uint8_t)(part->place || ((m->mask & KOF_SCAN_SYM) && oc_find_str_mask(ctx, m->mask, &e, bytes)));
			} else {
				const struct kof_form_block *b = &f->block[m->arg[a]];
				uint32_t gi = f->blk_base + m->arg[a];
				/* The form's own hashes are not kept (MEM-1): the engine's copy is, in the pool the matcher borrows. */
				const struct kof_mutation_block *eb_ = gi >= sc->eng->n_blk && gi - sc->eng->n_blk < sc->eng->n_dblk
					? &sc->eng->dblk[gi - sc->eng->n_blk] : NULL;
				const uint32_t *hh = eb_ ? sc->eng->dpool + eb_->first_hash : NULL;

				if (!hh) {
					continue;           /* not reachable for a loaded form; never read a table past its end */
				}
				part->kind = KDET_P_BLOCK;
				part->id = kof_mutation_fold(hh, b->n_hash);
				part->n = b->n_hash;
				part->mask = b->mask;
				part->mask_name = mname(fp, b->mask);
				part->side = b->side;
				part->pct = (uint8_t)kof_mutation_pct(&sc->mutation, gi);
				part->matched = kof_mutation_matched(&sc->mutation, gi);
				{
					/* pct is matched / n as the matcher counted them: for a block a function unit held by shape, `n` is the elements of
					 * the union the estimate was made over (kof_mutation_counts), which is not always the block's own count */
					uint32_t seen_, n_;

					if (kof_mutation_counts(&sc->mutation, gi, &seen_, &n_) && n_)
						part->n = (uint16_t)n_;
				}
				part->hit = (uint8_t)(part->pct >= m->thresh);
				w.p[w.n_p].hash = hh;
				w.p[w.n_p].n = b->n_hash;
				w.p[w.n_p].mask = b->mask;
				w.p[w.n_p].side = b->side;
				w.p[w.n_p].idx = out->n_part;
				w.n_p++;
			}
			out->n_part++;
		}
	}
	out->n_part_total = (uint8_t)(total > 255u ? 255u : total);
	if (w.n_p) {
		kof_buf b = kof_src_buf(sc->cur.src);

		w.bytes = b.p;
		w.n_bytes = b.n;
		w.syms = kof_src_syms_of(sc->cur.src, &w.n_syms);
		if (!b.p)
			return;
		if (sc->cur.from_packer) {
			(void)unit_cb(&w, KOF_SCAN_ALL, 0, b.n, KGENOME_MUTATION_SIDE_USER, NULL);
		} else {
			struct kof_scan_cut cut;

			sx_feed_cut(sc, ctx, sc->cur.present, 0, &cut);
			w.cfg = cut.cfg;
			kof_scan_mutation_units(ctx, b, sc->cur.present, &cut, kof_scan_ext_buf(sc, 1), unit_cb, &w);
		}
	}
}
