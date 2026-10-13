/*
 * objprod.c - see objprod.h.
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "scan_int.h"
#include <phenotype/lineages.h>
#include "objprod.h"

struct kof_prod {
	uint32_t refs;
	/* The parent's bytes, held because the graph and the apihash read them
	 * for as long as they live. */
	struct kof_objsrc        *src;
	struct kgenome_diag_scan *graph;
	/* The graph let go of the walk's ledger when it is freed, so the walk
	 * lives exactly as long as the graph does. Not adopted by a view: its
	 * trace is in the parent's coordinates. */
	struct kgenome_diag_walk *walk;
	struct kgenome_apihash   *apihash;

	uint8_t diag_done;      /* the parent latched KOF_OL_DIAG      */
	uint8_t gate_done;      /* ... and KOF_OL_DIAG_GATE            */
	uint8_t apihash_done;   /* ... and KOF_OL_APIHASH              */
	uint32_t n_diag, bm;
	uint8_t *bits;          /* hit, gate, unk - bm bytes each      */
	uint8_t *n_bind;
	uint16_t (*bind)[KOF_DB_MAX_DIAG_NODE];
};

void kof_prod_unref(struct kof_prod *p)
{
	if (!p || --p->refs)
		return;
	/* Graph first: freeing it touches the walk it was bound to. */
	kgenome_diag_scan_free(p->graph);
	kgenome_diag_walk_free(p->walk);
	kgenome_apihash_free(p->apihash);
	free(p->bits);
	free(p->n_bind);
	free(p->bind);
	kof_src_unref(p->src);
	free(p);
}

static struct kof_prod *prod_take(struct kof_scanner *sc)
{
	struct kof_prod *p = calloc(1, sizeof *p);
	uint32_t n = sc->diag_cap ? sc->diag_cap : 1u, bm = sc->diag_bm ? sc->diag_bm : 1u;

	if (!p)
		return NULL;
	p->refs = 1;
	p->n_diag = sc->diag_cap;
	p->bm = bm;
	p->bits = malloc(3u * (size_t)bm);
	p->n_bind = malloc(n);
	p->bind = malloc((size_t)n * sizeof *p->bind);
	if (!p->bits || !p->n_bind || !p->bind) {
		kof_prod_unref(p);
		return NULL;
	}
	memcpy(p->bits, sc->diag_hit, bm);
	memcpy(p->bits + bm, sc->diag_gate, bm);
	memcpy(p->bits + 2u * bm, sc->diag_unk, bm);
	memcpy(p->n_bind, sc->diag_n_bind, n);
	memcpy(p->bind, sc->diag_bind, (size_t)n * sizeof *p->bind);
	p->diag_done = sc->latch[KOF_OL_DIAG];
	p->gate_done = sc->latch[KOF_OL_DIAG_GATE];
	p->apihash_done = sc->latch[KOF_OL_APIHASH];
	/*
	 * MOVED, NOT COPIED. These are the parent's products and the parent has
	 * no further use for them: its pipeline is over, its result is built,
	 * and the next thing the scanner does is begin another object. The
	 * scanner's fields are cleared so that beginning it does not free them.
	 */
	if (sc->diag_graph && sc->cur_src && !sc->prod_borrowed) {
		p->graph = sc->diag_graph;
		p->walk = sc->walk;
		p->src = kof_src_ref(sc->cur_src);
		sc->diag_graph = NULL;
		sc->walk = NULL;
		sc->gr_n = 0;
	}
	if (sc->apihash && !sc->prod_borrowed) {
		p->apihash = sc->apihash;
		if (!p->src && sc->cur_src)
			p->src = kof_src_ref(sc->cur_src);
		sc->apihash = NULL;
	}
	return p;
}

void kof_prod_publish(struct kof_scanner *sc)
{
	struct kof_prod *p = NULL;
	uint32_t i;

	for (i = 0; i < sc->n_kids; i++) {
		struct kof_objsrc *k = sc->kids[i];

		if (kof_src_kind_of(k) != KOF_ENT_NORMALIZED || !kof_src_desc_of(k))
			continue;
		if (!p) {
			p = prod_take(sc);
			if (!p)
				return;         /* the view arrives with none */
		} else {
			p->refs++;
		}
		kof_src_declare_prod(k, p);
	}
}

void kof_prod_adopt(struct kof_scanner *sc, const struct kof_prod *p)
{
	uint32_t n = sc->diag_cap ? sc->diag_cap : 1u, bm = sc->diag_bm ? sc->diag_bm : 1u;

	sc->cur_prod = p;
	/* A database of a different size is a different scanner's: nothing to
	 * adopt, and nothing is derived either. */
	if (p->n_diag == sc->diag_cap && p->bm == bm) {
		memcpy(sc->diag_hit, p->bits, bm);
		memcpy(sc->diag_gate, p->bits + bm, bm);
		memcpy(sc->diag_unk, p->bits + 2u * bm, bm);
		memcpy(sc->diag_n_bind, p->n_bind, n);
		memcpy(sc->diag_bind, p->bind, (size_t)n * sizeof *p->bind);
	}
	/*
	 * ALL THREE LATCHED, whether or not the parent took them: a latch says
	 * "this is settled for the object", and for a view it is settled by what
	 * the parent found. Left open, the first reader would run the analysis on
	 * the view's bytes - the very thing this exists to prevent.
	 */
	sc->latch[KOF_OL_DIAG] = 1;
	sc->latch[KOF_OL_DIAG_GATE] = 1;
	sc->latch[KOF_OL_APIHASH] = 1;
	sc->diag_graph = p->graph;
	sc->apihash = p->apihash;
	sc->prod_borrowed = 1;
}

void kof_prod_unadopt(struct kof_scanner *sc)
{
	if (!sc->prod_borrowed)
		return;
	sc->diag_graph = NULL;
	sc->apihash = NULL;
	sc->cur_prod = NULL;
	sc->prod_borrowed = 0;
}
