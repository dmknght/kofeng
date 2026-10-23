/*
 * diag_text_graph.h - reading a TEXT-route scan's graph in a test, shared by the lib test (diag_text.c) and the engine test
 * (tests/unit/diag_text_built.c): one reader, so the two cannot disagree about what a node or a link is.
 */

#ifndef KOFENG_TESTS_DIAG_TEXT_GRAPH_H
#define KOFENG_TESTS_DIAG_TEXT_GRAPH_H

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>

static inline int count(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i, n = 0;

	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		n += kgenome_diag_scan_at(s, i)->cap == cap;
	return (int)n;
}

/* Is there a node of `to` that took a value from a node of `from`, in `role` (any role when it is 0xff). */
static inline int linked(const struct kgenome_diag_scan *s, uint16_t from, uint16_t to, int role)
{
	uint32_t i;
	uint8_t k;

	for (i = 0; i < kgenome_diag_scan_count(s); i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		if (h->cap != to)
			continue;
		for (k = 0; k < h->n_in; k++)
			if (kgenome_diag_scan_at(s, h->in[k].from)->cap == from && (role == 0xff || h->in[k].role == role))
				return 1;
	}
	return 0;
}

/* A node of `cap` that carries the BUILT flag: the name was made by the program. */
static inline int built_node(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i;

	for (i = 0; i < kgenome_diag_scan_count(s); i++)
		if (kgenome_diag_scan_at(s, i)->cap == cap && (kgenome_diag_scan_at(s, i)->flags & KGENOME_NUCLEO_F_BUILT))
			return 1;
	return 0;
}


#endif /* KOFENG_TESTS_DIAG_TEXT_GRAPH_H */
