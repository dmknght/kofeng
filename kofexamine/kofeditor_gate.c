#define _GNU_SOURCE

/*
 * kofeditor_gate.c - the gate of the signature on the draft: what the engine offers, what the draft states, and how one
 * condition reads (owner, 2026-11-17: "add thêm anomalies để check", "add được nucleo từ trong list nucleo thấy được từ file").
 *
 * NOTHING HERE WORKS OUT A FACT. The anomalies are the engine's word for the object (kof_result.anomalies, the word the gate is
 * answered from, named by its format's parser); the nucleo are the engine's list for the object (kdet_nucleo_seen); whether
 * a condition is one the engine can check is the engine's one check (kof_diag_gate_valid). The draft keeps the conditions in
 * the record's own type (struct kof_diag_when), and the generator writes them through the shared printer (draft_unit_items,
 * kof_dsrc_print); the engine evaluates them (scanners/objctx_diag_gate.c). What is here is only which of the offers the
 * draft does not state yet - a list that offers what it would refuse lies about itself.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h); the types and what the parts share are in kofeditor_private.h.
 */

#include "kofeditor_private.h"
#include "../libkofeng/analyzers/parsers/kofformat.h"
#include "../libkofeng/detectors/linkage/kofdiag.h"
#include <celllysis/nucleo.h>

static int gate_has(const struct kof_editor *e, uint16_t fact, uint64_t val)
{
	uint32_t i;

	for (i = 0; i < e->dr.n_gate && i < KOF_DIAG_MAX_WHEN; i++)
		if (e->dr.gate[i].fact == fact && e->dr.gate[i].val == val)
			return 1;
	return 0;
}

/* One offer: counted always, written while there is room. */
static void offer_put(struct kof_diag_when *out, uint32_t cap, uint32_t *n, uint16_t fact, uint64_t val)
{
	if (out && *n < cap) {
		out[*n].fact = fact;
		out[*n].val = val;
	}
	(*n)++;
}

uint32_t draft_gate_offer(const struct kof_editor *e, uint16_t fact, const struct kof_result *res, struct kof_diag_when *out,
			  uint32_t cap)
{
	uint32_t n = 0, k, total;

	if (!e || !res)
		return 0;
	if (fact == KOF_FACT_ANOMALY) {
		/* A bit of the word, in bit order, that the engine can check (kof_diag_gate_valid: its parser names it). */
		for (k = 0; k < 64u; k++) {
			uint64_t val = ((uint64_t)res->anomaly_fmt << 32) | k;

			if (((res->anomalies >> k) & 1u) && !gate_has(e, fact, val) && kof_diag_gate_valid(fact, val))
				offer_put(out, cap, &n, fact, val);
		}
		return n;
	}
	if (fact == KOF_FACT_NUCLEO) {
		uint16_t *caps;

		total = kdet_nucleo_seen(res, NULL, 0);
		if (!total)
			return 0;
		caps = malloc((size_t)total * sizeof *caps);
		if (!caps)
			return 0;
		total = kdet_nucleo_seen(res, caps, total);
		for (k = 0; k < total; k++)
			if (!gate_has(e, fact, caps[k]) && kof_diag_gate_valid(fact, caps[k]))
				offer_put(out, cap, &n, fact, caps[k]);
		free(caps);
	}
	return n;
}

int draft_gate_add(struct kof_editor *e, uint16_t fact, uint64_t val)
{
	if (!e || (fact != KOF_FACT_ANOMALY && fact != KOF_FACT_NUCLEO) || !kof_diag_gate_valid(fact, val) ||
	    gate_has(e, fact, val) || e->dr.n_gate >= KOF_DIAG_MAX_WHEN)
		return 0;
	e->dr.gate[e->dr.n_gate].fact = fact;
	e->dr.gate[e->dr.n_gate].val = val;
	e->dr.n_gate++;
	return 1;
}

size_t draft_gate_text(const struct kof_diag_when *w, char *out, size_t cap)
{
	int n = 0;

	if (!w || !out || !cap || !kof_diag_gate_valid(w->fact, w->val))
		return 0;
	if (w->fact == KOF_FACT_ANOMALY) {
		const struct kof_parser *p = kof_parser_of((uint8_t)(w->val >> 32));

		n = snprintf(out, cap, "%s %s", kof_format_name((uint8_t)(w->val >> 32)), p->anomaly_name((unsigned)(w->val & 63u)));
	} else if (w->fact == KOF_FACT_NUCLEO) {
		n = snprintf(out, cap, "%s", kgenome_nucleo_cap_name((uint16_t)w->val));
	}
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}
