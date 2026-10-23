/*
 * objctx_diag_query.c - the questions a rule asks about a diagnose: its slot, whether two
 * meet at a node, whether it carries a name, whether it matched. Split from
 * objctx_diag.c; the text is unchanged.
 */

#define _GNU_SOURCE

#include "../detectors/linkage/kofdiag.h"

#include "objctx_int.h"
#include "../analyzers/genome_obj.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * DO TWO DIAGNOSES MEET AT A NODE OF THIS CAPABILITY - see kof_diag_share.
 *
 * THE CAPABILITY IS PART OF THE QUESTION and not a filter bolted on. "The
 * stager's read and the socket's read are the same read" is the claim; "the
 * two have some node in common" is a weaker one that a shared allocation or
 * a shared resolve would also satisfy, and those are what a packed binary is
 * full of. Naming the node makes the verdict say which shape it means, and
 * it is the reason a diagnose no longer declares its own join points: the
 * pair is known at the verdict, never at the declaration.
 */
/*
 * THE SLOT OF THE DIAGNOSE A RULE NAMED. `wide` says what `id` is: the full 32-bit
 * id (kof_diag_id32_, what the macros pass) or the 16-bit fold an older module's
 * slots take (kof_diag_fold16_ of it). The slot is the diagnose's position and
 * what every bitmap here is indexed by; n_diag when none carries the id. The first
 * match wins, which only matters to a 16-bit caller - two diagnoses that fold
 * alike can both be loaded now, and the old slots cannot tell them apart.
 */
static uint32_t diag_slot(const struct kof_scanner *sc, uint32_t id, int wide)
{
	uint32_t i;

	for (i = 0; i < sc->eng->n_diag && i < sc->diag.cap; i++)
		if ((wide ? sc->eng->diag[i].id
			  : (uint32_t)kof_diag_fold16_(sc->eng->diag[i].id)) == id)
			return i;
	return sc->eng->n_diag;
}

static int diag_share_q(const struct kof_obj_ctx *ctx, uint16_t cap,
			uint32_t a, uint32_t b, int wide)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t ia, ib;

	if (!sc || !cap || !a || !b)
		return 0;
	/* ASKING IS THE DEMAND, exactly as in oc_diag - this is the same
	 * question about two diagnoses, and it used to call oc_diag_ready
	 * without setting the flag it is gated on, so a rule whose ONLY
	 * diagnose call was this one read an analysis that never ran. */
	oc_diag_demand(sc);
	oc_diag_ready(sc, ctx);
	oc_diag_trace_scan(sc);
	ia = diag_slot(sc, a, wide);
	ib = diag_slot(sc, b, wide);
	if (ia >= sc->eng->n_diag || ib >= sc->eng->n_diag)
		return 0;
	if (!((sc->diag.hit[ia >> 3] >> (ia & 7u)) & 1u) ||
	    !((sc->diag.hit[ib >> 3] >> (ib & 7u)) & 1u))
		return 0;
	/*
	 * REACHABILITY, not a shared node - see kof_diag_flow_join. The byte
	 * a socket read produced (a node of `cap` that NETRECV `b` bound)
	 * must flow into the region MEMEXEC `a` is about, and a scratch
	 * buffer between the read and the region is links in the middle that
	 * still link, not a break. The old test here asked only whether one
	 * node was bound by both, which a scratch buffer steps around.
	 */
	return kof_diag_flow_join(sc->obj.diag.graph, cap,
				  sc->diag.bind[ia], sc->diag.n_bind[ia],
				  sc->diag.bind[ib], sc->diag.n_bind[ib]);
}

int oc_diag_share(const struct kof_obj_ctx *ctx, uint16_t cap,
		  uint16_t a, uint16_t b)
{
	return diag_share_q(ctx, cap, a, b, 0);
}

int oc_diag_share32(const struct kof_obj_ctx *ctx, uint16_t cap,
		    uint32_t a, uint32_t b)
{
	return diag_share_q(ctx, cap, a, b, 1);
}

/*
 * DOES THIS DIAGNOSE MATCH, AND DOES IT CARRY THESE NAMES - see
 * kof_diag_str_any and _all in kofsig.h for what the answer means, and why false is
 * not the same as "no".
 *
 * A diagnose's names are the ones the analysis read at the call sites its
 * tree BOUND: each name is kept with the node of the call it was handed to,
 * and the diagnose is the thing that says which of those calls it is about.
 *
 * ASKING IS THE DEMAND, as in every other call that reads the analysis, and
 * it is also what labels the finding Diagnose, so the flag is set here.
 */
static int diag_str_q(const struct kof_obj_ctx *ctx, uint32_t id, const char *name,
		      int wide)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	const struct kof_diag *d = NULL;
	uint32_t i;

	if (!sc || !sc->eng || !id || !name)
		return 0;
	oc_diag_demand(sc);
	oc_diag_ready(sc, ctx);
	oc_diag_trace_scan(sc);
	i = diag_slot(sc, id, wide);
	if (i >= sc->eng->n_diag || i >= sc->diag.cap)
		return 0;
	/* The diagnose has to have matched: a name beside a behaviour that did
	 * not happen is not evidence of it. */
	if (!((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u) || !sc->obj.diag.graph)
		return 0;
	d = &sc->eng->diag[i];
	/*
	 * THE NAMES THIS DIAGNOSE CARRIES are the ones read at the call sites
	 * its tree bound - see kof_diag_scan_name - and not the ones handed to
	 * any call of the same capability. It used to be the second: a
	 * diagnose's names were those tagged with a capability one of its
	 * nodes named, so two diagnoses with a node of the same capability
	 * saw each other's.
	 */
	return kof_diag_scan_name(sc->obj.diag.graph, d, name);
}

int oc_diag_str(const struct kof_obj_ctx *ctx, uint16_t id, const char *name)
{
	return diag_str_q(ctx, id, name, 0);
}

int oc_diag_str32(const struct kof_obj_ctx *ctx, uint32_t id, const char *name)
{
	return diag_str_q(ctx, id, name, 1);
}

static int diag_q(const struct kof_obj_ctx *ctx, uint32_t id, int wide)
{
	struct kof_scanner *sc = kof_scan_of(ctx);
	uint32_t i;

	/* Ids are one based, because zero is what an uninitialised field
	 * holds and a rule that asked for diagnose zero by accident would
	 * otherwise be asking a real question. */
	if (!sc || !id)
		return 0;
	/*
	 * THE MODULE ASKING IS THE ASKER - see oc_diag_demand.
	 *
	 * A signature runs before any heuristic does, so a rule reading a
	 * diagnose cannot wait for one to turn the analysis on: it would
	 * read the answer of an analysis that has not happened and get no.
	 * Naming a diagnose in a rule IS the demand, and it is as scoped as
	 * the rule - a rule targeting ELF asks on ELF and nowhere else.
	 */
	oc_diag_demand(sc);
	oc_diag_ready(sc, ctx);
	/* The id is the name's hash, not a position - see kof_diag_id32_. The bit
	 * is still the diagnose's slot, which is its position. */
	i = diag_slot(sc, id, wide);
	if (i >= sc->eng->n_diag)
		return 0;
	oc_diag_trace_scan(sc);
	oc_diag_trace_ask(sc, i);
	return (sc->diag.hit[i >> 3] >> (i & 7u)) & 1u;
}

int oc_diag(const struct kof_obj_ctx *ctx, uint16_t id)
{
	return diag_q(ctx, id, 0);
}

int oc_diag32(const struct kof_obj_ctx *ctx, uint32_t id)
{
	return diag_q(ctx, id, 1);
}
