/*
 * objctx_diag_gate.c - THE GATE OF A SIGNATURE: conditions a diagnose states about what the ENGINE reported for an object.
 *
 * Owner, 2026-11-17: "bổ sung cơ chế gate mạnh trong signature generation"; the viewer adds "anomalies để check" and "nucleo
 * từ trong list nucleo thấy được từ file". A gate is a DECLARATION the engine evaluates ("chỉ cần thiết kế được gate ở dạng
 * option là ổn chứ không cần phải VM") and a NECESSARY condition: it must not block a real variant, which is why a condition
 * the engine could not look at is UNKNOWN and never NO.
 *
 * TWO CONDITIONS, carried as facts of the record (KOF_FACT_ANOMALY, KOF_FACT_NUCLEO in KDIG_SEC_WHEN, kofmod/kofdiagtree.h;
 * no section, layout or version moved):
 *
 *   ANOMALY  the object's parse raised this anomaly of this format: the word of the view the scan holds (oc_obj_anomalies,
 *            the word kof_result.anomalies publishes - for a normalised view the parent's description it inherits).
 *            Answered with the shape (oc_diag_when_met), before anything is searched. UNKNOWN when the object is another
 *            format (that format's parse did not run on it) or no view was kept.
 *   NUCLEO   the diagnose analysis made a node of this capability, exactly: the graph the scan holds (sc->obj.diag.graph),
 *            the nodes kof_result.lineage copies for a tool and kdet_nucleo_seen lists. Asked only after the form's
 *            expression answered yes, so a sample its markers rule out pays nothing; the form then WAITS (oc_diag_gate_defer:
 *            the declaration asks for the analysis, with the routes the author's list is made by, oc_diag_author_routes)
 *            and is settled at the ANALYSE stage, from the analysis made there (oc_diag_gate_settle). YES when a node has
 *            the capability; NO only when the graph is whole (KGENOME_OK) and every one of those routes ran; else UNKNOWN
 *            - no route for the object, the analysis refused or cut, or the analysis made before with fewer routes (a
 *            module reached for it first: it is made once per object), or a normalised view adopted a parent graph made
 *            without them. The last two are the SCOPE LIMIT of an ask made by the expression; the next algorithm is to ask
 *            for the author's routes at EXAMINE for every object whose shape a nucleo-gated form has (a cost to measure).
 *            A rule that reads a waiting form through kof_diag before ANALYSE reads no, as it reads a similarity form
 *            before SIMILAR.
 *
 * THE SOURCE (databases/diagsrc.c reads and prints it, the macros are kofmod/kofdiagtree.h's), one condition a line:
 *
 *     KOF_DIAG_HAS_ANOMALY(KOF_FMT_ELF, SECTAB_MISSING);   value (format << 32) | bit, the bit its parser names so
 *     KOF_DIAG_HAS_NUCLEO(KOF_NUCLEO_ALLOC_EXEC);          value the capability; a condition of a detection form only
 *
 * A name the format's parser does not have, a capability nucleo does not have, NONE, the same condition twice, more
 * conditions than a record holds and a nucleo condition on a graph are refused by the reader; a record carrying one is
 * refused by the loader (kof_diag_gate_valid, the one check of both).
 *
 * THE OTHER CONDITIONS a diagnose states (format, subtype, size, architecture, permissions...) are the engine's facts
 * (fact_holds, moved here from objctx_diag.c with oc_diag_when_met: this unit is the conditions of a diagnose, objctx_diag.c
 * the analysis). Their YES / NO answers did not change.
 *
 * WHAT A STATE COUNTS AS and HOW THE CONDITIONS COMBINE are the two owner decisions; each is written once, below, where it
 * is taken.
 */

#include "../kofcore/kofdebug.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include "objctx_int.h"
#include "../detectors/linkage/kofdiag.h"
#include "../analyzers/parsers/kofformat.h"
#include <string.h>

_Static_assert(KOF_DIAG_REPORT_GATE == KOF_DIAG_MAX_WHEN, "a report holds every condition a record may state");

/*
 * ---- THE FACTS THE ENGINE PUBLISHES ABOUT AN OBJECT ---------------------
 *
 * One question each, answered off the parse, and nothing here knows what
 * any of them is FOR. A diagnose states the condition - see
 * KOF_DIAG_HAS_ATTRB and enum kof_diag_fact - and this only fetches.
 *
 * IT USED TO BE THE OTHER WAY ROUND: a handful of named bits, each one's
 * meaning a few lines of C in this file, and a diagnose could only ask what
 * somebody had already written. One of them, ONE_LOAD, was a compound of
 * three clauses under a single name, so what a diagnose using it actually
 * demanded could not be read off the diagnose - and when one clause turned
 * out to be a build detail rather than a behaviour, nothing in the
 * declaration showed it.
 *
 * A FACT THIS BUILD DOES NOT KNOW ANSWERS NO. The loader refuses a
 * diagnose naming one, so reaching here with an unknown fact means the two
 * ends of the database disagree, and the safe answer to "should the
 * expensive analysis run" is no.
 */
static int fact_holds(const struct kof_obj_ctx *ctx, uint16_t fact,
		      uint64_t want)
{
	const struct kgenome_elf_info *ei = NULL;
	const struct kgenome_pe_info *pi = NULL;
	uint32_t i;

	if (!ctx)
		return 0;
	if (ctx->format == KOF_FMT_ELF) {
		ei = kof_elf(ctx);
		if (!ei || !ei->valid)
			return 0;
	} else if (ctx->format == KOF_FMT_PE) {
		pi = kof_pe(ctx);
		if (!pi)
			return 0;
	}

	switch (fact) {
	case KOF_FACT_ENTRY_PERM:
		/*
		 * EACH FORMAT'S OWN WORD FOR IT. The two permission enums
		 * happen to agree bit for bit and that is not something to
		 * rely on - KGENOME_PERM_X and KGENOME_PE_PERM_X are declared apart
		 * on purpose.
		 */
		if (ei)
			return ((uint64_t)ei->entry_perm & want) == want;
		if (pi)
			return ((uint64_t)pi->entry_perm & want) == want;
		return 0;               /* no answer is not a yes */
	case KOF_FACT_MAP_PERM:
		if (ei) {
			for (i = 0; i < ei->seg_count &&
				    i < KGENOME_ELF_MAX_SEGMENTS; i++)
				if (ei->seg[i].type == 1u &&      /* PT_LOAD */
				    ((uint64_t)ei->seg[i].perm & want) == want)
					return 1;
			return 0;
		}
		if (pi) {
			/* A section, which is where PE declares the same
			 * thing about a mapping. */
			for (i = 0; i < pi->sec_count; i++)
				if (((uint64_t)pi->sec[i].perm & want) == want)
					return 1;
			return 0;
		}
		return 0;
	case KOF_FACT_SECTIONS:
		if (ei)
			return (uint64_t)ei->shnum == want;
		if (pi)
			return (uint64_t)pi->sec_count == want;
		return 0;
	case KOF_FACT_OBJ_KIND:
		if (ei)
			return (uint64_t)ei->e_type == want;
		if (ctx->format == KOF_FMT_SCRIPT || ctx->format == KOF_FMT_PE)  /* BUG FIX 2026-11-10 */
			return (uint64_t)ctx->subtype == want;
		return 0;
	case KOF_FACT_FORMAT:
		return (uint64_t)ctx->format == want;
	case KOF_FACT_SIZE_MIN:
		return ctx->obj_size >= want;
	case KOF_FACT_ARCH_SET:
		return ctx->arch < 64u && ((want >> ctx->arch) & 1u) != 0;
	case KOF_FACT_FORMAT_SET:
		/* A bit per format: the diagnose is for any of them (a form that lives in an ELF, in a script, in a plain text). */
		return ctx->format < 64u && ((want >> ctx->format) & 1u) != 0;
	default:
		return 0;
	}
}

/* Every condition a diagnose stated - see KOF_DIAG_HAS_ATTRB. */
int oc_diag_when_met(const struct kof_obj_ctx *ctx,
		     const struct kof_diag *d)
{
	uint8_t i;

	for (i = 0; i < d->n_when; i++) {
		uint16_t f = d->when[i].fact;

		/* THE GATE'S TWO CONDITIONS: an anomaly is a question about the parse, answered with the shape; a nucleo condition
		 * is asked after the form's expression, at ANALYSE (oc_diag_gate_settle), not here. Every condition is ANDed with
		 * the others - TODO(owner) at gate_after; what UNKNOWN counts as is TODO(owner) at oc_diag_gate_pass. */
		if (f == KOF_FACT_NUCLEO)
			continue;
		if (f == KOF_FACT_ANOMALY) {
			if (!oc_diag_gate_pass(oc_diag_gate_shape(ctx, f, d->when[i].val)))
				return 0;
			continue;
		}
		if (!fact_holds(ctx, f, d->when[i].val))
			return 0;
	}
	return 1;
}


/*
 * TODO(owner): UNKNOWN counted as pass or as fail. Default implemented: UNKNOWN does not block - the gate is a necessary
 * condition, and a variant the engine could not look at (no route, a cut analysis, a format whose parse did not run) is
 * not evidence against the diagnose. Alternative: UNKNOWN blocks (a stricter gate that also blocks what was not seen).
 * Either way UNKNOWN is reported as UNKNOWN (kof_diag_report.gate), never as NO.
 */
int oc_diag_gate_pass(uint8_t state)
{
	return state != KOF_GATE_NO;
}

/*
 * THE OBJECT'S ANOMALY WORD, the one carrier of it: the format's word over the view the scan holds (ctx->file_header is the
 * view of ctx->format - the parser's cast, II.8 - and for a normalised view the parent's description it inherits). The gate
 * answers from it and the result publishes it (kof_result.anomalies, st_publish), so a tool offers what is checked.
 * KOF_FMT_UNKNOWN and 0 when the engine keeps no view of the object.
 */
uint64_t oc_obj_anomalies(const struct kof_obj_ctx *ctx, uint8_t *fmt)
{
	const struct kof_parser *p = ctx ? kof_parser_of(ctx->format) : NULL;

	*fmt = (uint8_t)KOF_FMT_UNKNOWN;
	if (!p || !p->anomalies || !ctx->file_header)
		return 0;
	*fmt = ctx->format;
	return p->anomalies(ctx->file_header);
}

uint8_t oc_diag_gate_shape(const struct kof_obj_ctx *ctx, uint16_t fact, uint64_t val)
{
	uint8_t fmt;
	uint64_t w;

	if (fact != KOF_FACT_ANOMALY || !ctx || (val & 0xffffffc0u) || (val >> 32) > 0xffu)
		return KOF_GATE_UNKNOWN;
	w = oc_obj_anomalies(ctx, &fmt);
	/* No view of that format: that format's parse did not run on this object, so the engine cannot say. */
	if (fmt == (uint8_t)KOF_FMT_UNKNOWN || fmt != (uint8_t)(val >> 32))
		return KOF_GATE_UNKNOWN;
	return ((w >> (val & 63u)) & 1u) ? KOF_GATE_YES : KOF_GATE_NO;
}

/* One nucleo condition against the graph the scan holds: see the note at the top. Reads only; never runs the analysis. */
static uint8_t nucleo_state(const struct kof_scanner *sc, const struct kof_obj_ctx *ctx, uint16_t cap)
{
	const struct kgenome_diag_scan *ds = sc->obj.diag.graph;
	unsigned want;
	uint32_t k, n;

	if (!ds)
		return KOF_GATE_UNKNOWN;
	n = kgenome_diag_scan_count(ds);
	for (k = 0; k < n; k++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(ds, k);

		if (h && h->cap == cap)
			return KOF_GATE_YES;
	}
	want = oc_diag_author_routes(ctx);
	if (!want || (sc->obj.diag.run & want) != want || kgenome_diag_scan_status(ds) != KGENOME_OK)
		return KOF_GATE_UNKNOWN;
	return KOF_GATE_NO;
}

/* Does form diagnose `i` state a nucleo condition. */
static int has_nucleo(const struct kof_diag *d)
{
	uint8_t k;

	for (k = 0; k < d->n_when; k++)
		if (d->when[k].fact == KOF_FACT_NUCLEO)
			return 1;
	return 0;
}

/*
 * THE DECLARATION IS THE ASK, and the answer waits for the analysis: the object's analysis is made ONCE, at the ANALYSE stage
 * (or when a rule reaches for it), with the routes the author's list is made by - so a nucleo condition is answered from the
 * same graph the researcher's list came from (the explain run makes it at the same stage), and not from one made earlier in
 * the pipeline, before the opening stages (measured: an analysis forced at DETECT saw a capability, anti-debug, that the
 * explain run of the same file and database did not list).
 */
int oc_diag_gate_defer(struct kof_scanner *sc, uint32_t i)
{
	if (!sc || !sc->eng || i >= sc->eng->n_diag || !has_nucleo(&sc->eng->diag[i]))
		return 0;
	sc->obj.diag.ask = 1;
	sc->obj.diag.author = 1;
	return 1;
}

/* Every nucleo condition of form diagnose `i`, against the graph the scan holds; 1 when the gate lets it match. */
static int gate_after(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, uint32_t i)
{
	const struct kof_diag *d = &sc->eng->diag[i];
	uint8_t k;

	for (k = 0; k < d->n_when; k++) {
		if (d->when[k].fact != KOF_FACT_NUCLEO)
			continue;
		/*
		 * TODO(owner): the conditions of a gate combine by AND or by OR. Default implemented: AND - every condition must
		 * pass (oc_diag_gate_pass), the anomaly ones with the shape (oc_diag_when_met) and these here; the first that does
		 * not ends the gate. Alternative: OR over the gate's conditions (one passing is enough), which needs the anomaly
		 * answers kept to this point rather than ending the shape test.
		 */
		if (!oc_diag_gate_pass(nucleo_state(sc, ctx, (uint16_t)d->when[k].val))) {
			sc->diag.fgate[i >> 3] |= (uint8_t)(1u << (i & 7u));
			return 0;
		}
	}
	return 1;
}

void oc_diag_gate_settle(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	uint32_t i, n;

	if (!sc || !sc->eng || !sc->eng->n_form)
		return;
	n = sc->eng->n_diag < sc->diag.cap ? sc->eng->n_diag : sc->diag.cap;
	for (i = 0; i < n; i++) {
		const uint8_t bit = (uint8_t)(1u << (i & 7u));
		const struct kof_diag *d = &sc->eng->diag[i];

		/* waiting: the expression said yes, the gate has not answered (neither a hit nor a refusal yet) */
		if (!d->form || !(sc->diag.fexpr[i >> 3] & bit) || ((sc->diag.fhit[i >> 3] | sc->diag.fgate[i >> 3]) & bit) ||
		    !has_nucleo(d))
			continue;
		if (gate_after(sc, ctx, i))
			sc->diag.fhit[i >> 3] |= bit;
		KOF_TRACE("[form] %u %s gate settled: %s\n", (unsigned)i, d->name, (sc->diag.fhit[i >> 3] & bit) ? "pass" : "no");
	}
}

void oc_diag_gate_report(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, uint32_t i, struct kof_diag_report *out)
{
	const struct kof_diag *d;
	uint8_t k, bit;
	int asked;

	if (!sc || !sc->eng || !out || i >= sc->eng->n_diag || i >= sc->diag.cap)
		return;
	d = &sc->eng->diag[i];
	bit = (uint8_t)(1u << (i & 7u));
	/* The nucleo conditions were asked when the form's expression answered yes: it matched (fhit) or the gate said no (fgate). */
	asked = d->form && (sc->diag.fdone[i >> 3] & bit) && ((sc->diag.fhit[i >> 3] | sc->diag.fgate[i >> 3]) & bit);
	out->n_gate = d->n_when < KOF_DIAG_REPORT_GATE ? d->n_when : (uint8_t)KOF_DIAG_REPORT_GATE;
	for (k = 0; k < out->n_gate; k++) {
		uint16_t f = d->when[k].fact;

		if (f == KOF_FACT_ANOMALY)
			out->gate[k] = oc_diag_gate_shape(ctx, f, d->when[k].val);
		else if (f == KOF_FACT_NUCLEO)
			out->gate[k] = asked ? nucleo_state(sc, ctx, (uint16_t)d->when[k].val) : (uint8_t)KOF_GATE_NOT_ASKED;
		else
			out->gate[k] = fact_holds(ctx, f, d->when[k].val) ? (uint8_t)KOF_GATE_YES : (uint8_t)KOF_GATE_NO;
	}
}
