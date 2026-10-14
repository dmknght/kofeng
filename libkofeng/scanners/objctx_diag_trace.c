/*
 * objctx_diag_trace.c - WHICH DIAGNOSE WAS CALLED, said the same way for every one.
 *
 * Nothing here is per diagnose: a diagnose is a generated definition (kofviewer,
 * kofeditor, ksigbuilder --diagnose) and carries no code of its own, so the trace lives
 * where the ENGINE asks, gates, routes and answers, and reads everything from the loaded
 * database (kof_diag: id, name, declared analyses, signs). One line per diagnose and
 * event, a stable greppable shape:
 *
 *   [diag] <name> id=<8 hex> asked-by=<module family|-> gate=<open|closed:<signs>>
 *          routes=<declared analyses> route=<the route the scan ran> insn=<spent|->
 *          stop=<scan status> answer=<yes|no|unknown>
 *
 *   asked-by  the module whose kof_diag / kof_diag_share / name read caused this call
 *             ("-": the verdict stage, or no module - kof_scan_diag_force)
 *   gate      open, or closed with the kinds of sign it declares that kept it shut
 *             (needcap, when, ref); WHICH of them failed is not kept by the gate, which
 *             stores one bit per diagnose
 *   routes    what the diagnose DECLARED: syscall, symbol, apihash from its analysis
 *             bits, and `emu` when it declared KOF_DIAG_USE_EMU (the diagnose needs
 *             emulation to analyse its subject; it says nothing about the file)
 *   route     emulate when the scan ran the emulate route for this diagnose, else
 *             static; `-` when the gate was closed and nothing ran for it
 *   insn      `-`: the instructions spent are not exposed by libgenome (the budget is,
 *             in kgenome_budget.max_insn)
 *   stop      the scan's status name (ok, truncated, over-budget, nomem, ...) - ONE
 *             status for the whole scan, not per route
 *   answer    unknown when the scan was cut and the diagnose said no (diag.unk)
 *
 * The same line goes two ways: KOF_TRACE (a DEBUG build) and the debug callback
 * (kscan_on_debug) as the fact "diag" - `kverdict_fact_id("diag")`, `what` the line
 * after "[diag] ", `value` 1 yes / 0 no / 2 unknown - so a tool shows it in a release
 * build when the host registered one. Unset, the cost is a NULL test.
 */

#define _GNU_SOURCE

#include "objctx_int.h"
#include "../detectors/linkage/kofdiag.h"
#include <stdio.h>
#include <string.h>

static void emit(struct kof_scanner *sc, const struct kof_diag *d, const char *gate,
		 const char *route, const char *stop, const char *answer)
{
	char line[400], routes[48], by[64];
	const char *fam = sc->mod.cur ? kof_db_family(sc->eng, sc->mod.cur) : NULL;
	int n = 0;

	routes[0] = 0;
	if (d->analysis & KOF_DIAG_ANALYSIS_SYSCALL)
		n += snprintf(routes + n, sizeof routes - (size_t)n, "%ssyscall", n ? "," : "");
	if (d->analysis & KOF_DIAG_ANALYSIS_SYMBOL)
		n += snprintf(routes + n, sizeof routes - (size_t)n, "%ssymbol", n ? "," : "");
	if (d->analysis & KOF_DIAG_ANALYSIS_APIHASH)
		n += snprintf(routes + n, sizeof routes - (size_t)n, "%sapihash", n ? "," : "");
	if (d->analysis & KOF_DIAG_USES_EMU)
		n += snprintf(routes + n, sizeof routes - (size_t)n, "%semu", n ? "," : "");
	if (!n)
		snprintf(routes, sizeof routes, "-");
	snprintf(by, sizeof by, "%s", fam && fam[0] ? fam : "-");
	snprintf(line, sizeof line,
		 "%s id=%08x asked-by=%s gate=%s routes=%s route=%s insn=- stop=%s answer=%s",
		 d->name ? d->name : "?", (unsigned)d->id, by, gate, routes, route, stop, answer);
	KOF_TRACE("[diag] %s\n", line);
	if (sc->debug_cb)
		sc->debug_cb(kof_fact_id("diag"), line,
			     answer[0] == 'y' ? 1u : answer[0] == 'n' ? 0u : 2u, sc->debug_user);
}

/* One diagnose's line: the gate from its bit and its declared signs, the route from what
 * the scan ran, the answer from the hit and unknown bits. */
static void line_of(struct kof_scanner *sc, uint32_t i, int ran)
{
	const struct kof_diag *d = &sc->eng->diag[i];
	const char *stop = kgenome_status_name(sc->obj.diag.status);
	char gate[40];
	int open = ((sc->diag.gate[i >> 3] >> (i & 7u)) & 1u) != 0;
	int hit = ((sc->diag.hit[i >> 3] >> (i & 7u)) & 1u) != 0;
	int unk = sc->diag.unk && ((sc->diag.unk[i >> 3] >> (i & 7u)) & 1u);

	if (open)
		snprintf(gate, sizeof gate, "open");
	else
		snprintf(gate, sizeof gate, "closed:%s%s%s%s%s%s",
			 d->n_needcap ? "needcap" : "", d->n_needcap && (d->n_when || d->n_ref) ? "+" : "",
			 d->n_when ? "when" : "", d->n_when && d->n_ref ? "+" : "",
			 d->n_ref ? "ref" : "",
			 !d->n_needcap && !d->n_when && !d->n_ref ? "file-shape" : "");
	emit(sc, d, gate, !open || !ran ? "-" : (d->analysis & KOF_DIAG_USES_EMU) ? "emulate" : "static",
	     stop, hit ? "yes" : unk ? "unknown" : "no");
}

/*
 * THE ANALYSIS RAN FOR THIS OBJECT: one line per diagnose something reads (or every
 * diagnose, when the caller asked for the report), once per object. Called after every
 * site that can have run it - a rule's question, the verdict stage, the syndrome.
 */
void oc_diag_trace_scan(struct kof_scanner *sc)
{
	uint32_t i;

	if (!(KOF_TRACING || sc->debug_cb) || !sc->obj.latch[KOF_OL_DIAG] || sc->obj.diag.traced ||
	    !sc->eng)
		return;
	sc->obj.diag.traced = 1;
	for (i = 0; i < sc->eng->n_diag && i < sc->diag.cap; i++) {
		if (!sc->obj.diag.all && sc->eng->diag[i].users_known && !sc->eng->diag[i].n_users &&
		    !sc->eng->diag[i].disease)
			continue;
		line_of(sc, i, sc->obj.diag.graph != NULL);
	}
}

/* A rule asked diagnose slot `i`: its line again, with the asker and the answer it got. */
void oc_diag_trace_ask(struct kof_scanner *sc, uint32_t i)
{
	if (!(KOF_TRACING || sc->debug_cb) || !sc->eng || i >= sc->eng->n_diag || i >= sc->diag.cap)
		return;
	line_of(sc, i, sc->obj.diag.graph != NULL);
}
