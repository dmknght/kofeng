/*
 * objctx_diag_text.c - the diagnose stage for a script: whether the TEXT route can read it, and its scan.
 *
 * A script is read by its lexer, so it has no relocation table, no functions, no walk and no emulator to hand the scan: the
 * route needs the text and the language, and what it may cost is the object's size. The rest of the stage (the gate, the
 * match, the charge) is the one objctx_diag.c does for every object.
 */

#define _GNU_SOURCE

#include "../analyzers/parsers/scripts/script_route.h"
#include "../analyzers/parsers/scripts/script_apply.h"
#include <textual/textual.h>
#include <celllysis/nucleo.h>
#include <phenotype/diag_scan.h>

#include "objctx_int.h"

/*
 * A SCRIPT THE TEXT ROUTE CAN READ: a language that has a profile row in the lib (kgenome_diag_text_serves). The one question the symbol block, the
 * gate and the route's selection all ask, so it is answered here once and by the one list: a language is added to the route in the lib's table,
 * and nothing in the engine names it.
 */
int oc_text_served(const struct kof_obj_ctx *ctx)
{
	uint32_t lang;
	const struct kof_scanner *sc;

	if (ctx->format != KOF_FMT_SCRIPT)
		return 0;
	lang = kof_script_textual_lang(ctx->subtype);
	if (!kgenome_diag_text_serves(lang))
		return 0;
	/* A normalised view is the program with its typing taken out, for the markers, and not a second program: the route reads it only where the
	 * language's row says it has something the script has not (php's computed constants). */
	sc = kof_scan_of(ctx);
	return !sc || !sc->cur.src || kof_src_kind_of(sc->cur.src) != KOF_ENT_NORMALIZED || kgenome_diag_text_reads_view(lang);
}

/* Which capability an import of an object is, by the object's own table of names: a script's is its language's - and the tables of the objects it makes (COM), from the same row. */
uint16_t oc_name_cap(const struct kof_obj_ctx *ctx, const char *name)
{
	if (ctx->format == KOF_FMT_SCRIPT)
		return kgenome_diag_text_cap_of_name(kof_script_textual_lang(ctx->subtype), name);
	return kgenome_nucleo_cap_of_name(ctx->format == KOF_FMT_PE ? KGENOME_NUCLEO_T_PE : KGENOME_NUCLEO_T_ELF, name);
}

struct kgenome_diag_scan *oc_diag_scan_text(struct kof_scanner *sc, const struct kof_obj_ctx *ctx, kof_buf b,
					    struct kgenome_budget *kb, enum kgenome_status *refused)
{
	struct kgenome_diag_text_req tq = {
		.base = b.p, .size = b.n, .lang = kof_script_textual_lang(ctx->subtype),
		.budget = kb, .refused = refused, .apply = kof_script_apply
	};
	struct kgenome_diag_scan *held;

	kgenome_budget_default(kb, b.n, 0);
	kb->max_bytes = oc_scan_room(sc);
	kof_prod_ran(sc, KOF_PROD_DIAG);
	/* the constants stage walked this text already and kept its scan: the graph is the same whichever callbacks were set */
	held = oc_text_take(sc, tq.lang, b);
	if (held)
		return held;
	return kgenome_diag_scan_text(&tq);
}
