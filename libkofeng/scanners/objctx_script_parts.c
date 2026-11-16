/*
 * objctx_script_parts.c - a script's ONE product of its text: the function table and the islands from one lex (celllysis/script_islands.h),
 * made on the first ask of the function table (objctx_diag.c's funcs_of) and read by every consumer of the object: the similarity cut
 * (scan_feed.c), the obfuscation measure (objctx_textscan.c). The islands are charged to the object's ledger and given back with it.
 */

#include "../kofcore/kofdebug.h"
#include "../analyzers/parsers/scripts/script_route.h"
#include <celllysis/script_islands.h>
#include <kofmod/script.h>

#include "objctx_int.h"
#include <stdlib.h>
#include <string.h>

/*
 * A SCRIPT'S FUNCTION TABLE AND ITS ISLANDS, from one lex. The islands are charged to the ledger for the object's life and given back
 * with it (oc_script_islands_drop); a table the ledger cannot hold is not kept, and the object says a limit fired: the similarity cut
 * then reads the whole object as one unit, as it did for a script with no islands.
 */
void oc_script_parts(struct kof_scanner *sc, const struct kof_obj_ctx *ctx)
{
	struct kgenome_script_parts parts;
	uint64_t isl_bytes;

	kof_script_parts_build(ctx, sc->match.m.data.p, sc->match.m.data.n,
			       KGENOME_SCRIPT_PART_ISLANDS | KGENOME_SCRIPT_PART_CLIENT, &parts);
	sc->obj.sym.funcs = parts.funcs;
	memset(&parts.funcs, 0, sizeof parts.funcs);
	isl_bytes = parts.bytes + sizeof *sc->obj.sym.isl;
	if (parts.isl.status == KGENOME_OK && kof_script_textual_lang(ctx->subtype) && isl_bytes <= oc_scan_room(sc))
		sc->obj.sym.isl = malloc(sizeof *sc->obj.sym.isl);
	if (sc->obj.sym.isl) {
		*sc->obj.sym.isl = parts.isl;
		memset(&parts.isl, 0, sizeof parts.isl);
		scan_charge(sc, isl_bytes);
		sc->obj.sym.isl_charged = isl_bytes;
	} else if (kof_script_textual_lang(ctx->subtype)) {
		OC_LIMIT(sc, "script islands: not built or over the memory ceiling");
	}
	kgenome_script_parts_free(&parts);
}

const struct kgenome_script_islands *oc_script_islands(const struct kof_obj_ctx *ctx)
{
	struct kof_scanner *sc = kof_scan_of(ctx);

	if (!sc || ctx->format != KOF_FMT_SCRIPT)
		return NULL;
	(void)oc_funcs(ctx);
	return sc->obj.sym.isl;
}

void oc_script_islands_drop(struct kof_scanner *sc)
{
	if (!sc->obj.sym.isl)
		return;
	kgenome_script_islands_free(sc->obj.sym.isl);
	free(sc->obj.sym.isl);
	sc->obj.sym.isl = NULL;
	oc_scan_release(sc, sc->obj.sym.isl_charged);
	sc->obj.sym.isl_charged = 0;
}

