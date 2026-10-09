/*
 * apihash_pe_00.c - the APIs a Windows program finds for itself, put back in
 * its description.
 *
 * A program that walks the loader data to find its own functions has none of
 * them in its import table, and what stands for an API in its code is a number
 * only the program understands: a hash, with a seed, a rotation and a combining
 * step the author picked and can change tomorrow. A static reader sees an
 * object that imports nothing and does a great deal - which is what the author
 * is counting on.
 *
 * IT IS A STEP OF ITS OWN, BESIDE THE DECRYPT ONES. Those take the text a
 * program hides and hand back what it says; this takes the names a program
 * hides and reports which ones - on the object itself, producing nothing, and
 * before anything else looks at the object. See KOF_ANALYZE_RECOVER for why a
 * convicted program, or one a decrypt module has already opened, must still be
 * described. The recovery is the engine's - it
 * runs the program's own resolver against the modelled loader, so no hash, seed
 * or rotation appears in this file - and what is left for a module is what a
 * module is for: deciding that the object is one it applies to, and reporting
 * what was found.
 *
 * THE REPORT IS THE OBJECT'S SYMBOLS. kunp_sym_import puts each name where an
 * import the author had written would be, so everything that reads imports - a
 * rule on them, a similarity over them, the result a tool shows - sees the
 * program the way it would if the author had used the import table.
 *
 * A PROGRAM THAT DOES NOT READ THE LOADER DATA COSTS A DECODE. The engine finds
 * the walk by its shape - the thread block read at the offset the PEB is at and
 * a load of PEB.Ldr a few instructions on - before it runs anything, and
 * answers "none" at once for the rest.
 */

#include <kofmod/kofsig.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_RECOVER);

/* The loader data is a Windows thing, and so is the table it replaces. */
KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("API-Hash");

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	char dll[16], fn[48];
	uint32_t i;

	for (i = 0; kunp_api_resolved(i, dll, sizeof dll, fn, sizeof fn); i++)
		kunp_sym_import(dll, fn);
}
