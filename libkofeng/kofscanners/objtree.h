/*
 * objtree.h - the object tree: which children exist, and where they come from.
 *
 * Named for its subject and not for the option that switches it on. It sits
 * beside objctx.c, which is what a module sees of one object, and objsrc.c,
 * which is where an object's bytes come from; this is how one object comes to
 * have others under it. "Deep scan" is the name of the switch, and a file named
 * after a switch tells a reader nothing about what is in it.
 *
 * WHY THIS IS ITS OWN UNIT AND NOT MORE STATICS IN scan.c.
 *
 * scan.c is the walk and the module loop. Descending is a third thing with its
 * own invariants, and it has a second caller: a host that wants a container's
 * children WITHOUT running a scan - the viewer separating an archive on demand -
 * asks the same questions in the same order and must get the same answers. A
 * static in scan.c cannot be asked, so the second caller would grow a copy, and
 * a copy of a policy is a policy that drifts.
 *
 * It is also where a 240-line unpack_object was heading. That function already
 * ran five unrelated passes in sequence - family-predicted unpack, general
 * unpack, carried-file search, rule-asked emulation, gated emulation - and
 * reading it required holding all five at once. The steps below are named so
 * that the sequence can be read without reading the bodies.
 *
 * WHAT IT DOES NOT DO: decoding. A codec turns coded bytes into original bytes
 * and knows nothing about trees; this decides what to hand a codec and what to
 * do with what comes back. See kof_unpack_at for the other side of that line.
 *
 * THE TWO SOURCES OF A CHILD, and both are here because the ORDER between them
 * is the policy:
 *
 *   DECLARED   the container's structure names it, and the parser read it.
 *              ctx->entries() is that answer. Exact, no guessing.
 *   SEARCHED   nothing names it - a linker put a file in a data section at
 *              compile time - so the engine looks for a header and validates
 *              it. Format independent, which is why it is the engine's.
 *
 * Declared first, searched second, and a search hit that overlaps a declared
 * entry is dropped. Without that order one attachment became two children: the
 * parser declared it and the search found the same bytes again.
 */

#ifndef KOFENG_OBJTREE_H
#define KOFENG_OBJTREE_H

#include "../kofeng.h"
#include <kofmod/kofsig.h>

/*
 * MAY THIS OBJECT BE OPENED AT ALL.
 *
 * The one question that has to be asked before any of the work, and it was
 * being asked in the wrong place: the flag was read only where the walk PUSHES
 * children, so every container was decompressed in full and its children were
 * then discarded. Measured, with a one byte production budget and descending
 * switched off: a gzip was still reported as "the engine could not finish" -
 * the engine paying for, and then failing at, work nobody had asked for.
 *
 * The question is heur_off and not a switch of its own. See kofeng.h: --heur 0
 * is already "name families and nothing else", and what is inside a container
 * is exactly the kind of evidence that level declines.
 */
int kof_objtree_may_open(const struct kof_scan_option *opt);

/*
 * THE CARRIED FILES THIS OBJECT'S STRUCTURE NAMED, opened as children. Returns
 * how many it made.
 *
 * ctx->entries, every row whose kind is KOF_ENT_EMBEDDED, clipped to the object
 * and windowed. Generic: it is the same walk for a PDF's /EF, a zip's central
 * directory and a CFB's directory, because by the time there is an entry table
 * the format is behind it.
 *
 * THE OTHER HALF IS NOT HERE, and that is the design rather than an omission. A
 * file NOBODY declared - one a linker placed in a data section at compile time -
 * is found by looking for its header, and that search is a MODULE:
 * bases/decomp/carried_pe.c declares the format it targets, the regions worth
 * looking in and the magic to look for. It was engine code with the magics
 * written in, and then adding a kind of carried file meant editing the engine
 * while declining to search a format meant a table in the engine naming that
 * format.
 *
 * So the two halves are not symmetrical and should not be: what a structure says
 * is generic and belongs here; what a header looks like and where it is worth
 * looking are format knowledge and belong in the database.
 *
 * ONE FILE PER RANGE, NEVER COALESCED, which is why this does not go through a
 * run list. kof_runs_add merges consecutive runs of one class on purpose, and
 * two carried files that happen to sit next to each other would merge the same
 * way - producing one child holding two files, and a marker that matches across
 * the seam between them, which is a finding about neither.
 */
uint32_t kof_objtree_declared(const struct kof_obj_ctx *ctx,
			      const struct kof_scan_option *opt);

#endif /* KOFENG_OBJTREE_H */
