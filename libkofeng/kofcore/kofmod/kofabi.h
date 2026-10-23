/*
 * kofabi.h - the ABI version a module is built against.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFABI_H
#define KOFENG_KOFABI_H

#include <stdint.h>

/*
 * ABI version, and it covers TWO things a module depends on: the vtable it
 * calls through - struct kof_content - and the LAYOUT of every view struct it
 * reads, kof_zip_info and the rest.
 *
 * TWO NUMBERS, BECAUSE THE TWO BREAK IN OPPOSITE DIRECTIONS.
 *
 * The vtable is append only WHILE IT GROWS: slots are not reordered or given
 * new meaning, so an OLD module in a NEW host is safe by construction - every
 * slot it knows is still where it was - and only the other direction is a
 * hazard: a module built against a newer header calls a slot past the end of
 * the host's table, which is a wild call out of a file. KOFSIG_ABI_VERSION is
 * the ceiling that refuses it.
 *
 * A SLOT CAN ALSO BE TAKEN AWAY, and that breaks the invariant in the same
 * direction a view struct does rather than in the ceiling's direction. Every
 * slot after the hole moves up one, so an old module calls its neighbour: the
 * wrong function, through the wrong prototype, with no crash and no refusal.
 * That is the floor's business, not the ceiling's - see KOFSIG_ABI_MIN - and
 * it is why removing a measure is a floor bump and not merely a rebuild.
 *
 * A VIEW STRUCT IS NOT APPEND ONLY, and that is why a ceiling alone was not
 * enough. When kof_zip_info's entry array became a pointer, every offset after
 * it moved. An old module in a new host then makes NO wild call - it reads
 * `z->entry[i]` at the offset its build put there, gets whatever now lives at
 * that address, and reports on it. No crash, no refusal, no anomaly: a scanner
 * quietly deciding on the wrong bytes, which is worse than one that stops.
 *
 * KOFSIG_ABI_MIN is the floor that refuses that. It is bumped to equal
 * KOFSIG_ABI_VERSION whenever a view struct's layout changes, and left alone
 * when only the vtable grows - so an engine update still reads databases built
 * before it, which is the property the ceiling alone was protecting.
 *
 * BUMPING: add a vtable slot -> raise VERSION only. Remove one, or move,
 * resize or retype any field of any kof_*_info -> raise both.
 */
/*
 * 3 - THE STRING MEASURE WAS TAKEN OUT, AND WITH IT A VTABLE SLOT.
 *
 * The string-measure slot sat between mutation_score and the block-set slot and is
 * gone, so every slot after it moved up one; a shape slot was appended at the end
 * in the same change. Both halves of this number move because the first of those
 * is the removal the note above describes, and a module built against ABI 2 would
 * call the block-set slot where it meant the string measure.
 *
 * The view structs moved too, which would have been reason enough on its own:
 * struct kof_mutation_desc lost its string pool, struct kof_mutation_region lost the
 * slice that indexed it, the block-vector struct lost the two string dimensions,
 * and struct kof_mutation_shape (since removed) gained lib_cut.
 *
 * WHY THE MEASURE WENT is recorded where a researcher will look for it - see
 * the note beside SIM_IT_BLKSET in kofexamine/kofeditor.h, which carries the
 * measurements: it hashed printable runs by their bytes, so any encoding of
 * the strings answered zero, and on a large statically linked binary most of
 * what it collected was not strings at all but printable byte sequences inside
 * machine code that unrelated programs share.
 */
#define KOFSIG_ABI_VERSION 4
#define KOFSIG_ABI_MIN     3

/*
 * A BUMP IS OWED, AND IT IS THE OWNER'S, a SECOND TIME (2026-10-15, the old verdict
 * removal): the module context lost `report` (struct kof_obj_ctx, the slot kept as
 * reserved_0) and the vtable lost seven slots to reserved_3..reserved_9 (the repair
 * and its arithmetic). Nothing moved, so by the rule above only VERSION would need to
 * go up - but a module built before still CALLS those slots and reads NULL, which is a
 * wild call out of a file, so MIN has to equal VERSION as well. And the pack side: the
 * heuristic-rule kind (KOF_PACK_RETIRED_HEUR) is gone and the loader refuses a pack that has
 * one, which is the other half of the same reason.
 *
 * Earlier, and still owed: the zip and pdf views became tables the file sizes
 * (zip.h, pdf.h; KOF_ZIP_INFO_VERSION and KOF_PDF_INFO_VERSION are 2) and the vtable gained
 * `view_next` at its end, so by the rule above both numbers move - VERSION to 5 (a module that
 * walks with kof_zip_next calls a slot an engine of ABI 4 does not have: the slot past the end of
 * its table is read, and what it holds is not defined) and MIN to 5 (a module of ABI 4 reads the
 * views' version 1 layout).
 *
 * What holds without it, and what a test pins (tests/unit/view_oldpack.c): the version 1 head of
 * each view keeps its offsets and the field that counted the rows reads zero, so a module of ABI 4
 * in this engine reads a valid empty table, opens nothing, and the engine reports the object
 * (sx_walk_check) instead of passing it as examined. Raising MIN refuses such a pack at load
 * instead, which is the stronger answer and the one for a view whose fields past the head a
 * third-party module may read.
 */

#endif /* KOFENG_KOFABI_H */
