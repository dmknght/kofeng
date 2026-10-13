/*
 * kofabi.h - the ABI version a module is built against, and the level a
 * finding is asserted at.
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
 * `ovl_strings` sat between mutation_score and ovl_blocks and is gone, so every
 * slot after it moved up one; `ovl_shape` was appended at the end in the same
 * change. Both halves of this number move because the first of those is the
 * removal the note above describes, and a module built against ABI 2 would
 * call ovl_blocks where it meant ovl_strings.
 *
 * The view structs moved too, which would have been reason enough on its own:
 * struct kof_mutation_desc lost its string pool, struct kof_mutation_region lost the
 * slice that indexed it, struct kof_ovl_vec lost the two string dimensions,
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
 * How strongly a finding is asserted.
 *
 * A level rather than a separate verdict, because the difference between "this is
 * the family" and "this looks like it" is a property of the finding and not of the
 * control flow. Both are reported the same way and named the same way, so there is
 * one mechanism and one table instead of two that must agree.
 */
enum kof_level {
	KOF_LVL_SUSPECT = 0, /* worth noting; not a detection */
	KOF_LVL_INFECT  = 1, /* the family is identified */
	/*
	 * A shape clean software does not have, with nothing identified.
	 *
	 * Reported only by a heuristic rule - see kofmod/heur.h - and a detector
	 * that tried would be refused by the build. The value matches
	 * KOF_LEVEL_HEUR in kofeng.h because the host passes the module's level
	 * straight through; the two enums are one enum written twice, once for
	 * each side of the ABI.
	 */
	KOF_LVL_HEUR    = 2,

	/*
	 * FIRED FOR THE ACTION, NOT FOR A VERDICT - see KOF_HEUR_ACT.
	 *
	 * The rule's ask is honoured and NOTHING is reported. It is a LEVEL and
	 * not a declaration on the module because the same rule needs both
	 * answers on different objects: an ELF carrying a second file is a
	 * reason to carve every time and a reason to conclude only when the
	 * passenger is most of the file. One rule, one measurement, two
	 * outcomes - which cannot be said in KOF_HEUR_WANT, because that is
	 * read out of the source at build time and is the same on every object.
	 *
	 * Above KOF_LVL_HEUR in value and below it in meaning; nothing orders
	 * these, the host branches on them.
	 */
	KOF_LVL_ACT     = 3
};

#endif /* KOFENG_KOFABI_H */
