/*
 * kofsearch.h - searching for declared strings: kof_find_str and its folds,
 * the offset forms, and the anchors an offset is counted from.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFSEARCH_H
#define KOFENG_KOFSEARCH_H

#include <stdint.h>
#include "kofctx.h"

/*
 * One search, normalised to 0 or 1.
 *
 * The host already answers with 0 or 1, and the normalisation is here anyway
 * because kof_find_str_multi adds these together: were find_str ever to return some
 * other non-zero, a count would silently become a sum of arbitrary values, and a
 * threshold written against it would be wrong in a way no test would show. The
 * comparison costs nothing - it is folded at compile time - and it means the
 * counting form does not depend on a convention held somewhere else.
 */
#define KOF_FS_ONE(rng, s)                                                 \
	((ctx)->content->find_str((ctx),                                   \
		KOF_PASTE(kof_strid_, s),                                  \
		KOF_PASTE(kof_rangeid_, rng)) != 0)

/*
 * Fold one operator across a list of string names.
 *
 * An expression, not an array and a loop. A compound literal holding the ids would
 * be the obvious shape and is the wrong one here: a module is freestanding position
 * independent code that the build verifies has no relocations and no data sections,
 * and an initialised array is exactly how one appears. Folding to `a || b || c`
 * leaves nothing but calls.
 *
 * It also makes the short circuit the C operator's rather than something a helper
 * would have to reimplement: kof_find_str_any stops at the first string present,
 * kof_find_str_all at the first absent.
 *
 * Sixteen names in one call, which is well past readable; past that, write two
 * calls and join them. The cap shows up as an undefined KOF_FS_<n>, so it is a
 * compile error rather than a silently truncated list.
 */
#define KOF_FS_1(op, r, a)       KOF_FS_ONE(r, a)
#define KOF_FS_2(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_1(op, r, __VA_ARGS__))
#define KOF_FS_3(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_2(op, r, __VA_ARGS__))
#define KOF_FS_4(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_3(op, r, __VA_ARGS__))
#define KOF_FS_5(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_4(op, r, __VA_ARGS__))
#define KOF_FS_6(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_5(op, r, __VA_ARGS__))
#define KOF_FS_7(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_6(op, r, __VA_ARGS__))
#define KOF_FS_8(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_7(op, r, __VA_ARGS__))
#define KOF_FS_9(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_8(op, r, __VA_ARGS__))
#define KOF_FS_10(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_9(op, r, __VA_ARGS__))
#define KOF_FS_11(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_10(op, r, __VA_ARGS__))
#define KOF_FS_12(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_11(op, r, __VA_ARGS__))
#define KOF_FS_13(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_12(op, r, __VA_ARGS__))
#define KOF_FS_14(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_13(op, r, __VA_ARGS__))
#define KOF_FS_15(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_14(op, r, __VA_ARGS__))
#define KOF_FS_16(op, r, a, ...) (KOF_FS_ONE(r, a) op KOF_FS_15(op, r, __VA_ARGS__))

#define KOF_NARG_(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,  \
		  _15, _16, N, ...) N
#define KOF_NARG(...) KOF_NARG_(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8,  \
				7, 6, 5, 4, 3, 2, 1)

#define KOF_FS_PICK(n, op, r, ...) KOF_PASTE(KOF_FS_, n)(op, r, __VA_ARGS__)
#define KOF_FS_FOLD(op, r, ...)                                                 \
	KOF_FS_PICK(KOF_NARG(__VA_ARGS__), op, r, __VA_ARGS__)

/* One string in one range. Non-zero if present. */
#define kof_find_str(rng, s) KOF_FS_ONE(rng, s)

/*
 * AT AN OFFSET THE MODULE WORKED OUT
 *
 *     if (kof_find_str_at(ctx->entry_off, stub)) ...
 *     if (kof_find_str_in(ctx->entry_off, 64, stub)) ...
 *
 * The offset is an ordinary expression, not a declaration, and that is the line the
 * whole design rests on: the PATTERN is metadata and belongs in the database, where
 * the host owns it, dedupes it and searches for many modules in one pass; the
 * OFFSET is logic and belongs here, because it depends on the object - an entry
 * point, a field read out of a header, arithmetic on either. Declaring a value that
 * is computed from the file is not something a build can do.
 *
 *     uint64_t target = kof_u32(ep + 1) + ep + 5;   
 *     if (kof_find_str_at(target, prologue)) ...    
 *
 * _at compares; _in searches. They are separate because they cost differently - one
 * comparison against a window - and a single call that did both would hide which
 * one a signature is paying for.
 *
 * Neither is memoised and neither consults the presence set. Both are bounds
 * checked by the host, so an offset past the end of the object is a zero answer and
 * never a read outside it.
 */
#define kof_find_str_at(off, s)                                            \
	((ctx)->content->find_str_at((ctx), KOF_PASTE(kof_strid_, s),      \
				     (uint64_t)(off)))

#define kof_find_str_in(off, len, s)                                       \
	((ctx)->content->find_str_in((ctx), KOF_PASTE(kof_strid_, s),      \
				     (uint64_t)(off), (uint64_t)(len)))

/*
 * THE PLACES AN OFFSET CAN BE COUNTED FROM, NAMED.
 *
 * Nothing new is computed here. All three are already in the context above
 * and a rule has always been able to write them, because the offset is an
 * ordinary expression - that is the line the design rests on and it does not
 * move. What was missing was a LIST OF NAMES for them, and the editor had
 * invented its own: a host that spells the engine's facts in its own words is
 * a second vocabulary to disagree with the first, which is the mistake
 * the region accessors exist to prevent one level down.
 *
 * So the names live with the facts, and the tools read them.
 *
 * BOF IS NOT A FOURTH THING. It is the object's first byte, which is offset
 * zero, which is what a plain number already meant - so its C spelling is
 * nothing at all and a rule written against it is a bare literal, exactly as
 * every such rule is written today. Naming it is what lets an author who has
 * moved a matcher to the entry point move it back.
 *
 * BOF, NOT "FILE START", and the difference is not pedantry: an archive
 * member, a carved payload and a normalised view are each an OBJECT with its
 * own offset zero, and none of them starts where the file on disk does.
 * Rules are written in object coordinates and this is the beginning of them.
 *
 * EOF IS ONE PAST THE LAST BYTE, so every offset counted from it is NEGATIVE.
 * `eof - 8` is the last eight bytes; `eof` itself and anything above it is
 * outside the object, which find_str_at answers with a no rather than a read.
 *
 * ENTRY CAN BE ABSENT. ctx->entry_off is KOF_NA for a format with no such
 * notion and KOF_BROKEN when it could not be resolved, and arithmetic on
 * either lands outside the object - so a rule anchored there simply does not
 * fire on an object that has no entry point. That is the right answer and it
 * is why the bound check is the host's.
 */
enum kof_anchor {
	KOF_ANCHOR_BOF = 0,     /* the object's first byte, which is 0     */
	KOF_ANCHOR_ENTRY,       /* ctx->entry_off                          */
	KOF_ANCHOR_EOF,         /* ctx->obj_size - one past the last byte  */
	KOF_ANCHOR_COUNT
};

/*
 * THE C TEXT OF ONE, which is here and not in the tool that writes it.
 *
 * A generator emits this into a signature source and an importer reads it
 * back out of one, so it is the spelling of an ABI field and not a label a
 * panel chose. Empty for BOF - see above.
 */
static inline const char *kof_anchor_expr(int anchor)
{
	return anchor == KOF_ANCHOR_ENTRY ? "ctx->entry_off"
	     : anchor == KOF_ANCHOR_EOF   ? "ctx->obj_size" : "";
}

/* And the short word a person picks it by, which has to fit in a table cell
 * beside the matcher rather than on a line of its own. */
static inline const char *kof_anchor_word(int anchor)
{
	return anchor == KOF_ANCHOR_ENTRY ? "entry"
	     : anchor == KOF_ANCHOR_EOF   ? "eof" : "bof";
}

/*
 * Where a declared string is within a range the module computed.
 *
 * KOF_BROKEN when absent, the same "could not be determined" every other
 * offset-valued accessor answers with. For locating a structure rather than
 * detecting one: kof_find_str_in asks whether a marker is present, this asks where
 * it is so the rest can be read relative to it.
 */
#define kof_find_str_where(off, len, s)                                    \
	((ctx)->content->find_str_where ?                                  \
	 (ctx)->content->find_str_where((ctx), KOF_PASTE(kof_strid_, s),   \
					(uint64_t)(off), (uint64_t)(len))  \
	 : KOF_BROKEN)

/* Non-zero if at least one of them is present. Stops at the first hit. */
#define kof_find_str_any(rng, ...) (KOF_FS_FOLD(||, rng, __VA_ARGS__))

/* Non-zero only if every one of them is present. Stops at the first miss. */
#define kof_find_str_all(rng, ...) (KOF_FS_FOLD(&&, rng, __VA_ARGS__))

/*
 * How many of them are present: a threshold, written as one.
 *
 * Distinct strings, not occurrences. A marker appearing forty times in a file says
 * the same thing as one appearing once, so counting occurrences would let a single
 * repeated string clear a threshold meant to require several different ones - which
 * is the difference between "this file has four traits of the family" and "this file
 * mentions one thing a lot".
 */
#define kof_find_str_multi(rng, ...) (KOF_FS_FOLD(+, rng, __VA_ARGS__))

#endif /* KOFENG_KOFSEARCH_H */
