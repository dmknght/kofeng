/*
 * kofeditor.h - the diagnose panel's draft model, apart from the viewer's.
 *
 * WHY THIS IS A FILE OF ISOLATED STATE.
 *
 * The draft a researcher builds - strings, blocks, matchers, conditions and
 * the tag each condition finds - is a model, and the panes, the tree, the input
 * handling and the disassembler are not. Nothing forced them apart, so nothing
 * kept them apart: a draft function reached into the selection, a drawing
 * function reached into the draft, and "what is the model" had no answer that
 * could be checked. The functions here touch no viewer state at all, or only
 * the draft and the object a marker was taken from.
 *
 * Nothing here writes a file. The panel previews the diagnose a draft stands
 * for; it does not save one.
 *
 * WHAT IS NOT HERE.
 *
 * Drawing and input. A model that knows how wide a column is, or which row was
 * clicked, is the same tangle under a new name.
 *
 * Anything the engine already answers. Where a marker is and which region that
 * is come from kof_locate_str in kofinspect.h, because two answers to one
 * question is how the panel came to call a marker absent that the scan finds
 * every time.
 */

#ifndef KOF_KOFEDITOR_H
#define KOF_KOFEDITOR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include <kofmod/kofmutation.h>
#include <kofeng.h>
#include "kofinspect.h"
#include "../libkofeng/analyzers/parsers/binaries/funcs.h"
#include "../libkofeng/analyzers/codenotes.h"
#include "../libkofeng/databases/tagsrc.h"


#define MAX_DECL  32

/*
 * THE LARGEST DECLARATION, AND THE TWO BUFFERS THAT MUST AGREE WITH IT.
 *
 * A hex marker is written three characters to the byte ("2E 2E 5C"), so the
 * spelling of a DECL_BYTES_MAX pattern needs 3*N characters and the scratch a
 * person types into must hold the same. They used to be two unrelated numbers -
 * hexs[512] and sedit[600] - and the gap between them was a silent data loss:
 * a hex marker of 171 bytes or more spells out past 512 characters, so the
 * field opened, took keys, and then decl_edit_commit refused the whole thing
 * for being too long. The edit vanished with no mark on the screen. Whatever
 * can be typed must be committable, which means one number, not two.
 */
#define DECL_BYTES_MAX 512u

/* How many occurrences of one marker the pane will light. Past this the
 * highlight stops being information and starts being a background colour. */
#define DECL_HITS_MAX  64u

/*
 * The right hand end of a string row, in columns from the right edge.
 *
 * The two arrows appear ONLY when there is more than one occurrence to step
 * between: a marker that is in the file once has nowhere to go, and a pair of
 * dead buttons on every row is worse than a row that is shorter.
 */
#define STR_BTN_X     4u        /* [x] */
#define STR_BTN_E     8u        /* [e] */
#define STR_BTN_NEXT 12u        /* [>] */
#define STR_CNT      19u        /* "nn/nn", five wide */
#define STR_BTN_PREV 23u        /* [<] */
#define DECL_HEXS_CAP  (3u * DECL_BYTES_MAX + 16u)

#define MAX_GROUP 8

#define MAX_RANGE 8


/* A string that no condition uses yet. Declaring one must not invent a place to
 * put it: the condition is the researcher's decision and making it for them is
 * the kind of help that has to be undone before anything else can be done. */

/*
 * The optional declarations.
 *
 * KOF_TARGET_FORMAT is required and comes from the parse. These three are not,
 * and each one is a precondition the host checks without entering the module -
 * so adding one is a decision about cost as much as about correctness, and it
 * belongs where the other declarations are rather than being inferred.
 *
 * Their values are seeded from the object, because the object is where a true
 * value comes from: the size of the sample, the architecture it was built for,
 * the kind of file it is. A researcher widens them from there; nobody starts
 * from zero.
 */
enum opt_kind {
	OPT_SIZE_MIN = 0,
	OPT_SIZE_MAX,
	OPT_ARCH,
	OPT_SUBTYPE,
	OPT_COUNT
};



/*
 * The kinds a declaration can be - see struct decl.hex.
 *
 * DECL_RX is RESERVED AND NOT WIRED. The chooser that adds a declaration
 * offers it, because that is the menu the panel is meant to have; nothing
 * behind it exists yet - no front end in decl_compile, no macro in generate -
 * and it is connected when that is written.
 */
#define DECL_STR 0
#define DECL_HEX 1
#define DECL_RX  2

struct decl {
	uint8_t *bytes;
	/*
	 * HOW MANY BYTES ARE IN THE ARRAY, WHICH IS NOT HOW LONG THE PATTERN IS.
	 *
	 * They were one number and could be while every marker was a run of
	 * concrete bytes. A hex pattern is not one: "2E ?? 5C" is three bytes
	 * long in a file and has no byte array at all, and "6A 40 [4-6] 8D" is
	 * six to eight. So `len` is what the pattern covers where it matches -
	 * what the size column shows and what the pane highlights - and
	 * `nbytes` bounds the array, which is empty for any pattern the engine
	 * had to compile.
	 */
	uint32_t nbytes;
	uint32_t span_max;          /* len is the minimum; equal when fixed */
	uint32_t len;
	/*
	 * WHICH OF THE THREE THIS IS - see DECL_STR, DECL_HEX, DECL_RX.
	 *
	 * It was a boolean, hex or not, and stayed one while there were two
	 * kinds. Kept as `hex` with those two values unchanged, so every site
	 * that asks "is this bytes or is it a pattern" still reads correctly
	 * when a third is added.
	 */
	int      hex;
	/*
	 * The target holds this as UTF-16LE - KOF_DEFINE_STR_WIDE.
	 *
	 * `bytes` stays the text as a person reads it, one byte per character,
	 * because that is what the declaration is written from and what every
	 * panel shows. The widening happens in ksigbuilder, at build time; see
	 * KOF_DEFINE_STR_WIDE for why it is not a compare mode.
	 *
	 * Set when a marker is taken out of a buffer that IS UTF-16 - an AMSI
	 * submission, which is most of them. Nothing infers it later: by the
	 * time the bytes are in here the zeros are gone, so a declaration that
	 * did not record it could not work it out again.
	 */
	int      wide;

	/*
	 * A HEX PATTERN AS IT WAS WRITTEN, WHICH `bytes` CANNOT HOLD.
	 *
	 * `bytes` is a byte sequence. A hex pattern is not one: DEAD??BEEF has a
	 * wildcard, 41[4-8]43 has a gap, 41(42|43)44 has a choice, and none of
	 * the three survives being flattened into bytes. So the spelling is kept
	 * beside them, and it is what gets shown and what gets written back.
	 *
	 * Empty for a literal, and empty for a hex pattern declared from a
	 * selection in this session - those really are concrete bytes and
	 * printing them from `bytes` is exact.
	 *
	 * The bug this exists for: a pack's (bytes, len) copied verbatim. For a
	 * hex marker those are the COMPILED PROGRAM and its total length, so
	 * ZipSlip's three byte "2E2E5C" showed as 67 bytes of 010001000300...
	 * and saving it replaced it with a different rule.
	 */
	char     hexs[DECL_HEXS_CAP];   /* the pattern, when bytes cannot say it */
	uint32_t obj;               /* which object it was taken from */
	/*
	 * WHERE THIS MARKER IS SEARCHED FOR - which is not one fact but two,
	 * and conflating them is what made the column go stale.
	 *
	 * `mask0` is where the BYTES CAME FROM: the region row they were
	 * selected in. It never changes, and it is zero for a marker read out
	 * of a source file, which says where to look but not where it was
	 * found.
	 *
	 * `mask` is where the rule ACTUALLY LOOKS, which is the union of the
	 * ranges of the matchers that use it, falling back to mask0 when no
	 * matcher does. It is derived, so it is recomputed rather than
	 * remembered - it used to be filled once while reading a source file,
	 * with `|=`, so it could only ever grow: dropping a scan range left
	 * the column reading "X&Y" about a rule that by then searched neither.
	 */
	uint32_t mask0;
	uint32_t mask;
	char     rgn[24];           /* that region's short name */
	/*
	 * WHICH MATCHERS USE IT - a bit each, not a number.
	 *
	 * It was one matcher per marker, and that made "at least three of these
	 * five, otherwise at least two" impossible to express: the second
	 * matcher had to search the same markers as the first, and they could
	 * only be owned once. A marker is a thing to look for; how many
	 * matchers ask about it is their business, not its.
	 *
	 * Zero means no matcher uses it - what GRP_NONE used to say.
	 */
	uint32_t grp;
	/*
	 * WHICH ADDRESS SPACE `at` AND `hits` ARE IN.
	 *
	 * Zero for the object's bytes, which is what everything here assumed.
	 * SYMN_IMP or SYMN_EXP for a marker scoped to a symbol half, whose
	 * offsets are into the BUILT block and are not file offsets at all.
	 *
	 * Without this, every consumer read a block offset as a file offset:
	 * clicking the row jumped the pane to whatever region sits at that
	 * distance from the start of the file - UNCLAIMED, on the sample this
	 * was found with - and the highlighter lit unrelated bytes at the same
	 * number in a pane the marker is not even in.
	 */
	/*
	 * WHICH SPACE `at` AND `hits` ARE IN, as the engine's own scan target.
	 *
	 * Zero for the object's bytes; KOF_SCAN_SYM_IMP or KOF_SCAN_SYM_EXP for
	 * the built symbol block. The engine's name for it rather than the
	 * viewer's row tag, because this is the model: whoever draws it maps it
	 * to whatever a row is called there.
	 */
	uint32_t sym;
	/* Where these bytes are in the object, so the row can jump to them and
	 * the pane can light them. KGENOME_BROKEN when they are not there at all -
	 * a marker taken from one sample and carried to another. */
	uint64_t at;
	/*
	 * AND EVERYWHERE ELSE IT IS, BECAUSE ONE OF THEM IS NOT THE ANSWER.
	 *
	 * `at` is the occurrence the row reports on - the one inside the region
	 * the module searches, when there is one. The pane lit that one and no
	 * other, so a marker that appears eight times looked like a marker that
	 * appears once, and the seven places worth reading were the seven the
	 * highlight did not point at.
	 *
	 * Kept sorted, and capped: a two byte marker occurs everywhere, and a
	 * list of every offset in a 16 MB object is neither drawable nor worth
	 * drawing. `hits_clipped` says the list is a prefix so the row can say
	 * so rather than imply the count is the whole of it.
	 */
	uint64_t hits[DECL_HITS_MAX];
	/*
	 * AND HOW LONG EACH ONE IS, WHICH IS NOT ONE NUMBER.
	 *
	 * `len` is the SHORTEST a match can be. A pattern with a jump has no
	 * single length - "GET /[4-7].tsunami" covers 17 bytes of "arm5" and 20
	 * of "powerpc" - so lighting `len` bytes at every occurrence cut the
	 * tail off the longer ones, by exactly as much as their jump exceeded
	 * its minimum. The row said "17-20" and the pane lit 17 either way.
	 */
	uint32_t hit_len[DECL_HITS_MAX];
	uint32_t n_hits;
	int      hits_clipped;
	/*
	 * WHICH ONE THE ROW IS POINTING AT.
	 *
	 * Clicking the bytes goes to this one, not to the first: after stepping
	 * to the third occurrence and scrolling away, clicking the row is how
	 * you get BACK to the third. Starting it at the occurrence the row
	 * reports on means the first click still lands where the row says it
	 * will.
	 */
	uint32_t cur_hit;

	/*
	 * How a literal is compared. Both are properties of KOF_DEFINE_STR and
	 * neither exists for a hex pattern - kofsig.h says why: folding case on
	 * a byte that may be a wildcard means nothing, and a word boundary is a
	 * notion of text.
	 */
	/*
	 * WHICH BOUNDARY, not a boolean any more: 0 pattern (match anywhere),
	 * 1 fullword, 2 token. The name stays `fullword` because every reader
	 * of it is a line of this panel and renaming the field would touch
	 * more than it explains; the VALUES are KOF_WORD_* and the panel spells
	 * them out. See KOF_WORD_TOKEN in kofsig.h.
	 */
	int      fullword;
	int      icase;

	/*
	 * The bytes are in the object, but not in the range that searches for
	 * them.
	 *
	 * The one fact that explains a signature which cannot fire however
	 * right it looks, and the panel had no way to say it: the region column
	 * showed the range the matcher DECLARES, so a marker declared in DATA
	 * and actually sitting in CODE read as "DATA, found" on both counts.
	 */
	int      off_rgn;
	char     at_rgn[24];        /* the region it is really in */
	uint32_t at_mask;           /* and that region's bits */
};

/*
 * A declared range: KOF_TARGET_RANGE, exactly.
 *
 * Its own entity rather than a property of a condition, because that is what it
 * is in the module language - a NAMED union of region bits that any number of
 * searches can then name. Which is also what makes the one hard constraint
 * workable: a search call takes one range, so a condition over markers from two
 * regions is impossible until the two regions are one range. Merging them is
 * how that is said, and it is a decision with a cost - a marker in a merged
 * range may then match in either half - so it is a thing somebody does on
 * purpose rather than something the tool arranges quietly.
 */
struct range {
	uint32_t mask;              /* an OR of the format's region bits */
	char     name[40];          /* what the source will call it */
};



/*
 * The same four rules, as the author is shown them.
 *
 * The AT rule is the one that is about a PLACE, and the place is the whole of
 * what distinguishes it, so it is shown as find_at.
 */
static inline const char *grp_rule_label(int rule)
{
	return rule == 1 ? "find_any" : rule == 2 ? "find_multi"
	     : rule == 3 ? "find_at" : "find_all";
}

/*
 * THE TWO ATTRIBUTES OF A MARKER, SPELLED ONCE.
 *
 * They were two columns in the viewer's string table, twenty-one characters
 * wide between them, and what they held sat at its default on most rows. One
 * column now carries both, so there are two spellings of one pair and they
 * are here rather than in the panel that draws them: kofexaminer prints a
 * declaration too, and a second set of words for the same fact is a second
 * vocabulary to disagree with the first.
 *
 * THE CELL IS "<case>:<word>" - e:pattern, i:fword, e:token. Case first
 * because it is one character and the eye reads the column as a pair with a
 * fixed left edge; "fword" rather than "fullword" because the cell is nine
 * characters wide at its widest and "i:fullword" is eleven.
 *
 * A REGEX HAS NEITHER. Both attributes are answered by the matcher that walks
 * the pattern, and a regex carries its own case rule and its own boundaries
 * inside the expression - so the cell says so with a dash and the panel makes
 * it unclickable, rather than offering a menu that would write a field the
 * matcher never reads.
 */
static inline const char *decl_word_word(int w)
{
	return w == KOF_WORD_TOKEN ? "token"
	     : w == KOF_WORD_FULLWORD ? "fullword" : "pattern";
}

/* The same three, in the width the cell has. Only fullword differs. */
static inline const char *decl_word_short(int w)
{
	return w == KOF_WORD_TOKEN ? "token"
	     : w == KOF_WORD_FULLWORD ? "fword" : "pattern";
}

/* Non-zero when the marker has attributes at all - see the dash above. */
static inline int decl_has_attr(const struct decl *d)
{
	return d->hex != DECL_RX;
}

/* Non-zero when both are at their default, which is what the panel dims. */
static inline int decl_attr_default(const struct decl *d)
{
	return !d->icase && d->fullword == KOF_WORD_SUBSTRING;
}

static inline void decl_attr_text(const struct decl *d, char *out, size_t cap)
{
	if (!decl_has_attr(d)) {
		snprintf(out, cap, "-");
		return;
	}
	snprintf(out, cap, "%c:%s", d->icase ? 'i' : 'e',
		 decl_word_short(d->fullword));
}

/*
 * WHERE AN AT MATCHER LOOKS: A BASE, AND A SIGNED STEP FROM IT.
 *
 * A file offset on its own could not say the thing rules actually say. Both
 * shipped AT rules are written from the entry point -
 *
 *     kof_find_str_at(ctx->entry_off + 236u, s0)      bases/signatures/rst_01.c
 *     kof_find_str_at(ctx->entry_off, s0)             bases/signatures/rst_00.c
 *
 * - because that is where the thing they match IS: an infector's stub sits at
 * a fixed displacement from the entry point and at no fixed offset in the
 * file. A literal would match one sample and no other build.
 *
 * So the field holds two parts. The base names something the engine works out
 * per object, or nothing at all, and the displacement is added to it. ABS is
 * the plain offset that was here before, spelled as a base of nothing, so the
 * two cases are one shape with one parser and one printer.
 *
 * SIGNED, because a displacement backwards from the entry point is a thing
 * somebody will write - the bytes just before an entry are as much a marker as
 * the bytes at it - and a parser that cannot read "- 8" reads "8". It is also
 * the only way to write an eof anchor, which counts backwards by definition.
 *
 * THE ANCHORS ARE THE ENGINE'S AND NOT THIS FILE'S - see enum kof_anchor in
 * kofsig.h. There was a grp_at_base here with its own two names and its own
 * two spellings, which is a host inventing words for the engine's facts: the
 * offsets it named have always been ctx->entry_off and a bare literal, both
 * of them ABI. What is left here is the COMPOSITION - an anchor with a step
 * written out, and read back - because that is the editor's own problem.
 */

/*
 * WRITING ONE OUT - the same text for the screen and for the file, differing
 * only in how the base is spelled, so that what the author is shown cannot
 * drift from what is generated. as_c picks the C spelling.
 *
 * The `u` suffix goes on the generated literal because the expression is added
 * to a uint64_t; without it a bare constant is an int and the addition is done
 * in whatever type the promotion lands on. The existing rules all write it.
 */
/*
 * THE THREE PARTS A PLACE IS MADE OF, so that the row which makes each one
 * clickable and the text that writes the whole thing out cannot spell them
 * differently.
 */
static inline char grp_at_sign(int64_t off) { return off < 0 ? '-' : '+'; }

static inline unsigned long long grp_at_mag(int64_t off)
{
	/* Negated through unsigned so the most negative value has no special
	 * case: -(INT64_MIN) is not representable as an int64_t. */
	return off < 0 ? (unsigned long long)-(off + 1) + 1ull
		       : (unsigned long long)off;
}

/*
 * THE SIGN IS THE ANCHOR'S FOR TWO OF THE THREE, and is only a choice on one.
 *
 * bof is the object's first byte, so a step back from it is before the object.
 * eof is one past its last, so a step forward from it is past the end. Both
 * are outside whatever the object holds, which find_str_at answers with a no -
 * a rule that can never fire, spelled in a way that looks deliberate.
 *
 * Only `entry` has both directions, and it really has both: the bytes just
 * before an entry point are as much a marker as the bytes at it.
 *
 * So the sign is corrected rather than offered, and the row shows no control
 * for it where there is no choice to make.
 */
/* Whether the row should draw a sign the author can press - see above. */
static inline int grp_at_sign_free(int anchor)
{
	return anchor == KOF_ANCHOR_ENTRY;
}



/* Whether a matcher compares at one offset rather than searching a range. */
static inline int grp_is_at(int rule) { return rule == 3; }

/* The kinds, spelled rather than counted at the point of use. */
#define GRP_KIND_STR    0u
/*
 * HOW ALIKE THIS OBJECT IS TO THE ONE THE RULE WAS WRITTEN FROM.
 *
 * Not a search. A string matcher looks for something IN the object; this one
 * measures the object AGAINST a reference and asks how much of it is here. It
 * was four separate kinds - one per measure - which made four matchers that
 * differed only in which number they compared, and a rule that used three of
 * them read as three unrelated things rather than as three ways of asking one
 * question.
 *
 * IT IS MADE BY TICKING A BLOCK AND DROPPED BY UNTICKING IT (blk_set_picked),
 * so there is no choosing it as a kind: the diagnose panel calls it find_sim
 * and its one row says the block's hash and the threshold. It holds that one
 * block as an ITEM, and `pct` is the one threshold the item has to reach. A
 * rule read from an older file may name several blocks in one matcher; the
 * items stay a list for that, and every item has to reach `pct`.
 *
 * Wanting two blocks at two thresholds is two matchers, and wanting either of
 * two is two conditions; that is how the rest of the editor already says both,
 * and a second way of saying them inside one matcher would be a second grammar.
 *
 * `rule`, `thresh`, `at_off` and `mask` mean nothing to one.
 */
#define GRP_KIND_SIM    1u

/*
 * THE MEASURES AN ITEM CAN NAME. Each is computed by the engine.
 */
/*
 * ONE NAMED RUN OF BYTES, region-anchored and fuzzy: kof_mutation_score. The
 * item carries which block, by index into kof_draft.blk.
 */
#define SIM_IT_BLOCK  0u
/*
 * 1 IS A GAP, AND SO IS 2: they were the object's GEOMETRY and its STRING SET,
 * measures over a whole object against a reference somebody identified. Both
 * were taken out. The geometry (kof_mutation_shape) identified nothing on its own -
 * an unrelated program of the same size answered 100% - and as a filter it fired
 * too rarely to keep a header, a descriptor and an editor path alive for it.
 *
 * The ids stay gaps so the ids of the measures that remain do not move and a
 * draft written by an older build still reads.
 */
/*
 * 3 IS NOT USED EITHER, AND FOR THE SAME REASON AS 2.
 *
 * It was the block vector - how alike an object was across a reference's
 * WHOLE set of selected windows rather than how much of one named run it
 * carried. The measurement was sound; the reach was not. Containment over a
 * whole set is strict enough that it answered on very few objects, and the
 * ones it did answer on were ones a named block already had, so a second
 * set-shaped measure was cost without reach.
 *
 * The id stays a gap for the reason 2's does: so the ids of the measures that
 * remain do not move, and a draft written by an older build still reads.
 */
/* (3 is a gap; there is no name for it.) */
/*
 * 4 IS A GAP TOO, AND NOT FOR 2 AND 3'S REASON.
 *
 * It was the object's CALL CHAIN - which capabilities the code asks the
 * system for, in order, and which of them were handed something an earlier
 * one produced. What it measured was worth measuring; the shape it measured
 * it in was wrong. A sequence with distances cannot hold a branch, cannot
 * hold two capabilities joined by control rather than by data, and a single
 * inserted call moves every distance after it - so the matcher behind this
 * id was removed rather than tuned. The vocabulary it was made of stayed:
 * kofmod/kofcap.h.
 *
 * The id stays a gap for the reason 2's and 3's do: the ids of the measures
 * that remain must not move, or a draft written by an older build reads as a
 * different rule.
 */

/* How many whole-object measures there are, which is what sim_use and
 * sim_kept are indexed by. It counts the GAPS as well, because the ids index
 * those arrays directly - lowering it when a measure is retired would make an
 * older draft's tick land in another measure's slot. Named because three
 * separate loops were bounded by a literal 4 and a fifth id left every one of
 * them one short - the tick was not hashed into the draft's change stamp, the
 * validator never saw it, and sim_recarve never marked it carried, so its
 * percentage stayed a dash for ever. */
#define SIM_IT_COUNT  5u

/* How many measures one similarity matcher can hold. At most one block apiece for the blocks a draft carries; eight is past what any
 * measured rule has needed, and it is also how many items a list row can hold
 * a click span for. */
#define GRP_SIM_MAX 8u

struct grp_sim_item {
	uint8_t  what;              /* SIM_IT_* */
	uint32_t blk;               /* SIM_IT_BLOCK only: index into dr.blk */
};

struct group {
	int      rule;              /* 0 ALL, 1 ANY, 2 threshold, 3 AT */
	uint32_t thresh;
	/*
	 * WHERE, for rule 3 - the place kof_find_str_at compares at.
	 *
	 * A base and a signed displacement from it, not a bare offset - see
	 * enum kof_anchor in kofsig.h for why the anchor has to be there.
	 *
	 * A matcher with this rule does not search: it is one comparison the
	 * length of the pattern, at a place the author names. So it carries an
	 * offset where the others carry a range, and `mask` means nothing to
	 * it.
	 *
	 * Seeded from the marker's own `at` when the rule is chosen, because
	 * the offset a researcher wants is almost always the one they are
	 * looking at. Every other occurrence is on the marker too - decl.hits -
	 * so the offset control offers those rather than asking for typing.
	 */
	int64_t  at_off;
	uint8_t  at_anchor;         /* enum kof_anchor - what at_off is from */
	/*
	 * WHETHER THE ENGINE PUT THIS NUMBER THERE, which decides whether
	 * changing the anchor may change the number.
	 *
	 * Set when the offset was seeded from an occurrence the engine
	 * LOCATED IN THIS OBJECT - see grp_seed_at - and cleared the moment a
	 * person types into the field. The two say different things with the
	 * same digits: a located occurrence is a PLACE, so re-expressing it
	 * from another anchor has to convert it; a typed number is a STEP
	 * from whichever anchor it was typed against, and converting that
	 * would be the tool overruling what was written.
	 *
	 * A marker whose bytes did not come out of this object - typed by
	 * hand, or read back out of a signature source - has no located
	 * occurrence behind it, so nothing it seeds is a place either.
	 */
	uint8_t  at_auto;
	char     note[512];         /* the author's note, emitted as a comment */
	/* How far it is scrolled inside its own box, for the same reason the
	 * module's comment has one: sliding the whole panel to read the end of
	 * a sentence takes the controls beside it off the screen. */
	uint32_t note_off;
	/*
	 * The range this matcher searches, as a mask.
	 *
	 * Not an index into a list of ranges, because there is no list to keep:
	 * a range has no existence apart from a matcher naming it. Zero means
	 * "the narrowest that holds what I have", recomputed as markers come
	 * and go - which is the answer that is right until somebody decides
	 * otherwise, and the only one that cannot go stale.
	 */
	uint32_t mask;
	/*
	 * WHAT THIS MATCHER LOOKS FOR - 0 the markers in `mask`, 1 ONE
	 * SIMILARITY BLOCK.
	 *
	 * A block matcher is the same kind of thing as the others - a search
	 * the rule names in a condition - so it lives in the same list and is
	 * combined by the same conditions. It holds exactly one block: a
	 * percentage belongs to the block it is about, and a matcher over
	 * several of them could only carry one. Two blocks with two thresholds
	 * are two matchers, which is also how "at least one of these" and "both
	 * of these" are already written.
	 *
	 * `rule`, `thresh`, `at_off` and `mask` mean nothing to one.
	 */
	uint8_t  kind;
	/*
	 * WHAT A SIMILARITY MATCHER IS ABOUT - one entry per block, all of
	 * which have to reach `pct`. The tick that made the matcher put its
	 * block here, so a matcher made by the panel holds exactly one.
	 */
	struct grp_sim_item sim[GRP_SIM_MAX];
	uint8_t  n_sim;
	uint8_t  pct;               /* how much of each the rule demands */
	/*
	 * THE TAG OF A BLOCK MATCHER THAT NO CONDITION USES - zero while none is
	 * chosen. Such a matcher is a diagnose of its own and says what it
	 * finds itself; one a condition names takes the condition's tag, and
	 * this is not read for it (grp_standalone).
	 */
	uint64_t tag;
};

static inline void grp_at_fix_sign(struct group *q)
{
	if (q->at_anchor == KOF_ANCHOR_BOF && q->at_off < 0)
		q->at_off = -q->at_off;
	else if (q->at_anchor == KOF_ANCHOR_EOF && q->at_off > 0)
		q->at_off = -q->at_off;
}

/* What a block matcher demands until somebody says otherwise. A placeholder,
 * not a recommendation: how alike is alike enough is the one thing about a
 * similarity rule that nothing but the author can answer. */
#define GRP_PCT_DEFAULT 60u

/* How many of a reference's strings a draft keeps. Measured: the median sample
 * yields 74 and three in four are under 327. */



struct cond {
	char     expr[64];          /* over matcher ids */
	/*
	 * WHAT THE CONDITION FINDS, as the ID of a tag of the tag sources; zero
	 * is "not chosen yet". The panel offers the tags that exist (a table
	 * with a search box) and nothing else, so no spelling can be wrong, and
	 * the id is what a diagnose will say - a rename of the tag moves no
	 * reference.
	 *
	 * THE CONDITION'S OWN, NOT SHARED: nothing else in the draft - not the
	 * shared Type - changes it. The file name is made from the tag's own
	 * type, family and name (cnd_file_name).
	 */
	uint64_t tag;
	/*
	 * WHICH TAB OF THE DIAGNOSE PANEL THE CONDITION IS WRITTEN ON - enum
	 * draft_tab. Set when it is made, from the tab that was open: a
	 * condition over strings and one over blocks are two kinds of diagnose,
	 * each with its own list, and an empty condition has no matcher to say
	 * which it is. `expr` is over this tab's matcher numbers (grp_loc).
	 */
	uint8_t  tab;
	/* Matcher ids this condition joins: "1 and 2" against "1 or 2". */
	int      op;                /* 0 and, 1 or - between this one's ids */
};

/*
 * THE DRAFT: everything a rule being written consists of.
 *
 * Lifted out of struct view field for field. The point of naming it is that a
 * function taking one of these cannot reach the tree cursor, the byte
 * selection or a column width even by accident - which is what the sixty-nine
 * functions in kofeditor.c now take instead of the whole viewer.
 *
 * `warn` and `warn_bad` are here rather than with the UI because the sentence
 * is the MODEL's: "String 3 would be empty" is a fact about the draft, and the
 * status line only decides where to put it.
 */
/*
 * How many similarity blocks one draft can hold - the engine's offers for the
 * object in front of it, plus whatever a loaded rule declared.
 *
 * A BOUND ON A HOSTILE FILE, not a taste. The functions of a binary are offered
 * one block each, and a few hundred is ordinary (46652 author functions over 133
 * measured binaries); a file that names a hundred thousand is not asking to be
 * browsed. It was sixty-four when the offer was a carve of the bytes into
 * roughly eight-kilobyte pieces, which is still how everything that is not
 * code is offered - see MTN_DATA_BLOCKS.
 */
#define MTN_MAX_BLOCK 4096u

/* The share of the table the byte carve may fill: the regions that are not
 * code. Unchanged from when the table held no more than this. */
#define MTN_DATA_BLOCKS 64u

/*
 * One block a researcher has marked on THIS object.
 *
 * The hashes are computed when the block is marked, not when the rule is
 * written, so the table can show what the block actually yields - a span that
 * produces eleven hashes cannot be a rule and the author should learn that
 * while they are still choosing the span.
 */
struct mtn_block {
	uint64_t off, len;                 /* where it is in this object */
	/*
	 * THE SYMBOL THE BLOCK IS, when it is functions the object names: the first
	 * function's name, and " +N" when the block is a group of N+1. Empty for a
	 * piece of data or of anything the symbols do not name. Display only - it is
	 * not part of what a rule matches.
	 */
	char     sym[40];
	uint32_t mask;                     /* the region it was taken from */
	/*
	 * WHICH HALF OF THE OBJECT IT WAS CUT FROM - enum kgenome_mutation_side.
	 *
	 * A block from the static library and a block from the author's own
	 * code answer different questions, and the matcher will only let a
	 * block be scored by windows from its own side. Recorded here so the
	 * carve, the panel and the generated rule all say the same thing; see
	 * the note on the enum.
	 */
	uint8_t  side;
	uint32_t hash[KOF_MUTATION_MAX_HASH];
	uint32_t n_hash;
	/*
	 * The whole block folded to one value, shown in the table and clicked
	 * on. Not a hash OF the hashes for any cryptographic reason - it is a
	 * name, short enough to read off a row and stable enough that the same
	 * block always shows the same one.
	 */
	uint32_t id;
	/*
	 * The region's NAME, kept rather than resolved later.
	 *
	 * Resolving a bit to a word needs the format's own table, and the block
	 * outlives the moment that table was in hand - a reader may switch
	 * objects and come back. The name is a property of where the block came
	 * from, so it is recorded with it.
	 */
	char     rgn[20];
	/*
	 * And the region's ENUM SPELLING, which is a different string from the
	 * label above and is the one a generated rule must carry: the table
	 * shows "CODE", the source says KGENOME_SCAN_ELF_CODE, and writing the
	 * short form into a rule produces a file that does not compile.
	 */
	char     rgn_enum[48];
	/*
	 * LOOK FOR IT ANYWHERE IN THE FILE, not only in the region it came
	 * from.
	 *
	 * The region is an ANCHOR and it is usually the right one - the same
	 * bytes in another region are another fact, and a rule that ignored
	 * that would score on a copy of the block sitting in a resource. But it
	 * is not always right: a rebuild moves a blob from CODE to DATA, a
	 * packer moves it into an overlay, and a block anchored to where it was
	 * the first time then scores nothing on the very sample the rule was
	 * written to catch.
	 *
	 * So it is the author's choice, per block, and the matcher already has
	 * the case: KOF_SCAN_ALL is a region bit of its own that the scanner
	 * feeds with the whole file. The fields above stay as the block was
	 * CARVED, so the choice can be taken back.
	 */
	uint8_t  anywhere;
	/*
	 * CARRIED FROM ANOTHER SAMPLE, rather than carved from this object.
	 *
	 * A block declared by a rule survives moving to another file - that is
	 * the whole point, and without it the score could only ever be a
	 * hundred, because a block carved from the object on screen contains
	 * itself. Its offsets belong to the sample it came from until the carve
	 * finds it here, which is when it learns where it is.
	 */
	uint8_t  kept;
	uint8_t  norm;                     /* enum kgenome_mutation_norm */
	uint8_t  picked;                   /* ticked: goes into the rule */
	uint8_t  lit;                      /* painted in the hex pane */
	uint8_t  colour;                   /* index into mtn_colour */
	/*
	 * How much of this block is in the object now on screen.
	 *
	 * The number the whole mode exists to show: mark a block on one sample,
	 * open another, and this says how much of it survived. On the sample it
	 * was carved from it is a hundred BY CONSTRUCTION - every hash of the
	 * block came out of those bytes - so there the column says "self"
	 * rather than printing an arithmetic certainty as though it were a
	 * measurement. See `kept`.
	 */
	uint8_t  score;
};

struct kof_draft {
	struct decl  decl[MAX_DECL];
	uint32_t     n_decl, sel_decl;
	/*
	 * THE SIMILARITY BLOCKS, which are declarations like the markers above.
	 *
	 * The engine carves them from the object and the author TICKS the ones
	 * the rule is to be written from - the same relation the markers have
	 * with the strings an object contains. A ticked block is declared, and
	 * a declared block no matcher names is an incomplete draft, exactly as
	 * an unused marker is.
	 *
	 * A pointer because the list outlives opening the next file: a block
	 * ticked on one sample is the QUESTION being asked of the next one, and
	 * the score column has nothing to measure without it. Allocated once -
	 * see where ext and probe are.
	 */
	struct mtn_block *blk;
	uint32_t     n_blk;
	/*
	 * AND ITS STRINGS, after the static library was subtracted.
	 *
	 * A fixed array rather than a pointer: a thousand is well past the 327
	 * a three-quarters of samples reach, and a draft that is copied about
	 * should not carry an allocation somebody has to remember to free.
	 */
	/*
	 * WHICH WHOLE-OBJECT MEASURES THE AUTHOR HAS CHOSEN, and which of them
	 * are carried - indexed by SIM_IT_*, with the block slot unused
	 * because a block's tick lives on the block.
	 *
	 * The same pair of facts the block table keeps, for the same reasons.
	 * `sim_use` is the tick: it says this measure is part of the rule, and
	 * nothing else - a matcher is added by hand and names it afterwards,
	 * exactly as one names a ticked block.
	 *
	 * `sim_kept` says the description in this draft came from somewhere
	 * other than the object in front of the reader - another sample, or a
	 * rule that was opened. Until then the percentage beside it is the
	 * object compared with itself, which is a hundred and means nothing;
	 * see mtn_block.kept, where the score column answers the same way.
	 */
	uint8_t      sim_use[SIM_IT_COUNT];
	uint8_t      sim_kept[SIM_IT_COUNT];
	char         sedit[DECL_HEXS_CAP];
	uint32_t     sedit_off;
	struct range rng[MAX_RANGE];
	struct group grp[MAX_GROUP];
	uint32_t     n_grp, cur_grp;
	struct cond  cnd[MAX_GROUP];
	uint32_t     n_cnd, cur_cnd;
	/*
	 * THE TAB THE PANEL SHOWS - enum draft_tab. A fact about the draft and
	 * not about the screen: a matcher is added to it by ticking a block, a
	 * condition is made on it and the output is listed by it, none of which
	 * may reach the viewer to find out.
	 */
	uint8_t      tab;
	char         warn[120];
	int          warn_bad;
	int         opt_on[OPT_COUNT];
	uint64_t    opt_val[OPT_COUNT];
	/*
	 * WHICH OF THOSE THE ENGINE FILLED IN, rather than the reader.
	 *
	 * draft_seed_target copies the object's own subtype into OPT_SUBTYPE so
	 * a drafted rule targets what is in front of the reader, and mtn_sync
	 * calls it on ARRIVAL at an object - before anything has been drafted
	 * at all. The options are hashed, so that copy made an empty draft read
	 * as edited the moment a file was opened, and an edited draft refuses
	 * to step to the next file: opening a PowerShell script and pressing
	 * for the next one answered "Finish or undo the draft first" with
	 * nothing in the panel.
	 *
	 * The same rule the block table follows - see the note on picked in
	 * draft_hash. What the engine observed about the object is its offer;
	 * what the reader chose is the draft. A value set here is skipped by
	 * the hash until the reader sets it themselves, which clears the flag.
	 */
	int         opt_auto[OPT_COUNT];
	char        family[64];
	uint32_t    maltype;
	/*
	 * WHICH OBJECT FORMATS THE RULE APPLIES TO, as a bit per format.
	 *
	 * A MASK AND NOT ONE VALUE, because the engine's target always was one:
	 * KOF_TARGET_FORMAT takes an OR and ksigbuilder loops over the names -
	 * see resolve_format, which errors with "use one declaration with '|'".
	 * What was single was this editor, which emitted the format of whatever
	 * object the draft happened to be built on.
	 *
	 * That is the wrong shape for the markers people actually write. The
	 * same command string lives in an ELF that carries it, in a shell
	 * script that is it, and in the plaintext this program decodes out of a
	 * base64 run - three formats, one marker, and a rule pinned to one of
	 * them misses the other two.
	 *
	 * Seeded from the object the first string is declared on, because that
	 * is the one format the reader has already demonstrated they care
	 * about; everything after that is theirs to add and remove.
	 */
	uint32_t    fmt_mask;
	uint32_t    rng_mask;
	uint32_t    rng_add[MAX_GROUP];
	uint32_t    n_rng_add;
	uint32_t    decl_cap;
	uint32_t    saved_hash;
	char        note[512];
};





struct object {
	char      name[256];


	/*
	 * WHAT A TREE ROW SHOWS, when the name is not the answer.
	 *
	 * obj_label composes a row from the object's FORMAT - "ELF-x64",
	 * "raw" - which is right for a scanned object and says nothing about
	 * an event. A log's rows want "//4021 FileNew pid=5104 f.exe", which
	 * only the record can supply.
	 *
	 * Empty for every ordinary object, and then obj_label behaves exactly
	 * as it did. Non-empty overrides it - one field, checked in one place,
	 * rather than obj_label learning what a log is.
	 */
	char      label[64];
	/*
	 * REGIONS THE ENGINE DECLARED for this object, and the count.
	 *
	 * Almost always zero, and then the parser's own resolver answers as it
	 * always has. Non-zero for a NORMALISED VIEW, which cannot be parsed
	 * for them: it keeps its parent's header byte for byte, so identifying
	 * it from its bytes yields an ELF or a PE whose offsets describe the
	 * parent - before the padding was taken out. Drawn from those, a view's
	 * data region begins at the parent's offset, runs into the kept code,
	 * and shows padding the view no longer carries.
	 *
	 * See kof_result.region, which is where these come from and why the
	 * engine has to be the one to say.
	 */
	struct kof_scan_region rgn[KOF_MAX_REGIONS];
	uint32_t  n_rgn;
	/* Which format's vocabulary rgn[].mask is written in - the PARENT's,
	 * because that is where the bits were resolved. A bit cannot be named
	 * without it: 1u << 5 is UNCLAIMED in an ELF and OVERLAY in a PE. */
	uint8_t   rgn_fmt;
	/*
	 * THE LANGUAGE THE ENGINE SCANNED THIS OBJECT AS, when it declared one
	 * - see kof_result.lang_known.
	 *
	 * Kept for the same reason rgn[] is: a normalised view's own bytes
	 * answer about themselves, and a decode can change the answer outright.
	 * A shell dropper whose base64 payload decodes to PHP reads back as
	 * PHP, and the panel then declined every rule written for the language
	 * the object actually is - beside a verdict saying one of them had
	 * fired.
	 */
	uint8_t   lang_known;
	uint8_t   subtype;
	uint8_t   subfamily;
	/*
	 * Set when the engine handed the symbol records over with the object -
	 * see kof_result.syms. sym_build must not overwrite them: the object is
	 * a rendering whose own headers cannot produce a block, and building
	 * from them yields none.
	 */
	uint8_t   sym_declared;

	/*
	 * THE BLOCKS THE CARVE CUT FROM THIS OBJECT, KEPT.
	 *
	 * The carve hashes every region, so it reads the whole object too:
	 * measured at 310ms on a 15MB view and 0.7s on a sample with three
	 * objects, paid on every arrival at the object rather than once.
	 *
	 * KEPT ONLY WHEN NOTHING WAS TICKED, which is what makes it exact
	 * rather than close. The cut positions do not depend on what the
	 * author has ticked - the share-out deliberately counts the whole
	 * table, see the note on it - but how many of the cuts FIT does, so a
	 * list recorded with none ticked is the list a fresh carve produces
	 * with none ticked, and nothing else is reused.
	 */
	struct mtn_block *carve;
	uint32_t          n_carve;
	uint8_t           carve_done;

	uint8_t  *own;              /* the copy, NULL for the mapped top level */
	void     *mapped;           /* or a spill file, mapped instead of copied */
	uint64_t  mapped_len;
	int       too_big;          /* kept nowhere: past the session's budget */
	kof_buf   buf;
	uint32_t  depth;            /* how many "//" its name carries */
	/*
	 * WHICH ENTRY OF ITS PARENT THIS OBJECT IS THE CONTENT OF, or
	 * KOF_ENTRY_NONE.
	 *
	 * From the engine and not worked out here - see kof_result.entry_of.
	 * It is what lets one stream be ONE row: an entry describes the coded
	 * extent where it lies in the file, and this object is that stream's
	 * content. Before this arrived the tree showed both, with nothing
	 * saying they were the same stream and the first of them opening onto
	 * compressed noise.
	 */
	uint32_t  entry_of;
	/* And what the producer said it IS - enum kof_entry_kind. The format of
	 * decoded content is almost always unknown, so this is the only thing
	 * that separates a peeled payload from a page description stream, and
	 * the two want opposite answers from every item in the Analysis menu. */
	uint32_t  entry_kind;

	const struct kof_parser *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	/*
	 * WHAT OPENED THIS OBJECT, in the engine's own words and in one field:
	 * "PE:MPRESS 2.12-2.19 LZMA" where the module could name a build,
	 * "MSF.xor" where it could not. See kof_result.packer_build - the whole
	 * answer is there and nothing here works any of it out.
	 */
	char              packer[48];
	/*
	 * The interpreter has already been run on this object.
	 *
	 * Asking twice cannot produce a different answer - the bytes have not
	 * changed and the run is deterministic - so a second press appended a
	 * second identical set of children, and a third a third. Recorded per
	 * object because the question is per object.
	 */
	int               emu_done;
	/*
	 * What the scanner's own gate makes of this object, when no module
	 * claimed it: KOF_EMU_UNP_* .
	 *
	 * ONCE, AND NOT UNTIL SOMETHING SHOWS IT - see obj_emu_why. It reads
	 * every executable segment, so computing it beside the parse faulted a
	 * spilled object in whole to fill one row; and computing it while
	 * drawing would do that on every keystroke. `emu_why_done` separates
	 * "not worked out yet" from "worked out, and the answer is zero",
	 * which a single field cannot say.
	 */
	uint8_t           emu_why;
	uint8_t           emu_why_done;
	/*
	 * SHA-256 OF THIS OBJECT'S BYTES, hex, or "" before it is computed.
	 *
	 * OF THE BYTES AND NOT OF THE FILE, which is the whole reason it is
	 * here rather than taken from the path. A child - an unpacked payload,
	 * a stream out of a PDF, a PE an event carried - has no path at all,
	 * and its hash is the one somebody actually wants to look up: it is
	 * the IOC for the thing that was hidden, not for the wrapper anybody
	 * can rebuild. For the top-level object the two are the same.
	 *
	 * COMPUTED ONCE, BESIDE THE PARSE, for the reason emu_why is: the
	 * property pane is repainted on every keystroke, and hashing a
	 * hundred-megabyte mapping per frame is not a slow feature, it is an
	 * unusable one.
	 */
	char              sha256[65];
	/*
	 * The version that module read out of the object, or -1 for none.
	 *
	 * Signed and not a flag beside a uint, because 0 is a version a container
	 * can carry and "it never said" has to be a different answer from "it
	 * said zero".
	 *
	 * It is the FORMAT version the module found in the file - UPX's l_info
	 * byte, RAR's archive version - and not the packer's release. The two get
	 * confused, so nothing here pretends to know that a UPX l_info of 13
	 * means UPX 3.9x: the module reported a field called version and this
	 * shows the field.
	 */
	/* What the engine said about this object, kept whole. */
	struct kof_result heur;
	/*
	 * Whether the engine got to the end of THIS object, and what stopped it.
	 *
	 * Kept per object rather than for the file, because it is per object: a
	 * container that opened may hold one entry it could not, and the packed
	 * parent being incomplete says nothing about the child that came out of
	 * it. enum kof_broken, KOF_BROKEN_NONE when it finished.
	 */
	uint32_t          broken;
	/*
	 * WHAT EACH DIAGNOSE MADE OF THIS OBJECT - an owned copy of
	 * kof_result.diag, which the engine lends only for the callback. Empty
	 * when the scan did not ask. See draw_decl_diag.
	 */
	struct kof_diag_report *diag;
	uint32_t                n_diag;
	/*
	 * THE FUNCTIONS ITS SYMBOLS NAME, built once beside the symbol block - see
	 * funcs.h. Empty for an object with none, and for a normalised view, whose
	 * headers describe its parent.
	 */
	struct kgenome_func_set     funcs;
	uint8_t                 funcs_done;
	/* What Analysis > Analyze disassembly found: labels and comments by file offset, from the engine (kof_codenotes_build). Empty until asked. */
	struct kof_codenotes        notes;
	uint8_t                 notes_done;

	/*
	 * The object's symbol records, in the KSYM layout kofsym.h fixes.
	 *
	 * Built ONCE, when the object is parsed, and right-sized: the cap is
	 * 4096 records and a scratch of that size for each of MAX_OBJ objects
	 * would be thirty megabytes held to show a table nobody may open, while
	 * the real counts are tens to a few thousand. NULL and zero for a file
	 * with no symbols and for every non-ELF - which is a normal answer, not
	 * a failure, so nothing downstream treats it as one.
	 */
	/*
	 * THE OBJECT'S SYMBOL BLOCK - the engine's, one copy, unsplit.
	 *
	 * It used to be two blocks that this file built by copying records out
	 * of the engine's according to their UNDEFINED flag. That was a second
	 * implementation of "which half is this symbol in", and it disagreed
	 * with the engine's: the engine coalesces adjacent records of one half
	 * into runs, so a pattern is never matched across a record of the other
	 * half, while a copied half joins records the engine keeps apart. On
	 * 23.8% of files the halves interleave, so the two really did answer
	 * differently.
	 *
	 * Now the block is whatever kof_syms_build returned and the halves are
	 * kof_sym_extents' answer - the same call kof_find_str makes.
	 */
	uint8_t          *sym;
	uint32_t          sym_n;
	/* THE UNITS OF THE PARENT'S CUT THAT THIS VIEW'S DECODE REWROTE, in its offsets - copied
	 * from kof_result.fixed, and handed to the cut so the table shows the scanner's units. */
	struct kof_range *fixed;
	uint32_t          n_fixed;

	/*
	 * WHERE THIS OBJECT'S LOADER KEEPS ITS PAYLOAD, from the tool's own
	 * analysis (kofscfind) - the engine does not look for loaders. Worked out
	 * ONCE per object, when it is examined (scfind_object in kv_collect.c),
	 * and read from here by every pane after that: the symbols dialog, the
	 * menu, the status line. payload_at is the symbol's value, zero when
	 * nothing was found; payload_len the blob's size as it sits in the object;
	 * payload_bits 32 or 64 where the payload said so, 0 where it did not.
	 * sc_done says the analysis ran, whatever it answered.
	 */
	uint64_t          payload_at;
	uint64_t          payload_len;
	uint32_t          payload_bits;
	uint8_t           sc_done;
	/* Set on the object the VIEWER derived from a parent's payload (the
	 * engine never produces one), so the
	 * menu can find it without inferring anything from the name. A name
	 * test alone would also match an unpacker's child that happened to sit
	 * under the same parent. */
	int               payload_of;
	/*
	 * WHERE A RULE SAID THE INFECTION IS - see struct kof_infected.
	 *
	 * Copied from the result rather than worked out here, and worked out
	 * nowhere: a module that can describe a repair had to locate the damage
	 * to do it, so this is a fact the scan already established. Nothing in
	 * this file searches for it, and nothing here decides what counts as
	 * infected.
	 */
	struct kof_infected infected[KOF_MAX_INFECTED];
	uint32_t          n_infected;
	/*
	 * WHICH MAPPED FILE OF A PROCESS VIEW THIS ROW IS, plus one - zero
	 * means it is not one. An index into view.seen_path, which holds the
	 * full path; the object's own name carries the basename because that
	 * is what fits a tree row.
	 */
	uint32_t          proc_path;
	/*
	 * WHICH VARIABLE IT CAME OUT OF, and what was wrapped round it.
	 *
	 * Kept on the child rather than left in its name: the name says what
	 * the object is, and the symbol is a fact about where in the PARENT it
	 * was found. A reader wants both, and only one of them belongs in a
	 * tree row eighteen columns wide.
	 */
	char              payload_sym[KOF_SYM_NAME_MAX + 1];
};
/*
 * WHAT THE EDITOR IS DRIVING: the draft, plus the little of its surroundings a
 * draft actually refers to.
 *
 * Measured rather than guessed. Of the forty-two model functions, three need
 * the object a marker was taken from, two the directory a rule is written to,
 * and one each the sample's path, the engine and whether the file is somebody
 * else's. Nothing else. So those seven are here and the rest of the viewer -
 * the tree, the panes, the selection - is not reachable from a function that
 * takes one of these.
 *
 * The four pointers borrow the host's storage rather than copying it: `n_obj`
 * and `foreign` change while a session runs, and a copy of a number that
 * changes is a number that goes stale.
 */
struct kof_editor {
	struct kof_draft   dr;

	struct object     *obj;      /* the host's array, not owned */
	const uint32_t    *n_obj;    /* live: objects appear as children are found */
	struct kof_engine *eng;
	struct kof_range  *scratch;  /* KOF_SCAN_MAX_EXTENTS, the host's */
	/*
	 * WHICH FIELD THE HOST HAS OPEN, borrowed the way the tables above are.
	 *
	 * The model does not interpret the number - how a host names its boxes
	 * is the host's business. It only CLEARS it, and only when a row that
	 * a box could be open on has just gone: removing a matcher shifts every
	 * one after it, so a caret that was in matcher 3 is now in what used to
	 * be matcher 4, typing into a rule nobody asked to edit.
	 *
	 * Cleared rather than adjusted because after a removal there are two
	 * cases - the row went, or it moved - and "no box open" is the only
	 * answer that is right in both. The same fix as blk_moved, for the same
	 * reason, at the one level that can see every removal.
	 */
	int               *edit;
	/*
	 * THE TAG SOURCES, borrowed from the host like the tables above: what a
	 * tag id in the draft means. NULL when the host has none, and then no
	 * tag has a name.
	 */
	const struct kof_tagset *tags;
	/*
	 * WHICH OBJECT THE DRAFT IS BEING WRITTEN ABOUT.
	 *
	 * The one piece of UI state the model genuinely needs: a rule is
	 * written from what the reader is looking at, and two functions ask -
	 * the one that records which sample it came from, and the one that says
	 * what is still missing. Set by the host wherever the selection moves,
	 * which is one place.
	 */
	uint32_t           cur;
};

void say_err(struct kof_editor *e, const char *fmt, ...);
/* ---- what an object IS, worked out once - see the definitions ---- */
void    obj_sha256(struct object *o);
uint8_t obj_emu_why(const struct object *o);

void say_note(struct kof_editor *e, const char *fmt, ...);

void decl_locate(struct kof_editor *e, struct decl *d);
uint32_t decl_free(struct kof_editor *e);
uint32_t grp_mask(struct kof_editor *e, uint32_t g);
uint32_t grp_count(struct kof_editor *e, uint32_t g);
int grp_has_range(struct kof_editor *e, uint32_t g);
void grp_add(struct kof_editor *e);
void cnd_label(struct kof_editor *e, uint32_t i, char *out, size_t cap);
void cnd_canon(struct kof_editor *e, uint32_t g, char *out, size_t cap);
void grp_remove(struct kof_editor *e, uint32_t g);
void cnd_add(struct kof_editor *e);
void cnd_set_op(struct kof_editor *e, uint32_t i, int op);
void cnd_remove(struct kof_editor *e, uint32_t i);
uint32_t grp_thresh_eff(struct kof_editor *e, uint32_t g);
void grp_seed_at(struct kof_editor *e, uint32_t g);
uint32_t draft_hash(struct kof_editor *e);

/*
 * THE SAMPLE LINE: its name AND the hash of the bytes it was written from.
 *
 *     Test sample: shell.asp  sha256:9f86d081...
 *
 * A name is what a file was called on one machine. Two researchers comparing
 * rules, or one of them coming back to this a year later, cannot tell from
 * "shell.asp" whether they are holding the same bytes - and the hash is already
 * computed for the object, beside the parse, so recording it costs nothing.
 *
 * IT IS THE HASH OF THE OBJECT THE RULE IS BEING WRITTEN ABOUT, which for a
 * carried payload is the payload and not the dropper around it - see
 * struct object's sha256, which says why that is the useful one.
 *
 * Written as one string because it is one fact about one sample: the reader
 * takes the rest of the line as the entry, so the pair survives a round trip
 * without a second list to keep in step with the first.
 */
int draft_edited(struct kof_editor *e);
/* `near_miss` and not `near`: mingw's headers still #define near and far as the
 * empty macros 16-bit compilers needed, so a parameter with that name compiles
 * everywhere except Windows, where it vanishes and the call site stops parsing. */
void rng_retarget(struct kof_editor *e, uint32_t was, uint32_t now);
uint32_t rng_removable(struct kof_editor *e, uint32_t *mask, int *unused, uint32_t cap);
uint32_t rng_all(struct kof_editor *e, uint32_t *mask, int *unused, uint32_t cap);
void rng_add_drop(struct kof_editor *e, uint32_t mask);
void rng_delete(struct kof_editor *e, uint32_t mask, int unused);
void rng_apply(struct kof_editor *e, int verb, uint32_t target, uint32_t here);
void draft_refresh(struct kof_editor *e);
void decl_sync_ranges(struct kof_editor *e);
void decl_edit_commit(struct kof_editor *e, uint32_t i);
void decl_remove(struct kof_editor *e, uint32_t i);

/*
 * SPELLED OUT, because the table is defined in kofeditor.c and sizeof cannot
 * see across a translation unit. The definition there asserts the two agree, so
 * adding a word without adding one here does not compile.
 */

/*
 * THE WORDS A RULE IS WRITTEN IN.
 *
 * The architecture names, the ELF and PE subtype names, the format names and
 * the malware-type names are the vocabulary of a KOF_TARGET_ declaration, so
 * they belong with the thing that writes and reads those declarations rather
 * than with the pane that happens to show them in a menu.
 *
 * The counts come with them because sizeof cannot see across a translation
 * unit; each is a variable filled by sizeof where the table is defined, so it
 * cannot disagree with the table it counts.
 */

struct kof_arch_word { const char *word; uint32_t val; };

/* The counts are variables, not macros - see the note in kofeditor.c. */
#define ARCH_N       arch_n
#define ELF_SUB_N    elf_sub_n
#define PE_SUB_N     pe_sub_n
#define FMT_WORD_N   fmt_word_n
#define MALTYPE_N    maltype_word_n

extern const struct kof_arch_word arch_word[];
extern const uint32_t arch_n;
extern const char *const elf_sub[];
extern const uint32_t elf_sub_n;
extern const char *const pe_sub[];
extern const uint32_t pe_sub_n;
/* The script kinds, for the same job - see script_sub in kofeditor.c. */
extern const char *const script_sub[];
extern const uint32_t script_sub_n;
/* And the platforms a process record can be from. */
extern const char *const proc_sub[];
extern const uint32_t proc_sub_n;
/* The identifier for a target value - "KOF_FMT_ZIP" - out of the engine's own
 * list rather than a copy here. See fmt_word in kofeditor.c. */
extern const uint32_t fmt_word_n;
extern const char *const maltype_word[];
extern const uint32_t maltype_word_n;

void draft_reset(struct kof_editor *e);

/*
 * Does this draft name a similarity block at all, and which matcher names one.
 *
 * Asked by everything that has to agree about it: where the rule is written,
 * what it includes, which block declarations are emitted, what the matcher menu
 * may offer, and whether a ticked block is still waiting for a matcher.
 */
uint32_t grp_of_block(const struct kof_editor *e, uint32_t blk);
void grp_label(const struct kof_editor *e, uint32_t g, char *out, size_t cap);
int grp_make_sim(struct kof_editor *e, uint32_t g);

/*
 * THE ITEMS OF A SIMILARITY MATCHER - added, removed and asked about through
 * these rather than by reaching into the array.
 *
 * Every one of them takes the pair (what, blk) as the item's IDENTITY: `blk`
 * is read only for SIM_IT_BLOCK, so the whole-object measure is one
 * per matcher and a block is one per block. That is what makes "is this
 * already here" answerable, and a matcher that held the same measure twice
 * would emit the same comparison twice.
 */
int grp_sim_add(struct kof_editor *e, uint32_t g, uint32_t what, uint32_t blk);
void grp_sim_del(struct kof_editor *e, uint32_t g, uint32_t i);
int grp_sim_has(const struct kof_editor *e, uint32_t g, uint32_t what,
		uint32_t blk);
/* Which matcher holds this item, or MAX_GROUP when none does. */
uint32_t grp_sim_of(const struct kof_editor *e, uint32_t what, uint32_t blk);
/* The default threshold for a measure: where each was measured, not one
 * number for all. See the notes on the SIM_IT_* kinds. */
uint32_t sim_pct_default(uint32_t what);
/* What a measure is called on the panel and in a menu. */
void blk_set_picked(struct kof_editor *e, uint32_t i, int on);
int blk_clears(const struct kof_editor *e, uint32_t i);
void blk_moved(struct kof_editor *e, uint32_t from, uint32_t to);
void blk_permute(struct kof_editor *e, const uint32_t *to, uint32_t n);



/*
 * The architectures, as the enum spells them.
 *
 * All of them, not the one this object happens to be: a signature for a family
 * that ships an arm build and an x86 one is written from whichever sample is to
 * hand, and being offered only that sample's architecture is how a signature
 * ends up narrower than the family it names.
 */


/*
 * A condition: what some combination of matchers MEANS - an expression over
 * matcher ids ("1", "1&2", "(1&2)|3") and the diagnose tag it finds.
 */

/*
 * THE THREE TABS OF THE DIAGNOSE PANEL, and what each one writes.
 *
 *   DT_PATTERNS  strings, their matchers (find_str, find_at) and conditions
 *   DT_BLOCKS    similarity blocks, one find_similar matcher per ticked block
 *   DT_GRAPHS    on hold: the diagnoses table and conditions over it
 *
 * The type, the family and the options are declared once for the whole draft.
 */
enum draft_tab { DT_PATTERNS = 0, DT_BLOCKS, DT_GRAPHS, DT_COUNT };

/* The tab a matcher belongs to, which follows from its kind alone, and how many
 * matchers a tab holds - what a condition on that tab can be made of. */
uint8_t grp_tab(const struct kof_editor *e, uint32_t g);
uint32_t grp_tab_count(const struct kof_editor *e, uint8_t tab);
/*
 * THE TAGS, as the panel reads them: the tag sources the host loaded (`tags` of
 * the editor), asked by id. tag_name is the tag's name, "" for no tag or one
 * that is not there. tag_label is what a Tag cell shows: the name, and - only
 * when more than one tag has that name - its family and types, to tell them
 * apart.
 */
const struct kof_tagent *tag_find(const struct kof_editor *e, uint64_t id);
const char *tag_name(const struct kof_editor *e, uint64_t id);
void tag_label(const struct kof_editor *e, uint64_t id, char *out, size_t cap);

/*
 * WHAT THE DRAFT WRITES: one diagnose per condition, and one per block matcher
 * that no condition uses. grp_standalone says which matchers are the second
 * kind.
 */
int grp_standalone(const struct kof_editor *e, uint32_t g);

/*
 * THE FILE NAME a diagnose would have, in the form
 * `<first type>_<family>_<tag>_<id>.c`, every word the tag's own: its first
 * type in the order the tag declares them, its family, its name. Lower case,
 * only [a-z0-9_-]; a type or family a tag does not have is left out, so no
 * underscore is doubled. The id is a running number per prefix, at least two
 * digits, counted over the conditions in order and then the standalone block
 * matchers in order - the order a Save would write them in. A diagnose with no
 * tag has `<tag>` in its place, so the gap is in the name itself. Nothing is
 * written anywhere.
 */
void cnd_file_name(const struct kof_editor *e, uint32_t ci, char *out,
		   size_t cap);
void grp_file_name(const struct kof_editor *e, uint32_t g, char *out,
		   size_t cap);

void draft_clear(struct kof_editor *e);





/* ---- what kofeditor.c answers ------------------------------------------- */

int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags);
int rng_holds(uint32_t rmask, uint32_t region);
/*
 * The matcher numbers of a condition's expression are the numbers of its own
 * tab: grp_loc is the number of matcher `g` on its tab (0 if there is none),
 * cnd_has_id the
 * plain question "is this number written in the expression" and cnd_uses the
 * one the panel asks - is matcher `g` one this condition names. cnd_foreign is
 * 0 for an expression whose every number is on the condition's tab, else the
 * first number that is not, plus one: a reference to another tab's matcher or
 * to none, which is refused rather than read as something else.
 */
uint32_t grp_loc(const struct kof_editor *e, uint32_t g);
int cnd_has_id(const struct cond *c, uint32_t id);
int cnd_uses(const struct kof_editor *e, const struct cond *c, uint32_t g);
unsigned long cnd_foreign(const struct kof_editor *e, const struct cond *c);
void rng_name_of(const struct kof_parser *fmt, uint32_t mask,
			char *out, size_t cap);
int decl_from_hexs(struct decl *d);
int decl_text_editable(const struct decl *d);
/*
 * The three edits a condition's id row can make to one of its matchers, and
 * the question the row asks before drawing it.
 *
 * A negated id is written "!1" in the expression rather than kept in a flag
 * beside it. The expression is also a TEXT BOX the author can type in, so a
 * flag would be a second place the same fact lived - and the two would part
 * company the first time somebody edited the text by hand.
 */
int  cnd_neg(const struct kof_editor *e, const struct cond *c, uint32_t g);
void cnd_drop_matcher(const struct kof_editor *e, struct cond *c, uint32_t g);
void cnd_negate_matcher(const struct kof_editor *e, struct cond *c,
			uint32_t g);
void cnd_swap_matcher(struct kof_editor *e, uint32_t ci, uint32_t g,
		      uint32_t to);

#endif /* KOF_KOFEDITOR_H */
