/*
 * kofeditor_proto_types.h - the draft model's types: declaration, range, group, condition, block, draft.
 *
 * THE DIAGNOSE GENERATOR'S DRAFT, A PROTOTYPE that will be redesigned: everything the draft
 * model is made of is here, moved verbatim from kofeditor.h, so the redesign touches the
 * proto headers (this and kofeditor_proto_fn.h) and not the umbrella. A part of kofeditor.h,
 * included by it and by nothing else.
 */
#ifndef KOF_KOFEDITOR_PROTO_TYPES_H
#define KOF_KOFEDITOR_PROTO_TYPES_H

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






#endif /* KOF_KOFEDITOR_PROTO_TYPES_H */
