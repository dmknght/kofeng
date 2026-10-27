/*
 * kv_chooser.h - the chooser popup: what a list is for and its state.
 *
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_CHOOSER_H
#define KV_CHOOSER_H

/* ---- a chooser ------------------------------------------------------------
 *
 * One overlay for every "pick one of these" in the draft panel: the condition's
 * rule, its range, its verdict, the malware type. They are the same interaction
 * four times, and four bespoke popups would be four places to get the click
 * routing wrong.
 */
/*
 * Enough rows for the longest list any menu builds, which is CH_MARKER's: one
 * per declared marker, and MAX_DECL of those. At sixteen, a draft with more
 * than sixteen unused markers simply ended - ch_add drops what does not fit and
 * the list has no scroll - so the markers past the sixteenth could not be put
 * into a matcher from the menu at all. Two spare for the rows a list adds
 * around its items.
 */
#define CH_ITEMS (MAX_DECL + 2)

/*
 * ONE PALETTE FOR EVERY POPUP - the menu bar's, which is the darker one.
 *
 * The choosers and the right-click menu were drawn on white (47), the bar on
 * bright black (100). Side by side on a dark terminal the white ones glare,
 * and two panels that do the same job should not look like two different
 * programs. Defined here rather than beside the bar because the popups are
 * drawn first and a define is only visible below itself.
 */
#define BAR_ON   "\033[100;97m"    /* an item that can be used */
#define BAR_OFF  "\033[100;37m"    /* the same panel, dimmer text */
#define BAR_CUR  "\033[107;30m"    /* the row under the cursor */

/*
 * The widest a list may get. It is a CAP, not the width: the drawn width is
 * chooser.w, measured from the longest row, so a list of "ELF / PE / MachO"
 * is three columns wider than "MachO" rather than thirty-eight wide with
 * thirty columns of empty highlight after it.
 */
#define CH_W     38
#define CH_W_MIN 12

enum ch_what {
	CH_NONE = 0,
	CH_RULE,        /* find_str or find_at, for a string matcher */
	/*
	 * WHICH OCCURRENCE an AT matcher compares at.
	 *
	 * The marker already knows every place it appears - decl.hits, built by
	 * decl_locate - so the offset is CHOSEN from that list rather than
	 * typed. A number typed by hand is a number that can be wrong in a way
	 * nothing checks; every row here is a place the bytes really are.
	 */
	CH_ATOFF,
	CH_RANGE,       /* which declared range a condition searches */
	CH_RANGE2,      /* what to do to the scan ranges */
	/*
	 * And WHICH REGION to apply, when the markers are spread over more
	 * than one. A string sits in exactly one region, but a matcher holds
	 * several strings and they need not agree - so "where the bytes are"
	 * can be two answers, and applying their union silently is deciding
	 * for the reader that they wanted both.
	 */
	CH_RANGE4,
	CH_RANGE_ADD,   /* which region to declare as a new range */
	CH_ENC_TYPE,    /* which coding the decoder should apply */
	CH_FMT,         /* what to do with one target format - by KIND */
	CH_FMT_SW,      /* which format of that kind to switch to */
	CH_FMT_SW_LANG, /* which language to switch to - a script and its subtype */
	CH_FMT_CAT,     /* which KIND of format - the first half of adding one */
	CH_FMT_ADD,     /* which format of that kind */
	CH_FMT_LANG,    /* which scripting language - format and subtype at once */
	CH_RANGE_EXT,   /* which region to extend the subject range with */
	CH_RANGE_DROP,  /* which region to drop off the subject range */
	CH_TYPE,        /* enum kof_maltype */
	CH_MARKER,      /* which unused marker to put in a matcher */
	CH_THRESH,      /* how many of the matcher's markers must be present */
	CH_OPT,         /* which optional declaration to add */
	CH_ARCH,        /* enum kgenome_arch, all of it */
	CH_SUBTYPE,     /* the format's subtypes, all of them */
	/*
	 * EVERY ATTRIBUTE OF ONE MARKER, IN ONE LIST.
	 *
	 * It was CH_WORD and CH_CASE, two lists behind two columns, and the
	 * two columns were twenty-one of them wide for a pair of facts that
	 * sit at their default on most rows. One column now carries both -
	 * see the attr column in draw_decl_strings - so one list has to
	 * carry both too.
	 *
	 * THE LIST DOES NOT CLOSE WHEN A ROW IS TAKEN, and that is the whole
	 * reason the merge is worth doing: the cell holds two INDEPENDENT
	 * facts, so one visit has to be able to set both. A list that closed
	 * on the first click would let a visit change half the cell, which is
	 * what the two separate columns already did.
	 *
	 * The case row is a tick and the three word rows are one choice of
	 * three, drawn as a tick box and a radio - because with the list
	 * staying open the marker is the only thing left saying what a click
	 * did. See ch_attr_build.
	 */
	CH_ATTR,
	CH_CMATCH,      /* which matcher to put into a condition */
	CH_CMATCH2,     /* what to do to one matcher a condition already names */
	CH_CSWAP,       /* which other matcher to put in its place */
	CH_DECLKIND     /* string, hex or regex - what [+ String] adds */
};

/*
 * A MENU ABOUT A PAIR, and ch_open takes one argument.
 *
 * "This matcher, inside this condition" is two indices, and they are packed
 * into `arg` rather than a second field being added, because ch_open memsets
 * the chooser before it builds the list - so anything a caller writes beside
 * arg is not there while the list is being made. That is not hypothetical: it
 * is exactly the bug recorded beside CH_RANGE_EXT, where a subject read from
 * arg2 came through as zero and the menu never opened. Both indices are bounded
 * by MAX_GROUP, which is 8.
 */
#define CH_PAIR(ci, m)  ((uint32_t)(ci) | ((uint32_t)(m) << 16))
#define CH_PAIR_C(x)    ((x) & 0xffffu)
#define CH_PAIR_M(x)    ((x) >> 16)

struct chooser {
	int      open;
	int      row, col;
	int      what;
	uint32_t arg;               /* which group it is about */
	int      n, sel;
	/*
	 * THE FIRST ROW DRAWN, when the list is taller than the room under it.
	 *
	 * A chooser used to paint from item zero and stop at the bottom of the
	 * screen - so on a short terminal the tail of a long list was invisible
	 * AND unclickable, which is how a draft with many markers ended up with
	 * the last ones unreachable from "+ marker". The cap on CH_ITEMS was
	 * raised for the same symptom once already; the cap was never the
	 * problem.
	 */
	int      off;
	/*
	 * THE DRAWN WIDTH, measured from the rows once they are all added.
	 * Every place that asks how wide the list is - the draw, the click
	 * test, and where a submenu is opened beside it - reads this, so a
	 * list cannot be drawn one width and clicked at another.
	 */
	int      w;
	uint32_t arg2;              /* the narrowest range, for CH_RANGE */
	char     item[CH_ITEMS][CH_W];
	/*
	 * WHAT EACH ROW DOES, carried rather than derived from its index.
	 *
	 * The range menu used to read the verb off c->sel, which holds only
	 * while every verb is always offered. It is not: switching a range
	 * away is refused when markers still live in it, and a list that drops
	 * a row silently renumbers every row after it - so picking "Extend"
	 * would have carried out "Switch". Written where the row is built,
	 * read where it is carried out, and the two cannot drift.
	 */
	uint8_t  verb[CH_ITEMS];
	/*
	 * WHICH ROWS OPEN ANOTHER LIST, marked the way the menu bar marks it:
	 * a ">" at the item's far edge (see bar_has_sub and the draw beside it),
	 * not a suffix on the text. Without it a row that opens a list and a row
	 * that acts are indistinguishable until one is pressed, and one of them
	 * appears to do nothing.
	 */
	uint8_t  sub[CH_ITEMS];
	/*
	 * A RULE OFF, AND NOT A ROW THAT CAN BE PICKED.
	 *
	 * The attribute list has two halves that mean different things - one
	 * tick, and one choice of three - and nothing but a gap says where
	 * one ends. A blank item would have been a row the cursor lands on
	 * and a click carries out, so the separator is marked rather than
	 * spelled: the draw paints a rule, the arrows step over it and a
	 * click on it does nothing at all.
	 */
	uint8_t  sep[CH_ITEMS];
	/*
	 * THE EDIT IN PROGRESS, which is not the draft yet - see CH_ATTR.
	 *
	 * The attribute list is a form: its rows move these, its Apply row
	 * writes them into the declaration, and every other way out leaves
	 * the declaration alone. Held here rather than in the draft because a
	 * draft written on each click is a draft edited four times by
	 * somebody trying two combinations before choosing one.
	 */
	int      pend_word, pend_icase;
};



#endif /* KV_CHOOSER_H */
