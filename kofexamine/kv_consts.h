/*
 * kv_consts.h - limits, widths and edit codes that more than one unit uses.
 *
 * The draft panel's own (NOTE_W, GEN_BTN_W, ED_GRP_PCT, ED_STR, ED_AT_OFF)
 * are kept in their original order; they are listed in prototypes.txt.
 * A part of kv.h.
 */
#ifndef KV_CONSTS_H
#define KV_CONSTS_H

/* ---- the signature being drafted -------------------------------------------
 *
 * What the tool exists for. Everything else - the region tree, the offsets that
 * count from the region rather than the file, the highlighting - is here to get
 * a person to the moment where they can say "that, and that, are the marker",
 * and this is where what they said is kept.
 *
 * A declaration remembers the region it came from as well as the bytes. That is
 * the half a hand-written signature usually gets wrong: the bytes are easy to
 * copy and the range they were found in is easy to forget, and a marker searched
 * for in the wrong region is a signature that quietly never fires.
 */
/*
 * When a recovered object stops being held in memory, and when it stops being
 * held at all.
 *
 * Eight megabytes is far past anything an unpacker normally hands back and far
 * short of anything worth paging; the quarter gigabyte is the whole session's
 * budget across every child.
 */
#define OBJ_SPILL   (8ull << 20)
#define OBJ_BUDGET  (256ull << 20)
/* "[ Discard ]" with a space in front, so the note box can leave room. */
#define NEW_BTN_W 12
/*
 * AND THE LAST COLUMN IS NOT THEIRS.
 *
 * Every row of the panel below this one ends in the divider the scrollbar is
 * drawn on - see draw_decl - and the head row was laid out from g_cols as
 * though it did not exist, so the closing bracket of Discard was painted on
 * top of it. One column, and the border was broken on exactly the row a reader
 * looks at first.
 */
#define HEAD_RMARGIN 1

/*
 * THE HEADING ROW IS LAID OUT AGAINST FIXED MARKS, NOT AGAINST THE CURSOR.
 *
 * Every box on it used to be as wide as its contents and every box after it
 * started wherever the last one stopped, so the row rearranged itself as the
 * draft was typed into - and clicking a field, which widened it, shoved
 * everything to its right along with it. On a narrow terminal that pushed the
 * Generate button off the end of the row entirely.
 *
 * So: the fields are a fixed width, the buttons are anchored to the RIGHT edge,
 * and the comment takes exactly the gap between them. Nothing on the row moves
 * unless the terminal is resized.
 */
#define NOTE_W    40    /* the comment box - a remark, not a paragraph */
#define GEN_BTN_W 8     /* "[ Save ]" */
/*
 * Where the string editor's codes live in view.edit.
 *
 * One code per declaration, in a band of its own well clear of every other
 * field's. The bands below it are 1, 103+i, 200+i, 300+i, 400+i, 500 and
 * 501, and each is tested as a band rather than as "at least" - a rule this
 * file learned the hard way when the size editor claimed everything from 200
 * up and swallowed the boxes added above it.
 */
/* One edit target per block row, so the caret knows which threshold it is in.
 * Above ED_STR's range, which is per declared string. */
#define ED_GRP_PCT 700
#define ED_STR    1000000     /* one code per declared string, and the table has no capacity: the band is far above every other code */
/* One per matcher, for the step of an AT place - see grp_of. Above ED_GRP_PCT
 * and tested as a band, like every other one. */
#define ED_AT_OFF 800
/*
 * The symbol dialog's filter field. A band of one, well clear of ED_AT_OFF's -
 * every other code here is tested as a band for the reason the note above
 * gives, and a single code that sat inside somebody else's range would be the
 * same fault in a smaller place.
 */
#define ED_SYMFILT 900

/* The draft panel's rows are a COUNT (n_prow) and nothing is sized from it: the sum of limits that stood here (MAX_PROW) stopped the count short
 * when a table outgrew it, which is a panel whose bottom cannot be scrolled to. The block table's rows drawn are its window (blk_win, kv_field.c). */

/*
 * How much encoded text the decoder will hold.
 *
 * A base64 payload out of a dropper is a few hundred bytes; this is past every
 * one measured and still a field a terminal can scroll through without the
 * caret arithmetic becoming the slow part.
 */
#define ENC_IN_MAX 8192u

/*
 * THE CODINGS THE STRING BOX OFFERS - enum kof_codec, in kofinspect.h.
 *
 * The list, the names and both directions live there, because a coding is bytes
 * in and bytes out: it has no terminal in it and nothing about it is this
 * panel's. What is here is the FORM - a field, a chooser, a button and where
 * the answer is drawn.
 */

/* The two text fields, by the edit id the rest of this file uses for focus. */
#define ED_ENC_IN  540
#define ED_ENC_KEY 541
/* Manage > Pathogens: the name field of its small dialogs. */
#define ED_FAM_NAME 560
#define ED_FAM_COMMENT 561
#define ED_FAM_CELL 562         /* the comment of a variant, edited in its table cell */
#define ED_FAM_FCOMMENT 565     /* the family's OWN comment (the Note row), Add family and Edit family only */
/* Manage > Syndromes: the name and comment fields of its small dialog. */
#define ED_TAG_NAME 563
#define ED_TAG_COMMENT 564

/*
 * DLG_ROWS / DLG_COLS - what a dialog's recorded text can hold.
 *
 * Sized from the boxes themselves: neither is taller than 28 rows and the
 * widest is 116 columns, so these are those numbers with room to spare. A row
 * longer than DLG_COLS is truncated in the RECORDING only - what is on screen
 * is whatever was drawn - and truncating the copy of a row nobody can select
 * past is not a loss.
 */
#define DLG_ROWS 40
#define DLG_COLS 168



#endif /* KV_CONSTS_H */
