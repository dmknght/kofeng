/*
 * kv_objects.h - the objects under view: the tree node, a hit, the sizes the view keeps.
 *
 * A part of kv.h, included by it and by nothing else.
 */
#ifndef KV_OBJECTS_H
#define KV_OBJECTS_H

/* ---- the objects under view ------------------------------------------------
 *
 * A file is not one object. A packed executable is itself and the image inside
 * it; an archive is itself and everything it holds; and a signature is written
 * against exactly one of them, so all of them have to be reachable.
 *
 * They come from a scan, because producing them is what unpack modules do and
 * the engine is the only thing that runs a module. Their bytes live only for the
 * length of the callback, so they are copied - a viewer holds what it shows.
 * That is bounded by the same budgets a scan is bounded by, which is why they
 * are the engine's to set and not this tool's to raise.
 */
#define MAX_OBJ  128
/*
 * 512 WAS SIZED FOR A DIFFERENT POPULATION, and the population changed.
 *
 * It was objects plus a dozen region rows each, which 512 covered with room.
 * The entry table is a row PER THING THE OBJECT HOLDS - a stream, a member, an
 * attachment - and a document may publish a thousand of them, so the old
 * number is now reachable by one ordinary file.
 *
 * Reaching it was also SILENT: tree_add returns when full, and the rows lost
 * are whatever came last - which, because detail rows are added per object
 * inside the walk, could be a LATER OBJECT'S OWN ROW. The object list itself
 * would have gone short with nothing saying so. Raised so that does not happen
 * on real input, and tree_build now spends the last slot saying when it does
 * happen anyway.
 *
 * The cost is the array: a node is about 120 bytes, so this is half a megabyte
 * in a tool that already asks the engine for a 32MB presence table.
 */
#define MAX_TREE 4096

/*
 * Events per window. Under MAX_OBJ so the parent fits beside them, and well
 * under MAX_TREE. Bigger buys nothing: a screen shows tens of rows, and the
 * window follows the selection.
 */
#define LOG_WIN 96u


/*
 * A row in the left pane.
 *
 * Objects and regions in one list rather than two trees: they are drawn as one
 * column, moved through with one cursor, and the only thing that differs is what
 * selecting one means. `depth` is what makes it a tree on screen - a region is
 * always one level inside the object that has it.
 */
/* Which of the two symbol blocks a tree row names. Not a bool any more: there
 * are two, they are a partition, and a row has to say which half it is. */
#define SYMN_IMP 1u
#define SYMN_EXP 2u

struct node {
	/* 64, matching obj_label's output: a node built from one used to be
	 * copied into a shorter field and lost its tail. */
	char     label[64];
	uint32_t depth;
	uint32_t obj;               /* which object this row belongs to */
	uint32_t mask;              /* the region, or 0 when the row IS the object */
	/*
	 * The symbol row is not a region and cannot be spelled as one: a region
	 * is an extent of the FILE, and these records are built rather than
	 * pointed at. So it gets a flag of its own instead of a reserved mask
	 * value - a sentinel mask would have to be excluded by hand everywhere a
	 * mask is resolved, and every place that forgot would resolve it as a
	 * real region and show the wrong bytes.
	 */
	uint8_t  sym;               /* 0 none, or SYMN_IMP / SYMN_EXP */
	/*
	 * AN ENTRY ROW IS NOT A REGION EITHER, and gets a flag for the same
	 * reason `sym` did rather than a reserved mask value.
	 *
	 * A region says which bytes are what KIND; an entry says what one thing
	 * IS - a stream, an attachment, a member - and two entries can be the
	 * same kind, so no mask distinguishes them. The bytes come straight
	 * from the entry rather than from resolve_scan, which is why off and len
	 * are here: they are the parser's answer for THIS entry and there is
	 * nothing to resolve.
	 *
	 * A sentinel mask would have had to be excluded by hand everywhere a
	 * mask is resolved, and every place that forgot would have shown the
	 * wrong bytes - the note on `sym` above is that lesson already learned
	 * once.
	 */
	uint8_t  ent;               /* the row IS an entry */
	uint32_t ent_i;             /* which row of ctx->entries */
	/* The exact bytes of an entry row: these bytes, not a resolve. */
	uint64_t ent_off, ent_len;
	uint64_t bytes;

	/*
 * How many pieces of one submission the character-to-byte map holds - the
 * record plus sixty-three continuations, which is about twenty-five kilobytes
 * of content. Past it a selection still copies and still declares; only the
 * highlight in the dump stops, because that is the part that needs to know
 * where each piece is.
 */
#define EVT_SEG_MAX 64

/*
	 * Where this row was last being looked at.
	 *
	 * Per row rather than one cursor for the pane, because moving between
	 * regions is how the tool is used - find something in CODE, check
	 * whether DATA has its twin, come back - and coming back to the top of
	 * a forty kilobyte region means finding the place again by hand every
	 * time. The offset is the reader's place in that region, so it belongs
	 * to the region.
	 */
	uint64_t at;
};

/*
 * One clickable RECTANGLE, and what pressing it does.
 *
 * A CALLBACK RATHER THAN A CODE, so the action lives beside the thing that
 * draws it instead of in a switch somewhere else that has to be kept in step.
 * `arg` is whatever that drawer needs - a marker index, a matcher id, a region
 * bit, a menu context.
 *
 * WHICH BUTTON, because the right one is not the left one with a different
 * name. Most spans are left-only; a pane that has a context menu declares a
 * rectangle for the right button and nothing else does. See the note on the
 * right-button gate in click().
 *
 * A ROW IS y0 == y1. Most controls are one row of one drawer, and hit_add is
 * for those; a PANE is many rows and declares itself with hit_zone.
 */
struct view;
struct dframe;
/* WHERE THE READER MOVED A DIALOG, as an offset from where it opens. The one carrier of a box's position the mouse drag writes
 * (v->dlg_move points at one): a framed dialog keeps it in its dframe, the dashboard and Pathogens dialogs in the view. */
struct dlg_off {
	int dx, dy;
};

/*
 * WHICH GESTURE A RECTANGLE ANSWERS.
 *
 * The wheel is here for the same reason the right button is: "what is under the
 * pointer" is one question, and answering it in a chain of geometry tests
 * somewhere else means every new scrollable area has to be added to that chain.
 * It was not, twice, for the right button; the wheel's chain had the same shape
 * and the text pane was missing from it in both directions.
 *
 * WHICH WAY it turned is g_wheel, read by the callback the way g_mx and g_my
 * already are - a direction is not a different rectangle, so it does not belong
 * in the mask.
 */
enum {
	HIT_L      = 1u << 0,
	HIT_R      = 1u << 1,
	HIT_WHEEL  = 1u << 2,   /* the wheel, plain */
	HIT_HWHEEL = 1u << 3    /* the wheel with shift or ctrl - sideways */
};

struct hit {
	int16_t   y0, y1, x0, x1;
	uint8_t   btn;
	void    (*fn)(struct view *, uint32_t arg);
	uint32_t  arg;
};

/*
 * Enough for the busiest panel a draft can have: every marker row carries
 * three spans and every matcher four, and MAX_DECL and MAX_GROUP bound both.
 * Registering past it is dropped rather than written past the end - a control
 * that cannot be clicked is a visible fault; a smashed stack is not.
 */
#define HIT_MAX 512u

/* How many regions one object's share-out has room for. Every format's table
 * is far shorter than this; the bound is here so the arrays that hold the
 * share-out are fixed. */
#define MTN_MAX_REGION 32u

/* The two generator buttons on the Mutation blocks heading, as drawn. */


struct kv_syn;                  /* the tag sources - see kv_syn.c */

/* The longest row of the disassembly panel as text, and the longest instruction text with its comments. A comment is the engine's words about the instruction and is not cut to the width of a screen. */
#define DIS_LINE_MAX 320
#define DIS_TEXT_MAX 300


#endif /* KV_OBJECTS_H */
