#define _GNU_SOURCE
#include "kv.h"
#include "kv_evt_private.h"

#define EVT_PAL_N 12u

/* ---- how a record's rows become screen lines -------------------------------
 *
 * A row is one fact and one range, but it is not one LINE: a path, a command
 * line and an AMSI submission are hundreds of characters, and a panel that
 * gives each row a line shows the first sixty of them and drops the rest -
 * which is the part a reader opened the record for.
 *
 * So a long value wraps, and the panel's unit of scrolling and of hit-testing
 * becomes the LINE rather than the row. Two functions answer that, and both
 * the drawer and the click routing go through them - the last time this pane
 * grew a second way to count its rows, the two disagreed and clicks landed one
 * row off wherever a panel had scrolled.
 */


/*
 * TWELVE, NOT SIX, because six could not keep one record's own fields apart.
 *
 * A process start shows twelve rows at once, so with six hues three of them
 * shared one - created, tid and image came out the same colour on the same
 * screen. They were never ADJACENT, which was the rule the six were chosen to
 * satisfy, and that rule turned out to be too weak: a reader matching a colour
 * in the dump against the table is not helped by the two candidates being far
 * apart, they still have to check both.
 */

/* The chip beside the row's name. Dark grounds with white text. */
static const char *const evt_pal_bg[EVT_PAL_N] = {
	"\033[48;5;24;97m",   /* deep blue   */
	"\033[48;5;58;97m",   /* olive       */
	"\033[48;5;53;97m",   /* plum        */
	"\033[48;5;22;97m",   /* forest      */
	"\033[48;5;94;97m",   /* amber-brown */
	"\033[48;5;60;97m",   /* slate       */
	"\033[48;5;89;97m",   /* wine        */
	"\033[48;5;23;97m",   /* teal        */
	"\033[48;5;100;97m",  /* moss        */
	"\033[48;5;54;97m",   /* violet      */
	"\033[48;5;52;97m",   /* rust        */
	"\033[48;5;30;97m"    /* sea         */
};

/* The same six hues as ink, bright enough to read a hex digit in. Paired by
 * index with the chips above - the pairing is the mapping, so the two arrays
 * are one table and must be edited together. */
#define EVT_INK_0 "\033[38;5;39m"
#define EVT_INK_1 "\033[38;5;185m"
#define EVT_INK_2 "\033[38;5;177m"
#define EVT_INK_3 "\033[38;5;84m"
#define EVT_INK_4 "\033[38;5;215m"
#define EVT_INK_5 "\033[38;5;147m"
#define EVT_INK_6 "\033[38;5;211m"
#define EVT_INK_7 "\033[38;5;80m"
#define EVT_INK_8 "\033[38;5;149m"
#define EVT_INK_9 "\033[38;5;141m"
#define EVT_INK_10 "\033[38;5;209m"
#define EVT_INK_11 "\033[38;5;44m"

static const char *const evt_pal_fg[EVT_PAL_N] = {
	EVT_INK_0 /* deep blue   */,
	EVT_INK_1 /* olive       */,
	EVT_INK_2 /* plum        */,
	EVT_INK_3 /* forest      */,
	EVT_INK_4 /* amber-brown */,
	EVT_INK_5 /* slate       */,
	EVT_INK_6 /* wine        */,
	EVT_INK_7 /* teal        */,
	EVT_INK_8 /* moss        */,
	EVT_INK_9 /* violet      */,
	EVT_INK_10 /* rust        */,
	EVT_INK_11 /* sea         */
};

/* The picked row: the same ink with bold and underline in front. A constant table, so
 * evt_byte_colour hands out no pointer into writable storage. */
static const char *const evt_pal_sel[EVT_PAL_N] = {
	"\033[1;4m" EVT_INK_0,
	"\033[1;4m" EVT_INK_1,
	"\033[1;4m" EVT_INK_2,
	"\033[1;4m" EVT_INK_3,
	"\033[1;4m" EVT_INK_4,
	"\033[1;4m" EVT_INK_5,
	"\033[1;4m" EVT_INK_6,
	"\033[1;4m" EVT_INK_7,
	"\033[1;4m" EVT_INK_8,
	"\033[1;4m" EVT_INK_9,
	"\033[1;4m" EVT_INK_10,
	"\033[1;4m" EVT_INK_11
};

/*
 * WHICH COLOUR A ROW OWNS, keyed on the FIELD and not on where it landed.
 *
 * It was the row's position, which is not a property of the field: a record's
 * rows are only the ones that verb has, so `object` is row six on a file event
 * and row eight on a process start, and the same field changed colour as the
 * reader walked the log. A colour that means something different on every
 * record is not a mapping, it is decoration - and it undoes the one thing the
 * two panes are here to do, which is to be comparable ACROSS events.
 *
 * Keyed on the name, so `object` is one colour for the life of the tool. The
 * names come from kof_evt_field, so a field added there and not here still
 * gets a colour - the hash is the fallback, not the scheme.
 */
static unsigned evt_key(const char *name)
{
	/*
	 * EVERY FIELD THE RECORD CAN SHOW, in the order its bytes appear, with
	 * the palette slot each one keeps.
	 *
	 * Assigned by hand rather than by position, because the rows a record
	 * shows are a SUBSET - a file event has no ports, a thread start no
	 * exit code - so two fields far apart in this list can end up on
	 * neighbouring lines. The numbers below are chosen so that no two
	 * fields which can appear on the same screen share a slot at all - not
	 * merely that they are not adjacent, which was the earlier rule and was
	 * too weak: a reader matching a colour in the dump against the table
	 * gains nothing from the two candidates being far apart, they still
	 * have to check both.
	 *
	 * A name not listed here still gets a colour, from the hash below. That
	 * is the fallback for a field added to kof_evt_field and not yet here -
	 * it works, it is stable, and it is not checked for adjacency.
	 */
	static const struct { const char *name; unsigned slot; } fixed[] = {
		{ "stamp",     0u },
		{ "seq",       1u },
		{ "created",   6u },
		{ "addr",      3u },
		{ "addr size", 4u },
		{ "pid",       5u },
		{ "ppid",      7u },
		{ "actor",     8u },
		{ "tid",       9u },
		{ "session",  10u },
		{ "exit",      2u },
		{ "peer",      3u },
		{ "bytes",     4u },
		{ "peer port", 6u },
		{ "verb",     11u },
		{ "technique", 7u },
		{ "raw id",    2u },
		{ "from",      8u },
		{ "where",     9u },
		{ "source",   10u },
		{ "image",     2u },
		{ "object",    3u },
		{ "cmdline",   4u }
	};
	unsigned i, h = 2166136261u;

	for (i = 0; i < sizeof fixed / sizeof fixed[0]; i++)
		if (!strcmp(name, fixed[i].name))
			return fixed[i].slot;

	/* FNV-1a over the name for everything else. Stable per name, which is
	 * the whole requirement; which of the six it lands on does not matter
	 * as long as it lands on the same one every time. */
	for (; *name; name++) {
		h = kof_hash_step(h, (unsigned char)*name);
	}
	return h % EVT_PAL_N;
}

const char *evt_row_colour(const char *name)
{
	return evt_pal_bg[evt_key(name) % EVT_PAL_N];
}

const char *evt_row_ink(const char *name)
{
	return evt_pal_fg[evt_key(name) % EVT_PAL_N];
}

/*
 * Is this row the panel's cursor, and is the panel showing anything at all.
 *
 * Two questions asked together everywhere they are asked, so they are one
 * predicate rather than a condition repeated in the drawer, the hex pane and
 * the click routing - which is where they drifted apart the last time a panel
 * grew a cursor.
 */
int evt_have_rec(const struct view *v)
{
	return v->log != NULL && v->evt_have && v->evt_n > 0;
}

int evt_live(const struct view *v)
{
	return evt_have_rec(v) && v->evt_open && g_evt_rows > 0;
}

/*
 * WHICH ROW A BYTE BELONGS TO, or -1.
 *
 * `off` is an offset into the RECORD, which for an event node is also the
 * offset into the region: the node is the record, whole, with no extents to
 * map through. That equality is asserted by the caller rather than assumed
 * here - see draw_hex.
 *
 * First match wins. The extents do not overlap today and a later field that
 * did would be a bug in the field table, not something to resolve by drawing
 * order; taking the first keeps the picture stable while that is true and
 * makes the overlap visible as a colour that never appears if it stops being.
 */
static int evt_row_of(const struct view *v, uint64_t off)
{
	int i;

	if (!evt_have_rec(v))
		return -1;
	for (i = 0; i < v->evt_n; i++) {
		uint16_t fo = 0, fl = 0;

		if (!kof_evt_field_extent(&v->evt, (unsigned)i, &fo, &fl))
			break;
		if (fl == 0)
			continue;   /* a note about no bytes - see the header */
		if (off >= fo && off < (uint64_t)fo + fl)
			return i;
	}
	return -1;
}

/* The colour a byte takes from the panel, or NULL when no row claims it. */
const char *evt_byte_colour(const struct view *v, uint64_t off)
{
	int r;

	if (!evt_live(v))
		return NULL;
	{
		char nm[32], vl[64];

		r = evt_row_of(v, off);
		if (r < 0)
			return NULL;
		if (!kof_evt_field(&v->evt, (unsigned)r, nm, sizeof nm,
				   vl, sizeof vl))
			return NULL;
		/*
		 * THE OBJECT IS NOT LIT, and that is the point.
		 *
		 * Every other row names a field of known size and known
		 * meaning, so a colour over its bytes is a claim that can only
		 * be right or wrong by an offset. The object is where the claim
		 * gets shaky: it is a length that came from the provider, it
		 * may be a path or a script or a PE image, and it may run past
		 * what the record actually holds. Lighting it wrongly is worse
		 * than not lighting it, because a wrong extent looks exactly
		 * like a right one.
		 *
		 * So those bytes keep the dump's own colouring - NULs from
		 * text, text from high bytes - which is the reading that
		 * needs no claim about where a field ends. The panel still
		 * shows the content, and its offset still says where to look.
		 */
		if (!strcmp(nm, "object"))
			return NULL;
		/*
		 * The picked row keeps its own hue and gains emphasis on top
		 * of it, rather than taking a seventh colour: the palette's one
		 * rule is that a colour means a field, and breaking it at the
		 * moment a reader is relying on it is the worst time to.
		 *
		 * Emphasis is bold and underline, not a background - the picked
		 * row is the one most likely to be the long one, because a long
		 * field is what a reader clicks a row to go and look at.
		 */
		if (r == v->evt_sel)
			return evt_pal_sel[evt_key(nm) % EVT_PAL_N];
		return evt_row_ink(nm);
	}
}

/*
 * WHAT A ROW SHOWS, which for one row is not what the record holds.
 *
 * The box row of a content event shows the WHOLE submission - the record's own
 * bytes and every continuation folded in - because that is the thing the reader
 * is after and the record alone is a prefix of it. Every other row is the
 * record's, straight from kof_evt_field.
 *
 * One function, because the classifier, the box and the drawer all ask, and
 * they have to agree on the string or the wrap, the scroll and the selection
 * land in different places.
 *
 * `val` is scratch the caller owns; the returned pointer may be it or may be
 * the gathered text, and is valid until the next call or the next selection.
 */
const char *evt_row_value(const struct view *v, int i,
				 char *val, size_t cap)
{
	char nm[32];

	if (!kof_evt_field(&v->evt, (unsigned)i, nm, sizeof nm, val, cap))
		return NULL;
	if (v->evt_text_len && !strcmp(nm, "object"))
		return v->evt_text;
	return val;
}

/*
 * Sort the record's rows into the three zones, once.
 *
 * `meta` gets every row that names bytes and is not the submission; `warn` gets
 * the rows that name none. Returns the object row's index, or -1.
 *
 * One classifier, called by the drawer and by the click routing, because the
 * two must agree about which row is where - the last time this pane had two
 * ways to count its rows they drifted and clicks landed a row off.
 */
int evt_zones(const struct view *v, int *meta, int *n_meta,
		     int *warn, int *n_warn)
{
	int i, box = -1;

	*n_meta = 0;
	*n_warn = 0;
	for (i = 0; i < v->evt_n && i < 64; i++) {
		char nm[32], vl[512];
		uint16_t fo = 0, fl = 0;

		if (!kof_evt_field(&v->evt, (unsigned)i, nm, sizeof nm,
				   vl, sizeof vl))
			break;
		(void)kof_evt_field_extent(&v->evt, (unsigned)i, &fo, &fl);
		if (!fl) {
			warn[(*n_warn)++] = i;
			continue;
		}
		/*
		 * WHICH ROW GETS THE BOX, decided by SHAPE and not by verb.
		 *
		 * The box is for the record's principal text - the thing a
		 * reader opened the event to read. For a submission that is
		 * `object`; for a process start it is `cmdline`, which is
		 * where a payload puts its encoded command and is every bit as
		 * long. Both are the LAST text in the arena, so taking the
		 * last one that qualifies gets it right without naming verbs.
		 *
		 * `image` stays in the table even though it sits beside them:
		 * a program's path is a short, stable fact about the event, and
		 * a reader scanning the table wants it there rather than three
		 * lines down in a scrolling box.
		 *
		 * A short value stays in the table too. A box around eleven
		 * characters is three rows spent to show one.
		 */
		if ((!strcmp(nm, "object") || !strcmp(nm, "cmdline")) &&
		    (v->evt_text_len ||
		     (int)strlen(vl) > (g_cols - (TREE_W + 3) - 1) / 2)) {
			if (box >= 0)
				meta[(*n_meta)++] = box;
			box = i;
			continue;
		}
		meta[(*n_meta)++] = i;
	}
	return box;
}

int evt_warn_lines(const struct view *v)
{
	int meta[64], warn[64], nm = 0, nw = 0;

	(void)evt_zones(v, meta, &nm, warn, &nw);
	return nw;
}

/* Lines the two-column table needs. The left column takes the first half, so
 * an odd count leaves the gap at the bottom right rather than in the middle. */
int evt_meta_lines(const struct view *v)
{
	int meta[64], warn[64], nm = 0, nw = 0;

	(void)evt_zones(v, meta, &nm, warn, &nw);
	return (nm + 1) / 2;
}
