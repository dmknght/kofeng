#define _GNU_SOURCE
#include "kv.h"


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

/* The offset column: four hex digits and the space after them. It was
 * "0077+392" - offset and length - and the length has gone; see the drawer. */
#define EVT_OFF_W 5


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
static const char *const evt_pal_fg[EVT_PAL_N] = {
	"\033[38;5;39m",      /* deep blue   */
	"\033[38;5;185m",     /* olive       */
	"\033[38;5;177m",     /* plum        */
	"\033[38;5;84m",      /* forest      */
	"\033[38;5;215m",     /* amber-brown */
	"\033[38;5;147m",     /* slate       */
	"\033[38;5;211m",     /* wine        */
	"\033[38;5;80m",      /* teal        */
	"\033[38;5;149m",     /* moss        */
	"\033[38;5;141m",     /* violet      */
	"\033[38;5;209m",     /* rust        */
	"\033[38;5;44m"       /* sea         */
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

static const char *evt_row_colour(const char *name)
{
	return evt_pal_bg[evt_key(name) % EVT_PAL_N];
}

static const char *evt_row_ink(const char *name)
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
		if (r == v->evt_sel) {
			static char lit[32];

			snprintf(lit, sizeof lit, "\033[1;4m%s",
				 evt_row_ink(nm));
			return lit;
		}
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
static const char *evt_row_value(const struct view *v, int i,
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

/*
 * The box's first row. Its rule is the row above it.
 *
 * CLAMPED TO THE PANEL, AND THAT IS A FIX RATHER THAN A GUARD.
 *
 * The layout asks for meta + warn + 1 + EVT_BOX_ROWS rows and then CAPS the
 * answer - g_evt_rows is held to half the pane, and to the pane less three -
 * while this was still adding the uncapped counts. Whenever the cap bit, the
 * box was drawn that many rows below the panel it belongs to.
 *
 * Which rows those are is the part that made it visible: hex_bot() is
 * decl_top() - 2, so a box two rows past the pane lands exactly on the draft
 * panel's heading and the rows under it. The draft appeared to jump down the
 * screen when an event was opened, because its top was being painted over.
 *
 * Reported as the signature panel moving; it never moved. The event box came
 * to it.
 *
 * One place rather than two: draw_evt positions the box from here and
 * evt_box_hit tests a click against it from here, so a clamp here keeps the
 * two agreeing. They would not have to - the box could be clamped in the draw
 * alone - and then a click would land on the row the box used to be on.
 */
int evt_box_top(const struct view *v)
{
	int want = evt_top() + evt_meta_lines(v) + evt_warn_lines(v) + 1;
	int last = hex_bot() - EVT_BOX_ROWS + 1;   /* the lowest it still fits */

	if (want > last)
		want = last;
	return want > evt_top() ? want : evt_top();
}

/* Where the box's text starts and how wide it is. */
static int evt_box_x(void)  { return TREE_W + 3 + 2; }
static int evt_box_w(void)
{
	int w = g_cols - evt_box_x() - 2;

	return w > 8 ? w : 8;
}

/*
 * The box's text, which is whichever row the box took.
 *
 * The caller supplies scratch because the answer may be the row's own value -
 * a command line - or the gathered submission, which lives in the view. It
 * returns whichever, so a caller never has to know which case it got.
 */
const char *evt_box_text(const struct view *v, char *buf, size_t cap,
				size_t *len)
{
	int meta[64], warn[64], nm = 0, nw = 0, box;
	const char *t;

	box = evt_zones(v, meta, &nm, warn, &nw);
	if (box < 0) {
		if (len)
			*len = 0;
		return "";
	}
	t = evt_row_value(v, box, buf, cap);
	if (!t)
		t = "";
	if (len)
		*len = strlen(t);
	return t;
}

/*
 * WHERE THE BOX'S TEXT SITS IN THE RECORD, and how many bytes a character of
 * it takes. Zero when the box holds nothing.
 *
 * The step is the whole reason this is not a straight offset: a UTF-16
 * submission renders one character per TWO bytes, so a run of ten characters
 * on screen is twenty bytes in the dump. Anything mapping a selection back to
 * the object needs both numbers, and getting them from one place is what stops
 * the two panes from disagreeing about which bytes a highlight means.
 */
static int evt_box_extent(const struct view *v, uint16_t *off, int *step)
{
	int meta[64], warn[64], nm = 0, nw = 0, box;
	uint16_t fo = 0, fl = 0;

	box = evt_zones(v, meta, &nm, warn, &nw);
	if (box < 0)
		return 0;
	if (!kof_evt_field_extent(&v->evt, (unsigned)box, &fo, &fl) || !fl)
		return 0;
	if (off)  *off = fo;
	if (step) *step = v->evt_wide ? 2 : 1;
	return (int)fl;
}

int evt_box_total(const struct view *v)
{
	char scratch[512];
	size_t n = 0;

	(void)evt_box_text(v, scratch, sizeof scratch, &n);
	return (int)((n + (size_t)evt_box_w() - 1u) / (size_t)evt_box_w());
}

/*
 * WHERE IN THE BOX'S TEXT THE POINTER IS. Zero when it is not over the box.
 *
 * One function for the press and the drag both, because a drag that computed
 * the position differently from the click that started it selects from
 * somewhere the reader never pressed - and the two were three lines apart,
 * which is exactly far enough to drift.
 */
int evt_text_at(const struct view *v, int my, int mx, int *ch)
{
	char scratch[512];
	size_t n = 0;
	int w = evt_box_w(), line, c;

	if (!evt_live(v))
		return 0;
	if (my < evt_box_top(v) || my >= evt_box_top(v) + EVT_BOX_ROWS)
		return 0;
	if (mx < evt_box_x())
		return 0;
	(void)evt_box_text(v, scratch, sizeof scratch, &n);
	if (!n)
		return 0;

	line = v->evt_scroll + (my - evt_box_top(v));
	c = line * w + (mx - evt_box_x());
	/* Clamped to the text: a pointer past the end of a short last line
	 * selects to the end, which is what dragging over ragged text does
	 * everywhere. */
	if (c > (int)n)
		c = (int)n;
	if (c < 0)
		c = 0;
	if (ch)
		*ch = c;
	return 1;
}

/*
 * WHICH TABLE CELL THE POINTER IS OVER, as a row index, or -1.
 *
 * The table is filled down the left column and then down the right, so the
 * cell under a pointer is `k` on the left and `half + k` on the right - the
 * same arithmetic the drawer uses, from the same classifier.
 */
int evt_meta_at(const struct view *v, int my, int mx)
{
	int meta[64], warn[64], nm = 0, nw = 0, half, k, cw;

	if (!evt_live(v))
		return -1;
	/*
	 * THE TREE IS NOT THIS PANEL, and the bound was missing.
	 *
	 * Only the row range was tested, so a click in the OBJECT LIST at a
	 * height that happened to fall inside the table was read as a click on
	 * a metadata cell: picking an event out of the list lit a field in the
	 * hex pane and never changed the selection. The panel starts to the
	 * right of the divider, like every other pane here.
	 */
	if (mx <= TREE_W)
		return -1;
	(void)evt_zones(v, meta, &nm, warn, &nw);
	half = (nm + 1) / 2;
	k = my - evt_top();
	if (k < 0 || k >= half)
		return -1;
	cw = (g_cols - (TREE_W + 3) - 1) / 2;
	if (mx >= TREE_W + 3 + cw)
		k += half;
	return k < nm ? meta[k] : -1;
}

/*
 * The picked run of the box, copied out. Returns how many characters, and
 * writes nothing when there is no selection.
 *
 * The box's text is a RENDERING - UTF-16 already collapsed, padding already
 * trimmed - so what comes back is what the reader sees, which is also what
 * belongs in a signature: KOF_DEFINE_STR_WIDE is written with the characters
 * and widened at build time.
 */

/* The picked run, low end first - the reader may have dragged backwards. */
static int evt_text_span(const struct view *v, int *from, int *to)
{
	if (v->evt_txt_a == v->evt_txt_b)
		return 0;
	if (from) *from = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_a
						      : v->evt_txt_b;
	if (to)   *to   = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_b
						      : v->evt_txt_a;
	return 1;
}

/*
 * Put the hex pane's selection over the bytes the box's selection came from.
 *
 * The two panes are showing one record and a reader dragging through the text
 * is pointing at bytes; leaving the dump unmarked made them do the arithmetic
 * themselves, which for a UTF-16 submission is "twice the character count,
 * plus wherever the field starts".
 *
 * CLAMPED TO WHAT IS REALLY THERE. Past the record's own arena the text came
 * from continuation records that sit further along the object, and the step
 * from a character to a byte stops being a multiplication - so the mark stops
 * at the end of this record's content rather than running on over bytes it
 * cannot account for.
 */
/*
 * One byte of the gathered content, as an offset into the node's bytes.
 * KGENOME_BROKEN when the map does not reach that far.
 *
 * The content is one string and several runs - see evt_seg - so this is a walk
 * over the pieces rather than an addition.
 */
static uint64_t evt_content_byte(const struct view *v, uint64_t at)
{
	int k;

	for (k = 0; k < v->evt_n_seg; k++) {
		if (at < v->evt_seg[k].len)
			return (uint64_t)v->evt_seg[k].at + at;
		at -= v->evt_seg[k].len;
	}
	return KGENOME_BROKEN;
}

/*
 * Take the dump to one character of the box.
 *
 * Used at the PRESS, where there is no span yet - a and b are the same
 * character - so evt_sync_hex has nothing to reveal and returns before it
 * could. Revealing the anchor instead is what a reader means by clicking into
 * text: show me where this is.
 */
void evt_reveal_char(struct view *v, int c)
{
	uint64_t at, per, hrow;

	if (!v->evt_n_seg)
		return;
	at = evt_content_byte(v, (uint64_t)c * (uint64_t)(v->evt_wide ? 2 : 1));
	if (at == KGENOME_BROKEN)
		return;
	per = (uint64_t)(v->per > 0 ? v->per : 16);
	hrow = at / per;
	v->rgn_at = hrow > JUMP_LEAD ? (hrow - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

void evt_sync_hex(struct view *v, int reveal)
{
	int step = 1, from = 0, to = 0;
	uint64_t a, b;

	if (!evt_text_span(v, &from, &to) || !v->evt_n_seg) {
		v->sel_a = v->sel_b = KGENOME_BROKEN;
		return;
	}
	step = v->evt_wide ? 2 : 1;

	/*
	 * THE FIRST AND LAST BYTE THE PICKED CHARACTERS OCCUPY.
	 *
	 * A UTF-16 character is two bytes, so a run of ten is twenty - and the
	 * run may cross from the record into a continuation, where the next
	 * byte is seventy-two further on than arithmetic would say. Both ends
	 * go through the map for that reason.
	 *
	 * The two ends may land in different pieces, and then the marked range
	 * covers the head between them. That is the honest picture: those bytes
	 * really are between the two halves of what was selected, and hiding
	 * them would draw a selection the file does not have.
	 */
	a = evt_content_byte(v, (uint64_t)from * (uint64_t)step);
	b = evt_content_byte(v, (uint64_t)to * (uint64_t)step - 1u);
	if (a == KGENOME_BROKEN || b == KGENOME_BROKEN || b < a) {
		v->sel_a = v->sel_b = KGENOME_BROKEN;
		return;
	}
	v->sel_a = a;
	v->sel_b = b;

	/*
	 * TAKE THE DUMP TO IT, but only when the selection STARTS.
	 *
	 * A mark the reader cannot see is the same as no mark, and after a few
	 * turns of the wheel the box is showing text whose bytes are a long way
	 * down the record - so a selection made there landed off-screen and the
	 * sync looked like it was not happening at all.
	 *
	 * Not on every drag step. The far end of a selection moves with the
	 * pointer, and scrolling the dump under it on each motion would make
	 * the bytes slide away while the reader is still choosing them.
	 */
	if (reveal) {
		uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
		uint64_t hrow = v->sel_a / per;

		v->rgn_at = hrow > JUMP_LEAD ? (hrow - JUMP_LEAD) * per : 0;
		if (v->rgn_at > hex_max(v))
			v->rgn_at = hex_max(v);
	}
}

size_t evt_sel_text(const struct view *v, char *out, size_t cap)
{
	char scratch[512];
	const char *t;
	size_t n = 0, len;
	int from = 0, to = 0;

	if (!out || !cap)
		return 0;
	out[0] = '\0';
	if (!evt_live(v) || !evt_text_span(v, &from, &to))
		return 0;
	t = evt_box_text(v, scratch, sizeof scratch, &n);
	if (!t)
		return 0;
	if (to > (int)n)
		to = (int)n;
	if (to <= from)
		return 0;
	len = (size_t)(to - from);
	/* cap 0 makes `cap - 1u` SIZE_MAX and the clamp a no-op - the same
	 * shape guarded in libkoforbit/antarc when it was found there. */
	if (!cap)
		return 0;
	if (len > cap - 1u)
		len = cap - 1u;
	memcpy(out, t + from, len);
	out[len] = '\0';
	return len;
}

/*
 * Take a copy of the selected event, or forget the one held.
 *
 * Called from view_select, so the panel follows the tree without every mover
 * of the cursor having to know the panel exists.
 */
void evt_load(struct view *v)
{
	const struct object *o;
	uint32_t sel, rec;
	int had_fmt;

	v->evt_have = 0;
	v->evt_n = 0;
	if (!v->log || !v->n_node)
		return;
	/*
	 * Object 0 is the log itself - "KOFT-<system>-<arch>" - and it is not
	 * a record. A panel that tried to spell it would read a header as a
	 * struct kof_evt and print whatever the two happened to share.
	 */
	sel = v->node[v->sel_node].obj;
	if (sel == 0)
		return;

	/*
	 * A CHILD IS READ THROUGH ITS PARENT - to find its BYTES, and for
	 * nothing else.
	 *
	 * The parent's record is where the join starts, so it has to be loaded
	 * to materialise the image. What it must NOT do is leave the event
	 * panel up: once a reader is on the PE row, or on one of its regions,
	 * they are looking at an executable, and a table of pids and timestamps
	 * underneath it is describing something else. The panel is closed at
	 * the end of this function for exactly that case.
	 */
	rec = v->pe_of[sel] ? v->pe_of[sel] : sel;
	had_fmt = v->obj[sel].fmt != NULL;
	o = &v->obj[rec];
	if (!o->buf.p || !o->buf.n)
		return;

	memset(&v->evt, 0, sizeof v->evt);
	memcpy(&v->evt, o->buf.p,
	       o->buf.n < sizeof v->evt ? (size_t)o->buf.n : sizeof v->evt);
	v->evt_have = 1;
	v->evt_n = (int)kof_evt_n_fields(&v->evt);

	/*
	 * THE CONTINUATIONS BEHIND IT, gathered into one buffer.
	 *
	 * The node's bytes are the whole span - the event and every chunk that
	 * followed it - so the chain is walked here rather than through the log
	 * reader: the records are already mapped and already known to be
	 * contiguous, which is what makes them one node.
	 *
	 * Through kof_evt_join, not by concatenating: the part worth having
	 * from that API is the refusal, and a viewer that joined across a
	 * dropped chunk would show a script that was never submitted.
	 */
	v->evt_join_len = 0;
	v->evt_text_len = 0;
	v->evt_wide = 0;
	v->evt_n_seg = 0;
	if (v->evt_join && v->evt_text && v->log) {
		const struct kofevt_log_hdr *h = kofevt_log_header(v->log);
		struct kof_evt_join j;
		size_t at = (size_t)h->head_size + v->evt.text_len;

		if (kof_evt_join_start(&j, &v->evt, v->evt_join,
				       EVT_JOIN_MAX)) {
			/* The record's own share, which is where the content
			 * starts in the node's bytes. */
			if (j.len) {
				v->evt_seg[0].at =
					(uint32_t)h->head_size +
					v->evt.off_object;
				v->evt_seg[0].len = (uint32_t)j.len;
				v->evt_n_seg = 1;
			}
			while (at + h->head_size <= o->buf.n) {
				struct kof_evt c;
				uint16_t tl = 0;

				memset(&c, 0, sizeof c);
				memcpy(&c, o->buf.p + at,
				       (size_t)h->head_size <= sizeof c
					       ? h->head_size : sizeof c);
				memcpy(&tl, o->buf.p + at + h->len_off,
				       sizeof tl);
				if (at + h->head_size + tl > o->buf.n)
					break;
				if (tl > sizeof c.text)
					break;
				memcpy(c.text, o->buf.p + at + h->head_size,
				       tl);
				{
					size_t was = j.len;

					if (!kof_evt_join_add(&j, &c))
						break;
					if (j.len > was &&
					    v->evt_n_seg < EVT_SEG_MAX) {
						v->evt_seg[v->evt_n_seg].at =
							(uint32_t)(at +
							   h->head_size +
							   c.off_object);
						v->evt_seg[v->evt_n_seg].len =
							(uint32_t)(j.len - was);
						v->evt_n_seg++;
					}
				}
				at += (size_t)h->head_size + tl;
			}
			v->evt_join_len = j.len;
			v->evt_wide = kof_evt_text_is_wide(v->evt_join,
							   j.len);
			v->evt_text_len = kof_evt_text_of(v->evt_join, j.len,
							  v->evt_text,
							  EVT_TEXT_MAX);

			/*
			 * THE FLAG DESCRIBED THE RECORD; THIS COPY IS THE
			 * EVENT.
			 *
			 * KOF_EF_TRUNCATED is set by the collector when the
			 * submission did not fit one record - which was true
			 * of the record and stopped being true the moment the
			 * continuations behind it were folded in. Left alone
			 * it put "text was cut" beside a submission that is
			 * whole, which is a false claim about evidence, and
			 * the worst kind: it tells a reader not to trust
			 * something that is complete.
			 *
			 * So the claim is re-made against what is actually
			 * held. kof_evt_join_whole is the one that knows -
			 * short because a chunk was lost, short because the
			 * buffer filled, or not short at all - and the warning
			 * now says only what survives that test.
			 *
			 * Not "remove the warning": a join that IS short still
			 * has to say so, and now it says so about the right
			 * thing.
			 */
			/*
			 * THE CHILD'S BYTES ARE THE JOIN, and the join is the
			 * file.
			 *
			 * kof_evt_join concatenates the CONTENT of each record
			 * and nothing else - no heads, no padding, no
			 * terminator - so what is in this buffer is what was
			 * submitted, byte for byte. An image opened from here
			 * parses exactly as it would from disk.
			 *
			 * Pointed at rather than copied: the buffer belongs to
			 * the view and lives as long as the selection does,
			 * which is exactly how long the object needs it.
			 */
			if (v->pe_of[sel] && j.len > v->pe_at) {
				struct object *c = &v->obj[sel];

				c->buf = kof_buf_make((const uint8_t *)
						      v->evt_join + v->pe_at,
						      j.len - v->pe_at);
				/*
				 * AND THROUGH THE PARSER, like any other
				 * object.
				 *
				 * The bytes are a file - kof_evt_join gives
				 * back the submission and nothing else - so
				 * there is no reason for this row to be the one
				 * place in the tool that shows an executable as
				 * undifferentiated bytes. Identified here it
				 * gets its format, its regions and everything
				 * downstream that reads ctx.
				 *
				 * Re-run per selection rather than cached: the
				 * buffer it describes is rebuilt each time the
				 * row is picked, so a kept view would describe
				 * the previous one.
				 */
				kof_inspect_free(c->fmt, c->info);
				c->info = NULL;
				c->fmt = kof_inspect_identify(c->buf, &c->ctx,
							      &c->info);
				if (!c->fmt)
					c->ctx.obj_size = c->buf.n;
				/*
				 * AND ITS REGIONS, which need the tree rebuilt
				 * because they were not knowable when it was
				 * last built: the image is materialised when
				 * the row is picked, and a region row is a
				 * question about a parsed object.
				 *
				 * Safe to do from here. tree_build does not
				 * call back into the selection, and the rows it
				 * adds for this object come AFTER the object's
				 * own row - so the selected node keeps its
				 * index and nothing has to be restored.
				 *
				 * Once per selection: the guard is fmt going
				 * from absent to present, which happens on the
				 * first load of a given child and not again.
				 */
				/*
				 * DEFERRED, NOT DONE HERE.
				 *
				 * evt_load runs inside view_select, which goes
				 * on to use v->node[v->sel_node] - and
				 * tree_build rewrites that array. Rebuilding
				 * from here left the caller holding an index
				 * into a list that had changed under it, which
				 * is a crash and was.
				 *
				 * The frame does it instead, before anything is
				 * drawn and while nothing holds a node.
				 */
				/*
				 * THE ROW SAYS WHAT IT IS, now that something
				 * has looked.
				 *
				 * "Img PE-x64" rather than "PE image": the
				 * architecture is the fact a reader most wants
				 * from a carried executable and the panel is
				 * where they are looking. Composed from the
				 * parser's own answers, so a submission that
				 * turns out to hold an ELF says ELF.
				 */
				if (c->fmt) {
					uint64_t cid = v->log_idx[sel];

					snprintf(c->label, sizeof c->label,
						 "%llu Img %s-%s",
						 (unsigned long long)cid,
						 kof_format_name(c->ctx.format),
						 kof_arch_name(c->ctx.arch));
				}
				/*
				 * AND SCANNED, because nothing else will scan
				 * it.
				 *
				 * objects_collect is skipped while a log is
				 * open - the engine would replace the event
				 * window with one object holding the whole file
				 * - so a carried image was the one object in
				 * the tool that no module ever ran against. A
				 * signature written from it could never fire,
				 * which is exactly what it looked like.
				 *
				 * ONLY WHEN IT PARSED. An image the engine
				 * cannot identify has no format for the
				 * prefilter to rule on, so a scan of it would
				 * be every module in the database against
				 * bytes nothing claimed.
				 *
				 * Once per materialisation, guarded by fmt
				 * arriving - the same edge the tree rebuild
				 * uses. Re-scanning on every keypress would
				 * spend the database on an object whose bytes
				 * have not changed.
				 */
				if (c->fmt && !had_fmt && v->eng) {
					struct kof_scan_option so;
					kof_scanner *sc2;

					memset(&so, 0, sizeof so);
					so.report_diag = 1;
					so.heur_level = KOF_HEUR_LEVEL_MAX;
					sc2 = kscan_new(v->eng);
					if (sc2) {
						v->into_obj = (int)sel;
						kscan_bytes(sc2, c->buf.p,
							       c->buf.n,
							       c->name, &so,
							       on_object, v);
						v->into_obj = -1;
						kscan_free(sc2);
					}
				}
				if (c->fmt && !had_fmt)
					v->tree_dirty = 1;
			}

			if (kof_evt_join_whole(&j, &v->evt))
				v->evt.flags &= (uint8_t)~KOF_EF_TRUNCATED;
			else
				v->evt.flags |= (uint8_t)KOF_EF_TRUNCATED;
			v->evt_n = (int)kof_evt_n_fields(&v->evt);
		}
	}

	/*
	 * AND NO PANEL FOR A CARRIED FILE.
	 *
	 * Last, because everything above it was needed: the record had to be
	 * read and the chunks joined to get the image out. What is not wanted
	 * is the explanation - the reader is on a PE now, and a field table
	 * about the event that carried it belongs to the row above.
	 */
	if (v->pe_of[sel]) {
		v->evt_have = 0;
		v->evt_n = 0;
	}

	/*
	 * The cursor is dropped, not carried across.
	 *
	 * Row 4 of one event and row 4 of the next are different fields - the
	 * list is what THIS record has - so keeping the index would move the
	 * highlight to something the reader never pointed at, in a pane whose
	 * whole claim is that the colour tells you what you picked.
	 */
	v->evt_sel = -1;
	v->evt_scroll = 0;
	/* The text selection is about THIS record's words. Carried across it
	 * would name a stretch of a string that is no longer there. */
	v->evt_txt_a = v->evt_txt_b = 0;
	v->evt_txt_drag = 0;
}


/*
 * THE EVENT PANEL - what the record above it says, in the wording montrace
 * prints.
 *
 * Deliberately the same wording. A reader who has watched the tracer's output
 * scroll past and then opens the log in here is looking at the same events, and
 * two spellings of one record - "pid" in one place and "process id" in the
 * other - is two vocabularies to learn for one fact. kof_evt_field is the one
 * source for both, so they cannot drift.
 */
void draw_evt(struct out *o, struct view *v)
{
	int head = evt_top() - 1;
	int col = TREE_W + 3;
	int meta[64], warn[64], nm = 0, nw = 0, objrow;
	int lines, half, k, row;
	int cw = (g_cols - col - 1) / 2;
	char note[48];

	if (!g_evt_rows)
		return;
	objrow = evt_zones(v, meta, &nm, warn, &nw);

	/*
	 * EVERY ROW THE PANEL OWNS, BLANKED FIRST.
	 *
	 * The panel is given g_evt_rows rows out of the bottom of the hex pane
	 * and then fills them from several independent pieces - a table whose
	 * length is the record's, warnings the record may not have, a rule and
	 * a box that only exist when the record has an object. Any piece that
	 * does not run leaves its rows untouched, and what shows through is
	 * whatever the pane drew there on the last frame: hex bytes when the
	 * panel has just opened, the draft panel's own buttons when it has
	 * just grown.
	 *
	 * Every one of those was a separate bug with a separate cause. Blanking
	 * the rectangle once, here, answers all of them and any later piece
	 * that forgets - which is the same argument draw_decl's trailing loop
	 * already makes for the draft.
	 */
	for (k = 0; k < g_evt_rows; k++) {
		out_at(o, evt_top() + k, col);
		out_str(o, "\033[K");
	}

	/* The heading, and the same close control the other panel has - a
	 * reader who has closed one knows where the other's is. */
	out_at(o, head, col);
	snprintf(note, sizeof note, " Event %s ",
		 kof_evt_verb_name(v->evt.verb));
	out_fmt(o, A_DIM "--" A_OFF A_BOLD "%s" A_OFF, note);
	out_str(o, A_DIM);
	{
		int used = col + 2 + (int)strlen(note);

		for (k = used; k < g_cols - 4; k++)
			out_str(o, "-");
	}
	out_str(o, A_OFF);
	out_at(o, head, g_cols - 3);
	out_str(o, A_D_KEY "[x]" A_OFF);

	/*
	 * THE TABLE, filled DOWN the left column and then down the right.
	 *
	 * Down-then-across, not across-then-down: the rows are in the record's
	 * own layout order, and reading a column top to bottom is then reading
	 * the record front to back. Filled across, consecutive fields would sit
	 * side by side and the eye would have to zigzag to follow the offsets.
	 */
	half = (nm + 1) / 2;
	/*
	 * THE LAST ROW THE TABLE AND THE WARNINGS MAY USE.
	 *
	 * The box is clamped into the panel - see evt_box_top - and its rule
	 * sits one row above it, so everything above stops two rows short of
	 * the box. Without this the table simply carried on and drew THROUGH
	 * the rule and the box, because the counts it walks are the record's
	 * and take no notice of how many rows the panel was given.
	 *
	 * Rows past the bound are dropped rather than scrolled. A record with
	 * more fields than a short terminal can show is a record to read on a
	 * taller one; inventing a second scrollbar for the table would put two
	 * of them in one panel, and the box already has the one that matters.
	 */
	{
		/*
		 * The rule and the box take the bottom of the panel when the
		 * record has an object; when it has none, draw_evt returns
		 * before either and the table may use every row.
		 *
		 * Reading evt_box_top() unconditionally is what broke it: with
		 * no box the value is meaningless, and once it was clamped into
		 * the panel it came out at the panel's own top - so the bound
		 * was above the first row and the table drew nothing at all.
		 */
		int table_last = objrow >= 0 ? evt_box_top(v) - 2 : hex_bot();

	for (k = 0; k < half && evt_top() + k <= table_last; k++) {
		int c2;

		row = evt_top() + k;
		out_at(o, row, col);
		for (c2 = 0; c2 < 2; c2++) {
			int idx = c2 == 0 ? k : half + k;
			char name[32], scratch[256];
			const char *val;
			uint16_t fo = 0, fl = 0;

			if (idx >= nm) {
				out_str(o, "\033[K");
				break;
			}
			if (c2)
				out_at(o, row, col + cw);
			if (!kof_evt_field(&v->evt, (unsigned)meta[idx], name,
					   sizeof name, scratch, sizeof scratch))
				continue;
			val = evt_row_value(v, meta[idx], scratch,
					    sizeof scratch);
			if (!val)
				continue;
			(void)kof_evt_field_extent(&v->evt,
						   (unsigned)meta[idx],
						   &fo, &fl);

			out_fmt(o, A_LOC "%0*X" A_OFF " ", EVT_OFF_W - 1,
				(unsigned)fo);
			out_str(o, evt_row_colour(name));
			out_fmt(o, " %-9.9s ", name);
			out_str(o, A_OFF);
			if (meta[idx] == v->evt_sel)
				out_str(o, A_BOLD);
			out_fmt(o, " %.*s", cw - EVT_OFF_W - 13, val);
			out_str(o, A_OFF);
			if (!c2)
				out_str(o, "\033[K");
		}
	}

	/* The warnings, full width and flush left - they are about the record
	 * as a whole and belong to neither zone. */
	for (k = 0; k < nw && evt_top() + half + k <= table_last; k++) {
		char name[32], scratch[256];

		row = evt_top() + half + k;
		out_at(o, row, col);
		if (kof_evt_field(&v->evt, (unsigned)warn[k], name,
				  sizeof name, scratch, sizeof scratch))
			out_fmt(o, A_WARN "! %s: %.*s" A_OFF, name,
				g_cols - col - 6, scratch);
		out_str(o, "\033[K");
	}
	}   /* table_last */

	if (objrow < 0)
		return;

	/*
	 * THE SUBMISSION, in a box of its own.
	 *
	 * A rule above it rather than a heading: the box is the rest of the
	 * panel, so what it holds needs no announcing, and a heading would cost
	 * one of the three lines it has to show text in.
	 */
	row = evt_box_top(v) - 1;
	out_at(o, row, col);
	{
		size_t n = 0;
		char lead[48], scratch[512], bname[32], bval[64];

		(void)evt_box_text(v, scratch, sizeof scratch, &n);
		if (!kof_evt_field(&v->evt, (unsigned)objrow, bname,
				   sizeof bname, bval, sizeof bval))
			bname[0] = '\0';
		{
			uint16_t bo = 0;

			/*
			 * The offset, in the same column format every field
			 * row uses. The box is a field like the others - it is
			 * only drawn differently - and a reader looking for
			 * where its bytes are should not have to click a row to
			 * find out.
			 */
			(void)evt_box_extent(v, &bo, NULL);
			snprintf(lead, sizeof lead, "  %04X  %u B%s ",
				 (unsigned)bo, (unsigned)n,
				 v->evt_wide ? " utf-16" : "");
		}
		/*
		 * THE NAME IN THE TITLE CARRIES THE FIELD'S OWN INK.
		 *
		 * The box is a field like any other and its bytes are lit in
		 * the dump; the title is the only place that says which field
		 * it is, so it is where the legend belongs. Without it the box
		 * was the one coloured run in the pane with nothing on screen
		 * naming it.
		 *
		 * The ink, not the chip. A chip is a block of ground and this
		 * sits inside a rule; the ink is what the dump uses, which is
		 * the thing being matched against.
		 *
		 * Not for `object`, whose bytes are deliberately left to the
		 * dump's own colouring - see evt_byte_colour. Colouring its
		 * title would point at a colour that is not there.
		 */
		out_str(o, A_DIM "--" A_OFF);
		if (strcmp(bname, "object"))
			out_fmt(o, "%s %s" A_OFF, evt_row_ink(bname), bname);
		else
			out_fmt(o, A_DIM " %s" A_OFF, bname);
		out_fmt(o, A_DIM "%s" A_OFF, lead);
		out_str(o, A_DIM);
		for (k = col + 2 + (int)strlen(bname) + 1 +
			 (int)strlen(lead); k < g_cols - 1; k++)
			out_str(o, "-");
		out_str(o, A_OFF);
	}
	out_str(o, "\033[K");

	lines = evt_box_total(v);
	if (v->evt_scroll > lines - EVT_BOX_ROWS)
		v->evt_scroll = lines - EVT_BOX_ROWS;
	if (v->evt_scroll < 0)
		v->evt_scroll = 0;

	{
		char scratch[512];
		size_t n = 0;
		const char *t = evt_box_text(v, scratch, sizeof scratch, &n);
		int w = evt_box_w();

		for (k = 0; k < EVT_BOX_ROWS; k++) {
			int at = (v->evt_scroll + k) * w;
			int take = (int)n - at;
			int from = 0, to = 0, a, b;

			/*
			 * The panel's own column, with the indent PRINTED
			 * rather than skipped.
			 *
			 * Nothing else draws the two columns in front of the
			 * box, and the rows above are a table whose offset
			 * column starts exactly there. Jumping straight to
			 * evt_box_x() and clearing only to the right of it
			 * left the first two characters of the PREVIOUS
			 * record's offset standing in front of the text -
			 * "0072" in the table became "00bash -c ..." in the
			 * box when the next record had a shorter table.
			 */
			out_at(o, evt_box_top(v) + k, col);
			out_str(o, "  ");
			if (at >= (int)n || take <= 0) {
				out_str(o, "\033[K");
				continue;
			}
			if (take > w)
				take = w;

			/*
			 * The picked run, clipped to this line - three flat
			 * pieces rather than a colour per character, so the
			 * wrap and the selection cannot disagree about where a
			 * line begins.
			 */
			a = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_a
							: v->evt_txt_b;
			b = v->evt_txt_a < v->evt_txt_b ? v->evt_txt_b
							: v->evt_txt_a;
			from = a - at;
			to   = b - at;
			if (from < 0) from = 0;
			if (to > take) to = take;
			if (a == b || to <= from) {
				out_fmt(o, "%.*s", take, t + at);
			} else {
				out_fmt(o, "%.*s", from, t + at);
				out_str(o, A_SELB);
				out_fmt(o, "%.*s", to - from, t + at + from);
				out_str(o, A_OFF);
				out_fmt(o, "%.*s", take - to, t + at + to);
			}
			out_str(o, A_OFF);
			out_str(o, "\033[K");
		}
		if (lines > EVT_BOX_ROWS)
			kv_scrollbar(o, g_cols, evt_box_top(v),
				  evt_box_top(v) + EVT_BOX_ROWS - 1,
				  (uint64_t)v->evt_scroll, (uint64_t)lines,
				  (uint64_t)EVT_BOX_ROWS);
	}
}
