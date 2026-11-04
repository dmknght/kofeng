#define _GNU_SOURCE
#include "kv.h"
#include "kv_evt_private.h"

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
int evt_box_x(void)  { return TREE_W + 3 + 2; }
int evt_box_w(void)
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
int evt_box_extent(const struct view *v, uint16_t *off, int *step)
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
