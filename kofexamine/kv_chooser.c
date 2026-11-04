#define _GNU_SOURCE
#include "kv.h"
#include "kv_tags.h"
#include "kv_chooser_private.h"

/* The chooser popup: following the cursor and drawing. Rows are kv_chooser_items.c; what a kind opens and takes is kv_chooser_open.inc and kv_chooser_take.inc, joined below in ONE table. */

/*
 * Keep the highlighted row inside the visible window - kv_popup_follow.
 *
 * Called wherever `sel` moves. Without it an arrow key walks the cursor off
 * the end of the drawn rows and the list stops responding to the eye.
 */
void ch_follow(struct chooser *c)
{
	struct kv_popup p;

	ch_popup(c, &p);
	kv_popup_follow(&p, c->sel);
	c->box.off = p.box.off;
}

static void draw_one_chooser(struct out *o, const struct chooser *c)
{
	struct kv_popup p;

	ch_popup(c, &p);
	/* The parent keeps the cursor on the row whose list is open, so the row that was chosen goes on looking chosen. */
	kv_popup_draw(o, &p, c->sel, -1);
}

void draw_chooser(struct out *o, struct view *v)
{
	if (!v->ch.open)
		return;
	if (v->ch_up.open)
		draw_one_chooser(o, &v->ch_up);
	draw_one_chooser(o, &v->ch);
}

#include "kv_chooser_open.inc"
#include "kv_chooser_take.inc"

typedef int (*ch_open_fn)(struct view *v, struct chooser *c, uint32_t arg);

/*
 * WHAT A KIND DOES, ONE ROW EACH: indexed by enum ch_what. `open` fills the
 * rows of a zeroed chooser and answers 1 to place the list (0: nothing to show);
 * `take` acts on the row chosen. A hole, or a NULL member, is a kind with no
 * list to open (CH_NONE, CH_RANGE4) or nothing to take. The functions are static
 * in the two .inc files above, which is why the table is in this unit.
 */
struct ch_kind {
	ch_open_fn open;
	void (*take)(struct view *v);
};

static const struct ch_kind ch_kinds[] = {
	[CH_ATOFF] = { ch_open_atoff, ch_take_atoff },
	[CH_RULE] = { ch_open_rule, ch_take_rule },
	[CH_RANGE] = { ch_open_range, ch_take_range },
	[CH_RANGE2] = { ch_open_range2, ch_take_range2 },
	[CH_RANGE_ADD] = { ch_open_range_add, ch_take_range_add },
	[CH_RANGE_EXT] = { ch_open_range_pick, ch_take_range_pick },
	[CH_RANGE_DROP] = { ch_open_range_pick, ch_take_range_pick },
	[CH_HFAM] = { ch_open_hfam, ch_take_hfam },
	[CH_HVAR] = { ch_open_hvar, ch_take_hvar },
	[CH_UTYPE] = { ch_open_utype, ch_take_utype_utag },
	[CH_UTAG] = { ch_open_utag, ch_take_utype_utag },
	[CH_MARKER] = { ch_open_marker, ch_take_marker },
	[CH_CMATCH] = { ch_open_cmatch, ch_take_cmatch },
	[CH_CMATCH2] = { ch_open_cmatch2, ch_take_cmatch2 },
	[CH_CSWAP] = { ch_open_cswap, ch_take_cswap },
	[CH_FMT] = { ch_open_fmt, ch_take_fmt },
	[CH_FMT_SW] = { ch_open_fmt_sw, ch_take_fmt_sw },
	[CH_FMT_SW_LANG] = { ch_open_fmt_sw_lang, ch_take_fmt_sw_lang },
	[CH_FMT_CAT] = { ch_open_fmt_cat, ch_take_fmt_cat },
	[CH_FMT_LANG] = { ch_open_fmt_lang, ch_take_fmt_lang },
	[CH_FMT_ADD] = { ch_open_fmt_add, ch_take_fmt_add },
	[CH_ENC_TYPE] = { ch_open_enc_type, ch_take_enc_type },
	[CH_OPT] = { ch_open_opt, ch_take_opt },
	[CH_ARCH] = { ch_open_arch, ch_take_arch },
	[CH_SUBTYPE] = { ch_open_subtype, ch_take_subtype },
	[CH_DECLKIND] = { ch_open_declkind, ch_take_declkind },
	[CH_ATTR] = { ch_open_attr, ch_take_attr },
	[CH_THRESH] = { ch_open_thresh, ch_take_thresh },
};

/* The rows of a chooser as a pop-up: an item is a row of its own (the id is its index), a separator a rule, a row that opens a list carries the ">". */
void ch_popup(const struct chooser *c, struct kv_popup *p)
{
	int i;

	kv_popup_init(p, 1);
	for (i = 0; i < c->n; i++)
		kv_popup_add(p, c->item[i], c->sep[i] ? KV_PR_RULE : c->sub[i] ? KV_PR_SUB : 0u, i);
	p->box = c->box;
}

/*
 * `row` IS THE CONTROL'S OWN ROW - g_my, and nothing arithmetic on it.
 *
 * The list is placed at row + 1, under the control, for the reasons written
 * where that is done. It did not always open downwards, and while it opened
 * UPWARDS five callers subtracted 2 or 3 to push it clear of the rows above
 * them. Those subtractions outlived the change and then pointed the wrong way:
 * a similarity matcher is two rows, so [+ Similarity] on its second row opened
 * its list at g_my - 2, one row ABOVE the matcher's own heading - the list was
 * drawn over the title of the thing it was adding to.
 *
 * Twenty-two callers pass g_my and five did not, two of them beside a sibling
 * in the same function that does. So the rule is here, in one place: hand this
 * the row that was clicked, and let it decide where the list goes.
 */
static void ch_open_in(struct view *v, int what, uint32_t arg, int row, int col, const struct chooser *up)
{
	struct chooser *c = &v->ch;

	memset(c, 0, sizeof *c);
	c->what = what;
	c->arg = arg;

	if (what < 0 || (size_t)what >= sizeof ch_kinds / sizeof ch_kinds[0] ||
	    !ch_kinds[what].open || !ch_kinds[what].open(v, c, arg))
		return;


	/*
	 * BESIDE WHAT WAS CLICKED, never on top of it, and BELOW IT FIRST.
	 *
	 * A list that covers its own control hides the thing being changed, and
	 * the click that would dismiss it lands on the list instead - so the
	 * next click goes into closing rather than doing, and the control below
	 * looks broken. That much has always been the rule; the direction was
	 * up, and up is where a panel keeps the heading that says what section
	 * the control belongs to. Opening [+ Matcher] painted the list straight
	 * over "Matchers" and the rows under it - the reader lost sight of what
	 * they were adding to at the moment of adding to it.
	 *
	 * So: the row under the control, which is where a list belongs and
	 * where the eye already is. Above only when the list does not fit
	 * below, which is the case the screen bottom forces.
	 */
	/* The last row of a list that did not fit says how many are missing (it stands in for one more, which is counted). */
	if (c->more)
		snprintf(c->item[c->n - 1], CH_W, "(%d more not shown)", c->more + 1);
	c->open = 1;
	/*
	 * THE BOX IS kv_popup_place's, and nothing here decides a row or a column.
	 *
	 * A list under a control: below it, above it when that is the room, the whole usable height (and then it scrolls) when neither
	 * is. A list a row of another opened (`up`): beside that row, its top on the row's own screen row, on the right of the parent
	 * or on the left when the right has no room. Both used to be worked out here, once by hand: the first with a width one wider
	 * than the rows drawn, the second two rows below its parent and one column off it.
	 */
	{
		struct kv_popup p;
		struct kv_popup_req q;

		ch_popup(c, &p);
		kv_popup_screen(&q);
		q.ay = row;
		q.ax = col;
		q.anchor_h = 1;
		q.min_w = CH_W_MIN;
		q.max_w = CH_W;
		if (up) {
			/* Rows of a chooser are its items one for one, so the parent's row is its cursor's position in its box. */
			int pr = up->box.y + up->sel - up->box.off;

			q.parent = &up->box;
			q.parent_row = pr >= up->box.y && pr < up->box.y + up->box.h ? pr : up->box.y;
			q.anchor_h = 0;
		}
		kv_popup_place(&p, &q);
		c->box = p.box;
	}

	/*
	 * NO ROW IS THE CURSOR YET, and that is the whole of it.
	 *
	 * The list opened on row zero highlighted, which claims something the
	 * reader has not done: they pressed a control to SEE the choices, not
	 * to hover the first one. Worse on a submenu - the highlight jumped off
	 * the category they had just clicked and onto a row of the list it
	 * opened, so the thing they chose stopped looking chosen.
	 *
	 * -1 is "the keyboard is not here". An arrow key brings it to row zero;
	 * a click names its own row and never consults this.
	 */
	c->sel = -1;
}

void ch_open(struct view *v, int what, uint32_t arg, int row, int col)
{
	ch_open_in(v, what, arg, row, col, NULL);
}

/* A list opened by a row of `up` (a copy of the parent taken before the new list replaces it): beside that row. */
void ch_open_beside(struct view *v, int what, uint32_t arg, const struct chooser *up)
{
	ch_open_in(v, what, arg, up->box.y, up->box.x, up);
}

void ch_take(struct view *v)
{
	struct chooser *c = &v->ch;

	c->open = 0;
	v->ch_up.open = 0;
	if (c->more && c->sel == c->n - 1)
		return;                         /* the "N more" row picks nothing */
	if (c->what >= 0 && (size_t)c->what < sizeof ch_kinds / sizeof ch_kinds[0] &&
	    ch_kinds[c->what].take)
		ch_kinds[c->what].take(v);
}
