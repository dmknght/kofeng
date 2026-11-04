#define _GNU_SOURCE
#include "kv.h"
#include <celllysis/disasm.h>
#include "kv_bar_private.h"


/*
 * The menu's three states, as one scheme rather than three unrelated choices.
 *
 * They were: enabled on a dark panel, disabled on a WHITE one, and the cursor
 * as a bare reverse-video. So the drop-down had two background colours at once,
 * the brighter of the two belonged to the items you cannot use - which made the
 * dead entries the loudest thing on screen - and the cursor, being a reverse of
 * whatever happened to be current, came out the same white as the disabled
 * rows. Three states, two of them indistinguishable, and the emphasis backwards.
 *
 * One background for the whole panel, so it reads as one panel; disabled differs
 * only in how bright its text is, which is what "disabled" should look like; and
 * the cursor is the one row that inverts, stated explicitly instead of reversing
 * whatever the terminal was left holding.
 */

/*
 * 37 and not 90 for the disabled row, which is the whole trick.
 *
 * 90 is bright black and 100 is bright black as a background - the same colour
 * twice, so the label is not dim, it is GONE. The note on the Save button in
 * this file says exactly that and this managed to walk into it anyway while
 * fixing something else. 37 is the ordinary white: clearly weaker than the 97
 * beside it, still ink on the panel rather than a hole in it.
 *
 * The rule this leaves behind: a foreground and a background from the same
 * pair - 30/40, 37/47, 90/100, 97/107 - is never a colour, it is an erasure.
 */

#define BAR_W 30


/*
 * The menu bar's drop-down and its submenu, as kv_menu sees them.
 *
 * Two descriptors over one table: `shown` is what distinguishes them, because a
 * drop-down holds the items of one menu that have no parent and a submenu holds
 * the children of one of those. Everything after that - where the rows land,
 * which one a click hit, how a greyed one is drawn - is the same question and
 * is now answered in one place.
 */
static int bm_shown_top(void *ud, int i)
{
	struct view *v = ud;

	return bar_item[i].menu == v->bar_open && bar_item[i].parent < 0 &&
	       bar_shown(v, i);
}

static int bm_shown_sub(void *ud, int i)
{
	struct view *v = ud;

	return bar_item[i].parent == v->bar_sub && bar_shown(v, i);
}

static int bm_enabled(void *ud, int i) { return bar_enabled((struct view *)ud, i); }
static int bm_rule(void *ud, int i)    { return bar_gap((struct view *)ud, i); }
static int bm_sub(void *ud, int i)     { (void)ud; return bar_has_sub(i); }
static const char *bm_label(void *ud, int i)
{
	return bar_label((struct view *)ud, i);
}

/* The drop-down is shown as a pop-up of at most one row per item and one rule above each: kv_popup_add refuses past KV_POP_MAX, so that must fit. */
_Static_assert(2 * BI_COUNT <= KV_POP_MAX, "the menu bar can hold more rows than a pop-up: raise KV_POP_MAX");

static struct kv_menu bar_menu(struct view *v, int sub)
{
	struct kv_menu m;

	memset(&m, 0, sizeof m);
	m.n = BI_COUNT;
	m.ud = v;
	m.shown = sub ? bm_shown_sub : bm_shown_top;
	m.enabled = bm_enabled;
	/*
	 * A submenu draws rules too. It used not to, on the grounds that the
	 * children of one item are one group - which held while the only
	 * submenu was two dump kinds, and stopped holding with the event
	 * filter: a list of checkboxes followed by the button that acts on
	 * them is two groups, and without a rule between them Apply reads as
	 * one more thing to tick.
	 *
	 * It still never opens a further submenu - nothing nests that deep,
	 * and has_sub is what would draw the arrow saying it did.
	 */
	m.rule_above = bm_rule;
	m.has_sub = sub ? NULL : bm_sub;
	m.label = bm_label;
	m.w = BAR_W;
	return m;
}

static int bar_popups(struct view *v, struct kv_popup *top, struct kv_popup *sub);

void draw_bar(struct out *o, struct view *v)
{
	int m, i;

	row_start(o, 1, 1);
	out_str(o, A_HEAD " ");
	for (m = 0; m < BM_COUNT; m++) {
		/* The open menu's title wears the same highlight its panel
		 * uses, so the two read as one control rather than two. */
		if (m == v->bar_open)
			out_fmt(o, BAR_CUR " %s " A_HEAD, bar_name[m]);
		else
			out_fmt(o, " %s ", bar_name[m]);
	}
	for (i = (int)o->col_hint; i < g_cols; i++)
		out_str(o, " ");
	out_str(o, A_OFF);

	if (v->bar_open < 0)
		return;

	/* The drop-down, drawn over whatever is under it, and its submenu beside the row it belongs to. */
	{
		struct kv_popup top, sub;
		int has_sub = bar_popups(v, &top, &sub);

		kv_popup_draw(o, &top, v->bar_sel, v->bar_sub);
		if (has_sub)
			kv_popup_draw(o, &sub, v->bar_sel, -1);
	}
}

/*
 * The drop-down and, when one is open, its submenu: the boxes kv_popup_place decides. Where each menu's block starts on the bar is
 * bar_col; the submenu opens beside its parent's row (on the left when the right has no room), so the drawing and the click test below
 * read one answer. Returns 1 when `sub` is filled.
 */
static int bar_popups(struct view *v, struct kv_popup *top, struct kv_popup *sub)
{
	struct kv_menu mt = bar_menu(v, 0);
	struct kv_popup_req q;
	int r;

	kv_menu_popup(&mt, top);
	kv_menu_req(&mt, 2, bar_col(v->bar_open), 0, &q);
	kv_popup_place(top, &q);
	if (v->bar_sub < 0)
		return 0;
	r = kv_popup_row_y(top, v->bar_sub);
	if (r < 0)
		return 0;
	{
		struct kv_menu ms = bar_menu(v, 1);

		kv_menu_popup(&ms, sub);
		kv_menu_req(&ms, r, top->box.x + top->box.w, 0, &q);
		q.parent = &top->box;
		q.parent_row = r;
		kv_popup_place(sub, &q);
	}
	return 1;
}

/*
 * Which item a click on an open drop-down landed on, or -1.
 *
 * The submenu is tested FIRST: it is drawn over whatever is beside its parent, so a click inside it is its click whatever else is there.
 */
int bar_item_at(struct view *v, int row, int col)
{
	struct kv_popup top, sub;
	int r;

	if (bar_popups(v, &top, &sub)) {
		r = kv_popup_hit(&sub, row, col);
		if (r >= 0)
			return sub.row[r].id;
	}
	r = kv_popup_hit(&top, row, col);
	return r >= 0 ? top.row[r].id : -1;
}

/* The items of one menu, in table order. Returns how many, up to `cap`. */
static int bar_items_of(struct view *v, int menu, int *out, int cap)
{
	int i, n = 0;

	for (i = 0; i < BI_COUNT && n < cap; i++)
		if (bar_shown(v, i) && bar_item[i].menu == menu &&
		    bar_item[i].parent < 0)
			out[n++] = i;
	return n;
}

/*
 * The rows of a submenu: the children of `parent`.
 *
 * Same filter as the loop that DRAWS them, because a cursor that walks a
 * different set from the one on the screen is a cursor that skips rows or rests
 * on rows nobody can see.
 */
static int bar_kids_of(struct view *v, int parent, int *out, int cap)
{
	int i, n = 0;

	for (i = 0; i < BI_COUNT && n < cap; i++)
		if (bar_shown(v, i) && bar_item[i].parent == parent)
			out[n++] = i;
	return n;
}

/*
 * Open item `i`'s submenu and put the cursor on its first usable row.
 *
 * While a submenu is open the cursor lives INSIDE it - bar_sel holds a child -
 * and the parent stays lit through bar_sub. Without this the submenu drew rows
 * that nothing selected and Enter ran the parent again, so the keyboard could
 * open a submenu and then not reach anything in it.
 */
void bar_enter_sub(struct view *v, int i)
{
	int kids[BI_COUNT], n = bar_kids_of(v, i, kids, BI_COUNT), k;

	v->bar_sub = i;
	v->bar_sel = n ? kids[0] : i;
	for (k = 0; k < n; k++)
		if (bar_enabled(v, kids[k])) {
			v->bar_sel = kids[k];
			break;
		}
}

/*
 * Open a menu by index and land the cursor on its first usable item.
 *
 * First ENABLED, not first: a menu whose top row is greyed - File's "Open",
 * which is not built yet - would otherwise open with the cursor on something
 * that does nothing, and an arrow press to leave it reads as the key not
 * working.
 */
void bar_open_menu(struct view *v, int menu)
{
	int items[BI_COUNT], n = bar_items_of(v, menu, items, BI_COUNT), i;

	/*
	 * AND A BAR MENU OPENS EMPTY TOO, for the reason menu_open_at gives.
	 * This lit the first enabled item, so opening the bar with the pointer
	 * pointed at a command nobody had chosen.
	 */
	(void)items; (void)n; (void)i;
	v->bar_open = menu;
	v->bar_sub = -1;
	v->bar_sel = -1;
}

/* Move the cursor up or down within the open menu, skipping disabled rows so
 * the cursor never rests on something Enter would ignore. */
void bar_move_item(struct view *v, int dir)
{
	int items[BI_COUNT], n, cur = -1, i, step;

	if (v->bar_open < 0)
		return;
	n = v->bar_sub >= 0 ? bar_kids_of(v, v->bar_sub, items, BI_COUNT)
			    : bar_items_of(v, v->bar_open, items, BI_COUNT);
	for (i = 0; i < n; i++)
		if (items[i] == v->bar_sel)
			cur = i;
	/*
	 * FROM NOTHING, EITHER END - see menu_step. A menu now opens with no
	 * item lit, and `cur` is then -1: stepping down must land on the first
	 * item and stepping up on the LAST, which -1 gives for down and not
	 * for up.
	 */
	if (cur < 0 && dir < 0)
		cur = 0;
	for (step = 0; step < n; step++) {
		cur = (cur + dir + n) % n;
		if (bar_enabled(v, items[cur])) {
			v->bar_sel = items[cur];
			return;
		}
	}
}


void bar_run(struct view *v, int i)
{
	if (!bar_enabled(v, i)) {
		/*
		 * A GREYED ITEM THAT DOES NOTHING WHEN CLICKED TEACHES NOTHING.
		 *
		 * Any item can be pressed from any pane, so it answers through
		 * act_msg - the slot that shows wherever the reader is and fades
		 * on its own.
		 */
		const char *why = bar_why_off(v, i);

		if (why) {
			snprintf(v->act_msg, sizeof v->act_msg, "%s", why);
			v->act_ok = 0;
		}
		return;
	}
	/* A parent opens; it does not act. Clicking it again closes what it
	 * opened, so the same press undoes itself. */
	if (bar_has_sub(i)) {
		if (v->bar_sub == i) {
			v->bar_sub = -1;
			v->bar_sel = i;
		} else {
			bar_enter_sub(v, i);
		}
		return;
	}
	/*
	 * A CHECKBOX DOES NOT CLOSE THE MENU, which is the whole difference
	 * between it and every other row here.
	 *
	 * Turning three verbs off means three presses, and a menu that shut
	 * after each one would mean reopening and re-descending twice. So the
	 * toggle happens before the close below and returns - the submenu
	 * stays exactly where it was, with the row now ticked.
	 */
	{
		int verb = bar_filt_verb(i);

		if (verb > 0) {
			v->log_keep ^= 1u << (unsigned)verb;
			return;
		}
	}

	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;
	switch (i) {
	case BI_FILT_APPLY:
		/*
		 * Applied to the OBJECT PANEL by rebuilding the window: the
		 * filter is part of what a window contains, so there is one
		 * place that knows about it and no second filtering step for
		 * the two to disagree at.
		 *
		 * Back to the start of the log rather than staying put,
		 * because the event the selection was on may be one of the
		 * ones just hidden - and a selection pointing at a row that no
		 * longer exists is the way a panel starts describing the wrong
		 * event.
		 */
		if (v->log) {

			v->log_first = 0;
			log_window(v);
			tree_build(v);
			v->sel_node = 0;
			v->sel_a = v->sel_b = KGENOME_BROKEN;
			v->dis_have = 0;
			view_select(v);
			if (!v->log_keep)
				snprintf(v->act_msg, sizeof v->act_msg,
					 "Every event type is unticked - "
					 "nothing to show");
			else
				snprintf(v->act_msg, sizeof v->act_msg,
					 "Filtered: %u event(s) in the window",
					 (unsigned)(v->n_obj ? v->n_obj - 1u
							     : 0));
			v->act_ok = 1;
		}
		break;
	/*
	 * IT HAD NO CASE, so it fell to `default: break;` - the menu closed and
	 * the program stayed open. That is the failure the note further down
	 * describes for BI_FIND, and this was the other instance of it: an item
	 * bar_enabled reports live, with nothing behind it.
	 *
	 * No confirmation, matching Ctrl+Q, which leaves whatever is open
	 * without asking. Two ways out that disagree about that would be worse
	 * than either.
	 */
	case BI_QUIT:    v->quit = 1; break;
	case BI_FIND:
		v->find_open = 1;
		v->goto_open = 0;              /* they share the box */
		v->edit = 500;
		v->ed.dr.warn[0] = 0;
		break;
	/* An item has to be here as well as in
	 * bar_enabled: an item that reports itself live and has no case falls
	 * to `default: break;` - the menu closes and nothing happens, which
	 * is exactly how BI_GOTO looked before the dialog existed. */
	case BI_SYNTAB:
		tags_open(v);
		break;
	case BI_FAMILIES:
		fam_open(v);
		break;
	case BI_INFECTION:
		prop_show_infection(v);
		v->act_msg[0] = 0;
		break;
	case BI_GOTO:
		v->goto_open = 1;
		v->find_open = 0;      /* they share the box - see draw_goto */
		v->gotobuf[0] = 0;
		v->num_fresh = 1;
		v->edit = 520;
		v->ed.dr.warn[0] = 0;
		break;
	case BI_DUMP_STATIC: dump_all(v, 0); break;
	case BI_DUMP_PLAIN:  dump_all(v, 0); break;
	case BI_DUMP_EMU:    dump_all(v, 1); break;
	case BI_UNPACKER: emu_here(v); break;
	case BI_DISASM:   dis_toggle(v, 0, KGENOME_BROKEN); break;
	case BI_DISANALYSE: dis_analyse(v); break;
	case BI_NEXT:    open_step(v, +1); break;
	case BI_PREV:    open_step(v, -1); break;
	case BI_SEPARATE: separate_now(v); break;
	case BI_REBUILD: rebuild_db(v); break;
	case BI_ENCSTR:
		enc_open_with(v, NULL, 0);      /* keeps whatever was typed */
		v->act_msg[0] = 0;
		break;
	case BI_DASH:
		/* Whatever the last copy or dump said belongs to the screen
		 * it was said on, not to a page opened afterwards. */
		prop_show(v);
		v->act_msg[0] = 0;
		break;
	case BI_KEYS:    v->help_open = 1; v->help_off = 0; break;
	case BI_ABOUT:   v->help_open = 2; v->help_off = 0; break;
	default: break;
	}
}
