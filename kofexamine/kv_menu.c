#define _GNU_SOURCE
#include "kv.h"



/* ---- the context menu -----------------------------------------------------
 *
 * What can be done with a selection, at the place it was made. A menu rather
 * than more keys: two copies and two ways of declaring a marker are four things
 * nobody will remember bindings for, and the reason this is a TUI rather than a
 * printout is that a pointer beats a manual.
 *
 * Items that cannot apply are drawn and disabled rather than hidden. A menu
 * whose shape changes has to be read every time; one that greys an item says
 * what is missing - here, that nothing is selected.
 */
enum menu_action {
	/*
	 * First, because it is first in the panel's menu and the table's order
	 * is the menu's order. It is shown ONLY there - in the hex pane there
	 * is no disassembly to copy - so putting it at the top costs the hex
	 * menu nothing.
	 */
	M_COPY_DISASM = 0,
	M_COPY_ASCII,
	M_COPY_HEX,
	M_COPY_OFF_HEX,
	M_COPY_OFF_DEC,
	M_DECL_STR,
	M_DECL_HEX,
	M_DISASM,
	/*
	 * READ THESE BYTES THE OTHER WAY - text, or a hex dump.
	 *
	 * Offered only where both readings mean something, which is a script or
	 * a text file: a hex dump of a php shell is unreadable and the text of
	 * an ELF is a column of dots. One item whose word flips, because it is
	 * one question - see the table.
	 */
	M_VIEW_HEX,
	/*
	 * The selected bytes, put into the Decoder's input field.
	 *
	 * On the bytes and not the offset column: it is a question about
	 * CONTENTS. It does not decode anything by itself - it fills the field
	 * and opens the box, because which coding these bytes are is the
	 * reader's to say and not this menu's to guess.
	 */
	M_DECODE,
	M_GOTO,
	M_FIND_STR,
	M_FIND_HEX,
	/*
	 * WHICH BLOCK THESE BYTES ARE IN, asked from the bytes rather than
	 * from the table.
	 *
	 * The block table answers "where is this block"; a reader looking at a
	 * run of bytes has the opposite question, and until now had to read
	 * offsets off the table and compare them by eye. Same pane, same
	 * gesture, other direction.
	 */
	M_MUTATION_WHICH,

	/*
	 * THE EVENT BOX'S OWN TWO, and they are separate items rather than the
	 * ones above with another context bit.
	 *
	 * "Copy text" already exists for the hex pane and copies the readable
	 * half of a BYTE selection. The box's selection is a run of characters
	 * in a rendering - UTF-16 already collapsed, padding already trimmed -
	 * so it is a different thing to copy, and one item that meant two
	 * things depending on where the reader right-clicked would be the kind
	 * of item nobody can predict.
	 */
	M_EVT_COPY,
	M_EVT_COPY_ALL,
	M_EVT_DECL,
	/*
	 * THE STRING DECODER'S PLAINTEXT WINDOW, and its own two items for the
	 * reason the event box has its own two: what is selected there is a run
	 * of CHARACTERS in something this program decoded, not a range of bytes
	 * in the file, so "Copy text" over there would mean a different thing
	 * from "Copy text" here. One item that means two things depending on
	 * where the reader right-clicked is an item nobody can predict.
	 */
	M_DEC_COPY,
	M_DEC_DECL,
	M_COUNT
};


/*
 * A menu item, and which half of the pane it belongs to.
 *
 * Right-clicking the offset column and right-clicking a byte are two different
 * questions - one is about a place, the other about contents - so they get two
 * menus. One table rather than two keeps the order and the wording in one
 * place; `ctx` is a mask, 1 for the bytes and 2 for the offset column, and the
 * items that make sense on either carry both.
 */
/* The Decoder - both directions, see enc_way. Defined with the other dialogs,
 * reached from the menu bar, from the hex pane's own menu, and from the draw
 * loop. */

static const struct {
	const char *label;
	int         ctx;
	int         group;      /* a rule is drawn where this changes */
} menu_item[M_COUNT] = {
	/*
	 * "Copy", not "Copy disassembly".
	 *
	 * It only ever appears in the disassembly panel, so the noun would be
	 * the panel's own name repeated back at the reader - and the item below
	 * it is "Copy hex", which is the one that DOES need saying because it
	 * copies something other than what is selected on screen.
	 */
	{ "Copy",                 4, 0 },
	/*
	 * "Copy text", not "Copy ASCII".
	 *
	 * ASCII is what the ENCODING was assumed to be, not what the reader is
	 * asking for - and it stopped being true as soon as the pane started
	 * showing UTF-16 script blocks. What the item does is give back the
	 * readable half of the selection, whatever that turns out to be, and
	 * naming it after one encoding invites the question of which item to
	 * use for the others. There is only this one.
	 */
	{ "Copy text",            1, 0 },
	{ "Copy hex",         1 | 4, 0 },
	{ "Copy offset (hex)",    2, 0 },
	{ "Copy offset (dec)",    2, 0 },
	{ "Declare as string",    1, 1 },
	{ "Declare as hex",   1 | 4, 1 },
	/*
	 * On the bytes and not on the offset column, and in its own group.
	 *
	 * It answers the question the other two do not: those turn a selection
	 * into a signature, this one asks what the selection DOES. It is also
	 * the only way into the panel for bytes with no region behind them - a
	 * payload lifted out of an encoder is one flat run and no CODE row
	 * exists to move to - which is the case it earns its place on.
	 */
	{ "View disassembly",     1, 2 },
	/*
	 * THE LABEL FLIPS - see cm_label. One item, because it is one question
	 * asked from either side: a script can be read as text or as bytes, and
	 * whichever it is showing, the item offers the other. Two items, one of
	 * them always greyed, would be a menu describing a mode rather than
	 * offering a change.
	 */
	{ "View hex",         1 | 2, 2 },
	{ "Decode string",    1 | 4, 2 },
	{ "Go to",                3, 3 },
	/*
	 * Offered in the panel too: looking at an instruction and wanting to
	 * find the next place those bytes appear is the same question asked
	 * from a different pane.
	 */
	{ "Find string",      3 | 4, 3 },
	{ "Find hex",         3 | 4, 3 },
	{ "Which mutation block",   3, 3 },

	/* Context 8: the event panel's text box. Nothing else offers these and
	 * they offer nothing else. */
	{ "Copy text",            8, 0 },
	/*
	 * The whole submission, not the part that was dragged.
	 *
	 * Directly under "Copy text" because it is the same verb over a wider
	 * subject, and a reader who has just failed to select two thousand
	 * characters by dragging should find it there.
	 *
	 * OFFERED ONLY WHEN THE CONTENT IS TEXT. A submission carrying a PE is
	 * an executable, and its rendering is a column of dots with the
	 * printable fragments of a binary between them - putting that on a
	 * clipboard gives back something that is neither the file nor a
	 * readable quotation of it. What that case wants is a dump, which is a
	 * different item and does not exist yet.
	 */
	{ "Copy all text",        8, 0 },
	{ "Declare as text",      8, 1 },
	{ "Copy text",           16, 0 },
	{ "Declare as string",   16, 1 }
};

static int decl_sel_is_text(struct view *v);

static int menu_shown(struct view *v, int a)
{
	/*
	 * A RECORD HAS NO INSTRUCTIONS.
	 *
	 * "View disassembly" asks what a run of bytes DOES, which is a question
	 * about code. An event's bytes are a struct: integers, offsets and a
	 * text arena. Disassembling them produces a page of plausible-looking
	 * instructions that correspond to nothing, which is worse than an empty
	 * panel because it reads as an answer.
	 *
	 * Hidden rather than greyed, and the rule under it goes with it - the
	 * separator existed to set this item apart from the two around it, so
	 * with the item gone it would be a line dividing nothing from nothing.
	 * menu_gap counts only SHOWN rows, so that follows on its own.
	 */
	if (v->log && a == M_DISASM)
		return 0;
	/*
	 * A RUN OF HEX HAS NO STRING TO DECLARE, so the item is not offered.
	 *
	 * Greyed, it was a choice that is not one: the bytes are on screen, the
	 * reader can see they are not text, and the item's only message was
	 * "not this one". The menu now shows the declaration that applies -
	 * "Declare as hex" - and nothing beside it.
	 *
	 * Only this reason hides it. Nothing selected, too long, too many
	 * markers: those keep the item visible and greyed, because they are
	 * things the reader can go and fix, and a vanishing item would not say
	 * what to fix. See decl_sel_is_text.
	 */
	if (a == M_DECL_STR && !decl_sel_is_text(v))
		return 0;
	/*
	 * AND NEITHER HAS A SCRIPT.
	 *
	 * The same question, asked of the object rather than of the log flag: a
	 * PHP file, a shell script, a JSP page are TEXT, and asking what a run
	 * of their bytes does as instructions produces a page of plausible
	 * x86 that corresponds to nothing. The log rule above was written for
	 * event records and stopped there, so every text format kept the item -
	 * greyed at best, because menu_enabled tests the arch and a script has
	 * none, and a greyed row is still a row that says the tool thinks this
	 * might be code.
	 *
	 * obj_maybe_code is the answer the disassembler and the emulator
	 * already share, and it is the parse's own claim rather than anything
	 * worked out here: where the format was named and the name is not code,
	 * no; where nothing named it, yes, because unclaimed bytes are exactly
	 * what a peeled payload looks like.
	 */
	if (a == M_DISASM && !obj_maybe_code(cur_obj(v)))
		return 0;
	/*
	 * BOTH READINGS HAVE TO MEAN SOMETHING, and that is a property of the
	 * FORMAT rather than of what the pane is doing right now - otherwise
	 * the item would vanish the moment it was used and there would be no
	 * way back.
	 */
	if (a == M_VIEW_HEX && !view_can_text(v))
		return 0;
	return (menu_item[a].ctx & v->menu_ctx) != 0;
}

/*
 * WHY A DECLARATION WOULD BE REFUSED, in a sentence, or NULL when it would not.
 *
 * ONE FUNCTION FOR THE TEST AND FOR THE REASON, because they were two things
 * and only the test existed. The menu greyed the row and menu_run returned, so
 * a declaration that could not be made produced NOTHING ON SCREEN - and a
 * feature that silently does nothing is indistinguishable from a broken one.
 * That is exactly how it was reported: "<td colspan=\"2\"> sometimes declares
 * and sometimes does not", which is a selection that sometimes included the
 * line ending and a refusal that never said so.
 *
 * The answer is a sentence the reader can act on - shorten the selection, use
 * hex, remove a marker - rather than a control that has gone quiet.
 *
 * Nothing is said on SUCCESS. The row appearing in the panel is the
 * confirmation, and a tool that reports its successes teaches the reader to
 * stop reading its messages.
 */
static const char *decl_why(struct view *v, int hex)
{
	static char why[160];
	uint64_t lo, hi, k, bn = 0;
	const uint8_t *bp;
	uint8_t t[DECL_BYTES_MAX];
	uint32_t n = 0;

	if (v->sel_a == KGENOME_BROKEN || v->sel_b == KGENOME_BROKEN)
		return "Select the bytes first - drag over them in the pane";
	if (v->ed.dr.n_decl >= MAX_DECL) {
		snprintf(why, sizeof why,
			 "This draft already holds %u markers, which is all a "
			 "rule may have", (unsigned)MAX_DECL);
		return why;
	}
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	/* Bounded whichever kind it is. Unbounded, a drag over a whole object
	 * declared a marker whose spelling no field could hold and no row
	 * could show. */
	if (hi - lo + 1u > DECL_BYTES_MAX) {
		snprintf(why, sizeof why,
			 "%llu bytes selected - a marker holds at most %u",
			 (unsigned long long)(hi - lo + 1u),
			 (unsigned)DECL_BYTES_MAX);
		return why;
	}
	if (hex)
		return NULL;

	/*
	 * Through view_bytes, or this judges the wrong bytes.
	 *
	 * It read the object's buffer at what view_map returns, which on a
	 * symbol row is an offset into the built block - so literal_safe was
	 * asked about unrelated file bytes at the same number and said no over
	 * a selection that was plain ASCII on screen.
	 */
	bp = view_bytes(v, &bn);
	if (!bp)
		return "These bytes are not in this object";
	for (k = lo; k <= hi; k++) {
		uint64_t f = view_map(v, k, 0);

		if (f >= bn)
			return "Part of this selection is not in this object";
		t[n++] = bp[f];
	}
	if (!literal_safe(t, n)) {
		uint32_t i;

		for (i = 0; i < n; i++)
			if (!(t[i] == '\t' || t[i] == '\n' || t[i] == '\r') &&
			    (t[i] < 0x20u || t[i] > 0x7eu))
				break;
		snprintf(why, sizeof why,
			 "Byte %u of the selection is 0x%02x, which is not "
			 "text - declare these bytes as hex instead",
			 (unsigned)i + 1u, i < n ? t[i] : 0);
		return why;
	}
	return NULL;
}

/*
 * IS THE SELECTION TEXT - asked on its own, because two callers want different
 * things from the answer.
 *
 * menu_enabled wants a REASON, to grey an item and say why. menu_shown wants a
 * yes or no, to leave the item out altogether. Offering "Declare as string"
 * greyed over a run of hex is offering a choice that is not one: the reader can
 * see the bytes, they are not text, and the item's only message is "not this
 * one". So the menu shows the item that applies.
 *
 * Only about the bytes. Every other reason decl_why can give - nothing
 * selected, too many markers, too long - applies to both kinds equally, and
 * those keep the item visible and greyed, because they are things the reader
 * can fix.
 */
static int decl_sel_is_text(struct view *v)
{
	uint64_t lo, hi, k, bn = 0;
	const uint8_t *bp;
	uint8_t t[DECL_BYTES_MAX];
	uint32_t n = 0;

	if (v->sel_a == KGENOME_BROKEN || v->sel_b == KGENOME_BROKEN)
		return 1;       /* nothing selected yet: not a verdict */
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	if (hi - lo + 1u > DECL_BYTES_MAX)
		return 1;       /* too long is a different complaint */
	bp = view_bytes(v, &bn);
	if (!bp)
		return 1;
	for (k = lo; k <= hi; k++) {
		uint64_t f = view_map(v, k, 0);

		if (f >= bn)
			return 1;
		t[n++] = bp[f];
	}
	return literal_safe(t, n);
}

int menu_enabled(struct view *v, int a)
{
	if (!menu_shown(v, a))
		return 0;
	/*
	 * Go to needs no selection and no draft - it is a jump to a number the
	 * reader types - so it is live whenever a file is open. Without a branch
	 * here it fell to the closing `return 0` and drew greyed for ever, which
	 * is the same silent nothing the missing menu_run branch used to give.
	 */
	if (a == M_GOTO)
		return 1;
	if (a == M_COPY_DISASM)
		/*
		 * The same condition dis_copy runs on, and it has to be: this
		 * asked for the panel's OWN selection while dis_copy will also
		 * copy the rows a hex selection lights, so the item greyed out
		 * over a highlight it was perfectly able to copy.
		 */
		return v->dis_open && v->dis_lines > 0 &&
		       (v->dis_have || dis_hex_sel(v));
	if (a == M_VIEW_HEX)
		return 1;       /* nothing to select first: it is a reading */
	if (a == M_DECODE)
		/* Bytes to put in the field is the whole requirement. */
		return v->sel_a != KGENOME_BROKEN && v->sel_b != KGENOME_BROKEN;
	if (a == M_DISASM) {
		struct object *ob = cur_obj(v);

		/*
		 * No selection needed. With one it opens on those bytes; with
		 * none it opens on the region, which is what the menu bar's own
		 * item does - and a reader who right-clicks the pane to ask
		 * "what is this code" should not have to select something first
		 * to be allowed to ask.
		 */
		if (!ob || !ob->buf.p || !v->rgn_len)
			return 0;
		return !ob->fmt || ob->ctx.arch == KGENOME_ARCH_X86 ||
		       ob->ctx.arch == KGENOME_ARCH_X86_64;
	}
	if (a == M_COPY_ASCII || a == M_COPY_HEX)
		return v->sel_a != KGENOME_BROKEN;
	if (a == M_COPY_OFF_HEX || a == M_COPY_OFF_DEC)
		return 1;
	if (a == M_DECL_HEX || a == M_DECL_STR)
		return decl_why(v, a == M_DECL_HEX) == NULL;
	if (a == M_EVT_COPY || a == M_EVT_DECL) {
		/* Both act on a selection, so neither is live without one -
		 * a greyed row says "select something first", which is the
		 * whole message. */
		char sel[8];

		return evt_sel_text(v, sel, sizeof sel) != 0;
	}
	if (a == M_DEC_COPY || a == M_DEC_DECL) {
		char sel[8];

		return enc_sel_text(v, sel, sizeof sel) != 0;
	}
	if (a == M_EVT_COPY_ALL) {
		/* Hidden rather than greyed for a binary payload: greying it
		 * would say "not yet", and the answer is not "not yet". */
		return v->evt_text_len != 0 &&
		       !kof_evt_content_looks_binary(&v->evt);
	}
	if (a == M_FIND_STR || a == M_FIND_HEX)
		return 1;       /* opens the find dialog, in either mode */
	/* Only when there is an answer: a byte no block covers has none, and
	 * an item that would say "none" is an item that need not be there. */
	if (a == M_MUTATION_WHICH)
		return mtn_at_byte(v) < v->ed.dr.n_blk;
	/* Not wired to anything yet. Shown because the menu is where they will
	 * be, and disabled because a menu item that does nothing teaches people
	 * not to trust the menu. */
	return 0;
}

/*
 * The context menu as kv_menu sees it.
 *
 * Built per call rather than kept: every field is a function pointer into this
 * file and the only state is `v`, so a cached one would be a struct that has to
 * be invalidated for no saving at all.
 */
static int cm_shown(void *ud, int i)   { return menu_shown((struct view *)ud, i); }
static int cm_enabled(void *ud, int i) { return menu_enabled((struct view *)ud, i); }
static const char *cm_label(void *ud, int i)
{
	/* The one item whose word depends on what the pane is doing: it always
	 * names the reading you are NOT getting, which is the one the click
	 * would give you. */
	if (i == M_VIEW_HEX)
		return text_pane((struct view *)ud) ? "View hex"
						    : "View script";
	return menu_item[i].label;
}

/*
 * A rule where the group changes - but only counting rows that are SHOWN.
 *
 * The previous item in the table may be hidden, in which case the group it
 * belongs to is not on the screen and a rule marking the change would be a
 * rule between two rows of the same group.
 */
static int cm_rule(void *ud, int i)
{
	struct view *v = ud;
	int k;

	for (k = i - 1; k >= 0; k--) {
		if (!menu_shown(v, k))
			continue;
		return menu_item[k].group != menu_item[i].group;
	}
	return 0;               /* the first shown row needs no rule above it */
}

static struct kv_menu ctx_menu(struct view *v)
{
	struct kv_menu m;

	memset(&m, 0, sizeof m);
	m.n = M_COUNT;
	m.ud = v;
	m.shown = cm_shown;
	m.enabled = cm_enabled;
	m.rule_above = cm_rule;
	m.label = cm_label;
	m.w = MENU_W;
	m.c_on  = BAR_ON;
	m.c_off = BAR_OFF;
	m.c_cur = BAR_CUR;
	return m;
}

/* Rows including the rules between groups, which take a line each. */
int menu_rows(struct view *v)
{
	struct kv_menu m = ctx_menu(v);

	return kv_menu_rows(&m);
}

/* The action on a drawn row, or -1 for a rule or past the end. */
int menu_at_row(struct view *v, int row)
{
	struct kv_menu m = ctx_menu(v);

	return kv_menu_at_row(&m, row);
}

void menu_open_at(struct view *v, int row, int col)
{
	v->menu_open = 1;
	v->menu_row = row;
	v->menu_col = col;
	if (v->menu_row + menu_rows(v) > g_rows)
		v->menu_row = g_rows - menu_rows(v);
	if (v->menu_row < 1)
		v->menu_row = 1;
	if (v->menu_col + MENU_W > g_cols)
		v->menu_col = g_cols - MENU_W;
	if (v->menu_col < 1)
		v->menu_col = 1;

	/*
	 * OPEN WITH NOTHING HIGHLIGHTED.
	 *
	 * It opened on the first choosable row, so that Enter always had
	 * something to do. What that actually does is point at an item the
	 * reader did not choose: the menu appears under the pointer with one
	 * row already lit, which reads as "this is what will happen" - and the
	 * row it lands on is whatever happens to be first, today "View hex".
	 *
	 * A menu opened by a right click is a list to look at. The highlight is
	 * the reader's answer, so it starts empty and the first arrow key or
	 * the pointer puts it somewhere. Enter with nothing chosen does
	 * nothing, which is what "I have not chosen" should do.
	 */
	v->menu_sel = -1;
}

void menu_step(struct view *v, int d)
{
	struct kv_menu m = ctx_menu(v);

	/*
	 * FROM NOTHING, EITHER END. The menu opens with no row lit, so the
	 * first key has to enter the list rather than step within it - down
	 * from the top, up from the bottom, which is what the key means.
	 */
	if (v->menu_sel < 0) {
		v->menu_sel = d > 0 ? kv_menu_first(&m)
				    : kv_menu_step(&m, kv_menu_rows(&m), -1);
		return;
	}
	v->menu_sel = kv_menu_step(&m, v->menu_sel, d);
}


void draw_menu(struct out *o, struct view *v)
{
	struct kv_menu m = ctx_menu(v);

	kv_menu_draw(o, &m, v->menu_row, v->menu_col, v->menu_sel, -1);
}

void menu_run(struct view *v, int a)
{
	/*
	 * A REFUSED DECLARATION SAYS WHY, and every other refusal stays quiet.
	 *
	 * The row is greyed either way - that is what tells the reader it is
	 * unavailable before they click. What was missing is the reason, and
	 * without it the two states a reader cares about, "I cannot do this
	 * here" and "this is broken", look identical. Only this action is
	 * treated so: the rest are greyed for reasons the reader can see on
	 * screen, and a message for each would be noise.
	 */
	if ((a == M_DECL_STR || a == M_DECL_HEX) && !menu_enabled(v, a)) {
		const char *why = decl_why(v, a == M_DECL_HEX);

		if (why) {
			v->act_ok = 0;
			snprintf(v->act_msg, sizeof v->act_msg, "%s", why);
		}
		v->menu_open = 0;
		return;
	}
	if (!menu_enabled(v, a))
		return;
	if (a == M_COPY_OFF_HEX || a == M_COPY_OFF_DEC) {
		copy_offset(v, a == M_COPY_OFF_HEX);
		v->menu_open = 0;
		return;
	}
	if (a == M_VIEW_HEX) {
		view_toggle_text(v);
		v->menu_open = 0;
		return;
	}
	if (a == M_DECL_STR || a == M_DECL_HEX) {
		decl_add(v, a == M_DECL_HEX);
		v->menu_open = 0;
		return;
	}
	if (a == M_EVT_COPY_ALL) {
		char scratch[512];
		size_t sn = 0;
		const char *all = evt_box_text(v, scratch, sizeof scratch, &sn);

		if (all && sn) {
			copy_osc52(all, sn);
			copy_said(v, sn);
		}
		v->menu_open = 0;
		return;
	}
	if (a == M_DEC_COPY || a == M_DEC_DECL) {
		char sel[512];
		size_t sn = enc_sel_text(v, sel, sizeof sel);

		if (sn) {
			if (a == M_DEC_COPY) {
				copy_osc52(sel, sn);
				copy_said(v, sn);
			} else {
				decl_add_text(v, sel, sn, 0);
			}
		}
		v->menu_open = 0;
		return;
	}
	if (a == M_EVT_COPY || a == M_EVT_DECL) {
		char sel[512];
		size_t sn = evt_sel_text(v, sel, sizeof sel);

		if (sn) {
			if (a == M_EVT_COPY) {
				copy_osc52(sel, sn);
				copy_said(v, sn);
			} else {
				decl_add_text(v, sel, sn, 1);
			}
		}
		v->menu_open = 0;
		return;
	}
	if (a == M_COPY_DISASM) {
		dis_copy(v);
		v->menu_open = 0;
		return;
	}
	if (a == M_DECODE) {
		uint64_t bn = 0;
		const uint8_t *bp = view_bytes(v, &bn);
		uint64_t a0 = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		uint64_t b0 = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
		uint64_t fa = view_map(v, a0, NULL);
		uint64_t fb = view_map(v, b0, NULL);

		v->menu_open = 0;
		/*
		 * Refused when the selection is not contiguous in the object:
		 * a region is a list of extents, and a selection spanning two
		 * of them is two ranges with a gap - handing that over as one
		 * string would put bytes in the field that are not next to
		 * each other in the file.
		 */
		if (!bp || fa == KGENOME_BROKEN || fb == KGENOME_BROKEN || fb < fa ||
		    fb - fa != b0 - a0 || fb >= bn) {
			say_note(&v->ed,
				 "That selection is not one run of bytes");
			return;
		}
		/*
		 * AND IT HAS TO BE TEXT, which is not a restriction so much as
		 * what the field is.
		 *
		 * The input holds a C string, so a NUL in the selection ends it
		 * - and a selection out of an ELF's data usually starts with
		 * one. Filling the field with that put an EMPTY box on the
		 * screen with no reason given, which is the worst of the three
		 * possible behaviours. Refusing and saying why is the honest
		 * one: what this decodes is encoded TEXT, and bytes that are
		 * not text were never going to be base64 or hex.
		 */
		{
			uint64_t i;

			for (i = fa; i <= fb; i++) {
				uint8_t c = bp[i];

				if (c == '\t' || c == '\n' || c == '\r' ||
				    (c >= 0x20u && c <= 0x7eu))
					continue;
				say_note(&v->ed, "The selection is not text - "
					 "this box takes text");
				return;
			}
		}
		/* The item says decode, so the box opens set to decode rather
		 * than to whatever the last use of it left behind. Encoding is
		 * the button beside it once the box is open. */
		v->enc_way = 0;
		enc_open_with(v, bp + fa, (uint32_t)(fb - fa + 1u));
		return;
	}
	if (a == M_DISASM) {
		v->dis_open = 0;                /* so the toggle opens */
		if (v->sel_a == KGENOME_BROKEN) {
			/* Nothing picked: the whole region, unpinned, exactly
			 * as the menu bar opens it. */
			dis_toggle(v, 0, KGENOME_BROKEN);
		} else {
			uint64_t a0 = v->sel_a < v->sel_b ? v->sel_a
							  : v->sel_b;
			uint64_t b0 = v->sel_a < v->sel_b ? v->sel_b
							  : v->sel_a;

			/*
			 * Pinned to the selection, so scrolling the hex no
			 * longer moves it: the reader asked about THESE bytes.
			 * Closing and reopening from the menu unpins it again.
			 */
			dis_toggle(v, a0, b0 - a0 + 1u);
		}
		v->menu_open = 0;
		return;
	}
	if (a == M_MUTATION_WHICH) {
		/*
		 * SAID, AND SHOWN. The sentence names the block so the reader
		 * can find its row, and the block is lit so the extent of it is
		 * on the screen rather than described.
		 */
		uint32_t bi = mtn_at_byte(v);

		if (bi < v->ed.dr.n_blk) {
			v->ed.dr.blk[bi].lit = 1;
			say_note(&v->ed, "Block %08x, %llu bytes from 0x%llx",
				 v->ed.dr.blk[bi].id,
				 (unsigned long long)v->ed.dr.blk[bi].len,
				 (unsigned long long)v->ed.dr.blk[bi].off);
		}
		v->menu_open = 0;
		return;
	}
	if (a == M_GOTO) {
		/*
		 * The item was in both menus and in the enum, and nothing ever
		 * handled it - so it drew, took the click, and did nothing. It
		 * opens the prompt now; see draw_goto.
		 */
		v->goto_open = 1;
		v->find_open = 0;      /* they share the box - see draw_goto */
		v->gotobuf[0] = 0;
		v->num_fresh = 1;
		v->edit = 520;
		v->menu_open = 0;
		v->ed.dr.warn[0] = 0;
		return;
	}
	if (a == M_FIND_STR || a == M_FIND_HEX) {
		v->find_hex = a == M_FIND_HEX;
		v->goto_open = 0;      /* they share the box - see draw_goto */
		v->find[0] = 0;
		v->find_at = KGENOME_BROKEN;
		v->find_open = 1;
		v->edit = 500;
		v->menu_open = 0;
		v->ed.dr.warn[0] = 0;
		return;
	}
	copy_selection(v, a == M_COPY_HEX);
	v->menu_open = 0;
}
