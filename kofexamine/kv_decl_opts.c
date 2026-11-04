#define _GNU_SOURCE
#include "kv_decl_private.h"

/* The draft panel's format, option and range rows and the hit callbacks of those rows. */

/* Defined below; a row registers its own callback before the callback is written. */
static void hit_row_opt(struct view *v, uint32_t i);
static void hit_row_fmts(struct view *v, uint32_t arg);
static void hit_row_ranges(struct view *v, uint32_t arg);
static void hit_optbtn(struct view *v, uint32_t arg);
static uint8_t draft_sub_fmt(struct view *v);
static void opt_text(struct view *v, uint32_t i, char *val, size_t cap);


/*
 * draw_decl_fmts - what object formats the rule applies to.
 *
 * Its own row above the options, because it is not optional: a module must say
 * what it applies to or ksigbuilder refuses it, and a required declaration
 * drawn among the optional ones reads as one more thing you may skip.
 *
 * Shaped like the scan ranges below it on purpose - a list of names, each one a
 * control for itself, and a button at the END of the list rather than flushed
 * right. The two rows answer the same kind of question and a reader who learns
 * one has learned the other.
 */
int draw_decl_fmts(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		uint8_t f;
		int c;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Format " A_OFF);
		v->n_fmt_hs = 0;
		for (f = 0; f < KOF_FMT_COUNT; f++) {
			int c0;

			if (!(v->ed.dr.fmt_mask & (1u << f)))
				continue;
			out_str(o, " ");
			c0 = o->col_base + (int)o->col_hint;
			out_fmt(o, A_LOC "%s" A_OFF, kof_format_name(f));
			if (v->n_fmt_hs < KOF_FMT_COUNT) {
				v->fmt_hs[v->n_fmt_hs][0] = c0;
				v->fmt_hs[v->n_fmt_hs][1] =
					o->col_base + (int)o->col_hint - 1;
				v->n_fmt_hs++;
			}
		}
		/* WARN and not DIM: a draft with no format cannot be written,
		 * and the row that says so should not look like a row with
		 * nothing interesting on it. */
		if (!v->n_fmt_hs)
			out_str(o, A_WARN " None" A_OFF);

		out_str(o, "  ");
		c = o->col_base + (int)o->col_hint;
		/* A_ID, the same as [+ Options], [+ Matcher], [+ String] and
		 * [+ Condition]. It used to wear the menu bar's grey, which
		 * made two of the five add-buttons look like a different kind
		 * of control from the other three. */
		out_fmt(o, A_ID "[+ Formats]" A_OFF);
		v->fma_c0 = c;
		v->fma_c1 = o->col_base + (int)o->col_hint - 1;

		hit_add(v, PR(r), 0, g_cols - 1, hit_row_fmts, 0);
	}
	r++;                            /* the target format row, always */
	return r;
}

/*
 * draw_decl_opts - the optional KOF_TARGET_ declarations.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
/*
 * The button that adds an optional declaration, on a row of its own under the
 * formats.
 *
 * NOT on the Format row and not on the name row above it. It belongs to the
 * list it extends - the optional declarations drawn below - and the list has no
 * row at all until one exists, so the button has to carry the row itself.
 */
static void hit_row_opt(struct view *v, uint32_t i)
{
	if (g_mx >= g_cols - 4) {
		v->ed.dr.opt_on[i] = 0;
	} else if (g_mx >= v->opt_c0[i] && g_mx <= v->opt_c1[i]) {
		if (i == OPT_ARCH)
			ch_open(v, CH_ARCH, 0, g_my, g_mx);
		else if (i == OPT_SUBTYPE)
			ch_open(v, CH_SUBTYPE, 0, g_my, g_mx);
		else {
			/* A size is typed, so the field starts from what it
			 * says rather than empty. */
			snprintf(v->num, sizeof v->num, "%llu",
				 (unsigned long long)v->ed.dr.opt_val[i]);
			/* Opened by a click, so it starts selected: the first
			 * digit replaces rather than extends, which is what
			 * clicking a number and typing one means everywhere
			 * else. */
			v->num_fresh = 1;
			v->edit = 200 + (int)i;
		}
	}
}

/*
 * ONE SPAN PER ROW, and the row's own column tests inside it.
 *
 * The defect was never the column arithmetic - that was written beside the
 * paint and proved. It was the ROW COUNTER: click_panel_rows re-derived which
 * row is which by counting in the order the draw emits them, so a row added to
 * one and not the other shifted every click below it. Registering the row where
 * it is painted removes the counting; the tests below are the walk's, verbatim.
 */
static void hit_row_fmts(struct view *v, uint32_t arg)
{
	uint32_t h;

	(void)arg;
	for (h = 0; h < v->n_fmt_hs; h++)
		if (g_mx >= v->fmt_hs[h][0] && g_mx <= v->fmt_hs[h][1]) {
			ch_open(v, CH_FMT, h, g_my, g_mx);
			return;
		}
	if (g_mx >= v->fma_c0 && g_mx <= v->fma_c1)
		ch_open(v, CH_FMT_CAT, 0, g_my, g_mx);
}

static void hit_row_ranges(struct view *v, uint32_t arg)
{
	uint32_t h;

	(void)arg;
	/* A NAME IS THE SUBJECT. Which range was pressed is passed as the
	 * menu's argument, so every item it offers is about that one. */
	for (h = 0; h < v->n_rng_hs; h++)
		if (g_mx >= v->rng_hs[h][0] && g_mx <= v->rng_hs[h][1]) {
			ch_open(v, CH_RANGE2, h, g_my, g_mx);
			return;
		}
	if (g_mx >= v->rga_c0 && g_mx <= v->rga_c1)
		ch_open(v, CH_RANGE_ADD, 0, g_my, g_mx);
}

/* [+ Options] - the only control on its row. */
static void hit_optbtn(struct view *v, uint32_t arg)
{
	(void)arg;
	ch_open(v, CH_OPT, 0, g_my, g_mx);
}

int draw_decl_optbtn(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		int c;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Option " A_OFF);
		c = o->col_base + (int)o->col_hint;
		out_fmt(o, " " A_ID "[+ Options]" A_OFF);
		/*
		 * ONE SPAN, ON THIS ROW, AND NOWHERE ELSE.
		 *
		 * o_c0/o_c1 used to be written here as well, because the
		 * heading row's click chain read them - and those columns land
		 * on "[Virus]" up there, so the type box opened this list
		 * instead of its own. The field is gone with that chain.
		 */
		hit_add(v, PR(r), c, o->col_base + (int)o->col_hint - 1,
			hit_optbtn, 0);
	}
	r++;                            /* the option button row, always */
	return r;
}

/*
 * THE FORMAT A SUBTYPE IS READ AGAINST - the one the DRAFT declares, not the
 * one the object under the cursor happens to be.
 *
 * The panel and the preview have to agree about which format a subtype belongs
 * to, or the panel shows one thing and the preview says another.
 *
 * It shows up first on an event record, which has no format at all - the node
 * is built straight out of the mapping and never parsed - so the row printed
 * "?" beside a platform it had already written into the draft correctly.
 */
static uint8_t draft_sub_fmt(struct view *v)
{
	uint32_t fi;

	for (fi = 0; fi < KOF_FMT_COUNT; fi++)
		if (v->ed.dr.fmt_mask & (1u << fi))
			return (uint8_t)fi;
	return cur_obj(v) ? cur_obj(v)->ctx.format : (uint8_t)KOF_FMT_UNKNOWN;
}

/*
 * WHAT AN OPTION'S VALUE IS CALLED, written once: the option rows draw it and
 * the output pane lists it, and two spellings of one value would drift.
 */
static void opt_text(struct view *v, uint32_t i, char *val, size_t cap)
{
	if (i == OPT_ARCH)
		snprintf(val, cap, "%s",
			 arch_word[v->ed.dr.opt_val[i] < ARCH_N
				   ? v->ed.dr.opt_val[i] : 0].word);
	else if (i == OPT_SUBTYPE) {
		const char *w = kof_inspect_subtype_name(
			draft_sub_fmt(v), (uint8_t)v->ed.dr.opt_val[i]);

		snprintf(val, cap, "%s", w ? w : "?");
	} else
		snprintf(val, cap, "%llu",
			 (unsigned long long)v->ed.dr.opt_val[i]);
}

int draw_decl_opts(struct out *o, struct view *v, int r)
{
	uint32_t i;

	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		char val[40];
		int y;

		if (!v->ed.dr.opt_on[i])
			continue;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		r++;
		opt_text(v, i, val, sizeof val);
		row_start(o, y, 1);
		out_fmt(o, "   %s%-20s" A_OFF " ", A_DIM, opt_word[i]);
		v->opt_c0[i] = 1 + (int)o->col_hint;
		if (v->edit == 200 + (int)i) {
			out_str(o, A_SEL);
			field_draw(o, v->num, v->caret, &v->num_off, 18, 1, "");
			out_str(o, A_OFF);
		} else {
			out_fmt(o, "%s%s" A_OFF, A_ID, val);
		}
		v->opt_c1[i] = (int)o->col_hint;
		out_at(o, y, g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
		hit_add(v, y, 0, g_cols - 1, hit_row_opt, i);
	}

	/*
	 * What the finished source will declare, read only.
	 *
	 * A range has no existence apart from a matcher naming one, so there is
	 * nothing here to add, rename or delete - and nothing that can be left
	 * pointing at a marker that has gone. It is a summary, and its whole job
	 * is answering "which ranges is this signature going to search", which
	 * is the question that made a managed list look necessary.
	 */
	return r;
}

/*
 * draw_decl_ranges - the scan ranges the draft declares.
 *
 * One section of the draft panel. They were one nine-hundred line function, so
 * the column arithmetic of one row and the hit test of another sat in the same
 * scope and could reach each other's locals; `r` is the panel's running row
 * number and it is now passed in and handed back rather than shared.
 */
int draw_decl_ranges(struct out *o, struct view *v, int r)
{
	if (PR_VIS(r)) {
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(&v->ed, rm, ru, 2u * MAX_GROUP), k;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Region " A_OFF);
		/*
		 * EACH NAME IS A CONTROL, and its own subject.
		 *
		 * The row used to end in one [Update scan range] button that
		 * acted on "a range" and then asked which one - a question the
		 * reader had already answered by looking at the row. Clicking
		 * the name opens the menu for THAT range, so extend, drop and
		 * remove all read as things done to the thing pressed.
		 *
		 * An unused range - declared, no matcher searching it - is
		 * still named and still clickable, because removing it is the
		 * one thing it needs and this is where that lives.
		 */
		v->n_rng_hs = 0;
		for (k = 0; k < nr; k++) {
			char t[40];
			int c0;

			rng_name_of(cur_obj(v)->fmt, rm[k], t, sizeof t);
			out_str(o, " ");
			c0 = o->col_base + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, ru[k] ? A_WARN : A_LOC, t);
			if (ru[k])
				out_fmt(o, A_DIM " (unused)" A_OFF);
			if (v->n_rng_hs < 2u * MAX_GROUP) {
				v->rng_hs[v->n_rng_hs][0] = c0;
				v->rng_hs[v->n_rng_hs][1] =
					o->col_base + (int)o->col_hint - 1;
				v->n_rng_hs++;
			}
		}
		if (!nr)
			out_str(o, A_DIM " None" A_OFF);
		/*
		 * And a way to declare one more, at the END of the names rather
		 * than flushed to the right edge: it belongs to the list it
		 * extends, and a control parked in the corner reads as being
		 * about the panel instead.
		 */
		{
			int c0;

			out_str(o, "  ");
			c0 = o->col_base + (int)o->col_hint;
			/* A_ID, like every other add-button - see [+ Formats]. */
			out_fmt(o, A_ID "[+ Scan region]" A_OFF);
			v->rga_c0 = c0;
			v->rga_c1 = o->col_base + (int)o->col_hint - 1;
		}
		hit_add(v, PR(r), 0, g_cols - 1, hit_row_ranges, 0);
	}
	r++;                            /* the scan ranges row, always */
	return r;
}
