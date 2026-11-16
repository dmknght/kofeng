#define _GNU_SOURCE
#include "kv.h"

#include <textual/textual.h>
#include "../libkofeng/analyzers/parsers/scripts/script_route.h"


/*
 * Where the text starts, past the line-number gutter.
 *
 * Six digits and one space. It was eight and two, which is ten columns spent on
 * a number that is three digits in almost every script - a tenth of a narrow
 * terminal, taken from the text, to line up a case that does not occur. Six
 * still holds a million lines; past that the field grows and the text shifts,
 * which is a file nobody is reading by eye anyway.
 */
#define TXT_GUTTER 6

/* ---- the symbol view -------------------------------------------------------
 *
 * The rows of the KSYM block, one record to a line, in place of the hex pane.
 *
 * IT IS NOT A HEX DUMP AND DOES NOT PRETEND TO BE ONE. The records are built
 * from the section table rather than read out of a run of the file, so there is
 * no offset column that would mean anything: printing one would invite a reader
 * to go to it, and land them somewhere unrelated. What identifies a row here is
 * the record number, which is why that is the first field.
 */

/*
 * The flag byte as five characters, ONE PER BIT.
 *
 * Five, because there are five flags - and the column is headed "flags", which
 * is five wide, so the field now fills its own heading instead of sitting four
 * characters into a five character column.
 *
 * DEFINED and UNDEFINED get a slot each rather than sharing one. They used to:
 * slot zero was 'D', 'u' or '.', which is shorter and lies about the data - the
 * two are separate bits in the record, so a record carrying both, or a record
 * carrying neither because it was built by something that did not set them, was
 * displayed as one of the ordinary cases. Five slots cannot misreport a byte
 * whatever is in it.
 *
 * A dot rather than a blank for a bit that is clear: a blank column reads as a
 * field that was not printed.
 */
void sym_flag_str(uint8_t f, char *out)
{
	out[0] = (f & KOF_SYM_F_DEFINED)     ? 'D' : '.';
	out[1] = (f & KOF_SYM_F_UNDEFINED)   ? 'U' : '.';
	out[2] = (f & KOF_SYM_F_IN_WRITABLE) ? 'W' : '.';
	out[3] = (f & KOF_SYM_F_IN_EXEC)     ? 'X' : '.';
	out[4] = (f & KOF_SYM_F_HAS_SIZE)    ? 'S' : '.';
	out[5] = 0;
}

/*
 * "UND", "ABS", or the index.
 *
 * The two special cases are NOT the same value and must not be tested as one.
 * ELF's SHN_UNDEF is zero and the builder keeps it - an import genuinely has no
 * section - while the reserved indices above 0xff00 (SHN_ABS, SHN_COMMON) are
 * folded to 0xffff so a rule comparing the field has one number to compare
 * against. Reading zero as an ordinary index printed "0" for every import,
 * which is a real section number and the wrong answer.
 *
 * UND is decided by the FLAG rather than by the zero: the flag is what the
 * builder itself concluded, so the column and anything matching on the flag
 * cannot disagree.
 */
void sym_shn_str(const uint8_t *r, char *out, size_t n)
{
	uint32_t x = (uint32_t)r[KOF_SYM_R_SHNDX] |
		     ((uint32_t)r[KOF_SYM_R_SHNDX + 1] << 8);

	if (r[KOF_SYM_R_FLAGS] & KOF_SYM_F_UNDEFINED)
		snprintf(out, n, "%s", "UND");
	else if (x == 0xffffu)
		snprintf(out, n, "%s", "ABS");
	else
		snprintf(out, n, "%u", x);
}

/* ---- the text pane --------------------------------------------------------
 *
 * The bytes pane, drawn for something a person reads. Everything structural is
 * the hex pane's and is reached through the same calls - view_map for the file
 * offset of a region offset, in_sel/decl_kind for what a byte is
 * wearing, rgn_at for where the top of the pane is. What differs is two things
 * and no more: a row is a LINE rather than a fixed run of bytes, and the number
 * in the gutter counts lines rather than bytes.
 */

/*
 * The file offset of region position `at` - or, for a RENDERED buffer (kgenome_textual_pretty,
 * txt_pretty_view below), `at` itself: the rendered buffer is a display transform with no file offset
 * of its own (textual.h's own header on this call), and view_map's extents describe the OBJECT's raw
 * bytes, which this buffer's length no longer matches once indentation has added to it - asking it for
 * a position past the raw length would answer offset 0 instead of "no mapping", silently reading the
 * wrong byte. Every line-walking function below takes `rendered` for this one reason and no other.
 */
static uint64_t txt_fo(struct view *v, uint64_t at, int rendered)
{
	return rendered ? at : view_map(v, at, 0);
}

/* The byte the line containing `at` starts on. */
uint64_t txt_line_start(struct view *v, const uint8_t *base,
			       uint64_t base_n, uint64_t at, int rendered)
{
	while (at > 0) {
		uint64_t fo = txt_fo(v, at - 1u, rendered);

		if (fo < base_n && base[fo] == '\n')
			break;
		at--;
	}
	return at;
}

/* The byte after the line containing `at` ends, newline included. */
uint64_t txt_line_end(struct view *v, const uint8_t *base,
			     uint64_t base_n, uint64_t at, int rendered)
{
	while (at < base_n) {
		uint64_t fo = txt_fo(v, at, rendered);

		at++;
		if (fo < base_n && base[fo] == '\n')
			break;
	}
	return at;
}

/*
 * The 0 based line number of `at`, counted from the nearest thing already
 * known - see txt_anchor. The anchor moves to the answer, so scrolling costs
 * the distance scrolled and nothing else.
 */
/* The newlines in [from, to), in the region's own address space. */
static uint64_t txt_line_count(struct view *v, const uint8_t *base,
			       uint64_t base_n, uint64_t from, uint64_t to, int rendered)
{
	uint64_t i, n = 0;

	for (i = from; i < to; i++) {
		uint64_t fo = txt_fo(v, i, rendered);

		if (fo < base_n && base[fo] == '\n')
			n++;
	}
	return n;
}

uint64_t txt_line_of(struct view *v, const uint8_t *base,
			    uint64_t base_n, uint64_t at, int rendered)
{
	uint64_t n = 0;
	int bad = 0;

	if (v->txt_anchor > base_n)
		v->txt_anchor = v->txt_anchor_ln = 0;
	if (at >= v->txt_anchor) {
		n = v->txt_anchor_ln +
		    txt_line_count(v, base, base_n, v->txt_anchor, at, rendered);
	} else {
		uint64_t back = txt_line_count(v, base, base_n, at,
					       v->txt_anchor, rendered);

		/*
		 * AN ANCHOR THAT CANNOT PAY FOR THE LINES BEHIND IT IS NOT THIS
		 * VIEW'S, and subtracting anyway is where the huge numbers came
		 * from.
		 *
		 * This counted down from the anchor in a uint64_t, so an anchor
		 * holding a line number from a DIFFERENT region - the reader
		 * had been looking at BODY and picked MARKUP, which changes
		 * view_map under a cache nothing reset - underflowed to
		 * 18446744073709551000-odd. Scrolling down then incremented it
		 * back through zero, so the gutter showed twenty-digit numbers
		 * and "started from 0" a dozen lines later. Seen on the MARKUP
		 * of Ani-Shell.php, where the line was really 3591.
		 */
		if (back > v->txt_anchor_ln)
			bad = 1;
		else
			n = v->txt_anchor_ln - back;
	}
	/*
	 * AND THE ANSWER IS CHECKED AGAINST A BOUND THAT CANNOT LIE. Every line
	 * costs at least its newline, so the count can never be larger than the
	 * offset it was counted to. That catches a stale anchor in the FORWARD
	 * direction as well, which nothing else here can see - and makes the
	 * cache unable to produce a wrong answer rather than merely unlikely
	 * to.
	 */
	if (bad || n > at) {
		v->txt_anchor = v->txt_anchor_ln = 0;
		n = txt_line_count(v, base, base_n, 0, at, rendered);
	}
	v->txt_anchor = at;
	v->txt_anchor_ln = n;
	return n;
}

/*
 * THE FURTHEST THE PANE MAY BE SCROLLED - the top line that still leaves a full
 * screen of text under it.
 *
 * Walked back from the last line rather than counted forward from the first,
 * because the answer is a fixed number of lines from the END and the number of
 * lines before it is not needed at all. That is a screen's worth of stepping,
 * whatever the object's size.
 *
 * Without it the step below stopped only when the NEXT line would pass the end,
 * so the last line of a script could be scrolled up to the top row and the rest
 * of the pane was blank - the reader could keep pressing down long after there
 * was anything left to see.
 */
uint64_t txt_max_top(struct view *v, const uint8_t *base,
			    uint64_t base_n, int rows, int rendered)
{
	uint64_t a;
	int i;

	if (!base_n)
		return 0;
	a = txt_line_start(v, base, base_n, base_n - 1u, rendered);
	for (i = 1; i < rows && a > 0; i++)
		a = txt_line_start(v, base, base_n, a - 1u, rendered);
	return a;
}
static int txt_x0(void) { return TREE_W + 3 + TXT_GUTTER + 1; }

/*
 * DOES THE SCRIPT PANE SHOW A HORIZONTAL BAR, and therefore have one row fewer
 * for text?
 *
 * One function because three places need the same answer and they must not
 * disagree: the drawer, the click mapping and the scroll limit. A pane that
 * drew forty rows while clicks were mapped against forty-one puts the caret one
 * line off, which is the kind of fault that looks like the mouse is broken.
 *
 * Measured against the width WITH a vertical bar, so the answer does not depend
 * on whether that one is shown - otherwise each would need the other first.
 */
static int txt_hbar_on(const struct view *v)
{
	int wide = g_cols - txt_x0() - 1;

	return wide > 0 && v->txt_maxlen > (uint32_t)wide;
}

int txt_bot(const struct view *v)
{
	return hex_last() - (txt_hbar_on(v) ? 1 : 0);
}

/*
 * ONE BYTE, ONE COLUMN, AND NO INTERPRETATION - the same rule the hex pane's
 * ascii gutter states for itself.
 *
 * A tab is drawn as a space rather than expanded, because expanding it makes a
 * column stop being a byte and every click, every selection and every offset
 * this pane reports would need a second mapping to undo. What the reader loses
 * is the alignment of indented code; what they keep is that the column the
 * status line names is the byte a marker would be taken from.
 */
static char txt_glyph(uint8_t c)
{
	if (c == '\t')
		return ' ';
	return (c >= 32 && c < 127) ? (char)c : '.';
}

/*
 * THE SCRIPT NORM CHILD, LAID OUT FOR A READER (kgenome_textual_pretty, textual.h) - owner, 2026-11-11:
 * "viết và hiển thị trong kofviewer thay thế nội dung phần norm" (write it and show it in kofviewer,
 * replacing the norm section's content). Built once, lazily, and only for the object this IS: the form
 * child of a KOF_FMT_SCRIPT object (entry_kind KOF_ENT_NORMALIZED), in a language the call lays out
 * (kof_script_textual_lang answers KGENOME_TEXTUAL_LANG_NONE for one it does not). Answers 0 - every
 * caller then keeps ob->buf.p/buf.n exactly as before - for anything else, including a call that wrote
 * nothing: a cosmetic failure is never evidence lost, the raw form is always there to fall back to (see
 * kgenome_textual_pretty's own header).
 *
 * THIS IS A DISPLAY-ONLY TRANSFORM, never fed back into the engine. It is also not addressed by FILE
 * OFFSET the way ob->buf is: a declared string's hits and the engine's own markers were found by
 * searching the RAW form, in ITS coordinates, so every caller that swaps to this buffer also stops
 * asking those (the same reason a symbol row, kv_hex.c's own `sym`, turns them off) and passes
 * `rendered` to the txt_line_* calls, which is the other half of the same fact: view_map maps a raw
 * file offset, and this buffer's length no longer matches the object's once indentation has added to
 * it (textual_pretty.c's cap is not KGENOME_TEXTUAL_FORM_CAP(n): it can be, and almost always is,
 * larger than the object it is laid out from).
 */
int txt_pretty_view(struct object *ob, const uint8_t **p, uint64_t *n)
{
	uint32_t lang;
	uint64_t cap;
	uint8_t *buf;
	struct kgenome_textual_pretty_req rq;
	struct kgenome_textual_pretty_res res;

	if (ob->pretty_done) {
		if (!ob->pretty_p)
			return 0;
		*p = ob->pretty_p;
		*n = ob->pretty_n;
		return 1;
	}
	ob->pretty_done = 1;
	if (ob->ctx.format != KOF_FMT_SCRIPT || ob->entry_kind != KOF_ENT_NORMALIZED ||
	    !ob->buf.p || !ob->buf.n)
		return 0;
	lang = kof_script_textual_lang(ob->ctx.subtype);
	if (lang == KGENOME_TEXTUAL_LANG_NONE)
		return 0;
	/* However much indentation could plausibly add, plus room to spare - truncation here only
	 * cuts the cosmetic job short (res.truncated), never evidence: see textual_pretty.c's own
	 * KGENOME_TEXTUAL_PRETTY_INDENT_MAX/WIDTH for the per-break worst case this is sized against. */
	cap = ob->buf.n * 4u + 4096u;
	if (cap > 64u * 1024u * 1024u)
		cap = 64u * 1024u * 1024u;
	buf = malloc((size_t)cap);
	if (!buf)
		return 0;
	memset(&rq, 0, sizeof rq);
	rq.in = ob->buf.p;
	rq.n = ob->buf.n > 0xffffffffu ? 0xffffffffu : (uint32_t)ob->buf.n;
	rq.lang = lang;
	rq.out = buf;
	rq.cap = cap > 0xffffffffu ? 0xffffffffu : (uint32_t)cap;
	/*
	 * CODE FROM ITS FIRST BYTE, THE SAME TEST objctx_script.c's own form call makes (kof_script_from_code, the engine's: the
	 * object's entry, ISL-1 2026-11-10): an island has no opening tag of its own - php's lexer reads code only inside a tag's
	 * island, so without this its whole text reads as one block of markup and this call is a no-op, byte for byte (measured:
	 * n_out == buf.n exactly, the same symptom Merge 173 found and fixed for kgenome_textual_form).
	 */
	if (kof_script_from_code(&ob->ctx))
		rq.flags = KGENOME_TEXTUAL_FRAGMENT;
	kgenome_textual_pretty(&rq, &res);
	if (!res.n_out) {
		free(buf);
		return 0;
	}
	ob->pretty_p = buf;
	ob->pretty_n = res.n_out;
	*p = buf;
	*n = res.n_out;
	return 1;
}

void draw_text(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	int top = hex_top(), bot = hex_last();
	int gut = TREE_W + 3, x0 = txt_x0();
	int wide = g_cols - x0;
	uint64_t base_n;
	const uint8_t *base;
	int rendered = txt_pretty_view(ob, &base, &base_n);
	uint64_t at, ln, maxtop;
	int row, vbar, hbar;

	if (!rendered) {
		base_n = ob->buf.n;
		base = ob->buf.p;
	}
	if (!base)
		base_n = 0;

	/*
	 * THE TWO BARS, AND EACH ONLY WHEN THERE IS SOMETHING OFF SCREEN.
	 *
	 * A pane of text says nothing about how much of the file it is showing
	 * or where in it the reader is; the hex pane has had a bar for that all
	 * along and this one had neither. Sideways matters at least as much
	 * here - a minified shell is one line of forty kilobytes, and without a
	 * bar there is nothing to say that the line continues, let alone how
	 * far.
	 *
	 * Each takes its space from the text only when it is drawn, so a file
	 * that fits keeps every column and every row.
	 *
	 * DOWN THE PAGE THE SCALE IS BYTES, not lines. Counting the lines of a
	 * region means walking it, which is a pass over the object on every
	 * frame; the byte offset is already known and moves monotonically with
	 * the line, so the thumb sits in the right place and costs nothing.
	 * txt_max_top is the furthest it can be scrolled, so the bytes still
	 * below the top of the pane are what is left to see.
	 */
	/* txt_maxlen is last frame's widest line - the only width there is
	 * before the rows are walked, and it changes only when the view does. */
	hbar = txt_hbar_on(v);
	if (hbar)
		bot--;
	maxtop = txt_max_top(v, base, base_n, bot - top + 1, rendered);
	vbar = base_n > 0 && maxtop > 0;
	if (vbar)
		wide--;
	if (wide < 1)
		wide = 1;

	at = txt_line_start(v, base, base_n, v->rgn_at, rendered);
	ln = txt_line_of(v, base, base_n, at, rendered);
	v->txt_maxlen = 0;

	for (row = top; row <= bot; row++) {
		uint64_t end, k;
		int c;

		out_at(o, row, gut);
		if (at >= base_n) {
			out_str(o, "\033[K");
			continue;
		}
		end = txt_line_end(v, base, base_n, at, rendered);
		{
			const char *a = A_LOC;

			out_fmt(o, "%s%*llu" A_OFF " ", a, TXT_GUTTER,
				(unsigned long long)(ln + 1u));
		}
		/* How far right there is anything to see, so the sideways
		 * scroll can stop there - see txt_maxlen. The newline is not
		 * part of the line's width. */
		{
			uint64_t len = end - at;

			while (len && at + len - 1u < base_n) {
				uint64_t fo = txt_fo(v, at + len - 1u, rendered);
				uint8_t bv = fo < base_n ? base[fo] : 0;

				if (bv != '\n' && bv != '\r')
					break;
				len--;
			}
			if (len > v->txt_maxlen)
				v->txt_maxlen = (uint32_t)len;
		}
		/*
		 * SCROLLED SIDEWAYS, and the skip is over BYTES because a
		 * column is a byte here - see txt_glyph. A line shorter than
		 * the origin draws nothing, which is what a reader scrolled
		 * past the end of it should see.
		 */
		k = at + (uint64_t)v->txt_col;
		for (c = 0; c < wide && k < end; c++, k++) {
			uint64_t fo = txt_fo(v, k, rendered);
			uint8_t bv = fo < base_n ? base[fo] : 0;
			const char *ec, *pl;

			if (bv == '\n' || bv == '\r')
				break;
			/* A rendered buffer has no file offset of its own - a marker found by
			 * searching the RAW form would light an unrelated byte at the same
			 * number here, the same reason a symbol row turns these off (kv_hex.c's
			 * own `sym`). Selection stays: it is set by THIS pane's own click
			 * (text_under), in the SAME buffer's coordinates, whichever one this is. */
			ec = rendered ? NULL : evt_byte_colour(v, k);
			pl = rendered ? NULL : mtn_lit_at(v, k);
			/* The same ladder the hex pane paints a byte with, in
			 * the same order: what the reader picked beats what the
			 * draft declared. */
			/* A lit block sits below the selection and above
			 * everything else: it is what the reader asked to see
			 * on this frame, and the engine's markers are what was
			 * there before they asked. */
			out_str(o, in_sel(v, k) ? A_SELB :
				pl ? pl :
				ec ? ec
				  : (!rendered && decl_kind(v, fo)) ? A_HIT3
				  : byte_colour(bv));
			out_fmt(o, "%c", txt_glyph(bv));
			out_str(o, A_OFF);
		}
		out_str(o, "\033[K");
		at = end;
		ln++;
	}
	if (vbar)
		kv_scrollbar(o, g_cols, top, bot, v->rgn_at, base_n,
			  base_n - maxtop);
	if (hbar) {
		kv_scrollbar_h(o, bot + 1, x0, g_cols - (vbar ? 1 : 0),
			    v->txt_col, v->txt_maxlen, (uint64_t)wide);
		/*
		 * AND THE CORNER WHERE THEY MEET, which neither bar owns.
		 *
		 * The vertical one stops at the last text row and the
		 * horizontal one stops one column short of it, so the cell
		 * between them was painted by nobody - a notch out of the
		 * bottom right that reads as the bar having run out. A column
		 * no drawer owns is also a column that keeps whatever was last
		 * in it, which this file has been bitten by before.
		 */
		if (vbar) {
			out_at(o, bot + 1, g_cols);
			out_str(o, A_DIM G_V A_OFF);
		}
	}
}

/* Which byte a click landed on, and where it is in the line. Mirrors
 * byte_under, which answers the same question for the hex layout. */
/* KNOWN DEFECT KXV-SCR-1 (2026-11-10, R) [sev M]: owner-reported, not reproduced live this
 * session - a script-view pane stops accepting clicks after horizontal scroll. Trigger: scroll a
 * long-line script object right, then click text. Effect: `at += v->txt_col + (col - x0)` below
 * looks correct on inspection; v->txt_maxlen staleness after hscroll, or the click never reaching
 * here for a script child, are not ruled out. Reproducer: none yet (owner report only). Fix: get
 * a live (pyte) repro before changing this function. */
int text_under(struct view *v, int row, int col, uint64_t *out,
		      uint64_t *out_line, uint32_t *out_col)
{
	struct object *ob = cur_obj(v);
	uint64_t base_n;
	const uint8_t *base;
	int rendered = ob && txt_pretty_view(ob, &base, &base_n);
	uint64_t at, end, ln;
	int r, x0 = txt_x0();

	if (!rendered) {
		base_n = ob ? ob->buf.n : 0;
		base = ob ? ob->buf.p : NULL;
	}
	if (!base)
		base_n = 0;
	/* Not the horizontal bar's row - see txt_bot. */
	if (row < hex_top() || row > txt_bot(v) || col < x0)
		return 0;

	at = txt_line_start(v, base, base_n, v->rgn_at, rendered);
	ln = txt_line_of(v, base, base_n, at, rendered);
	for (r = hex_top(); r < row; r++) {
		if (at >= base_n)
			return 0;
		at = txt_line_end(v, base, base_n, at, rendered);
		ln++;
	}
	if (at >= base_n)
		return 0;
	end = txt_line_end(v, base, base_n, at, rendered);
	at += (uint64_t)v->txt_col + (uint64_t)(col - x0);
	if (at >= end || at >= base_n)
		return 0;
	if (out)
		*out = at;
	if (out_line)
		*out_line = ln + 1u;
	if (out_col)
		*out_col = (uint32_t)(v->txt_col + (uint32_t)(col - x0) + 1u);
	return 1;
}

void draft_seed_target(struct view *v)
{
	struct object *fo = cur_obj(v);
	uint8_t fmt;

	if (v->ed.dr.fmt_mask)
		return;
	/*
	 * A RECORD ANSWERS FOR ITSELF, AND IT HAS TO BE ASKED FIRST.
	 *
	 * An event node has no parser - log_window builds it out of the
	 * mapping and nothing sniffs it, because a record has no magic - so
	 * the line below seeded KOF_FMT_UNKNOWN and the Format row read "Raw".
	 * That is not a blank label. Raw is a real target: the rule it writes
	 * is offered every unclaimed byte the scanner meets, and is never
	 * offered the event it was written from.
	 *
	 * SEEDED FIRST WINS, which is why the guard has to be here and not
	 * only where a marker is declared: a log opens on its root row, this
	 * runs against that row, and one Raw seed is all it takes - every
	 * later call sees a mask and leaves it alone.
	 *
	 * NOT THE IMAGE THE RECORD CARRIES. `pe_of` is what says which of the
	 * two rows is in hand - the same test the panel and the scan use - and
	 * a PE pulled out of a submission is a PE, whatever it arrived in.
	 */
	if (v->log && !v->pe_of[v->node[v->sel_node].obj]) {
		uint8_t t = evt_decl_target(v, NULL);

		if (t != EVT_TARGET_NONE)
			v->ed.dr.fmt_mask = 1u << t;
		/*
		 * AND THE PLATFORM, WHICH THE RECORD ALREADY SAYS.
		 *
		 * A command line is not one language - see KOF_PROC_OS_LIST -
		 * so a rule taken off a bash start has no business being
		 * offered a cmd.exe start, and this axis is how the host drops
		 * it before the call rather than inside it.
		 *
		 * MAPPED, NOT COPIED. kof_evt.os is a MASK - see enum
		 * kof_evt_os - and a subtype is an ORDINAL into one. They
		 * happen to agree on the first two values and would stop
		 * agreeing the day a third platform is added, which is the
		 * kind of coincidence that fails silently.
		 */
		if (t == KOF_EVT_PROC && !v->ed.dr.opt_on[OPT_SUBTYPE]) {
			uint32_t sub = KOF_PROC_OS_UNKNOWN;

			if (v->evt.os & KOF_OS_WINDOWS)
				sub = KOF_PROC_OS_WINDOWS;
			else if (v->evt.os & KOF_OS_LINUX)
				sub = KOF_PROC_OS_LINUX;
			if (sub != KOF_PROC_OS_UNKNOWN) {
				v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
				v->ed.dr.opt_val[OPT_SUBTYPE] = sub;
			}
		}
		/*
		 * AND NOTHING WHEN THE RECORD HAS NO TARGET, which includes
		 * the log's own row before any record is picked. A log is not
		 * a scan target - this file already refuses to run the engine
		 * over one - so it does not get to name what a rule is about
		 * either.
		 */
		return;
	}
	fmt = (uint8_t)((fo && fo->fmt && fo->ctx.format < KOF_FMT_COUNT)
			? fo->ctx.format : KOF_FMT_UNKNOWN);
	v->ed.dr.fmt_mask = 1u << fmt;
	if (fo && fo->ctx.subtype && kv_cap(fmt, KV_CAP_TEXT) &&
	    !v->ed.dr.opt_on[OPT_SUBTYPE]) {
		v->ed.dr.opt_on[OPT_SUBTYPE] = 1;
		v->ed.dr.opt_val[OPT_SUBTYPE] = fo->ctx.subtype;
		/* The engine's reading, not the reader's - see
		 * kof_draft.opt_auto. */
		v->ed.dr.opt_auto[OPT_SUBTYPE] = 1;
	}
}

/*
 * SIDEWAYS, AND IT STOPS WHERE THE TEXT DOES.
 *
 * One function because two things ask for it - the arrow keys and the modified
 * wheel - and a clamp written twice is a clamp that ends up different in the
 * two. Unbounded, this scrolls into blank space: past the longest line on
 * screen every row is empty, and a control that empties the pane reads as one
 * that broke rather than as the end of the line.
 *
 * txt_maxlen is what the LAST FRAME actually drew, so the limit follows the
 * text as the reader moves through it rather than being a property of the whole
 * object - which would mean measuring every line of a ten megabyte script to
 * answer a keypress.
 */
void txt_hscroll(struct view *v, int by)
{
	int wide = g_cols - txt_x0();
	uint32_t max;

	if (wide < 1)
		wide = 1;
	max = v->txt_maxlen > (uint32_t)wide
	      ? v->txt_maxlen - (uint32_t)wide : 0u;
	if (by < 0) {
		uint32_t n = (uint32_t)(-by);

		v->txt_col = v->txt_col >= n ? v->txt_col - n : 0u;
	} else {
		v->txt_col += (uint32_t)by;
	}
	if (v->txt_col > max)
		v->txt_col = max;
}

/* The furthest the text pane scrolls, for whatever object is in hand. */
uint64_t txt_home_end(struct view *v)
{
	struct object *ob = cur_obj(v);
	uint64_t n;
	const uint8_t *b;
	int rendered = ob && txt_pretty_view(ob, &b, &n);

	if (!rendered) {
		n = ob ? ob->buf.n : 0;
		b = ob ? ob->buf.p : NULL;
	}
	if (!b)
		n = 0;
	return txt_max_top(v, b, n, txt_bot(v) - hex_top() + 1, rendered);
}

/*
 * CAN THIS OBJECT BE READ BOTH WAYS - which is a property of the FORMAT and
 * not of what the pane is doing right now.
 *
 * Asked by the menu item, by the chord and by nothing else, so the two ways in
 * cannot disagree about when the choice exists. Not text_pane: that answers
 * "which reading am I getting", and if the item were gated on it there would be
 * no way back once it had been used.
 */
int view_can_text(struct view *v)
{
	const struct object *ob = cur_obj(v);

	return ob && ob->fmt && !sym_view(v) && !evt_live(v) &&
	       kv_cap(ob->ctx.format, KV_CAP_TEXT);
}

/*
 * Swap the reading. rgn_at is left alone on purpose: it is a BYTE OFFSET in
 * both layouts - that is the whole reason it is one field - so where the pane
 * is looking survives the change, and only the sideways origin, which means
 * nothing to a hex dump, goes back to zero.
 */
void view_toggle_text(struct view *v)
{
	if (!view_can_text(v))
		return;
	v->hex_forced = !v->hex_forced;
	v->txt_col = 0;
}

/* Non-zero when the pane in hand is showing text rather than a hex dump. */
int text_pane(struct view *v)
{
	struct object *ob = cur_obj(v);

	if (!ob || sym_view(v) || evt_live(v) || v->hex_forced)
		return 0;
	return ob->fmt && kv_cap(ob->ctx.format, KV_CAP_TEXT);
}
