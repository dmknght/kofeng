/* SPDX-License-Identifier: MIT */
/*
 * kofview.c - the terminal, and what is drawn on it. See kofview.h for the
 * boundary this file is on the far side of.
 */

/* _GNU_SOURCE, not _POSIX_C_SOURCE, and before any include: this file now
 * pulls in kofplatform.h for kof_write_all, and that header's POSIX branch
 * has an inline kof_memmem whose body calls memmem - a GNU extension the
 * compiler must see declared to compile the body at all, whether or not this
 * translation unit ever calls it. On glibc _POSIX_C_SOURCE does not merely
 * fail to enable memmem, it suppresses it. Same reasoning, same wording, as
 * kofdb.c and kofmatch.c. */
#define _GNU_SOURCE

#include "kofview.h"
/* For enum kof_format, which kv_cap answers about. kofview.h itself stays
 * free of it: the header is a terminal and a widget, and a caller that only
 * draws should not have to pull in the engine to do it. */
#include <kofmod/kofsig.h>
#include "kofplat.h"
#include "../libkofeng/core/kofplatform.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* ---- the terminal ---------------------------------------------------------
 *
 * Raw mode, alternate screen, no cursor - and every one of them put back on the
 * way out, including the way out nobody plans for. A tool that leaves a terminal
 * in raw mode after a crash is a tool people stop running, so the restore is
 * registered before the first change is made and is idempotent.
 */
/*
 * Everything this program puts on the terminal goes through one call.
 *
 * It used to be two - fputs for the mode changes, write for the frames - and
 * that was a real bug rather than untidiness. stdout to a terminal is line
 * buffered and a mode change carries no newline, so "turn the mouse on" sat in
 * stdio's buffer for the whole session while every frame went straight out
 * around it. The terminal was never asked to report a click, so it never did,
 * and the viewer looked like a viewer whose mouse did not work.
 *
 * It also makes the restore path correct: write is async-signal-safe and
 * fputs/fflush are not, and the restore runs from a signal handler.
 */
void term_write_n(const char *s, size_t n)
{
	/* A screen that could not be written is not worth an error path: the
	 * next redraw writes the whole thing again. */
	(void)kof_write_all(STDOUT_FILENO, s, n);
}

void term_write(const char *s)
{
	term_write_n(s, strlen(s));
}

static int g_tty_raw;
int g_rows = 24, g_cols = 80;

void term_restore(void)
{
	if (!g_tty_raw)
		return;
	g_tty_raw = 0;
	kof_tty_raw_leave();
	/* Cursor back, main screen back, in that order: the show has to happen
	 * on the screen that is about to be left, or it applies to the one being
	 * returned to and the user's shell gets it. */
	term_write("\033[?2004l\033[?1006l\033[?1002l\033[?1000l\033[?25h\033[?1049l");
}

static void on_signal(int sig)
{
	term_restore();
	/* Re-raise with the default handler so the exit status says what
	 * happened. Exiting 0 here would tell a script the run succeeded. */
	signal(sig, SIG_DFL);
	raise(sig);
}

int term_setup(void)
{
	if (!kof_tty_ok()) {
		fprintf(stderr, "kofviewer: needs a terminal\n");
		return 0;
	}

	atexit(term_restore);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGSEGV, on_signal);

	if (!kof_tty_raw_enter())
		return 0;
	g_tty_raw = 1;
	/* Alternate screen, no cursor, and SGR mouse reporting - the last so a
	 * click can move the cursor to what it landed on. */
	/*
	 * Alternate screen, no cursor, and mouse reporting in three parts: 1000
	 * for press and release, 1002 for motion WHILE a button is down, 1006
	 * for the SGR encoding that has no coordinate ceiling.
	 *
	 * 1002 is what makes a drag a drag. It also takes the terminal's own
	 * text selection away, which is the point rather than a cost: a
	 * selection made of screen characters would span the tree pane, the
	 * offset column and the ASCII column, and none of those are what is
	 * being selected. Holding shift still bypasses all of this and gives
	 * back the terminal's copy, in every terminal that implements 1006.
	 */
	kof_tty_watch_size();
	/*
	 * ?2004h is bracketed paste. Without it a paste arrives as the keys it
	 * spells, so pasting a path into a field runs whatever those letters
	 * are bound to; with it the run is delimited and can be put where the
	 * caret is.
	 */
	term_write("\033[?1049h\033[?25l\033[?1000h\033[?1002h\033[?1006h"
		   "\033[?2004h");
	return 1;
}

void term_size(void)
{
	int r = 0, c = 0;

	if (kof_tty_size(&r, &c)) {
		g_rows = r;
		g_cols = c;
	}
	if (g_rows < 12)
		g_rows = 12;
	if (g_cols < 60)
		g_cols = 60;
}

/* ---- drawing --------------------------------------------------------------
 *
 * One frame is built into a buffer and written with one call. Not for speed:
 * writing a screen in fifty pieces makes a resize or a slow link show the frame
 * being assembled, and the flicker looks like a bug in the tool.
 */

void out_add(struct out *o, const char *s, size_t n)
{
	if (o->n + n + 1 > o->cap) {
		size_t want = o->cap ? o->cap * 2 : 8192;

		while (want < o->n + n + 1)
			want *= 2;
		o->p = realloc(o->p, want);
		if (!o->p)
			exit(1);
		o->cap = want;
	}
	memcpy(o->p + o->n, s, n);
	o->n += n;
}

void out_str(struct out *o, const char *s)
{
	const char *p;

	out_add(o, s, strlen(s));
	for (p = s; *p; p++) {
		if (*p == '\033') {
			while (*p && *p != 'm' && *p != 'H' && *p != 'K')
				p++;
			if (!*p)
				break;
			continue;
		}
		o->col_hint++;
	}
}

/*
 * One GLYPH: several bytes, one column.
 *
 * out_str counts col_hint per byte, which is right for ASCII and wrong for
 * anything else - a three byte box character would advance the column count by
 * three and every width and click box computed from it after that would be out.
 * The scrollbar gets away with out_str because it writes one glyph and then
 * repositions; a border cannot.
 */
void out_glyph(struct out *o, const char *g)
{
	out_add(o, g, strlen(g));
	o->col_hint++;
}

void out_fmt(struct out *o, const char *fmt, ...)
{
	char t[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	if (n > 0) {
		size_t keep = (size_t)n < sizeof t ? (size_t)n : sizeof t - 1;

		t[keep] = 0;
		out_str(o, t);
	}
}

void out_at(struct out *o, int row, int col)
{
	out_fmt(o, "\033[%d;%dH", row, col);
	o->row_hint = row;
	o->col_base = col;
}

/*
 * MAGENTA FOR A HEURISTIC, the colour the scanner has used for one since it had
 * colour at all.
 *
 * The three verdicts were painted in two here: anything that fired came out
 * red, so a structural guess and a named family looked alike on the one screen
 * where the difference is the point. A reader moving between the two tools
 * should not have to learn a second scheme.
 */
/*
 * AND and OR, told apart by colour.
 *
 * Both were A_WARN, so a condition read as one yellow word between blue ids and
 * the reader had to actually read it to know whether the rule was narrowing or
 * widening - which is the single most consequential thing on the row. AND is
 * cyan because it TIGHTENS (every id must be present); OR keeps the yellow it
 * had, because widening is the one that costs false positives and yellow is
 * what this panel already uses for "worth a second look".
 *
 * Named rather than written as escapes at the two sites: the operator inside a
 * condition and the join to the next one are drawn in different functions with
 * opposite polarity (`op` is 0-and-1-or, `join` is 0-or-1-and), and the pair
 * only stays consistent if the colour is chosen by the WORD, not by the field.
 */


/* ---- a dropdown ----------------------------------------------------------- */

static int kv_shown(const struct kv_menu *m, int i)
{
	return m->shown ? m->shown(m->ud, i) : 1;
}

static int kv_enabled(const struct kv_menu *m, int i)
{
	return m->enabled ? m->enabled(m->ud, i) : 1;
}

static int kv_rule(const struct kv_menu *m, int i)
{
	return m->rule_above ? m->rule_above(m->ud, i) : 0;
}

/*
 * One walk, and every question below is a different thing to do while making
 * it.
 *
 * Written three times over two menus before this, and the copies had already
 * drifted: one counted a rule before deciding the item was hidden, so a hidden
 * item at a group boundary left a rule with nothing under it and every row
 * after it was one off. `want` is the row being looked for, or -1 to just
 * count; `of` is an item to find the row of, or -1.
 */
static int kv_walk(const struct kv_menu *m, int want, int of)
{
	int i, row = 0;

	for (i = 0; i < m->n; i++) {
		if (!kv_shown(m, i))
			continue;
		if (kv_rule(m, i))
			row++;                  /* the rule takes a row */
		if (of == i)
			return row;
		if (want == row)
			return i;
		row++;
	}
	return want >= 0 || of >= 0 ? -1 : row;
}

int kv_menu_rows(const struct kv_menu *m)
{
	return kv_walk(m, -1, -1);
}

int kv_menu_at_row(const struct kv_menu *m, int row)
{
	return row < 0 ? -1 : kv_walk(m, row, -1);
}

int kv_menu_row_of(const struct kv_menu *m, int item)
{
	return kv_walk(m, -1, item);
}

int kv_menu_first(const struct kv_menu *m)
{
	int i;

	for (i = 0; i < m->n; i++)
		if (kv_shown(m, i) && kv_enabled(m, i))
			return i;
	return 0;
}

int kv_menu_step(const struct kv_menu *m, int cur, int d)
{
	int i, k = cur;

	for (i = 0; i < m->n; i++) {
		k += d;
		if (k < 0 || k >= m->n)
			return cur;
		if (kv_shown(m, k) && kv_enabled(m, k))
			return k;
	}
	return cur;
}

void kv_menu_draw(struct out *o, const struct kv_menu *m, int top, int left,
		  int sel, int sel2)
{
	int i, y = top, k;

	for (i = 0; i < m->n; i++) {
		if (!kv_shown(m, i))
			continue;
		if (kv_rule(m, i)) {
			out_at(o, y++, left);
			out_str(o, m->c_on);
			out_str(o, " ");
			for (k = 0; k < m->w - 2; k++)
				out_glyph(o, G_H);
			out_str(o, " " A_OFF);
		}
		out_at(o, y++, left);
		if (i == sel || i == sel2)
			out_str(o, m->c_cur);
		else if (!kv_enabled(m, i))
			out_str(o, m->c_off);
		else
			out_str(o, m->c_on);
		/* The submenu arrow is drawn INSIDE the width, not after it: a
		 * row that is one column wider than its neighbours puts a step
		 * in the right edge of the box. */
		if (m->has_sub && m->has_sub(m->ud, i))
			out_fmt(o, " %-*.*s>", m->w - 2, m->w - 2,
				m->label(m->ud, i));
		else
			out_fmt(o, " %-*.*s", m->w - 1, m->w - 1,
				m->label(m->ud, i));
		out_str(o, A_OFF);
	}
}

/* ---- what a format can be asked - see kofview.h ---------------------------- */

int kv_cap(uint8_t format, int cap)
{
	switch (format) {
	case KOF_FMT_ELF:
	case KOF_FMT_PE:
	case KOF_FMT_MACHO:
		/* All four: an executable image has a symbol table, code at an
		 * entry point, is the thing a packer packs, and is where a
		 * loader keeps the payload it will run. */
		return cap == KV_CAP_SYMBOLS || cap == KV_CAP_CODE ||
		       cap == KV_CAP_UNPACK || cap == KV_CAP_SHELLCODE;

	case KOF_FMT_UNKNOWN:
		/*
		 * Bytes nothing claimed. No symbol table to look for, but they
		 * may well BE code - a payload an unpacker peeled, a blob
		 * carved out of a variable - and that is the case the emulator
		 * and the disassembler exist for.
		 */
		return cap == KV_CAP_CODE || cap == KV_CAP_UNPACK;

	default:
		/*
		 * Every container and every document format. Their members come
		 * out by being READ, which the engine does on its own and which
		 * is not what any of these items mean, and none of them has a
		 * symbol table or an entry point.
		 *
		 * Written as a default rather than listed, because the list is
		 * the longer one and a format added tomorrow is far likelier to
		 * belong here than with the executables - so the safe answer is
		 * the one a new format gets by saying nothing.
		 */
		return 0;
	}
}
