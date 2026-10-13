#define _GNU_SOURCE
#include "kv.h"


#define PROP_TAB_COLS 4u

struct prop_table {
	/*
	 * The label in the left column, or NULL when a section heading above
	 * the table already names it.
	 *
	 * Four tables one under the other read as one wall of rows with the
	 * names lost in the left margin, so each of them gets a heading at the
	 * same level as "Process" and a blank line before it. That leaves this
	 * column free for the count, which is the thing that has nowhere else
	 * to go.
	 */
	const char *name;
	const char *col[PROP_TAB_COLS];
	uint8_t     width[PROP_TAB_COLS];   /* 0 = take what is left */
	/*
	 * WHICH COLUMNS MOVE WITH shift+wheel. Non-zero for the ones that hold
	 * something long.
	 *
	 * Sideways used to move every cell, and that is wrong for the shape
	 * these tables actually have: a variable NAME is short and a variable
	 * VALUE is a PATH. Scrolling both took the names off the screen to
	 * reach the tail of a value, so the reader lost the only thing telling
	 * them which row they were reading. Marking the long column moves it
	 * under a heading that still names it.
	 */
	uint8_t     hscroll[PROP_TAB_COLS];
	uint32_t    n_col;
	uint32_t    n_row;
	uint32_t    visible;                /* rows shown at once */
	enum prop_tab_id id;                /* which scroll offset is ours */
	/* Fill `out` with n_col cells for `row`. Cells may be NULL for "". */
	void      (*cell)(void *user, uint32_t row, const char **out);
	void       *user;
};

/*
 * Below this a table is drawn WITHOUT its frame - the heading and the rows and
 * nothing else.
 *
 * A border, a scrollbar and a "1-3 of 3" line around three values is more
 * furniture than data: it says "there is more here" when there is not, and it
 * costs three rows to say it. The frame earns its place only once the window
 * is actually a window.
 */
#define PROP_TAB_FRAME_MIN 6u

/* Rows of connection shown before the panel says how many more there are. */
#define PROC_NET_ROWS 6u
/* Same reasoning, and a session hands a child about forty of these. */
#define PROC_ENV_ROWS 6u
/* A process maps a dozen libraries and a pile of locale files; this is the
 * screenful, and the rest is counted. */
#define PROC_LIB_ROWS 20u

/*
 * The two lists the record carries are flat text with a separator - the
 * environment is one space between assignments, the connection list one
 * newline between rows - so both feeders are "find the nth piece". Counting
 * and fetching are the same walk, which is why they are one function: a count
 * that disagreed with the fetch would show a row the table could not fill.
 */
struct prop_list {
	const char *text;
	/*
	 * HOW LONG THE BLOCK IS, because one of the two separators is NUL.
	 *
	 * The environment cannot be split on a space: a value may contain one,
	 * and a row split there shows one variable as two with the second
	 * unnamed. The collector therefore keeps the NULs between assignments,
	 * and a NUL-separated block is not a string - strlen names its first
	 * piece. 0 means "take strlen", which is what the connection list,
	 * separated by newlines, wants.
	 */
	uint32_t    len;
	char        sep;
	/* Wide enough for the longest cell either feeder writes: a raw net
	 * line is bounded by the collector at 256, and a value is cut to what
	 * a column can show anyway. */
	char        buf[4][256];
};

/* The three standard descriptors, by name, out of the record's arena - they
 * are written consecutively, so each is found by stepping past the one
 * before. */
struct prop_fdlist {
	const struct object *ob;
	const struct kof_proc_info *pi;
	char buf[64];
};

/*
 * WHAT THE PROCESS HAS MAPPED, one row per file.
 *
 * The tree already carries these as objects, so this is not a second walk of
 * anything - it reads the rows that are already there. It is worth a table
 * anyway: the tree interleaves them with the memory regions in address order,
 * which is the order the address space has and not an order anybody reads, and
 * the question "what did this load" wants them together.
 *
 * TOLD APART FROM THE MEMORY REGIONS BY NAME, which is the convention the walk
 * establishes: a region is MEM_<something> and a mapped file is its basename.
 * A name test rather than a flag because the name is what the rest of the
 * viewer already keys on, and a second marker would be a second thing to keep
 * in step.
 */
/*
 * The mapped files, as a table like the other three.
 *
 * KIND FIRST, THEN SIZE, THEN THE PATH. A reader scanning this column is
 * asking "what has this process got loaded" - an ELF, a locale table, a cache
 * - and the answer is the same six characters on most rows, which is what
 * makes a column worth reading down. The path is last because it is the one
 * that does not fit, and the one that therefore scrolls.
 *
 * THE WHOLE PATH AND NOT THE LEAF. Two mappings named `libc.so.6` may be the
 * system one and one out of a writable directory, which is the difference
 * between a normal process and an interesting one, and a basename cannot say
 * which. It is too wide for any column, so it is the column that moves under
 * shift and the wheel.
 */
struct prop_liblist {
	const struct view *v;
	char buf[3][320];
};


static void prop_add(const char *fmt, ...)
{
	va_list ap;

	if (g_n_prop >= PROP_MAX)
		return;
	va_start(ap, fmt);
	vsnprintf(g_prop[g_n_prop].text, PROP_W, fmt, ap);
	va_end(ap);
	g_n_prop++;
}

/* A heading, with a blank line above it unless it opens the page. */
static void prop_head(const char *w)
{
	if (g_n_prop)
		prop_add(A_DIM "%s", "");
	prop_add(A_BOLD "%s" A_OFF, w);
}

/* An offset that may be one of the two sentinels: KGENOME_NA (the format has no such
 * thing - an ET_REL has no entry in the file) or KGENOME_BROKEN (it should, and does
 * not resolve). Printed raw they read as 18446744073709551615. */
void prop_off(char *out, size_t cap, uint64_t v)
{
	if (v == KGENOME_NA)
		snprintf(out, cap, "-");
	else if (v == KGENOME_BROKEN)
		snprintf(out, cap, "unresolved");
	else
		snprintf(out, cap, "0x%llx", (unsigned long long)v);
}

static void prop_perm(char *out, size_t cap, unsigned p)
{
	snprintf(out, cap, "%c%c%c", (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-',
		 (p & 1) ? 'X' : '-');
}

/* "9 of 9 declared", and the count that did not add up said as such. */
static void prop_claimed(const char *label, uint32_t have, uint32_t claimed)
{
	prop_add(A_DIM "  %-11s " A_OFF "%s%u of %u" A_OFF A_DIM
		 " declared" A_OFF, label,
		 have == claimed ? A_SIZE : A_WARN, have, claimed);
}

/*
 * THE PROCESS PANEL.
 *
 * Shaped like prop_elf and prop_pe beside it: one function per format, reading
 * that format's info struct off ob->info and writing rows. Nothing here knows
 * where the facts came from - the collector filled a record, the parser turned
 * it into kof_proc_info, and this draws it - which is the same three steps
 * every other panel on this page is made of.
 *
 * THIS IS WHERE THE HEAD AND THE DESCRIPTORS LIVE NOW. They used to be scan
 * REGIONS as well, and they were dropped from that: see KOF_SCAN_PROC_CLAIMED
 * for why a packed struct of integers is not something a signature searches.
 * Not being searchable is not a reason to hide them from a reader, and this is
 * the place a reader looks.
 *
 * The strings are read out of the record's own arena by offset, because the
 * parse already checked those offsets are inside it - `valid` is that check.
 */
static const char *proc_str(const struct object *ob, uint32_t off)
{
	const char *p;

	if (!off || off >= ob->buf.n)
		return "";
	p = (const char *)ob->buf.p + off;
	return p;
}
/* Where each table was drawn, so a wheel over one scrolls THAT one. Reset
 * every time the page is built, because a table that is no longer drawn must
 * not keep catching the pointer. */
static int      g_prop_tab_row0[PROP_TAB_COUNT];
static int      g_prop_tab_rows[PROP_TAB_COUNT];
static int      g_prop_tab_wid[PROP_TAB_COUNT];
/*
 * WHERE EACH COLUMN OF EACH TABLE STARTS AND HOW WIDE IT IS, in the columns of
 * the recorded line - so a click can be turned back into a CELL.
 *
 * Recorded as the table is drawn because that is the only place the geometry
 * exists: the widths are the declaration's and the prefix is this function's,
 * and a second copy of that sum in the click handler would be a second thing
 * to keep in step.
 */
static int      g_prop_tab_cx[PROP_TAB_COUNT][PROP_TAB_COLS];
static int      g_prop_tab_cw[PROP_TAB_COUNT][PROP_TAB_COLS];
static int      g_prop_tab_ncol[PROP_TAB_COUNT];
/*
 * THE TABLE'S LEFT AND RIGHT EDGE, and whether it has anywhere to scroll.
 *
 * A wheel over a table scrolls the table - but "over" was answered by the ROW
 * alone, and the page is far wider than any table. Everything to the right of
 * a table, all the way to the border, is a row of that table by that test, so
 * the wheel in the empty half of the page went to a widget the pointer was
 * nowhere near.
 *
 * And a table with nothing to scroll swallowed it anyway: the offset moved and
 * the draw clamped it straight back, so the page did not move and neither did
 * the table. That is the "sometimes it works" - it worked below the last table,
 * where no table claimed the row, and nowhere else.
 */
static int      g_prop_tab_x0[PROP_TAB_COUNT];
static int      g_prop_tab_x1[PROP_TAB_COUNT];

/*
 * Which table the pointer is over, or -1.
 *
 * Asked in SCREEN rows and answered from where each table was drawn, which is
 * recorded as the page is built. The page scrolls, so a table's rows move: the
 * offset of the page is taken off here rather than being baked into what was
 * recorded, so one number moves both.
 */
int prop_tab_at(const struct view *v, int row, int col)
{
	int rr = row - v->dlg_y0;
	int cc = col - v->dlg_x0;
	int i, r;

	/*
	 * Through the recording, which already maps a screen row to the line
	 * of the page showing there - see view.dlg_src. Computing it from the
	 * page offset instead would be a second copy of that arithmetic, and
	 * the two would disagree the first time either changed.
	 */
	if (rr < 0 || rr >= v->dlg_rows)
		return -1;
	r = v->dlg_src[rr];
	if (r < 0)
		return -1;

	for (i = 0; i < PROP_TAB_COUNT; i++)
		if (g_prop_tab_rows[i] > 0 && r >= g_prop_tab_row0[i] &&
		    r < g_prop_tab_row0[i] + g_prop_tab_rows[i] &&
		    cc >= g_prop_tab_x0[i] && cc <= g_prop_tab_x1[i])
			return i;
	return -1;
}

/*
 * The CELL a click landed in, as a span of columns on the recorded row, or 0
 * when the click was not inside one of the tables' columns.
 *
 * The geometry is the drawing's own - see g_prop_tab_cx - so this cannot drift
 * from where the cell actually is. The span is the column's full width; the
 * caller trims the padding off the right, which is what makes a double click on
 * a short value take the value and not the blanks after it.
 */
int prop_cell_span(const struct view *v, int row, int col,
			  int *c0, int *c1)
{
	int id = prop_tab_at(v, row, col);
	int k;

	if (id < 0)
		return 0;
	for (k = 0; k < g_prop_tab_ncol[id] && k < (int)PROP_TAB_COLS; k++) {
		int x = g_prop_tab_cx[id][k];

		if (col >= x && col < x + g_prop_tab_cw[id][k]) {
			*c0 = x;
			*c1 = x + g_prop_tab_cw[id][k] - 1;
			return 1;
		}
	}
	return 0;
}

static void prop_table(const struct prop_table *t)
{
	uint32_t off, shown, i, k;
	int framed = t->n_row >= PROP_TAB_FRAME_MIN;
	char line[PROP_W];

	if (!t->n_row) {
		g_prop_tab_rows[t->id] = 0;
		return;
	}
	off = g_prop_tab_off[t->id];
	if (off + t->visible > t->n_row)
		off = t->n_row > t->visible ? t->n_row - t->visible : 0u;
	g_prop_tab_off[t->id] = off;

	/*
	 * A BORDER, BECAUSE A TABLE WITHOUT ONE IS JUST INDENTED ROWS.
	 *
	 * The panel is a column of label/value rows, so a window of six rows
	 * with a heading read as six more of the same - and the "1-6 of 111"
	 * line under it looked like a value whose name was blank. A rule above
	 * and below and a wall down each side says where the widget starts and
	 * stops, which is the whole of what was confusing.
	 */
	{
		/*
		 * SIZED IN BYTES FOR A WIDTH IN GLYPHS. G_H is three bytes, so
		 * a 200-byte buffer holds 66 columns of rule while the rows
		 * beside it were 70 wide - the corner fell off the end and the
		 * frame had a gap where its right side should be.
		 */
		char rule[PROP_TAB_MAX_W * 3u + 1u];
		uint32_t wid = 0, n = 0;

		for (k = 0; k < t->n_col; k++)
			wid += (t->width[k] ? t->width[k] : 24u) + 1u;
		if (wid > PROP_TAB_MAX_W)
			wid = PROP_TAB_MAX_W;
		g_prop_tab_wid[t->id] = (int)wid;
		while (n < wid) {
			memcpy(rule + n * 3u, G_H, sizeof G_H - 1u);
			n++;
		}
		rule[n * (sizeof G_H - 1u)] = 0;
		if (framed)
			prop_add(A_DIM "  %-11s " G_TL "%s" G_TR A_OFF,
				 t->name ? t->name : "", rule);
	}

	/*
	 * WHERE IN THE LIST THIS WINDOW IS - UNDER THE TABLE'S NAME.
	 *
	 * A table that just stopped reads as a process with six variables; the
	 * count is the difference between a window and a wrong answer. It sat
	 * on the bottom rule, twenty rows below the name it belonged to, which
	 * is far enough away to read as a caption on whatever came next. The
	 * name is on the top rule, so this goes on the two rows under it.
	 *
	 * Across two rows because the label column is eleven wide: "1-6/111"
	 * fits and "121-126/1024" does not, and a count that is cut is worse
	 * than no count. The range first, the total under it.
	 */
	char cap[2][24];

	cap[0][0] = cap[1][0] = 0;
	if (t->n_row > t->visible) {
		snprintf(cap[0], sizeof cap[0], "%lu-%lu",
			 (unsigned long)(off + 1u),
			 (unsigned long)(off + (t->n_row - off > t->visible
					        ? t->visible
					        : t->n_row - off)));
		snprintf(cap[1], sizeof cap[1], "of %lu",
			 (unsigned long)t->n_row);
	}

	/* The heading. */
	{
		int n = snprintf(line, sizeof line, "  %-11s " A_DIM "%s"
				 A_OFF,
				 framed ? cap[0] : (t->name ? t->name : ""),
				 framed ? G_V : " ");

		for (k = 0; k < t->n_col && n > 0 && (size_t)n < sizeof line;
		     k++)
			n += snprintf(line + n, sizeof line - (size_t)n,
				      A_DIM "%-*.*s " A_OFF,
				      t->width[k] ? t->width[k] : 24,
				      t->width[k] ? t->width[k] : 24,
				      t->col[k] ? t->col[k] : "");
		if (framed && n > 0 && (size_t)n < sizeof line)
			snprintf(line + n, sizeof line - (size_t)n,
				 A_DIM G_V A_OFF);
		prop_add("%s", line);
	}

	/* The row this table starts on, for the wheel. prop_add has just
	 * written the heading, so the first data row is the next one. */
	g_prop_tab_row0[t->id] = (int)g_n_prop;
	{
		/* "  " + an 11-wide label + " " + the wall. */
		/* "  " + an 11-wide label + " " + one column of wall or
		 * blank - the same width either way, which is what keeps a
		 * framed and an unframed table's columns lined up. */
		int x = 2 + 11 + 1 + 1;

		g_prop_tab_x0[t->id] = x - 1;   /* the wall, or the blank */
		for (k = 0; k < t->n_col && k < PROP_TAB_COLS; k++) {
			int w = t->width[k] ? t->width[k] : 24;

			g_prop_tab_cx[t->id][k] = x;
			g_prop_tab_cw[t->id][k] = w;
			x += w + 1;
		}
		g_prop_tab_ncol[t->id] = (int)t->n_col;
		/* Up to and including the right wall, which is where the
		 * scrollbar is - a wheel on the bar is a wheel on the table. */
		g_prop_tab_x1[t->id] = x;
		/*
		 * WHAT THIS TABLE CAN ACTUALLY DO WITH A WHEEL. Sideways is a
		 * property of the declaration and downwards of the data, and a
		 * table that can do neither has to let the wheel past or the
		 * page stops scrolling wherever a table happens to be.
		 */
		g_prop_tab_scroll_v[t->id] = t->n_row > t->visible;
		g_prop_tab_scroll_h[t->id] = 0;
		for (k = 0; k < t->n_col && k < PROP_TAB_COLS; k++)
			if (t->hscroll[k])
				g_prop_tab_scroll_h[t->id] = 1;
	}

	shown = t->n_row - off;
	if (shown > t->visible)
		shown = t->visible;
	for (i = 0; i < shown; i++) {
		const char *cell[PROP_TAB_COLS] = { NULL, NULL, NULL, NULL };
		uint32_t hoff = g_prop_tab_hoff[t->id];
		int n;

		t->cell(t->user, off + i, cell);
		n = snprintf(line, sizeof line, "  %-11s " A_DIM "%s" A_OFF,
			     (framed && i == 0) ? cap[1] : "",
			     framed ? G_V : " ");
		for (k = 0; k < t->n_col && n > 0 && (size_t)n < sizeof line;
		     k++) {
			const char *c = cell[k] ? cell[k] : "";
			uint32_t w = t->width[k] ? t->width[k] : 24u;

			/*
			 * SIDEWAYS IS PER CELL, not per row: shifting the
			 * whole line would slide the columns out of their
			 * headings. Each cell shows a later part of ITSELF,
			 * so the table keeps its shape and a long value walks
			 * under a heading that still names it.
			 */
			if (hoff && t->hscroll[k]) {
				size_t cl = strlen(c);

				c = hoff < cl ? c + hoff : "";
			}
			n += snprintf(line + n, sizeof line - (size_t)n,
				      A_ID "%-*.*s" A_OFF " ",
				      (int)w, (int)w, c);
		}
		/*
		 * THE SCROLLBAR, IN THE WALL ITSELF. One cell of it per row,
		 * so a reader sees both where the window is and how much there
		 * is without a line of arithmetic. Drawn only when there is
		 * more than fits - a full-height thumb says nothing.
		 */
		if (framed && n > 0 && (size_t)n < sizeof line) {
			/*
			 * A GLYPH AND NOT A REVERSED SPACE: a space in reverse
			 * video is the thumb everywhere else in this tree, and
			 * in a one-column wall it reads as a HOLE in the border
			 * rather than as a marker on it.
			 *
			 * Through the shared bar, so this wall tracks the way
			 * every pane's does - it had a thumb of one row wherever
			 * it was, which on a long table is a mark that moves and
			 * says nothing about how much there is.
			 */
			const char *bar = kv_bar_at((int)t->visible, (int)i,
						    off, t->n_row, t->visible,
						    0);

			snprintf(line + n, sizeof line - (size_t)n, "%s",
				 bar ? bar : A_DIM G_V A_OFF);
		}
		prop_add("%s", line);
	}
	g_prop_tab_rows[t->id] = (int)shown;

	/*
	 * WHERE IN THE LIST THIS WINDOW IS, whenever there is more than fits.
	 * A table that just stopped reads as a process with six variables; the
	 * count is the difference between a window and a wrong answer.
	 */
	if (framed) {
		char rule[PROP_TAB_MAX_W * 3u + 1u];
		uint32_t wid = (uint32_t)g_prop_tab_wid[t->id], n = 0;

		while (n < wid) {
			memcpy(rule + n * 3u, G_H, sizeof G_H - 1u);
			n++;
		}
		rule[n * (sizeof G_H - 1u)] = 0;
		/* Nothing in the label column here: the count is up beside the
		 * name, where a caption belongs. */
		prop_add(A_DIM "  %-11s " G_BL "%s" G_BR A_OFF, "", rule);
	}
}

/* memchr and not strchr, so the separator may be NUL - see prop_list.len. */
static const char *plist_nth(const char *t, uint32_t tn, char sep, uint32_t n,
			     char *out, size_t cap)
{
	uint32_t i = 0, at = 0;

	out[0] = 0;
	while (at < tn) {
		const char *e = memchr(t + at, sep, tn - at);
		size_t len = e ? (size_t)(e - (t + at)) : (size_t)(tn - at);

		if (i == n) {
			if (len >= cap)
				len = cap ? cap - 1u : 0u;
			memcpy(out, t + at, len);
			out[len] = 0;
			return out;
		}
		i++;
		if (!e)
			break;
		at = (uint32_t)(e - t) + 1u;
	}
	return out;
}

static uint32_t plist_count(const char *t, uint32_t tn, char sep)
{
	uint32_t n = 0, at = 0;

	while (at < tn) {
		const char *e = memchr(t + at, sep, tn - at);

		n++;
		if (!e)
			break;
		at = (uint32_t)(e - t) + 1u;
	}
	return n;
}

/* The block's extent - what the caller declared, or strlen when it did not. */
static uint32_t plist_len(const struct prop_list *l)
{
	return l->len ? l->len : (uint32_t)strlen(l->text);
}

/* NAME=value split into two columns - the whole reason the environment is a
 * table and not a list: the names line up, so the eye finds LD_PRELOAD without
 * reading a single value. */
static void env_cell(void *user, uint32_t row, const char **out)
{
	struct prop_list *l = user;
	char *eq;

	plist_nth(l->text, plist_len(l), l->sep, row, l->buf[0],
		  sizeof l->buf[0]);
	eq = strchr(l->buf[0], '=');
	if (eq) {
		*eq = 0;
		snprintf(l->buf[1], sizeof l->buf[1], "%s", eq + 1);
	} else {
		l->buf[1][0] = 0;
	}
	out[0] = l->buf[0];
	out[1] = l->buf[1];
}

/* "TCP 1.2.3.4:1 -> 5.6.7.8:2 STATE" into four columns. */
static void net_cell(void *user, uint32_t row, const char **out)
{
	struct prop_list *l = user;
	char raw[256];

	plist_nth(l->text, plist_len(l), l->sep, row, raw, sizeof raw);
	l->buf[0][0] = l->buf[1][0] = l->buf[2][0] = l->buf[3][0] = 0;
	if (sscanf(raw, "%15s %63s -> %63s %31s", l->buf[0], l->buf[1],
		   l->buf[2], l->buf[3]) < 3)
		snprintf(l->buf[0], sizeof l->buf[0], "%s", raw);
	out[0] = l->buf[0];
	out[1] = l->buf[1];
	out[2] = l->buf[2];
	out[3] = l->buf[3];
}

static void fd_cell(void *user, uint32_t row, const char **out)
{
	static const char *const names[3] = { "stdin", "stdout", "stderr" };
	struct prop_fdlist *f = user;
	uint32_t off = f->pi->off_fd0, k;
	const char *t = "";

	for (k = 0; k <= row && k < 3u; k++) {
		t = proc_str(f->ob, off);
		if (!off || off >= f->ob->buf.n)
			break;
		off += (uint32_t)strlen(t) + 1u;
	}
	snprintf(f->buf, sizeof f->buf, "%s", t[0] ? t : "(none)");
	out[0] = names[row < 3u ? row : 2u];
	out[1] = f->buf;
}

static void prop_proc_libs(const struct view *v);

static void prop_proc(const struct view *v, const struct object *ob)
{
	const struct kof_proc_info *pi = ob->info;
	const char *cmd;

	if (!pi || !pi->valid)
		return;

	prop_head("Process");
	prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM "  parent " A_OFF
		 A_SIZE "%lu" A_OFF, "pid", (unsigned long)pi->pid,
		 (unsigned long)pi->ppid);
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "exe",
		 proc_str(ob, pi->off_exe));
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "name",
		 proc_str(ob, pi->off_comm));
	cmd = proc_str(ob, pi->off_cmdline);
	/*
	 * SAID EVEN WHEN IT IS EMPTY, because an empty command line and one
	 * nobody could read are different facts and only one of them is about
	 * the program - the same distinction KOFW_PF_CMDLINE_LOST draws.
	 */
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF, "cmdline",
		 cmd[0] ? cmd : "(none recorded)");

	/*
	 * The per-platform tail, named by the record's OWN os rather than by
	 * this build: a snapshot taken on the other platform reads correctly
	 * here, which is the reason kof_proc_rec carries the byte at all.
	 */
	if (pi->os == KOF_PLAT_WINDOWS)
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM
			 "  integrity " A_OFF A_SIZE "%lu" A_OFF, "session",
			 (unsigned long)pi->plat_a,
			 (unsigned long)pi->plat_b);
	else
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM "  gid "
			 A_OFF A_SIZE "%lu" A_OFF, "uid",
			 (unsigned long)pi->plat_a,
			 (unsigned long)pi->plat_b);

	/*
	 * THE COUNTS, AND WHETHER THEY WERE READ AT ALL.
	 *
	 * KOF_PROC_F_FDS_READ is what separates "this process holds no
	 * descriptors" from "nobody was allowed to look", and a panel that
	 * printed 0 for both would be inventing the first.
	 */
	if (pi->flags & KOF_PROC_F_FDS_READ)
		prop_add(A_DIM "  %-11s " A_SIZE "%lu" A_OFF A_DIM
			 "  sockets " A_OFF A_SIZE "%lu" A_OFF, "fds",
			 (unsigned long)pi->n_fd,
			 (unsigned long)pi->n_socket);
	else
		prop_add(A_DIM "  %-11s not readable" A_OFF, "fds");

	/*
	 * WHAT WAS NOT COLLECTED, WHERE THE THINGS THAT WERE ARE LISTED.
	 *
	 * The tables below are a list of what this process has, and a list
	 * that quietly stops is read as the whole of it. Saying the number
	 * here turns "these are its mappings" into "these are the ones that
	 * were taken", which is the true statement and the one a reader needs
	 * before concluding a library is absent.
	 */
	if (v->proc_skipped)
		prop_add(A_WARN "  %-11s %lu mapping(s) not collected" A_OFF
			 A_DIM " - too large, or past the time this may take"
			 A_OFF, "partial", (unsigned long)v->proc_skipped);

	/*
	 * The three shapes the rules key on, said in words. A reader looking
	 * at a panel should be able to see what a rule saw.
	 *
	 * STILL IN THE PROCESS SECTION, above the tables: each table now has a
	 * heading of its own, so a row left after them reads as a footnote to
	 * whichever one it happens to follow.
	 */
	if (pi->fd_same_01)
		prop_add(A_WARN "  %-11s fd 0 and fd 1 name the SAME object"
			 A_OFF, "stdio");
	if (pi->comm_bracketed)
		prop_add(A_WARN "  %-11s name is bracketed, like a kernel "
			 "thread" A_OFF, "masquerade");
	if (pi->flags & KOF_PROC_F_KTHREAD)
		prop_add(A_DIM "  %-11s kernel thread" A_OFF, "kind");
	if (!(pi->flags & KOF_PROC_F_EXE_ON_DISK))
		prop_add(A_WARN "  %-11s the executable is not on disk" A_OFF,
			 "exe");

	/*
	 * WHAT IT HAS MAPPED, FIRST.
	 *
	 * The order here is the order a reader asks in: what is this running,
	 * who is it talking to, what does it hold open, and how was it
	 * launched. The mapped files answer the first and are the widest net -
	 * a library nobody shipped is visible here and nowhere else in the
	 * panel.
	 */
	prop_proc_libs(v);

	/*
	 * WHO IT IS TALKING TO. Beside the descriptors and not on a page of
	 * its own, because the two answer one question together: a socket on
	 * fd 0 is a reverse shell only once you know what it is CONNECTED TO.
	 */
	{
		struct prop_list nl;
		struct prop_table t;
		const char *raw = proc_str(ob, pi->off_net);

		if (raw[0]) {
			memset(&nl, 0, sizeof nl);
			nl.text = raw;
			nl.sep = '\n';
			memset(&t, 0, sizeof t);
			prop_head("Connections");
			t.name = NULL;
			t.col[0] = "proto";  t.width[0] = 6;
			t.col[1] = "local";  t.width[1] = 24;
			t.col[2] = "remote"; t.width[2] = 24;
			t.col[3] = "state";  t.width[3] = 12;
			/* Both addresses, because an IPv6 pair is longer than
			 * any width worth giving it and the proto and state
			 * columns are what keep the row readable. */
			t.hscroll[1] = t.hscroll[2] = 1;
			t.n_col = 4;
			t.n_row = plist_count(raw, (uint32_t)strlen(raw), '\n');
			t.visible = PROC_NET_ROWS;
			t.id = PROP_TAB_NET;
			t.cell = net_cell;
			t.user = &nl;
			prop_table(&t);
		} else if (pi->n_socket) {
			/*
			 * SOCKETS IT HOLDS AND NOTHING TO SAY ABOUT THEM -
			 * a unix socket, or a namespace this could not read.
			 * The count beats a blank that reads as "none".
			 */
			prop_head("Connections");
			prop_add(A_DIM "  %lu socket(s), none in the "
				 "connection tables" A_OFF,
				 (unsigned long)pi->n_socket);
		}
	}

	/*
	 * THE DESCRIPTORS, through the same table - see struct prop_table.
	 *
	 * They are read ACROSS rather than down: the question is never "what
	 * is fd 1" on its own, it is whether two of them name the same thing.
	 * Three rows in one column makes a reader hold two strings in their
	 * head; a table puts them under each other where the eye does it.
	 *
	 * Three rows is under the framing threshold, so it draws as a plain
	 * heading and three rows - a border round three values is furniture.
	 * The threshold is the table's, not this caller's: the day the record
	 * carries every descriptor rather than the standard three, the frame
	 * and the scroll appear on their own.
	 */
	{
		struct prop_fdlist fl;
		struct prop_table t;

		fl.ob = ob;
		fl.pi = pi;
		memset(&t, 0, sizeof t);
		prop_head("Descriptors");
		t.name = NULL;
		t.col[0] = "stream"; t.width[0] = 8;
		t.col[1] = "target"; t.width[1] = 56;
		t.hscroll[1] = 1;
		t.n_col = 2;
		t.n_row = 3;
		t.visible = 3;
		t.id = PROP_TAB_FD;
		t.cell = fd_cell;
		t.user = &fl;
		prop_table(&t);
	}

	/*
	 * THE ENVIRONMENT AND THE CONNECTIONS, both as tables with a scroll of
	 * their own - see struct prop_table for why they are declared rather
	 * than drawn here.
	 */
	{
		struct prop_list el;
		struct prop_table t;

		uint32_t en = pi->len_env;

		memset(&el, 0, sizeof el);
		el.text = proc_str(ob, pi->off_env);
		/*
		 * NUL-SEPARATED, AND THE EXTENT IS THE REGION'S. The arena
		 * writes a terminator after the block, and the region runs to
		 * the next one's offset, so the last byte or two are NULs that
		 * would each read as an empty variable.
		 */
		while (en && !el.text[en - 1u])
			en--;
		el.len = en;
		el.sep = '\0';
		memset(&t, 0, sizeof t);
		if (en)
			prop_head("Environment");
		t.name = NULL;
		t.col[0] = "variable"; t.width[0] = 28;
		/* 40 and not the 64 a value can be: the table has to fit the
		 * panel or its right wall and scrollbar fall off the edge,
		 * which is the confusion the border was added to remove. What
		 * a value loses to the width, shift+wheel gets back. */
		t.col[1] = "value";    t.width[1] = 40;
		/* Only the value moves: a name is short and is what tells the
		 * reader which row they are on. */
		t.hscroll[1] = 1;
		t.n_col = 2;
		t.n_row = en ? plist_count(el.text, en, '\0') : 0u;
		t.visible = PROC_ENV_ROWS;
		t.id = PROP_TAB_ENV;
		t.cell = env_cell;
		t.user = &el;
		prop_table(&t);
	}

}

/*
 * The nth object that IS a mapped file.
 *
 * `proc_path` is the test and the only one needed: the walk stamps it on the
 * object it made from a mapped file and on nothing else, so this excludes the
 * memory regions (MEM_HEAP and its kind, which have no file behind them) and
 * the CHILDREN of a mapped file - an appended payload, an archive member -
 * which are things found INSIDE a mapping rather than mappings.
 *
 * Walked per row rather than indexed once, because the list is bounded by
 * PROC_SEEN_MAX and a table shows twenty rows.
 */
static uint32_t lib_obj(const struct view *v, uint32_t row)
{
	uint32_t i, n = 0;

	for (i = 1; i < v->n_obj; i++) {
		if (!v->obj[i].proc_path)
			continue;
		if (n++ == row)
			return i;
	}
	return 0;
}

static uint32_t lib_count(const struct view *v)
{
	uint32_t i, n = 0;

	for (i = 1; i < v->n_obj; i++)
		if (v->obj[i].proc_path)
			n++;
	return n;
}

static void lib_cell(void *user, uint32_t row, const char **out)
{
	struct prop_liblist *l = user;
	uint32_t i = lib_obj(l->v, row);
	const struct object *o;

	l->buf[0][0] = l->buf[1][0] = l->buf[2][0] = 0;
	if (!i) {
		out[0] = out[1] = out[2] = "";
		return;
	}
	o = &l->v->obj[i];
	if (o->fmt)
		snprintf(l->buf[0], sizeof l->buf[0], "%s-%s",
			 kof_format_name(o->ctx.format),
			 kof_arch_name(o->ctx.arch));
	else
		snprintf(l->buf[0], sizeof l->buf[0], "data");
	snprintf(l->buf[1], sizeof l->buf[1], "%llu",
		 (unsigned long long)o->buf.n);
	/* Every row here has a path - it is what put the row in the table. */
	snprintf(l->buf[2], sizeof l->buf[2], "%s",
		 l->v->seen_path[o->proc_path - 1u]);
	out[0] = l->buf[0];
	out[1] = l->buf[1];
	out[2] = l->buf[2];
}

static void prop_proc_libs(const struct view *v)
{
	struct prop_liblist ll;
	struct prop_table t;

	if (!v->n_obj)
		return;
	memset(&t, 0, sizeof t);
	ll.v = v;
	prop_head("Mapped files");
	t.name = NULL;
	t.col[0] = "type";
	t.col[1] = "bytes";
	t.col[2] = "path";
	t.width[0] = 10;
	t.width[1] = 10;
	t.width[2] = 48;
	t.hscroll[2] = 1;
	t.n_col = 3;
	t.n_row = lib_count(v);
	t.visible = PROC_LIB_ROWS;
	t.id = PROP_TAB_LIB;
	t.cell = lib_cell;
	t.user = &ll;
	prop_table(&t);
}

static void prop_elf(const struct object *ob)
{
	const struct kgenome_elf_info *e = ob->info;
	char perm[4], fo[24];
	uint32_t i;

	prop_head("ELF");
	prop_add(A_DIM "  %-11s " A_ID "%s %s" A_OFF A_DIM
		 "   type=" A_OFF A_SIZE "%u" A_OFF A_DIM " machine=" A_OFF
		 A_SIZE "%u" A_OFF, "class",
		 e->elf_class == KGENOME_ELFCLASS_64 ? "ELF64" : "ELF32",
		 e->elf_data == KGENOME_ELFDATA_BE ? "big-endian"
					       : "little-endian",
		 e->e_type, e->e_machine);
	prop_perm(perm, sizeof perm, e->entry_perm);
	prop_off(fo, sizeof fo, ob->ctx.entry_off);
	prop_add(A_DIM "  %-11s " A_LOC "0x%llx" A_OFF A_DIM
		 "  file " A_OFF A_LOC "%s" A_OFF "  " A_ID "%s" A_OFF,
		 "entry", (unsigned long long)e->entry_addr, fo, perm);

	prop_claimed("segments", e->phnum, e->phnum_claimed);
	for (i = 0; i < e->seg_count; i++) {
		const char *w = kof_inspect_ptype_name(e->seg[i].type);
		char num[24];

		if (!w) {
			snprintf(num, sizeof num, "0x%x", e->seg[i].type);
			w = num;
		}
		prop_perm(perm, sizeof perm, e->seg[i].perm);
		prop_add("    " A_ID "%-16s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "0x%-8llx" A_OFF A_DIM " size=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM " vaddr=" A_OFF A_LOC
			 "0x%-10llx" A_OFF A_ID "%s" A_OFF,
			 w, (unsigned long long)e->seg[i].file_off,
			 (unsigned long long)e->seg[i].file_size,
			 (unsigned long long)e->seg[i].mem_addr, perm);
	}
	prop_claimed("sections", e->shnum, e->shnum_claimed);
	for (i = 0; i < e->sec_count; i++) {
		const char *w = kof_inspect_shtype_name(e->sec[i].type);
		char num[24];

		if (!w) {
			snprintf(num, sizeof num, "0x%x", e->sec[i].type);
			w = num;
		}
		prop_add("    " A_ID "%-16s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "0x%-8llx" A_OFF A_DIM " size=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM " %s" A_OFF,
			 e->sec[i].name,
			 (unsigned long long)e->sec[i].file_off,
			 (unsigned long long)e->sec[i].file_size, w);
	}
}

/*
 * WHAT A PDF SAYS ABOUT ITSELF, which is the first thing a reader wants.
 *
 * Six strings from the /Info dictionary: who wrote it, with what, and what it
 * claims to be about. They are the top of the dashboard for the same reason
 * they are the top of a document's own properties dialog - a researcher
 * deciding whether a file is worth an hour reads them before any byte of it.
 *
 * A PRODUCER STRING IS ALSO EVIDENCE, not just provenance. Builders leave
 * theirs in, and one that names a tool which does not lay objects out the way
 * this document does is a disagreement worth seeing beside the anomalies.
 *
 * LOOPED OVER THE ENUM rather than six named lines, so a field added to the
 * parse appears here without this function being touched - the same reason the
 * regions and the anomalies below are drawn from the registry rather than
 * listed. The label comes from the parse too, so the two cannot disagree about
 * what a field is called.
 *
 * Nothing is drawn for a key the document does not carry, which is most of
 * them in most files. A row reading "author -" teaches nothing and pushes the
 * rows that do say something off a short pane.
 */
static void prop_pdf(const struct object *ob)
{
	/*
	 * ob->info IS the view. kof_pdf() takes a CONTEXT and reads
	 * ctx->file_header out of it, so handing it the view made it read some
	 * field of the view as a pointer and follow it - which crashed the
	 * dashboard the first time it was opened on a PDF.
	 *
	 * Nothing caught it at compile time because ob->info is void *, which
	 * converts to any object pointer silently. The other blocks here assign
	 * it directly for the same reason, and this one now matches them.
	 */
	const struct kof_pdf_info *p = ob->info;
	unsigned k;

	/* `valid` as well as non-NULL: a view that a refused parse left zeroed
	 * is a view whose ranges mean nothing, and every field below is a range
	 * this function is about to read with. */
	if (!p || !p->valid)
		return;
	for (k = 0; k < KOF_PDF_DOCINFO_COUNT; k++) {
		char val[96];

		if (!p->docinfo[k].len || !ob->buf.p)
			continue;
		/* Bounded by what the object actually holds: the range came out
		 * of the file, and this is a read. */
		if (p->docinfo[k].off >= ob->buf.n ||
		    p->docinfo[k].len > ob->buf.n - p->docinfo[k].off)
			continue;
		if (!kof_pdf_text(ob->buf.p + p->docinfo[k].off,
				  p->docinfo[k].len, p->docinfo[k].hex,
				  val, sizeof val))
			continue;
		prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
			 kof_pdf_docinfo_name(k), val);
	}
}

static void prop_pe(const struct object *ob)
{
	const struct kgenome_pe_info *p = ob->info;
	char perm[4], fo[24];
	uint32_t i;

	prop_head("PE");
	prop_add(A_DIM "  %-11s " A_ID "%s" A_OFF A_DIM "  machine="
	 A_OFF A_LOC "0x%04x" A_OFF A_DIM " characteristics=" A_OFF A_LOC
	 "0x%04x" A_OFF, "image", p->pe32_plus ? "PE32+" : "PE32", p->machine,
	 p->characteristics);
	/* The CLI header's own extent. What it MEANS - that this is managed
	 * code - is said on the identity block; this is the header fact. */
	if (p->clr_len)
		prop_add(A_DIM "  %-11s off=" A_OFF A_LOC "0x%llx" A_OFF A_DIM
			 "  len=" A_OFF A_SIZE "%llu" A_OFF A_DIM
			 "  entry token=" A_OFF A_LOC "0x%08x" A_OFF,
			 "CLI header", (unsigned long long)p->clr_off,
			 (unsigned long long)p->clr_len, p->clr_entry_token);

	prop_add(A_DIM "  %-11s lfanew=" A_OFF A_LOC "0x%llx" A_OFF A_DIM
		 "  gap=" A_OFF A_SIZE "%llu" A_OFF, "stub",
		 (unsigned long long)p->lfanew,
		 (unsigned long long)p->stub_len);
	prop_add(A_DIM "  %-11s end=" A_OFF A_LOC "0x%llx" A_OFF A_DIM
		 "  declared=" A_OFF A_SIZE "%llu" A_OFF, "headers",
		 (unsigned long long)p->header_end,
		 (unsigned long long)p->size_of_headers);
	prop_perm(perm, sizeof perm, p->entry_perm);
	prop_off(fo, sizeof fo, ob->ctx.entry_off);
	prop_add(A_DIM "  %-11s rva=" A_OFF A_LOC "0x%llx" A_OFF A_DIM
		 "  file " A_OFF A_LOC "%s" A_OFF A_DIM "  sec=" A_OFF A_ID
		 "%s" A_OFF "  " A_ID "%s" A_OFF, "entry",
		 (unsigned long long)p->entry_rva, fo,
		 p->entry_sec < p->sec_count ? p->sec[p->entry_sec].name
					     : "none", perm);
	prop_add(A_DIM "  %-11s code=" A_OFF A_SIZE "%llu" A_OFF A_DIM
		 " init=" A_OFF A_SIZE "%llu" A_OFF A_DIM " uninit=" A_OFF
		 A_SIZE "%llu" A_OFF, "summary",
		 (unsigned long long)p->size_of_code,
		 (unsigned long long)p->size_of_init_data,
		 (unsigned long long)p->size_of_uninit_data);
	/*
	 * Both are worth a line only when they exist, and both matter when
	 * they do: a certificate is what an unsigned copy of a signed program
	 * is missing, and an overlay is where a packer's payload usually is.
	 */
	if (p->cert_len)
		prop_add(A_DIM "  %-11s off=" A_OFF A_LOC "0x%llx" A_OFF
			 A_DIM "  len=" A_OFF A_SIZE "%llu" A_OFF, "signature",
			 (unsigned long long)p->cert_off,
			 (unsigned long long)p->cert_len);
	if (p->overlay_len)
		prop_add(A_WARN "  %-11s" A_OFF A_DIM " off=" A_OFF A_LOC
			 "0x%llx" A_OFF A_DIM "  len=" A_OFF A_WARN "%llu" A_OFF,
			 "overlay", (unsigned long long)p->overlay_off,
			 (unsigned long long)p->overlay_len);
	prop_claimed("sections", p->nsec, p->nsec_claimed);
	for (i = 0; i < p->sec_count; i++) {
		prop_perm(perm, sizeof perm, p->sec[i].perm);
		prop_add("    " A_ID "%-9s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "0x%-8llx" A_OFF A_DIM " raw=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM " rva=" A_OFF A_LOC "0x%-8llx"
			 A_OFF A_DIM " vsz=" A_OFF A_LOC "0x%-8llx" A_OFF A_ID
			 "%s" A_OFF, p->sec[i].name,
			 (unsigned long long)p->sec[i].file_off,
			 (unsigned long long)p->sec[i].file_size,
			 (unsigned long long)p->sec[i].mem_rva,
			 (unsigned long long)p->sec[i].mem_size, perm);
	}
}

/*
 * The chain an object hangs from, above the object itself.
 *
 * A child's name is a path INSIDE its containers - "sample.zip//0:a.rar//1:x" -
 * so the enclosing objects are its own name's prefixes, cut at each "//". That
 * makes the walk a string operation and not a second tree: whatever the tree
 * pane shows, this reads the same names.
 *
 * NUMBERED BY DEPTH, from the file down. The file is 0, what it produced is 1,
 * and so on to the object in focus - the same direction the engine reached them
 * and the same direction the panel is read in. It counted the other way at
 * first, up from the object being looked at, and that put the highest number at
 * the top of the screen: the two blocks read as a chain and their numbers ran
 * against it.
 */
static int obj_by_name(const struct view *v, const char *name, size_t n)
{
	uint32_t i;

	for (i = 0; i < v->n_obj; i++)
		if (strlen(v->obj[i].name) == n &&
		    strncmp(v->obj[i].name, name, n) == 0)
			return (int)i;
	return -1;
}

/* The enclosing objects, outermost first. Returns how many were found. */
uint32_t obj_ancestors(const struct view *v, const struct object *ob,
			      const struct object **out, uint32_t cap)
{
	const char *name = ob->name;
	size_t cut[MAX_OBJ];
	uint32_t n = 0, k, w = 0;
	const char *p;

	/* Every "//" in the name is one container boundary. */
	for (p = strstr(name, "//"); p && n < MAX_OBJ; p = strstr(p + 2, "//"))
		cut[n++] = (size_t)(p - name);

	for (k = 0; k < n && w < cap; k++) {
		int idx = obj_by_name(v, name, cut[k]);

		if (idx >= 0)
			out[w++] = &v->obj[idx];
	}
	return w;
}

/* The page's sink: one finished line becomes one row. */
static void prop_sink(void *user, const char *text)
{
	(void)user;
	prop_add("%s", text);
}

/*
 * WHAT BUILT IT, on the identity block rather than in the format block.
 *
 * "Is this .NET", "was it linked statically", "which compiler" are questions
 * about the SAMPLE, asked in the same breath as its format and architecture -
 * so they belong beside those and not three headings down among the header
 * offsets. The PE and ELF blocks below are the header, and a reader who has
 * scrolled to them is already past the point of asking what the thing is.
 *
 * The rows themselves come from kof_inspect_toolchain, so kofexamine says the
 * same things in the same words. What stays here is the palette, which is this
 * tool's and not the library's.
 */
static void prop_toolchain(const struct object *ob)
{
	static const struct kof_inspect_style style = {
		A_ID, A_LOC, A_WARN, A_OFF
	};

	if (!ob->fmt || !ob->info)
		return;
	kof_inspect_toolchain(&ob->ctx, ob->info, ob->buf, &style,
			      prop_sink, NULL);
	/*
	 * And where its metadata is, when it is managed. Beside the toolchain
	 * rows because the two answer the same reader's next two questions -
	 * what built this, and what is in it - and because a heap offset is
	 * useless without knowing the image is .NET at all.
	 */
	kof_inspect_dotnet(&ob->ctx, ob->info, &style, prop_sink, NULL);
}

static void prop_object_rows(struct view *v, const struct object *ob, int full)
{
	const char *base = kof_path_sep_last(ob->name);
	const char *sub = ob->fmt ? kof_inspect_subtype_name(ob->ctx.format,
							     ob->ctx.subtype)
				  : NULL;
	/* "Raw", capitalised like every name kof_format_name returns - it sits
	 * in the same column as "ELF" and "PE" and was the only lower-case one
	 * there. */
	const char *fmt = ob->fmt ? kof_format_name(ob->ctx.format) : "Raw";
	int top = strstr(ob->name, "//") == NULL;

	/*
	 * What to call it, which differs by where it came from.
	 *
	 * A file is its basename. A CHILD has no basename worth printing: its
	 * name is a path inside a container and the last slash-separated piece
	 * of it is often the bare index - the enclosing block for a UPX payload
	 * read "name 0", which tells a reader nothing at all. The piece after
	 * the last "//" is the entry as the tree pane spells it, index and
	 * label together, so the two panes name the same object the same way.
	 */
	{
		const char *sep = NULL, *q;

		for (q = strstr(ob->name, "//"); q; q = strstr(q + 2, "//"))
			sep = q;
		base = sep ? sep : (base ? base + 1 : ob->name);
	}
	/*
	 * The name, and for a reconstructed payload the VARIABLE it came out of
	 * on the same row.
	 *
	 * Same row rather than a section of its own, which is where it started:
	 * "//Shellcode" leaves most of the line empty, and the symbol is the
	 * one thing a reader of that row wants next - which of the parent's
	 * globals this was. A whole section for one short fact cost three lines
	 * to say what fits beside the name.
	 *
	 * `from` rather than `variable`, because the row already has a label
	 * and the word only has to say how the two halves relate.
	 */
	/*
	 * WHAT IT IS - and for the file itself, WHAT IT IS CALLED.
	 *
	 * A CHILD is spelled by obj_label, the same function the tree pane
	 * uses, so the two panes cannot come to different words for one row.
	 * That was made true of the file as well, and for the file it was
	 * wrong: the row read "ELF-x64" while the two rows under it already
	 * said format ELF and arch x64, and the name was nowhere. The note
	 * that used to stand here claimed the name was "the folder row's other
	 * half" - it is not. The folder row ends at the last separator, so the
	 * basename appeared in no row at all, only inside the copy button.
	 *
	 * So the file gets its basename. In the full view that is the whole
	 * row, because format and arch have rows of their own below. On an
	 * ENCLOSING row (full == 0) it carries the type too: those rows have no
	 * format or arch line, which is what the note beside the size row
	 * below is about.
	 */
	{
		char id[64];

		if (top && ob->ctx.format == KOF_EVT_PROC && ob->info) {
			/*
			 * A PROCESS IS NAMED BY WHAT IT IS RUNNING, and then
			 * by which instance of it.
			 *
			 * "pid:185262" is the object's internal name and says
			 * nothing a reader wants: the interesting half is the
			 * program, and the number only distinguishes one run
			 * of it from another. So the binary leads and the pid
			 * qualifies it, which is the order a person says it in.
			 */
			const struct kof_proc_info *pi = ob->info;
			const char *exe = proc_str(ob, pi->off_exe);

			snprintf(id, sizeof id, "%.36s [pid %lu]",
				 exe[0] ? kof_path_base(exe) : "?",
				 (unsigned long)pi->pid);
		} else if (top) {
			/* `nm` and not `base`: there is a basedir-ish `base`
			 * further out in this function's scope. */
			const char *nm = kof_path_base(ob->name);
			char what[24];

			snprintf(what, sizeof what, "%s%s%s",
				 ob->fmt ? kof_format_name(ob->ctx.format)
					 : "Raw",
				 ob->fmt ? "-" : "",
				 ob->fmt ? kof_arch_name(ob->ctx.arch) : "");
			/* The cut is written into the format rather than left
			 * to the buffer, the way obj_label writes its own: a
			 * file name has no length limit and the row has a
			 * column count, so a reader of the format string can
			 * see where it stops. */
			if (full)
				snprintf(id, sizeof id, "%.60s", nm);
			else
				snprintf(id, sizeof id, "%.36s  %.18s", nm,
					 what);
		} else {
			obj_label(ob, id, sizeof id);
		}
		if (ob->payload_of && ob->payload_sym[0])
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF
				 A_DIM "  from " A_OFF A_ID "%s" A_OFF "%s",
				 "name", id, ob->payload_sym, "");
		else
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "name", id);
	}

	/*
	 * Only the object that came off the disk has a folder.
	 *
	 * The name of a child is a path inside its container, so its directory
	 * is the container's; printing one would suggest the child has a place
	 * of its own on the filesystem. Which object that is is decided from the
	 * NAME rather than from the selection, so an enclosing block gets it
	 * right too - the top of the chain is the file, wherever the reader
	 * happens to be standing.
	 */
	if (top && v->path && v->path[0]) {
		char dir[KOF_DUMP_PATH_ROOM];
		/*
		 * FOR A PROCESS, THE FOLDER IS WHERE THE BINARY LIVES.
		 *
		 * v->path is "pid:185262", which has no separator, so this row
		 * said "./" - a directory that exists and is not the one the
		 * program was started from. The record carries the executable's
		 * full path, and that is the only filesystem location a
		 * process has.
		 */
		const char *from = v->path;
		const char *slash;

		if (ob->ctx.format == KOF_EVT_PROC && ob->info) {
			const char *exe =
				proc_str(ob, ((const struct kof_proc_info *)
					      ob->info)->off_exe);

			if (exe[0])
				from = exe;
		}
		slash = kof_path_sep_last(from);

		/* Ending in a separator, always: a directory row and a name row
		 * sit one above the other in the same column, and without it the
		 * last component reads as another file name. */
		if (!slash) {
			snprintf(dir, sizeof dir, "./");
		} else {
			size_t n = (size_t)(slash - from) + 1u;

			if (n >= sizeof dir)
				n = sizeof dir - 1u;
			memcpy(dir, from, n);
			dir[n] = 0;
		}
		/*
		 * AND A WAY TO TAKE THE WHOLE PATH IN ONE GESTURE.
		 *
		 * The folder and the name are two rows, so copying the thing a
		 * person actually needs - the path to hand to another tool -
		 * meant selecting one row, copying, selecting the other,
		 * copying, and joining them by hand. The button copies
		 * v->path, which is exactly that join.
		 *
		 * Only on this row, which is only drawn for the object that
		 * came off the disk - see the note above. A child's name is a
		 * path inside its container and has no filesystem path to copy,
		 * and in a nested view the row belongs to the outermost parent,
		 * so the button follows the same rule without a second test.
		 */
		prop_add(A_DIM "  %-11s " A_OFF A_LOC "%s" A_OFF
			 "  \033[47;30m%s" A_OFF, "folder", dir,
			 PROP_CP_LABEL);
	}

	/*
	 * Under the folder and above the size, which is where a reader looks
	 * for it: the rows above say WHICH object this is by name and place,
	 * and this says which object it is in the only way that survives being
	 * renamed, moved, or copied off the machine.
	 */
	if (full && ob->sha256[0])
		prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
			 "sha256", ob->sha256);

	if (full) {
		prop_add(A_DIM "  %-11s " A_OFF A_SIZE "%llu" A_OFF
			 A_DIM " bytes" A_OFF, "size",
			 (unsigned long long)ob->buf.n);
		prop_add(A_DIM "  %-11s " A_OFF A_ID "%s%s%s" A_OFF,
			 "format", fmt, sub ? " " : "", sub ? sub : "");
		/*
		 * THE FAMILY FOR A SCRIPT, WHERE THE ARCHITECTURE GOES FOR
		 * everything else.
		 *
		 * Every script is KGENOME_ARCH_ANY, so this row said "any" on all
		 * of them. What a reader of a script needs here is the family,
		 * because kof_module_precond declines a module whose declared
		 * subtypes all sit in another one - and with only the language
		 * on screen, a shell script that reads as a php page looks
		 * identical to one that does not, while only the second runs
		 * shell rules.
		 */
		if (ob->fmt && ob->ctx.format == KOF_FMT_SCRIPT) {
			const char *fa = kof_script_fam_name(ob->ctx.subfamily);

			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "family", fa ? fa : "any");
		} else if (ob->fmt) {
			prop_add(A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "arch", kof_arch_name(ob->ctx.arch));
		}
		prop_toolchain(ob);
	} else {
		/* Bytes and nothing else. The format and the architecture are
		 * on the identity row above, and saying them twice on two
		 * adjacent rows is how a reader learns to skip one of them. */
		prop_add(A_DIM "  %-11s " A_OFF A_SIZE "%llu" A_OFF
			 A_DIM " bytes" A_OFF,
			 "size", (unsigned long long)ob->buf.n);
	}

	/*
	 * The module beside this object, and WHICH RELATION it names.
	 *
	 * On a child it is the module that PRODUCED it - "unpacked by". On the
	 * file itself it is the module that OPENED it - "opened by" - and the
	 * two are not the same statement. It read "unpacked by" for both, which
	 * was merely odd while one block was on screen and is wrong now that the
	 * chain is stacked: the top of the chain came off the disk, and a panel
	 * saying it was unpacked by something invents a layer above the file.
	 */
	/*
	 * AND NOT TWICE FOR ONE EVENT.
	 *
	 * "MPRESS.PE opened this file" and "MPRESS.PE unpacked that child" are
	 * the two ends of ONE edge, and the chain panel stacks them one line
	 * apart. Read together they say MPRESS twice and a reader counts two
	 * layers of it - which is what happened on 111.exe, where there is one
	 * MPRESS layer and one VMProtect layer under it:
	 *
	 *     111.exe      opened by   MPRESS.PE      <- the same edge
	 *     //0          unpacked by MPRESS.PE      <- said again
	 *     //0          unpacked by VMProtect.PE
	 *
	 * So the file's own line is dropped when a child below it already
	 * names that module. It is kept when none does - a module that opens
	 * an object and produces nothing, like Hollow.PE, has no other line to
	 * appear on, and that is the case the row exists for.
	 */
	if (ob->packer[0])
		prop_add(A_DIM "  %-11s " A_OFF "%s%s" A_OFF,
			 top ? "opened by" : "unpacked by",
			 (ob->heur.from_packer ||
			  (ob->heur.heur_flags &
			   KOF_HEUR_FL(KOF_HEUR_F_PACKED))) ? A_BAD : A_WARN,
			 ob->packer);
}

/*
 * The colour a verdict is painted in - the scanner's, so the two tools agree.
 *
 * Ranked through the engine rather than compared as numbers: KOF_LEVEL_HEUR is
 * 2 and INFECT is 1, so ">" on the constants puts them the wrong way round.
 */
static const char *level_attr(uint32_t level)
{
	if (level == KOF_LEVEL_INFECT)
		return A_BAD;
	return level == KOF_LEVEL_HEUR ? A_HEUR : A_WARN;
}

/* The strongest thing anything said about this object, for the summary line. */
static const char *worst_attr(const struct object *ob)
{
	uint32_t i, worst = 0;
	int have = 0;

	for (i = 0; i < ob->n_touch; i++)
		if (ob->touch[i].fired &&
		    (!have || kverdict_level_rank(ob->touch[i].fired_level) >
			      kverdict_level_rank(worst))) {
			worst = ob->touch[i].fired_level;
			have = 1;
		}
	return have ? level_attr(worst) : A_BAD;
}

/*
 * The dashboard for one event: where it came from, and what it says.
 *
 * The field rows are the SAME ones the panel shows, from kof_evt_field, for the
 * reason they were made an API in the first place - a page and a panel that
 * described the same record differently would be two vocabularies for one
 * thing. What the page adds is room: every field, untruncated, and the log's
 * own header above them.
 */

/*
 * The dashboard for one event.
 *
 * The rows are composed by kof_inspect_event, which kofexamine uses too - see
 * the note there on why the LAYOUT is shared and not only the wording. What
 * this function decides is the headings and the palette, which are the two
 * things a page has and a printed line does not.
 */
static void prop_event(struct view *v)
{
	static const struct kof_inspect_style style = {
		A_ID, A_LOC, A_WARN, A_OFF
	};
	const struct kofevt_log_hdr *h;

	if (!v->log)
		return;
	h = kofevt_log_header(v->log);

	prop_head("Event log");
	kof_inspect_event_log(h, v->log_events, v->log_n, &style,
			      prop_sink, NULL);

	/*
	 * THE VERB TABLE BELONGS TO THE LOG'S ROW AND NOWHERE ELSE.
	 *
	 * It was on every event's page, where it answered a question about the
	 * whole file that the page was not about. Here it is the point: this
	 * row IS the file, and what a reader wants first is what kind of trace
	 * they have.
	 *
	 * Two columns, with counts. A mask of which verbs are present says a
	 * lot less than how many of each - "RegSet" and "RegSet 41000" are
	 * different facts, and the second is the one that decides where to
	 * look.
	 */
	/*
	 * THE VERB TABLE BELONGS TO THE LOG'S ROW AND NOWHERE ELSE.
	 *
	 * It was on every event's page, where it answered a question about the
	 * whole file that the page was not about. Here it is the point: this
	 * row IS the file, and what a reader wants first is what kind of trace
	 * they have.
	 *
	 * Composed by kof_inspect_event_verbs, so kofexamine says it the same
	 * way - the palette is this tool's, the layout is not.
	 */
	if (v->node[v->sel_node].obj == 0) {
		prop_head("Events by verb");
		kof_inspect_event_verbs(v->log_count, v->log_keep, &style,
					prop_sink, NULL);
		return;
	}

	if (!evt_have_rec(v))
		return;

	/*
	 * "Record", not "This event" - the page is already about one event, so
	 * the heading only has to name what the rows ARE, which is the fields
	 * of its record.
	 */
	prop_head("Record");
	kof_inspect_event(&v->evt, &style, prop_sink, NULL);

	/*
	 * The whole submission's size, which no field row can report: the
	 * record's own says how much of it THIS record holds, and the rest
	 * arrived in continuations.
	 */
	if (v->evt_text_len)
		prop_add("       " A_ID "%-11s" A_OFF A_SIZE "%llu" A_OFF
			 " characters%s", "gathered",
			 (unsigned long long)v->evt_text_len,
			 v->evt_wide ? " (utf-16)" : "");
}

void prop_build(struct view *v)
{
	struct object *ob = cur_obj(v);

	/*
	 * THE DIGEST, HERE, BECAUSE THIS IS THE ONLY THING THAT PRINTS IT.
	 *
	 * It reads every byte of the object. Worked out when an object was
	 * merely SELECTED, it faulted a spilled view into memory in full to
	 * fill one row of a pane that may be closed - see the note in
	 * object_touch. draw_prop reaches this only when the pane is open, and
	 * the object caches it, so it is still computed once.
	 */
	obj_sha256(ob);
	const char *base = kof_path_sep_last(ob->name);
	uint32_t i, hit = 0;
	uint64_t total = 0;

	g_n_prop = 0;
	base = base ? base + 1 : ob->name;

	/*
	 * THE CHAIN FIRST, THEN THE OBJECT.
	 *
	 * A child on its own is a size and a format with no answer to "where did
	 * this come from" - and that question is most of why anybody opens the
	 * dashboard on a child at all. The enclosing objects are stacked above
	 * it, outermost first, so the panel reads top down the way the engine
	 * reached the bytes: the file, what it held, what that held.
	 *
	 * They are deliberately smaller than the block below them. The object in
	 * focus is what the rest of this page is about; the chain is context,
	 * and context that takes as much room as the subject stops being context.
	 */
	{
		const struct object *up[MAX_OBJ];
		uint32_t n_up = obj_ancestors(v, ob, up, MAX_OBJ), k;

		for (k = 0; k < n_up; k++) {
			char head[32];

			/* k is the depth: 0 is the file, and the count runs the
			 * way the blocks are stacked. */
			snprintf(head, sizeof head, "Enclosing %u", k);
			prop_head(head);
			prop_object_rows(v, up[k], 0);
			/*
			 * THE PROCESS FACTS BELONG TO THE OBJECT THEY ARE
			 * ABOUT, which is the enclosing one - the record.
			 *
			 * Drawn here rather than at the foot of the page: a
			 * reader standing on MEM_HEAP reads down from the
			 * outermost object inwards, and the pid and the
			 * command line are part of what that outermost object
			 * IS. At the bottom they read as an afterthought about
			 * the row in front of them, which is the one thing
			 * they are not.
			 */
			if (up[k]->ctx.format == KOF_EVT_PROC && up[k]->info)
				prop_proc(v, up[k]);
		}
		if (n_up) {
			char head[32];

			/* The chain's last link carries its own number, so the
			 * sequence does not stop one short of the thing it was
			 * counting towards. On a file with nothing above it the
			 * number would be the only one on the page and says
			 * nothing, so it is left off. */
			snprintf(head, sizeof head, "Object %u", n_up);
			prop_head(head);
		} else {
			prop_head("Object");
		}
	}
	prop_object_rows(v, ob, 1);
	/* And when the process record IS the row in front of the reader, the
	 * same panel in the same place - under the object it describes. */
	if (ob->ctx.format == KOF_EVT_PROC && ob->info)
		prop_proc(v, ob);

	/*
	 * AN EVENT'S PAGE IS A DIFFERENT PAGE.
	 *
	 * Everything below - the format block, the regions, the partition check
	 * - is about a parsed file. A record has no parser and no regions, so
	 * that half would be a column of "no parser divides this object" under
	 * a heading that promised otherwise. What a reader wants here is the
	 * log it came from and what the record says.
	 *
	 * NOT for a carried file. A PE that arrived inside a submission is an
	 * executable and gets the ordinary page, headers and regions and all -
	 * see the note in bar_shown about testing the object rather than the
	 * file.
	 */
	/*
	 * A LOG'S OWN ROW GETS THE LOG'S PAGE, not a file's.
	 *
	 * Object 0 is the file - "KOFT-windows-x86_64" - and it was falling
	 * through to the format block, the regions and the partition check,
	 * which described it as raw bytes nobody had parsed. That is true and
	 * it is not what anybody opens a log to read.
	 */
	if (v->log && !v->pe_of[v->node[v->sel_node].obj]) {
		prop_event(v);
		return;
	}

	/*
	 * NOT FOR A NORMALISED VIEW. Its headers describe the file before the
	 * padding came out, so every offset in them is stale wherever something
	 * collapsed ahead of it: read against the view's own bytes the section
	 * table came out as fifteen rows of 15263131283388305642. The view is
	 * declared raw (see KOF_ENT_NORMALIZED); what it is - its regions - is
	 * drawn below, and what its parent said is on the parent's page.
	 */
	if (ob->fmt && ob->info && ob->entry_kind != KOF_ENT_NORMALIZED) {
		if (ob->ctx.format == KOF_FMT_ELF)
			prop_elf(ob);
		else if (ob->ctx.format == KOF_FMT_PE)
			prop_pe(ob);
		else if (ob->ctx.format == KOF_FMT_PDF)
			prop_pdf(ob);
	}



	/*
	 * The regions, which is the engine's own division of the file and the
	 * thing every range in every signature is written against. The share
	 * is there because that is how a packed file announces itself: one
	 * region holding nearly all of it.
	 */
	prop_head("Regions");
	{
		uint32_t n = 0;

		for (i = 0; i < v->n_node; i++)
			if (v->node[i].obj == v->node[v->sel_node].obj &&
			    v->node[i].mask && !v->node[i].sym)
				n++;
		/* No parser claimed the bytes, so nothing divided them. That
		 * is not a file whose regions fail to add up - it is a file
		 * with no regions, and saying MISMATCH there invented a
		 * problem. */
		if (!n) {
			prop_add(A_DIM "  %-11s no parser divides this "
				 "object" A_OFF, "whole");
			goto no_regions;
		}
	}
	/*
	 * The symbol halves are left out of this sum on purpose.
	 *
	 * What follows is a PARTITION CHECK - the regions are extents of the
	 * file and must add up to it - and the halves are built, so their bytes
	 * are not the file's. Counted in, every ELF with symbols would report
	 * MISMATCH about a partition that is perfectly sound.
	 */
	for (i = 0; i < v->n_node; i++)
		if (v->node[i].obj == v->node[v->sel_node].obj &&
		    v->node[i].mask && !v->node[i].sym)
			total += v->node[i].bytes;
	for (i = 0; i < v->n_node; i++) {
		const struct node *n = &v->node[i];

		if (n->obj != v->node[v->sel_node].obj || !n->mask || n->sym)
			continue;
		/*
		 * And how random those bytes are, from kof_inspect_region_entropy
		 * so kofexamine reports the same number the same way. It is the
		 * column that says which row to look at: an UNCLAIMED region at
		 * 7.9 is a file somebody appended, the same region at 0.0 is
		 * alignment, and the size alone does not tell them apart.
		 */
		/*
		 * "H 4.8" MEANT NOTHING TO A READER, and the column is the
		 * whole point of the row. H is the physicist's letter for
		 * entropy and nobody outside that habit reads it; the number
		 * has a unit - bits per byte, 0 to 8 - and printing it bare
		 * left people guessing at the scale as well as the name.
		 */
		prop_add("  " A_ID "%-11s " A_OFF A_SIZE "%-10llu" A_OFF
			 A_LOC "%5.1f%%" A_OFF A_DIM "  %.1f/8 bits" A_OFF,
			 n->label, (unsigned long long)n->bytes,
			 total ? 100.0 * (double)n->bytes / (double)total : 0.0,
			 (double)kof_inspect_region_entropy(&ob->ctx, ob->buf,
							    n->mask) / 8.0);
	}
	/*
	 * THE SUM ONLY MEANS SOMETHING WHERE THE FORMAT CLAIMS TO PARTITION.
	 *
	 * Every file format here divides an object completely - that is what
	 * UNCLAIMED is for - so a total short of the size is a real defect and
	 * is shouted about. A process record does NOT: its head and its
	 * descriptor links are deliberately not scan regions - see
	 * KOF_SCAN_PROC_CLAIMED - because a packed struct of integers is not
	 * something a signature searches. The bytes are still there and still
	 * on this page; they simply are not a region.
	 *
	 * Without this the panel reported MISMATCH on every process, which is
	 * a defect being claimed about a decision.
	 */
	if (total != ob->buf.n && ob->ctx.format != KOF_EVT_PROC)
		prop_add(A_BAD "  %-11s regions sum to %llu of %llu" A_OFF,
			 "MISMATCH", (unsigned long long)total,
			 (unsigned long long)ob->buf.n);
no_regions:

	/*
	 * What the parser thought was wrong with it.
	 *
	 * Said even when there is nothing, because "no anomalies" is a finding
	 * and an absent section reads as a section that was not checked.
	 */
	prop_head("Anomalies");
	/*
	 * A RECONSTRUCTED PAYLOAD SAYS SO HERE, in place of the parser's list.
	 *
	 * DISPLAY ONLY - no anomaly bit is added and the engine's anomaly logic
	 * is untouched. The parser's honest answer for this object is
	 * "SECTAB_MISSING", which is true and useless: it describes the header
	 * this viewer wrote, not anything about the payload. A reader looking
	 * at the row wants to know the object is a reconstruction and what of,
	 * and that is exactly what is not derivable from its bytes.
	 *
	 * Spelled RECONSTRUCTED_<format>-<arch>_SHELLCODE so it cannot be
	 * mistaken for one of the parser's own names, which are all bare
	 * conditions - SEG_PAST_EOF, ENTRY_NOT_EXEC.
	 */
	if (ob->payload_of) {
		prop_add(A_WARN "  RECONSTRUCTED_%s-%s_SHELLCODE" A_OFF,
			 ob->fmt ? kof_format_name(ob->ctx.format) : "RAW",
			 ob->fmt ? kof_arch_name(ob->ctx.arch) : "?");
	} else if (ob->fmt && ob->info && ob->fmt->anomalies) {
		uint64_t anom = ob->fmt->anomalies(ob->info);

		if (!anom)
			prop_add(A_DIM "  none" A_OFF);
		for (i = 0; i < 64; i++) {
			const char *an;

			if (!(anom >> i & 1))
				continue;
			an = ob->fmt->anomaly_name(i);
			if (an)
				prop_add(A_BAD "  %s" A_OFF, an);
			else
				prop_add(A_BAD "  bit%u" A_OFF, i);
		}
	} else {
		prop_add(A_DIM "  no parser claimed these bytes" A_OFF);
	}

	/*
	 * WHAT THE HEURISTIC WOULD SAY, SHOWN BESIDE WHAT THE SIGNATURES SAID.
	 *
	 * Scored here rather than read back from a scan, because the scan the
	 * viewer ran may have had the heuristic switched off - and a page that
	 * showed nothing in that case would be reporting the option rather than
	 * the object. The model is the engine's own, so the number on this page
	 * is the number a scanner would produce.
	 *
	 * The traces are listed under it with their values. A score with no
	 * breakdown is a number to be believed rather than read, and this page
	 * exists to be read.
	 */
	/*
	 * WHO OPENED IT, OR WHAT SAYS SOMETHING SHOULD HAVE.
	 *
	 * Its own section rather than a line under Heuristic, because it is a
	 * different kind of statement: the heuristic scores STRUCTURE and
	 * reports a level, while this says a packer is involved and names the
	 * one thing a reader can do about it. Filing them together put "the
	 * code is hidden" beside "the file is truncated" as though they were
	 * two readings of one measurement.
	 */
	if (ob->packer[0] || emu_why_tag(ob->emu_why)) {
		prop_head("Packer");
		if (ob->packer[0])
			prop_add("  %-11s " A_BAD "%s" A_OFF,
				 "unpacker", ob->packer);
		else
			prop_add("  %-11s %s%s" A_OFF A_DIM "  %s" A_OFF,
				 "verdict",
				 ob->emu_why == KGENOME_EMU_UNP_WHY_DENSE
				 ? A_BAD : A_WARN,
				 emu_why_tag(ob->emu_why),
				 emu_why_reason(ob->emu_why));
		if (!ob->packer[0])
			prop_add(A_DIM "  %-11s Analysis > Examine with "
				 "emulator" A_OFF, "try");
	}

	{
		const struct kof_heur_model *hm = kof_heur_default();
		struct kof_heur_facts hf;
		const char *guess = "Unknown";
		int32_t sc = 0;
		uint32_t k;

		prop_head("Heuristic");
		if (!heur_of(ob, &hf, &sc, &guess)) {
			prop_add(A_DIM "  no model for this format - not scored" A_OFF);
		} else {
			prop_add("  %-11s %s%d" A_OFF A_DIM
				 "  of %d to report" A_OFF, "score",
				 sc >= hm->bar_centinats ? A_HEUR : A_SIZE,
				 sc, hm->bar_centinats);
			/*
			 * The colour goes in the TEXT, not in prop_add's first
			 * argument: that argument is stored on the row and read
			 * by nothing, so this line has been printing in the
			 * default colour for as long as it has existed.
			 */
			if (sc >= hm->bar_centinats)
				prop_add("  %-11s " A_HEUR "%s" A_OFF,
					 "verdict", guess);
			for (k = 0; k < hm->n_anom; k++)
				if (hm->anom[k].format == hf.format &&
				    (hf.anomalies & hm->anom[k].mask))
					prop_add("     %s+%-6d" A_OFF
						 A_DIM " %s" A_OFF, A_WARN,
						 hm->anom[k].centinats,
						 hm->anom[k].guess);
			for (k = 0; k < hm->n_flag; k++)
				if (hf.flags & KOF_HEUR_FL(hm->flag[k].fact))
					prop_add("     %s+%-6d" A_OFF
						 A_DIM " %s" A_OFF, A_WARN,
						 hm->flag[k].centinats,
						 hm->flag[k].guess);
		}
	}

	prop_head("Signatures");
	for (i = 0; i < ob->n_touch; i++)
		hit += (uint32_t)(ob->touch[i].fired != 0);
	/*
	 * "matched" and "skipped", not "fired" and "did not".
	 *
	 * The old pair said what happened to the MODULE; these say what happened
	 * to the object, which is what a reader of this page is asking. "did not"
	 * was worse still - it ended mid-sentence and left the reader to guess
	 * whether the module ran and declined, or never ran at all.
	 */
	prop_add("  %s%u" A_OFF A_DIM " matched, " A_OFF A_SIZE "%u"
		 A_OFF A_DIM " skipped" A_OFF, hit ? worst_attr(ob) : A_SIZE,
		 hit, ob->n_touch - hit);
	for (i = 0; i < ob->n_touch; i++) {
		const struct kof_touch *t = &ob->touch[i];
		char name[80], head[24];

		kof_touch_name(t, name, sizeof name);
		touch_head(t, head, sizeof head);
		prop_add("  %s%-44s" A_OFF A_SIZE "%-10s" A_OFF A_WARN
			 "%s" A_OFF, t->fired ? level_attr(t->fired_level)
					      : A_ID, name, head,
			 t->kind == KOF_TOUCH_INELIGIBLE && t->ruled_out
			 ? t->ruled_out : "");
	}
}
