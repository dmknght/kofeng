/*
 * kofviewer - the engine's view of a file, navigable.
 *
 *   kofviewer [--db <dir>] [--sources <dir>] <file>
 *
 * kofexamine prints everything at once and is right to: piped into grep or
 * diffed against yesterday, a dump is the useful shape. This is the other half
 * of the same job - the same facts, but reachable one at a time, because writing
 * a signature is not reading a report. It is looking at a region, at some bytes
 * inside it, and at what the database already says about them, and moving
 * between the three until the marker is obvious.
 *
 * Both front ends stand on kofinspect, so neither owns a parser and the two
 * cannot drift about what an object is.
 *
 *
 * WHY NO CURSES
 *
 * The panes here are three rectangles of text with a cursor line in one of
 * them. Curses solves problems this does not have - overlapping windows,
 * terminals whose escape sequences are unknown, output that must be diffed
 * against the previous frame because the link is slow - and costs a dependency
 * in a tree whose modules are built -nostdlib and whose platform layer carries
 * its own memmem rather than assume one. A full repaint of a 24 line screen is
 * two kilobytes; there is nothing to optimise and so nothing for a library to
 * do.
 *
 *
 * WHAT IT DOES NOT DO YET
 *
 * Recovered objects are not in the tree. The engine produces them through a scan
 * and the tree here is built from one parse, so putting them in means holding a
 * scan's output as a tree - which is the next thing, not a missing thing.
 * Selection, and turning a selection into a declaration, likewise.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/core/kofplatform.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>

#include "kofinspect.h"
#include "../libkofeng/kofscanners/scan.h"

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
static void term_write_n(const char *s, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t k = write(STDOUT_FILENO, s + off, n - off);

		if (k <= 0)
			return;
		off += (size_t)k;
	}
}

static void term_write(const char *s)
{
	term_write_n(s, strlen(s));
}

static struct termios  g_saved_tty;
static int             g_tty_raw;
static int             g_rows = 24, g_cols = 80;

static void term_restore(void)
{
	if (!g_tty_raw)
		return;
	g_tty_raw = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_tty);
	/* Cursor back, main screen back, in that order: the show has to happen
	 * on the screen that is about to be left, or it applies to the one being
	 * returned to and the user's shell gets it. */
	term_write("\033[?1006l\033[?1002l\033[?1000l\033[?25h\033[?1049l");
}

static void on_signal(int sig)
{
	term_restore();
	/* Re-raise with the default handler so the exit status says what
	 * happened. Exiting 0 here would tell a script the run succeeded. */
	signal(sig, SIG_DFL);
	raise(sig);
}

static int term_setup(void)
{
	struct termios raw;

	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		fprintf(stderr, "kofviewer: needs a terminal\n");
		return 0;
	}
	if (tcgetattr(STDIN_FILENO, &g_saved_tty) != 0)
		return 0;
	raw = g_saved_tty;
	/* No echo, no line discipline, no signals from keys, and a read that
	 * returns as soon as one byte is there. */
	raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN | ISIG);
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	raw.c_oflag &= (tcflag_t)~OPOST;
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;

	atexit(term_restore);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGSEGV, on_signal);

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
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
	term_write("\033[?1049h\033[?25l\033[?1000h\033[?1002h\033[?1006h");
	return 1;
}

static void term_size(void)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row && ws.ws_col) {
		g_rows = ws.ws_row;
		g_cols = ws.ws_col;
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
struct out {
	char  *p;
	size_t n, cap;
	/* Printable columns emitted since the last row_start, so a caller
	 * laying out a line can record where its pieces landed. Escapes do not
	 * count; nothing here needs more than that. */
	size_t col_hint;
};

static void out_add(struct out *o, const char *s, size_t n)
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

static void out_str(struct out *o, const char *s)
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

static void out_fmt(struct out *o, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void out_fmt(struct out *o, const char *fmt, ...)
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

static void out_at(struct out *o, int row, int col)
{
	out_fmt(o, "\033[%d;%dH", row, col);
}

#define A_OFF   "\033[0m"
#define A_BOLD  "\033[1m"
#define A_DIM   "\033[90m"
#define A_ID    "\033[34m"
#define A_LOC   "\033[36m"
#define A_SIZE  "\033[32m"
#define A_BAD   "\033[31m"
#define A_WARN  "\033[33m"
#define A_SEL   "\033[7m"

/*
 * Byte classes, the way a modern hex dumper colours them.
 *
 * Not decoration: it is the first thing a reader wants from a dump and the thing
 * the eye is worst at. A run of zeroes, a run of text and a run of high bytes
 * look identical in two-digit hex and completely different in colour, and
 * telling padding from data from a compressed block is most of what scrolling a
 * file is for.
 */
#define A_B_NUL   "\033[90m"      /* 00 - padding, almost always */
#define A_B_TEXT  "\033[32m"      /* printable ASCII */
#define A_B_WS    "\033[36m"      /* space, tab, newline */
#define A_B_CTRL  "\033[35m"      /* the rest of ASCII */
#define A_B_HIGH  "\033[33m"      /* >= 0x80 */

static const char *byte_colour(uint8_t c)
{
	if (c == 0x00)                  return A_B_NUL;
	if (c >= 0x80)                  return A_B_HIGH;
	if (c == 0x09 || c == 0x0a || c == 0x0d || c == 0x20)
					return A_B_WS;
	if (c < 0x20 || c == 0x7f)      return A_B_CTRL;
	return A_B_TEXT;
}
/*
 * A marker is lit with a BACKGROUND, not with reverse video.
 *
 * Reverse swaps foreground and background, which throws away the byte class
 * colour underneath - a highlighted run would lose the one thing the rest of the
 * pane uses to tell zeroes from text. A background keeps both: the class stays
 * the ink, the match becomes the block of colour.
 */
#define A_SELB  "\033[44;97m"   /* the drag selection */
#define A_HIT1  "\033[41;97m"   /* counted by the module */
#define A_HIT2  "\033[43;30m"   /* present, but outside its regions */

#define TREE_W   30

/*
 * Four fixed rows and everything else is the panes.
 *
 * The markers list used to own nine rows and usually put one line in them. It is
 * a summary now - one line, above the status - and the list it summarises opens
 * over the screen when it is asked for. Space spent on a pane that is empty most
 * of the time is space the hex view could have had, and the hex view is what the
 * tool is for.
 */
/*
 * No title row.
 *
 * It held the full path, which is the one fact about an open file that does not
 * change and does not fit - a sha256 filename with a directory in front of it
 * fills a line and says nothing after the first second. What belongs there is a
 * menu bar, and until there is one the row is better spent on the panes.
 */
static int hex_top(void)  { return 1; }
static int hex_bot(void)  { return g_rows - 2; }
static int mark_row(void) { return g_rows; }

/* ---- the objects under view ------------------------------------------------
 *
 * A file is not one object. A packed executable is itself and the image inside
 * it; an archive is itself and everything it holds; and a signature is written
 * against exactly one of them, so all of them have to be reachable.
 *
 * They come from a scan, because producing them is what unpack modules do and
 * the engine is the only thing that runs a module. Their bytes live only for the
 * length of the callback, so they are copied - a viewer holds what it shows.
 * That is bounded by the same budgets a scan is bounded by, which is why they
 * are the engine's to set and not this tool's to raise.
 */
#define MAX_OBJ  128
#define MAX_TREE 512

struct object {
	char      name[256];
	uint8_t  *own;              /* the copy, NULL for the mapped top level */
	kof_buf   buf;
	uint32_t  depth;            /* how many "//" its name carries */

	const struct kof_inspect_fmt *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	char            **finding;
	uint32_t          n_finding;
	char              packer[48];   /* the module that opened or unpacked it */
	struct kof_touch *touch;
	uint32_t          n_touch;
};

/*
 * A row in the left pane.
 *
 * Objects and regions in one list rather than two trees: they are drawn as one
 * column, moved through with one cursor, and the only thing that differs is what
 * selecting one means. `depth` is what makes it a tree on screen - a region is
 * always one level inside the object that has it.
 */
struct node {
	char     label[48];
	uint32_t depth;
	uint32_t obj;               /* which object this row belongs to */
	uint32_t mask;              /* the region, or 0 when the row IS the object */
	uint64_t bytes;

	/*
	 * Where this row was last being looked at.
	 *
	 * Per row rather than one cursor for the pane, because moving between
	 * regions is how the tool is used - find something in CODE, check
	 * whether DATA has its twin, come back - and coming back to the top of
	 * a forty kilobyte region means finding the place again by hand every
	 * time. The offset is the reader's place in that region, so it belongs
	 * to the region.
	 */
	uint64_t at;
};

struct view {
	const char *path;
	void       *map;
	uint64_t    map_len;

	struct object obj[MAX_OBJ];
	uint32_t      n_obj;

	char        pending[48];    /* the unpacker that has just spoken */

	struct node node[MAX_TREE];
	uint32_t    n_node, sel_node, tree_top;

	struct kof_range *ext;
	uint32_t          n_ext;
	uint64_t          rgn_len, rgn_at;

	/*
	 * A selection of BYTES, not of screen text.
	 *
	 * Held as offsets into the region, which is what dissolves both problems
	 * a character selection has: there is no offset column and no ASCII
	 * column in this model, only bytes, so clicking either one names the
	 * same byte and neither can be dragged into the selection by accident.
	 * A press outside the hex pane is not a hex selection at all, so the
	 * tree and the markers line cannot be dragged into it either.
	 *
	 * KOF_BROKEN for "nothing selected", which is distinct from a selection
	 * of length zero.
	 */
	uint64_t    sel_a, sel_b;
	int         dragging;
	int         dragged;        /* the pointer moved off the pressed byte */

	uint32_t    sel_touch, list_off;
	int         show_list;
	/* 0: the signatures. 1: the markers of the selected one. Two depths of
	 * one dialog rather than two dialogs, because the second is only ever
	 * reached from a row of the first. */
	int         list_depth;
	uint32_t    str_off, sel_str;

	/*
	 * Which signatures the dialog is showing: all of them, the ones that
	 * fired, or the ones that did not. The status line says "hit 3 skip 5"
	 * and both numbers are clickable, so the filter is the answer to which
	 * of them was clicked.
	 */
	int         list_filter;    /* 0 all, 1 fired, 2 skipped */

	/* Where the clickable words ended up on the status line. Recorded while
	 * drawing rather than computed twice: the line is built from variable
	 * length pieces and a second copy of that arithmetic would be a second
	 * thing to keep right. */
	int         hit_c0, hit_c1, skip_c0, skip_c1, name_c0, name_c1;

	int         menu_open, menu_row, menu_col, menu_sel;

	/*
	 * How far each list is scrolled sideways.
	 *
	 * A deep tree spends its width on indentation and a signature name is
	 * as long as its author made it, so on a narrow terminal both get cut
	 * before they get useful. Vertical scrolling does not help with that -
	 * the row is there, it is the row that is too wide - so the panes that
	 * hold text keep a horizontal offset too. The hex pane has none by
	 * design: it reflows, fitting fewer bytes per row rather than running
	 * off the edge.
	 */
	uint32_t    tree_hoff, list_hoff;
	int         pane;           /* 0 tree, 1 hex, 2 markers */
	int         per;            /* bytes a hex row shows, for click mapping */
};

static struct object *cur_obj(struct view *v)
{
	return &v->obj[v->node[v->sel_node].obj];
}

/* ---- collecting the objects ------------------------------------------------ */

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct view *v = user;
	struct object *o;
	const char *p;
	uint32_t i;

	if (v->n_obj >= MAX_OBJ || !len)
		return 0;
	o = &v->obj[v->n_obj];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name);
	if (v->pending[0]) {
		snprintf(o->packer, sizeof o->packer, "%s", v->pending);
		v->pending[0] = 0;
	}
	for (p = name; (p = strstr(p, "//")) != NULL; p += 2)
		o->depth++;

	/* The top level is already mapped; anything else exists only inside this
	 * call and has to be kept if it is to be looked at. */
	if (o->depth == 0 && v->map && len == v->map_len) {
		o->buf = kof_buf_make(v->map, len);
	} else {
		o->own = malloc((size_t)len);
		if (!o->own)
			return 0;
		memcpy(o->own, bytes, (size_t)len);
		o->buf = kof_buf_make(o->own, len);
	}

	for (i = 0; i < res->n; i++) {
		char **g = realloc(o->finding, (o->n_finding + 1) * sizeof *g);

		if (!g)
			break;
		o->finding = g;
		o->finding[o->n_finding] = strdup(res->v[i].name);
		if (!o->finding[o->n_finding])
			break;
		o->n_finding++;
	}
	v->n_obj++;
	return 0;
}

/*
 * Which module is doing the unpacking, learnt from the module itself.
 *
 * The engine does not name the producer on the callback, but an unpack module
 * reports its own name through kof_debug - "UPX.ELF.method 14".
 *
 * It arrives BEFORE any object does, which was worth measuring rather than
 * assuming: the engine opens an object completely and reports it afterwards, so
 * the first thing a run of a packed file emits is the unpacker talking about
 * work in progress. The note is therefore held and given to the next object
 * announced - which is the one that was being opened, the packed one. That is
 * the object somebody is looking at when the question occurs to them.
 */
static void on_debug(const char *what, uint64_t value, void *user)
{
	struct view *v = user;
	const char *dot = strrchr(what, '.');
	size_t n = dot ? (size_t)(dot - what) : strlen(what);

	(void)value;
	if (n >= sizeof v->pending)
		n = sizeof v->pending - 1u;
	memcpy(v->pending, what, n);
	v->pending[n] = 0;
}

static void objects_collect(struct view *v, kof_engine *eng)
{
	struct kof_scan_option opt;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	sc = kof_scanner_new(eng);
	if (!sc)
		return;
	kof_scanner_on_debug(sc, on_debug, v);
	kof_scan_path(sc, v->path, &opt, on_object, v);
	kof_scanner_free(sc);
}

/* Parse each object and ask the database about it. Done after the scan rather
 * than inside it: the callback runs while the engine holds the object, and
 * driving the matcher over the same engine from in there is a re-entry nobody
 * has designed for. */
static void objects_examine(struct view *v, kof_engine *eng)
{
	uint32_t i;

	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		o->fmt = kof_inspect_identify(o->buf, &o->ctx, &o->info);
		if (!o->fmt)
			o->ctx.obj_size = o->buf.n;
		if (eng &&
		    !kof_touch_object(eng, o->buf, &o->ctx,
				      (const char *const *)o->finding,
				      o->n_finding, &o->touch, &o->n_touch))
			o->n_touch = 0;
	}
}

/* ---- the tree -------------------------------------------------------------- */

static void tree_add(struct view *v, uint32_t depth, uint32_t obj,
		     uint32_t mask, uint64_t bytes, const char *label)
{
	struct node *n;

	if (v->n_node >= MAX_TREE)
		return;
	n = &v->node[v->n_node++];
	n->depth = depth;
	n->obj = obj;
	n->mask = mask;
	n->bytes = bytes;
	snprintf(n->label, sizeof n->label, "%s", label);
}

static void tree_build(struct view *v)
{
	uint32_t i, k;

	v->n_node = 0;
	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];
		const char *tail = strrchr(o->name, '/');
		char label[48], what[24];

		/*
		 * What the object IS, not what it is called.
		 *
		 * The path is on the title line already, and a sha256 filename
		 * repeated in a nineteen column field says nothing. "ELF x64"
		 * does: a signature targets a format and an architecture, so
		 * those are the two facts a row in this tree exists to carry.
		 */
		/*
		 * "ELF-a32", not "ELF a32".
		 *
		 * The row is space separated fields, so a field that contains a
		 * space reads as two - "//0 ELF a32" looks like three columns
		 * and is two. The hyphen is also what the engine itself uses
		 * when it composes a finding name, so the two spell the same
		 * object the same way.
		 */
		snprintf(what, sizeof what, "%s%s%s",
			 o->fmt ? kof_format_name(o->ctx.format) : "raw",
			 o->fmt ? "-" : "",
			 o->fmt ? kof_arch_name(o->ctx.arch) : "");
		if (o->depth == 0)
			snprintf(label, sizeof label, "%s", what);
		else
			snprintf(label, sizeof label, "//%s %s",
				 tail ? tail + 1 : o->name, what);
		tree_add(v, o->depth * 2u, i, 0, o->buf.n, label);

		if (!o->fmt || !v->ext)
			continue;
		for (k = 0; k < o->fmt->n_regions; k++) {
			const char *rn = o->fmt->region_name(o->fmt->regions[k]);
			uint32_t j, n;
			uint64_t total = 0;

			if (!rn)
				continue;
			n = kof_scan_resolve_range(&o->ctx, o->fmt->regions[k],
						   v->ext);
			for (j = 0; j < n; j++)
				total += v->ext[j].len;
			if (!total)
				continue;
			{
				const char *s = strrchr(rn, '_');

				tree_add(v, o->depth * 2u + 1u, i,
					 o->fmt->regions[k], total,
					 s ? s + 1 : rn);
			}
		}
	}
}

/*
 * The furthest the hex pane may be scrolled.
 *
 * Not rgn_len. Clamping the TOP of the view to the end of the data lets the pane
 * scroll until every row is past the end and the screen is blank - which it did,
 * and which is worse than not scrolling at all: an empty pane reads as a region
 * with nothing in it rather than as a cursor parked past the last byte.
 *
 * The limit is the position that puts the LAST row of data on the bottom row of
 * the pane. A region that fits entirely gets a limit of zero and does not scroll
 * at all - a ten row header has nothing below it to scroll to.
 */
static uint64_t hex_max(const struct view *v)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t rows = (uint64_t)(hex_bot() - hex_top() + 1);
	uint64_t last, top;

	if (!v->rgn_len)
		return 0;
	last = (v->rgn_len - 1u) / per * per;      /* where the last row starts */
	if (!rows)
		return last;
	top = (rows - 1u) * per;
	return last > top ? last - top : 0;
}

/* Resolve whichever region the cursor is on, and put the hex pane back where it
 * was the last time this row was looked at. */
static void view_select(struct view *v)
{
	struct object *o = cur_obj(v);
	uint32_t i;

	v->n_ext = 0;
	v->rgn_len = 0;
	if (!v->ext)
		return;
	v->n_ext = kof_scan_resolve_range(&o->ctx,
					  v->node[v->sel_node].mask ?
					  v->node[v->sel_node].mask :
					  KOF_SCAN_ALL, v->ext);
	if (!v->n_ext && o->buf.n) {
		v->ext[0].off = 0;
		v->ext[0].len = o->buf.n;
		v->n_ext = 1;
	}
	for (i = 0; i < v->n_ext; i++)
		v->rgn_len += v->ext[i].len;

	/* A remembered place is re-clamped rather than trusted: the pane may be
	 * a different height than it was when the row was left. */
	v->rgn_at = v->node[v->sel_node].at;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

/*
 * Move the tree cursor, keeping each row's place.
 *
 * The row being left keeps where it was; the row being arrived at gets its own
 * back. A byte selection does not survive the move - it is an offset into the
 * region that was showing, and the same number means somewhere else in the next
 * one - and the module the markers line is on only resets when the OBJECT
 * changes, because it is a property of the object and not of the region.
 */
static void goto_node(struct view *v, uint32_t k)
{
	uint32_t was;

	if (k >= v->n_node || k == v->sel_node)
		return;
	was = v->node[v->sel_node].obj;
	v->node[v->sel_node].at = v->rgn_at;
	v->sel_node = k;
	v->sel_a = v->sel_b = KOF_BROKEN;
	v->dragging = 0;
	if (v->node[k].obj != was)
		v->sel_touch = 0;
	view_select(v);
}

/* The file offset of byte `at` of the selected region, and how much of that
 * extent is left. Regions are not contiguous, so a pane that walked the file
 * would show bytes the region does not contain. */
static uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run)
{
	uint32_t i;

	for (i = 0; i < v->n_ext; i++) {
		if (at < v->ext[i].len) {
			if (run)
				*run = v->ext[i].len - at;
			return v->ext[i].off + at;
		}
		at -= v->ext[i].len;
	}
	if (run)
		*run = 0;
	return 0;
}

/* The inverse of view_map: where in the region a file offset sits, or KOF_BROKEN
 * when the region does not contain it. Needed because the markers speak file
 * offsets and the hex cursor is an offset into the region. */
static uint64_t view_unmap(const struct view *v, uint64_t off)
{
	uint64_t base = 0;
	uint32_t i;

	for (i = 0; i < v->n_ext; i++) {
		if (off >= v->ext[i].off && off < v->ext[i].off + v->ext[i].len)
			return base + (off - v->ext[i].off);
		base += v->ext[i].len;
	}
	return KOF_BROKEN;
}

/* ---- panes ---------------------------------------------------------------- */


/* Erase to end of line rather than clearing the screen.
 *
 * A full clear followed by a full repaint is one write and so cannot tear, but
 * it does make the terminal blank and refill every frame, which on a real
 * terminal is a visible flash at every keystroke. Erasing each line as it is
 * rewritten never leaves the screen empty. */
static void row_start(struct out *o, int row, int col)
{
	out_at(o, row, col);
	out_str(o, "\033[K");
	o->col_hint = 0;
}

static void draw_frame(struct out *o, struct view *v)
{
	int i;

	(void)v;

	for (i = hex_top(); i <= hex_bot(); i++) {
		out_at(o, i, TREE_W + 1);
		out_str(o, A_DIM "|" A_OFF);
	}
	row_start(o, hex_bot() + 1, 1);
	out_str(o, A_DIM);
	for (i = 0; i < g_cols; i++)
		out_str(o, "-");
	out_str(o, A_OFF);
}

static void draw_tree(struct out *o, struct view *v)
{
	int top = hex_top(), bot = hex_bot();
	int rows = bot - top + 1;
	uint32_t i;

	if (v->sel_node < v->tree_top)
		v->tree_top = v->sel_node;
	if (rows > 0 && v->sel_node >= v->tree_top + (uint32_t)rows)
		v->tree_top = v->sel_node - (uint32_t)rows + 1;

	for (i = 0; (int)i < rows; i++) {
		uint32_t k = v->tree_top + i;
		const struct node *n;
		int sel;

		row_start(o, top + (int)i, 1);
		if (k >= v->n_node)
			continue;
		n = &v->node[k];
		sel = k == v->sel_node;

		/* Indent and label as one string, so scrolling sideways moves
		 * the whole row and not the label out from under its own
		 * indentation. */
		{
			char row[96];
			size_t off;

			snprintf(row, sizeof row, "%*s%s", (int)n->depth, "",
				 n->label);
			off = v->tree_hoff < strlen(row) ? v->tree_hoff
							 : strlen(row);
			if (sel)
				out_str(o, v->pane == 0 ? A_SEL : A_BOLD);
			else
				/* An object row can hold a signature; a region
				 * row is a place inside one. Different colours
				 * because they are different kinds of answer,
				 * not different rows of one kind. */
				out_str(o, n->mask ? A_ID : A_BOLD);
			/* Truncated, not merely padded: a label wider than its
			 * column runs into the pane beside it, and the first
			 * file anyone opens has a sha256 for a name. */
			out_fmt(o, "%-19.19s", row + off);
		}
		if (!sel)
			out_str(o, A_OFF A_SIZE);
		out_fmt(o, "%9llu", (unsigned long long)n->bytes);
		out_str(o, A_OFF);
	}
}

/*
 * Is this file offset inside a marker of the module the markers line is on?
 *
 * The whole reason the two panes are on one screen. A row saying "three of six"
 * is a number; the same three lit up in the bytes is where they are, what is
 * around them, and whether the fourth is nearly there - which is the question
 * somebody writing a variant is actually asking.
 *
 * Returns 0 for no, 1 for a marker the module would have counted, 2 for one
 * that is present but outside the regions it searches. The second is not a
 * lesser version of the first: it is the interesting one.
 */
/* Is this region offset inside the current selection. */
static int in_sel(const struct view *v, uint64_t at)
{
	uint64_t lo, hi;

	if (v->sel_a == KOF_BROKEN)
		return 0;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	return at >= lo && at <= hi;
}

/*
 * Which signature has a marker covering this file offset.
 *
 * Any of them, not just the one being lit: the point is to be able to click a
 * highlighted run and find out whose it is. In-region markers win over
 * elsewhere ones when two overlap, because that is the one that counts for its
 * owner. -1 for none.
 */
static int hit_owner(struct view *v, uint64_t off)
{
	struct object *ob = cur_obj(v);
	int best = -1;
	uint32_t i, j;

	for (i = 0; i < ob->n_touch; i++) {
		const struct kof_touch *t = &ob->touch[i];

		for (j = 0; j < t->n_str; j++) {
			const struct kof_touch_str *st = &t->str[j];

			if (st->at == KOF_BROKEN)
				continue;
			if (off < st->at || off >= st->at + st->len)
				continue;
			if (st->in_rgn)
				return (int)i;
			if (best < 0)
				best = (int)i;
		}
	}
	return best;
}

static int hit_kind(struct view *v, uint64_t off)
{
	struct object *ob = cur_obj(v);
	const struct kof_touch *t;
	uint32_t j;

	if (v->sel_touch >= ob->n_touch)
		return 0;
	t = &ob->touch[v->sel_touch];
	for (j = 0; j < t->n_str; j++) {
		const struct kof_touch_str *st = &t->str[j];

		if (st->at == KOF_BROKEN)
			continue;
		if (off >= st->at && off < st->at + st->len)
			return st->in_rgn ? 1 : 2;
	}
	return 0;
}

static void draw_hex(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	int top = hex_top(), bot = hex_bot();
	int col = TREE_W + 3;
	int per = (g_cols - col - 12) / 4;
	int row;
	uint64_t at = v->rgn_at;

	if (per > 16)
		per = 16;
	if (per < 4)
		per = 4;
	v->per = per;

	for (row = top; row <= bot; row++) {
		uint64_t run = 0, off = view_map(v, at, &run);
		int k;

		out_at(o, row, col);
		out_str(o, "\033[K");
		if (at >= v->rgn_len)
			continue;
		out_fmt(o, A_LOC "%08llx" A_OFF "  ", (unsigned long long)off);
		for (k = 0; k < per; k++) {
			if (at + (uint64_t)k >= v->rgn_len) {
				out_str(o, "   ");
				continue;
			}
			/* A run ending mid line is an extent boundary, marked
			 * because a marker written across one can never match:
			 * the matcher walks each extent on its own. */
			if ((uint64_t)k == run && k)
				out_str(o, A_WARN "|" A_OFF);
			else
				out_str(o, " ");
			{
				uint64_t fo = view_map(v, at + (uint64_t)k, 0);
				uint8_t bv = ob->buf.p[fo];
				int h = hit_kind(v, fo);

				out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
					h ? (h == 1 ? A_HIT1 : A_HIT2)
					  : byte_colour(bv));
				out_fmt(o, "%02X", bv);
				out_str(o, A_OFF);
			}
		}
		out_str(o, "  ");
		for (k = 0; k < per && at + (uint64_t)k < v->rgn_len; k++) {
			uint64_t fo = view_map(v, at + (uint64_t)k, 0);
			uint8_t c = ob->buf.p[fo];
			int h = hit_kind(v, fo);

			out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
				h ? (h == 1 ? A_HIT1 : A_HIT2)
				  : byte_colour(c));
			out_fmt(o, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
			out_str(o, A_OFF);
		}
		at += (uint64_t)per;
	}
}

/* The composed name a scan would print for this module, less the target. */
static void touch_name(const struct kof_touch *t, char *out, size_t cap)
{
	const char *var = t->fired_name ? t->fired_name :
			  (t->n_names && t->name[0] ? t->name[0] : NULL);

	snprintf(out, cap, "%s:%s%s%s", kof_maltype_name(t->maltype),
		 t->family[0] ? t->family : "?", var ? "-" : "", var ? var : "");
}

static const char *touch_colour(const struct kof_touch *t)
{
	return t->fired                        ? A_BAD :
	       t->kind == KOF_TOUCH_ELSEWHERE  ? A_LOC :
	       t->kind == KOF_TOUCH_INELIGIBLE ? A_DIM : A_WARN;
}

static void touch_head(const struct kof_touch *t, char *out, size_t cap)
{
	if (!t->n_str)
		snprintf(out, cap, "structural");
	else
		snprintf(out, cap, "%u/%u",
			 t->kind == KOF_TOUCH_INELIGIBLE ? t->n_present
							 : t->n_in_rgn,
			 t->n_str);
}

/*
 * One line: how many modules this object touched, and which one the hex pane is
 * lighting up. The rest is one keypress or one click away.
 */
static void draw_marker_line(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	char name[80], head[24];
	uint32_t hit = 0, i;

	row_start(o, mark_row(), 1);

	/* Which pane has the keys. Not a hotkey - a hotkey list is a reminder of
	 * what could be pressed, this says what pressing would do next, and that
	 * changes. */
	out_fmt(o, A_SEL " %-8s " A_OFF " ",
		v->pane == 0 ? "obj tree" : v->pane == 1 ? "hex" : "marker");

	/*
	 * A selection displaces everything else on this line.
	 *
	 * While bytes are selected they are what the next action is about, and
	 * the length and the first of them are what says whether the right ones
	 * were caught. The markers are one keystroke away and are not going
	 * anywhere.
	 */
	if (v->sel_a != KOF_BROKEN) {
		struct object *so = cur_obj(v);
		uint64_t lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		uint64_t hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
		uint64_t k, n = hi - lo + 1u;

		out_fmt(o, A_SELB " %llu byte(s) at %08llx " A_OFF "  ",
			(unsigned long long)n,
			(unsigned long long)view_map(v, lo, 0));
		for (k = 0; k < n && k < 16; k++)
			out_fmt(o, "%02X",
				so->buf.p[view_map(v, lo + k, 0)]);
		if (n > 16)
			out_str(o, "...");
		out_fmt(o, A_DIM "   right-click clears" A_OFF);
		return;
	}

	/* What packed it, when something did. First on the line because it is a
	 * property of the object rather than any module's opinion of it, and
	 * because a signature written here only ever runs while that unpacker
	 * still claims the sample. */
	if (ob->packer[0])
		out_fmt(o, A_BAD "%s" A_OFF A_DIM "  |  " A_OFF, ob->packer);

	if (!ob->n_touch) {
		out_str(o, A_DIM "no markers" A_OFF);
		return;
	}
	for (i = 0; i < ob->n_touch; i++)
		hit += (uint32_t)(ob->touch[i].fired != 0);

	touch_name(&ob->touch[v->sel_touch], name, sizeof name);
	touch_head(&ob->touch[v->sel_touch], head, sizeof head);

	/* Three clickable words, and their columns recorded as they are laid
	 * out. "hit" and "skip" open the dialog filtered to what they count;
	 * the name opens that signature's markers directly. */
	{
		char hits[24], skips[24];
		int c = 1;

		c += (int)o->col_hint;              /* whatever preceded us */
		snprintf(hits, sizeof hits, "hit %u", hit);
		snprintf(skips, sizeof skips, "skip %u", ob->n_touch - hit);

		v->hit_c0 = c;
		v->hit_c1 = c + (int)strlen(hits) - 1;
		c += (int)strlen(hits) + 2;
		v->skip_c0 = c;
		v->skip_c1 = c + (int)strlen(skips) - 1;
		c += (int)strlen(skips) + 5;
		v->name_c0 = c;
		v->name_c1 = c + (int)strlen(name) - 1;

		out_fmt(o, "%s%s" A_OFF A_DIM "  %s  |  " A_OFF "%s%s %s" A_OFF,
			hit ? A_BAD : A_DIM, hits, skips,
			touch_colour(&ob->touch[v->sel_touch]), name, head);
	}
}


/*
 * The list, over the screen rather than beside it.
 *
 * Beside it costs its height on every object including the many that touch
 * nothing; over it costs nothing until it is asked for. Clicking a row is what
 * changes which signature the hex pane lights up, so the list is also the
 * control and not only the display.
 *
 * Four rows and it scrolls. A dialog that grows with its contents covers the
 * pane it is explaining as soon as the contents get interesting, and at database
 * scale they will. Four is enough to compare the top of a ranked list against
 * itself, which is what it is for.
 */
#define LIST_ROWS 4u

/* Does this signature belong in the dialog as it is filtered right now. */
static int list_keep(struct view *v, const struct kof_touch *t)
{
	if (v->list_filter == 1)
		return t->fired != 0;
	if (v->list_filter == 2)
		return t->fired == 0;
	return 1;
}

/* The i-th signature under the filter, or n_touch when there is no such row. */
static uint32_t list_nth(struct view *v, uint32_t i)
{
	struct object *ob = cur_obj(v);
	uint32_t k, seen = 0;

	for (k = 0; k < ob->n_touch; k++) {
		if (!list_keep(v, &ob->touch[k]))
			continue;
		if (seen++ == i)
			return k;
	}
	return ob->n_touch;
}

static uint32_t list_total(struct view *v)
{
	struct object *ob = cur_obj(v);
	uint32_t k, n = 0;

	if (v->list_depth)
		return v->sel_touch < ob->n_touch
		       ? ob->touch[v->sel_touch].n_str : 0;
	for (k = 0; k < ob->n_touch; k++)
		n += (uint32_t)list_keep(v, &ob->touch[k]);
	return n;
}

static uint32_t list_shown(struct view *v)
{
	uint32_t n = list_total(v);

	return n < LIST_ROWS ? n : LIST_ROWS;
}

/* The header row; the entries follow it, and the last one sits directly on the
 * bottom line - there is no spare row between them. */
static int list_top(struct view *v)
{
	return g_rows - 2 - (int)list_shown(v);
}

/* Keep the cursor inside the window rather than the window on the cursor: a list
 * that jumps when it opens has lost the place it was opened to show. */
static void list_scroll(struct view *v)
{
	uint32_t shown = list_shown(v), n = list_total(v);

	if (!shown)
		return;
	if (v->list_depth) {
		if (v->str_off + shown > n)
			v->str_off = n - shown;
		return;
	}
	if (v->sel_touch < v->list_off)
		v->list_off = v->sel_touch;
	if (v->sel_touch >= v->list_off + shown)
		v->list_off = v->sel_touch - shown + 1u;
	if (v->list_off + shown > n)
		v->list_off = n - shown;
}

/*
 * The selected row keeps its own colour.
 *
 * It used to be drawn in reverse video, which paints it white and takes the
 * colour with it - so selecting a row was also hiding the one thing the row was
 * colour-coded to say. A caret marks the selection instead and the colour
 * survives, which matters most on exactly the row being looked at.
 */
static void list_row(struct out *o, int sel, const char *colour)
{
	out_str(o, colour);
	if (sel)
		out_str(o, "\033[1m");
	out_str(o, sel ? ">" : " ");
}

static void draw_list(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	const struct kof_touch *t = v->sel_touch < ob->n_touch
				   ? &ob->touch[v->sel_touch] : NULL;
	int top, w = g_cols - 4;
	uint32_t shown, i, total;
	char range[40];

	list_scroll(v);
	shown = list_shown(v);
	top = list_top(v);
	total = list_total(v);

	/* A window of four over a list of thirty has to say so somewhere, or it
	 * reads as a list of four. */
	/*
	 * The filter is named with the word that was clicked to set it.
	 *
	 * The header used to spell it out - "signatures that did not fire" -
	 * which is a sentence where a label belongs, and a different sentence
	 * from the "skip 5" that opened it. Echoing the word makes the dialog
	 * the answer to the click rather than a restatement of it.
	 */
	/*
	 * The note on the right says three things and has to stay unambiguous
	 * when only some of them apply: which filter is on, how many rows there
	 * are under it, and which of them are on screen. A bare "hit  1" said
	 * none of that clearly - the 1 could have been a row number.
	 */
	{
		const char *f = v->list_depth ? "" :
				v->list_filter == 1 ? "hit: " :
				v->list_filter == 2 ? "skip: " : "";
		uint32_t off = v->list_depth ? v->str_off : v->list_off;

		if (!total)
			snprintf(range, sizeof range, "%snone", f);
		else if (total > shown)
			snprintf(range, sizeof range, "%s%u-%u of %u", f,
				 off + 1u, off + shown, total);
		else
			snprintf(range, sizeof range, "%s%u", f, total);
	}

	row_start(o, top, 3);
	if (!v->list_depth)
		out_fmt(o, A_DIM " %-52s %-10s%*s" A_OFF, "signatures",
			"markers", w - 66, range);
	else
		out_fmt(o, A_DIM " %-14s %6s %8s  %-10s %-*s" A_OFF,
			"marker", "db id", "size", "at", w - 46 > 0 ? w - 46 : 1,
			range);

	for (i = 0; i < shown; i++) {
		row_start(o, top + 1 + (int)i, 3);

		if (!v->list_depth) {
			uint32_t idx = list_nth(v, v->list_off + i);
			const struct kof_touch *e;

			if (idx >= ob->n_touch)
				continue;
			e = &ob->touch[idx];
			char name[80], head[24];

			touch_name(e, name, sizeof name);
			touch_head(e, head, sizeof head);
			list_row(o, idx == v->sel_touch, touch_colour(e));
			{
				size_t off = v->list_hoff < strlen(name)
					     ? v->list_hoff : strlen(name);

				out_fmt(o, "%-52.52s %-10s", name + off, head);
			}
			out_str(o, A_OFF);
			continue;
		}

		/* The markers of one signature, the way kofexamine prints them:
		 * present ones in full, absent ones greyed with a dash where an
		 * offset would be. */
		if (t && v->str_off + i < t->n_str) {
			const struct kof_touch_str *st =
				&t->str[v->str_off + i];
			int miss = st->at == KOF_BROKEN;
			int sel = v->str_off + i == v->sel_str;
			char kind[16];
			uint32_t b;

			if (st->kind == KOF_STR_HEX)
				snprintf(kind, sizeof kind, "hex");
			else
				snprintf(kind, sizeof kind, "str: %s-%s",
					 (st->flags & KOF_STR_FULLWORD) ? "fuw"
									: "sub",
					 (st->flags & KOF_STR_ICASE) ? "i" : "c");

			out_str(o, miss ? A_DIM : (st->in_rgn ? A_OFF : A_WARN));
			if (sel)
				out_str(o, "\033[1m");
			out_str(o, sel ? ">" : " ");
			out_fmt(o, "%-14s %6u %8u  ", kind, st->uid, st->len);
			if (miss)
				out_fmt(o, "%-10s ", "-");
			else
				out_fmt(o, "%-10llu ",
					(unsigned long long)st->at);
			for (b = 0; b < st->len && b < 20u; b++)
				out_fmt(o, "%02X", st->bytes[b]);
			if (st->len > 20u)
				out_str(o, "...");
			out_str(o, A_OFF);
		}
	}
}

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
	M_COPY_ASCII = 0,
	M_COPY_HEX,
	M_ADD_STR,
	M_ADD_HEX,
	M_COUNT
};

static const char *const menu_label[M_COUNT] = {
	"Copy ASCII",
	"Copy hex",
	/*
	 * "Declare", because that is the word the module language uses:
	 * KOF_DEFINE_STR declares a string this module looks for, and what this
	 * item does is write one of those. "Add hex to signature" described the
	 * mechanics and was the longest thing in the menu; "Add hex" on its own
	 * would not have said add it to WHAT.
	 *
	 * The ellipsis is the usual promise that a dialog follows rather than
	 * the thing happening on the spot.
	 */
	"Declare as string...",
	"Declare as hex..."
};

#define MENU_W 26

static int menu_enabled(struct view *v, int a)
{
	if (a == M_COPY_ASCII || a == M_COPY_HEX)
		return v->sel_a != KOF_BROKEN;
	/* Not wired to anything yet. Shown because the menu is where they will
	 * be, and disabled because a menu item that does nothing teaches people
	 * not to trust the menu. */
	return 0;
}

static void menu_open_at(struct view *v, int row, int col)
{
	int i;

	v->menu_open = 1;
	v->menu_row = row;
	v->menu_col = col;
	if (v->menu_row + M_COUNT > g_rows)
		v->menu_row = g_rows - M_COUNT;
	if (v->menu_row < 1)
		v->menu_row = 1;
	if (v->menu_col + MENU_W > g_cols)
		v->menu_col = g_cols - MENU_W;
	if (v->menu_col < 1)
		v->menu_col = 1;

	/* Open on something choosable, so Enter always does what is highlighted. */
	v->menu_sel = 0;
	for (i = 0; i < M_COUNT; i++)
		if (menu_enabled(v, i)) {
			v->menu_sel = i;
			break;
		}
}

static void menu_step(struct view *v, int d)
{
	int i, k = v->menu_sel;

	for (i = 0; i < M_COUNT; i++) {
		k += d;
		if (k < 0 || k >= M_COUNT)
			return;
		if (menu_enabled(v, k)) {
			v->menu_sel = k;
			return;
		}
	}
}

static void draw_menu(struct out *o, struct view *v)
{
	int i;

	for (i = 0; i < M_COUNT; i++) {
		int on = menu_enabled(v, i);

		out_at(o, v->menu_row + i, v->menu_col);
		/*
		 * Disabled keeps the menu's background and loses contrast, it
		 * does not lose the text. It was 100;90 - bright black on
		 * bright black - which is the same colour twice, so the items
		 * were there and unreadable. A disabled item still has to say
		 * what it would do; that is the whole reason it is shown.
		 */
		if (i == v->menu_sel && on)
			out_str(o, A_SEL);
		else if (!on)
			out_str(o, "\033[47;90m");
		else
			out_str(o, "\033[47;30m");
		out_fmt(o, " %-*.*s", MENU_W - 2, MENU_W - 2, menu_label[i]);
		out_str(o, A_OFF);
	}
}

/*
 * Copy through the terminal, not through a clipboard this program can reach.
 *
 * OSC 52 hands the bytes to whatever is drawing the screen, which is the only
 * thing that works when the screen is being drawn on another machine - and
 * being usable over ssh is most of why this is a TUI. A terminal with the
 * sequence disabled ignores it silently; there is no reply to wait for and
 * nothing better to fall back to.
 */
static void copy_osc52(const char *bytes, size_t n)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				  "abcdefghijklmnopqrstuvwxyz0123456789+/";
	struct out o = { NULL, 0, 0, 0 };
	size_t i;

	out_str(&o, "\033]52;c;");
	for (i = 0; i < n; i += 3) {
		unsigned long w = (unsigned long)(unsigned char)bytes[i] << 16;
		char t[5];

		if (i + 1 < n)
			w |= (unsigned long)(unsigned char)bytes[i + 1] << 8;
		if (i + 2 < n)
			w |= (unsigned long)(unsigned char)bytes[i + 2];
		t[0] = b64[(w >> 18) & 63];
		t[1] = b64[(w >> 12) & 63];
		t[2] = i + 1 < n ? b64[(w >> 6) & 63] : '=';
		t[3] = i + 2 < n ? b64[w & 63] : '=';
		t[4] = 0;
		out_str(&o, t);
	}
	out_str(&o, "\a");
	if (o.n)
		term_write_n(o.p, o.n);
	free(o.p);
}

static void menu_run(struct view *v, int a)
{
	struct object *ob = cur_obj(v);
	uint64_t lo, hi, k, n;
	struct out t = { NULL, 0, 0, 0 };

	if (!menu_enabled(v, a))
		return;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	n = hi - lo + 1u;

	for (k = 0; k < n; k++) {
		uint8_t c = ob->buf.p[view_map(v, lo + k, 0)];

		if (a == M_COPY_HEX) {
			char x[3];

			snprintf(x, sizeof x, "%02X", c);
			out_add(&t, x, 2);
		} else {
			/* The bytes as they are, not as they print. A marker is
			 * bytes, and turning the unprintable ones into dots
			 * would put something in the clipboard that is not what
			 * was selected. */
			out_add(&t, (const char *)&c, 1);
		}
	}
	if (t.n)
		copy_osc52(t.p, t.n);
	free(t.p);
	v->menu_open = 0;
}

/*
 * A number that changes exactly when the screen would.
 *
 * Button-event tracking reports motion continuously while a button is held, and
 * every report used to repaint. Most of them move nothing - the pointer is still
 * over the same byte - so most of the repaints were the screen being rewritten
 * with what it already said, which is what a click looks like when it flickers.
 */
static uint64_t view_stamp(struct view *v)
{
	uint64_t h = 1469598103934665603ull;
	uint64_t p[] = {
		v->sel_node, v->tree_top, v->rgn_at, v->sel_a, v->sel_b,
		v->sel_touch, v->list_off, (uint64_t)v->pane,
		(uint64_t)v->list_depth, v->str_off, (uint64_t)v->list_filter,
		v->sel_str,
		(uint64_t)v->show_list, (uint64_t)v->menu_open,
		(uint64_t)v->menu_sel, (uint64_t)v->menu_row,
		(uint64_t)v->menu_col, v->tree_hoff, v->list_hoff,
		(uint64_t)g_rows, (uint64_t)g_cols
	};
	size_t i;

	for (i = 0; i < sizeof p / sizeof p[0]; i++) {
		h ^= p[i];
		h *= 1099511628211ull;
	}
	return h;
}

static void redraw(struct view *v)
{
	struct out o = { NULL, 0, 0, 0 };

	term_size();

	/*
	 * Synchronised output, DEC mode 2026.
	 *
	 * A frame is one write, but a terminal is free to render what it has
	 * received so far - so a screen rewritten row by row is briefly a screen
	 * half old and half new. This asks it to hold the picture until the
	 * frame is complete. Terminals that do not know the mode ignore it,
	 * which is why it can be sent unconditionally.
	 */
	out_str(&o, "\033[?2026h");
	draw_frame(&o, v);
	draw_tree(&o, v);
	draw_hex(&o, v);
	draw_marker_line(&o, v);
	if (v->show_list)
		draw_list(&o, v);
	if (v->menu_open)
		draw_menu(&o, v);
	if (o.n)
		{
			size_t off = 0;

			while (off < o.n) {
				ssize_t k = write(STDOUT_FILENO, o.p + off,
						  o.n - off);

				if (k <= 0)
					break;
				off += (size_t)k;
			}
		}
	free(o.p);
}

/*
 * Which byte is under (row, col), if any.
 *
 * The hex pane draws each byte twice - once as two digits, once as a character -
 * and both are the same byte. So both map to it, and the separator columns and
 * the offset column map to nothing. That is the whole answer to "a drag picks up
 * the offset and the ASCII column too": those are not selectable things, they
 * are two renderings and one label of things that are.
 */
static int byte_under(struct view *v, int row, int col, uint64_t *out)
{
	int per = v->per > 0 ? v->per : 16;
	int base = TREE_W + 3;
	int hexs = base + 10;
	int asci = hexs + 3 * per + 2;
	int k;
	uint64_t at;

	if (row < hex_top() || row > hex_bot())
		return 0;
	if (col >= hexs && col < hexs + 3 * per)
		k = (col - hexs) / 3;
	else if (col >= asci && col < asci + per)
		k = col - asci;
	else
		return 0;

	at = v->rgn_at + (uint64_t)(row - hex_top()) * (uint64_t)per +
	     (uint64_t)k;
	if (at >= v->rgn_len)
		return 0;
	*out = at;
	return 1;
}

/*
 * Put a file offset on screen, a few rows down rather than at the very top.
 *
 * Landing a jump on the first row leaves nothing above it, and what is above a
 * marker is half of what says whether it is the right marker - the string before
 * it, the padding, the structure it sits in. Two rows of lead-in costs nothing
 * and is what a reader would have scrolled to anyway.
 */
#define JUMP_LEAD 2u

static void view_show(struct view *v, uint64_t file_off)
{
	uint64_t r = view_unmap(v, file_off);
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t row;

	if (r == KOF_BROKEN)
		return;
	row = r / per;
	v->rgn_at = row > JUMP_LEAD ? (row - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

/* ---- input ---------------------------------------------------------------- */

enum key {
	K_NONE = 0, K_UP = 256, K_DOWN, K_PGUP, K_PGDN, K_HOME, K_END,
	K_CLICK, K_RCLICK, K_WHEEL_UP, K_WHEEL_DOWN, K_DRAG, K_RELEASE,
	K_BACKTAB
};

static int g_mx, g_my;          /* where the last click was, 1 based */
static int g_mod_shift;         /* shift was held for it */

/*
 * SGR mouse reporting, not the original X10 encoding.
 *
 * X10 packs the coordinates into single bytes with an offset of 32, so column
 * 224 and beyond cannot be expressed and the ones near it collide with UTF-8.
 * SGR is "ESC [ < b ; x ; y M" in plain digits with no ceiling, and every
 * terminal that reports a click at all has understood it for a decade.
 */
/*
 * The legacy encoding, for terminals that did not take the SGR request.
 *
 * "ESC [ M b x y", three bytes each biased by 32. It cannot express a column
 * past 223 and it has no separate release code worth trusting, but it is what
 * arrives when ?1006 was ignored - and a request being ignored is silent, so a
 * viewer that only speaks SGR looks to its user like a viewer whose mouse does
 * nothing at all. Which is exactly how it looked.
 */
static int read_mouse_x10(void)
{
	unsigned char t[3];
	int b;

	if (read(STDIN_FILENO, t, 1) != 1 || read(STDIN_FILENO, t + 1, 1) != 1 ||
	    read(STDIN_FILENO, t + 2, 1) != 1)
		return K_NONE;
	b = t[0] - 32;
	g_mx = t[1] - 32;
	g_my = t[2] - 32;
	g_mod_shift = (b & 0x04) != 0;

	if (b & 0x40)
		return (b & 3) == 0 ? K_WHEEL_UP : K_WHEEL_DOWN;
	if (b & 0x20)
		return K_DRAG;
	/* Button 3 in this encoding is "released", whichever was let go. */
	if ((b & 3) == 3)
		return K_RELEASE;
	if ((b & 3) == 2)
		return K_RCLICK;
	return K_CLICK;
}

static int read_mouse(void)
{
	char t[32];
	size_t n = 0;
	int b, x, y;

	while (n + 1 < sizeof t) {
		if (read(STDIN_FILENO, t + n, 1) != 1)
			return K_NONE;
		if (t[n] == 'M' || t[n] == 'm')
			break;
		n++;
	}
	{
		int release = t[n] == 'm';

		t[n] = 0;
		if (sscanf(t, "%d;%d;%d", &b, &x, &y) != 3)
			return K_NONE;
		g_mx = x;
		g_my = y;
		if (release)
			return K_RELEASE;
	}
	g_mod_shift = (b & 0x04) != 0;
	if ((b & 0x20))                      /* motion, with a button held */
		return K_DRAG;
	if ((b & 0x40) && (b & 3) == 0)
		return K_WHEEL_UP;
	if ((b & 0x40) && (b & 3) == 1)
		return K_WHEEL_DOWN;
	if ((b & 3) == 2)
		return K_RCLICK;
	return K_CLICK;
}

static int read_key(void)
{
	unsigned char c, seq[3];

	if (read(STDIN_FILENO, &c, 1) != 1)
		return K_NONE;
	if (c != 27)
		return c;
	if (read(STDIN_FILENO, seq, 1) != 1)
		return 27;
	if (seq[0] != '[' && seq[0] != 'O')
		return 27;
	if (read(STDIN_FILENO, seq + 1, 1) != 1)
		return 27;
	if (seq[1] == '<')
		return read_mouse();
	if (seq[1] == 'M')
		return read_mouse_x10();
	switch (seq[1]) {
	case 'A': return K_UP;
	case 'B': return K_DOWN;
	case 'H': return K_HOME;
	case 'F': return K_END;
	/* Shift+Tab. CSI Z, not a tab with a modifier: the terminal has one
	 * code for it and this is the one. */
	case 'Z': return K_BACKTAB;
	case '5': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_PGUP;
	case '6': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_PGDN;
	default:  return 27;
	}
}

static void hex_step(struct view *v, long lines)
{
	long per = v->per > 0 ? v->per : 16;
	long long at = (long long)v->rgn_at + lines * per;
	uint64_t max = hex_max(v);

	if (at < 0)
		at = 0;
	if ((uint64_t)at > max)
		at = (long long)max;
	v->rgn_at = (uint64_t)at;
}

/* A click says which pane as well as which row, so it moves the focus too:
 * clicking a row nobody is looking at and having nothing happen is the one
 * behaviour a mouse must not have. */
static void click(struct view *v, int rclick)
{
	struct object *ob = cur_obj(v);

	/*
	 * The right button is the hex pane's alone.
	 *
	 * Everywhere else it used to do whatever the left button does, which is
	 * a mouse with one button pretending to have two: right-clicking a tree
	 * row moved the cursor, right-clicking "hit" opened the dialog. A
	 * button that duplicates another teaches nothing and surprises whoever
	 * expected a menu.
	 */
	if (rclick && !(g_my >= hex_top() && g_my <= hex_bot() &&
			g_mx > TREE_W && !v->show_list && !v->menu_open))
		return;

	if (v->menu_open) {
		int k = g_my - v->menu_row;

		/* Anywhere off the menu dismisses it. A menu that only closes
		 * on the right key is a menu people leave open. */
		if (g_mx >= v->menu_col && g_mx < v->menu_col + MENU_W &&
		    k >= 0 && k < M_COUNT && menu_enabled(v, k))
			menu_run(v, k);
		v->menu_open = 0;
		return;
	}
	if (v->show_list) {
		int row = g_my - list_top(v) - 1;
		int on = g_my > list_top(v) &&
			 g_my <= list_top(v) + (int)list_shown(v);

		if (on && !v->list_depth) {
			uint32_t k = list_nth(v, v->list_off + (uint32_t)row);

			/* A signature row opens into its markers rather than
			 * closing the dialog: the row was chosen to be looked
			 * at, and its markers are what there is to look at. */
			if (k < ob->n_touch) {
				v->sel_touch = k;
				v->list_depth = 1;
				v->str_off = 0;
				v->sel_str = 0;
			}
			return;
		}
		if (on) {
			/* A marker row moves the hex pane to it. That is the
			 * whole point of listing where each one is. */
			const struct kof_touch *t = &ob->touch[v->sel_touch];
			uint32_t k = v->str_off + (uint32_t)row;

			if (v->sel_touch < ob->n_touch && k < t->n_str &&
			    t->str[k].at != KOF_BROKEN) {
				v->sel_str = k;
				view_show(v, t->str[k].at);
			}
			return;
		}
		/* Anywhere off the dialog closes it - one that only closes on
		 * the right key is one people leave open. */
		v->show_list = 0;
		v->list_depth = 0;
		return;
	}
	if (g_my == mark_row()) {
		if (!ob->n_touch)
			return;
		/* Three words, three answers. "hit" and "skip" open the dialog
		 * filtered to what they just counted; the name opens that
		 * signature's markers, which is the thing the name is about. */
		if (g_mx >= v->hit_c0 && g_mx <= v->hit_c1) {
			v->list_filter = 1;
			v->list_depth = 0;
			v->list_off = 0;
		} else if (g_mx >= v->skip_c0 && g_mx <= v->skip_c1) {
			v->list_filter = 2;
			v->list_depth = 0;
			v->list_off = 0;
		} else if (g_mx >= v->name_c0 && g_mx <= v->name_c1) {
			v->list_filter = 0;
			v->list_depth = 1;
			v->str_off = 0;
			v->sel_str = 0;
		} else {
			/* The rest of the line is a readout, not a control. The
			 * pane indicator lives there, and clicking it used to
			 * open the signature dialog - which is not what the
			 * word says and not what anyone would expect it to do. */
			return;
		}
		v->show_list = 1;
		return;
	}
	if (g_my >= hex_top() && g_my <= hex_bot() && g_mx > TREE_W) {
		uint64_t at;

		v->pane = 1;
		if (rclick) {
			menu_open_at(v, g_my, g_mx);
			return;
		}
		if (byte_under(v, g_my, g_mx, &at)) {
			v->sel_a = v->sel_b = at;
			v->dragging = 1;
			v->dragged = 0;
		}
		return;
	}
	if (g_my >= hex_top() && g_my <= hex_bot()) {
		if (g_mx <= TREE_W) {
			uint32_t k = v->tree_top + (uint32_t)(g_my - hex_top());

			v->pane = 0;
			goto_node(v, k);
		} else {
			v->pane = 1;
		}
	}
	(void)rclick;   /* the menu it will open does not exist yet */
}

static int handle(struct view *v, int k)
{
	int page = hex_bot() - hex_top();

	if (page < 1)
		page = 1;

	switch (k) {
	case 'q':
		if (v->show_list) {
			v->show_list = 0;
			break;
		}
		return 0;
	case 'n': {
		/* Scrolling a region hunting for a highlight is the one thing
		 * the marker offsets make unnecessary. */
		struct object *ob = cur_obj(v);
		uint64_t best = KOF_BROKEN;
		uint32_t j;

		if (v->sel_touch < ob->n_touch) {
			const struct kof_touch *t = &ob->touch[v->sel_touch];

			for (j = 0; j < t->n_str; j++) {
				uint64_t r;

				if (t->str[j].at == KOF_BROKEN)
					continue;
				r = view_unmap(v, t->str[j].at);
				if (r == KOF_BROKEN || r <= v->rgn_at)
					continue;
				if (best == KOF_BROKEN || r < best)
					best = r;
			}
			/* Nothing after the cursor means wrap, not stop: the
			 * key is for cycling through them. */
			if (best == KOF_BROKEN)
				for (j = 0; j < t->n_str; j++) {
					uint64_t r;

					if (t->str[j].at == KOF_BROKEN)
						continue;
					r = view_unmap(v, t->str[j].at);
					if (r != KOF_BROKEN &&
					    (best == KOF_BROKEN || r < best))
						best = r;
				}
		}
		if (best != KOF_BROKEN)
			v->rgn_at = best - (best % (uint64_t)(v->per ? v->per
								     : 16));
		break;
	}
	case 'm':
		v->show_list = !v->show_list && cur_obj(v)->n_touch;
		v->list_depth = 0;
		v->list_filter = 0;
		break;
	case '\r': case '\n':
		if (v->menu_open) {
			menu_run(v, v->menu_sel);
			v->menu_open = 0;
			break;
		}
		if (v->show_list && !v->list_depth) {
			v->list_depth = 1;
			v->str_off = 0;
			v->sel_str = 0;
			break;
		}
		v->show_list = 0;
		v->list_depth = 0;
		break;
	case '\t':
		v->pane = (v->pane + 1) % 3;
		break;
	case K_BACKTAB:
		/* + 2 rather than - 1: pane is an int, and C's modulo of a
		 * negative one is negative. */
		v->pane = (v->pane + 2) % 3;
		break;
	case K_CLICK:  click(v, 0); break;
	case K_RCLICK: click(v, 1); break;
	case K_DRAG: {
		uint64_t at;

		if (v->dragging && byte_under(v, g_my, g_mx, &at)) {
			if (at != v->sel_a)
				v->dragged = 1;
			v->sel_b = at;
		}
		break;
	}
	case K_RELEASE:
		if (v->menu_open)
			break;
		/*
		 * A press and a release on one byte is a click, not a selection
		 * of length one - and on a lit byte the obvious thing to want
		 * is to know whose marker it is. So it selects that signature,
		 * which relights the pane around it. Anywhere else it is a
		 * caret and stays as one.
		 */
		if (v->dragging && !v->dragged && v->sel_a != KOF_BROKEN) {
			int who = hit_owner(v, view_map(v, v->sel_a, 0));

			if (who >= 0) {
				v->sel_touch = (uint32_t)who;
				v->sel_a = v->sel_b = KOF_BROKEN;
			}
		}
		v->dragging = 0;
		break;
	case 27:
		if (v->menu_open) {
			v->menu_open = 0;
			break;
		}
		/* Back one depth before out: Esc in a sub-list means "up". */
		if (v->show_list && v->list_depth) {
			v->list_depth = 0;
			break;
		}
		v->sel_a = v->sel_b = KOF_BROKEN;
		v->show_list = 0;
		v->list_depth = 0;
		break;
	/*
	 * The wheel turns whatever the pointer is over.
	 *
	 * It used to always scroll the hex pane, which meant scrolling a tree
	 * that was under the cursor moved something else on the other side of
	 * the screen. A wheel that ignores where it is pointing is a wheel
	 * people stop using.
	 */
	case K_WHEEL_UP:
	case K_WHEEL_DOWN: {
		int down = k == K_WHEEL_DOWN, n;

		/* Shift turns the wheel sideways, the way it does in every
		 * other program that has both. */
		if (g_mod_shift) {
			uint32_t *h = (v->show_list && g_my > list_top(v) &&
				       g_my <= list_top(v) +
					       (int)list_shown(v))
				      ? &v->list_hoff :
				      (g_mx <= TREE_W) ? &v->tree_hoff : NULL;

			if (h) {
				if (down)
					*h += 4u;
				else
					*h = *h > 4u ? *h - 4u : 0u;
			}
			break;
		}
		if (v->show_list && g_my > list_top(v) &&
		    g_my <= list_top(v) + (int)list_shown(v)) {
			if (down && v->sel_touch + 1 < cur_obj(v)->n_touch)
				v->sel_touch++;
			else if (!down && v->sel_touch)
				v->sel_touch--;
		} else if (g_mx <= TREE_W && g_my >= hex_top() &&
			   g_my <= hex_bot()) {
			for (n = 0; n < 3; n++)
				goto_node(v, down ? v->sel_node + 1u
						  : v->sel_node - 1u);
		} else {
			hex_step(v, down ? 3 : -3);
		}
		break;
	}
	case 'j': case K_DOWN:
		if (v->menu_open) {
			menu_step(v, 1);
			break;
		}
		/* The list takes the keys while it is open, whatever pane has
		 * focus underneath: it is in front, and a cursor that moves
		 * something behind an open list is a cursor nobody can see. */
		if (v->show_list && v->list_depth) {
			struct object *o2 = cur_obj(v);
			const struct kof_touch *t2 = &o2->touch[v->sel_touch];

			if (v->sel_str + 1 < list_total(v))
				v->sel_str++;
			if (v->sel_str >= v->str_off + list_shown(v))
				v->str_off = v->sel_str - list_shown(v) + 1u;
			if (t2->str[v->sel_str].at != KOF_BROKEN)
				view_show(v, t2->str[v->sel_str].at);
		} else if (v->show_list) {
			if (v->sel_touch + 1 < cur_obj(v)->n_touch)
				v->sel_touch++;
		} else if (v->pane == 0 && v->sel_node + 1 < v->n_node) {
			goto_node(v, v->sel_node + 1u);
		} else if (v->pane == 1) {
			hex_step(v, 1);
		} else if (v->pane == 2 &&
			   v->sel_touch + 1 < cur_obj(v)->n_touch) {
			v->sel_touch++;
		}
		break;
	case 'k': case K_UP:
		if (v->menu_open) {
			menu_step(v, -1);
			break;
		}
		if (v->show_list && v->list_depth) {
			struct object *o2 = cur_obj(v);
			const struct kof_touch *t2 = &o2->touch[v->sel_touch];

			if (v->sel_str)
				v->sel_str--;
			if (v->sel_str < v->str_off)
				v->str_off = v->sel_str;
			if (t2->str[v->sel_str].at != KOF_BROKEN)
				view_show(v, t2->str[v->sel_str].at);
		} else if (v->show_list) {
			if (v->sel_touch)
				v->sel_touch--;
		} else if (v->pane == 0 && v->sel_node) {
			goto_node(v, v->sel_node - 1u);
		} else if (v->pane == 1) {
			hex_step(v, -1);
		} else if (v->pane == 2 && v->sel_touch) {
			v->sel_touch--;
		}
		break;
	case ' ': case K_PGDN: hex_step(v,  page); break;
	case 'b': case K_PGUP: hex_step(v, -page); break;
	case 'g': case K_HOME: v->rgn_at = 0; break;
	case 'G': case K_END:  v->rgn_at = hex_max(v); break;
	default:
		break;
	}
	return 1;
}

/* ---- main ----------------------------------------------------------------- */

static void usage(void)
{
	fprintf(stderr,
	"kofviewer - the engine's view of a file, navigable\n"
	"\n"
	"  kofviewer [--db <dir>] <file>\n"
	"\n"
	"  --db D   load that database. Without it there is one object and no\n"
	"           markers: unpacking is what modules do, and modules live in\n"
	"           a database.\n");
}

static void view_free(struct view *v)
{
	uint32_t i, k;

	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		kof_touch_free(o->touch, o->n_touch);
		for (k = 0; k < o->n_finding; k++)
			free(o->finding[k]);
		free(o->finding);
		free(o->info);
		free(o->own);
	}
	free(v->ext);
}

int main(int argc, char **argv)
{
	const char *path = NULL, *db = NULL;
	kof_engine *eng = NULL;
	struct view v;
	struct stat st;
	int fd, i, rc = 0;

	memset(&v, 0, sizeof v);
	v.sel_a = v.sel_b = KOF_BROKEN;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--db") && i + 1 < argc)
			db = argv[++i];
		else if (argv[i][0] == '-') {
			usage();
			return 2;
		} else if (!path) {
			path = argv[i];
		} else {
			usage();
			return 2;
		}
	}
	if (!path) {
		usage();
		return 2;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0) {
		fprintf(stderr, "kofviewer: %s is not a regular non-empty "
				"file\n", path);
		if (fd >= 0)
			close(fd);
		return 1;
	}
	v.map_len = (uint64_t)st.st_size;
	v.map = kof_map_file_ro(fd, v.map_len);
	close(fd);
	if (!v.map) {
		fprintf(stderr, "kofviewer: cannot map %s\n", path);
		return 1;
	}
	v.path = path;

	v.ext = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.ext);
	if (!v.ext) {
		fprintf(stderr, "kofviewer: out of memory\n");
		return 1;
	}

	if (db) {
		eng = kof_engine_open(db);
		if (!eng)
			fprintf(stderr, "kofviewer: cannot load a database from "
					"%s\n", db);
	}
	if (eng)
		objects_collect(&v, eng);
	if (!v.n_obj) {
		/*
		 * No database, or a scan that produced nothing. The file is
		 * still an object and is still worth looking at - the tree is
		 * just one deep.
		 */
		struct object *o = &v.obj[0];

		memset(o, 0, sizeof *o);
		snprintf(o->name, sizeof o->name, "%s", path);
		o->buf = kof_buf_make(v.map, v.map_len);
		v.n_obj = 1;
	}
	objects_examine(&v, eng);
	tree_build(&v);
	view_select(&v);

	if (!term_setup()) {
		rc = 1;
		goto out;
	}
	redraw(&v);
	for (;;) {
		int k = read_key();
		uint64_t was;

		if (k == K_NONE)
			break;
		was = view_stamp(&v);
		if (!handle(&v, k))
			break;
		/* Repaint only when something moved. term_size is read inside
		 * redraw, so a resize still gets through: it changes the stamp. */
		term_size();
		if (view_stamp(&v) != was)
			redraw(&v);
	}
	term_restore();

out:
	view_free(&v);
	kof_unmap_file(v.map, v.map_len);
	kof_engine_close(eng);
	return rc;
}
