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
	fputs("\033[?25h\033[?1049l", stdout);
	fflush(stdout);
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
	fputs("\033[?1049h\033[?25l", stdout);
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
	out_add(o, s, strlen(s));
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
	if (n > 0)
		out_add(o, t, (size_t)n < sizeof t ? (size_t)n : sizeof t - 1);
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

/* ---- the object under view ------------------------------------------------ */

#define MAX_TREE 64

struct node {
	char     label[40];
	uint32_t mask;        /* the region, or 0 for the object row */
	uint64_t bytes;
};

struct view {
	const char *path;
	kof_buf     buf;
	void       *map;
	uint64_t    map_len;

	const struct kof_inspect_fmt *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	struct node node[MAX_TREE];
	uint32_t    n_node, sel_node;

	/* The extents of the selected region, and where in them the hex pane is
	 * looking. An offset into the REGION, not into the file: the region is
	 * what a signature searches, so it is what a cursor should move through,
	 * and the file offset is derived for display. */
	struct kof_range *ext;
	uint32_t          n_ext;
	uint64_t          rgn_len, rgn_at;

	struct kof_touch *touch;
	uint32_t          n_touch, sel_touch;

	int pane;             /* 0 tree, 1 hex, 2 markers */
};

/* Resolve whichever region the tree cursor is on, and rebase the hex pane. */
static void view_select(struct view *v)
{
	uint32_t i;

	v->n_ext = 0;
	v->rgn_len = 0;
	v->rgn_at = 0;
	if (!v->ext)
		return;
	v->n_ext = kof_scan_resolve_range(&v->ctx,
					  v->node[v->sel_node].mask ?
					  v->node[v->sel_node].mask :
					  KOF_SCAN_ALL, v->ext);
	if (!v->n_ext && v->buf.n) {
		v->ext[0].off = 0;
		v->ext[0].len = v->buf.n;
		v->n_ext = 1;
	}
	for (i = 0; i < v->n_ext; i++)
		v->rgn_len += v->ext[i].len;
}

/* The file offset of byte `at` of the selected region, and how many bytes of
 * that extent are left. Regions are not contiguous, so a hex pane that walked
 * the file would show bytes the region does not contain. */
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

static void view_build_tree(struct view *v)
{
	uint32_t i;

	v->n_node = 0;
	snprintf(v->node[0].label, sizeof v->node[0].label, "%s",
		 v->fmt ? kof_format_name(v->ctx.format) : "unrecognised");
	v->node[0].mask = 0;
	v->node[0].bytes = v->buf.n;
	v->n_node = 1;

	if (!v->fmt)
		return;
	for (i = 0; i < v->fmt->n_regions && v->n_node < MAX_TREE; i++) {
		const char *rn = v->fmt->region_name(v->fmt->regions[i]);
		struct kof_range *e = v->ext;
		uint32_t k, n;
		uint64_t total = 0;

		if (!rn || !e)
			continue;
		n = kof_scan_resolve_range(&v->ctx, v->fmt->regions[i], e);
		for (k = 0; k < n; k++)
			total += e[k].len;
		if (!total)
			continue;
		/* The enum name less its prefix: "KOF_SCAN_ELF_CODE" is what a
		 * signature writes and "CODE" is what fits in a pane. */
		{
			const char *s = strrchr(rn, '_');

			snprintf(v->node[v->n_node].label,
				 sizeof v->node[v->n_node].label, "%s",
				 s ? s + 1 : rn);
		}
		v->node[v->n_node].mask = v->fmt->regions[i];
		v->node[v->n_node].bytes = total;
		v->n_node++;
	}
}

/* ---- panes ---------------------------------------------------------------- */

#define TREE_W   26
#define MARK_H   9

static void draw_frame(struct out *o, struct view *v)
{
	int hex_top = 2, hex_bot = g_rows - MARK_H - 1;
	int i;

	out_str(o, "\033[2J");

	/* Title. */
	out_at(o, 1, 1);
	out_fmt(o, A_BOLD "%.*s" A_OFF, g_cols - 2, v->path);

	/* Vertical rule between tree and hex, and the horizontal one above the
	 * markers pane. Drawn rather than boxed: a box costs four lines of the
	 * screen and buys nothing a rule does not. */
	for (i = hex_top; i <= hex_bot; i++) {
		out_at(o, i, TREE_W + 1);
		out_str(o, A_DIM "|" A_OFF);
	}
	out_at(o, hex_bot + 1, 1);
	out_str(o, A_DIM);
	for (i = 0; i < g_cols; i++)
		out_str(o, "-");
	out_str(o, A_OFF);
}

static void draw_tree(struct out *o, struct view *v)
{
	int top = 2, bot = g_rows - MARK_H - 2;
	uint32_t i;

	for (i = 0; i < v->n_node && (int)i + top <= bot; i++) {
		const struct node *n = &v->node[i];
		int sel = i == v->sel_node;

		out_at(o, top + (int)i, 1);
		if (sel)
			out_str(o, v->pane == 0 ? A_SEL : A_BOLD);
		out_fmt(o, "%s%-12s" A_OFF "%s %s%8llu" A_OFF,
			sel ? "" : (n->mask ? A_ID : A_BOLD), n->label,
			sel ? "" : "", sel ? "" : A_SIZE,
			(unsigned long long)n->bytes);
		if (sel)
			out_str(o, A_OFF);
	}
}

static void draw_hex(struct out *o, struct view *v)
{
	int top = 2, bot = g_rows - MARK_H - 2;
	int col = TREE_W + 3;
	int per = (g_cols - col - 12) / 4;
	int row;
	uint64_t at = v->rgn_at;

	if (per > 16)
		per = 16;
	if (per < 4)
		per = 4;

	for (row = top; row <= bot; row++) {
		uint64_t run = 0, off = view_map(v, at, &run);
		int k;

		out_at(o, row, col);
		if (at >= v->rgn_len)
			break;
		out_fmt(o, A_LOC "%08llx" A_OFF "  ", (unsigned long long)off);
		for (k = 0; k < per; k++) {
			if (at + (uint64_t)k >= v->rgn_len) {
				out_str(o, "   ");
				continue;
			}
			/* A run that ends mid-line is an extent boundary. Marked,
			 * because a marker written across one can never match:
			 * the matcher walks each extent on its own. */
			if ((uint64_t)k == run && k)
				out_str(o, A_WARN "|" A_OFF);
			else
				out_str(o, " ");
			out_fmt(o, "%02X",
				v->buf.p[view_map(v, at + (uint64_t)k, 0)]);
		}
		out_str(o, "  ");
		for (k = 0; k < per && at + (uint64_t)k < v->rgn_len; k++) {
			uint8_t c = v->buf.p[view_map(v, at + (uint64_t)k, 0)];

			out_fmt(o, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
		}
		at += (uint64_t)per;
	}
}

static void draw_markers(struct out *o, struct view *v)
{
	/* One below the rule, which sits at g_rows - MARK_H. Sharing the row put
	 * the first module on top of the line that separates it. */
	int top = g_rows - MARK_H + 1;
	uint32_t i;

	out_at(o, top, 1);
	if (!v->n_touch) {
		out_str(o, A_DIM "no module in the database has a marker here"
			A_OFF);
		return;
	}
	for (i = 0; i < v->n_touch && (int)i < MARK_H - 2; i++) {
		const struct kof_touch *t = &v->touch[i];
		const char *c = t->kind == KOF_TOUCH_COMPLETE  ? A_BAD  :
				t->kind == KOF_TOUCH_PARTIAL   ? A_WARN :
				t->kind == KOF_TOUCH_ELSEWHERE ? A_LOC  : A_DIM;

		out_at(o, top + (int)i, 1);
		if (i == v->sel_touch && v->pane == 2)
			out_str(o, A_SEL);
		/* The name a scan would print, less the target - spelled with the
		 * engine's separators, the same way kofexamine spells it, so a
		 * row here and a row there are the same string. */
		{
			char name[80];
			const char *var = t->n_names && t->name[0] ? t->name[0]
								   : NULL;

			if (var)
				snprintf(name, sizeof name, "%s:%s-%s",
					 kof_maltype_name(t->maltype),
					 t->family[0] ? t->family : "?", var);
			else
				snprintf(name, sizeof name, "%s:%s",
					 kof_maltype_name(t->maltype),
					 t->family[0] ? t->family : "?");

			out_fmt(o, "%s%-14s" A_OFF " %s%-32s" A_OFF " %u/%u", c,
				kof_touch_kind_name(t->kind),
				t->kind == KOF_TOUCH_INELIGIBLE ? A_DIM : A_ID,
				name,
				t->kind == KOF_TOUCH_INELIGIBLE ? t->n_present
								: t->n_in_rgn,
				t->n_str);
		}
		if (t->ruled_out)
			out_fmt(o, A_DIM "   %s" A_OFF, t->ruled_out);
		out_str(o, A_OFF);
	}
}

static void draw_status(struct out *o, struct view *v)
{
	out_at(o, g_rows, 1);
	out_fmt(o, A_DIM "[%s]  j/k move  space/b page  tab pane  q quit"
		"   region %llu bytes, %u extent(s)" A_OFF,
		v->pane == 0 ? "tree" : v->pane == 1 ? "hex" : "markers",
		(unsigned long long)v->rgn_len, v->n_ext);
}

static void redraw(struct view *v)
{
	struct out o = { NULL, 0, 0 };

	term_size();
	draw_frame(&o, v);
	draw_tree(&o, v);
	draw_hex(&o, v);
	draw_markers(&o, v);
	draw_status(&o, v);
	if (o.n)
		(void)!write(STDOUT_FILENO, o.p, o.n);
	free(o.p);
}

/* ---- input ---------------------------------------------------------------- */

enum key { K_NONE = 0, K_UP = 256, K_DOWN, K_PGUP, K_PGDN, K_HOME, K_END };

static int read_key(void)
{
	unsigned char c;
	unsigned char seq[3];

	if (read(STDIN_FILENO, &c, 1) != 1)
		return K_NONE;
	if (c != 27)
		return c;
	/* An escape on its own is a key too, so a partial sequence is not an
	 * error - it is Esc and whatever follows. */
	if (read(STDIN_FILENO, seq, 1) != 1)
		return 27;
	if (seq[0] != '[' && seq[0] != 'O')
		return 27;
	if (read(STDIN_FILENO, seq + 1, 1) != 1)
		return 27;
	switch (seq[1]) {
	case 'A': return K_UP;
	case 'B': return K_DOWN;
	case 'H': return K_HOME;
	case 'F': return K_END;
	case '5': read(STDIN_FILENO, seq + 2, 1); return K_PGUP;
	case '6': read(STDIN_FILENO, seq + 2, 1); return K_PGDN;
	default:  return 27;
	}
}

static void hex_step(struct view *v, long lines)
{
	long per = 16;
	long long at = (long long)v->rgn_at + lines * per;

	if (at < 0)
		at = 0;
	if ((uint64_t)at > v->rgn_len)
		at = (long long)v->rgn_len;
	v->rgn_at = (uint64_t)at;
}

static int handle(struct view *v, int k)
{
	int page = g_rows - MARK_H - 4;

	if (page < 1)
		page = 1;

	switch (k) {
	case 'q':
		return 0;
	case '\t':
		v->pane = (v->pane + 1) % 3;
		break;
	case 'j': case K_DOWN:
		if (v->pane == 0 && v->sel_node + 1 < v->n_node) {
			v->sel_node++;
			view_select(v);
		} else if (v->pane == 1) {
			hex_step(v, 1);
		} else if (v->pane == 2 && v->sel_touch + 1 < v->n_touch) {
			v->sel_touch++;
		}
		break;
	case 'k': case K_UP:
		if (v->pane == 0 && v->sel_node) {
			v->sel_node--;
			view_select(v);
		} else if (v->pane == 1) {
			hex_step(v, -1);
		} else if (v->pane == 2 && v->sel_touch) {
			v->sel_touch--;
		}
		break;
	case ' ': case K_PGDN: hex_step(v,  page); break;
	case 'b': case K_PGUP: hex_step(v, -page); break;
	case 'g': case K_HOME: v->rgn_at = 0; break;
	case 'G': case K_END:  hex_step(v, (long)v->rgn_len); break;
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
	"  --db D   load that database, so the markers pane can say what it\n"
	"           already knows about this object\n");
}

int main(int argc, char **argv)
{
	const char *path = NULL, *db = NULL;
	kof_engine *eng = NULL;
	struct view v;
	struct stat st;
	int fd, i, rc = 0;

	memset(&v, 0, sizeof v);

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
	v.buf = kof_buf_make(v.map, v.map_len);

	v.ext = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.ext);
	if (!v.ext) {
		fprintf(stderr, "kofviewer: out of memory\n");
		return 1;
	}

	v.fmt = kof_inspect_identify(v.buf, &v.ctx, &v.info);
	if (!v.fmt)
		v.ctx.obj_size = v.buf.n;
	view_build_tree(&v);
	view_select(&v);

	if (db) {
		eng = kof_engine_open(db);
		if (!eng)
			fprintf(stderr, "kofviewer: cannot load a database from "
					"%s\n", db);
		else if (!kof_touch_object(eng, v.buf, &v.ctx, &v.touch,
					   &v.n_touch))
			v.n_touch = 0;
	}

	if (!term_setup()) {
		rc = 1;
		goto out;
	}
	redraw(&v);
	for (;;) {
		int k = read_key();

		if (!k)
			break;
		if (!handle(&v, k))
			break;
		redraw(&v);
	}
	term_restore();

out:
	kof_touch_free(v.touch, v.n_touch);
	free(v.ext);
	free(v.info);
	kof_unmap_file(v.map, v.map_len);
	kof_engine_close(eng);
	return rc;
}
