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
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/core/kofplatform.h"
#include "goto_parse.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include "../kofparsers/binaries/elf_sym.h"
#include "../kofparsers/binaries/pe_sym.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>

#include "kofinspect.h"

/* The disassembler the emulator already carries: the viewer links the same
 * library, so this costs an include path and nothing else. */
#include "bddisasm.h"
#include "../libkofeng/kofheur/kofheur.h"
#include "../libkofeng/kofscanners/scan.h"
#include "../libkofeng/kofunpack/emu_unpack.h"
#include "../libkofeng/kofmatchers/kofmatch.h"
#include "../libkofeng/kofmatchers/hexprog.h"
#include "../libkofeng/kofdb/kofpack.h"

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

static volatile sig_atomic_t g_winch;

static void on_winch(int sig)
{
	(void)sig;
	g_winch = 1;
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
	{
		/*
		 * Without SA_RESTART on purpose: the point is for the blocked
		 * read to come back so the loop can lay the screen out again.
		 */
		struct sigaction sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_handler = on_winch;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGWINCH, &sa, NULL);
	}
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
	/*
	 * And WHERE that row began, which col_hint alone cannot say.
	 *
	 * col_hint counts from the last positioning, not from column one, so
	 * "1 + col_hint" is only the real column when the row started at column
	 * one. The find dialog starts its rows at column three, and its click
	 * boxes were two columns left of the text they name for as long as they
	 * were written that way; they are "col_base + col_hint" now, and so is
	 * the Go to box. A field that wants to turn a click into a caret cannot
	 * be wrong by two, so the base is recorded rather than assumed - and
	 * anything laying out a row records its boxes from it, never from 1.
	 */
	int   row_hint, col_base;
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

/*
 * One GLYPH: several bytes, one column.
 *
 * out_str counts col_hint per byte, which is right for ASCII and wrong for
 * anything else - a three byte box character would advance the column count by
 * three and every width and click box computed from it after that would be out.
 * The scrollbar gets away with out_str because it writes one glyph and then
 * repositions; a border cannot.
 */
static void out_glyph(struct out *o, const char *g)
{
	out_add(o, g, strlen(g));
	o->col_hint++;
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
	o->row_hint = row;
	o->col_base = col;
}

#define A_OFF   "\033[0m"
#define A_BOLD  "\033[1m"
#define A_DIM   "\033[90m"
#define A_ID    "\033[34m"
#define A_LOC   "\033[36m"
#define A_SIZE  "\033[32m"
#define A_BAD   "\033[31m"
#define A_WARN  "\033[33m"
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
#define A_AND   "\033[36m"
#define A_OR    "\033[33m"
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

/*
 * THE SYMBOL TABLE'S COLOURS, WHICH ARE ABOUT FIELDS AND NOT ABOUT BYTES.
 *
 * The byte colours above answer "what kind of byte is this" - the only question
 * worth asking of an extent of a file, where nothing says where one value ends
 * and the next begins. A symbol record is the opposite: every field is at a
 * fixed offset and the reader already knows the boundaries, so colouring by
 * byte value would spend the whole palette saying something the layout says
 * better, and say nothing about which number is a size and which is an address.
 * So these key on the FIELD.
 *
 * Value and size borrow A_LOC and A_SIZE deliberately rather than picking new
 * hues: an address is cyan in the hex gutter, in the tree and in a finding's
 * location, and a size is green everywhere the tool prints one. A reader who
 * has learnt those two here has learnt them for the rest of the screen.
 */
/*
 * ONE HUE PER FIELD, AND NO HUE USED TWICE.
 *
 * This is the whole rule, and it was broken twice. type, vis and flags were
 * 95, 35 and 35 - two magentas and a bright magenta - so the four attribute
 * bytes at the front of every record came out as one red-purple smear with no
 * boundary visible in it; and the dialog's record number shared 93 with bind's
 * 33, two yellows. Fields the reader is meant to tell apart must not be told
 * apart by brightness alone.
 *
 * They are assigned so that ADJACENT fields are far apart in hue, because
 * adjacency is what makes two colours hard to separate. In the block the order
 * is type, bind, vis, flags, shndx, value, size, name - bytes 0,1,2,3,4,8,16,24
 * - and no two neighbours below are from the same family.
 *
 * Value and size are fixed points, not choices: an address is cyan in the hex
 * gutter, in the tree and in a finding's location, and a size is green
 * everywhere the tool prints one. Everything else is arranged around them.
 */
#define A_S_HDR   "\033[93m"      /* the block's 16-byte header, once at the top */
/*
 * The record number, and DIM on purpose. It is the one column that is not in
 * the record at all - the viewer counts it - so it reads as a gutter rather
 * than as a field, which is also what keeps it clear of every hue below.
 */
#define A_S_IDX   "\033[90m"
#define A_S_TYPE  "\033[95m"      /* STT_*  bright magenta */
#define A_S_BIND  "\033[33m"      /* STB_*  yellow */
#define A_S_VIS   "\033[94m"      /* STV_*  bright blue */
#define A_S_FLAG  "\033[91m"      /* the derived flags, bright red */
/*
 * The section index - a REAL PURPLE, and the only 256-colour code in this file.
 *
 * Every other colour here is one of the sixteen, and that is what ran out. The
 * eight families are all spoken for - red flags, green size, yellow bind,
 * bright-yellow header, blue vis, magenta type, cyan value, white name, grey
 * rec - and eleven things need telling apart, so some family must be used
 * twice. That is fine only where the two are never adjacent in EITHER view,
 * and this field is the one that cannot satisfy it: it has DIFFERENT NEIGHBOURS
 * in the two, flags and value in the block, size and name in the dialog, so it
 * has to be clear of four colours rather than two. Light grey read as the name
 * beside it; bright cyan touches value; bright green touches size; blue sits
 * two bytes from vis; and plain magenta - which is what it was - is the SAME
 * FAMILY as type's bright magenta, which is why the two read as one colour
 * however far apart they sit.
 *
 * So: #af87ff, a hue no other field owns. Cyan stays "an address" and green
 * stays "a size" throughout the tool, which is the reason for reaching outside
 * the sixteen rather than taking one of those two meanings for a third job.
 *
 * A terminal without 256-colour support ignores the sequence and draws the
 * column in the default foreground - it loses a distinction, it does not break
 * the layout.
 */
#define A_S_SHN   "\033[38;5;141m"
#define A_S_VAL   A_LOC           /* st_value - an address, like every other */
#define A_S_SIZE  A_SIZE          /* st_size  - a size, like every other */
#define A_S_NAME  "\033[97m"      /* the name */
#define A_S_HEAD  "\033[4;37m"    /* the column titles */
/*
 * THE ROW A HEURISTIC NAMED, and the only place in this table where a whole
 * row takes one colour.
 *
 * Every other colour here says what a FIELD is; this says something about the
 * record as a whole, so it cannot be another hue in the same scheme - it has
 * to be the kind of mark that reads as "this one", which is a background. The
 * red is the one the hex pane already uses for a marker the database counted
 * (A_HIT1), so a reader who has seen a highlighted byte knows what it means
 * before being told.
 */
#define A_S_FOUND "\033[41;97m"

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
 * THE DISASSEMBLY PANEL'S OWN PALETTE, and why it is a separate one.
 *
 * The two panes sit one above the other and show the same bytes twice. Colouring
 * them from one palette made that worse rather than better: a green in the hex
 * meant "printable ASCII" and a green in the disassembly would mean "register",
 * and a reader glancing between them has to remember which pane they are in
 * before a colour means anything.
 *
 * So the hex pane keeps the normal range - 32, 33, 35, 36, 90 - and this one
 * uses the BRIGHT range throughout. Nothing here can be confused for a byte
 * class, and which pane an eye has landed on is answered by the colours being
 * brighter rather than by reading the addresses.
 *
 * What each one is for:
 *
 *   OFF   the offset column, which is a location and reads like one
 *   BYTE  the raw bytes: supporting detail, deliberately the quietest thing
 *         on the row, because the reason to have a disassembly is not to read
 *         hex
 *   MNEM  the mnemonic - what the instruction DOES, so the brightest
 *   REG   registers
 *   IMM   immediates and addresses
 *   KEY   the size and pointer words - qword, ptr, rel - which are grammar
 *         rather than content
 *   PUNC  commas and brackets, which carry no information at all
 */
#define A_D_OFF   "\033[94m"
#define A_D_BYTE  "\033[90m"
#define A_D_MNEM  "\033[97m"
#define A_D_REG   "\033[92m"
/*
 * Bright CYAN and not bright yellow, which is where this started.
 *
 * The hex pane paints every byte at or above 0x80 yellow, and in a binary that
 * is most of them - so a yellow immediate here landed in a pane whose neighbour
 * is already largely yellow, which is the one thing this palette exists to
 * avoid. Nothing in the disassembly is yellow now.
 */
#define A_D_IMM   "\033[96m"
#define A_D_KEY   "\033[95m"
#define A_D_PUNC  "\033[37m"
/*
 * The bytes a HEX selection covers, marked in the byte column.
 *
 * A background on the BYTES rather than a colour on the whole row, and that is
 * the whole design: a marker is a run of bytes, and what a reader needs to know
 * about the run they have picked is whether it starts and ends on instruction
 * boundaries - a signature that begins mid-instruction moves the moment the
 * source is rebuilt with another register allocation. Marking whole rows in two
 * colours was tried and said the same thing far less exactly. Marking the bytes
 * themselves shows it byte for byte.
 */
#define A_D_SEL   "\033[106;30m"

/*
 * Which colour a token of the operand text gets.
 *
 * A classifier and not a parser. bddisasm's text is regular enough that the
 * first character decides nearly everything - a digit starts an immediate, a
 * letter starts either a register or one of a dozen grammar words - and a real
 * operand parser here would be a second disassembler to disagree with the
 * first.
 */
static const char *dis_token_colour(const char *t, size_t n)
{
	static const char *const key[] = {
		"byte", "word", "dword", "qword", "tword", "oword", "yword",
		"zword", "ptr", "rel", "far", "near", "short"
	};
	unsigned i;

	if (!n)
		return A_D_PUNC;
	if (t[0] >= '0' && t[0] <= '9')
		return A_D_IMM;
	for (i = 0; i < sizeof key / sizeof key[0]; i++)
		if (strlen(key[i]) == n && !memcmp(t, key[i], n))
			return A_D_KEY;
	return A_D_REG;
}

/*
 * SHORTEN THE IMMEDIATES, IN PLACE.
 *
 * bddisasm prints them at the operand's full width, so a push of 34 comes out
 * as 0x0000000000000022 - eighteen characters of which two carry the value. On a
 * row that also holds an offset and seven bytes of hex that is most of the line
 * spent on zeroes, and the number a reader is looking for is the hardest thing
 * on it to find.
 *
 * Done to the TEXT rather than while painting, so the clipboard gets the same
 * short form the screen does. Leading zeroes only: nothing else about the number
 * changes, and a value that really is zero keeps one digit rather than becoming
 * an empty 0x.
 */
static void dis_shorten(char *t)
{
	char *r = t, *w = t;

	while (*r) {
		if (r[0] == '0' && r[1] == 'x') {
			char *d = r + 2, *keep;

			*w++ = *r++;            /* 0 */
			*w++ = *r++;            /* x */
			while (*d == '0')
				d++;
			keep = d;
			while ((*keep >= '0' && *keep <= '9') ||
			       (*keep >= 'a' && *keep <= 'f') ||
			       (*keep >= 'A' && *keep <= 'F'))
				keep++;
			if (keep == d)
				*w++ = '0';     /* the value was zero */
			while (d < keep)
				*w++ = *d++;
			r = keep;
			continue;
		}
		*w++ = *r++;
	}
	*w = 0;
}

/*
 * Paint one instruction's text: the mnemonic, then its operands token by token.
 *
 * Emitted into the frame directly rather than built into a string, because the
 * colours are escape sequences and a string with escapes in it is a string
 * whose length no longer matches its width - and the panel's copy path needs
 * the plain text, which it already has.
 */
static void dis_paint(struct out *o, const char *text)
{
	size_t i = 0, n = strlen(text);

	/* The mnemonic is everything up to the first space. */
	while (i < n && text[i] != ' ')
		i++;
	out_str(o, A_D_MNEM);
	out_add(o, text, i);
	out_str(o, A_OFF);
	while (i < n) {
		size_t j = i;

		if (text[i] == ' ') {
			while (j < n && text[j] == ' ')
				j++;
			out_add(o, text + i, j - i);
			i = j;
			continue;
		}
		/* Punctuation one character at a time: it is never part of a
		 * token and gluing it to one would colour the token wrong. */
		if (!((text[i] >= '0' && text[i] <= '9') ||
		      (text[i] >= 'a' && text[i] <= 'z') ||
		      (text[i] >= 'A' && text[i] <= 'Z') ||
		      text[i] == '_')) {
			out_str(o, A_D_PUNC);
			out_add(o, text + i, 1);
			out_str(o, A_OFF);
			i++;
			continue;
		}
		while (j < n && ((text[j] >= '0' && text[j] <= '9') ||
				 (text[j] >= 'a' && text[j] <= 'z') ||
				 (text[j] >= 'A' && text[j] <= 'Z') ||
				 text[j] == '_' || text[j] == 'x'))
			j++;
		out_str(o, dis_token_colour(text + i, j - i));
		out_add(o, text + i, j - i);
		out_str(o, A_OFF);
		i = j;
	}
}

/*
 * A marker is lit with a BACKGROUND, not with reverse video.
 *
 * Reverse swaps foreground and background, which throws away the byte class
 * colour underneath - a highlighted run would lose the one thing the rest of the
 * pane uses to tell zeroes from text. A background keeps both: the class stays
 * the ink, the match becomes the block of colour.
 */
/*
 * A section bar in the draft panel, and the status line.
 *
 * Bright black behind bright white, so it reads as a rule with words on it
 * whichever way round the terminal's palette is. Not A_SEL: reverse video means
 * "this is selected" everywhere else in this file, and a heading that looks
 * selected is a heading people click.
 */
#define A_HEAD  "\033[100;97m"

#define A_SELB  "\033[44;97m"   /* the drag selection */
#define A_HIT1  "\033[41;97m"   /* counted by the module */
#define A_HIT2  "\033[43;30m"   /* present, but outside its regions */
/*
 * A string the draft itself declares, lit where it sits in the object.
 *
 * A different colour from the database's markers on purpose: one is what the
 * engine already knows, the other is what this draft is claiming, and the whole
 * job of the pane is telling those two apart.
 */
#define A_HIT3  "\033[45;97m"


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
/* Row 1 is the menu bar, so the panes start below it. */
static int hex_top(void)  { return 2; }
/*
 * How many rows the draft panel is using.
 *
 * File scope so the geometry helpers stay parameterless - they are called from
 * everywhere including the click routing, and threading a view pointer through
 * them to ask one question would be worse than one number kept in step in one
 * place. Updated at the top of every frame.
 *
 * Zero until there is a draft: an empty panel would cost the hex view its
 * height on every file, including the many opened to be read rather than
 * written about. It appears with the first declaration and leaves with the last.
 */
static int g_decl_rows;

/*
 * Bottom-up: the status bar owns the last row, the draft panel the rows above
 * it, and the rule sits between the draft and the hex pane. They were one row
 * short of each other - the rule was being drawn on the draft's header line -
 * which made the two panels look like one.
 */
static int hex_bot(void)  { return g_rows - g_decl_rows - 2; }
static int decl_top(void) { return g_rows - g_decl_rows; }
static int mark_row(void) { return g_rows; }

/*
 * How many rows the disassembly panel is using, and zero when it is closed.
 *
 * It takes them from the BOTTOM OF THE HEX COLUMN and from nowhere else: the
 * object tree beside it keeps its full height, because the tree is how a reader
 * moves between objects and losing half of it to look at one is the wrong
 * trade. So the split is horizontal inside one column rather than a new pane.
 *
 * File scope beside g_decl_rows and for the same reason - the geometry helpers
 * are called from the click routing as well as the drawing, and threading a
 * view pointer through them to ask one question would be worse.
 */
static int g_disasm_rows;

/* The panel's first row. Its heading, which carries the close button, is the
 * row above that, and the row above THAT is left blank as the rule. */
static int dis_top(void)  { return hex_bot() - g_disasm_rows + 1; }

/*
 * The last row the HEX rows may use.
 *
 * Everything about the pane as a whole - the tree, the divider, the rule under
 * both - still asks hex_bot(). Only the things that are about hex BYTES ask
 * this: what fits on screen, which byte a click landed on, how far a page
 * scrolls. Keeping the two questions apart is what lets the panel open without
 * the tree changing height.
 */
static int hex_last(void) { return g_disasm_rows ? dis_top() - 2 : hex_bot(); }

/* ---- the signature being drafted -------------------------------------------
 *
 * What the tool exists for. Everything else - the region tree, the offsets that
 * count from the region rather than the file, the highlighting - is here to get
 * a person to the moment where they can say "that, and that, are the marker",
 * and this is where what they said is kept.
 *
 * A declaration remembers the region it came from as well as the bytes. That is
 * the half a hand-written signature usually gets wrong: the bytes are easy to
 * copy and the range they were found in is easy to forget, and a marker searched
 * for in the wrong region is a signature that quietly never fires.
 */
/*
 * When a recovered object stops being held in memory, and when it stops being
 * held at all.
 *
 * Eight megabytes is far past anything an unpacker normally hands back and far
 * short of anything worth paging; the quarter gigabyte is the whole session's
 * budget across every child.
 */
#define OBJ_SPILL   (8ull << 20)
#define OBJ_BUDGET  (256ull << 20)

#define MAX_DECL  32
/*
 * THE LARGEST DECLARATION, AND THE TWO BUFFERS THAT MUST AGREE WITH IT.
 *
 * A hex marker is written three characters to the byte ("2E 2E 5C"), so the
 * spelling of a DECL_BYTES_MAX pattern needs 3*N characters and the scratch a
 * person types into must hold the same. They used to be two unrelated numbers -
 * hexs[512] and sedit[600] - and the gap between them was a silent data loss:
 * a hex marker of 171 bytes or more spells out past 512 characters, so the
 * field opened, took keys, and then decl_edit_commit refused the whole thing
 * for being too long. The edit vanished with no mark on the screen. Whatever
 * can be typed must be committable, which means one number, not two.
 */
#define DECL_BYTES_MAX 512u
/* How many occurrences of one marker the pane will light. Past this the
 * highlight stops being information and starts being a background colour. */
#define DECL_HITS_MAX  64u
/*
 * The right hand end of a string row, in columns from the right edge.
 *
 * The two arrows appear ONLY when there is more than one occurrence to step
 * between: a marker that is in the file once has nowhere to go, and a pair of
 * dead buttons on every row is worse than a row that is shorter.
 */
#define STR_BTN_X     4u        /* [x] */
#define STR_BTN_E     8u        /* [e] */
#define STR_BTN_NEXT 12u        /* [>] */
#define STR_CNT      19u        /* "nn/nn", five wide */
#define STR_BTN_PREV 23u        /* [<] */
#define DECL_HEXS_CAP  (3u * DECL_BYTES_MAX + 16u)
/* "[ Discard ]" with a space in front, so the note box can leave room. */
#define NEW_BTN_W 12
/*
 * Where the string editor's codes live in view.edit.
 *
 * One code per declaration, in a band of its own well clear of every other
 * field's. The bands below it are 1, 4+i, 103+i, 200+i, 300+i, 400+i, 500 and
 * 501, and each is tested as a band rather than as "at least" - a rule this
 * file learned the hard way when the size editor claimed everything from 200
 * up and swallowed the boxes added above it.
 */
#define ED_STR    600
/* How many samples and authors one rule's history holds. Past this the oldest
 * are dropped rather than the file growing without bound - a rule tested against
 * forty samples is a rule whose first ten no longer say much. */
#define MAX_META  16
#define MAX_GROUP 8

/* Every row the draft panel can ever hold, spelled from the limits rather than
 * counted once: the panel grew three kinds of row after this array was sized,
 * and a table that silently stops short is a panel whose bottom cannot be
 * scrolled to. */
#define MAX_PROW  (OPT_COUNT + 1 + 2 + MAX_DECL + 2 + 2 * MAX_GROUP + 2 + \
		   4 * MAX_GROUP)
#define MAX_RANGE 8

/*
 * DLG_ROWS / DLG_COLS - what a dialog's recorded text can hold.
 *
 * Sized from the boxes themselves: neither is taller than 28 rows and the
 * widest is 116 columns, so these are those numbers with room to spare. A row
 * longer than DLG_COLS is truncated in the RECORDING only - what is on screen
 * is whatever was drawn - and truncating the copy of a row nobody can select
 * past is not a loss.
 */
#define DLG_ROWS 40
#define DLG_COLS 168

/* A string that no condition uses yet. Declaring one must not invent a place to
 * put it: the condition is the researcher's decision and making it for them is
 * the kind of help that has to be undone before anything else can be done. */

/*
 * The optional declarations.
 *
 * KOF_TARGET_FORMAT is required and comes from the parse. These three are not,
 * and each one is a precondition the host checks without entering the module -
 * so adding one is a decision about cost as much as about correctness, and it
 * belongs where the other declarations are rather than being inferred.
 *
 * Their values are seeded from the object, because the object is where a true
 * value comes from: the size of the sample, the architecture it was built for,
 * the kind of file it is. A researcher widens them from there; nobody starts
 * from zero.
 */
enum opt_kind {
	OPT_SIZE_MIN = 0,
	OPT_SIZE_MAX,
	OPT_ARCH,
	OPT_SUBTYPE,
	OPT_COUNT
};

/*
 * What each declaration is called on screen.
 *
 * Not the macro's name. KOF_TARGET_SIZE_MIN is what gets written to the file
 * and is the right name there, where the reader is looking at C; on a panel it
 * is a token to decode, and "size_min" does not say whether it is a minimum
 * this module requires or a minimum it refuses.
 */
static const char *const opt_word[OPT_COUNT] = {
	"Smallest file size", "Largest file size",
	"Architecture", "File subtype"
};

/*
 * The architectures, as the enum spells them.
 *
 * All of them, not the one this object happens to be: a signature for a family
 * that ships an arm build and an x86 one is written from whichever sample is to
 * hand, and being offered only that sample's architecture is how a signature
 * ends up narrower than the family it names.
 */
static const struct { const char *word; uint32_t val; } arch_word[] = {
	{ "ANY",     0 }, { "X86",     1 }, { "X86_64",  2 }, { "ARM",     3 },
	{ "ARM64",   4 }, { "RISCV64", 5 }, { "MIPS",    6 }, { "PPC64",   7 },
	{ "MIPS64",  8 }, { "PPC",     9 }, { "RISCV32", 10 }
};
#define ARCH_N (sizeof arch_word / sizeof arch_word[0])

/* The subtypes, per format. The values overlap between formats, which is why
 * naming one format's values while targeting another is a build error. */
static const char *const fmt_word[] = {
	/* Index 0 is the format an object has when nothing identified it, and it
	 * is a target like any other: a rule written for a decrypted payload
	 * applies to exactly that and to no ELF. It read KOF_FMT_ANY here, which
	 * is a different statement - every format - and is spelled where that is
	 * meant. */
	"KOF_FMT_UNKNOWN", "KOF_FMT_ELF", "KOF_FMT_PE",
	"KOF_FMT_MACHO", "KOF_FMT_SCRIPT", "KOF_FMT_TEXT",
	"KOF_FMT_GZIP", "KOF_FMT_DOCOLE", "KOF_FMT_ZIP",
	"KOF_FMT_DOCZIP", "KOF_FMT_TAR", "KOF_FMT_7Z",
	"KOF_FMT_RAR", "KOF_FMT_XZ", "KOF_FMT_RTF",
	"KOF_FMT_PDF"
};
#define FMT_WORD_N (sizeof fmt_word / sizeof fmt_word[0])

static const char *const elf_sub[] = { "NONE", "REL", "EXEC", "DYN", "CORE" };
static const char *const pe_sub[]  = { "EXE", "DLL", "SYS" };

/*
 * A declared range: KOF_TARGET_RANGE, exactly.
 *
 * Its own entity rather than a property of a condition, because that is what it
 * is in the module language - a NAMED union of region bits that any number of
 * searches can then name. Which is also what makes the one hard constraint
 * workable: a search call takes one range, so a condition over markers from two
 * regions is impossible until the two regions are one range. Merging them is
 * how that is said, and it is a decision with a cost - a marker in a merged
 * range may then match in either half - so it is a thing somebody does on
 * purpose rather than something the tool arranges quietly.
 */
struct range {
	uint32_t mask;              /* an OR of the format's region bits */
	char     name[40];          /* what the source will call it */
};

/*
 * A condition, and the markers it is about.
 *
 * The group is the thing that is created first: somebody decides "any of these"
 * before deciding which these. What is NOT free is the region - kof_find_str_all
 * and its siblings take ONE range for every string in the call, so a group is a
 * condition over markers that share a region. "Two of these three, in the code
 * section" is a sentence the engine can say; "two of these three, wherever they
 * are" is not.
 *
 * So the region is not chosen, it is learnt: it is fixed by the first marker put
 * into the group, and a marker from anywhere else has to go in a different one.
 * Saying that at the moment of adding beats discovering it at build time.
 */
/*
 * A matcher: one search call, and nothing else.
 *
 * find_all / find_any / find_multi over some markers in one range. It says
 * whether those bytes are there and takes no position on what that means - so
 * it carries no verdict, and the same matcher can be used by two different
 * conclusions.
 */
struct group {
	int      rule;              /* 0 ALL, 1 ANY, 2 threshold */
	uint32_t thresh;
	char     note[512];         /* the author's note, emitted as a comment */
	/* How far it is scrolled inside its own box, for the same reason the
	 * module's comment has one: sliding the whole panel to read the end of
	 * a sentence takes the controls beside it off the screen. */
	uint32_t note_off;
	/*
	 * The range this matcher searches, as a mask.
	 *
	 * Not an index into a list of ranges, because there is no list to keep:
	 * a range has no existence apart from a matcher naming it. Zero means
	 * "the narrowest that holds what I have", recomputed as markers come
	 * and go - which is the answer that is right until somebody decides
	 * otherwise, and the only one that cannot go stale.
	 */
	uint32_t mask;
};

/*
 * A condition: what some combination of matchers MEANS.
 *
 * This is where the flexibility lives, and where bases/signatures already puts
 * it. lkm_rootkit_general.c is the shape: one matcher gates the file as a
 * rootkit at all, and three more each name a different family inside that gate.
 * Neither half of that is expressible if a verdict is welded to a search -
 * the gate concludes nothing on its own, and the three share it.
 *
 * So a condition is an expression over matcher ids ("1", "1&2", "(1&2)|3"), a
 * verdict, and optionally a parent it sits inside. A condition with children
 * concludes nothing itself: it is the gate, and its children are what happens
 * once it holds.
 */
/*
 * What a condition concludes.
 *
 * LV_NONE is not "undecided" - it is a branch that matched and reports nothing
 * on purpose, which is the only way to say "these bytes are here and they are
 * fine" in a chain of alternatives. It also lets a gate stay a gate.
 */
enum cnd_level { LV_INFECT = 0, LV_SUSPECT, LV_NONE, LV_COUNT };

static const char *const lvl_word[LV_COUNT] = {
	"INFECT", "SUSPECT", "No verdict"
};

struct cond {
	char     expr[64];          /* over matcher ids */
	/*
	 * Two different combinations, and they are not the same question.
	 *
	 * `op` joins the matcher ids INSIDE this condition - "1 and 2" against
	 * "1 or 2". `join` says how the next condition at this level attaches
	 * to this one: as an alternative tried only when this one misses, or as
	 * a separate test made anyway. A join has nothing to combine unless
	 * there is a sibling below, so it exists only when there is one.
	 */
	int      op;                /* 0 and, 1 or - between this one's ids */
	int      join;              /* 0 alternative, 1 checked as well */
	int      level;             /* enum cnd_level */
	int      var_kind;          /* 0 AUTO, 1 GENERIC, 2 custom */
	char     variant[48];
	int      parent;            /* -1 for a top level block */
};

struct decl {
	uint8_t *bytes;
	/*
	 * HOW MANY BYTES ARE IN THE ARRAY, WHICH IS NOT HOW LONG THE PATTERN IS.
	 *
	 * They were one number and could be while every marker was a run of
	 * concrete bytes. A hex pattern is not one: "2E ?? 5C" is three bytes
	 * long in a file and has no byte array at all, and "6A 40 [4-6] 8D" is
	 * six to eight. So `len` is what the pattern covers where it matches -
	 * what the size column shows and what the pane highlights - and
	 * `nbytes` bounds the array, which is empty for any pattern the engine
	 * had to compile.
	 */
	uint32_t nbytes;
	uint32_t span_max;          /* len is the minimum; equal when fixed */
	uint32_t len;
	int      hex;               /* KOF_DEFINE_HEXSTR, else KOF_DEFINE_STR */

	/*
	 * A HEX PATTERN AS IT WAS WRITTEN, WHICH `bytes` CANNOT HOLD.
	 *
	 * `bytes` is a byte sequence. A hex pattern is not one: DEAD??BEEF has a
	 * wildcard, 41[4-8]43 has a gap, 41(42|43)44 has a choice, and none of
	 * the three survives being flattened into bytes. So the spelling is kept
	 * beside them, and it is what gets shown and what gets written back.
	 *
	 * Empty for a literal, and empty for a hex pattern declared from a
	 * selection in this session - those really are concrete bytes and
	 * printing them from `bytes` is exact.
	 *
	 * The bug this exists for: a signature opened WITHOUT its source - the
	 * database keeps strings, not logic - arrived through draft_from_touch,
	 * which copied the pack's (bytes, len) verbatim. For a hex marker those
	 * are the COMPILED PROGRAM and its total length, so ZipSlip's three byte
	 * "2E2E5C" showed as 67 bytes of 010001000300... and, far worse,
	 * Generate wrote that program back out as the pattern. Opening a rule
	 * and saving it replaced it with a different rule.
	 */
	char     hexs[DECL_HEXS_CAP];   /* the pattern, when bytes cannot say it */
	uint32_t obj;               /* which object it was taken from */
	/*
	 * WHERE THIS MARKER IS SEARCHED FOR - which is not one fact but two,
	 * and conflating them is what made the column go stale.
	 *
	 * `mask0` is where the BYTES CAME FROM: the region row they were
	 * selected in. It never changes, and it is zero for a marker read out
	 * of a source file, which says where to look but not where it was
	 * found.
	 *
	 * `mask` is where the rule ACTUALLY LOOKS, which is the union of the
	 * ranges of the matchers that use it, falling back to mask0 when no
	 * matcher does. It is derived, so it is recomputed rather than
	 * remembered - it used to be filled once while reading a source file,
	 * with `|=`, so it could only ever grow: dropping a scan range left
	 * the column reading "X&Y" about a rule that by then searched neither.
	 */
	uint32_t mask0;
	uint32_t mask;
	char     rgn[24];           /* that region's short name */
	/*
	 * WHICH MATCHERS USE IT - a bit each, not a number.
	 *
	 * It was one matcher per marker, and that made "at least three of these
	 * five, otherwise at least two" impossible to express: the second
	 * matcher had to search the same markers as the first, and they could
	 * only be owned once. A marker is a thing to look for; how many
	 * matchers ask about it is their business, not its.
	 *
	 * Zero means no matcher uses it - what GRP_NONE used to say.
	 */
	uint32_t grp;
	/*
	 * WHICH ADDRESS SPACE `at` AND `hits` ARE IN.
	 *
	 * Zero for the object's bytes, which is what everything here assumed.
	 * SYMN_IMP or SYMN_EXP for a marker scoped to a symbol half, whose
	 * offsets are into the BUILT block and are not file offsets at all.
	 *
	 * Without this, every consumer read a block offset as a file offset:
	 * clicking the row jumped the pane to whatever region sits at that
	 * distance from the start of the file - UNCLAIMED, on the sample this
	 * was found with - and the highlighter lit unrelated bytes at the same
	 * number in a pane the marker is not even in.
	 */
	uint8_t  sym;
	/* Where these bytes are in the object, so the row can jump to them and
	 * the pane can light them. KOF_BROKEN when they are not there at all -
	 * a marker taken from one sample and carried to another. */
	uint64_t at;
	/*
	 * AND EVERYWHERE ELSE IT IS, BECAUSE ONE OF THEM IS NOT THE ANSWER.
	 *
	 * `at` is the occurrence the row reports on - the one inside the region
	 * the module searches, when there is one. The pane lit that one and no
	 * other, so a marker that appears eight times looked like a marker that
	 * appears once, and the seven places worth reading were the seven the
	 * highlight did not point at.
	 *
	 * Kept sorted, and capped: a two byte marker occurs everywhere, and a
	 * list of every offset in a 16 MB object is neither drawable nor worth
	 * drawing. `hits_clipped` says the list is a prefix so the row can say
	 * so rather than imply the count is the whole of it.
	 */
	uint64_t hits[DECL_HITS_MAX];
	/*
	 * AND HOW LONG EACH ONE IS, WHICH IS NOT ONE NUMBER.
	 *
	 * `len` is the SHORTEST a match can be. A pattern with a jump has no
	 * single length - "GET /[4-7].tsunami" covers 17 bytes of "arm5" and 20
	 * of "powerpc" - so lighting `len` bytes at every occurrence cut the
	 * tail off the longer ones, by exactly as much as their jump exceeded
	 * its minimum. The row said "17-20" and the pane lit 17 either way.
	 */
	uint32_t hit_len[DECL_HITS_MAX];
	uint32_t n_hits;
	int      hits_clipped;
	/*
	 * WHICH ONE THE ROW IS POINTING AT.
	 *
	 * Clicking the bytes goes to this one, not to the first: after stepping
	 * to the third occurrence and scrolling away, clicking the row is how
	 * you get BACK to the third. Starting it at the occurrence the row
	 * reports on means the first click still lands where the row says it
	 * will.
	 */
	uint32_t cur_hit;

	/*
	 * How a literal is compared. Both are properties of KOF_DEFINE_STR and
	 * neither exists for a hex pattern - kofsig.h says why: folding case on
	 * a byte that may be a wildcard means nothing, and a word boundary is a
	 * notion of text.
	 */
	int      fullword;
	int      icase;

	/*
	 * The bytes are in the object, but not in the range that searches for
	 * them.
	 *
	 * The one fact that explains a signature which cannot fire however
	 * right it looks, and the panel had no way to say it: the region column
	 * showed the range the matcher DECLARES, so a marker declared in DATA
	 * and actually sitting in CODE read as "DATA, found" on both counts.
	 */
	int      off_rgn;
	char     at_rgn[24];        /* the region it is really in */
	uint32_t at_mask;           /* and that region's bits */
};

/*
 * Can these bytes be the second argument of KOF_DEFINE_STR.
 *
 * Printable ASCII, and that is the whole rule. Three of those bytes cannot be
 * written raw into a C literal - a quote and a backslash end it, and a pair of
 * question marks becomes a trigraph under -std=c11 - so decl_put_literal writes
 * them as \" \\ \?, which ksigbuilder now reads back as themselves.
 *
 * It used to REFUSE those three, and the effect was not a smaller set of
 * literals, it was the wrong kind of marker. A researcher declaring
 * "POST /GponForm/diag_Form?images/ HTTP/1.1" or realm="HuaweiHomeGateway" was
 * offered hex only - a compiled matcher program in place of bytes, unreadable
 * as the string it is in every tool that shows markers - because of one "?" and
 * one quote.
 */
/* A byte that reads as text. The same set literal_safe accepts, kept separate
 * because they answer different questions: this one is about what a person is
 * looking at, that one about what can be written down. */
static int byte_text(uint8_t c)
{
	return c >= 0x20u && c <= 0x7eu;
}

static int literal_safe(const uint8_t *b, uint32_t n)
{
	uint32_t i;

	if (!n)
		return 0;
	for (i = 0; i < n; i++)
		if (b[i] < 0x20u || b[i] > 0x7eu)
			return 0;
	return 1;
}

/*
 * One marker's bytes, as the inside of a C string literal.
 *
 * Only the three that have to be: a quote and a backslash because C would
 * otherwise read the literal differently, and "?" because two of them in a row
 * form a trigraph. Escaping every "?" rather than only the pairs keeps this a
 * property of the byte instead of a property of its neighbour - the pair rule is
 * the kind that is right until somebody edits the string next to it.
 */
static void decl_put_literal(FILE *f, const uint8_t *b, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (b[i] == '"' || b[i] == '\\' || b[i] == '?')
			fputc('\\', f);
		fputc(b[i], f);
	}
}

/* ---- a chooser ------------------------------------------------------------
 *
 * One overlay for every "pick one of these" in the draft panel: the condition's
 * rule, its range, its verdict, the malware type. They are the same interaction
 * four times, and four bespoke popups would be four places to get the click
 * routing wrong.
 */
/*
 * Enough rows for the longest list any menu builds, which is CH_MARKER's: one
 * per declared marker, and MAX_DECL of those. At sixteen, a draft with more
 * than sixteen unused markers simply ended - ch_add drops what does not fit and
 * the list has no scroll - so the markers past the sixteenth could not be put
 * into a matcher from the menu at all. Two spare for the rows a list adds
 * around its items.
 */
#define CH_ITEMS (MAX_DECL + 2)
#define CH_W     38

enum ch_what {
	CH_NONE = 0,
	CH_RULE,        /* find all / any / multi, for a new or existing group */
	CH_RANGE,       /* which declared range a condition searches */
	CH_RANGE2,      /* what to do to the scan ranges */
	/*
	 * And WHICH REGION to apply, when the markers are spread over more
	 * than one. A string sits in exactly one region, but a matcher holds
	 * several strings and they need not agree - so "where the bytes are"
	 * can be two answers, and applying their union silently is deciding
	 * for the reader that they wanted both.
	 */
	CH_RANGE4,
	CH_RANGE_ADD,   /* which region to declare as a new range */
	CH_RANGE_EXT,   /* which region to extend the subject range with */
	CH_RANGE_DROP,  /* which region to drop off the subject range */
	CH_LEVEL,       /* infect or suspect */
	CH_VARIANT,     /* how the finding names itself */
	CH_TYPE,        /* enum kof_maltype */
	CH_MARKER,      /* which unused marker to put in a matcher */
	CH_THRESH,      /* how many of the matcher's markers must be present */
	CH_OPT,         /* which optional declaration to add */
	CH_ARCH,        /* enum kof_arch, all of it */
	CH_SUBTYPE,     /* the format's subtypes, all of them */
	CH_WORD,        /* fullword or substring */
	CH_CASE,        /* case sensitive or not */
	CH_CMATCH,      /* which matcher to put into a condition */
	CH_SWITCH,      /* what to do about unsaved work before switching */
	CH_LOGIC        /* how the next condition at this level attaches */
};

struct chooser {
	int      open;
	int      row, col;
	int      what;
	uint32_t arg;               /* which group it is about */
	int      n, sel;
	uint32_t arg2;              /* the narrowest range, for CH_RANGE */
	char     item[CH_ITEMS][CH_W];
	/*
	 * WHAT EACH ROW DOES, carried rather than derived from its index.
	 *
	 * The range menu used to read the verb off c->sel, which holds only
	 * while every verb is always offered. It is not: switching a range
	 * away is refused when markers still live in it, and a list that drops
	 * a row silently renumbers every row after it - so picking "Extend"
	 * would have carried out "Switch". Written where the row is built,
	 * read where it is carried out, and the two cannot drift.
	 */
	uint8_t  verb[CH_ITEMS];
	/*
	 * WHICH ROWS OPEN ANOTHER LIST, marked the way the menu bar marks it:
	 * a ">" at the item's far edge (see bar_has_sub and the draw beside it),
	 * not a suffix on the text. Without it a row that opens a list and a row
	 * that acts are indistinguishable until one is pressed, and one of them
	 * appears to do nothing.
	 */
	uint8_t  sub[CH_ITEMS];
};


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
	void     *mapped;           /* or a spill file, mapped instead of copied */
	uint64_t  mapped_len;
	int       too_big;          /* kept nowhere: past the session's budget */
	kof_buf   buf;
	uint32_t  depth;            /* how many "//" its name carries */

	const struct kof_inspect_fmt *fmt;
	struct kof_obj_ctx            ctx;
	void                         *info;

	char            **finding;
	uint32_t          n_finding;
	char              packer[48];   /* the module that opened or unpacked it */
	/*
	 * The interpreter has already been run on this object.
	 *
	 * Asking twice cannot produce a different answer - the bytes have not
	 * changed and the run is deterministic - so a second press appended a
	 * second identical set of children, and a third a third. Recorded per
	 * object because the question is per object.
	 */
	int               emu_done;
	/*
	 * What the scanner's own gate makes of this object, when no module
	 * claimed it: KOF_EMU_UNP_* . Computed once beside the parse rather
	 * than while drawing - it reads every executable segment, and the
	 * status line is repainted on every keystroke.
	 */
	uint8_t           emu_why;
	/*
	 * The version that module read out of the object, or -1 for none.
	 *
	 * Signed and not a flag beside a uint, because 0 is a version a container
	 * can carry and "it never said" has to be a different answer from "it
	 * said zero".
	 *
	 * It is the FORMAT version the module found in the file - UPX's l_info
	 * byte, RAR's archive version - and not the packer's release. The two get
	 * confused, so nothing here pretends to know that a UPX l_info of 13
	 * means UPX 3.9x: the module reported a field called version and this
	 * shows the field.
	 */
	long long         packer_ver;
	/* What the engine said about this object, kept whole. */
	struct kof_result heur;
	/*
	 * Whether the engine got to the end of THIS object, and what stopped it.
	 *
	 * Kept per object rather than for the file, because it is per object: a
	 * container that opened may hold one entry it could not, and the packed
	 * parent being incomplete says nothing about the child that came out of
	 * it. enum kof_broken, KOF_BROKEN_NONE when it finished.
	 */
	uint32_t          broken;
	struct kof_touch *touch;
	uint32_t          n_touch;

	/*
	 * The object's symbol records, in the KSYM layout kofsym.h fixes.
	 *
	 * Built ONCE, when the object is parsed, and right-sized: the cap is
	 * 4096 records and a scratch of that size for each of MAX_OBJ objects
	 * would be thirty megabytes held to show a table nobody may open, while
	 * the real counts are tens to a few thousand. NULL and zero for a file
	 * with no symbols and for every non-ELF - which is a normal answer, not
	 * a failure, so nothing downstream treats it as one.
	 */
	/*
	 * THE OBJECT'S SYMBOL BLOCK - the engine's, one copy, unsplit.
	 *
	 * It used to be two blocks that this file built by copying records out
	 * of the engine's according to their UNDEFINED flag. That was a second
	 * implementation of "which half is this symbol in", and it disagreed
	 * with the engine's: the engine coalesces adjacent records of one half
	 * into runs, so a pattern is never matched across a record of the other
	 * half, while a copied half joins records the engine keeps apart. On
	 * 23.8% of files the halves interleave, so the two really did answer
	 * differently.
	 *
	 * Now the block is whatever kof_syms_build returned and the halves are
	 * kof_sym_extents' answer - the same call kof_find_str makes.
	 */
	uint8_t          *sym;
	uint32_t          sym_n;

	/* The address a heuristic named as a carried payload, and its length, or
	 * zero when none did. Reported through kof_debug - see on_debug. */
	uint64_t          payload_at;
	uint64_t          payload_len;
	/* Set on the CHILD this viewer built from a parent's payload, so the
	 * menu can find it without inferring anything from the name. A name
	 * test alone would also match an unpacker's child that happened to sit
	 * under the same parent. */
	int               payload_of;
	/*
	 * WHICH VARIABLE IT CAME OUT OF, and what was wrapped round it.
	 *
	 * Kept on the child rather than left in its name: the name says what
	 * the object is, and the symbol is a fact about where in the PARENT it
	 * was found. A reader wants both, and only one of them belongs in a
	 * tree row eighteen columns wide.
	 */
	char              payload_sym[KOF_SYM_NAMELEN + 1];
	int               payload_b64;
};

/*
 * A row in the left pane.
 *
 * Objects and regions in one list rather than two trees: they are drawn as one
 * column, moved through with one cursor, and the only thing that differs is what
 * selecting one means. `depth` is what makes it a tree on screen - a region is
 * always one level inside the object that has it.
 */
/* Which of the two symbol blocks a tree row names. Not a bool any more: there
 * are two, they are a partition, and a row has to say which half it is. */
#define SYMN_IMP 1u
#define SYMN_EXP 2u

struct node {
	char     label[48];
	uint32_t depth;
	uint32_t obj;               /* which object this row belongs to */
	uint32_t mask;              /* the region, or 0 when the row IS the object */
	/*
	 * The symbol row is not a region and cannot be spelled as one: a region
	 * is an extent of the FILE, and these records are built rather than
	 * pointed at. So it gets a flag of its own instead of a reserved mask
	 * value - a sentinel mask would have to be excluded by hand everywhere a
	 * mask is resolved, and every place that forgot would resolve it as a
	 * real region and show the wrong bytes.
	 */
	uint8_t  sym;               /* 0 none, or SYMN_IMP / SYMN_EXP */
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

	/*
	 * WHAT SURVIVES A FILE SWITCH.
	 *
	 * Opening the next file used to re-exec this program, because the view
	 * is full of pointers whose lifetime is one file and unpicking them by
	 * hand is how a stale one gets left behind. Re-execing also threw away
	 * the database, and loading it is most of what starting costs - so
	 * every step through a directory paid for a load nobody asked for.
	 *
	 * These four are the state that belongs to the SESSION rather than to
	 * the file. file_open keeps exactly them and clears everything else, so
	 * a field added to this struct is cleared by default: the failure mode
	 * of forgetting one is a reset panel, not a pointer into a file that is
	 * no longer mapped.
	 *
	 * `pathbuf` exists because `path` used to point into argv, which is
	 * fine for a path that never changes and wrong the moment one does.
	 */
	kof_engine *eng;
	char        dbdir[256];
	char        pathbuf[KOF_DUMP_PATH_ROOM];

	struct object obj[MAX_OBJ];
	uint32_t      n_obj;

	/*
	 * THE GENERATED BLOCK'S CONTENTS, CARRIED ACROSS A LOAD AND A SAVE.
	 *
	 * A rule is written once and then tested again, against a second sample
	 * and a third. The block used to hold one "Test sample" line and the
	 * save rewrote it, so testing an existing rule against a new file
	 * ERASED the record of what it had been tested against before - the one
	 * fact in the file that cannot be recovered from anywhere else. The
	 * samples accumulate now, and so do the names of the people who wrote
	 * them.
	 *
	 * `made` is the date the block was first written, kept from whatever is
	 * already in the file; a save only ever sets the "updated" date. Empty
	 * means this rule is new and today is both.
	 */
	/* 128, because samples are routinely named by their hash: a 64 character
	 * digest plus the collection's suffix is 82, and 80 cut it mid word. */
	char        meta_sample[MAX_META][128];
	uint32_t    n_meta_sample;
	char        meta_who[MAX_META][48];
	uint32_t    n_meta_who;
	char        meta_made[24];

	/*
	 * Lines of kof_scan this panel cannot hold - see body_modelled.
	 *
	 * Not an error and not a parse failure: the file is a valid module, and
	 * the draft beside it is a truthful view of the part that IS modelled.
	 * What it costs is the right to write the file back, because writing it
	 * back would write only that part.
	 */
	uint32_t    foreign;

	char        pending[48];    /* the unpacker that has just spoken */
	long long   pending_ver;    /* and the version it reported, or -1 */
	/*
	 * WHERE A HEURISTIC SAID THE PAYLOAD IS, held the same way and for the
	 * same reason: a rule reports it while the object is being opened, so
	 * it arrives before the object does and has to wait for it.
	 *
	 * The ADDRESS, not the record index - see the note in
	 * bases/heur/scloader_00.c. That is what lets the symbols dialog find
	 * the row without knowing anything about how the rule found it: the
	 * dialog compares each record's own value, and nothing here has to
	 * repeat the test the rule made.
	 */
	uint64_t    pend_payload;
	uint64_t    pend_paylen;

	struct node node[MAX_TREE];
	uint32_t    n_node, sel_node, tree_top;

	struct kof_range *ext;
	uint32_t          n_ext;
	/*
	 * A second extent buffer, for asking about a region that is not the one
	 * being looked at.
	 *
	 * `ext` describes the selected node and the hex pane maps every byte
	 * through it. A lookup that resolved some other region into it left the
	 * pane mapping through extents that belonged to nothing it was showing
	 * - every offset came back as the start of the file, so declaring a
	 * string turned the whole pane into byte zero repeated. A question
	 * about another region gets its own paper.
	 */
	struct kof_range *probe;
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

	/*
	 * THE DISASSEMBLY PANEL.
	 *
	 * `dis_open` is the panel; `dis_bits` is 32 or 64, because raw shellcode
	 * carries no header to say which and the answer changes what the same
	 * bytes mean - a payload unpacked out of a Metasploit encoder is bytes
	 * and nothing else. It is seeded from the object's architecture when
	 * there is one and left for the reader to change when there is not.
	 *
	 * `dis_at`/`dis_len` pin the panel to a RANGE the reader chose, and
	 * KOF_BROKEN in dis_len means it is not pinned: it follows the hex
	 * scroll instead. Both are region offsets, like every other position in
	 * this view.
	 */
	int         dis_open;
	int         dis_bits;
	uint64_t    dis_at, dis_len;

	/*
	 * A selection of LINES in the panel, and the text each one printed.
	 *
	 * Lines rather than characters, because an instruction is the unit
	 * somebody copies: half of a MOV pasted into a note is not a smaller
	 * answer, it is a wrong one. Held as row indices from the top of the
	 * panel, and -1 when nothing is selected.
	 *
	 * The text is kept because the panel is redrawn from the bytes every
	 * frame and the copy has to be of what was on screen - decoding it a
	 * second time at copy time would be a second decoder to disagree with
	 * the first, in exactly the case where the reader is looking at the
	 * output of the first.
	 */
	/*
	 * A TEXT SELECTION, character by character, the way one behaves
	 * anywhere else: an anchor where the press landed and a cursor where the
	 * pointer is, each a row and a column into the panel's own rows.
	 *
	 * It was whole lines, and whole lines are wrong for the same reason a
	 * hex selection is not whole rows: the reader picks what they mean to
	 * copy, and an operand or a mnemonic on its own is a thing people take.
	 *
	 * dis_have is 0 when nothing is selected.
	 */
	/*
	 * ANCHORED TO BYTES, NOT TO ROWS.
	 *
	 * Each end is the file offset of the instruction its row starts at, plus
	 * a column within that row's text. Row indices were tried and are wrong
	 * for one reason: they go stale the moment the panel scrolls, so row 3
	 * stayed lit while row 3 became a different instruction - and scrolling
	 * away and back lost the selection entirely. A byte offset means the
	 * highlight belongs to the instruction, which is what the reader picked.
	 */
	uint64_t    dis_a_at, dis_b_at;
	int         dis_ac, dis_bc;
	int         dis_have;           /* anything selected at all */
	int         dis_dragging;


	/*
	 * WHAT THE PANEL IS READING FROM when it is not pinned.
	 *
	 * See dis_follow_hex for the rule that sets it, and dis_seen_* for what
	 * it last saw of the two things that can move it.
	 */
	uint64_t    dis_follow;
	/*
	 * HOW FAR THE PANEL SITS FROM THE HEX SCROLL, and it is a CONSTANT.
	 *
	 * The panel reads from rgn_at + dis_bias, so scrolling the hex moves it
	 * by exactly as much - the two are locked together whatever the bias is.
	 * Selecting bytes is what sets the bias: enough to bring the selected run
	 * onto these rows. Nothing else changes it, so scrolling away and back
	 * puts the selection back where it was.
	 *
	 * This replaced four attempts that each tied the panel's POSITION to the
	 * selection instead of to the scroll. Every one of them broke one of the
	 * two things asked of it - either the panel stopped following the scroll,
	 * or the highlight left the rows and did not come back. A bias is the
	 * thing that was missing: an offset can satisfy both because it is not a
	 * position at all.
	 */
	int64_t     dis_bias;

	/*
	 * WHO SET THE BYTE SELECTION, and it has to be recorded because the
	 * sync runs both ways.
	 *
	 * The panel follows the hex selection, and picking lines in the panel
	 * SETS that selection - so without this the panel followed itself: a
	 * click on a line moved the selection, the selection moved the panel's
	 * start, and the row under the pointer was no longer the row that had
	 * been clicked. The hex pane does not scroll to a selection, so the two
	 * came apart as well.
	 *
	 * One flag, and the rule it encodes: a selection made HERE does not move
	 * this panel. A selection made in the hex pane does.
	 */
	int         sel_from_dis;
	char        dis_line[64][120];
	/*
	 * The bytes each drawn line stands for.
	 *
	 * Kept so that a selection made in the panel can be turned back into a
	 * byte range - which is what lets the hex pane's own menu items work on
	 * it unchanged. Selecting three instructions and declaring them as a
	 * marker is the same act as selecting their bytes, and it should not
	 * need a second implementation to say so.
	 */
	uint64_t    dis_line_at[64], dis_line_len[64];
	int         dis_lines;

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

	/* Which half of the hex pane the menu was opened on. */
	int         menu_ctx;       /* 1 bytes, 2 the offset column */
	uint64_t    menu_off;       /* the row offset it was opened on */

	int         menu_open, menu_row, menu_col, menu_sel;
	struct chooser ch;

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
	uint32_t    tree_hoff, list_hoff, decl_hoff;

	/* The region column's width for this frame - see draw_decl. */
	int         rgn_w;

	struct decl  decl[MAX_DECL];
	uint32_t     n_decl, sel_decl;

	/*
	 * A string being edited, as text.
	 *
	 * The declaration holds bytes, and bytes are not what somebody types. A
	 * literal is typed as the characters it is - not as the escaped spelling
	 * the generated source carries, because the escaping is the file
	 * format's business and typing \x41 to mean A is asking the reader to
	 * be a compiler. A hex pattern is typed as spaced pairs, the way the
	 * source reads, which is also what leaves room for the things bytes
	 * cannot express: ?? for a wildcard, [n-m] for a gap, (a|b) for a
	 * choice.
	 *
	 * So the text lives here while it is being edited and is parsed back
	 * into the declaration when the field closes. `sedit_ok` is cleared when
	 * the text cannot be parsed, so the row can say so without the panel
	 * having to guess.
	 */
	char         sedit[DECL_HEXS_CAP];
	uint32_t     sedit_off;     /* how far the field is scrolled */

	struct range rng[MAX_RANGE];
	uint32_t     n_rng, cur_rng;

	struct group grp[MAX_GROUP];       /* matchers */
	uint32_t     n_grp, cur_grp;

	struct cond  cnd[MAX_GROUP];
	uint32_t     n_cnd, cur_cnd;
	char         warn[120];     /* why the last add was refused */
	/*
	 * What the last ACTION did, wherever it was asked for.
	 *
	 * Its own slot rather than `warn`, which is scoped to the draft panel
	 * having focus. A copy is almost always made from the hex pane and a
	 * dump is asked for from the menu bar, so put in `warn` the one message
	 * that exists to prove something happened was itself invisible.
	 *
	 * One slot for both because they are one thing to a reader - the last
	 * thing I asked for, and how it went - and two would mean deciding which
	 * of them wins on a screen that can only show one.
	 */
	char         act_msg[160];
	int          act_ok;        /* whether it did what was asked */
	int          warn_bad;      /* 1 it failed, 0 it is only worth knowing */

	/*
	 * What the finished module will declare about itself.
	 *
	 * The type is cycled rather than typed because it is an enum the build
	 * checks - ksigbuilder refuses a word that is not in its table, and a
	 * text box that can produce a build error is a text box that should have
	 * been a list. The other two are free text and belong to whoever is
	 * writing the signature.
	 */
	int         opt_on[OPT_COUNT];
	uint64_t    opt_val[OPT_COUNT];

	char        family[64];
	uint32_t    maltype;
	char        basedir[256];

	/*
	 * How the conditions combine, written the way ClamAV writes it: numbers
	 * for conditions, & and |, parentheses. Free text because the shapes
	 * people want are not a menu - "1&2", "(1&2)|3" - and because an empty
	 * one has an obvious meaning worth keeping as the default: every
	 * condition, joined by &.
	 */
	char        expr[96];

	int         edit;           /* 0 none, 1 family, 2 variant */
	int         gen_ok;
	/*
	 * WAS THIS DRAFT READ OUT OF A SIGNATURE THAT ALREADY EXISTS.
	 *
	 * Set by draft_show on BOTH of its paths - the .c source when it can be
	 * found, the database when it cannot - because either way the reader is
	 * looking at a rule somebody already wrote, not writing one. gen_path
	 * cannot answer this: it is only set on the source path, so a rule
	 * loaded from the database (which is the usual case, since --bases has
	 * to point at the tree for the source to be found) looked exactly like
	 * a fresh draft.
	 *
	 * What it changes is what a marker's colour MEANS - see the region
	 * column in draw_decl.
	 */
	int         from_rule;
	char        gen_path[600];

	/* Where the header's controls landed, recorded as they are drawn. */
	int         f_c0, f_c1, t_c0, t_c1, v_c0, v_c1, g_c0, g_c1;
	int         n_c0, n_c1;     /* the "+ condition" button */
	int         sv_c0, sv_c1;   /* "Save As", when there is a file */
	int         nw_c0, nw_c1;   /* "New" - empty the panel */
	int         nt_c0, nt_c1;   /* the module's own note */
	int         nt_len, nt_room;/* its length and the width it is shown in */
	int         grp_len[MAX_GROUP], grp_room[MAX_GROUP];
	int         rng_c0, rng_c1, m_c0, m_c1, s_c0, s_c1, e_c0, e_c1;
	/*
	 * WHERE EACH RANGE NAME IS ON THE SCAN RANGES ROW.
	 *
	 * The row used to carry one [Update scan range] button that acted on
	 * "a range" and then asked which. Now the NAME is the control: clicking
	 * one opens a menu whose subject is that range, so the question "which"
	 * is answered by where the reader pressed instead of by another list.
	 * Parallel to the order rng_all produces, which is the order they are
	 * drawn in.
	 */
	int         rng_hs[2 * MAX_GROUP][2];
	uint32_t    n_rng_hs;
	int         rga_c0, rga_c1; /* "[+ Add scan range]" at the row's end */
	int         rgf_c0, rgf_c1; /* "Update string regions" - where they are */
	uint32_t    rng_mask;       /* the region the range menu was built on */
	/*
	 * Ranges the draft declares that no matcher names yet.
	 *
	 * A range normally has no existence apart from a matcher naming one,
	 * which is why the summary row derives itself. "Add CODE to scan
	 * ranges" breaks that for as long as it takes to give the range a
	 * matcher - so it is held here, listed as unused, and refused at save
	 * time rather than turned into an empty matcher nobody asked for.
	 */
	uint32_t    rng_add[MAX_GROUP];
	uint32_t    n_rng_add;
	/*
	 * The list a submenu came out of, kept so it can stay on screen.
	 *
	 * A submenu that replaces its parent is not beside it, it is instead of
	 * it - and the reader loses the line they were acting on at the moment
	 * they are asked to qualify it.
	 */
	struct chooser ch_up;
	int         a_c0, a_c1, b_c0, b_c1, o_c0, o_c1;
	/*
	 * "[+ String]" - ONE PAIR PER MATCHER, because its column depends on
	 * how many marker ids that matcher's row already printed. A single
	 * shared pair was overwritten by every row in turn, so only the last
	 * matcher's button answered a click and the earlier rows' buttons were
	 * dead while blank space at the last row's column was live.
	 */
	int         p_c0[MAX_GROUP][2];
	int         opt_c0[OPT_COUNT], opt_c1[OPT_COUNT];

	/*
	 * The panel's rows, listed once and used twice.
	 *
	 * Drawing walked this shape and the click router walked it again, and
	 * keeping two copies of one walk in step is a thing that fails quietly:
	 * a row added to one and not the other sends every click below it to
	 * the wrong control. Built once per frame, indexed by both.
	 */
	uint8_t     prow_kind[MAX_PROW];
	uint32_t    prow_idx[MAX_PROW];
	uint32_t    n_prow, prow_off;
	/*
	 * How many draft rows the panel is allowed to show, and whether the
	 * divider is being dragged.
	 *
	 * A cap rather than a height, because the panel still shrinks to fit a
	 * short draft: a researcher who drags the divider down is saying how
	 * much room the draft may take, not demanding that much blank space
	 * while it is empty.
	 */
	uint64_t    last_click;     /* the byte a click landed on */
	uint64_t    last_click_ms;  /* and when, so a second one can pair */
	uint32_t    decl_cap;
	uint32_t    prow_seen;      /* how tall the draft was last frame */
	uint32_t    saved_hash;     /* what the draft was when it was written */
	uint64_t    obj_held;       /* bytes of recovered objects being kept */
	int         sizing;
	/*
	 * Which scrollbar the pointer took hold of, so a drag keeps moving that
	 * one after the pointer has left its column. A bar that only responds
	 * while the pointer stays inside a single column is a bar nobody can
	 * drag.
	 */
	int         bar_drag;       /* 0 none, 1 hex, 2 tree, 3 draft */
	/*
	 * WHICH UNPACKER FILLED THE TREE ON SCREEN.
	 *
	 * Zero is the static unpackers, which is what opening a file uses and
	 * what a reader should get without asking: they read structure, they
	 * are fast, and where one applies it is the better answer. One is the
	 * interpreter, in place of them.
	 *
	 * NOT kept when the file changes, unlike basedir and dbdir. It is a
	 * question asked about ONE object - "what does this look like if it is
	 * run instead of read" - and carrying the answer to the next sample
	 * means every step through a directory pays for an interpretation
	 * nobody asked for, which on a large object is tens of seconds. So
	 * stepping to another file starts over on the static unpackers, and the
	 * researcher who wants the other answer asks for it again.
	 */
	int         emu_mode;

	/* Set while a sub-scan runs: swallow its echo of the object it was
	 * given. See on_object. */
	int         skip_root;

	/* Which top-level item's submenu is showing, -1 for none. */
	int         bar_sub;

	int         bar_open;       /* which menu is down, -1 for none */
	int         bar_sel;        /* the item under the pointer or the cursor */
	int         help_open;      /* 0 none, 1 keyboard, 2 about */
	int         prop_open;      /* the properties page is up */
	uint32_t    prop_off;       /* the first of its lines on screen */
	int         prop_x0, prop_x1, prop_y;   /* its close control */
	/*
	 * "[Copy full path]" on the folder row: which row carries it and which
	 * of that row's columns it occupies, or -1 when the page has no such
	 * row at all.
	 *
	 * Recorded per BUILD rather than per frame because the page scrolls -
	 * the row's index in g_prop is fixed, its position on the screen is
	 * not, so the click converts one to the other with prop_off the way the
	 * select path already does.
	 */
	int32_t     prop_cp_row;
	int         prop_cp_x0, prop_cp_x1;
	/*
	 * WHAT IS SELECTED ON THE PAGE, WHICH IS NOT THE SAME AS WHAT WAS CLICKED.
	 *
	 * Clicking used to copy outright, and that is the wrong gesture: a reader
	 * clicks to look, and a click that reaches outside the program and changes
	 * the clipboard is a side effect nobody asked for. Selecting shows what
	 * would be taken and lets it be adjusted; Ctrl+C is when they say to take
	 * it. Same two steps the hex pane already uses, for the same reason.
	 *
	 * Columns index the line's PLAIN text - what prop_plain produces - so the
	 * range means the same thing to the painter and to the copier.
	 */
	int32_t     prop_sel_row;               /* -1 when nothing is selected */
	int32_t     prop_sel_a, prop_sel_b;     /* inclusive, may be reversed */
	/*
	 * Where the mouse went DOWN, which is not where the selection starts.
	 *
	 * A click selects the whole word under it, so the selection's ends are
	 * the word's ends. Dragging must grow from the point that was clicked,
	 * not from whichever end the word happened to put there - otherwise
	 * pulling back over the word does nothing until the pointer passes its
	 * far edge, which is what made dragging feel broken.
	 */
	int32_t     prop_anchor;
	int         prop_dragging;
	/*
	 * What is being searched for, and where it was last found.
	 *
	 * `scope` is the one thing a terminal cannot give a modifier for:
	 * Ctrl+Shift+F arrives as the same byte as Ctrl+F on every terminal
	 * that does not implement the newer key protocols, so the choice
	 * between this region and the whole object is made inside the prompt
	 * with Tab rather than by a chord that most terminals cannot send.
	 */
	char        find[80];
	int         find_open;      /* the dialog is up */
	/*
	 * GO TO: an offset typed in, and where it is measured from.
	 *
	 * Its own flag and buffer rather than the find dialog's, because the two
	 * take different things - find takes bytes to look for, this takes one
	 * number - and sharing the field meant a half-typed search turning into
	 * an offset. `goto_file` says whether the number is a FILE offset or an
	 * offset into the region being looked at: both are what somebody means
	 * by "offset" depending on what they are reading, and the hex pane shows
	 * region offsets while every report and every finding names file ones.
	 */
	int         goto_open;
	/*
	 * THE SYMBOLS DIALOG: which half it is showing, and how far down.
	 *
	 * Zero when closed, otherwise SYMN_IMP or SYMN_EXP - one field rather
	 * than an open flag beside a mode, because those two can disagree and
	 * "open, showing neither" is a state that has to be drawn as something.
	 *
	 * The scroll is its own, not the pane's: the dialog is a table of
	 * records and the pane behind it is a table of bytes, and sharing one
	 * offset made opening the dialog jump the pane.
	 */
	/*
	 * The shellcode dialog: open, and how far down its byte dump is.
	 *
	 * Separate from the symbols dialog's fields even though the two look
	 * alike, because they can be open over each other and a shared offset
	 * would move one when the other scrolled.
	 */
	/*
	 * A DIALOG'S TEXT, AND THE CHARACTERS SELECTED IN IT.
	 *
	 * One set of fields for both dialogs, because only one of them can be
	 * selected in at a time - the boxes are modals, and the topmost owns
	 * the mouse. Two sets would be two things to keep in step for no gain.
	 *
	 * dlg_y0/dlg_x0 are where row 0, column 0 of the recorded text sits on
	 * screen, so a click can be turned into a (row, column) in the text
	 * without the click routing knowing how the box is laid out.
	 *
	 * The anchor is where the drag started and is NOT normalised: a
	 * selection dragged upwards has b before a, and normalising on the way
	 * in would make the anchor move as the pointer does. It is ordered when
	 * it is read, in dlg_span.
	 */
	char        dlg_line[DLG_ROWS][DLG_COLS];
	int         dlg_rows;
	int         dlg_y0, dlg_x0;
	int         dlg_ar, dlg_ac, dlg_br, dlg_bc;
	int         dlg_have;
	int         dlg_drag;

	uint8_t     sym_open;
	uint64_t    sym_at;
	/*
	 * How far the table is scrolled SIDEWAYS, in columns of the unclipped
	 * row. Its own field beside sym_at rather than a shared "scroll",
	 * because the two axes clamp against different limits: a table that
	 * fits vertically may still not fit across.
	 */
	int         sym_hoff;
	int         sy_close[2];        /* the close button */
	int         sy_tab[2][2];       /* [imports|exports], each a box */
	int         goto_file;      /* 1 file offset, 0 offset in this region */
	char        gotobuf[20];
	int         find_hex;       /* the text is hex digits, not bytes */
	int         find_icase;     /* letters compare either way; text only */
	int         find_regex;     /* declared, refused: see draw_find */
	int         find_scope;     /* 0 this region, 1 the whole object */
	uint64_t    find_at;        /* the last hit, in file offsets */
	uint32_t    find_i, find_n; /* which hit it is, and how many there are */
	uint32_t    find_off;       /* how far the field is scrolled */
	uint32_t    goto_off;       /* the same, for the Go to field */
	int         g_txt[2], g_mode[2], g_go[2], g_cancel[2];
	/* One offset per field that can hold more than it shows. Separate
	 * because they scroll independently: a caret in one says nothing about
	 * where another is being read from. */
	uint32_t    fam_off, num_off;
	uint32_t    cnd_off[MAX_GROUP], cnd_eoff[MAX_GROUP];
	/* The search's own message. Shared with the draft panel's it produced
	 * a bare "not found" beside the Generate button, which is an answer to
	 * a question that panel never asked. */
	char        find_msg[64];
	/* Where each control landed, recorded as it is drawn. */
	int         f_txt[2], f_mode[2], f_rx[2], f_ic[2], f_all[2];
	int         f_next[2], f_back[2], f_cancel[2];

	char        num[24];        /* the size being typed */
	int         num_fresh;      /* nothing typed into it yet */
	int         row_cnd, row_str;
	int         cnd_lv[MAX_GROUP][2], cnd_vr[MAX_GROUP][2];
	int         cnd_nm[MAX_GROUP][2];
	/* The comment boxes, and the condition's own "+ matcher". Recorded per
	 * row as they are drawn, because a row that is scrolled out has no
	 * columns and must not answer a click meant for the one in its place. */
	int         grp_nt[MAX_GROUP][2];
	/* Where a string row's word/case block and its bytes were drawn. Read
	 * back rather than assumed: the columns move when a field widens, and
	 * a click routed by a remembered number goes to the wrong control. */
	int         str_wc[MAX_DECL][2], str_by[MAX_DECL][2];
	int         grp_rl[MAX_GROUP][2], grp_rg[MAX_GROUP][2];
	int         grp_th[MAX_GROUP][2];
	int         cnd_kid[MAX_GROUP][2];
	int         cnd_jn[MAX_GROUP][2], cnd_op[MAX_GROUP][2];
	uint8_t     cseq_kind[4 * MAX_GROUP];
	uint32_t    cseq_idx[4 * MAX_GROUP];
	uint32_t    n_cseq;
	int         cnd_id0[MAX_GROUP];   /* where its matcher ids start */
	/*
	 * And where its TYPED EXPRESSION box is, when the condition carries one
	 * that is not a plain list of ids.
	 *
	 * The box was drawn with a focus colour and the keys to edit it were
	 * wired (edit band 103+i), but nothing recorded a click range and
	 * nothing ever set that band - so a rule loaded from source with an
	 * expression like "(1&2)|3" showed a field that could not be focused or
	 * typed into by any means.
	 */
	int         cnd_ex[MAX_GROUP][2];
	int         cnd_mt[MAX_GROUP][2];
	int         row_rng, row_grp;
	int         pane;           /* 0 tree, 1 hex, 2 markers, 3 draft */
	/*
	 * What the module says about itself, beside the family and the type.
	 *
	 * The two that are already there are a name and an enum; this is the
	 * sentence neither can hold - which family this really belongs to, why
	 * the type was chosen, what the sample was. Written into the generated
	 * source above the declarations, where the next reader meets it before
	 * any of the logic.
	 */
	char        note[512];
	/*
	 * How far the comment is scrolled inside its own box.
	 *
	 * Its own, not the panel's: the box is one field on a row of fields and
	 * sliding the whole row to read the end of it would take the buttons
	 * off the screen. Follows the caret while the field is being typed
	 * into, so what is being written is always the part on show.
	 */
	uint32_t    note_off;
	/*
	 * Where the caret is in whatever field is being typed into, and which
	 * field that was last time round.
	 *
	 * One caret because only one field is ever open. Comparing the field
	 * against last frame's is how it gets placed at the end of the text
	 * when a field is opened, without every place that opens one having to
	 * remember to say so.
	 */
	uint32_t    caret;
	int         edit_prev;
	/*
	 * The whole field is selected, so the next thing typed replaces it.
	 *
	 * A one line field has nowhere to draw a range, so "selected" is all or
	 * nothing and is shown by reversing the field. That is what Ctrl+A means
	 * here and what every dialog box does with it.
	 */
	int         field_all;
	int         per;            /* bytes a hex row shows, for click mapping */
};

static struct object *cur_obj(struct view *v)
{
	return &v->obj[v->node[v->sel_node].obj];
}

/* Names a region mask - defined with the range menu it belongs to, declared
 * here because locating a string needs it to say where the string turned up. */
static void rng_name_of(const struct kof_inspect_fmt *fmt, uint32_t mask,
			char *out, size_t cap);

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
	/*
	 * A scan of one object's bytes reports that object first, and it is
	 * already in the tree - it is the row the reader picked. Dropped here
	 * rather than filtered by name, because two objects can share a name
	 * and only this one is the echo.
	 */
	if (v->skip_root) {
		v->skip_root = 0;
		return 0;
	}
	o = &v->obj[v->n_obj];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name);
	o->packer_ver = -1;
	o->broken = res->broken;
	/*
	 * The heuristic, as the ENGINE computed it.
	 *
	 * Copied rather than reconstructed. This panel used to build its own
	 * facts out of what it could see - the tree depth, the module name it
	 * had been handed - and that was a second implementation of the
	 * engine's, which drifted the moment the engine learned to tell a
	 * packer from a container.
	 */
	o->heur = *res;
	if (v->pending[0]) {
		snprintf(o->packer, sizeof o->packer, "%s", v->pending);
		o->packer_ver = v->pending_ver;
		v->pending[0] = 0;
		v->pending_ver = -1;
	}
	/* Cleared as it is taken, whether or not anything reported one, so a
	 * payload named on one object can never be shown against the next. */
	o->payload_at  = v->pend_payload;
	o->payload_len = v->pend_paylen;
	v->pend_payload = v->pend_paylen = 0;
	for (p = name; (p = strstr(p, "//")) != NULL; p += 2)
		o->depth++;

	/*
	 * The top level is already mapped; anything else exists only inside
	 * this call and has to be kept if it is to be looked at.
	 *
	 * Kept three ways, by size. Small children go on the heap, which is
	 * every child in practice. A large one is spilled to a temporary file
	 * and mapped, so the pages it is not being looked at cost nothing -
	 * a hex pane shows twenty rows however big the object is, and holding
	 * a decompressed installer resident to show twenty rows of it is how a
	 * viewer gets killed by an archive somebody chose.
	 *
	 * Past a total budget nothing more is kept at all. Those objects were
	 * still scanned - that happened before this is called - so nothing is
	 * missed; they simply cannot be browsed, and the tree says so.
	 */
	if (o->depth == 0 && v->map && len == v->map_len) {
		o->buf = kof_buf_make(v->map, len);
	} else if (v->obj_held + len > OBJ_BUDGET) {
		o->buf = kof_buf_make(NULL, 0);
		o->too_big = 1;
	} else if (len >= OBJ_SPILL) {
		char tmp[] = "/tmp/kofviewerXXXXXX";
		int fd = mkstemp(tmp);

		if (fd < 0)
			return 0;
		unlink(tmp);            /* it lives only as long as the fd */
		if (write(fd, bytes, (size_t)len) != (ssize_t)len) {
			close(fd);
			return 0;
		}
		o->mapped = kof_map_file_ro(fd, len);
		close(fd);
		if (!o->mapped) {
			o->buf = kof_buf_make(NULL, 0);
			o->too_big = 1;
		} else {
			o->mapped_len = len;
			o->buf = kof_buf_make(o->mapped, len);
			v->obj_held += len;
		}
	} else {
		o->own = malloc((size_t)len);
		if (!o->own)
			return 0;
		memcpy(o->own, bytes, (size_t)len);
		o->buf = kof_buf_make(o->own, len);
		v->obj_held += len;
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
static void on_debug(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct view *v = user;
	const char *dot = strrchr(what, '.');
	size_t n = dot ? (size_t)(dot - what) : strlen(what);
	/* Computed once. The engine hands the field's id with every note, so
	 * picking the one field this cares about is an integer compare rather
	 * than finding a dot and running strcmp per note per object. */
	static uint32_t f_version, f_payload, f_paylen;

	if (!f_version) {
		f_version = kof_fact_id("version");
		f_payload = kof_fact_id("payload");
		f_paylen  = kof_fact_id("length");
	}

	if (n >= sizeof v->pending)
		n = sizeof v->pending - 1u;
	/*
	 * A different module speaking drops the version the last one gave, so a
	 * version can never be shown against a name that did not report it.
	 */
	if (strlen(v->pending) != n || memcmp(v->pending, what, n) != 0)
		v->pending_ver = -1;
	memcpy(v->pending, what, n);
	v->pending[n] = 0;
	/*
	 * One field is picked out of everything a module says, and it is the one
	 * spelled "version". Three modules across two formats report it -
	 * UPX.ELF, UPX.PE and Rar - and it is the field a reader looking at a
	 * packed sample asks for first, because it decides which layout the rest
	 * of the numbers belong to. The others are detail and kofexamine --debug
	 * prints all of them.
	 */
	if (fact == f_version)
		v->pending_ver = (long long)value;
	/*
	 * Two more fields kept, and they are kept for the same reason "version"
	 * is: a reader looking at this object asks for them. A rule that says
	 * "this file carries a payload" is only half an answer - the other half
	 * is which of the symbols it is, and that is a number the rule already
	 * computed and would otherwise be thrown away.
	 */
	else if (fact == f_payload)
		v->pend_payload = value;
	else if (fact == f_paylen)
		v->pend_paylen = value;
}

static void objects_collect(struct view *v, kof_engine *eng)
{
	struct kof_scan_option opt;
	kof_scanner *sc;

	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	/*
	 * LEVEL 2, and this is only expressible because the level and the
	 * emulator became separate fields.
	 *
	 * A viewer wants every heuristic that has anything to say about the
	 * object in front of the reader - that is what the panel is for - and a
	 * rule gated to level 2 is gated on COST, not on confidence. It does
	 * NOT want the interpreter, which is the other half of what --heur 2
	 * means on the command line. Before these were two fields, asking for
	 * one without the other was not possible.
	 */
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	/*
	 * NEVER rather than the zeroed AUTO, and ONLY when asked for.
	 *
	 * A scanner wants AUTO: interpret whatever no module could open, since
	 * a missed payload is a missed detection. A viewer wants neither half
	 * of that silently. Opening a file must show what the unpackers make of
	 * it, so that what is on screen is what a scan would have matched
	 * against; and when a reader asks for the interpreter they want its
	 * answer for THIS object, not only for the objects the modules gave up
	 * on. So the two settings here are the two ends, and the middle one -
	 * useful to a scan - would be the one setting whose output nobody could
	 * attribute to either.
	 */
	opt.emu_use = v->emu_mode ? KOF_EMU_ONLY : KOF_EMU_NEVER;
	/*
	 * The most this build's heuristic can be asked for.
	 *
	 * A tool that examines one named file is not a scanner walking a
	 * filesystem: the reason a level is optional there - it costs a pass
	 * over every object - is not a reason here, where there is one object
	 * and somebody is sitting in front of it waiting to be told about it.
	 * Named rather than numbered so this keeps meaning "the most" as levels
	 * are added.
	 */
	/* -1 rather than the zeroed view's 0, because 0 is a version a container
	 * can carry. Set here so the first module to speak cannot inherit it. */
	v->pending_ver = -1;
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
/* ---- the symbol table, as records ------------------------------------------
 *
 * The KSYM block kofsym.h defines, read back for the screen. The viewer does
 * NOT re-walk the symbol table to draw it: the engine builds the block, this
 * file only lays the fields out, so the table a reader sees and the bytes a
 * signature matches are the same bytes. A second walk here would be a second
 * chance to disagree with the first.
 */

/*
 * Every field is at a constant offset, so these are the whole of the reader.
 *
 * They take a BLOCK rather than an object because there are two of them now -
 * imports and exports - and a reader keyed on the object would have to be told
 * which, in every caller, with nothing to stop it being told wrong.
 */
static uint32_t sym_count(const uint8_t *b, uint32_t n)
{
	if (!b || n < KOF_SYM_HDRLEN)
		return 0;
	return (uint32_t)b[KOF_SYM_H_COUNT] |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 1] << 8) |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 2] << 16) |
	       ((uint32_t)b[KOF_SYM_H_COUNT + 3] << 24);
}

static const uint8_t *sym_rec(const uint8_t *b, uint32_t n, uint32_t i)
{
	uint64_t at = (uint64_t)KOF_SYM_HDRLEN + (uint64_t)i * KOF_SYM_RECLEN;

	if (i >= sym_count(b, n) || at + KOF_SYM_RECLEN > n)
		return 0;
	return b + at;
}

static uint64_t sym_u64(const uint8_t *r, uint32_t at)
{
	uint64_t v = 0;
	int k;

	for (k = 7; k >= 0; k--)
		v = (v << 8) | (uint64_t)r[at + (uint32_t)k];
	return v;
}

/* ELF's own names for ELF's own numbering. Spelled here rather than shared with
 * kofexamine because the two print different widths and a shared table would
 * have to be padded for the wider one. */
static const char *sym_type_str(uint8_t t)
{
	switch (t) {
	case 0:  return "NOTYPE";
	case 1:  return "OBJECT";
	case 2:  return "FUNC";
	case 3:  return "SECTION";
	case 4:  return "FILE";
	case 5:  return "COMMON";
	case 6:  return "TLS";
	case 10: return "GNU_IFUNC";
	default: return "?";
	}
}

static const char *sym_bind_str(uint8_t b)
{
	switch (b) {
	case 0:  return "LOCAL";
	case 1:  return "GLOBAL";
	case 2:  return "WEAK";
	case 10: return "GNU_UNIQ";
	default: return "?";
	}
}

static const char *sym_vis_str(uint8_t x)
{
	switch (x) {
	case 0:  return "DEFAULT";
	case 1:  return "INTERNAL";
	case 2:  return "HIDDEN";
	case 3:  return "PROTECTED";
	default: return "?";
	}
}

static const char *sym_origin_str(const uint8_t *b, uint32_t n)
{
	if (!b || n < KOF_SYM_HDRLEN)
		return "none";
	switch (b[KOF_SYM_H_ORIGIN]) {
	case KOF_SYM_ORIGIN_SYMTAB: return ".symtab";
	case KOF_SYM_ORIGIN_DYNSYM: return ".dynsym";
	default:                    return "none";
	}
}

/*
 * WHICH FIELD A BYTE OF THE BLOCK BELONGS TO, as a colour.
 *
 * This replaces byte_colour for the two symbol rows, and the reason is that
 * byte_colour answers the wrong question here. It asks "what KIND of byte is
 * this" - the only question worth asking of an extent of a file, where nothing
 * marks where one value ends and the next begins. In a KSYM block every field
 * is at a known offset, so that question is already answered, and asking it
 * anyway produced a screen of magenta: A_B_CTRL fires on everything under 0x20,
 * which is every type, bind, vis, flags and shndx byte in the block, plus every
 * small value and size. The palette was spending itself saying "control byte"
 * about two thirds of the block and saying nothing about the structure.
 *
 * The bytes are still BYTES - nothing here decodes them, which is the whole
 * point of these two rows - but the colour now says which field each one is in,
 * so a record's boundaries and its fields can be read off the hex directly.
 * A record is 64 bytes and the pane draws 8 or 16 to a row, so records always
 * start on a row boundary and the bands line up down the pane.
 *
 * The zeros stay visible rather than being dimmed away: over half the block is
 * zero by construction - a 40 byte name field holds a 16 byte name - and a zero
 * in the value field is a fact worth seeing, not padding to be hidden.
 */
static const char *sym_byte_colour(uint64_t off)
{
	uint64_t r;

	if (off < KOF_SYM_HDRLEN)
		return A_S_HDR;
	r = (off - KOF_SYM_HDRLEN) % KOF_SYM_RECLEN;
	if (r == KOF_SYM_R_TYPE)
		return A_S_TYPE;
	if (r == KOF_SYM_R_BIND)
		return A_S_BIND;
	if (r == KOF_SYM_R_VIS)
		return A_S_VIS;
	if (r == KOF_SYM_R_FLAGS)
		return A_S_FLAG;
	/*
	 * EACH FIELD AS ITS OWN RANGE, start and length, not "below the next
	 * one's offset".
	 *
	 * It was a chain of `r < KOF_SYM_R_VALUE`, `r < KOF_SYM_R_SIZE`,
	 * `r < KOF_SYM_R_NAME` - which reads as if it follows the macros but
	 * silently assumes they are in ascending order. Reordering the record
	 * so the name sits next to the attributes made every one of those tests
	 * false about a different field, and nothing would have failed to
	 * compile: the pane would simply have coloured the wrong bytes. Written
	 * this way the tests do not care what order the fields are in.
	 */
	if (r >= KOF_SYM_R_NAME && r < KOF_SYM_R_NAME + KOF_SYM_NAMELEN)
		return A_S_NAME;
	if (r >= KOF_SYM_R_SHNDX && r < KOF_SYM_R_SHNDX + 2u)
		return A_S_SHN;
	if (r >= KOF_SYM_R_SIZE && r < KOF_SYM_R_SIZE + 8u)
		return A_S_SIZE;
	if (r >= KOF_SYM_R_VALUE && r < KOF_SYM_R_VALUE + 8u)
		return A_S_VAL;
	/* The two reserved bytes, which belong to no field. Dim, like the
	 * record number, because that is what they are: structure, not data. */
	return A_S_IDX;
}

/* Is the row the cursor is on a symbol row rather than a region. */
static int sym_view(const struct view *v)
{
	return v->sel_node < v->n_node && v->node[v->sel_node].sym != 0;
}

/*
 * The block the selected row names, and its length.
 *
 * This is what makes the two rows show BYTES. A symbol row is not an extent of
 * the file, so the pane cannot read the object's buffer for it - but the block
 * is a run of bytes like any other, so once the pane is pointed at it every
 * column it draws is the column it always drew. The alternative was a second
 * pane that happened to look like a hex dump, and two hex panes drift.
 */
static const uint8_t *sym_block(const struct view *v, uint64_t *n)
{
	const struct object *o = &v->obj[v->node[v->sel_node].obj];

	if (n)
		*n = o->sym_n;
	return o->sym;
}

/*
 * ONE HALF OF THE BLOCK, described the way the engine describes it.
 *
 * A thin wrapper and deliberately nothing more: the membership test, the run
 * coalescing and the order are all kof_sym_extents', and this only adds up what
 * it returned so a row can show a size. Anything else computed here would be
 * the second opinion this file just stopped having.
 *
 * Returns how many RECORDS the half holds; *bytes gets how many bytes.
 */
static uint32_t sym_half(const struct object *o, uint32_t mask,
			 struct kof_range *ext, uint32_t cap, uint64_t *bytes)
{
	uint32_t n, i, recs = 0;
	uint64_t t = 0;

	n = kof_sym_extents(o->sym, o->sym_n, mask, ext, cap);
	for (i = 0; i < n; i++) {
		t += ext[i].len;
		recs += (uint32_t)(ext[i].len / KOF_SYM_RECLEN);
	}
	if (bytes)
		*bytes = t;
	return recs;
}

/* The mask for a row's half. SYMN_* is the viewer's own tag for the two rows;
 * the scan targets are the engine's names for the same two things. */
static uint32_t sym_row_mask(uint8_t which)
{
	return which == SYMN_IMP ? KOF_SCAN_SYM_IMP : KOF_SCAN_SYM_EXP;
}

/* And back: which row shows the half a scan target names. Zero for a mask that
 * names none, which is what "the object's own bytes" reads as. */
static uint8_t sym_which_of(uint32_t mask)
{
	if (mask & KOF_SCAN_SYM_IMP)
		return SYMN_IMP;
	if (mask & KOF_SCAN_SYM_EXP)
		return SYMN_EXP;
	return 0;
}

/*
 * The block-record indices of one half, ASCENDING, for a table to scroll.
 *
 * Derived from the engine's extents rather than by testing the flag byte again:
 * an extent covers len/KOF_SYM_RECLEN consecutive records starting at its
 * offset, so the membership question is already answered. The extents come back
 * last-run-first, so they are walked in reverse to read forwards.
 */
static uint32_t sym_half_recs(const struct object *o, uint32_t mask,
			      struct kof_range *ext, uint32_t cap,
			      uint32_t *idx, uint32_t idx_cap)
{
	uint32_t n = kof_sym_extents(o->sym, o->sym_n, mask, ext, cap);
	uint32_t k = 0, e;

	for (e = n; e-- > 0; ) {
		uint64_t first = (ext[e].off - KOF_SYM_HDRLEN) /
				 KOF_SYM_RECLEN;
		uint64_t cnt = ext[e].len / KOF_SYM_RECLEN, c;

		for (c = 0; c < cnt && k < idx_cap; c++)
			idx[k++] = (uint32_t)(first + c);
	}
	return k;
}

/*
 * The object's symbol block, built once.
 *
 * One call, because which builder a format gets is kof_syms_build's decision
 * and the scanner makes it the same way - see sym_any.c. This file used to
 * choose between kof_elf_syms and kof_pe_syms itself and then split the result
 * in two; both of those were copies of something the engine already does.
 *
 * A block with no records is dropped rather than kept as a header alone: every
 * reader would have to test the count anyway, and NULL says it once. That is
 * also what a stripped file gives, which is the right answer for it.
 */
static void sym_build(struct object *o)
{
	free(o->sym);
	o->sym = NULL;
	o->sym_n = 0;
	o->sym = malloc(KOF_SYM_MAX_BYTES);
	if (!o->sym)
		return;
	o->sym_n = kof_syms_build(o->ctx.format, o->buf.p, o->buf.n, o->info,
				  o->sym, KOF_SYM_MAX_BYTES);
	if (!kof_sym_count(o->sym, o->sym_n)) {
		free(o->sym);
		o->sym = NULL;
		o->sym_n = 0;
	}
}

/* The largest payload the viewer will decode into, which is the largest one
 * the heuristic will report - see SCL_SIZE_MAX in bases/heur/scloader_00.c.
 * Named here because two functions decode into a buffer of it and a mismatch
 * would truncate one view and not the other. */
#define SCL_SIZE_MAX_VIEW 8192u

/* Base64, decoded, because that is the one wrapper that can be undone with no
 * guesswork: the alphabet is fixed and the transform is reversible. Returns the
 * bytes written, or 0 when the input is not base64 - which is most payloads,
 * and not a failure. */
static uint32_t b64_try(const uint8_t *in, uint32_t n, uint8_t *out,
			uint32_t cap)
{
	static const char *A =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint32_t i, k = 0, acc = 0, bits = 0;

	/*
	 * Refused on the first byte that is not in the alphabet, rather than
	 * skipped. A payload with a few base64-looking bytes in it is not
	 * base64, and decoding the parts that happen to fit would produce a
	 * blob that means nothing and looks like an answer.
	 */
	if (n < 8u)
		return 0;
	for (i = 0; i < n; i++) {
		const char *p;
		uint8_t c = in[i];

		/*
		 * A NUL ENDS THE INPUT, it does not fail it.
		 *
		 * These blobs are declared as C string literals - `char code[]
		 * = "SDHJ..."` - so sizeof includes the terminator and the
		 * symbol's size is one more than the text. Treating that last
		 * byte as "not base64" refused every one of them, and the
		 * dialog said "looks like ?" over a screen of visibly base64
		 * ASCII.
		 *
		 * Only at the END, though: a NUL with data after it is not a
		 * string and not base64, so the loop stops rather than skipping
		 * and the tail is never decoded as if it belonged.
		 */
		if (!c)
			break;
		if (c == '=' || c == '\n' || c == '\r')
			continue;
		p = strchr(A, (int)c);
		if (!p)
			return 0;
		acc = (acc << 6) | (uint32_t)(p - A);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (k >= cap)
				return 0;
			out[k++] = (uint8_t)(acc >> bits);
		}
	}
	return k;
}

/*
 * Take a run of bytes as a new object in the tree.
 *
 * The small half of what on_object does, and only the small half: bytes this
 * size are always copied, because the one caller is a payload and the
 * heuristic that names one bounds it at SCL_SIZE_MAX. No spill, no budget
 * branch, no findings - those exist in on_object because the engine hands it
 * whatever an unpacker produced, which can be a decompressed installer.
 *
 * Not shared with on_object for that reason: factoring the two together would
 * mean one function with a parameter saying which of its halves to run, and
 * the half this caller does not want is the half with the temporary files in
 * it.
 */
static int obj_take(struct view *v, const char *name,
		    const uint8_t *bytes, uint32_t len)
{
	struct object *o;
	const char *p;

	if (v->n_obj >= MAX_OBJ || !len || !bytes)
		return 0;
	if (v->obj_held + len > OBJ_BUDGET)
		return 0;
	o = &v->obj[v->n_obj];
	memset(o, 0, sizeof *o);
	snprintf(o->name, sizeof o->name, "%s", name);
	o->own = malloc((size_t)len);
	if (!o->own)
		return 0;
	memcpy(o->own, bytes, (size_t)len);
	o->buf = kof_buf_make(o->own, len);
	v->obj_held += len;
	/* Depth from the "//" in the name, exactly as on_object derives it, so
	 * the tree indents this the same way it indents an unpacked child. */
	for (p = o->name; (p = strstr(p, "//")) != NULL; p += 2)
		o->depth++;
	v->n_obj++;
	return 1;
}


/*
 * WHICH WIDTH TO DECODE A PAYLOAD AT, which is NOT its parent's.
 *
 * A 64-bit ELF routinely carries 32-bit Windows shellcode - two of the samples
 * measured do - and a payload child has no format of its own, so the ordinary
 * arch test cannot answer for it and the fallback says 64. At 64 the fourth
 * byte of a textbook msf x86 prologue comes out "(data)": `60` is PUSHAD in
 * 32-bit mode and does not exist in 64-bit.
 *
 * Taken from the same prefixes sc_kind recognises, because recognising the stub
 * IS knowing which mode emitted it. Falls back to the caller's default when
 * nothing is recognised, which is the best available guess and no worse than
 * what was there before - and the disassembly panel's own bit switch is right
 * there to override it.
 */
static unsigned sc_bits(const uint8_t *b, uint32_t n, unsigned dflt)
{
	if (!b)
		return dflt;
	if (n >= 6 && b[0] == 0xfc && b[1] == 0x48 && b[2] == 0x83)
		return 64;                      /* x64 block_api */
	if (n >= 7 && b[0] == 0xfc && b[1] == 0xe8 && b[2] == 0x82 &&
	    b[6] == 0x60)
		return 32;                      /* x86 block_api, PUSHAD */
	if (n >= 4 && b[0] == 0x48 && b[1] == 0x31)
		return 64;                      /* x64/xor, and raw x64 */
	if (n >= 8 && (b[4] == 0xd9 || b[5] == 0xd9))
		return 32;                      /* fnstenv GetPC is x86 */
	return dflt;
}

static const char *sc_kind(const uint8_t *b, uint32_t n)
{
	if (n >= 6 && b[0] == 0xfc && b[1] == 0x48 && b[2] == 0x83 &&
	    b[3] == 0xe4 && b[4] == 0xf0 && b[5] == 0xe8)
		return "msf x64 block_api (Windows, raw)";
	if (n >= 9 && b[0] == 0xfc && b[1] == 0xe8 && b[2] == 0x82 &&
	    b[3] == 0x00 && b[4] == 0x00 && b[5] == 0x00 && b[6] == 0x60)
		return "msf x86 block_api (Windows, raw)";
	if (n >= 6 && b[0] == 0x48 && b[1] == 0x31 && b[2] == 0xc9 &&
	    b[3] == 0x48 && b[4] == 0x81 && b[5] == 0xe9)
		return "msf x64/xor decoder stub";
	if (n >= 4 && b[0] == 0xd9 && b[1] == 0x74 && b[2] == 0x24)
		return "msf x86 fnstenv GetPC (shikata family)";
	if (n >= 8 && (b[4] == 0xd9 || b[5] == 0xd9) &&
	    (b[5] == 0x74 || b[6] == 0x74))
		return "msf x86 fnstenv GetPC (shikata family)";
	if (n >= 4 && b[0] == 0x48 && b[1] == 0x31 && b[2] == 0xc0)
		return "x86-64 shellcode, no decoder in front";
	if (n >= 2 && b[0] == 0xeb)
		return "jmp/pop/xor decoder stub";
	return "?";
}

/*
 * A PSEUDO ELF HEADER IN FRONT OF THE PAYLOAD.
 *
 * WHY. Without one the payload is a formatless blob, and the scanner says so:
 * "SKIPPED - no module targets this format". Every rule declares a format and
 * scopes itself to a region, so a blob matches nothing and is not even offered
 * to a module. A header is what makes the payload reachable - it is not a
 * claim that a file like this ever existed, exactly as bases/unp/msf_pe.h says
 * of its own reconstruction.
 *
 * THE PAYLOAD GOES IN A WRITABLE, NON-EXECUTABLE SEGMENT, so it lands in region
 * DATA. Three measured reasons, and the first is the one that matters:
 *
 *  - In the PARENT the payload is in .data, so region DATA. One DATA-scoped
 *    rule then reaches both: the un-encoded payload sitting in the loader's
 *    variable, and the decoded payload here. Nine of twelve samples measured
 *    are already matchable in the parent that way, with no reconstruction.
 *  - An entry point inside a non-executable segment raises
 *    KOF_ELF_ANOM_ENTRY_NOT_EXEC, which kof_emu_unp_gate reads as "unloadable"
 *    and would hand every reconstructed child to the interpreter for nothing.
 *    ET_DYN with e_entry 0 raises nothing: an image with no entry point is what
 *    a blob lifted out of a variable IS.
 *  - An RWX segment with the entry on it lands the payload in CODE and is
 *    byte-for-byte the shape bases/heur/shellcode_00.c looks for - no section
 *    table, one program header, one executable PT_LOAD that is the whole file.
 *    Measured: the engine flags its own reconstruction as an msfvenom template.
 *
 * p_filesz MUST NOT EXCEED WHAT IS WRITTEN, or KOF_ELF_ANOM_SEG_PAST_EOF fires
 * and kofheur scores it "Truncated" - the engine detecting its own output.
 * p_memsz may be larger; that is what .bss is. Measured both ways.
 *
 * The width follows the payload, not the parent: sc_bits reads it off the stub,
 * because a 64-bit loader routinely carries 32-bit Windows shellcode.
 */
#define PELF_EH64 64u
#define PELF_PH64 56u
#define PELF_EH32 52u
#define PELF_PH32 32u

static void pelf_put(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

/*
 * Write the header for `n` payload bytes into `out` (at least 120 bytes) and
 * return its length. `bits` is 32 or 64 and decides ELF32 against ELF64 - not
 * cosmetic, because the collector reads the class to set the object's
 * architecture, and an x86 payload described as ELF64 would be disassembled as
 * amd64.
 */
static uint32_t pelf_hdr(uint8_t *out, uint32_t n, unsigned bits)
{
	int b64 = bits != 32;
	uint32_t eh = b64 ? PELF_EH64 : PELF_EH32;
	uint32_t ph = b64 ? PELF_PH64 : PELF_PH32;
	uint32_t hdrs = eh + ph;
	uint8_t *p;
	uint32_t k;

	for (k = 0; k < hdrs; k++)
		out[k] = 0;
	out[0] = 0x7f; out[1] = 'E'; out[2] = 'L'; out[3] = 'F';
	out[4] = b64 ? 2u : 1u;         /* ELFCLASS64 / ELFCLASS32 */
	out[5] = 1;                     /* ELFDATA2LSB             */
	out[6] = 1;                     /* EV_CURRENT              */
	pelf_put(out + 16, 3, 2);       /* ET_DYN - see the note   */
	pelf_put(out + 18, b64 ? 0x3eu : 3u, 2);   /* x86-64 / i386 */
	pelf_put(out + 20, 1, 4);       /* EV_CURRENT              */
	/* e_entry stays 0. e_shoff and e_shnum stay 0: there is no section
	 * table, and inventing one would be inventing bytes. */
	/*
	 * The offsets, and they are worth spelling out because getting them
	 * wrong is silent. Written two bytes late at first - 54/56/58 for
	 * ELF64 instead of 52/54/56 - so the parser read e_phentsize as 64 and
	 * e_phnum as 56: fifty-six program headers of sixty-four bytes, far
	 * past the end of a 203-byte file. It still identified as ELF-x64, and
	 * the whole object came back as one HEADERS region with no DATA at all.
	 *
	 *   ELF64  e_phoff 32(8)  e_ehsize 52(2)  e_phentsize 54(2)  e_phnum 56(2)
	 *   ELF32  e_phoff 28(4)  e_ehsize 40(2)  e_phentsize 42(2)  e_phnum 44(2)
	 */
	pelf_put(out + (b64 ? 32u : 28u), eh, b64 ? 8u : 4u);   /* e_phoff */
	pelf_put(out + (b64 ? 52u : 40u), eh, 2);               /* e_ehsize */
	pelf_put(out + (b64 ? 54u : 42u), ph, 2);               /* e_phentsize */
	pelf_put(out + (b64 ? 56u : 44u), 1, 2);                /* e_phnum */

	p = out + eh;
	pelf_put(p + 0, 1, 4);                  /* PT_LOAD */
	if (b64) {
		pelf_put(p + 4,  6, 4);         /* p_flags = RW */
		pelf_put(p + 8,  0, 8);         /* p_offset */
		pelf_put(p + 16, 0, 8);         /* p_vaddr  */
		pelf_put(p + 24, 0, 8);         /* p_paddr  */
		pelf_put(p + 32, hdrs + n, 8);  /* p_filesz - exactly the file */
		pelf_put(p + 40, hdrs + n, 8);  /* p_memsz  */
		pelf_put(p + 48, 0x1000, 8);    /* p_align  */
	} else {
		pelf_put(p + 4,  0, 4);         /* p_offset */
		pelf_put(p + 8,  0, 4);         /* p_vaddr  */
		pelf_put(p + 12, 0, 4);         /* p_paddr  */
		pelf_put(p + 16, hdrs + n, 4);  /* p_filesz */
		pelf_put(p + 20, hdrs + n, 4);  /* p_memsz  */
		pelf_put(p + 24, 6, 4);         /* p_flags = RW */
		pelf_put(p + 28, 0x1000, 4);    /* p_align  */
	}
	return hdrs;
}

/*
 * THE PAYLOAD A HEURISTIC NAMED, AS AN OBJECT OF ITS OWN.
 *
 * This is the whole reason the rule reports an address. A dialog showing the
 * bytes was the first attempt and it was the wrong shape: a researcher cannot
 * do anything with a hex dump in a box, while an OBJECT gets everything this
 * tool already does - a row in the tree, the hex pane with its selection and
 * its right-click menu, the disassembly panel, Find, Go to, the marker list,
 * and the draft panel to declare a signature from. None of that had to be
 * written for it; it works because the object is an object.
 *
 * NAMED "//payload", because depth in this tree is counted from the "//" in a
 * name - see on_object - so the separator is what makes it a child rather than
 * a sibling. It carries the symbol's own name too, since that is what a reader
 * saw in the symbols dialog and is how they will recognise it here.
 *
 * DECODED WHEN IT IS BASE64, and the name says which: the encoded text is not
 * the payload, and an object holding it would disassemble as garbage. Only
 * base64, for the reason b64_try gives - it is the one wrapper undoable with no
 * guesswork. An encoder STUB is left alone: it is real code and disassembling
 * it is exactly what a reader wants.
 *
 * WHAT THIS IS NOT: a claim that this object was ever a file. It was not. It is
 * the bytes a global variable holds, presented as the thing they are so that
 * the tools can reach them - the same claim bases/unp/msf_elf32.h makes about a
 * reconstructed payload, and the same reason.
 */
static int payload_child(struct view *v, uint32_t parent)
{
	struct object *po = &v->obj[parent];
	const struct kof_elf_info *e = po->info;
	static uint8_t dec[SCL_SIZE_MAX_VIEW];
	const uint8_t *b = 0;
	uint32_t n = 0, dn, i;
	char name[256], sym[KOF_SYM_NAMELEN + 1];

	if (!po->payload_at || !po->payload_len || !e || !e->valid || !po->buf.p)
		return 0;
	if (v->n_obj >= MAX_OBJ)
		return 0;

	/* The address, through the parent's own section table. */
	for (i = 0; i < e->sec_count && i < KOF_ELF_MAX_SECTIONS; i++) {
		const struct kof_elf_sec *sc = &e->sec[i];
		uint64_t fo;

		if (sc->type != 1u || !sc->mem_addr)
			continue;
		if (po->payload_at < sc->mem_addr ||
		    po->payload_at >= sc->mem_addr + sc->file_size)
			continue;
		fo = sc->file_off + (po->payload_at - sc->mem_addr);
		if (fo >= po->buf.n || po->payload_len > po->buf.n - fo)
			return 0;
		b = po->buf.p + fo;
		n = (uint32_t)po->payload_len;
		break;
	}
	if (!b || !n)
		return 0;

	/* Which symbol it was, read back from the block rather than remembered,
	 * so the name here and the row marked in the symbols dialog can only
	 * ever be the same symbol. */
	sym[0] = 0;
	{
		const uint8_t *r;
		uint32_t k;

		for (k = 0; (r = kof_sym_rec(po->sym, po->sym_n, k)); k++) {
			uint32_t j;

			if (kof_sym_u64(r, KOF_SYM_R_VALUE) != po->payload_at)
				continue;
			for (j = 0; j < KOF_SYM_NAMELEN &&
				    r[KOF_SYM_R_NAME + j]; j++)
				sym[j] = (char)r[KOF_SYM_R_NAME + j];
			sym[j] = 0;
			break;
		}
	}

	dn = b64_try(b, n, dec, (uint32_t)sizeof dec);
	/*
	 * NAMED "Shellcode", NOT after the symbol it came from.
	 *
	 * It was `//code`, `//shellcode`, `//buf`, `//random` - whatever the
	 * author had called the variable - which is the same mistake the static
	 * signature makes: the name carries no information and changes with
	 * every sample. The tree row reads "//Shellcode ELF-x64", which says
	 * what the object IS in the two terms that matter, and the symbol it
	 * was lifted from is a fact about the PARENT, so it belongs in the
	 * dashboard beside the parent's other facts - see payload_sym.
	 */
	snprintf(name, sizeof name, "%s//Shellcode", po->name);

	/*
	 * The payload with a pseudo header in front of it, not the bare bytes.
	 *
	 * Bare, the child came back "SKIPPED - no module targets this format":
	 * every rule declares a format and scopes to a region, so a blob is
	 * never offered to one. With the header it is an ELF whose DATA region
	 * IS the payload, which is the same region the bytes occupy in the
	 * parent - so one rule reaches both. See pelf_hdr.
	 */
	{
		static uint8_t img[SCL_SIZE_MAX_VIEW + 128u];
		const uint8_t *src = dn ? dec : b;
		uint32_t sn = dn ? dn : n;
		uint32_t hn;

		if (sn > SCL_SIZE_MAX_VIEW)
			return 0;
		hn = pelf_hdr(img, sn, sc_bits(src, sn, 64u));
		memcpy(img + hn, src, sn);
		if (!obj_take(v, name, img, hn + sn))
			return 0;
	}
	{
		struct object *ko = &v->obj[v->n_obj - 1u];

		ko->payload_of = 1;
		ko->payload_b64 = dn ? 1 : 0;
		snprintf(ko->payload_sym, sizeof ko->payload_sym, "%s",
			 sym[0] ? sym : "(unnamed)");
	}
	return 1;
}

/*
 * Parse and look up the objects from `from` onward.
 *
 * A range rather than the whole list, because objects arrive twice now: once
 * when the file is opened, and again when the reader runs the interpreter on a
 * node and it produces more. Re-examining the earlier ones would allocate a
 * second view for each and leak the first.
 */
static void objects_examine_from(struct view *v, kof_engine *eng, uint32_t from)
{
	uint32_t i;

	for (i = from; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		o->fmt = kof_inspect_identify(o->buf, &o->ctx, &o->info);
		if (!o->fmt)
			o->ctx.obj_size = o->buf.n;
		if (o->fmt && o->info && o->ctx.format == KOF_FMT_ELF)
			o->emu_why = (uint8_t)kof_emu_unp_gate(&o->ctx, o->info,
							       o->buf.p,
							       o->buf.n);
		if (o->fmt && o->info &&
		    (o->ctx.format == KOF_FMT_ELF ||
		     o->ctx.format == KOF_FMT_PE))
			sym_build(o);
		if (eng &&
		    !kof_touch_object(eng, o->buf, &o->ctx,
				      (const char *const *)o->finding,
				      o->n_finding, &o->touch, &o->n_touch))
			o->n_touch = 0;
	}
}

/*
 * WHICH SIGNATURE THE PANE LIGHTS BY DEFAULT, and why it is not the first one.
 *
 * The hex pane marks where the SELECTED signature's markers sit, which is what
 * makes the pane useful while authoring one: pick a rule, see where its bytes
 * land. Defaulting that selection to index zero meant an arbitrary rule's
 * markers lit up on every file opened - and a short marker lands somewhere by
 * chance in almost any header. A reader reads a highlight as "this matched",
 * so the pane was reporting a match that had not happened.
 *
 * The default is now the first rule that FIRED. When nothing fired the
 * selection is past the end, which hit_kind already reads as "light nothing" -
 * so an unlit pane means no rule matched, and a lit one means one did.
 */
static uint32_t touch_default(const struct object *ob)
{
	uint32_t i;

	for (i = 0; i < ob->n_touch; i++)
		if (ob->touch[i].fired)
			return i;
	return ob->n_touch;             /* nothing fired: select nothing */
}

static void objects_examine(struct view *v, kof_engine *eng)
{
	objects_examine_from(v, eng, 0);
	/*
	 * The payloads a heuristic named, added as objects of their own.
	 *
	 * AFTER the parse, because the address a rule reports has to be turned
	 * into a file offset through the parent's section table, and that table
	 * is what objects_examine_from builds. Then examined again from the
	 * first new one, so the payloads themselves get identified, scanned for
	 * markers and given a region tree like anything else.
	 */
	{
		uint32_t before = v->n_obj, i;

		for (i = 0; i < before; i++)
			payload_child(v, i);
		if (v->n_obj > before)
			objects_examine_from(v, eng, before);
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
	n->sym = 0;
	n->bytes = bytes;
	snprintf(n->label, sizeof n->label, "%s", label);
}

/* The symbol row, marked as such. Separate from tree_add because `at` is
 * deliberately NOT cleared there - a row keeps its scroll across a rebuild - so
 * the slot arrives with the last tenant's values in it and a flag that is only
 * ever set would stay set on whatever region row inherited the slot. */
static void tree_add_sym(struct view *v, uint32_t depth, uint32_t obj,
			 uint64_t bytes, uint8_t which, const char *label)
{
	/*
	 * A REAL MASK, because these halves are real scan targets.
	 *
	 * It used to be zero, which said "this row is not something a signature
	 * can be scoped to" - and that was true only for as long as the engine
	 * could not search the block. It can (KOF_SCAN_SYM_IMP in kofsig.h),
	 * and scoping to it is the entire point of splitting the block in two:
	 * a name matched in DATA is any occurrence of those bytes, and the same
	 * name matched in SYM_EXP is the claim that this object exports it.
	 *
	 * Zero also had a second meaning here that it should never have had -
	 * node_at reads a maskless row as THE OBJECT ROW - so a symbol row was
	 * one wrong lookup away from being handed back as the whole file.
	 */
	tree_add(v, depth, obj, which == SYMN_IMP ? KOF_SCAN_SYM_IMP
						  : KOF_SCAN_SYM_EXP,
		 bytes, label);
	if (v->n_node)
		v->node[v->n_node - 1u].sym = which;
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
		else if (o->payload_of)
			/*
			 * "Shellcode-x64", in the SAME SHAPE as every other
			 * object row: the root reads "ELF-x64", a PE child
			 * reads "PE-x86", and this reads "Shellcode-x64".
			 * <what it is>-<arch>, one convention, already on the
			 * screen above it.
			 *
			 * Two shapes were tried and both were worse.
			 * "ELF-x64//Shellcode" is eighteen columns against the
			 * sixteen a depth-one row has, so it came out
			 * "ELF-x64//Shellco" - and the "ELF-" was the redundant
			 * half anyway, since the parent row says ELF and this
			 * object's own HEADERS and DATA rows say it again.
			 * "[Shellcode] x64" fits and marks the reconstruction,
			 * but it invents a bracket convention this tree does
			 * not otherwise use.
			 *
			 * NOT "SHELLCODE". Capitals in this tree mean REGION -
			 * HEADERS, CODE, DATA, SYM_IMP - and this is an object.
			 * Shouting it would file a child object under the
			 * parent's regions, which is the one thing the row must
			 * not say.
			 *
			 * The ARCHITECTURE stays because it is the one fact the
			 * parent does not imply: a 64-bit loader routinely
			 * carries a 32-bit payload, and the x86 samples show
			 * Shellcode-x86 over an ELF32 header.
			 *
			 * That it is a RECONSTRUCTION is said where there is
			 * room to say it - the dashboard's Anomalies row reads
			 * RECONSTRUCTED_ELF-x64_SHELLCODE, and the name row
			 * names the variable it came out of.
			 */
			snprintf(label, sizeof label, "Shellcode-%s",
				 o->fmt ? kof_arch_name(o->ctx.arch) : "?");
		else
			snprintf(label, sizeof label, "//%s %s%s",
				 tail ? tail + 1 : o->name, what,
				 /* Scanned, but not kept: there is nothing to
				  * show and the row should not pretend there
				  * is. */
				 o->too_big ? "  (not kept)" : "");
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
		/*
		 * Last, and only when there is something in it.
		 *
		 * Last because it is not a region: every row above it is an
		 * extent of the file and this one is built, so it reads as the
		 * derived thing it is rather than as another slice. Suppressed
		 * when empty because a row that opens onto nothing is worse
		 * than no row - the reader clicks it to find out, every time.
		 * A stripped file simply has no symbol row, which is itself the
		 * answer.
		 */
		/*
		 * The two symbol rows, last, and each only when it has records.
		 *
		 * Last because they are not regions: every row above is an
		 * extent of the file and these are built, so they read as the
		 * derived things they are rather than as more slices. Sized in
		 * BYTES like every other row - the column means bytes, and a
		 * record count there would read as a very small region.
		 *
		 * Suppressed when empty rather than shown as zero: an object
		 * that imports nothing and one whose symbols could not be read
		 * are different facts, and a row that opens onto nothing
		 * cannot tell them apart. No row at all is the honest answer,
		 * the same one a stripped file gives.
		 */
		{
			uint8_t which[2] = { SYMN_IMP, SYMN_EXP };
			const char *lab[2] = { "SYM_IMP", "SYM_EXP" };
			uint32_t h;

			/* Size and existence both from the engine's extents,
			 * like every region row above. */
			for (h = 0; h < 2u; h++) {
				uint64_t bytes = 0;

				if (!v->ext)
					break;
				if (!sym_half(o, sym_row_mask(which[h]),
					      v->ext, KOF_SCAN_MAX_EXTENTS,
					      &bytes))
					continue;
				tree_add_sym(v, o->depth * 2u + 1u, i, bytes,
					     which[h], lab[h]);
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
	uint64_t rows = (uint64_t)(hex_last() - hex_top() + 1);
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
	/*
	 * A SYMBOL ROW IS A ROW OF EXTENTS LIKE ANY OTHER, and its extents come
	 * from the engine.
	 *
	 * It used to be a special case with n_ext left at zero, which meant
	 * view_map, view_unmap, the selection and the search each needed their
	 * own branch for it - and each of those branches was a place to get the
	 * two address spaces confused, which is what happened four separate
	 * times. Resolved the same way a region is, all of that goes away: the
	 * pane walks extents, so it shows exactly the records of that half and
	 * nothing between them.
	 */
	if (v->node[v->sel_node].sym) {
		uint32_t a, b2;

		v->n_ext = kof_sym_extents(o->sym, o->sym_n,
					   v->node[v->sel_node].mask, v->ext,
					   KOF_SCAN_MAX_EXTENTS);
		/*
		 * REVERSED FOR READING, and only for reading.
		 *
		 * The engine hands back its runs last-first, because a search
		 * wants the author's own symbols before the runtime's and a
		 * boolean answer does not care about order. A TABLE does: read
		 * in that order the symbol list runs backwards. So the extents
		 * are flipped here, where the decision is about the screen -
		 * the search still calls kof_sym_extents itself and still gets
		 * the engine's order.
		 */
		for (a = 0, b2 = v->n_ext; a + 1u < b2; a++) {
			struct kof_range t = v->ext[a];

			b2--;
			v->ext[a] = v->ext[b2];
			v->ext[b2] = t;
		}
	} else
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
	/* The panel's rows are about the bytes that were on screen; moving to
	 * another region makes them about different ones. */
	v->dis_have = 0;
	v->dragging = 0;
	if (v->node[k].obj != was)
		v->sel_touch = touch_default(&v->obj[v->node[k].obj]);
	view_select(v);
}

/*
 * THE BYTES THE SELECTED ROW IS SHOWING, whatever kind of row it is.
 *
 * One accessor, because five places need it and they had all hard-coded
 * `ob->buf.p`: the pane, the copy, the marker being declared, the word the
 * double-click extends to, and the disassembler's feed. On a symbol row that
 * pointer is wrong - view_map returns an offset into the BLOCK, so indexing the
 * file with it reads unrelated bytes at the same number and hands them to the
 * copy and to the marker as though they were what was on screen. Every caller
 * asks here instead, so a row kind added later cannot be right in the drawing
 * and silently wrong in everything that acts on it.
 */
static const uint8_t *view_bytes(const struct view *v, uint64_t *n)
{
	const struct object *o = &v->obj[v->node[v->sel_node].obj];

	if (sym_view(v))
		return sym_block(v, n);
	if (n)
		*n = o->buf.n;
	return o->buf.p;
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

/*
 * A vertical scrollbar in one column.
 *
 * Drawn only when there is more than fits, because a bar that is always full
 * height says nothing and costs a column of every pane it is in. The thumb is
 * at least one row so a very long object still shows where it is - proportional
 * alone would round it away and leave the track empty.
 *
 * ASCII, like the pane divider: this is read over ssh on whatever terminal is
 * at the other end.
 */
static int bar_thumb(int top, int bot, uint64_t off, uint64_t total,
		     uint64_t shown, int *out_len)
{
	int rows = bot - top + 1, t0, t1;
	uint64_t max;

	if (rows < 2 || !total || shown >= total)
		return -1;
	max = total - shown;
	t1 = (int)((uint64_t)(rows - 1) * shown / total);
	if (t1 < 1)
		t1 = 1;
	t0 = (int)((uint64_t)(rows - t1) * (off < max ? off : max) / max);
	*out_len = t1;
	return t0;
}

/*
 * A BAR, DRAWN AS ONE SHAPE IN TWO WEIGHTS.
 *
 * It was '#' for the thumb and ':' for the track - two different characters, so
 * the eye read it as a column of punctuation rather than as a rule with a
 * position on it. One character throughout, bright where the thumb is and dim
 * elsewhere, reads as what it is; and it is the same shape the panes are divided
 * by, so a vertical line means the same thing everywhere on the screen.
 *
 * Every pane's bar comes through here, so there is one style rather than one per
 * caller.
 */
static void scrollbar(struct out *o, int col, int top, int bot,
		      uint64_t off, uint64_t total, uint64_t shown)
{
	int rows = bot - top + 1, i, t0, t1;

	t0 = bar_thumb(top, bot, off, total, shown, &t1);
	if (t0 < 0)
		return;
	for (i = 0; i < rows; i++) {
		out_at(o, top + i, col);
		out_str(o, i >= t0 && i < t0 + t1
			   ? A_BOLD "\xe2\x94\x82" A_OFF
			   : A_DIM "\xe2\x94\x82" A_OFF);
	}
}

static void draw_frame(struct out *o, struct view *v)
{
	int i;

	for (i = hex_top(); i <= hex_bot(); i++) {
		out_at(o, i, TREE_W + 1);
		out_str(o, A_DIM "|" A_OFF);
	}
	/*
	 * The divider, which is also the handle that resizes the draft panel.
	 *
	 * Marked in the middle rather than announced in a legend: a row of
	 * dashes with a grip drawn on it is a thing people try to drag, and the
	 * ones who do not try lose nothing.
	 */
	row_start(o, hex_bot() + 1, 1);
	out_str(o, v->sizing ? A_WARN : A_DIM);
	for (i = 0; i < g_cols; i++)
		out_str(o, i >= g_cols / 2 - 3 && i <= g_cols / 2 + 3
			   ? "=" : "-");
	out_str(o, A_OFF);
}

/*
 * The colour an OBJECT row is drawn in: its verdict, or plain when it has none.
 *
 * Read from what the engine reported for that object rather than from anything
 * this panel worked out - the same rule the heuristic fields follow. A row with
 * no finding stays as it was, because most rows have none and a tree where
 * everything is coloured says nothing.
 */
static const char *tree_colour(const struct view *v, const struct node *n)
{
	const struct object *ob;
	uint32_t i;
	int worst = -1;

	if (n->obj >= v->n_obj)
		return A_BOLD;
	ob = &v->obj[n->obj];
	if (!ob->n_finding && !ob->heur.n)
		return A_BOLD;
	for (i = 0; i < ob->heur.n; i++) {
		int lv = (int)ob->heur.v[i].level;

		/* INFECT outranks SUSPECT outranks HEUR, and the row shows the
		 * strongest thing said about it - a row that matched a family
		 * and also scored on structure is a match. */
		if (worst < 0 || lv == KOF_LEVEL_INFECT ||
		    (lv == KOF_LEVEL_SUSPECT && worst == KOF_LEVEL_HEUR))
			worst = lv;
	}
	if (worst == KOF_LEVEL_INFECT)
		return A_HIT1;                  /* the same red a match is */
	if (worst == KOF_LEVEL_SUSPECT)
		return A_HIT2;
	if (worst == KOF_LEVEL_HEUR)
		return A_WARN;
	/* A finding was recorded but its level is not in the result any more -
	 * still not a plain row. */
	return ob->n_finding ? A_HIT1 : A_BOLD;
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
			out_str(o, sel ? A_BOLD : "");
			/* A star, not a chevron: "> " reads as a thing that
			 * would open if it were pressed, and these rows are
			 * already all open. */
			out_str(o, sel ? "*" : " ");
			/*
			 * A region row is a place inside an object; an object
			 * row can hold a signature. Different colours because
			 * they are different kinds of answer.
			 *
			 * AN OBJECT THAT MATCHED SOMETHING IS NOT WHITE, and
			 * that is the point of the tree on a nested sample. An
			 * archive of forty entries, or a dropper unpacked three
			 * deep, is a column of rows that all look alike - and
			 * the one worth reading is the one a signature fired
			 * on, which the reader had to find by walking every row
			 * and watching the status line. The colour is the
			 * verdict's own, so a match, a suspicion and a
			 * heuristic are told apart without opening any of them.
			 *
			 * Applied to the SELECTED row as well. It was not, and
			 * the row selected when a file opens is the root - so
			 * the verdict on the object a reader is looking at was
			 * the one verdict the tree never showed.
			 */
			if (n->mask || n->sym) {
				if (!sel)
					out_str(o, A_ID);
			} else {
				out_str(o, tree_colour(v, n));
			}
			/* Truncated, not merely padded: a label wider than its
			 * column runs into the pane beside it, and the first
			 * file anyone opens has a sha256 for a name. */
			out_fmt(o, "%-18.18s", row + off);
		}
		if (!sel)
			out_str(o, A_OFF A_SIZE);
		out_fmt(o, "%9llu", (unsigned long long)n->bytes);
		out_str(o, A_OFF);
	}
	/* The tree's own bar, in the two columns its rows never reach: a row is
	 * a mark, eighteen of label and nine of size, and TREE_W is thirty. */
	scrollbar(o, TREE_W, top, bot, v->tree_top, v->n_node,
		  (uint64_t)(bot - top + 1));
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
			/* `off` is an offset in whatever the pane is showing
			 * and st->at is in whatever buffer it was found in;
			 * comparing across the two lights an unrelated byte at
			 * the same number. */
			if (sym_which_of(st->sym) !=
			    v->node[v->sel_node].sym)
				continue;
			/* span_min, not the pool length: for a hex marker the
			 * pool holds a compiled program, and lighting its
			 * length lit the marker plus whatever followed it in
			 * the object. */
			if (off < st->at || off >= st->at + st->span_at)
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
		/* Same space only - see touch_at_off. */
		if (sym_which_of(st->sym) != v->node[v->sel_node].sym)
			continue;
		if (off >= st->at && off < st->at + st->span_at)
			return st->in_rgn ? 1 : 2;
	}
	return 0;
}

/*
 * Where a declared string sits in this object, searched for once.
 *
 * A string declared by selecting bytes already knows; one loaded from a
 * database row knows too. One read out of a source file does not - the file
 * says what to look for, not where it was found - and that is the case this is
 * for. Case folding is honoured because the declaration honours it.
 */
static uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off);

/*
 * The pattern a declaration stands for, compiled the way the database will.
 *
 * Shared because two locators need it and a second reading of the same
 * declaration is a second thing to keep in step - which is how the panel came
 * to report "found" about markers the scan would miss in the first place.
 */
static int decl_pattern(const struct decl *d, uint8_t *prog,
			const uint8_t **pat, uint32_t *plen,
			uint8_t *kind, uint8_t *flags)
{
	*flags = 0;
	if (d->hex && d->hexs[0]) {
		*plen = kof_hex_compile(d->hexs, prog, KOF_HEX_MAX_PROG, NULL);
		if (!*plen)
			return 0;       /* it will not compile; it cannot match */
		*pat = prog;
		*kind = KOF_STR_HEX;
	} else {
		*pat = d->bytes;
		*plen = d->nbytes;
		*kind = KOF_STR_LITERAL;
		if (!d->hex) {
			if (d->icase)
				*flags |= KOF_STR_ICASE;
			if (d->fullword)
				*flags |= KOF_STR_FULLWORD;
		}
	}
	return *pat && *plen && *plen <= 0xffffu;
}

/*
 * How long each hit actually is, asked of the matcher.
 *
 * kof_match_where says where a match starts and not where it ends, and the
 * engine keeps that to itself. Truncating the buffer is how to ask: a match
 * needs its whole length to be there, so the shortest cut the pattern still
 * matches under IS its length. Monotonic - a longer cut can only help - so it
 * is a bisection rather than a walk, eight probes for the widest jump the
 * compiler allows. Skipped entirely for a pattern of fixed length, which is
 * nearly all of them.
 */
static void decl_hit_lens(struct decl *d, struct kof_match_ctx *m,
			  const uint8_t *buf, uint64_t n, const uint8_t *pat,
			  uint32_t plen, uint8_t kind, uint8_t flags)
{
	uint32_t h;

	for (h = 0; h < d->n_hits; h++) {
		uint32_t lo = d->len, hi = d->span_max;

		if (d->span_max <= d->len) {
			d->hit_len[h] = d->len;
			continue;
		}
		if (d->hits[h] + hi > n)
			hi = (uint32_t)(n - d->hits[h]);
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			kof_match_begin(m, kof_buf_make(buf, d->hits[h] + mid));
			if (kof_match_at(m, d->hits[h], pat, (uint16_t)plen,
					 kind, flags))
				hi = mid;
			else
				lo = mid + 1u;
		}
		d->hit_len[h] = lo;
	}
}

/*
 * WHERE A MARKER SCOPED TO A SYMBOL HALF SITS - in that half, not in the file.
 *
 * A different address space, so a different search: the block is built, the
 * object's bytes do not contain it, and running the file locator over a
 * sym-scoped marker would report it absent from a scan that finds it every
 * time.
 *
 * The half searched is the one the pane shows, so an offset recorded here is a
 * pane coordinate and the row's jump lands where the reader took the bytes
 * from. The engine searches its own interleaved block instead, but the halves
 * are byte-identical run for run - sym_extents coalesces adjacent records of
 * one half, which is exactly the contiguous block kofviewer built - so both
 * answer the same question about the same bytes.
 *
 * Records only. The block's own header is not scanned by the engine, so a
 * marker over it must not be reported as found here either.
 *
 * A mask naming BOTH halves is searched imports first and reported as whichever
 * half holds the bytes - the same convention the file locator already uses for
 * a string present in two regions, where the row names one and the widen offer
 * names the union.
 */
static void decl_locate_sym(struct view *v, struct decl *d)
{
	struct object *ob = &v->obj[d->obj < v->n_obj ? d->obj : 0];
	struct kof_match_ctx m;
	uint8_t prog[KOF_HEX_MAX_PROG];
	const uint8_t *pat;
	uint32_t plen;
	uint8_t kind, flags;
	int half;

	if (!decl_pattern(d, prog, &pat, &plen, &kind, &flags))
		return;
	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0))
		return;

	for (half = 0; half < 2; half++) {
		uint32_t bit = half ? KOF_SCAN_SYM_EXP : KOF_SCAN_SYM_IMP;
		uint32_t ne, e;

		if (!(d->mask & bit) || !ob->sym || !v->probe)
			continue;
		/*
		 * THE EXTENTS ARE THE ENGINE'S, not a half copied out of the
		 * block by this file.
		 *
		 * kof_sym_extents is the same call kof_find_str makes, so the
		 * runs searched here are the runs searched by the scan - which
		 * is what stops the panel from finding a marker across a
		 * record boundary that the module never will, and the other
		 * way round.
		 */
		ne = kof_sym_extents(ob->sym, ob->sym_n, bit, v->probe,
				     KOF_SCAN_MAX_EXTENTS);
		kof_match_begin(&m, kof_buf_make(ob->sym, ob->sym_n));
		for (e = 0; e < ne; e++) {
			uint64_t from = v->probe[e].off;
			uint64_t end = from + v->probe[e].len;

			while (from < end) {
				uint64_t at = kof_match_where(&m, from,
							      end - from, pat,
							      (uint16_t)plen,
							      kind, flags);

				if (at == KOF_BROKEN)
					break;
				/* Re-asked, because restarting the window
				 * moves the word boundary - see the same note
				 * in decl_locate. */
				if ((flags & KOF_STR_FULLWORD) &&
				    !kof_match_at(&m, at, pat, (uint16_t)plen,
						  kind, flags)) {
					from = at + 1u;
					continue;
				}
				if (d->n_hits < DECL_HITS_MAX)
					d->hits[d->n_hits++] = at;
				else
					d->hits_clipped = 1;
				if (d->at == KOF_BROKEN) {
					d->at = at;
					d->cur_hit = d->n_hits
						   ? d->n_hits - 1u : 0u;
					d->at_mask = bit;
					/* Offsets into the block, said before
					 * anyone reads them as file offsets. */
					d->sym = half ? SYMN_EXP : SYMN_IMP;
					snprintf(d->at_rgn,
						 sizeof d->at_rgn, "%s",
						 half ? "SYM_EXP" : "SYM_IMP");
				}
				from = at + 1u;
				if (d->hits_clipped)
					break;
			}
			if (d->hits_clipped)
				break;
		}
		if (d->n_hits) {
			decl_hit_lens(d, &m, ob->sym, ob->sym_n, pat, plen,
				      kind, flags);
			break;
		}
	}
	kof_match_state_free(&m);
}

static void decl_locate(struct view *v, struct decl *d)
{
	struct object *ob = &v->obj[d->obj < v->n_obj ? d->obj : 0];
	struct kof_match_ctx m;
	uint8_t prog[KOF_HEX_MAX_PROG];
	const uint8_t *pat;
	uint64_t at, from = 0, first = KOF_BROKEN;
	uint32_t plen, first_nd = 0, seen_mask = 0;
	uint8_t kind, flags = 0;

	d->at = KOF_BROKEN;
	d->sym = 0;
	d->off_rgn = 0;
	d->at_rgn[0] = 0;
	d->at_mask = 0;
	d->n_hits = 0;
	d->hits_clipped = 0;
	if (!d->len)
		return;
	/*
	 * A different buffer entirely - see decl_locate_sym. Tested before the
	 * size check below, which is against the object and would refuse a
	 * marker longer than a small file but present in its symbol block.
	 */
	if (d->mask & KOF_SCAN_SYM) {
		decl_locate_sym(v, d);
		/*
		 * A MIXED MASK NAMES TWO SPACES, AND BOTH HAVE TO BE LOOKED IN.
		 *
		 * This used to return here whatever the answer was, so a mask
		 * like SYM_EXP|NOLOAD was only ever searched in the block. A
		 * marker that lives in NOLOAD and not in the block - "\0
		 * shellcode \0" is one, because the byte in front of a
		 * record's name is its flags and never zero - was reported
		 * absent from a rule that finds it every time. The engine does
		 * not behave that way: c_find_str answers the symbol halves,
		 * and falls through to the file regions when they say no.
		 *
		 * Same order here, so the panel and the scan agree about which
		 * occurrence gets reported.
		 */
		if (d->at != KOF_BROKEN || !(d->mask & ~KOF_SCAN_SYM))
			return;
		/* Nothing in the halves: start the file search clean, and stop
		 * claiming the offsets are block offsets. */
		d->sym = 0;
		d->n_hits = 0;
		d->hits_clipped = 0;
		d->at_mask = 0;
		d->at_rgn[0] = 0;
	}
	if (d->len > ob->buf.n)
		return;

	/*
	 * SEARCHED BY THE ENGINE, NOT BY A SECOND SEARCH WRITTEN HERE.
	 *
	 * This used to walk the buffer comparing d->bytes itself, which was a
	 * copy of the matcher with two of its rules missing: a hex pattern with
	 * a wildcard has no byte run to compare at all, and a literal was
	 * compared without the word and case rules the module will be matched
	 * under. So the panel could say "found" about a marker the database
	 * will not find, and "not found" about one it will.
	 *
	 * kof_hex_compile turns the written pattern into the same program the
	 * pack stores, and kof_match_where runs the same walk over these bytes.
	 * Whatever the panel says about a marker is now what the scan will do
	 * with it, including the parts nobody here had to know about.
	 */
	if (!decl_pattern(d, prog, &pat, &plen, &kind, &flags))
		return;

	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0))
		return;
	kof_match_begin(&m, kof_buf_make(ob->buf.p, ob->buf.n));

	/*
	 * EVERY OCCURRENCE, NOT THE FIRST ONE.
	 *
	 * This stopped at the first match and judged the marker by where that
	 * landed - so a string present in BOTH the declared region and some
	 * other one was reported as living in whichever came first in the file.
	 * With the other one first, the row said "declared in CODE, found in
	 * DATA" and coloured itself as a rule that cannot fire, about a rule
	 * that fires perfectly: the bytes are in CODE as well, and the module
	 * searches CODE.
	 *
	 * So an occurrence INSIDE the declared region wins, wherever it sits in
	 * the file, and the first occurrence anywhere is kept as the fallback
	 * for the case where none of them is.
	 */
	while (from < ob->buf.n) {
		uint32_t nd;

		at = kof_match_where(&m, from, ob->buf.n - from, pat,
				     (uint16_t)plen, kind, flags);
		if (at == KOF_BROKEN)
			break;
		/*
		 * RE-ASKED, BECAUSE RESTARTING MOVED THE WORD BOUNDARY.
		 *
		 * A range search treats the START of its range as a word
		 * boundary - that is right when the range is a region a module
		 * named, and wrong here, where the range start is only "past
		 * the last hit". Walking occurrences this way, every hit after
		 * the first was judged word-initial whatever byte preceded it,
		 * so the pane could light a run that the module will not match.
		 *
		 * kof_match_at has no window and uses the object, which is the
		 * boundary that applies to the file being examined.
		 */
		if ((flags & KOF_STR_FULLWORD) &&
		    !kof_match_at(&m, at, pat, (uint16_t)plen, kind, flags)) {
			from = at + 1u;
			continue;
		}
		/*
		 * Recorded before anything is decided about it.
		 *
		 * The walk used to return the moment it found the occurrence
		 * the row would report, so the pane knew about that one and no
		 * other. Every occurrence is a place worth reading, so the
		 * search now runs to the end of the object and the choice of
		 * which one the row names is made from the whole list.
		 */
		if (d->n_hits < DECL_HITS_MAX)
			d->hits[d->n_hits++] = at;
		else
			d->hits_clipped = 1;

		nd = node_at(v, d->obj, at);
		if (first == KOF_BROKEN) {
			first = at;
			first_nd = nd;
		}
		/*
		 * EVERY region this string turns up in, not the first one.
		 *
		 * What this feeds is the offer to widen the rule's range, and
		 * that offer has to name where the bytes ARE - all of it. Built
		 * from the first occurrence alone, a string present in two
		 * regions proposed whichever came earlier in the file, so a
		 * marker in both NOLOAD and DATA could be answered with the
		 * wrong one and the rule would still not fire.
		 */
		if (nd < v->n_node)
			seen_mask |= v->node[nd].mask;
		/*
		 * In the region the module searches: this is the occurrence
		 * the ROW reports, and nothing later can improve on it. The
		 * walk carries on regardless - the pane wants the rest.
		 *
		 * Only a range that NAMES regions can be satisfied this way -
		 * an unset mask means nothing has been decided yet, and
		 * KOF_SCAN_ALL is satisfied by any occurrence at all.
		 */
		if (d->at == KOF_BROKEN &&
		    (!d->mask || d->mask == KOF_SCAN_ALL ||
		     (nd < v->n_node && (d->mask & v->node[nd].mask)))) {
			d->at = at;
			d->cur_hit = d->n_hits ? d->n_hits - 1u : 0u;
			if (nd < v->n_node && v->node[nd].mask) {
				d->at_mask = v->node[nd].mask;
				snprintf(d->at_rgn, sizeof d->at_rgn, "%s",
					 v->node[nd].label);
			}
		}
		from = at + 1u;
		if (d->hits_clipped && d->at != KOF_BROKEN)
			break;  /* the list is full and the row has its answer */
	}
	/*
	 * How long each of them actually is, asked of the matcher.
	 *
	 * kof_match_where says where a match starts and not where it ends, and
	 * the engine keeps that to itself. Truncating the buffer is how to ask:
	 * a match needs its whole length to be there, so the shortest cut the
	 * pattern still matches under IS its length here. Monotonic - a longer
	 * cut can only help - so it is a bisection rather than a walk, eight
	 * probes for the widest jump the compiler allows.
	 *
	 * Skipped entirely for a pattern whose length is fixed, which is nearly
	 * all of them.
	 */
	decl_hit_lens(d, &m, ob->buf.p, ob->buf.n, pat, plen, kind, flags);
	kof_match_state_free(&m);
	if (d->at != KOF_BROKEN)
		return;

	/* Present, and nowhere the module looks. That is the finding. */
	if (first != KOF_BROKEN) {
		d->at = first;
		d->cur_hit = 0;
		if (first_nd < v->n_node && v->node[first_nd].mask) {
			/*
			 * The row still points at the first occurrence, because
			 * a reader jumping to it wants one address. The MASK is
			 * the union, because the range that would find this
			 * string has to cover everywhere it is.
			 */
			d->at_mask = seen_mask ? seen_mask
					       : v->node[first_nd].mask;
			if (d->at_mask == v->node[first_nd].mask)
				snprintf(d->at_rgn, sizeof d->at_rgn, "%s",
					 v->node[first_nd].label);
			else
				rng_name_of(ob->fmt, d->at_mask, d->at_rgn,
					    sizeof d->at_rgn);
			d->off_rgn = 1;
		}
	}
}

/* Is this file offset inside a string the draft declares. */
static int decl_kind(struct view *v, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < v->n_decl; i++) {
		const struct decl *d = &v->decl[i];

		uint32_t j;

		/*
		 * `off` is an offset in whatever the pane is showing, and a
		 * marker's hits are in whatever space it was found in. Compare
		 * them only when those are the same space - otherwise a block
		 * offset lights an unrelated byte at the same number in a
		 * region the marker is not in.
		 */
		if (d->sym != v->node[v->sel_node].sym ||
		    d->obj != v->node[v->sel_node].obj)
			continue;
		if (!d->n_hits) {
			/* Set by a path that never searched. One is still
			 * better than none. */
			if (d->at != KOF_BROKEN &&
			    off >= d->at && off < d->at + d->len)
				return 1;
			continue;
		}
		for (j = 0; j < d->n_hits; j++) {
			if (off < d->hits[j])
				break;  /* sorted: nothing later can contain it */
			if (off < d->hits[j] + d->hit_len[j])
				return 1;
		}
	}
	return 0;
}

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
static void sym_flag_str(uint8_t f, char *out)
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
static void sym_shn_str(const uint8_t *r, char *out, size_t n)
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

static void draw_hex(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	int top = hex_top(), bot = hex_last();
	int col = TREE_W + 3;
	int per = (g_cols - col - 12) / 4;
	int row;
	uint64_t at = v->rgn_at;
	/*
	 * WHERE THE BYTES COME FROM, and it is not always the object.
	 *
	 * A symbol row draws the KSYM block, which is built rather than read
	 * out of the file, so the pane is pointed at that buffer instead. Held
	 * as one pointer rather than branched on per byte: the pane reads it
	 * three times per column and a test repeated there is a test that can
	 * be forgotten in one of the three.
	 *
	 * `sym` also turns the HIGHLIGHTING off. hit_kind and decl_kind take
	 * FILE offsets - a marker's occurrences, a declared string's hits - and
	 * the offsets here are into the block, so asking them would light bytes
	 * that mean nothing: the highlight would be at the same numeric offset
	 * as a real hit somewhere entirely unrelated.
	 */
	uint64_t base_n = ob->buf.n;
	const uint8_t *base = ob->buf.p;
	int sym = sym_view(v);

	if (sym)
		base = sym_block(v, &base_n);
	if (!base)
		base_n = 0;

	if (per > 16)
		per = 16;
	if (per < 4)
		per = 4;
	v->per = per;

	for (row = top; row <= bot; row++) {
		uint64_t run = 0, off = view_map(v, at, &run);
		int k;

		/*
		 * Overwrite, then clear the tail - not clear, then write.
		 *
		 * A hex row fills its width, so writing over the old one leaves
		 * nothing to erase in front of it. Erasing first put every row
		 * of the pane through a blank state before its bytes arrived,
		 * and on a terminal that ignores synchronized output that blank
		 * is on screen: holding page-down strobed the whole pane.
		 */
		out_at(o, row, col);
		if (at >= v->rgn_len) {
			out_str(o, "\033[K");
			continue;
		}
		out_fmt(o, A_LOC "%08llx" A_OFF "  ",
			(unsigned long long)off);
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
				uint8_t bv = fo < base_n ? base[fo] : 0;
				/* hit_kind compares spaces itself now, so an
				 * engine hit inside a symbol record lights in
				 * the row that shows it. */
				int h = hit_kind(v, fo);

				/*
				 * decl_kind runs on a symbol row too.
				 *
				 * It used to be gated off there, from before a
				 * declaration recorded WHICH space its offsets
				 * were in: a block offset read as a file offset
				 * would have lit an unrelated byte at the same
				 * number. It records that now and compares only
				 * markers from the same space, so the gate is
				 * what stops a marker taken from SYM_EXP from
				 * being lit in the very row it was taken from.
				 *
				 * hit_kind stays gated: those are the engine's
				 * hits, which are file offsets and have no
				 * meaning here.
				 */
				out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
					h ? (h == 1 ? A_HIT1 : A_HIT2)
					  : decl_kind(v, fo) ? A_HIT3
					  : sym ? sym_byte_colour(fo)
					  : byte_colour(bv));
				out_fmt(o, "%02X", bv);
				out_str(o, A_OFF);
			}
		}
		out_str(o, "  ");
		for (k = 0; k < per && at + (uint64_t)k < v->rgn_len; k++) {
			uint64_t fo = view_map(v, at + (uint64_t)k, 0);
			uint8_t c = fo < base_n ? base[fo] : 0;
			int h = hit_kind(v, fo);

			out_str(o, in_sel(v, at + (uint64_t)k) ? A_SELB :
				h ? (h == 1 ? A_HIT1 : A_HIT2)
				  : decl_kind(v, fo) ? A_HIT3
				  : sym ? sym_byte_colour(fo)
				  : byte_colour(c));
			out_fmt(o, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
			out_str(o, A_OFF);
		}
		out_str(o, "\033[K");
		at += (uint64_t)per;
	}
	/* Only when the rows leave the column free. On a narrow terminal the
	 * hex reaches the edge, and a bar drawn over the last ASCII column
	 * would be a scrollbar that eats the thing it is scrolling. */
	if (col + 8 + 2 + per * 3 + 2 + per <= g_cols)
		scrollbar(o, g_cols, top, bot, v->rgn_at, v->rgn_len,
			  (uint64_t)(bot - top + 1) * (uint64_t)per);
}

/* The composed name a scan would print for this module, less the target. */
/*
 * The name to show, and only as much of it as is known.
 *
 * A variant is what a module REPORTED, so it exists only once it has fired.
 * Showing the first declared one otherwise put "Rootkit:LKM-Diamorphine-x64"
 * beside "hit 0", which reads as a detection that also says it did not detect -
 * and the variant named was simply the first in the file, not one anything had
 * concluded. Without a verdict the family is the whole of what can be said.
 */
static void touch_name(const struct kof_touch *t, char *out, size_t cap)
{
	const char *fam = t->family[0] ? t->family : "?";

	/* The engine's spelling. The "(n matchers)" tail is this panel's own and
	 * is added after it, never mixed into it - see kof_name_compose. */
	kof_name_compose(out, cap, NULL, kof_maltype_name(t->maltype), fam,
			 t->fired_name);
	if (!t->fired_name && t->n_names > 1u) {
		size_t at = strlen(out);

		/*
		 * MATCHERS, which is what this tool calls the find-pattern
		 * blocks a module is written out of.
		 *
		 * The number is the count of verdict names the module can
		 * report, and it says "matchers" because that is what those
		 * names correspond to in a module's source: one per block that
		 * can conclude something. It is not read out of the module's
		 * code - a compiled blob has no such count to read - so a
		 * module that reports one name from two blocks will say one.
		 * Called "variants" before, which named the wrong half: a
		 * reader wants to know how many ways this module can fire, not
		 * how many spellings the answer has.
		 */
		snprintf(out + at, cap - at, " (%u matchers)", t->n_names);
	}
}

/* Defined with the input loop; the status line needs it to age a message. */
static uint64_t now_ms(void);

static const char *touch_colour(const struct kof_touch *t)
{
	return t->fired                        ? A_BAD :
	       t->kind == KOF_TOUCH_ELSEWHERE  ? A_LOC :
	       t->kind == KOF_TOUCH_INELIGIBLE ? A_DIM : A_WARN;
}

/*
 * Which module opened an object, coloured by what that module is.
 *
 * An EXECUTABLE PACKER is red. Its whole purpose is that the file cannot be
 * read as it stands, and there is no ordinary reason to ship a program that
 * way; that it was recognised at all is a statement about the object.
 *
 * A DECOMPRESSOR, ARCHIVE OR DOCUMENT PARSER is yellow. It says the object
 * arrived inside a container, which is how nearly all software arrives.
 *
 * The engine does not classify its unpackers - a module is only a kof_unpack
 * entry point and whatever name it gives itself through kof_debug - so the
 * split is made here, from that name. Unknown names take the quieter colour:
 * a module this list has not heard of is far more likely to be a new container
 * than a new packer, and guessing wrong towards red is the failure that trains
 * people to ignore the colour.
 */
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
/*
 * The bottom line: what is known about this object on the left, what is under
 * the cursor on the right.
 *
 * They used to be the same space, so making a selection erased the marker
 * counts - the two things a reader compares while choosing bytes. They are
 * different questions with different lifetimes and they get different halves.
 *
 * The pane indicator is gone. It named the thing with the keyboard focus, which
 * the caret in that pane already says, and it was the first thing on the line
 * that nobody needed.
 */
/*
 * The draft, as it stands.
 *
 * Grouped visually by region rather than sorted, because the order markers were
 * chosen in is information - it is the order somebody read the object - and a
 * signature's declarations do not care about order at all.
 */
static const char *const maltype_word[] = {
	"Virus", "Trojan", "Rootkit", "Botnet", "Ransom",
	"Miner", "Adware", "Exploit", "Dropper", "Hacktool"
};
#define MALTYPE_N (sizeof maltype_word / sizeof maltype_word[0])

/* How many markers are in this condition. */
/* Markers not yet in any condition. */
static uint32_t decl_free(struct view *v)
{
	uint32_t i, n = 0;

	for (i = 0; i < v->n_decl; i++)
		n += v->decl[i].grp == 0;
	return n;
}

/*
 * Does a range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything - a
 * bit test alone would say a marker found in the code section is not inside the
 * whole file, which is the one answer that cannot be right.
 */
static int rng_holds(uint32_t rmask, uint32_t region)
{
	return (rmask & KOF_SCAN_ALL) || (region & KOF_SCAN_ALL) ||
	       (rmask & region);
}

/* What this matcher searches: what it was told, or the narrowest that holds
 * what it has. */
/*
 * Does this condition's expression name matcher `g`.
 *
 * Compared as a number rather than a character, because matcher 1 and matcher
 * 12 share a digit and a substring test would report the wrong one - which
 * would show up as a row listing matchers it does not use, and only on drafts
 * big enough that nobody was checking by hand any more.
 *
 * An empty expression names all of them, which is what it generates.
 */
static int cnd_uses(const struct cond *c, uint32_t g)
{
	const char *p = c->expr;

	while (*p) {
		if (*p >= '0' && *p <= '9') {
			char *end;
			unsigned long n;

			n = strtoul(p, &end, 10);
			p = end;

			if (n == (unsigned long)g + 1ul)
				return 1;
			continue;
		}
		p++;
	}
	return 0;
}

static uint32_t grp_mask(struct view *v, uint32_t g)
{
	uint32_t i, need = 0;

	if (v->grp[g].mask)
		return v->grp[g].mask;
	for (i = 0; i < v->n_decl; i++)
		if (v->decl[i].grp & (1u << g))
			need |= v->decl[i].mask;
	return need ? need : KOF_SCAN_ALL;
}

/*
 * Has this matcher a range worth naming.
 *
 * Holding markers is one way - the range is derived from where they are - and
 * being given one outright is the other. Only the first used to count, so a
 * matcher handed a range and no markers yet drew as having no range at all.
 */
static int grp_has_range(struct view *v, uint32_t g);

static uint32_t grp_count(struct view *v, uint32_t g)
{
	uint32_t i, n = 0;

	for (i = 0; i < v->n_decl; i++)
		n += (v->decl[i].grp >> g) & 1u;
	return n;
}


static int grp_has_range(struct view *v, uint32_t g)
{
	return grp_count(v, g) != 0 || v->grp[g].mask != 0;
}

static void grp_add(struct view *v)
{
	if (v->n_grp >= MAX_GROUP)
		return;
	memset(&v->grp[v->n_grp], 0, sizeof v->grp[0]);
	v->cur_grp = v->n_grp++;
	v->warn[0] = 0;
}

/*
 * A new condition, inside the one that is selected when it has no expression of
 * its own to lose - which is how a gate gets its branches without a separate
 * "nest this" gesture: add a condition, give it the gate, then add the ones
 * that live under it.
 */
/*
 * Is matcher `m` offerable to condition `c`.
 *
 * One predicate rather than two copies of the same three tests: the list that
 * is shown and the code that acts on the choice used to filter differently -
 * the list hid the parent's matchers and the action did not - so the nth row of
 * the list and the nth matcher that passed the action's filter were different
 * matchers, and picking "2" quietly added 1.
 */
static int cmatch_ok(struct view *v, uint32_t c, uint32_t m)
{
	if (cnd_uses(&v->cnd[c], m))
		return 0;
	/*
	 * Nor the ones its parent already tests: control only reaches a nested
	 * condition once the gate above it held, so repeating one of the gate's
	 * matchers inside is a search that has already been decided.
	 */
	if (v->cnd[c].parent >= 0 && cnd_uses(&v->cnd[v->cnd[c].parent], m))
		return 0;
	return 1;
}

/*
 * What a condition is called on screen: "1)" at the top level, "1-2)" for the
 * second thing nested inside the first.
 *
 * Numbered by position among its siblings rather than by its index in the
 * array, because the array is creation order and the screen is reading order.
 * A child called "2)" because it happened to be added second read as a sibling
 * of "1)" no matter how far it was indented.
 */
static void cnd_label(struct view *v, uint32_t i, char *out, size_t cap)
{
	uint32_t k, mine = 0, pos = 0;

	if (v->cnd[i].parent < 0) {
		for (k = 0; k < i; k++)
			pos += v->cnd[k].parent < 0;
		snprintf(out, cap, "%u.", pos + 1u);
		return;
	}
	for (k = 0; k < v->n_cnd; k++) {
		if (v->cnd[k].parent >= 0)
			continue;
		pos++;
		if (k == (uint32_t)v->cnd[i].parent)
			break;
	}
	for (k = 0; k < i; k++)
		mine += v->cnd[k].parent == v->cnd[i].parent;
	snprintf(out, cap, "%u.%u.", pos, mine + 1u);
}

/*
 * The expression a plain list of ids would produce, for comparing against what
 * is actually stored.
 *
 * The id row can add, remove and re-join, which covers every expression that is
 * a list. Anything else - a parenthesis, a mix of & and | - was typed, and
 * rendering that as a list would show a different condition from the one that
 * will be generated. So when the two disagree, the typed text is what is shown.
 */
static void cnd_canon(struct view *v, uint32_t g, char *out, size_t cap)
{
	const struct cond *c = &v->cnd[g];
	size_t at = 0;
	uint32_t m;

	out[0] = 0;
	for (m = 0; m < v->n_grp; m++) {
		if (!cnd_uses(c, m))
			continue;
		at += (size_t)snprintf(out + at, cap - at, "%s%u",
				       at ? (c->op ? "|" : "&") : "", m + 1u);
	}
}

/* Is another condition still to come at this one's level, under this parent.
 * The connector below it is drawn or not drawn on the answer. */
static int cnd_more_siblings(struct view *v, uint32_t i)
{
	uint32_t k;

	for (k = i + 1u; k < v->n_cnd; k++)
		if (v->cnd[k].parent == v->cnd[i].parent)
			return 1;
	return 0;
}

/* How deep a condition sits. Two levels is the whole of it: a third would be a
 * tree to navigate, and the logic it would express is already sayable in one
 * expression box. */
static int cnd_depth(struct view *v, uint32_t i)
{
	return v->cnd[i].parent >= 0 ? 1 : 0;
}

/*
 * Take a matcher out, and put every reference to it right.
 *
 * The one thing on this panel that could be added and not removed. Removing it
 * is not just a shift: the conditions name matchers by number, so every
 * expression has to be renumbered or a condition that said "2" starts meaning
 * the matcher that used to be 3 - the kind of change nothing on screen shows
 * and no one would look for.
 */
static void grp_remove(struct view *v, uint32_t g)
{
	uint32_t i, k;

	if (g >= v->n_grp)
		return;
	for (i = 0; i < v->n_decl; i++) {
		uint32_t lo = v->decl[i].grp & ((1u << g) - 1u);
		uint32_t hi = v->decl[i].grp >> (g + 1u);

		/* Its bit goes and every matcher above it moves down one -
		 * the same renumbering the matcher array itself gets. */
		v->decl[i].grp = lo | (hi << g);
	}
	for (k = 0; k < v->n_cnd; k++) {
		struct cond *c = &v->cnd[k];
		char out[64];
		size_t at = 0;
		const char *p = c->expr;
		int first = 1;

		out[0] = 0;
		while (*p) {
			if (*p >= '0' && *p <= '9') {
				char *end;
				unsigned long n;

				n = strtoul(p, &end, 10);
				p = end;

				if (n == (unsigned long)g + 1ul)
					continue;
				if (n > (unsigned long)g + 1ul)
					n--;
				at += (size_t)snprintf(out + at,
						       sizeof out - at, "%s%lu",
						       first ? "" : (c->op
						       ? "|" : "&"), n);
				first = 0;
				continue;
			}
			p++;
		}
		out[at] = 0;
		snprintf(c->expr, sizeof c->expr, "%s", out);
	}
	memmove(&v->grp[g], &v->grp[g + 1u],
		(v->n_grp - g - 1u) * sizeof v->grp[0]);
	v->n_grp--;
	if (v->cur_grp >= v->n_grp && v->n_grp)
		v->cur_grp = v->n_grp - 1u;
}

static void cnd_add(struct view *v, int nested)
{
	struct cond *c;

	if (v->n_cnd >= MAX_GROUP)
		return;
	c = &v->cnd[v->n_cnd];
	memset(c, 0, sizeof *c);
	c->parent = nested && v->n_cnd ? (int)v->cur_cnd : -1;
	v->cur_cnd = v->n_cnd++;
	v->warn[0] = 0;
}

/*
 * Drop a condition.
 *
 * Its children are lifted to the top rather than deleted with it: they are
 * separate conclusions that happened to share a gate, and taking the gate away
 * is a reason to re-read them, not a reason to lose them.
 */
static void cnd_remove(struct view *v, uint32_t i)
{
	uint32_t k;

	if (i >= v->n_cnd)
		return;
	for (k = 0; k < v->n_cnd; k++)
		if (v->cnd[k].parent == (int)i)
			v->cnd[k].parent = -1;
	memmove(&v->cnd[i], &v->cnd[i + 1u],
		(v->n_cnd - i - 1u) * sizeof v->cnd[0]);
	v->n_cnd--;
	for (k = 0; k < v->n_cnd; k++)
		if (v->cnd[k].parent > (int)i)
			v->cnd[k].parent--;
	if (v->cur_cnd >= v->n_cnd && v->n_cnd)
		v->cur_cnd = v->n_cnd - 1u;
}

static uint32_t cnd_children(struct view *v, uint32_t i)
{
	uint32_t k, n = 0;

	for (k = 0; k < v->n_cnd; k++)
		n += v->cnd[k].parent == (int)i;
	return n;
}

/*
 * The declared range that holds this region, made if there is not one.
 *
 * A region met for the first time becomes a range on its own; met again it
 * finds the range it is already in, merged or not. So the list of ranges grows
 * out of where markers were actually found, which is the only place a range
 * has any business coming from.
 */
/*
 * Does this range hold bytes found in that region.
 *
 * KOF_SCAN_ALL is the whole object, so a range built on it holds everything -
 * a bit test alone would have said a marker found in the code section is not
 * inside the whole file, which is the one answer that cannot be right.
 */
/*
 * A mask, spelled with the format's own region words.
 *
 * Built on demand rather than stored: a range is whatever a matcher currently
 * needs, and a name kept beside it would be one more thing to update when a
 * marker is added or taken away.
 */
static void rng_name_of(const struct kof_inspect_fmt *fmt, uint32_t mask,
			char *out, size_t cap)
{
	uint32_t b, k;
	size_t at = 0;

	out[0] = 0;
	if (mask & KOF_SCAN_ALL) {
		snprintf(out, cap, "WHOLE-FILE");
		return;
	}
	/*
	 * The symbol halves name themselves.
	 *
	 * The loop below asks the FORMAT what a bit is called, and these two
	 * are not a format's - they mean the same thing for every input that
	 * has a symbol block, which is why kofsig.h defines them rather than
	 * elf.h or pe.h. Left to the loop they would come back unnamed, and an
	 * unnamed mask falls out of the bottom of this function as WHOLE-FILE:
	 * a range that says "search the exports" would have been written into
	 * a rule as "search everything".
	 */
	for (b = 30u; b < 32u && at + 1u < cap; b++) {
		if (!(mask & (1u << b)))
			continue;
		at += (size_t)snprintf(out + at, cap - at, "%s%s",
				       at ? "&" : "",
				       b == 30u ? "SYM_IMP" : "SYM_EXP");
	}
	for (b = 0; b < 30u && at + 1u < cap; b++) {
		const char *w = NULL;

		if (!(mask & (1u << b)))
			continue;
		if (fmt)
			for (k = 0; k < fmt->n_regions; k++)
				if (fmt->regions[k] == (1u << b))
					w = fmt->region_name(1u << b);
		if (!w)
			continue;
		{
			const char *t = strrchr(w, '_');

			/*
			 * "&" and not "|" for the reader.
			 *
			 * The mask is a union of region bits, so the operator
			 * that BUILDS it is or - and the generated source says
			 * so, spelling it "CODE | DATA" in C. This string is
			 * not that: it answers "where does this matcher look",
			 * and the answer is both places.
			 */
			at += (size_t)snprintf(out + at, cap - at, "%s%s",
					       at ? "&" : "", t ? t + 1 : w);
		}
	}
	if (!out[0])
		snprintf(out, cap, "WHOLE-FILE");
}

/*
 * Write one matcher as the call it is.
 *
 * _all and _any short-circuit and _multi cannot - kofsig.h says so at the fold -
 * so the extremes get the macro that stops early rather than a threshold that
 * happens to equal them.
 */
/*
 * The C identifier for a range, spelled from the region words.
 *
 * Both the KOF_TARGET_RANGE that declares it and the search call that names it
 * go through here, because a range that is declared under one name and searched
 * under another is a build error found by the compiler rather than by this - and
 * that used to happen, since the caller passed no format and got WHOLE_FILE for
 * everything.
 */
/*
 * How long a scan_range_ identifier can get: the prefix, plus the longest
 * region name rng_name_of produces (a join of every region word - for ELF
 * "headers_code_data_noload" is 24 characters on its own), plus the terminator.
 * Named so the two callers and this function cannot be sized differently -
 * which is how the identifier came to be cut in the first place.
 */
#define RNG_IDENT_MAX 64

static void rng_ident(const struct kof_inspect_fmt *fmt, uint32_t mask,
		      char *out, size_t cap)
{
	/* Forty, like every other rng_name_of caller. At 24 the display name of
	 * a mask over enough regions was cut before it became an identifier, so
	 * two different masks could have produced one scan_range_ name - two
	 * KOF_TARGET_RANGE declarations of the same identifier, which does not
	 * compile, in a file the tool reported as written. */
	char w[40];
	size_t i;

	/* Named the way bases/ names them - scan_range_data, not DATA. A bare
	 * region word at file scope is a short lowercase-able identifier in a
	 * translation unit that includes engine headers, which is how a draft
	 * ends up colliding with something it never mentioned. */
	/*
	 * Every separator the display name can hold becomes an underscore.
	 *
	 * This turns a string meant for a person into a C identifier, so it has
	 * to survive that string being reworded. It did not: the join moved
	 * from "|" to "&" and this still mapped only "|", so a range over two
	 * regions was declared as scan_range_code&data - a name no compiler
	 * accepts, in a file the tool reported as written.
	 */
	rng_name_of(fmt, mask, w, sizeof w);
	for (i = 0; w[i]; i++) {
		if (!((w[i] >= 'A' && w[i] <= 'Z') ||
		      (w[i] >= 'a' && w[i] <= 'z') ||
		      (w[i] >= '0' && w[i] <= '9')))
			w[i] = '_';
		else if (w[i] >= 'A' && w[i] <= 'Z')
			w[i] = (char)(w[i] - 'A' + 'a');
	}
	snprintf(out, cap, "scan_range_%s", w);
}

/*
 * TWO MATCHERS, ONE SCAN.
 *
 * "at least three of these five, otherwise at least two" is one question asked
 * once, not two questions. Written as two matchers it used to compile to two
 * kof_find_str_multi calls over the same markers in the same region - the same
 * work twice, and the second one only to compare its answer against a smaller
 * number.
 *
 * So matchers that ASK THE SAME THING - same kind of call, same range, same
 * markers - share one call in the generated body, and each keeps its own
 * threshold to compare against it:
 *
 *     uint32_t m1 = kof_find_str_multi(scan_range_code, s0, s1, s2, s3, s4);
 *
 *     if (m1 >= 3)
 *             KOF_SCAN_INFECT("Strong");
 *     else if (m1 >= 2)
 *             KOF_SCAN_SUSPECT("Weak");
 *
 * Only find_multi shares. all and any carry no threshold, so two of them that
 * asked the same thing would be the same matcher written twice - which is a
 * mistake the panel refuses rather than a shape to optimise.
 */
/*
 * WHAT A MATCHER'S THRESHOLD REALLY IS.
 *
 * The three kinds are three spellings of one comparison against a count:
 * find_any is "at least one", find_all is "all of them", find_multi says the
 * number itself. Measured rather than argued - a rule written each way over the
 * same four markers agrees on every sample, including the one where none are
 * present.
 *
 * What differs is the WORK, not the answer, and that is the whole constraint on
 * folding them together: kofsig.h folds any to `a || b || c` and all to
 * `a && b && c`, so they stop at the first marker that settles the question,
 * while multi has to look for all of them to produce a count. Turning an any
 * into a count would therefore make a rule slower - unless the count is already
 * being computed for something else, which is exactly and only when this folds.
 */
static uint32_t grp_thresh_eff(struct view *v, uint32_t g)
{
	if (v->grp[g].rule == 1)
		return 1u;                      /* any: at least one */
	if (v->grp[g].rule == 2)
		return v->grp[g].thresh;
	return grp_count(v, g);                 /* all: every one of them */
}

/* The same question - same range, same markers - whatever it is spelled as. */
static int grp_same_set(struct view *v, uint32_t a, uint32_t b)
{
	uint32_t i;

	if (a == b)
		return 1;
	if (grp_mask(v, a) != grp_mask(v, b))
		return 0;
	/* The same markers, and no others. Order is not part of the question:
	 * a matcher is a set. */
	for (i = 0; i < v->n_decl; i++) {
		int in_a = (v->decl[i].grp >> a) & 1u;
		int in_b = (v->decl[i].grp >> b) & 1u;

		if (in_a != in_b)
			return 0;
	}
	return 1;
}

/* Same question AND same answer to it: a copy, whatever the two are spelled as. */
static int grp_same_call(struct view *v, uint32_t a, uint32_t b)
{
	return grp_same_set(v, a, b) &&
	       grp_thresh_eff(v, a) == grp_thresh_eff(v, b);
}

/*
 * The lowest numbered matcher asking the same thing as this one - the one whose
 * number names the shared variable, so the name does not move when a later
 * matcher is removed.
 */
static uint32_t grp_lead(struct view *v, uint32_t g)
{
	uint32_t i;

	for (i = 0; i < g; i++)
		if (grp_same_set(v, i, g))
			return i;
	return g;
}

/* Does this matcher's call get a variable: multi, and asked more than once. */
static int grp_shared(struct view *v, uint32_t g)
{
	uint32_t i, n = 0, multi = 0;

	for (i = 0; i < v->n_grp; i++) {
		if (!grp_same_set(v, i, g))
			continue;
		n++;
		multi += v->grp[i].rule == 2;
	}
	/*
	 * At least two asking it, and at least one of them a find_multi - that
	 * second half is what keeps the fold honest. A group of any/all
	 * matchers alone short circuits today; giving them a count would be
	 * work they currently avoid. Once ANY of them needs the number, every
	 * other one in the group gets to compare against it for free.
	 */
	return n > 1u && multi > 0u;
}

/* The call itself, without whatever is compared against it. `force_multi` asks
 * for the counting form whatever the matcher is spelled as, which is what a
 * shared call has to be. */
static void emit_call_as(FILE *f, struct view *v, uint32_t g, int force_multi)
{
	const struct group *q = &v->grp[g];
	char nm[RNG_IDENT_MAX];
	uint32_t i;

	rng_ident(cur_obj(v)->fmt, grp_mask(v, g), nm, sizeof nm);
	fprintf(f, "kof_find_str_%s(%s",
		force_multi ? "multi"
			    : q->rule == 1 ? "any" : q->rule == 2 ? "multi"
							         : "all", nm);
	for (i = 0; i < v->n_decl; i++)
		if (v->decl[i].grp & (1u << g))
			fprintf(f, ", s%u", i);
	fprintf(f, ")");
}

static void emit_call(FILE *f, struct view *v, uint32_t g)
{
	emit_call_as(f, v, g, 0);
}

static void emit_call_multi(FILE *f, struct view *v, uint32_t g)
{
	emit_call_as(f, v, g, 1);
}

static void emit_matcher(FILE *f, struct view *v, uint32_t g)
{
	const struct group *q = &v->grp[g];

	/* The call happened once, above; this is only the comparison - and any
	 * and all become comparisons here too, which is what they are. */
	if (grp_shared(v, g)) {
		fprintf(f, "m%u >= %u", grp_lead(v, g) + 1u,
			grp_thresh_eff(v, g));
		return;
	}
	emit_call(f, v, g);
	if (q->rule == 2)
		fprintf(f, " >= %u", q->thresh);
}

/*
 * The expression, with each matcher id replaced by its call.
 *
 * Anything that is not a digit, a space, "&", "|" or a bracket is dropped
 * rather than passed through: this text becomes C, and the one thing it must
 * not do is carry something the person typing did not mean as code.
 */
static void emit_expr(FILE *f, struct view *v, const char *e)
{
	int any = 0;

	if (!e[0]) {
		/*
		 * Nothing to test.
		 *
		 * It used to mean every matcher ANDed together - a whole
		 * signature's worth of meaning attached to an empty field. It
		 * is unreachable now anyway: a branch that decides something is
		 * refused until it names a matcher, and a grouping with none is
		 * written as a block rather than as an if.
		 */
		(void)any;
		fprintf(f, "1");
		return;
	}
	while (*e) {
		if (*e >= '0' && *e <= '9') {
			uint32_t id = 0;

			while (*e >= '0' && *e <= '9')
				id = id * 10u + (uint32_t)(*e++ - '0');
			if (id >= 1u && id <= v->n_grp)
				emit_matcher(f, v, id - 1u);
			else
				fprintf(f, "0");
			continue;
		}
		if (*e == '&')
			fprintf(f, " && ");
		else if (*e == '|')
			fprintf(f, " || ");
		else if (*e == '(' || *e == ')')
			fputc(*e, f);
		e++;
	}
}

/*
 * The author's note for a matcher or a condition, as a C comment.
 *
 * On its own line above the code it belongs to, indented with it, and only when
 * there is one: a blank comment above every branch is noise, and noise in a
 * generated file is what teaches people to stop reading generated files.
 * Newlines cannot appear in these boxes and the text is bounded, so the only
 * thing to guard is a sequence that would close the comment early.
 */
static void emit_note(FILE *f, const char *note, int depth)
{
	const char *p;
	int d;

	if (!note[0])
		return;
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	fputs("/* ", f);
	for (p = note; *p; p++)
		fputc((*p == '*' && p[1] == '/') ? ' ' : *p, f);
	fputs(" */\n", f);
}

/* The verdict a condition reports, or nothing when it reports none. */
static void emit_verdict(FILE *f, const struct cond *c, int depth)
{
	int d;

	for (d = 0; d < depth; d++)
		fputc('\t', f);
	if (c->level == LV_NONE) {
		/*
		 * Matched, reports nothing, and stops.
		 *
		 * The stop is the whole of it. Verdicts return, so everything
		 * after a branch runs only when that branch declined - and a
		 * branch that declines without returning declines nothing: the
		 * gate's verdict below would fire anyway. Returning is what
		 * makes this say "these bytes are here and they are fine".
		 */
		fprintf(f, "/* matched, and deliberately reports nothing */\n");
		for (d = 0; d < depth; d++)
			fputc('\t', f);
		fprintf(f, "return;\n");
		return;
	}
	fprintf(f, "KOF_SCAN_%s(", c->level == LV_SUSPECT ? "SUSPECT"
							  : "INFECT");
	if (c->var_kind == 2 && c->variant[0])
		fprintf(f, "\"%s\"", c->variant);
	else if (c->var_kind == 1)
		fprintf(f, "KOF_MALVAR_GENERIC");
	else
		fprintf(f, "KOF_MALVAR_AUTO");
	fprintf(f, ");\n");
}

/*
 * One branch, and the ones nested under it.
 *
 * `chained` makes this an "else if" rather than an "if". Conditions nested
 * under a gate are alternatives to each other - which variant of the thing the
 * gate established - so they chain, and the gate's own verdict becomes the else
 * that catches the case where the gate held and none of the alternatives did.
 * Without that else a gate with children concluded nothing at all when its
 * children all missed, which is the one outcome a gate is worth writing for.
 *
 * Top level conditions do not chain: they are separate detections that happen
 * to live in one module, not alternatives to one another.
 */
static void emit_cond(FILE *f, struct view *v, uint32_t i, int depth,
		      int chained)
{
	const struct cond *c = &v->cnd[i];
	uint32_t k;
	int d;

	/*
	 * A matcher's note goes above the branch that uses it, not beside the
	 * call: the call is one term of an expression inside an if, and a
	 * comment there would break the line that has to stay readable. Named
	 * by number so it can be told from the condition's own note when a
	 * branch carries several.
	 *
	 * A GROUPING GETS NONE OF THEM. It has no test of its own - it is a
	 * brace around some branches - so it uses no matcher, and its children
	 * carry their own notes a line or two below. The filter below used to be
	 * gated on the condition HAVING an expression, and a grouping has none,
	 * so it printed every matcher's note in the file and then each child
	 * printed its own again. Prometei_00.c came out with three notes above
	 * the brace and the same three repeated inside it.
	 *
	 * An empty expression on a LEAF is a different thing: it means the
	 * default, every matcher joined by &, so there every note belongs.
	 */
	if (!(!c->expr[0] && cnd_children(v, i)))
		for (k = 0; k < v->n_grp; k++) {
			char t[120];

			if (!v->grp[k].note[0])
				continue;
			if (c->expr[0] && !cnd_uses(c, k))
				continue;
			snprintf(t, sizeof t, "matcher %u: %s", k + 1u,
				 v->grp[k].note);
			emit_note(f, t, depth);
		}
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	if (!c->expr[0] && cnd_children(v, i)) {
		/*
		 * A grouping: no test of its own, so no if of its own.
		 *
		 * Written as a bare block rather than "if (1)", because that is
		 * what it is - a brace around some branches so the statement
		 * after them belongs to the group and not to whatever came
		 * before it. Verdicts return, so that statement is reached
		 * exactly when none of the branches inside concluded.
		 */
		fprintf(f, "{\n");
	} else {
		fprintf(f, "%sif (", chained ? "else " : "");
		emit_expr(f, v, c->expr);
		fprintf(f, ")");
	}

	if (!cnd_children(v, i)) {
		if (c->level == LV_NONE) {
			fprintf(f, " {\n");
			emit_verdict(f, c, depth + 1);
			for (d = 0; d < depth; d++)
				fputc('\t', f);
			fprintf(f, "}\n");
			return;
		}
		fprintf(f, "\n");
		emit_verdict(f, c, depth + 1);
		return;
	}

	if (c->expr[0])
		fprintf(f, " {\n");
	{
		uint32_t prev = v->n_cnd;

		for (k = 0; k < v->n_cnd; k++) {
			if (v->cnd[k].parent != (int)i)
				continue;
			/*
			 * Chained or not, as the rule between them says.
			 *
			 * It used to be decided by depth - nested siblings
			 * always chained, top level ones never did - which made
			 * the same two rows on screen mean two different things
			 * depending on where they sat.
			 */
			emit_cond(f, v, k, depth + 1,
				  prev < v->n_cnd && !v->cnd[prev].join);
			prev = k;
		}
	}
	/*
	 * The gate's own verdict, after the children rather than as an else.
	 *
	 * Every KOF_SCAN_INFECT and KOF_SCAN_SUSPECT reports and returns, so a
	 * child that concluded anything has already left the function - which
	 * means the statement after the children is reached exactly when none
	 * of them concluded, which is what a gate's own verdict means.
	 *
	 * Written as "else" it bound to the LAST child's if and nothing more:
	 * with two children it fired whenever the second missed, whatever the
	 * first had done.
	 */
	if (c->level != LV_NONE)
		emit_verdict(f, c, depth + 1);
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	fprintf(f, "}\n");
}

/*
 * Write the draft out as a signature source.
 *
 * One KOF_TARGET_RANGE per distinct region, one search call per range, and the
 * calls joined with && - which is the shape every hand-written signature in
 * bases/ already has. The range comes from where each marker was found, so the
 * one thing a hand-written signature usually gets wrong is the one thing this
 * cannot get wrong.
 *
 * Never into bases/. That directory is the content that ships, and a draft is
 * not content until somebody has looked at it.
 */
/*
 * The draft, as one number.
 *
 * Compared against the number at the last save to answer "has this changed" -
 * the same trick the frame repaint uses, and for the same reason: a flag set by
 * hand at every place that mutates the draft is a flag that gets missed at the
 * next place, and the one that gets missed is the one that loses somebody's
 * work.
 */
/*
 * The status line's two voices.
 *
 * Red is for something that went wrong and stopped what was asked for: a
 * required field absent, a file that could not be written. Yellow is for
 * something worth knowing that stopped nothing - a rule already in the tree
 * carrying these markers, a draft that came back only partly read, a string
 * that is not in this object.
 *
 * They shared one colour, and the case that showed it up is "same markers as
 * HCRootkit.c": it appears AFTER a Save As that worked, because the file just
 * written now has a sibling with the same patterns. Painted red it reads as
 * the save having failed.
 */
static void say_err(struct view *v, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(v->warn, sizeof v->warn, fmt, ap);
	va_end(ap);
	v->warn_bad = 1;
}

static void say_note(struct view *v, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(v->warn, sizeof v->warn, fmt, ap);
	va_end(ap);
	v->warn_bad = 0;
}

static uint32_t draft_hash(struct view *v)
{
	uint32_t h = 2166136261u, i, j;

	#define MIX(b) do { h ^= (uint32_t)((uint64_t)(b) & 0xffffffffu); \
			    h = (uint32_t)((uint64_t)h * 16777619u); } while (0)
	for (i = 0; v->family[i]; i++)
		MIX((uint8_t)v->family[i]);
	for (i = 0; v->note[i]; i++)
		MIX((uint8_t)v->note[i]);
	MIX(v->maltype);
	for (i = 0; i < v->n_rng_add; i++)
		MIX(v->rng_add[i]);
	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		MIX(v->opt_on[i]);
		MIX(v->opt_val[i]);
		MIX(v->opt_val[i] >> 32);
	}
	for (i = 0; i < v->n_decl; i++) {
		const struct decl *d = &v->decl[i];

		MIX(d->len); MIX(d->hex); MIX(d->mask);
		MIX(d->grp); MIX(d->fullword); MIX(d->icase);
		/* The spelling when there is one - it is what would be
		 * written, and `bytes` may be NULL beside it. */
		if (d->hexs[0])
			for (j = 0; d->hexs[j]; j++)
				MIX((uint8_t)d->hexs[j]);
		else
			for (j = 0; j < d->nbytes; j++)
				MIX(d->bytes[j]);
	}
	for (i = 0; i < v->n_grp; i++) {
		MIX(v->grp[i].rule); MIX(v->grp[i].thresh); MIX(v->grp[i].mask);
		for (j = 0; v->grp[i].note[j]; j++)
			MIX((uint8_t)v->grp[i].note[j]);
	}
	for (i = 0; i < v->n_cnd; i++) {
		const struct cond *c = &v->cnd[i];

		MIX(c->level); MIX(c->var_kind); MIX(c->parent);
		MIX(c->op); MIX(c->join);
		for (j = 0; c->expr[j]; j++)
			MIX((uint8_t)c->expr[j]);
		for (j = 0; c->variant[j]; j++)
			MIX((uint8_t)c->variant[j]);
	}
	#undef MIX
	return h;
}

/* The sample in front of the reader, as the metadata block names it. */
/*
 * The sample this rule was tested against: THE FILE, not the object.
 *
 * It used to name the selected object, and inside a container that is the
 * child's name - which for an unpacked payload is its index, so a rule drafted
 * against something UPX had just produced recorded "Test sample: 0".
 *
 * The file is the right answer even when the draft was written against a child,
 * because the line exists so that somebody can reproduce this: what they need
 * is the thing to feed the engine, and the engine reaches the child by itself.
 * Which child it was is not lost either - it is what the rule's target format
 * and its ranges say.
 */
static const char *draft_sample(struct view *v)
{
	const char *n = (v->path && v->path[0]) ? v->path : cur_obj(v)->name;
	const char *s = strrchr(n, '/');

	return s ? s + 1 : n;
}

/* Is this sample already in the rule's history. */
static int meta_has_sample(struct view *v)
{
	const char *w = draft_sample(v);
	uint32_t i;

	for (i = 0; i < v->n_meta_sample; i++)
		if (!strcmp(v->meta_sample[i], w))
			return 1;
	return 0;
}

/*
 * HAS THE READER CHANGED ANYTHING.
 *
 * Narrower than draft_dirty, and the two are not interchangeable. draft_dirty
 * also answers yes when the draft is fine but this sample is not yet recorded in
 * it - which is a reason to offer Save, and NOT a reason to say there is work to
 * lose. Opening a file loads the signature that matched it, so on any detected
 * sample draft_dirty is true before the reader has touched a key, and using it to
 * guard "move on" made Next file dead on exactly the files somebody is stepping
 * through.
 */
static int draft_edited(struct view *v)
{
	return draft_hash(v) != v->saved_hash;
}

static int draft_dirty(struct view *v)
{
	/*
	 * A RULE TESTED AGAINST A NEW SAMPLE HAS CHANGED.
	 *
	 * Not its logic - not one byte of what it matches - but the file on
	 * disk does not yet record that this rule was checked against this
	 * sample, and that is the fact the metadata block exists to keep. Left
	 * out, Save stayed greyed on exactly the case worth saving: open a rule,
	 * confirm it fires on a second sample, and there was no way to write
	 * that down.
	 */
	/*
	 * An EMPTY draft is not dirty, whatever the metadata says.
	 *
	 * The test below asks whether this sample has been recorded, and on a
	 * draft with nothing in it the answer is no and always will be - there
	 * is nothing to record it against. Read as dirty it made a viewer that
	 * had written nothing refuse to move on, which is how this was found.
	 */
	if (v->n_decl && !meta_has_sample(v))
		return 1;
	return draft_hash(v) != v->saved_hash;
}

/* Throw the draft away. Called before loading another signature into it, and
 * only once whoever owns the unsaved work has said so. */
static void draft_clear(struct view *v)
{
	uint32_t i;

	for (i = 0; i < v->n_decl; i++)
		free(v->decl[i].bytes);
	memset(v->decl, 0, sizeof v->decl);
	memset(v->grp, 0, sizeof v->grp);
	memset(v->cnd, 0, sizeof v->cnd);
	memset(v->opt_on, 0, sizeof v->opt_on);
	memset(v->opt_val, 0, sizeof v->opt_val);
	v->n_decl = v->n_grp = v->n_cnd = 0;
	v->n_rng_add = 0;
	v->cur_grp = v->cur_cnd = v->sel_decl = 0;
	v->family[0] = 0;
	v->maltype = 0;
	/* The note belongs to the signature, not to the session. Left behind,
	 * it followed the researcher from one rule into the next and got
	 * written into that one's file on the next save. */
	v->note[0] = 0;
	v->note_off = 0;
	v->foreign = 0;
	v->n_meta_sample = 0;
	v->n_meta_who = 0;
	v->meta_made[0] = 0;
	v->gen_path[0] = 0;
	v->gen_ok = 0;
	v->from_rule = 0;
	v->prow_off = 0;
	v->prow_seen = 0;
}

/*
 * Empty the panel and call that the saved state.
 *
 * draft_clear on its own leaves the panel looking unsaved: saved_hash still
 * describes whatever was in it, so an empty draft reads as work in progress and
 * the guards that ask "is there something to lose" all answer yes.
 *
 * This is what the New button does, and what a signature examined and then
 * abandoned needs - opening a rule to look at it loads it into the panel, and
 * the way back to a blank one should not be closing the program.
 */
static void draft_reset(struct view *v)
{
	draft_clear(v);
	v->saved_hash = draft_hash(v);
	v->sel_decl = 0;
	v->cur_grp = v->cur_cnd = 0;
	v->warn[0] = 0;
	say_note(v, "Panel cleared");
}

/* ---- reading a signature back out of its source ---------------------------
 *
 * The pack has the strings and the names; it does not have the logic, because
 * the logic is compiled code. So a rule shown in the panel has to come from the
 * file it was written in, and the file has to be found: the family names it,
 * except that a family may name several - bases/signatures/mirai.c and
 * mirai_42bb.c both declare "Mirai" on purpose - so the line each detection
 * carries is what settles it.
 *
 * Read the restricted way ksigbuilder reads them. Anything this cannot parse is
 * left out of the draft rather than guessed at, and the panel says how much of
 * the file it understood.
 */
#define SRC_MAX        512u
#define SRC_MAX_LINES  64u

struct src_ent {
	char     family[80];
	char     path[512];
	uint32_t line[SRC_MAX_LINES];
	uint32_t n_line;
	/*
	 * What this file searches for, independent of how it is written.
	 *
	 * A sum of per-string hashes, so reordering the declarations does not
	 * change it - which is the point: two signatures that look different
	 * only because their KOF_DEFINE_STRs are in another order are one
	 * signature written twice, and the database pays for both.
	 */
	uint32_t pat;
	uint32_t n_pat;

	/*
	 * What this file targets, folded the same way.
	 *
	 * Separate from the patterns because it answers a different question.
	 * Two modules can look for exactly the same bytes and still be two
	 * modules: the rootkit itself is a relocatable object and the thing
	 * that installs it is an executable, so the same five kernel symbol
	 * names mean a different family, a different malware type and a
	 * different subtype. Comparing patterns alone called that pair a
	 * duplicate and greyed out Save As on the second one.
	 */
	uint32_t tgt;
};

/* One identifier out of a comma list, trimmed. Returns where to carry on. */
static const char *src_ident(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	while (*p == ' ' || *p == '\t' || *p == ',')
		p++;
	while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
	       (*p >= '0' && *p <= '9') || *p == '_') {
		if (n + 1 < cap)
			out[n++] = *p;
		p++;
	}
	out[n] = 0;
	return p;
}

/*
 * One target declaration into a fingerprint.
 *
 * Case folded, because the two sides spell these from different places - the
 * panel holds "Rootkit" and the source says KOF_MALTYPE_ROOTKIT - and folded
 * by addition so the order the declarations appear in does not matter.
 */
static uint32_t tgt_mix(uint32_t h, const char *tok)
{
	uint32_t k = 2166136261u;

	for (; *tok; tok++) {
		uint8_t c = (uint8_t)*tok;

		if (c >= 'a' && c <= 'z')
			c = (uint8_t)(c - 'a' + 'A');
		k ^= c;
		k = (uint32_t)((uint64_t)k * 16777619u);
	}
	return h + k;
}

static uint32_t pat_of(const uint8_t *b, uint32_t n, int hex);

/*
 * One spelling for one pattern, so a hash of it means something.
 *
 * The same marker is written three ways: "2E 2E 5C" in a source file, "2e2e5c"
 * by somebody who prefers lower case, and "2E2E5C" when the panel rebuilds it
 * from a pack that kept the compiled program and not the text. They are the
 * same pattern, so the duplicate check has to see one string, not three.
 */
static void hex_canon(const char *in, char *out, size_t cap)
{
	size_t n = 0;

	for (; *in && n + 1u < cap; in++) {
		if (*in == ' ' || *in == '\t')
			continue;
		out[n++] = (char)toupper((unsigned char)*in);
	}
	out[n] = 0;
}

/*
 * WHAT A DECLARATION HASHES TO - THE SPELLING, NOT THE BYTES.
 *
 * The source side of the duplicate check reads a .c file and hashes the text
 * between the quotes. So the draft side has to hash the text it WOULD write
 * between those quotes, or the two never agree. They never did for a hex
 * marker: the file says "2E 2E 5C" and the draft hashed the three decoded
 * bytes, so a rule was never reported as a duplicate of itself.
 *
 * And now it cannot even try, because a hex pattern with a wildcard has no
 * decoded bytes at all - which is what turned a wrong answer into a null
 * dereference.
 */
static uint32_t decl_pat(const struct decl *d)
{
	char t[DECL_HEXS_CAP];
	size_t n = 0;
	uint32_t k;

	if (!d->hex)
		return pat_of(d->bytes, d->nbytes, 0);
	if (d->hexs[0]) {
		hex_canon(d->hexs, t, sizeof t);
		return pat_of((const uint8_t *)t, (uint32_t)strlen(t), 1);
	}
	/* Declared from a selection: generation writes it as plain pairs, so
	 * that is the spelling this has to hash. */
	for (k = 0; k < d->nbytes && n + 3u < sizeof t; k++)
		n += (size_t)snprintf(t + n, sizeof t - n, "%02X",
				      d->bytes[k]);
	t[n] = 0;
	return pat_of((const uint8_t *)t, (uint32_t)n, 1);
}

static uint32_t pat_of(const uint8_t *b, uint32_t n, int hex)
{
	uint32_t h = 2166136261u, i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h = (uint32_t)((uint64_t)h * 16777619u);
	}
	h ^= (uint32_t)hex;
	return h ? h : 1u;
}

static struct src_ent *g_src;
static uint32_t        g_n_src;
static int             g_src_done;

/*
 * DROP THE SOURCE INDEX, BECAUSE THE TREE UNDER IT HAS MOVED.
 *
 * The index is a cache of the bases tree, built once on first use and matched
 * against a fired module by the SOURCE LINE each of its detection names sits
 * on. That is a fine key while the sources hold still, and rebuilding is
 * exactly the moment they do not.
 *
 * The bug it exists for: generate a signature, press Rebuild database, and the
 * viewer showed every matcher as find_all. The new database carries the new
 * line numbers, the index still held the old ones, no source matched - so the
 * draft was rebuilt from the DATABASE, which keeps a module's strings and not
 * its logic, and a draft with no logic defaults to find_all. Closing and
 * reopening was fine because that scanned the tree again.
 *
 * Called wherever the tree changes: after a rebuild, and after a save writes a
 * source into it.
 */
static void src_forget(void)
{
	free(g_src);
	g_src = NULL;
	g_n_src = 0;
	g_src_done = 0;
}

static int src_read(const char *path, struct src_ent *out)
{
	FILE *f = fopen(path, "r");
	char line[1024];
	uint32_t lineno = 0;

	if (!f)
		return 0;
	out->family[0] = 0;
	out->n_line = 0;
	out->pat = 0;
	out->n_pat = 0;
	out->tgt = 0;
	while (fgets(line, sizeof line, f)) {
		char *p, *q;
		size_t n = 0;

		lineno++;
		if (!out->family[0] &&
		    (p = strstr(line, "KOF_TARGET_NAME(")) != NULL &&
		    (p = strchr(p, ',')) != NULL &&
		    (q = strchr(p, '"')) != NULL) {
			for (q++; *q && *q != '"' &&
			     n + 1 < sizeof out->family; q++)
				out->family[n++] = *q;
			out->family[n] = 0;
		}
		if ((strstr(line, "KOF_SCAN_INFECT(") ||
		     strstr(line, "KOF_SCAN_SUSPECT(")) &&
		    out->n_line < SRC_MAX_LINES)
			out->line[out->n_line++] = lineno;
		/* What it targets, as the identifiers the file actually
		 * spells - no table lookup needed on this side, and none that
		 * could drift out of step with the emitter's. */
		{
			static const char *const decl[] = {
				"KOF_TARGET_FORMAT(", "KOF_TARGET_NAME(",
				"KOF_TARGET_ARCH(", "KOF_TARGET_SUBTYPE("
			};
			size_t d;

			for (d = 0; d < sizeof decl / sizeof decl[0]; d++)
				if ((p = strstr(line, decl[d])) != NULL) {
					char w[64];

					src_ident(p + strlen(decl[d]), w,
						  sizeof w);
					if (w[0])
						out->tgt = tgt_mix(out->tgt, w);
				}
			if ((p = strstr(line, "KOF_TARGET_SIZE_MIN(")) != NULL) {
				char w[48];

				snprintf(w, sizeof w, "SIZE_MIN=%llu",
					 (unsigned long long)
					 strtoull(p + 20, NULL, 0));
				out->tgt = tgt_mix(out->tgt, w);
			}
		}
		if ((p = strstr(line, "KOF_DEFINE_STR(")) != NULL ||
		    (p = strstr(line, "KOF_DEFINE_HEXSTR(")) != NULL) {
			int hex = strstr(line, "KOF_DEFINE_HEXSTR(") != NULL;
			char text[512];

			if ((q = strchr(p, '"')) != NULL) {
				size_t m = 0;

				for (q++; *q && *q != '"' &&
				     m + 1 < sizeof text; q++)
					text[m++] = *q;
				text[m] = 0;
				if (hex) {
					char c[sizeof text];

					hex_canon(text, c, sizeof c);
					m = strlen(c);
					memcpy(text, c, m + 1u);
				}
				out->pat += pat_of((const uint8_t *)text,
						   (uint32_t)m, hex);
				out->n_pat++;
			}
		}
	}
	fclose(f);
	return out->family[0] != 0;
}

static void src_scan(const char *dir, int depth)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	if (!d || depth > 4)
		return;
	while ((e = readdir(d)) != NULL) {
		char path[512];
		struct stat st;
		size_t n;

		if (e->d_name[0] == '.')
			continue;
		if ((size_t)snprintf(path, sizeof path, "%s/%s", dir,
				     e->d_name) >= sizeof path)
			continue;
		if (stat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			src_scan(path, depth + 1);
			continue;
		}
		n = strlen(e->d_name);
		if (n < 3 || strcmp(e->d_name + n - 2, ".c") != 0)
			continue;
		if (g_n_src >= SRC_MAX)
			break;
		snprintf(g_src[g_n_src].path, sizeof g_src[0].path, "%s", path);
		if (src_read(path, &g_src[g_n_src]))
			g_n_src++;
	}
	closedir(d);
}

/*
 * The file a fired module was written in - ASKED, NOT DERIVED.
 *
 * The database carries it now (kof_db_source), because the build knew it and
 * used to discard it. What stood here re-derived it: scan the bases tree once,
 * read every source, and match a module to a file on the LINE NUMBERS its
 * detection names sit on.
 *
 * That key is correct exactly while the sources hold still, and it was cached
 * for the life of the process. So pressing Rebuild database - the one action
 * whose whole purpose is that the sources changed - left an index describing
 * the tree as it had been: nothing matched, the draft fell back to the
 * database, and because a database keeps a module's strings and not its logic
 * every rule redrew as a single find_all.
 *
 * A duplicate of something the engine can answer is not just more code. It is a
 * second thing to keep true, and it goes false quietly.
 */
/*
 * Build the index of the bases tree, once, for the ONE question that still
 * needs it: does some existing source already declare this exact set of
 * markers. That is a content question over the whole tree, and no single scan
 * result answers it - unlike "which file was this module written in", which the
 * database now carries and which used to be answered from here by matching line
 * numbers. See src_of.
 */
static void src_index(struct view *v)
{
	if (g_src_done)
		return;
	g_src_done = 1;
	g_src = calloc(SRC_MAX, sizeof *g_src);
	if (g_src)
		src_scan(v->basedir, 0);
}

static const char *src_of(struct view *v, const struct kof_touch *t)
{
	static char path[KOF_DUMP_PATH_ROOM];
	const char *rel;

	if (!v->eng || !t->mod)
		return NULL;
	rel = kof_db_source(v->eng, t->mod);
	if (!rel || !rel[0])
		return NULL;
	/*
	 * The database records the path INSIDE the tree; where the tree is, is
	 * this viewer's own --bases. An absolute path in the database would be a
	 * fact about the machine that built it.
	 */
	if ((size_t)snprintf(path, sizeof path, "%s/%s",
			     v->basedir[0] ? v->basedir : ".", rel) >= sizeof path)
		return NULL;
	return path;
}


/*
 * Turn one signature source into a draft.
 *
 * Line oriented, and deliberately narrow: it reads the shapes ksigbuilder
 * accepts and nothing else. A construct it does not recognise is skipped rather
 * than approximated, because a draft that quietly differs from the file it came
 * from is worse than one that is visibly short of it.
 */
struct sname { char id[40]; uint32_t idx; };

static uint32_t src_mask_of(const struct kof_inspect_fmt *fmt, const char *e)
{
	uint32_t m = 0, k;

	if (strstr(e, "KOF_SCAN_ALL"))
		return KOF_SCAN_ALL;
	/* Before the format's own words and independently of them: these two
	 * are in kofsig.h, so a rule can name them with no format header at
	 * all, and reopening such a rule must give back the range it declared
	 * rather than an empty mask. */
	if (strstr(e, "KOF_SCAN_SYM_IMP"))
		m |= KOF_SCAN_SYM_IMP;
	if (strstr(e, "KOF_SCAN_SYM_EXP"))
		m |= KOF_SCAN_SYM_EXP;
	if (!fmt)
		return m;
	for (k = 0; k < fmt->n_regions; k++) {
		const char *w = fmt->region_name(fmt->regions[k]);

		if (w && strstr(e, w))
			m |= fmt->regions[k];
	}
	return m;
}

/* The text between the first pair of quotes, unescaped only as far as
 * ksigbuilder unescapes it - which is not at all. */
/*
 * The inside of a C string literal, back to the bytes it stands for.
 *
 * The three escapes decl_put_literal writes - \" \\ \? - and no others, which is
 * the same set ksigbuilder accepts. An escaped quote in particular has to be
 * understood here or it ends the literal: reading realm=\"X\" quote to quote
 * yields realm= and drops the rest of the marker silently.
 *
 * Anything else after a backslash is passed through as written rather than
 * refused. This is a viewer: a file it cannot fully account for should be shown
 * as nearly as it can be, and the build is where a bad escape is an error.
 */
static int hexval(char c);

/*
 * A hex pattern's concrete leading bytes, for locating it in the object.
 *
 * Whitespace is skipped, because the spelling in a file has it: bases/ writes
 * "2E 2E 5C" and reading that two characters at a time gives 2E 02 0E 5C - four
 * bytes, none of them the marker, so the row said "4" and reported the pattern
 * as absent from an object it is in.
 *
 * Stops at the first character that is not a hex digit, which is how a wildcard
 * or a gap ends the concrete part. Short is the honest answer there: there is no
 * byte a "??" is equal to, and inventing a 00 would be a marker the rule never
 * had. What the pattern IS remains in decl.hexs; this is only what can be
 * searched for.
 */
/*
 * A hex pattern, read by THE ENGINE'S COMPILER.
 *
 * What stood here read the text itself and kept only the concrete bytes,
 * stopping at the first character that was not a hex digit. That is right for
 * a pattern with no wildcard in it and quietly wrong for every pattern that
 * has one: "2E ?? 5C" came back as the single byte 2E, so the row said the
 * marker was one byte long and the search went looking for that one byte -
 * editing a working pattern to add a wildcard made it stop matching at the
 * wildcard.
 *
 * The repair is not a better parser here. kof_hex_compile is the parser, it
 * already knows "??" and "?4" and "[4-6]" and "( E8 | E9 )", it is what the
 * build runs over the same text, and a second reading of the same syntax in
 * this file would be a second thing to keep correct. So the panel compiles the
 * pattern exactly as the database will and asks the compiler how long a match
 * spans; the bytes array goes away, because a pattern with a wildcard has none.
 */
static int decl_from_hexs(struct decl *d)
{
	uint8_t prog[KOF_HEX_MAX_PROG];
	struct kof_hex_stat st;

	free(d->bytes);
	d->bytes = NULL;
	d->nbytes = 0;
	if (!kof_hex_compile(d->hexs, prog, sizeof prog, &st)) {
		d->len = 0;
		d->span_max = 0;
		return 0;               /* kof_hex_error() says what is wrong */
	}
	d->len = st.min_span;
	d->span_max = st.max_span;
	return 1;
}

static int src_quoted(const char *p, char *out, size_t cap)
{
	const char *q = strchr(p, '"');
	size_t n = 0;

	if (!q)
		return 0;
	for (q++; *q && *q != '"'; q++) {
		if (*q == '\\' &&
		    (q[1] == '"' || q[1] == '\\' || q[1] == '?'))
			q++;
		if (n + 1 < cap)
			out[n++] = *q;
	}
	out[n] = 0;
	return *q == '"';
}

static uint32_t src_str_idx(struct sname *tab, uint32_t n, const char *id)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(tab[i].id, id))
			return tab[i].idx;
	return 0xffffffffu;
}

/*
 * One line of the file's leading comment onto the note.
 *
 * Joined with a single space rather than kept as lines, because the note is one
 * field of one line - the shape it is written in and the shape it is edited in.
 */
static void head_put(char *dst, size_t cap, size_t *n, const char *s, size_t len)
{
	if (*n && *n + 1 < cap)
		dst[(*n)++] = ' ';
	while (len-- && *n + 1 < cap)
		dst[(*n)++] = *s++;
	dst[*n] = 0;
}

/*
 * The banner this tool opens its own header block with.
 *
 * One string, tested only against the first line of a block, and it identifies
 * a whole block rather than a line: what the tool generates and what the author
 * wrote are separate comments, so recognising the banner is enough to tell them
 * apart and nothing has to guess at the prose inside either one.
 */
#define HEAD_BANNER "Generated by KOFViewer"

/* ---- the generated block's metadata ---------------------------------------
 *
 * What a rule records about its own making: which samples it was tested
 * against, who wrote it, when, and against which engine and database. The same
 * facts a YARA rule keeps in `meta`, and for the same reason - months later the
 * question about a rule is never "what does it match", which the code says, but
 * "what was this checked against and by whom", which nothing else records.
 *
 * Accumulated rather than replaced. See view.meta_sample.
 */

/* Add one entry unless it is already there, dropping the oldest at the cap.
 * Deduplicated because re-testing the same sample is the common case and a list
 * of one name repeated is not a history. */
static void meta_add(char tab[][128], uint32_t *n, uint32_t cap, const char *w)
{
	uint32_t i;

	if (!w || !w[0])
		return;
	for (i = 0; i < *n; i++)
		if (!strcmp(tab[i], w))
			return;
	if (*n == cap) {
		memmove(tab[0], tab[1], (cap - 1u) * 128u);
		(*n)--;
	}
	snprintf(tab[*n], 128, "%.127s", w);
	(*n)++;
}

static void meta_add_who(char tab[][48], uint32_t *n, uint32_t cap,
			 const char *w)
{
	uint32_t i;

	if (!w || !w[0])
		return;
	for (i = 0; i < *n; i++)
		if (!strcmp(tab[i], w))
			return;
	if (*n == cap) {
		memmove(tab[0], tab[1], (cap - 1u) * 48u);
		(*n)--;
	}
	snprintf(tab[*n], 48, "%.47s", w);
	(*n)++;
}

/*
 * Who is at this machine.
 *
 * The account name, because it is the one identifier that is already there and
 * already means a person to the team that shares the machine. Not a real name:
 * this tool has no way to know one and inventing a field for somebody to fill in
 * would leave it empty in every file.
 */
static const char *meta_user(void)
{
	const char *u = getenv("USER");

	if (!u || !u[0])
		u = getenv("LOGNAME");
	if (!u || !u[0]) {
		struct passwd *pw = getpwuid(getuid());

		u = pw && pw->pw_name ? pw->pw_name : "";
	}
	return u ? u : "";
}

/* Today, as the one date format that sorts and cannot be read two ways. */
static void meta_today(char *out, uint32_t cap)
{
	time_t now = time(NULL);
	struct tm tmv;

	if (localtime_r(&now, &tmv))
		strftime(out, cap, "%Y-%m-%d", &tmv);
	else
		snprintf(out, cap, "unknown");
}

/*
 * One line of an existing generated block, back into the fields it came from.
 *
 * Only the lines this writes are read back; anything else in the block is a
 * line an older build wrote or a person added, and it is dropped rather than
 * guessed at. Returns 1 when the line was one of ours.
 */
static int meta_take(struct view *v, const char *t)
{
	static const struct { const char *tag; int what; } tab[] = {
		{ "Test sample:", 0 }, { "Researcher:", 1 }, { "Created", 2 }
	};
	uint32_t i;

	for (i = 0; i < sizeof tab / sizeof tab[0]; i++) {
		size_t n = strlen(tab[i].tag);

		if (strncmp(t, tab[i].tag, n))
			continue;
		t += n;
		while (*t == ' ' || *t == '\t')
			t++;
		if (!*t)
			return 1;
		if (tab[i].what == 0)
			meta_add(v->meta_sample, &v->n_meta_sample, MAX_META,
				 t);
		else if (tab[i].what == 1)
			meta_add_who(v->meta_who, &v->n_meta_who, MAX_META, t);
		else {
			/* "Created <date>, updated <date>" - the first date is
			 * the one worth keeping; the second is rewritten on
			 * every save and is read back only to be discarded. */
			uint32_t k = 0;

			while (t[k] && t[k] != ',' &&
			       k + 1u < sizeof v->meta_made)
				k++;
			snprintf(v->meta_made, sizeof v->meta_made, "%.*s",
				 (int)k, t);
		}
		return 1;
	}
	return 0;
}



/*
 * IS THIS LINE OF kof_scan SOMETHING THE EDITOR CAN ACTUALLY HOLD.
 *
 * The panel models one shape: matchers made of kof_find_str_* calls, conditions
 * made of ifs, and verdicts. That is most rules and it is not all of them - a
 * hand written module may compute something, loop, call a parser accessor, or
 * do arithmetic on an offset, and none of that has a control on the panel.
 *
 * The old behaviour on such a file was the dangerous one: the unrecognised
 * lines were ignored, a draft was built from whatever was left, `gen_path` was
 * pointed at the original, and Save was offered - so saving a rule the editor
 * had only partly understood REPLACED it with the editor's reduced version.
 * The custom logic was gone and nothing had said so.
 *
 * So the line is checked instead. Punctuation, else, return and the three
 * modelled constructs are accounted for; anything else means this file holds
 * logic the panel does not carry, and the rule opens read only.
 *
 * Deliberately conservative in the safe direction: a construct this does not
 * know costs a save that has to be done in an editor, and the opposite mistake
 * costs somebody's work.
 */
static int body_modelled(const char *line)
{
	const char *t = line;

	if (strstr(line, "kof_find_str") || strstr(line, "KOF_SCAN_") ||
	    strstr(line, "if (") || strstr(line, "if("))
		return 1;
	for (; *t; t++) {
		if (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n')
			continue;
		if (*t == '{' || *t == '}' || *t == ';')
			continue;
		if (!strncmp(t, "else", 4)) {
			t += 3;
			continue;
		}
		if (!strncmp(t, "return", 6)) {
			t += 5;
			continue;
		}
		return 0;
	}
	return 1;
}

static int draft_from_source(struct view *v, const char *path)
{
	FILE *f = fopen(path, "r");
	char line[1024], pend[160];
	struct sname str[MAX_DECL];
	struct { char id[48]; uint32_t mask; } rng[8];
	uint32_t n_str = 0, n_rng = 0, i;
	const struct kof_inspect_fmt *fmt = cur_obj(v)->fmt;
	/*
	 * Which condition owns each brace depth, so a verdict lands on the one
	 * whose body it is in.
	 *
	 * A bare KOF_SCAN_ line after the children is the enclosing condition's
	 * own verdict; one that follows an if with no brace belongs to that if.
	 * Attaching every verdict to the last condition seen put the gate's
	 * fallback onto its final child, which reads as the wrong branch of the
	 * wrong rule.
	 */
	int owner[8];
	int depth = 0, body = 0, cur = -1, parent = -1, skipped = 0;
	int just_opened = 0;
	/*
	 * THE SHARED CALLS, READ BACK.
	 *
	 * The generator writes "at least three, otherwise at least two" as one
	 * call into a variable and two comparisons against it. Reading that
	 * back needs the variable remembered: the call says what to look for
	 * and where, and each "m1 >= N" is a matcher over exactly that with its
	 * own threshold. Without this the ifs referred to a name that meant
	 * nothing here and the rule came back with no matchers at all.
	 */
	struct { char id[16]; int rule; uint32_t mask, decls; } shc[8];
	uint32_t n_shc = 0;
	int pend_if = -1;
	char head[sizeof v->note];
	size_t head_n = 0;
	int in_head = 0, head_done = 0, mine = 0;

	if (!f)
		return 0;
	pend[0] = 0;
	head[0] = 0;
	for (i = 0; i < sizeof owner / sizeof owner[0]; i++)
		owner[i] = -1;
	while (fgets(line, sizeof line, f)) {
		char *p;

		/*
		 * The file's own leading comment, back into the note field.
		 *
		 * The rules below treat every block comment as punctuation and
		 * skip it, which is right for the ones that annotate a branch
		 * and wrong for this one: the generator writes the author's own
		 * line about the module into the header. Skipping it meant
		 * opening a signature showed an empty note, and saving it then
		 * deleted the one sentence in the file a person had written.
		 */
		if (!head_done) {
			char *t = line, *e;
			size_t n;

			while (*t == ' ' || *t == '\t' || *t == '\n' ||
			       *t == '\r')
				t++;
			if (!in_head) {
				if (!*t)
					continue;       /* between blocks */
				if (t[0] != '/' || t[1] != '*') {
					/* Code: the header is over, and
					 * nothing below should see this line
					 * twice. */
					head_done = 1;
					goto no_head;
				}
				in_head = 1;
				mine = 0;
				t += 2;
			}
			if ((e = strstr(t, "*/")) != NULL)
				*e = 0;
			while (*t == ' ' || *t == '\t' || *t == '*')
				t++;
			n = strlen(t);
			while (n && (t[n - 1] == '\n' || t[n - 1] == '\r' ||
				     t[n - 1] == ' ' || t[n - 1] == '\t'))
				n--;
			if (n) {
				/* Cut here, not just measured: what follows is
				 * stored and compared, and a trailing newline
				 * made every entry differ from the same entry
				 * read back - so nothing deduplicated and the
				 * block grew a blank line per item. */
				t[n] = 0;
				/* The banner only counts as one where it is
				 * written - opening the block. A line of prose
				 * quoting it further down is prose. */
				if (!head_n && !mine &&
				    !strncmp(t, HEAD_BANNER,
					     sizeof HEAD_BANNER - 1))
					mine = 1;
				/* Inside our own block the recognised lines
				 * are the rule's history and are kept; the
				 * author's block is prose and goes to the
				 * note. */
				if (mine)
					meta_take(v, t);
				else
					head_put(head, sizeof head, &head_n,
						 t, n);
			}
			if (e)
				in_head = 0;    /* the next block may follow */
			continue;
		}
no_head:

		/* A comment on its own line belongs to whatever comes next -
		 * which is how the generator wrote it and how the modules in
		 * bases/ are written by hand. */
		/*
		 * A COMMENT AFTER CODE DOES NOT MAKE THE LINE A COMMENT.
		 *
		 * The two branches below treat any line holding a comment opener
		 * as one, and that dropped whole declarations. bases/ has them:
		 * ZipSlip writes its Windows marker as
		 * KOF_DEFINE_HEXSTR(path_on_ntwin, "2E 2E 5C") with a trailing
		 * comment spelling out the three bytes.
		 *
		 * That marker was never declared when the rule was opened, its
		 * matcher came up with no markers, and the comment text became
		 * the pending note that attached to the NEXT matcher - so the
		 * panel showed a rule that was not the rule in the file.
		 *
		 * So: code before the opener means the code is the line, and
		 * the comment is cut off it. Only a line that begins with the
		 * comment is a comment, which is what the branches below now
		 * see. The trailing text is dropped rather than kept, because
		 * the only place this model has to put it is "the next thing",
		 * and the next thing is not what it was written about.
		 */
		{
			char *c = strstr(line, "/*");
			char *t;
			int code = 0;

			for (t = line; c && t < c; t++)
				if (*t != ' ' && *t != '\t') {
					code = 1;
					break;
				}
			if (code) {
				char *e = strstr(c, "*/");

				/* One that does not close here takes the rest
				 * of the line with it. */
				if (e)
					memmove(c, e + 2, strlen(e + 2) + 1);
				else
					*c = 0;
			}
		}
		if ((p = strstr(line, "/*")) != NULL &&
		    strstr(line, "*/") != NULL) {
			char *q = strstr(p, "*/");
			size_t n = 0;

			for (p += 2; p < q && n + 1 < sizeof pend; p++)
				if (n || (*p != ' ' && *p != '\t'))
					pend[n++] = *p;
			while (n && (pend[n - 1] == ' ' || pend[n - 1] == '\t'))
				n--;
			pend[n] = 0;
			continue;
		}
		if (strstr(line, "/*") || strstr(line, "*/") ||
		    strstr(line, " * ")) {
			continue;               /* a block comment; skip it */
		}

		if ((p = strstr(line, "KOF_TARGET_NAME(")) != NULL) {
			char w[48];
			uint32_t k;

			src_ident(p + 16, w, sizeof w);
			for (k = 0; k < MALTYPE_N; k++) {
				char t[48];

				snprintf(t, sizeof t, "KOF_MALTYPE_%s",
					 maltype_word[k]);
				if (!strcasecmp(t, w))
					v->maltype = k;
			}
			src_quoted(p, v->family, sizeof v->family);
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_RANGE(")) != NULL &&
		    n_rng < sizeof rng / sizeof rng[0]) {
			const char *q = src_ident(p + 17, rng[n_rng].id,
						  sizeof rng[0].id);

			rng[n_rng].mask = src_mask_of(fmt, q);
			n_rng++;
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_SIZE_MIN(")) != NULL) {
			v->opt_on[OPT_SIZE_MIN] = 1;
			v->opt_val[OPT_SIZE_MIN] = strtoull(p + 20, NULL, 0);
			continue;
		}
		/*
		 * The optional declarations are read back because they are
		 * written out: a rule opened, changed in one place and saved
		 * would otherwise come back without its arch or its subtype,
		 * and a signature that quietly stops being prefiltered is a
		 * signature that quietly starts running on everything.
		 */
		if ((p = strstr(line, "KOF_TARGET_ARCH(KOF_ARCH_")) != NULL) {
			char w[32];
			uint32_t k;

			src_ident(p + 25, w, sizeof w);
			for (k = 0; k < ARCH_N; k++)
				if (!strcmp(arch_word[k].word, w)) {
					v->opt_on[OPT_ARCH] = 1;
					v->opt_val[OPT_ARCH] = k;
				}
			continue;
		}
		if ((p = strstr(line, "KOF_TARGET_SUBTYPE(")) != NULL) {
			const char *const *tab = NULL;
			const char *sub;
			char w[32];
			uint32_t n = 0, k;

			if ((sub = strstr(p, "KOF_ELF_")) != NULL) {
				tab = elf_sub;
				n = sizeof elf_sub / sizeof elf_sub[0];
				src_ident(sub + 8, w, sizeof w);
			} else if ((sub = strstr(p, "KOF_PE_")) != NULL) {
				tab = pe_sub;
				n = sizeof pe_sub / sizeof pe_sub[0];
				src_ident(sub + 7, w, sizeof w);
			}
			for (k = 0; tab && k < n; k++)
				if (!strcmp(tab[k], w)) {
					v->opt_on[OPT_SUBTYPE] = 1;
					v->opt_val[OPT_SUBTYPE] = k;
				}
			continue;
		}
		if ((p = strstr(line, "KOF_DEFINE_STR(")) != NULL ||
		    (p = strstr(line, "KOF_DEFINE_HEXSTR(")) != NULL) {
			int hex = strstr(line, "KOF_DEFINE_HEXSTR(") != NULL;
			char text[512];
			struct decl *d;

			if (v->n_decl >= MAX_DECL || n_str >= MAX_DECL)
				continue;
			d = &v->decl[v->n_decl];
			memset(d, 0, sizeof *d);
			src_ident(strchr(p, '(') + 1, str[n_str].id,
				  sizeof str[0].id);
			if (!src_quoted(p, text, sizeof text))
				continue;
			if (hex) {
				size_t n = strlen(text) / 2u, k;

				/* Verbatim, because the file already holds the
				 * pattern in the one form that can express it -
				 * and the byte conversion below turns a "??"
				 * into a 00, which is a different pattern. */
				snprintf(d->hexs, sizeof d->hexs, "%s", text);
				decl_from_hexs(d);
				(void)n; (void)k;
				d->hex = 1;
			} else {
				d->len = (uint32_t)strlen(text);
				d->bytes = malloc(d->len ? d->len : 1u);
				if (!d->bytes)
					continue;
				memcpy(d->bytes, text, d->len);
				d->nbytes = d->len;
				d->icase = strstr(line, "KOF_CASE_ICASE") != 0;
				d->fullword = strstr(line,
						     "KOF_WORD_FULLWORD") != 0;
			}
			d->obj = v->node[v->sel_node].obj;
			d->grp = 0;
			snprintf(d->rgn, sizeof d->rgn, "-");
			str[n_str].idx = v->n_decl;
			n_str++;
			v->n_decl++;
			continue;
		}

		{
			/*
			 * The line that opens the body is not IN the body.
			 *
			 * It trips the foreign test otherwise - it is a
			 * function signature, which is code and is none of the
			 * three modelled constructs - so every ordinary rule
			 * came back read only.
			 */
			int opens = strstr(line, "kof_scan(") != NULL ||
				    strstr(line, "KOF_DEFINE_SCAN") != NULL;

			if (opens)
				body = 1;
			if (!body)
				continue;
			just_opened = opens;
		}

		{
			/*
			 * A brace with nothing testing it is a grouping, and
			 * has to come back as one: read as plain punctuation
			 * its branches would surface as siblings of whatever
			 * came before, which is a different signature.
			 */
			const char *t = line;

			while (*t == ' ' || *t == '\t')
				t++;
			if (*t == '{' && body && depth >= 1 &&
			    v->n_cnd < MAX_GROUP) {
				struct cond *c = &v->cnd[v->n_cnd];

				memset(c, 0, sizeof *c);
				c->parent = parent;
				c->level = LV_NONE;
				if (cur >= 0 && v->cnd[cur].parent == parent)
					v->cnd[cur].join = 1;
				cur = (int)v->n_cnd;
				pend_if = -1;
				v->n_cnd++;
			}
		}
		if (strstr(line, "if (") || strstr(line, "if(")) {
			struct cond *c;

			if (v->n_cnd >= MAX_GROUP) {
				skipped++;
				continue;
			}
			c = &v->cnd[v->n_cnd];
			memset(c, 0, sizeof *c);
			c->parent = parent;
			c->level = LV_NONE;
			c->op = strstr(line, "||") != NULL;
			/*
			 * How the previous condition at this level joins to
			 * this one, read off the source rather than assumed:
			 * "else if" chains, a fresh "if" does not. Assuming
			 * one turned three independent branches into a chain
			 * on the way back out - the same behaviour, since
			 * verdicts return, but not the same file.
			 */
			if (cur >= 0 && v->cnd[cur].parent == parent)
				v->cnd[cur].join = strstr(line, "else") == NULL;
			cur = (int)v->n_cnd;
			pend_if = cur;
			v->n_cnd++;
			/* `pend` is left alone: the comment above a branch
			 * describes the search it makes, and the search is the
			 * matcher on the same line. */
		}
		/*
		 * "uint32_t mN = <call>;" - the call, kept under its name. It
		 * is not a matcher on its own: nothing is compared against it
		 * yet, and the comparisons below are what carry the thresholds.
		 */
		if ((p = strstr(line, "kof_find_str_")) != NULL &&
		    memchr(line, '=', (size_t)(p - line)) != NULL &&
		    !strstr(line, "if (") && !strstr(line, "if(")) {
			const char *q;
			char id[48];

			if (n_shc >= sizeof shc / sizeof shc[0])
				goto shc_done;
			memset(&shc[n_shc], 0, sizeof shc[0]);
			shc[n_shc].rule = !strncmp(p + 13, "any", 3) ? 1
					: !strncmp(p + 13, "multi", 5) ? 2 : 0;
			/* The variable's own name, the identifier before "=". */
			{
				const char *e = memchr(line, '=',
						       (size_t)(p - line));
				const char *b2 = e;

				while (b2 > line && (b2[-1] == ' ' ||
						     b2[-1] == '\t'))
					b2--;
				{
					const char *st2 = b2;

					while (st2 > line &&
					       (isalnum((unsigned char)st2[-1])
						|| st2[-1] == '_'))
						st2--;
					snprintf(shc[n_shc].id,
						 sizeof shc[0].id, "%.*s",
						 (int)(b2 - st2), st2);
				}
			}
			q = strchr(p, '(');
			if (!q)
				goto shc_done;
			q = src_ident(q + 1, id, sizeof id);
			for (i = 0; i < n_rng; i++)
				if (!strcmp(rng[i].id, id))
					shc[n_shc].mask = rng[i].mask;
			while (*q == ',' || *q == ' ') {
				char sid[48];
				uint32_t k;

				q = src_ident(q, sid, sizeof sid);
				if (!sid[0])
					break;
				k = src_str_idx(str, n_str, sid);
				if (k < v->n_decl && k < 32u)
					shc[n_shc].decls |= 1u << k;
				while (*q == ' ')
					q++;
			}
			if (shc[n_shc].id[0])
				n_shc++;
shc_done:
			continue;
		}
		/* "mN >= K" - one matcher over the remembered call. */
		if (cur >= 0 && n_shc && !strstr(line, "kof_find_str_")) {
			uint32_t si;

			for (si = 0; si < n_shc; si++) {
				const char *at = strstr(line, shc[si].id);
				const char *ge;
				struct group *g;
				uint32_t k;

				if (!at)
					continue;
				ge = strstr(at, ">=");
				if (!ge || v->n_grp >= MAX_GROUP)
					continue;
				g = &v->grp[v->n_grp];
				memset(g, 0, sizeof *g);
				g->rule = shc[si].rule;
				g->mask = shc[si].mask;
				g->thresh = (uint32_t)strtoul(ge + 2, NULL, 10);
				for (k = 0; k < v->n_decl && k < 32u; k++)
					if (shc[si].decls & (1u << k))
						v->decl[k].grp |= 1u << v->n_grp;
				{
					size_t l = strlen(v->cnd[cur].expr);

					snprintf(v->cnd[cur].expr + l,
						 sizeof v->cnd[0].expr - l,
						 "%s%u",
						 l ? (v->cnd[cur].op ? "|" : "&")
						   : "", v->n_grp + 1u);
				}
				v->n_grp++;
				break;
			}
		}
		if ((p = strstr(line, "kof_find_str_")) != NULL) {
			/*
			 * One call is one matcher, which is exactly the rule
			 * the panel is built on - a matcher is a single
			 * find_all/find_any/find_multi over one range.
			 */
			const char *q = p + 13;
			char id[48];
			struct group *g;
			int rule = 0;

			if (!strncmp(q, "any", 3))
				rule = 1;
			else if (!strncmp(q, "multi", 5))
				rule = 2;
			if (v->n_grp >= MAX_GROUP || cur < 0) {
				skipped++;
				continue;
			}
			g = &v->grp[v->n_grp];
			memset(g, 0, sizeof *g);
			g->rule = rule;
			q = strchr(p, '(');
			if (!q)
				continue;
			q = src_ident(q + 1, id, sizeof id);
			for (i = 0; i < n_rng; i++)
				if (!strcmp(rng[i].id, id))
					g->mask = rng[i].mask;
			while (*q == ',' || *q == ' ') {
				char sid[48];
				uint32_t k;

				q = src_ident(q, sid, sizeof sid);
				if (!sid[0])
					break;
				k = src_str_idx(str, n_str, sid);
				if (k < v->n_decl)
					v->decl[k].grp |= 1u << v->n_grp;
				while (*q == ' ')
					q++;
			}
			if (rule == 2) {
				const char *ge = strstr(p, ">=");

				g->thresh = ge ? (uint32_t)strtoul(ge + 2, NULL,
								   10) : 2u;
			}
			if (pend[0]) {
				/*
				 * The LABEL is not part of the note.
				 *
				 * generate writes "matcher N: <note>", and this
				 * kept the whole line - so the next generate
				 * prefixed a label that was already there and
				 * the file grew "matcher 1: matcher 1: ..." one
				 * layer per save. The number is derived from
				 * where the matcher sits, so reading it back is
				 * reading back something this side already
				 * knows.
				 */
				const char *note = pend;

				if (strncmp(note, "matcher ", 8) == 0) {
					const char *colon = strchr(note + 8, ':');

					if (colon) {
						note = colon + 1;
						while (*note == ' ')
							note++;
					}
				}
				snprintf(g->note, sizeof g->note, "%s", note);
				pend[0] = 0;
			}
			{
				size_t l = strlen(v->cnd[cur].expr);

				snprintf(v->cnd[cur].expr + l,
					 sizeof v->cnd[0].expr - l, "%s%u",
					 l ? (v->cnd[cur].op ? "|" : "&") : "",
					 v->n_grp + 1u);
			}
			v->n_grp++;
		}

		if (strstr(line, "KOF_SCAN_INFECT(") ||
		    strstr(line, "KOF_SCAN_SUSPECT(")) {
			/*
			 * An "else" on its own before it is the old shape this
			 * tool used to write, where the gate's fallback was
			 * bound to the last child's if. It was meant as the
			 * gate's, so that is where it goes.
			 */
			int at = pend_if >= 0 ? pend_if
				 : (depth > 0 && depth < 8 ? owner[depth] : -1);

			if (at < 0)
				at = cur;
			if (at >= 0) {
				struct cond *c = &v->cnd[at];

				c->level = strstr(line, "SUSPECT")
					   ? LV_SUSPECT : LV_INFECT;
				if (strstr(line, "KOF_MALVAR_GENERIC"))
					c->var_kind = 1;
				else if (strchr(line, '"')) {
					c->var_kind = 2;
					src_quoted(line, c->variant,
						   sizeof c->variant);
				}
			}
			pend_if = -1;
		}
		/* Whatever this line was, was it something the panel can hold. */
		if (body && !just_opened && !body_modelled(line))
			v->foreign++;

		for (p = line; *p; p++) {
			if (*p == '{' && body) {
				depth++;
				if (depth < 8)
					owner[depth] = cur;
				if (depth > 1 && cur >= 0)
					parent = cur;
				pend_if = -1;   /* it opened a block */
			} else if (*p == '}' && body) {
				if (depth < 8 && depth >= 0)
					owner[depth] = -1;
				depth--;
				if (depth <= 1)
					parent = -1;
			}
		}
	}
	fclose(f);

	/*
	 * A string's region column, filled from the matcher that searches it.
	 *
	 * The source says where each matcher looks, not where each string is -
	 * and where it looks is the fact the table is for. A string no matcher
	 * claimed keeps its dash, which is the truthful answer.
	 */
	for (i = 0; i < v->n_decl; i++) {
		struct decl *d = &v->decl[i];

		uint32_t g2;

		if (!d->grp || d->mask)
			continue;
		/* Every matcher that searches for it contributes its range. */
		for (g2 = 0; g2 < v->n_grp; g2++)
			if (d->grp & (1u << g2))
				d->mask |= v->grp[g2].mask;
		if (d->mask)
			rng_name_of(fmt, d->mask, d->rgn, sizeof d->rgn);
	}
	/* The source says what to look for, not where it was found. */
	for (i = 0; i < v->n_decl; i++)
		decl_locate(v, &v->decl[i]);
	if (head_n)
		snprintf(v->note, sizeof v->note, "%s", head);
	return skipped ? -1 : 1;
}

/*
 * Fill the draft from a signature that fired on this object.
 *
 * The point is a starting position, not a copy: a researcher writing a variant
 * begins from what the existing rule already knows about the family, and typing
 * its strings back in by hand is the tedious half of that.
 *
 * What comes across is everything the database holds - the family, the type,
 * each declared string with its case and word handling, and the region each one
 * was actually found in. What does not is the logic. A module's conditions are
 * compiled code; the pack keeps the strings and the names, not which of them
 * were required together or in what combination. So they all land in one
 * find_all and the row says so, for the researcher to take apart.
 */
static void draft_from_touch(struct view *v, const struct kof_touch *t)
{
	uint32_t i;

	if (!t)
		return;
	{
		/* Through a local: the family may be a pointer into the very
		 * object being written to, and snprintf may not overlap. */
		char fam[64];

		snprintf(fam, sizeof fam, "%s", t->family ? t->family : "");
		snprintf(v->family, sizeof v->family, "%s", fam);
	}
	for (i = 0; i < MALTYPE_N; i++)
		if (t->maltype == i)
			v->maltype = i;

	for (i = 0; i < t->n_str && v->n_decl < MAX_DECL; i++) {
		const struct kof_touch_str *st = &t->str[i];
		struct decl *d = &v->decl[v->n_decl];

		if (!st->pool_len)
			continue;
		memset(d, 0, sizeof *d);
		d->hex = st->kind == KOF_STR_HEX;
		if (d->hex) {
			/*
			 * The pack holds a hex marker as a COMPILED PROGRAM.
			 * Turned back into what its author wrote, because that
			 * is the only form a person can read and the only one
			 * that can be written back out - see decl.hexs.
			 *
			 * And then read the same way the source loader reads
			 * the same spelling out of a file, deliberately: a
			 * signature opened without its source and the same
			 * signature opened with it must produce the same draft,
			 * or "is this a duplicate of a rule in the tree" gets
			 * two answers for one rule.
			 */
			size_t hn, k;

			snprintf(d->hexs, sizeof d->hexs, "%s", st->text);
			if (!d->hexs[0])
				continue;
			decl_from_hexs(d);
			(void)hn; (void)k;
		} else {
			d->bytes = malloc(st->pool_len);
			if (!d->bytes)
				break;
			memcpy(d->bytes, st->pool, st->pool_len);
			d->len = st->pool_len;
			d->nbytes = d->len;
		}
		d->icase = (st->flags & KOF_STR_ICASE) != 0;
		d->fullword = (st->flags & KOF_STR_FULLWORD) != 0;
		d->obj = v->node[v->sel_node].obj;
		/*
		 * THE RANGE THE MODULE DECLARED, which the pack does keep.
		 *
		 * This used to derive a region from where the bytes turned out
		 * to be, on the grounds that "the module's range is not in the
		 * pack either". That was wrong: the pack stores each module's
		 * scan_mask, the engine reads it on every search, and
		 * kof_touch_object now carries it through.
		 *
		 * Deriving it was not merely roundabout, it was unsound. A
		 * marker declared in SYM_EXP is not in the file at all - the
		 * block's records are built - so node_at found nothing, the
		 * range came out "-", decl_locate then searched the file
		 * instead of the block, and the row called a marker absent
		 * that the scan finds every time. The engine and the panel
		 * disagreeing about one object is the one answer this pane
		 * must never give.
		 *
		 * Zero stays zero: a module that names no region cannot be
		 * skipped by region, and widening it to whole-file here would
		 * be inventing a range it never declared.
		 */
		d->mask = t->scan_mask;
		d->mask0 = t->scan_mask;
		if (d->mask)
			rng_name_of(v->obj[d->obj].fmt, d->mask, d->rgn,
				    sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "-");
		d->grp = 1u;             /* matcher 1, the only one here */
		d->at = st->at;
		v->n_decl++;
	}
	if (!v->n_decl)
		return;
	/*
	 * The pack says where ONE occurrence is; the pane wants them all.
	 *
	 * st->at is what the scan happened to stop on. Re-running the search
	 * here fills the occurrence list and settles at/at_rgn the same way the
	 * source path does, so a draft built from a database and a draft built
	 * from a file light the same bytes. The declared region above is left
	 * alone: the pack kept the strings and not the logic, so where the
	 * bytes are IS the only reading of where the module would look.
	 */
	{
		uint32_t di;

		for (di = 0; di < v->n_decl; di++)
			decl_locate(v, &v->decl[di]);
	}

	memset(&v->grp[0], 0, sizeof v->grp[0]);
	v->n_grp = 1;
	v->cur_grp = 0;
	/* The range is the module's own, so the matcher shows what the rule
	 * actually searches rather than WHOLE-FILE. */
	v->grp[0].mask = t->scan_mask;
	snprintf(v->grp[0].note, sizeof v->grp[0].note,
		 "from %s - the database keeps the strings, not the logic",
		 t->family[0] ? t->family : "the database");

	memset(&v->cnd[0], 0, sizeof v->cnd[0]);
	snprintf(v->cnd[0].expr, sizeof v->cnd[0].expr, "1");
	v->cnd[0].parent = -1;
	v->cnd[0].level = LV_INFECT;
	v->n_cnd = 1;
	v->cur_cnd = 0;
	say_note(v, "Loaded %u string(s) from %s - markers only, no logic",
		 v->n_decl,
		 t->family[0] ? t->family : "the database");
	v->saved_hash = draft_hash(v);
}

/*
 * Show a signature that fired on this object, in place of whatever is in the
 * panel.
 *
 * Refuses while there is unsaved work and says so instead; the caller asks
 * again once that has been settled. Losing an hour of drafting to a click on a
 * list is the kind of thing a tool only has to do once.
 */
static void draft_show(struct view *v, uint32_t idx)
{
	struct object *ob = cur_obj(v);

	if (idx >= ob->n_touch)
		return;
	draft_clear(v);
	v->sel_touch = idx;

	/*
	 * The source first, and the database only when there is no source.
	 *
	 * The database holds the strings and the names; the logic is compiled
	 * code and is not in it. A rule shown from the database alone has every
	 * marker in one find_all and one branch under it, which is a shape the
	 * module may never have had - so it is the fallback, and it says so.
	 */
	{
		const char *path = src_of(v, &ob->touch[idx]);
		int rc = path ? draft_from_source(v, path) : 0;

		if (rc) {
			/*
			 * A draft that came from a file belongs to that file:
			 * generating writes it back rather than starting a
			 * numbered copy beside it. Opening a signature in order
			 * to change it is a deliberate act, which is the thing
			 * the do-not-overwrite rule exists to tell apart from
			 * a name that happened to collide.
			 */
			snprintf(v->gen_path, sizeof v->gen_path, "%.*s",
				 (int)sizeof v->gen_path - 1, path);
			v->gen_ok = 1;
			v->from_rule = 1;
			v->saved_hash = draft_hash(v);
			/* The path shows on its own; `warn` is for things that
			 * are wrong, and a loaded file is not one. */
			v->warn[0] = 0;
			if (rc < 0)
				say_note(v, "Partly read - check it against the file");
			return;
		}
		draft_from_touch(v, &ob->touch[idx]);
		v->from_rule = 1;
	}
}

/*
 * A signature in the tree that searches for the same thing as this draft.
 *
 * Order independent, and independent of the names and the comments, because a
 * duplicate rarely looks like one: the usual way to make one is to write the
 * same markers again from the same sample under a slightly different family.
 * Its own file does not count as a duplicate of itself.
 *
 * Returns the path, or NULL. Also reports a near miss - the same patterns bar
 * one - because that is a variant that should have been a branch of the
 * existing rule rather than a second rule.
 */
/*
 * The same fingerprint for the draft, spelled from the same words the file
 * would be written with - so a rule saved and then read back matches itself.
 */
static uint32_t draft_tgt(struct view *v)
{
	struct object *ob = &v->obj[v->n_decl && v->decl[0].obj < v->n_obj
				    ? v->decl[0].obj : 0];
	uint8_t fm = ob->ctx.format;
	uint32_t h = 0;
	char w[64];

	h = tgt_mix(h, (ob->fmt && fm < FMT_WORD_N) ? fmt_word[fm]
						    : "KOF_FMT_ANY");
	snprintf(w, sizeof w, "KOF_MALTYPE_%s",
		 v->maltype < MALTYPE_N ? maltype_word[v->maltype] : "VIRUS");
	h = tgt_mix(h, w);
	if (v->opt_on[OPT_ARCH]) {
		snprintf(w, sizeof w, "KOF_ARCH_%s",
			 arch_word[v->opt_val[OPT_ARCH] < ARCH_N
				   ? v->opt_val[OPT_ARCH] : 0].word);
		h = tgt_mix(h, w);
	}
	if (v->opt_on[OPT_SUBTYPE]) {
		uint64_t k = v->opt_val[OPT_SUBTYPE];

		if (fm == KOF_FMT_ELF)
			snprintf(w, sizeof w, "KOF_ELF_%s",
				 elf_sub[k < sizeof elf_sub / sizeof elf_sub[0]
					 ? k : 0]);
		else if (fm == KOF_FMT_PE)
			snprintf(w, sizeof w, "KOF_PE_%s",
				 pe_sub[k < sizeof pe_sub / sizeof pe_sub[0]
					? k : 0]);
		else
			w[0] = 0;
		if (w[0])
			h = tgt_mix(h, w);
	}
	if (v->opt_on[OPT_SIZE_MIN]) {
		snprintf(w, sizeof w, "SIZE_MIN=%llu",
			 (unsigned long long)v->opt_val[OPT_SIZE_MIN]);
		h = tgt_mix(h, w);
	}
	return h;
}

static const char *draft_dup(struct view *v, int *near)
{
	uint32_t pat = 0, n = 0, i, tgt;

	if (near)
		*near = 0;
	if (!v->n_decl)
		return NULL;
	src_index(v);
	if (!g_src)
		return NULL;
	tgt = draft_tgt(v);
	for (i = 0; i < v->n_decl; i++) {
		pat += decl_pat(&v->decl[i]);
		n++;
	}
	for (i = 0; i < g_n_src; i++) {
		if (v->gen_path[0] && !strcmp(g_src[i].path, v->gen_path))
			continue;
		if (!g_src[i].n_pat)
			continue;
		/* Same bytes AND the same thing to run them against. Same
		 * bytes aimed at another format, another subtype or another
		 * malware type is a sibling rule, not a copy of this one. */
		if (g_src[i].tgt != tgt)
			continue;
		if (g_src[i].pat == pat && g_src[i].n_pat == n)
			return g_src[i].path;
	}
	/*
	 * Nothing identical. A file with all but one of these patterns is worth
	 * naming too, and is found by dropping each of ours in turn - cheap at
	 * these sizes, and the answer a researcher wants before adding a rule
	 * that mostly repeats one.
	 */
	for (i = 0; i < g_n_src && near; i++) {
		uint32_t k;

		if (v->gen_path[0] && !strcmp(g_src[i].path, v->gen_path))
			continue;
		if (g_src[i].n_pat + 1u != n && g_src[i].n_pat != n + 1u)
			continue;
		for (k = 0; k < v->n_decl; k++) {
			uint32_t less = pat - decl_pat(&v->decl[k]);

			if (g_src[i].pat == less &&
			    g_src[i].n_pat + 1u == n) {
				*near = 1;
				return g_src[i].path;
			}
		}
	}
	return NULL;
}

/*
 * Why the draft cannot be generated yet, or NULL when it can.
 *
 * Checked as a whole rather than at the button, because the answer is also the
 * thing to say: a greyed control with no reason beside it is a control people
 * click repeatedly. The order is the order the work is done in, so the message
 * names the next thing to do rather than the last thing missing.
 */
/* The vocabulary a family or variant name is allowed to be spelled in. Empty is
 * not this function's business - a name that has not been typed yet is a
 * different message from one typed wrongly. */
static int name_chars_ok(const char *s)
{
	for (; *s; s++)
		if (!isalnum((unsigned char)*s) && *s != '.' && *s != '-' &&
		    *s != '_')
			return 0;
	return 1;
}

/*
 * What stops this draft being written, or NULL. `as_new` asks about Save As,
 * which is allowed in one case Save is not - see the note on v->foreign below.
 */
static const char *draft_missing_of(struct view *v, int as_new);

/* The strict question, for every caller that is describing the draft to a
 * reader rather than deciding whether one particular button works. */
static const char *draft_missing(struct view *v)
{
	return draft_missing_of(v, 0);
}

static const char *draft_missing_of(struct view *v, int as_new)
{
	uint32_t i;

	/*
	 * LOGIC THIS PANEL DOES NOT CARRY STOPS SAVE, AND ONLY SAVE.
	 *
	 * First, before anything about the draft's completeness, because it is
	 * not a complaint about the draft: the draft is fine and is a truthful
	 * view of the modelled part. It is a statement about the FILE - it
	 * holds more than this can write back, so writing it back would delete
	 * the rest.
	 *
	 * SAVE AS is a different act and used to be refused with it, which was
	 * wrong. Overwriting destroys the unmodelled logic; writing a NEW file
	 * destroys nothing, and deriving a rule from the part that is modelled
	 * is a thing a researcher does on purpose. The original stays exactly
	 * as it is, one directory entry away, to compare against.
	 *
	 * So this is asked with `as_new`, and the caller says which act it is.
	 */
	if (v->foreign && !as_new)
		return "Custom logic - Save As to derive a new rule from it";
	if (!v->family[0])
		return "Name the family";
	/*
	 * A NAME, AND ONLY THE CHARACTERS A NAME HAS.
	 *
	 * The family and every custom variant become part of a detection string
	 * - "ELF-x64/Botnet:Mirai-0i0bq" - and the variant is also written into
	 * the generated C as a quoted literal. Written straight, a quote in it
	 * ends that literal and everything after it is code the build compiles:
	 *
	 *     KOF_SCAN_INFECT("x", 0); system("id"); //");
	 *
	 * Refused here rather than escaped, because escaping would preserve a
	 * name nobody can have meant. ksigbuilder refuses the same set for the
	 * same reason, so a file written by hand is stopped too - this is the
	 * early, legible half of that check, not the whole of it.
	 */
	if (!name_chars_ok(v->family))
		return "Family: letters, digits, . - _ only";
	for (i = 0; i < v->n_cnd; i++)
		if (v->cnd[i].var_kind == 2 && v->cnd[i].variant[0] &&
		    !name_chars_ok(v->cnd[i].variant))
			return "Variant: letters, digits, . - _ only";
	if (!v->n_decl)
		return "Declare a string";
	if (!v->n_grp)
		return "Add a matcher";
	/*
	 * TWO MATCHERS THAT ASK THE SAME THING, INCLUDING THE THRESHOLD.
	 *
	 * Sharing a call is what makes two thresholds over one marker set
	 * cheap, and it is exactly what makes an accidental copy invisible:
	 * a duplicate no longer costs a second scan, so nothing about the
	 * generated code would look wrong. It is still a matcher that decides
	 * nothing the other one has not already decided, and the condition
	 * naming it is dead weight - so it is refused here rather than found
	 * later by wondering which of the two a branch meant.
	 *
	 * The threshold is part of the comparison on purpose: differing there
	 * is the whole point of the shape, and only matchers that agree on it
	 * too are copies.
	 *
	 * Compared as questions rather than as spellings - see grp_thresh_eff.
	 * find_any over a set and find_multi >= 1 over the same set are one
	 * matcher written two ways, and the generated body makes that plain by
	 * emitting "m1 >= 1" twice: the second branch is unreachable. The old
	 * test compared the rule kinds first and so let that pair through.
	 */
	for (i = 0; i < v->n_grp; i++) {
		uint32_t j;

		for (j = i + 1u; j < v->n_grp; j++)
			if (grp_same_call(v, i, j))
				return "Two matchers ask the same thing - "
				       "remove one or change a threshold";
	}
	for (i = 0; i < v->n_grp; i++)
		if (!grp_count(v, i))
			return "Every matcher needs a string";
	/*
	 * What one call can hold.
	 *
	 * KOF_FS_FOLD stops at sixteen names and the cap shows up as an
	 * undefined KOF_FS_17 - a compile error, which is the right place for
	 * it in a hand written module and the wrong place for one this tool
	 * generated. Refused here so the failure lands where the decision was
	 * made rather than in a build log.
	 */
	for (i = 0; i < v->n_grp; i++)
		if (grp_count(v, i) > 16u)
			return "A matcher holds at most 16 markers - "
			       "split it in two";
	if (!v->n_cnd)
		return "Add a condition";
	for (i = 0; i < v->n_cnd; i++) {
		/*
		 * A condition with children and no matchers of its own is a
		 * grouping, not an omission.
		 *
		 * It is how a shape like "(1) or (2 and 3)" gets written
		 * without a free text expression: the outer one tests nothing
		 * and exists to hold the two that do. Only a branch that has to
		 * decide something needs something to decide it on.
		 */
		if (!v->cnd[i].expr[0] && !cnd_children(v, i))
			return "Every condition needs a matcher";
	}

	/*
	 * Nothing declared and then left out.
	 *
	 * A string in no matcher still gets a KOF_DEFINE_STR and is never
	 * searched for; a matcher no condition names is never written into the
	 * body at all, which quietly takes its strings with it. Both compile,
	 * both look finished on screen, and neither does what the panel appears
	 * to say - so they are caught here rather than found later by wondering
	 * why a marker never fires.
	 *
	 * What is deliberately NOT checked is a matcher named more than once. It
	 * reads like a redundancy and sometimes is, but "(M1|M2) & (M1|M3)" is a
	 * real shape - the same search meaning different things on two branches
	 * - and refusing it would cost more than the tidiness is worth.
	 */
	{
		static char why[64];

		for (i = 0; i < v->n_decl; i++)
			if (v->decl[i].grp == 0) {
				snprintf(why, sizeof why,
					 "string %u is in no matcher", i + 1u);
				return why;
			}
		for (i = 0; i < v->n_grp; i++) {
			uint32_t k, used = 0;

			for (k = 0; k < v->n_cnd; k++)
				used += (uint32_t)cnd_uses(&v->cnd[k], i);
			if (!used) {
				snprintf(why, sizeof why,
					 "matcher %u is in no condition",
					 i + 1u);
				return why;
			}
		}
		/*
		 * A range nothing searches.
		 *
		 * Same rule as the two above and for the same reason: a
		 * KOF_TARGET_RANGE no kof_find_str names compiles, reads as
		 * part of the signature, and does nothing.
		 */
		for (i = 0; i < v->n_rng_add; i++) {
			uint32_t k, used = 0;
			char nm[24];

			for (k = 0; k < v->n_grp; k++)
				used += (uint32_t)(grp_has_range(v, k) &&
						   grp_mask(v, k) ==
						   v->rng_add[i]);
			if (used)
				continue;
			rng_name_of(cur_obj(v)->fmt, v->rng_add[i], nm,
				    sizeof nm);
			snprintf(why, sizeof why,
				 "scan range %.12s is in no matcher", nm);
			return why;
		}
	}
	return NULL;
}

/*
 * Whether Save, Save As and Generate would do anything - asked in one place.
 *
 * generate() already decides this for itself, because a key runs it as well as
 * a button, and the buttons used to decide it a second time for their colour.
 * The two disagreed on exactly the case that matters: a signature opened out of
 * the Skip list and not yet touched drew Save GREEN and Save As grey, so the
 * one lit control on the screen was the one that overwrites somebody else's
 * file - and pressing it did nothing but set a message, because generate()
 * refused it. Both now read the same answer from here.
 */
static int save_ok(struct view *v)
{
	int near = 0;

	if (draft_missing_of(v, 0))
		return 0;
	/* A draft with a file behind it: only an actual change is worth
	 * writing. Without a file it is a new module, and the thing to refuse
	 * is one the tree already holds. */
	if (v->gen_path[0])
		return draft_dirty(v);
	return !(draft_dup(v, &near) && !near);
}

static int save_as_ok(struct view *v)
{
	int near = 0;

	if (draft_missing_of(v, 1) || !v->gen_path[0] || !draft_dirty(v))
		return 0;
	return !(draft_dup(v, &near) && !near);
}


static void generate(struct view *v, int as_new)
{
	{
		/*
		 * The button is greyed when this returns something, but the
		 * key that also runs it is not - and a draft that is short of
		 * a matcher would otherwise be written out as a module that
		 * searches for nothing.
		 */
		/* The same question the button asked, with the same argument:
		 * a key runs this too, and the two must not disagree about
		 * whether Save As is allowed on a read-only rule. */
		const char *why = draft_missing_of(v, as_new);
		int near = 0;
		const char *dup;

		if (why) {
			say_err(v, "%s first", why);
			return;
		}
		dup = draft_dup(v, &near);
		if (dup && !near) {
			say_note(v, "Same markers as %s - edit that instead",
				 dup);
			return;
		}
		/*
		 * Nothing to write either way.
		 *
		 * For Save As a copy would be a duplicate; for Save the file
		 * on disk already says this. Repeated clicks used to rewrite
		 * it each time, which was harmless and looked like nothing was
		 * happening.
		 */
		if (!draft_dirty(v) && v->gen_path[0]) {
			say_note(v, "%s",
				 as_new ? "Nothing changed - a copy would be a "
					  "duplicate"
					: "Nothing changed since the last save");
			return;
		}
	}
	struct object *ob = &v->obj[v->decl[0].obj];
	char path[400], safe[48], fname[48];
	uint32_t i, k;
	FILE *f;
	size_t j = 0;

	/* Kept, not cleared: it is the answer to "which file is this draft's",
	 * and clearing it here made every generate look like the first one -
	 * so a draft opened from a file wrote a numbered copy beside it. */
	if (!v->n_decl || !v->family[0])
		return;

	for (i = 0; v->family[i] && j + 1u < sizeof safe; i++)
		if (isalnum((unsigned char)v->family[i]) || v->family[i] == '_')
			safe[j++] = v->family[i];
	safe[j] = 0;
	/*
	 * THE FILE NAME IS LOWER CASE; THE FAMILY NAME IS NOT.
	 *
	 * They share their letters and nothing else. A signature tree sorted by
	 * a tool that folds case, or read on a filesystem that does, should not
	 * depend on how a researcher typed the family into the panel - so the
	 * name on disk is settled here, once.
	 *
	 * What the module DECLARES itself to be keeps the spelling it was
	 * given: KOF_TARGET_NAME below writes `safe`, and that string is the
	 * verdict a user reads. "mirai" is not how the family is written. The
	 * two used to be one variable, which is why lowering the path lowered
	 * the verdict with it.
	 */
	for (i = 0; safe[i]; i++)
		fname[i] = (char)tolower((unsigned char)safe[i]);
	fname[i] = 0;
	if (!j)
		return;

	/*
	 * One directory serves as both the source tree and the output, because
	 * they are the same thing: what this writes IS a signature source.
	 *
	 * A content root and one of its kind-directories are both reasonable
	 * things to be given. "bases" holds signatures/, decomp/ and unp/ and a
	 * detection does not belong loose at its top; "bases/signatures" is
	 * already the right place. So a signatures/ subdirectory, where one
	 * exists, is where the file goes.
	 */
	{
		char dir[300];
		struct stat st;

		snprintf(dir, sizeof dir, "%s/signatures", v->basedir);
		if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
			snprintf(dir, sizeof dir, "%s", v->basedir);
		if (kof_mkdir(dir, 0777) != 0 && errno != EEXIST) {
			say_err(v, "Cannot create %.90s", dir);
			return;
		}
		/*
		 * A file this session created, or a name nothing is using.
		 *
		 * Two families are often written from the same sample and a
		 * researcher writes several drafts for one family, so a name
		 * colliding is normal rather than exceptional - and silently
		 * overwriting somebody's signature because the family matched
		 * is not a thing to do quietly.
		 *
		 * So: whatever this draft has already been written to stays
		 * its file, and generate keeps updating it. Otherwise a new
		 * one is numbered.
		 *
		 * ALWAYS NUMBERED, even when the bare name is free.
		 *
		 * A family is written more than once - a variant, a second
		 * sample, a rule for the loader beside the rule for the payload
		 * - so Mirai.c is not the name of a signature, it is the name
		 * of the first one somebody happened to write. Numbering from
		 * the start means the second file is not a special case, the
		 * set reads as a set, and no name has to be renamed later to
		 * make room. Nothing this session did not create is touched.
		 */
		v->gen_ok = 0;
		if (!as_new && v->gen_path[0] &&
		    !strncmp(v->gen_path, dir, strlen(dir))) {
			snprintf(path, sizeof path, "%.*s",
				 (int)sizeof path - 1, v->gen_path);
		} else {
			/*
			 * The first number nothing is using, and the number
			 * gets WIDER rather than running out.
			 *
			 * Two digits is the everyday width and reads well: a
			 * family with a handful of rules gets _00 to _09. A
			 * family with more than a hundred is not an error to
			 * refuse, it is a family somebody has worked on, so the
			 * width grows instead. Falling off the end of a fixed
			 * width would leave the last name - which exists -
			 * about to be overwritten, and not overwriting is the
			 * whole reason these are numbered.
			 */
			static const unsigned wide[] = { 2u, 4u, 5u };
			unsigned lim[] = { 100u, 10000u, 100000u };
			size_t w;
			int free_one = 0;

			for (w = 0; w < sizeof wide / sizeof wide[0] &&
				    !free_one; w++) {
				unsigned n;

				for (n = 0; n < lim[w]; n++) {
					struct stat es;

					snprintf(path, sizeof path,
						 "%s/%s_%0*u.c", dir, fname,
						 (int)wide[w], n);
					if (stat(path, &es) != 0) {
						free_one = 1;
						break;
					}
				}
			}
			if (!free_one) {
				say_err(v, "%.40s has no free number left",
					fname);
				return;
			}
		}
	}
	f = fopen(path, "w");
	if (!f) {
		say_err(v, "Cannot write %.90s", path);
		return;
	}

	{
		/*
		 * The sample's name, not the path it happened to be at.
		 *
		 * A path names a machine as much as a file - somebody's home
		 * directory, a mount that will not exist next week - and none
		 * of that helps whoever reads this file later. The name is the
		 * part that identifies the sample.
		 */
		const char *base = draft_sample(v);
		char today[24];
		uint32_t m;

		/*
		 * This sample and this author join what the file already
		 * recorded rather than replacing it - the list was read back
		 * out of the block when the rule was opened. Testing a rule
		 * against a second sample used to erase the first.
		 */
		meta_add(v->meta_sample, &v->n_meta_sample, MAX_META, base);
		meta_add_who(v->meta_who, &v->n_meta_who, MAX_META,
			     meta_user());
		meta_today(today, sizeof today);
		if (!v->meta_made[0])
			snprintf(v->meta_made, sizeof v->meta_made, "%s",
				 today);

		fprintf(f, "/*\n * Generated by KOFViewer.\n *\n");
		for (m = 0; m < v->n_meta_sample; m++)
			fprintf(f, " * Test sample: %s\n", v->meta_sample[m]);
		if (ob->packer[0])
			fprintf(f, " * Unpacked by: %s\n", ob->packer);
		for (m = 0; m < v->n_meta_who; m++)
			fprintf(f, " * Researcher:  %s\n", v->meta_who[m]);
		fprintf(f, " * Created %s, updated %s\n", v->meta_made, today);
		/*
		 * The two version numbers that exist and that decide whether
		 * this file still works: the pack format a database must be in
		 * for this build to load it, and the module ABI the compiled
		 * signature must present. The engine has no version string of
		 * its own yet - kofeng.h says so beside kof_engine_db_version -
		 * and inventing one here would put a number in every file that
		 * nothing else in the tree could confirm.
		 */
		fprintf(f, " * Engine:      db format %u, module ABI %u\n",
			(unsigned)KOF_PACK_VERSION,
			(unsigned)KOFSIG_ABI_VERSION);
		fprintf(f, " */\n");
	}
	/*
	 * The author's own line about the module, in a block of its own.
	 *
	 * Separate from the one above deliberately. Both are leading comments
	 * and both come back through the same reader, so what tells them apart
	 * has to be structure rather than wording: the block that opens with
	 * the banner is this tool's, everything else in the header is the
	 * author's. Sharing one block meant the reader had to recognise the
	 * generated lines by their English, and anything a person wrote that
	 * happened to start "Test sample:" would have gone missing.
	 *
	 * Guarded the way every other emitted comment is: the text cannot hold
	 * a newline, so the only thing to stop is a sequence that would close
	 * the comment early.
	 */
	if (v->note[0]) {
		const char *q;

		fprintf(f, "\n/*\n * ");
		for (q = v->note; *q; q++)
			fputc((*q == '*' && q[1] == '/') ? ' ' : *q, f);
		fprintf(f, "\n */\n");
	}
	fprintf(f, "\n#include <kofmod/kofsig.h>\n\n");

	/* The format the object actually is, so the host can rule the module
	 * out without entering it - and so the regions above mean something. */
	fprintf(f, "KOF_TARGET_FORMAT(%s);\n",
		(ob->fmt && ob->ctx.format < FMT_WORD_N)
		? fmt_word[ob->ctx.format] : "KOF_FMT_ANY");
	fprintf(f, "KOF_TARGET_NAME(KOF_MALTYPE_%s, \"%s\");\n\n",
		v->maltype == 0 ? "VIRUS" :
		v->maltype == 1 ? "TROJAN" :
		v->maltype == 2 ? "ROOTKIT" :
		v->maltype == 3 ? "BOTNET" :
		v->maltype == 4 ? "RANSOM" :
		v->maltype == 5 ? "MINER" :
		v->maltype == 6 ? "ADWARE" :
		v->maltype == 7 ? "EXPLOIT" :
		v->maltype == 8 ? "DROPPER" : "HACKTOOL", safe);

	/* One declaration per declared range, spelled as the OR of the region
	 * names it holds - which is what a source has to write and what
	 * somebody grepping for it will search for. */
	if (v->opt_on[OPT_SIZE_MIN])
		fprintf(f, "KOF_TARGET_SIZE_MIN(%llu);\n",
			(unsigned long long)v->opt_val[OPT_SIZE_MIN]);
	if (v->opt_on[OPT_ARCH])
		fprintf(f, "KOF_TARGET_ARCH(KOF_ARCH_%s);\n",
			arch_word[v->opt_val[OPT_ARCH] < ARCH_N
				  ? v->opt_val[OPT_ARCH] : 0].word);
	if (v->opt_on[OPT_SUBTYPE]) {
		uint8_t fm = ob->ctx.format;

		if (fm == KOF_FMT_ELF)
			fprintf(f, "KOF_TARGET_SUBTYPE(KOF_ELF_%s);\n",
				elf_sub[v->opt_val[OPT_SUBTYPE] <
					sizeof elf_sub / sizeof elf_sub[0]
					? v->opt_val[OPT_SUBTYPE] : 0]);
		else if (fm == KOF_FMT_PE)
			fprintf(f, "KOF_TARGET_SUBTYPE(KOF_PE_%s);\n",
				pe_sub[v->opt_val[OPT_SUBTYPE] <
				       sizeof pe_sub / sizeof pe_sub[0]
				       ? v->opt_val[OPT_SUBTYPE] : 0]);
	}
	if (v->opt_on[OPT_SIZE_MIN] || v->opt_on[OPT_ARCH] ||
	    v->opt_on[OPT_SUBTYPE])
		fprintf(f, "\n");

	/*
	 * One declaration per distinct range the matchers actually search.
	 *
	 * Derived here rather than kept as a list, for the same reason the
	 * panel derives the summary: a range has no existence apart from a
	 * matcher naming one, and a kept list goes stale the moment a marker
	 * moves between matchers. This used to walk a list that nothing filled
	 * any more, so every generated module declared no range at all and then
	 * searched one.
	 */
	{
		uint32_t seen[MAX_GROUP], n_seen = 0, g2;

		for (g2 = 0; g2 < v->n_grp; g2++) {
			uint32_t m, b, q;
			char nm[RNG_IDENT_MAX];
			int first = 1;

			if (!grp_count(v, g2))
				continue;
			m = grp_mask(v, g2);
			for (q = 0; q < n_seen; q++)
				if (seen[q] == m)
					break;
			if (q < n_seen)
				continue;
			seen[n_seen++] = m;

			rng_ident(ob->fmt, m, nm, sizeof nm);
			fprintf(f, "KOF_TARGET_RANGE(%s, ", nm);
			/*
			 * The symbol halves first, and by their own names.
			 *
			 * The loop below spells a bit by asking the FORMAT for
			 * it, and these two belong to no format - so they came
			 * out unnamed, `first` stayed set, and the range was
			 * written as KOF_SCAN_ALL. A rule meaning "search the
			 * exports" would have compiled, shipped, and searched
			 * the whole file.
			 */
			if (!(m & KOF_SCAN_ALL) && (m & KOF_SCAN_SYM_IMP)) {
				fprintf(f, "KOF_SCAN_SYM_IMP");
				first = 0;
			}
			if (!(m & KOF_SCAN_ALL) && (m & KOF_SCAN_SYM_EXP)) {
				fprintf(f, "%sKOF_SCAN_SYM_EXP",
					first ? "" : " | ");
				first = 0;
			}
			if (!(m & KOF_SCAN_ALL))
				for (b = 0; b < 30u; b++) {
					const char *w = NULL;

					if (!(m & (1u << b)))
						continue;
					if (ob->fmt)
						for (q = 0;
						     q < ob->fmt->n_regions;
						     q++)
							if (ob->fmt->regions[q]
							    == (1u << b))
								w = ob->fmt->
								  region_name(
								    1u << b);
					if (!w)
						continue;
					fprintf(f, "%s%s",
						first ? "" : " | ", w);
					first = 0;
				}
			if (first)
				fprintf(f, "KOF_SCAN_ALL");
			fprintf(f, ");\n");
		}
		if (n_seen)
			fprintf(f, "\n");
	}

	for (i = 0; i < v->n_decl; i++) {
		const struct decl *d = &v->decl[i];

		if (d->hex) {
			fprintf(f, "KOF_DEFINE_HEXSTR(s%u, \"", i);
			/* The spelling, when the pattern has one that bytes
			 * cannot hold. Otherwise the bytes, which for a
			 * pattern declared from a selection is exact. */
			if (d->hexs[0])
				fputs(d->hexs, f);
			else
				for (j = 0; j < d->nbytes; j++)
					fprintf(f, "%02X", d->bytes[j]);
			fprintf(f, "\");\n");
		} else {
			fprintf(f, "KOF_DEFINE_STR(s%u, \"", i);
			decl_put_literal(f, d->bytes, d->nbytes);
			fprintf(f, "\", %s, %s);\n",
				d->icase ? "KOF_CASE_ICASE" : "KOF_CASE_EXACT",
				d->fullword ? "KOF_WORD_FULLWORD"
					    : "KOF_WORD_SUBSTRING");
		}
	}

	/* Spelled out rather than through KOF_DEFINE_SCAN. The macro expands to
	 * exactly this, and every module in bases/ writes it this way - a
	 * generated file that does not look like the hand written ones is a
	 * file people hesitate to edit. */
	fprintf(f, "\nvoid kof_scan(const struct kof_obj_ctx *ctx)\n{\n");
	/*
	 * A maximum size is a line in the body, not a declaration.
	 *
	 * kofsig.h refuses to have one at KOF_TARGET_SIZE_MIN and says why: an
	 * upper bound declared to the host is escaped by appending bytes nothing
	 * reads, which would turn padding into a way of not being scanned. In
	 * the body it is the module's own logic and costs what any other check
	 * costs.
	 */
	if (v->opt_on[OPT_SIZE_MAX])
		fprintf(f, "\tif (ctx->obj_size > %lluull)\n\t\treturn;\n\n",
			(unsigned long long)v->opt_val[OPT_SIZE_MAX]);
	/*
	 * Conditions, nested the way they were built.
	 *
	 * A condition with children is a gate: it concludes nothing itself and
	 * its children are what happens once it holds. That is exactly the
	 * shape bases/signatures/lkm_rootkit_general.c is written in, and it is
	 * only sayable because a matcher carries no verdict of its own.
	 */
	/*
	 * The shared calls, once each, before anything tests them.
	 *
	 * Named by the matcher that leads the group - see grp_same_call - so
	 * the name does not move when a later matcher is removed.
	 */
	{
		uint32_t g, wrote = 0;

		for (g = 0; g < v->n_grp; g++) {
			if (!grp_shared(v, g) || grp_lead(v, g) != g)
				continue;
			/* The shared call always counts: the group's members
			 * compare against a number, so the leader's own
			 * spelling does not decide the call's kind. */
			/*
			 * uint8_t, because the value cannot exceed 16: the
			 * count is a sum of 0/1 terms and KOF_FS_FOLD takes
			 * at most sixteen names in one call. Measured rather
			 * than assumed - the same module built both ways came
			 * out 165 bytes with uint32_t and 159 with uint8_t,
			 * the 8 bit form comparing in %al instead of loading
			 * and zero extending. Small, and it is also the type
			 * that states the bound.
			 */
			fprintf(f, "\tuint8_t m%u = ", g + 1u);
			emit_call_multi(f, v, g);
			fprintf(f, ";\n");
			wrote++;
		}
		if (wrote)
			fprintf(f, "\n");
	}
	{
		uint32_t prev = v->n_cnd;

		for (k = 0; k < v->n_cnd; k++) {
			if (v->cnd[k].parent >= 0)
				continue;
			emit_cond(f, v, k, 1,
				  prev < v->n_cnd && !v->cnd[prev].join);
			prev = k;
		}
	}
	fprintf(f, "}\n");

	v->gen_ok = ferror(f) == 0;
	fclose(f);
	/*
	 * The PATH, not a sentence about it.
	 *
	 * This used to hold "wrote /some/file.c", which reads well on the
	 * status line and is not a path - so the next Save could not recognise
	 * the file it had just written, fell through to "pick a name nothing is
	 * using", and produced a new numbered copy on every click. Save now
	 * overwrites, which is what Save has always meant; Save As is the one
	 * that starts a new file.
	 */
	snprintf(v->gen_path, sizeof v->gen_path, "%.*s",
		 (int)sizeof v->gen_path - 1, path);
	if (!v->gen_ok) {
		say_err(v, "Could not write the file");
		return;
	}
	/* A source has just appeared in the tree, or an existing one has moved
	 * its lines. Either way what the index knows about where each detection
	 * name sits is now about the file that was there before. */
	src_forget();
	v->warn[0] = 0;
	/* What was written is now what is saved. Without this the draft stayed
	 * dirty forever: the panel kept saying "(unsaved)" and the guard that
	 * refuses a pointless Save never fired. */
	v->saved_hash = draft_hash(v);
}

/*
 * The draft, laid out the way the source it becomes is laid out.
 *
 * Two areas. Above: what the module DECLARES - its name, its type, its ranges,
 * its strings, each with the id the conditions below will refer to. Below: the
 * conditions, which name ids rather than repeating bytes.
 *
 * That split is not decoration. A string declared once and used by a condition
 * is exactly the shape of the file being written, and a panel that printed the
 * bytes again under each condition would be describing a different file - and
 * would make a string used twice look like two strings.
 */
static void ch_add(struct chooser *c, const char *t)
{
	if (c->n < CH_ITEMS)
		snprintf(c->item[c->n++], CH_W, "%s", t);
}

/* The same, for a list whose rows are not all always there. */
static void ch_add_verb(struct chooser *c, const char *t, unsigned verb)
{
	if (c->n < CH_ITEMS)
		c->verb[c->n] = (uint8_t)verb;
	ch_add(c, t);
}

/* The same, for a row that OPENS A LIST rather than acting - drawn with the
 * menu bar's ">" marker. See chooser.sub. */
static void ch_add_verb_sub(struct chooser *c, const char *t, unsigned verb)
{
	if (c->n < CH_ITEMS)
		c->sub[c->n] = 1;
	ch_add_verb(c, t, verb);
}

/*
 * Fill and place a chooser.
 *
 * The contents are built here rather than by each caller so that what a list
 * offers stays next to what picking from it does - two halves of one decision,
 * which drift apart the moment they live in different functions.
 */
static void ch_open(struct view *v, int what, uint32_t arg, int row, int col);
/* The removable scan ranges, listed the same way where the menu is built and
 * where a pick is carried out. Defined beside rng_apply, used here first. */
static uint32_t rng_removable(struct view *v, uint32_t *mask, int *unused,
			      uint32_t cap);
/* Every range the draft has, in one order, and which regions the object has -
 * both defined beside rng_apply and used by the menus above it. */
static uint32_t rng_all(struct view *v, uint32_t *mask, int *unused,
			uint32_t cap);
static uint32_t rng_object_regions(struct view *v);


/*
 * Is this optional declaration worth offering on THIS object.
 *
 * One function because two places need the answer - the list that offers them
 * and the taker that walks the same list to find which row was picked - and a
 * predicate written twice is a menu that offers what it will refuse.
 *
 * Architecture and subtype belong to executables and to nothing else: a zip has
 * no machine and a PDF has no ET_DYN. Asked of the object in hand rather than
 * from a fixed list, so the menu answers for the file being looked at.
 */
static int opt_offerable(struct view *v, int k)
{
	uint8_t fm = cur_obj(v)->ctx.format;
	int exe = fm == KOF_FMT_ELF || fm == KOF_FMT_PE || fm == KOF_FMT_MACHO;

	if (k < 0 || k >= OPT_COUNT || v->opt_on[k])
		return 0;
	if (k == OPT_ARCH)
		return exe && cur_obj(v)->ctx.arch != 0;
	if (k == OPT_SUBTYPE)
		return exe && kof_inspect_subtype_name(fm,
						cur_obj(v)->ctx.subtype) != NULL;
	return 1;                       /* the two sizes always apply */
}

static void ch_open(struct view *v, int what, uint32_t arg, int row, int col)
{
	struct chooser *c = &v->ch;
	uint32_t i;

	memset(c, 0, sizeof *c);
	c->what = what;
	c->arg = arg;

	if (what == CH_RULE) {
		ch_add(c, "find_all");
		ch_add(c, "find_any");
		ch_add(c, "find_multi (>=N)");
	} else if (what == CH_RANGE) {
		/*
		 * WHICH DEFINED RANGE THIS MATCHER SEARCHES.
		 *
		 * Every range the draft has, plus WHOLE-FILE - not a set worked
		 * out from the markers the matcher happens to hold. That was
		 * the old rule and it is what made a matcher on CODE&DATA
		 * refuse a DATA marker: the range was DERIVED from the first
		 * marker, so taking one from CODE narrowed the matcher to CODE
		 * and locked the other region out, even though the draft had
		 * declared CODE&DATA and the row displayed it.
		 *
		 * Picking here PINS grp[g].mask to the chosen range, so the
		 * eligibility test - rng_holds, an overlap - then admits a
		 * marker from any region the range covers. That is the whole
		 * fix: the range says what may go in, rather than the first
		 * thing that went in saying what the range is.
		 */
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(v, rm, ru, 2u * MAX_GROUP), k;
		char t[CH_W];

		for (k = 0; k < nr; k++) {
			rng_name_of(cur_obj(v)->fmt, rm[k], t, sizeof t);
			ch_add(c, t);
		}
		ch_add(c, "WHOLE-FILE");
	} else if (what == CH_RANGE2) {
		/*
		 * THE MENU FOR ONE RANGE, the one whose name was clicked.
		 *
		 * `arg` is its index in rng_all's order - the same order the row
		 * drew the names in - so the subject is settled before a single
		 * item is offered, and every item names it.
		 *
		 * Three things can be done to a range and they are different
		 * questions: make it cover MORE (extend), make it cover LESS
		 * (drop one region), or make it not exist (remove). Drop and
		 * remove are deliberately not the same item: on CODE&DATA&NOLOAD
		 * "remove" takes the whole range away, while "drop" takes one
		 * region off and leaves a narrower range behind.
		 */
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(v, rm, ru, 2u * MAX_GROUP);
		uint32_t cur, have, rest, bits = 0, b;
		char nm[40], t[CH_W];

		if (arg >= nr)
			return;
		cur  = rm[arg];
		have = rng_object_regions(v);
		rest = have & ~cur;               /* regions it does not cover */
		for (b = 0; b < 32u; b++)
			bits += (cur >> b) & 1u;
		rng_name_of(cur_obj(v)->fmt, cur, nm, sizeof nm);
		c->arg2 = cur;

		/* Extend: one region left is named outright, several ask. */
		if (rest && !(cur & KOF_SCAN_ALL)) {
			uint32_t rb = 0;

			for (b = 0; b < 32u; b++)
				rb += (rest >> b) & 1u;
			if (rb == 1u) {
				char on[40];

				rng_name_of(cur_obj(v)->fmt, rest, on, sizeof on);
				snprintf(t, sizeof t, "Extend with %.20s", on);
				ch_add_verb(c, t, 0);
			} else {
				ch_add_verb_sub(c, "Extend with a region", 0);
			}
		}
		/*
		 * Drop one region, only while there is more than one to drop
		 * FROM: a range of a single region has nothing to narrow to,
		 * and taking its last region away is what Remove means.
		 */
		if (bits > 1u)
			ch_add_verb_sub(c, "Drop a region from this range", 1);
		snprintf(t, sizeof t, "Remove scan range %.15s", nm);
		ch_add_verb(c, t, 2);
		if (!c->n)
			return;
	} else if (what == CH_RANGE_ADD) {
		/*
		 * A NEW RANGE, over any single region the object has, and
		 * WHOLE-FILE last.
		 *
		 * Every region is offered, not only those no range covers yet.
		 * A narrow range and a wider one containing it are different
		 * questions - "this marker must be in CODE" beside "any of
		 * these, wherever the compiler put them" - and offering only
		 * the uncovered ones made the narrow one unreachable the moment
		 * the wide one existed, with no way back. An exactly duplicate
		 * mask is still refused where the range is created; the packer
		 * merges identical masks anyway.
		 */
		uint32_t have = rng_object_regions(v), b;
		char t[CH_W];

		for (b = 0; b < 32u; b++) {
			if (!(have & (1u << b)))
				continue;
			rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
			ch_add(c, t);
		}
		ch_add(c, "WHOLE-FILE");
	} else if (what == CH_RANGE_EXT || what == CH_RANGE_DROP) {
		/*
		 * Which region to add to, or take off, the subject range. The
		 * subject came down in arg2 from the menu that raised this one.
		 */
		/*
		 * THE SUBJECT COMES THROUGH `arg`, not arg2.
		 *
		 * ch_open memsets the chooser and then builds the items, so
		 * anything the caller writes into arg2 AFTERWARDS is not there
		 * while this list is being made. It was read from arg2 and the
		 * effects were both bugs: Drop saw 0, produced no items and so
		 * never opened at all, and Extend saw "every region" while the
		 * taker later saw "every region except this range's" - two
		 * different lists, so row N chose a different region from the
		 * one printed on it.
		 */
		uint32_t set = what == CH_RANGE_EXT
			     ? (rng_object_regions(v) & ~arg) : arg;
		char t[CH_W];
		uint32_t b;

		for (b = 0; b < 32u; b++) {
			if (!(set & (1u << b)))
				continue;
			rng_name_of(cur_obj(v)->fmt, 1u << b, t, sizeof t);
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_LEVEL) {
		/*
		 * Two menus, not one of six.
		 *
		 * The level and the variant are independent - every level works
		 * with every naming - so one list of their combinations makes
		 * the reader find their own answer among products of two
		 * questions, and grows by multiplication the moment either
		 * side gains an option.
		 */
		ch_add(c, lvl_word[LV_INFECT]);
		ch_add(c, lvl_word[LV_SUSPECT]);
		/*
		 * A branch that concludes nothing, on purpose.
		 *
		 * Reads as a gap in the list until it is needed, and then it is
		 * the only thing that will do: a gate wants it so its children
		 * are the whole answer, and a chain wants it so one case can be
		 * ruled out before the else catches everything left.
		 */
		ch_add(c, lvl_word[LV_NONE]);
	} else if (what == CH_VARIANT) {
		ch_add(c, "Auto");
		ch_add(c, "Generic");
		ch_add(c, "Custom");
	} else if (what == CH_TYPE) {
		for (i = 0; i < MALTYPE_N; i++)
			ch_add(c, maltype_word[i]);
	} else if (what == CH_MARKER) {
		/*
		 * Only the markers this condition could actually search for:
		 * unused, and inside the range it names. Offering the rest and
		 * refusing afterwards would be a list that lies about itself.
		 */
		char t[CH_W];
		for (i = 0; i < v->n_decl; i++) {
			/* Already in THIS matcher is what disqualifies it -
			 * being in another one does not. A marker two matchers
			 * ask about is the whole point of the shape. */
			if (v->decl[i].grp & (1u << arg))
				continue;
			if (!rng_holds(grp_mask(v, arg), v->decl[i].mask))
				continue;
			snprintf(t, sizeof t, "%u  %s  %s", i + 1u,
				 v->decl[i].hex ? "hex" : "str",
				 v->decl[i].rgn);
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_CMATCH) {
		/*
		 * The matchers this condition does not already name.
		 *
		 * Same shape as picking a marker for a matcher, one level up:
		 * a condition is written over matchers the way a matcher is
		 * written over markers, and offering one that is already in
		 * the expression would produce "1&1".
		 */
		char t[CH_W];

		for (i = 0; i < v->n_grp; i++) {
			if (!cmatch_ok(v, arg, i))
				continue;
			snprintf(t, sizeof t, "%u  %s", i + 1u,
				 v->grp[i].rule == 1 ? "find_any" :
				 v->grp[i].rule == 2 ? "find_multi" :
				 "find_all");
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_LOGIC) {
		/* The operators, unglossed. They are the two words a signature
		 * author already thinks in, and a sentence explaining what "or"
		 * means is a sentence they read once and then read past. */
		ch_add(c, "or");
		ch_add(c, "and");
	} else if (what == CH_SWITCH) {
		/*
		 * Three answers, and the one that loses work is not the first.
		 *
		 * Named by what happens rather than by yes and no: "discard"
		 * is a word people read before clicking, "OK" is not.
		 */
		/*
		 * Capitalised, like every other row that is an ACTION. The
		 * lowercase rows in these menus are values a signature can
		 * hold - fullword, ignore-case, and, or, find_all - and the
		 * difference is worth keeping visible: one row sets a field,
		 * the other does something to the draft.
		 */
		ch_add(c, "Keep editing");
		ch_add(c, "Write it, then switch");
		ch_add(c, "Discard it and switch");
	} else if (what == CH_OPT) {
		/* Only the ones this object can answer for, and only the ones
		 * not already there: a list that offers what it will refuse is
		 * a list that lies about itself. */
		if (opt_offerable(v, OPT_SIZE_MIN))
			ch_add(c, opt_word[OPT_SIZE_MIN]);
		if (opt_offerable(v, OPT_SIZE_MAX))
			ch_add(c, opt_word[OPT_SIZE_MAX]);
		/* Architecture and subtype belong to executables and to nothing
		 * else - opt_offerable is where that is decided, for this list
		 * and for the taker both. */
		if (opt_offerable(v, OPT_ARCH))
			ch_add(c, opt_word[OPT_ARCH]);
		if (opt_offerable(v, OPT_SUBTYPE))
			ch_add(c, opt_word[OPT_SUBTYPE]);
		if (!c->n)
			return;
	} else if (what == CH_ARCH) {
		for (i = 0; i < ARCH_N; i++)
			ch_add(c, arch_word[i].word);
	} else if (what == CH_SUBTYPE) {
		uint8_t fmt = cur_obj(v)->ctx.format;

		if (fmt == KOF_FMT_ELF)
			for (i = 0; i < sizeof elf_sub / sizeof elf_sub[0]; i++)
				ch_add(c, elf_sub[i]);
		else if (fmt == KOF_FMT_PE)
			for (i = 0; i < sizeof pe_sub / sizeof pe_sub[0]; i++)
				ch_add(c, pe_sub[i]);
		if (!c->n)
			return;
	} else if (what == CH_WORD) {
		ch_add(c, "substring");
		ch_add(c, "fullword");
	} else if (what == CH_CASE) {
		ch_add(c, "exact-case");
		ch_add(c, "ignore-case");
	} else if (what == CH_THRESH) {
		char t[CH_W];
		uint32_t n = arg < v->n_grp ? grp_count(v, arg) : 0;

		/*
		 * WHERE THE LIST STARTS DEPENDS ON WHETHER THE CALL IS SHARED.
		 *
		 * On its own, ">= 1" is find_any spelled the long way and n is
		 * find_all - both already have their own entry in the rule
		 * list, so offering them here would be two ways to say one
		 * thing.
		 *
		 * Sharing a call changes that. "at least three, otherwise at
		 * least one" is a real pair of thresholds over ONE scan, and
		 * writing the weaker half as a second find_any matcher would
		 * scan the same markers in the same region again - the cost
		 * this shape exists to remove. So when another matcher asks the
		 * same thing, 1 becomes a threshold like any other.
		 */
		uint32_t lo = (arg < v->n_grp && grp_shared(v, arg)) ? 1u : 2u;

		/* The number, and only the number. How many there are to
		 * choose from is not a choice - it is shown beside the field
		 * and follows the markers as they are added. */
		for (i = lo; i + 1u <= n; i++) {
			snprintf(t, sizeof t, ">= %u", i);
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else {
		return;
	}

	/*
	 * Above what was clicked, never on top of it.
	 *
	 * A list that covers its own control hides the thing being changed, and
	 * the click that would dismiss it lands on the list instead - so the
	 * next click goes into closing rather than doing, and the control below
	 * looks broken. `row` is the row that was clicked; the list ends on the
	 * one above it.
	 */
	c->open = 1;
	c->row = row - c->n;
	if (c->row + c->n > g_rows)
		c->row = g_rows - c->n;
	if (c->row < 1)
		c->row = 1;
	c->col = col;
	if (c->col + CH_W > g_cols)
		c->col = g_cols - CH_W;
	if (c->col < 1)
		c->col = 1;
}

/*
 * Give every matcher searching `was` the mask `now`.
 *
 * By range rather than by matcher because that is what the summary row edits:
 * the row lists distinct ranges, and two matchers sharing one are two names for
 * the same decision - changing what DATA covers changes it for both.
 */
static void rng_retarget(struct view *v, uint32_t was, uint32_t now)
{
	uint32_t g, i, w = 0;

	for (g = 0; g < v->n_grp; g++) {
		if (!grp_has_range(v, g) || grp_mask(v, g) != was)
			continue;
		v->grp[g].mask = now;
	}
	/*
	 * AND THE DECLARED LIST, which is the half this used to miss.
	 *
	 * A range put there by [+ Scan range] lives in rng_add until a matcher
	 * is given it, and this function only ever walked the matchers. Two
	 * things went wrong from that. Extending a range NO matcher had yet did
	 * nothing at all - the loop above matched nothing - so a range could
	 * only be widened after it had been handed to a matcher. And extending
	 * one that a matcher DID have moved the matcher to the wider mask while
	 * leaving the old narrow mask sitting in rng_add, where rng_all then
	 * reported it as a second, unused range: a region that appeared out of
	 * nowhere the moment you extended.
	 *
	 * Rewritten with a dedup, because the wider mask may already be
	 * declared - two entries for one mask would draw the same range twice.
	 */
	for (i = 0; i < v->n_rng_add; i++) {
		uint32_t m = v->rng_add[i] == was ? now : v->rng_add[i];
		uint32_t k;
		int dup = 0;

		for (k = 0; k < w; k++)
			dup |= v->rng_add[k] == m;
		if (!dup)
			v->rng_add[w++] = m;
	}
	v->n_rng_add = w;
	/*
	 * THE STRINGS ARE LEFT ALONE.
	 *
	 * This used to rewrite every marker's own region to the matcher's new
	 * range. That is a different fact: a string's region is where it WAS
	 * FOUND and the matcher's range is where it will be LOOKED FOR - the
	 * distinction the panel spends two column headings on. Widening a
	 * matcher to CODE&DATA does not move a marker that was found in CODE,
	 * and saying it does makes the row claim a provenance the search never
	 * established. Eligibility still holds: rng_holds is an overlap, so a
	 * CODE marker remains valid for a CODE&DATA matcher.
	 */
}

/*
 * THE SCAN RANGES A READER MAY REMOVE, and which kind each one is.
 *
 * Two kinds on one list, because a reader thinks of them as one thing - the
 * ranges this draft has. An UNUSED range is a KOF_TARGET_RANGE the draft
 * declared that no matcher searches; removing it just drops the declaration. A
 * range a matcher DOES search has no life apart from that matcher - see the note
 * on grp.mask - so removing it removes the matcher, the same thing the matcher's
 * own [x] does, reached from where the reader was looking instead.
 *
 * Unused first, then the matcher ranges deduplicated. Enumerated the same way
 * where the menu is drawn and where a pick is carried out, so a row index means
 * the same on both sides.
 */
static uint32_t rng_removable(struct view *v, uint32_t *mask, int *unused,
			      uint32_t cap)
{
	uint32_t n = 0, i, g, k;

	for (i = 0; i < v->n_rng_add && n < cap; i++) {
		int used = 0;

		for (g = 0; g < v->n_grp; g++)
			used |= grp_has_range(v, g) &&
				grp_mask(v, g) == v->rng_add[i];
		if (used)
			continue;
		mask[n] = v->rng_add[i];
		unused[n] = 1;
		n++;
	}
	for (g = 0; g < v->n_grp && n < cap; g++) {
		uint32_t mm;
		int dup = 0;

		if (!grp_has_range(v, g))
			continue;
		mm = grp_mask(v, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == mm;
		if (dup)
			continue;
		mask[n] = mm;
		unused[n] = 0;
		n++;
	}
	return n;
}

/*
 * EVERY RANGE THE DRAFT HAS, in one order.
 *
 * The distinct masks the matchers search, then the declared ones nothing
 * searches yet. Its own function because three places need the same list in the
 * same order - the row that draws the names, the click that turns a column into
 * a range, and the menu that acts on one - and a list built three times is a
 * list that disagrees with itself about which range is which.
 */
static uint32_t rng_all(struct view *v, uint32_t *mask, int *unused,
			uint32_t cap)
{
	uint32_t n = 0, g, k;

	for (g = 0; g < v->n_grp && n < cap; g++) {
		uint32_t m;
		int dup = 0;

		if (!grp_has_range(v, g))
			continue;
		m = grp_mask(v, g);
		for (k = 0; k < n; k++)
			dup |= mask[k] == m;
		if (dup)
			continue;
		mask[n] = m;
		unused[n] = 0;
		n++;
	}
	for (g = 0; g < v->n_rng_add && n < cap; g++) {
		int used = 0;

		for (k = 0; k < n; k++)
			used |= mask[k] == v->rng_add[g];
		if (used)
			continue;
		mask[n] = v->rng_add[g];
		unused[n] = 1;
		n++;
	}
	return n;
}

/* Which regions the object HAS, as a mask - what a range may be built from. */
static uint32_t rng_object_regions(struct view *v)
{
	uint32_t m = 0, k;

	for (k = 0; k < v->n_node; k++)
		if (v->node[k].obj == v->node[v->sel_node].obj && v->node[k].mask)
			m |= v->node[k].mask;
	return m;
}

/* Drop an unused declared range from the draft. */
static void rng_add_drop(struct view *v, uint32_t mask)
{
	uint32_t i;

	for (i = 0; i < v->n_rng_add; i++)
		if (v->rng_add[i] == mask) {
			memmove(&v->rng_add[i], &v->rng_add[i + 1u],
				(v->n_rng_add - i - 1u) * sizeof v->rng_add[0]);
			v->n_rng_add--;
			return;
		}
}

/*
 * Remove one scan range. An unused declaration is dropped; a range a matcher
 * searches takes the matcher(s) with it - backwards, because grp_remove shifts
 * every matcher above the one it drops down by one.
 */
static void rng_delete(struct view *v, uint32_t mask, int unused)
{
	if (unused) {
		rng_add_drop(v, mask);
		say_note(v, "%s", "Scan range removed");
		return;
	}
	{
		uint32_t g = v->n_grp;

		while (g-- > 0)
			if (grp_has_range(v, g) && grp_mask(v, g) == mask)
				grp_remove(v, g);
	}
	say_note(v, "%s", "Scan range removed with its matcher");
}

/*
 * Carry out one line of the scan range menu.
 *
 * `target` is the range being acted on - the only one, or the one picked from
 * the second list. `here` is where this draft's markers actually are, which is
 * what every line but the last is made of. The verbs are the menu's own order,
 * so the two cannot drift apart: whatever line n says, this does.
 */
static void rng_apply(struct view *v, int verb, uint32_t target, uint32_t here)
{
	switch (verb) {
	case 0:
		rng_retarget(v, target, here);
		say_note(v, "%s", "Scan range switched");
		break;
	case 1:
		rng_retarget(v, target, target | here);
		say_note(v, "%s", "Scan range extended");
		break;
	case 2: {
		/*
		 * The range and nothing else.
		 *
		 * It used to create the matcher that would name it, which put
		 * a matcher on the panel nobody had asked for and which could
		 * not be wanted yet - it has no markers, and which markers
		 * belong in it is a decision only the researcher can make. A
		 * declared range with no matcher is an ordinary half-finished
		 * state; it is listed as unused and it stops the save, which
		 * is what a half-finished state should do.
		 */
		uint32_t k;

		for (k = 0; k < v->n_grp; k++)
			if (grp_has_range(v, k) && grp_mask(v, k) == here) {
				say_note(v, "%s", "A matcher already searches "
					 "that range");
				return;
			}
		for (k = 0; k < v->n_rng_add; k++)
			if (v->rng_add[k] == here) {
				say_note(v, "%s", "That range is already "
					 "declared");
				return;
			}
		if (v->n_rng_add >= MAX_GROUP) {
			say_err(v, "%s", "No room for another range");
			return;
		}
		v->rng_add[v->n_rng_add++] = here;
		say_note(v, "%s", "Scan range added - give it a matcher");
		break;
	}
	case 3:
		rng_retarget(v, target, KOF_SCAN_ALL);
		say_note(v, "%s", "Scan range is now the whole file");
		break;
	default:
		break;
	}
}

/* What picking the highlighted item does. */
static void ch_take(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q;

	c->open = 0;
	v->ch_up.open = 0;
	if (c->what == CH_TYPE) {
		v->maltype = (uint32_t)c->sel;
		return;
	}
	if (c->what == CH_ARCH) {
		v->opt_val[OPT_ARCH] = arch_word[(size_t)c->sel % ARCH_N].val;
		return;
	}
	if (c->what == CH_SUBTYPE) {
		v->opt_val[OPT_SUBTYPE] = (uint32_t)c->sel;
		return;
	}
	if (c->what == CH_OPT) {
		struct object *ob = cur_obj(v);
		int seen = 0, k;

		for (k = 0; k < OPT_COUNT; k++) {
			/*
			 * THE SAME QUESTION THE LIST ASKED - see opt_offerable.
			 *
			 * These skips used to be written out again here, and the
			 * two spellings disagreed on the commonest object there
			 * is: the list offers "File subtype" when the format has
			 * a NAME for the object's subtype, and KOF_PE_EXE is
			 * zero with the name "EXE", while this loop skipped any
			 * subtype that was zero. So on an ordinary PE the row
			 * was offered, picked, and silently did nothing.
			 */
			if (!opt_offerable(v, k))
				continue;
			if (seen++ != c->sel)
				continue;
			v->opt_on[k] = 1;
			v->opt_val[k] = k == OPT_SIZE_MIN ? ob->buf.n :
					k == OPT_SIZE_MAX ? ob->buf.n * 2u :
					k == OPT_ARCH ? ob->ctx.arch
						      : ob->ctx.subtype;
			break;
		}
		return;
	}
	if (c->what == CH_WORD || c->what == CH_CASE) {
		if (c->arg >= v->n_decl)
			return;
		if (c->what == CH_WORD)
			v->decl[c->arg].fullword = c->sel;
		else
			v->decl[c->arg].icase = c->sel;
		return;
	}
	if (c->what == CH_RULE && c->arg == MAX_GROUP) {
		/* A new condition: the rule is chosen before there is anything
		 * in it, which is the order somebody thinks in. */
		grp_add(v);
		if (!v->n_grp)
			return;
		q = &v->grp[v->n_grp - 1u];
		q->rule = c->sel;
		if (c->sel == 2)
			q->thresh = 2;
		return;
	}
	if (c->what == CH_RANGE2) {
		/*
		 * One range is the subject, and c->arg2 holds its mask - put
		 * there when the menu was built, so the taker cannot disagree
		 * with the row about which range was pressed even if the draft
		 * changed shape in between.
		 */
		uint32_t cur = c->arg2, rest = rng_object_regions(v) & ~cur;
		int verb = (c->sel >= 0 && c->sel < c->n)
			 ? (int)c->verb[c->sel] : 2;
		uint32_t b, rb = 0;

		for (b = 0; b < 32u; b++)
			rb += (rest >> b) & 1u;

		if (verb == 0) {                /* extend */
			if (rb == 1u) {
				rng_retarget(v, cur, cur | rest);
				say_note(v, "%s", "Scan range extended");
			} else if (rb > 1u) {
				struct chooser up = *c;

				up.open = 1;
				ch_open(v, CH_RANGE_EXT, cur,
					up.row + up.sel + 1, up.col + CH_W);
				v->ch_up = up;
			}
			return;
		}
		if (verb == 1) {                /* drop one region */
			struct chooser up = *c;

			up.open = 1;
			ch_open(v, CH_RANGE_DROP, cur,
				up.row + up.sel + 1, up.col + CH_W);
			v->ch_up = up;
			return;
		}
		/* verb 2: remove the whole range, matcher and all. */
		{
			uint32_t dm[2u * MAX_GROUP];
			int du[2u * MAX_GROUP];
			uint32_t dn = rng_removable(v, dm, du, 2u * MAX_GROUP), i;

			for (i = 0; i < dn; i++)
				if (dm[i] == cur) {
					rng_delete(v, cur, du[i]);
					return;
				}
			/* Not in the removable list means a matcher searches it
			 * and rng_delete's own walk will take that matcher; ask
			 * it directly rather than refusing. */
			rng_delete(v, cur, 0);
		}
		return;
	}
	if (c->what == CH_RANGE_ADD) {
		uint32_t have = rng_object_regions(v), b, n = 0, pick = 0;

		for (b = 0; b < 32u; b++) {
			if (!(have & (1u << b)))
				continue;
			if ((int)n++ == c->sel) {
				pick = 1u << b;
				break;
			}
		}
		/* Past the last region is the WHOLE-FILE row. */
		rng_apply(v, 2, 0, pick ? pick : KOF_SCAN_ALL);
		return;
	}
	if (c->what == CH_RANGE_EXT || c->what == CH_RANGE_DROP) {
		uint32_t cur = c->arg;          /* the same field the build read */
		uint32_t set = c->what == CH_RANGE_EXT
			     ? (rng_object_regions(v) & ~cur) : cur;
		uint32_t b, n = 0, pick = 0;

		for (b = 0; b < 32u; b++) {
			if (!(set & (1u << b)))
				continue;
			if ((int)n++ == c->sel) {
				pick = 1u << b;
				break;
			}
		}
		if (!pick)
			return;
		if (c->what == CH_RANGE_EXT) {
			rng_retarget(v, cur, cur | pick);
			say_note(v, "%s", "Scan range extended");
		} else {
			/*
			 * Narrowed, not removed: the range keeps every region
			 * but this one. Taking the LAST region away would leave
			 * a matcher searching nothing, which is what Remove is
			 * for - so it is refused here rather than silently
			 * producing one.
			 */
			if ((cur & ~pick) == 0) {
				say_err(v, "%s", "That is the range's only "
					"region - remove the range instead");
				return;
			}
			rng_retarget(v, cur, cur & ~pick);
			say_note(v, "%s", "Region dropped from the scan range");
		}
		return;
	}
	if (c->what == CH_LOGIC) {
		if (c->arg < v->n_cnd)
			v->cnd[c->arg].join = c->sel;
		return;
	}
	if (c->what == CH_SWITCH) {
		if (c->sel == 0)
			return;                 /* stay where the work is */
		if (c->sel == 1)
			generate(v, 0);
		draft_show(v, c->arg);
		return;
	}
	if (c->what == CH_CMATCH) {
		struct cond *cc;
		uint32_t i, n = 0;

		if (c->arg >= v->n_cnd)
			return;
		cc = &v->cnd[c->arg];
		for (i = 0; i < v->n_grp; i++) {
			size_t l;

			if (!cmatch_ok(v, c->arg, i))
				continue;
			if ((int)n++ != c->sel)
				continue;
			/*
			 * Appended with & rather than replacing the text: the
			 * expression is the author's, and a second matcher
			 * usually narrows a condition. Anything else - an |, a
			 * parenthesis - is still typed into the box, which is
			 * why the box stays.
			 */
			l = strlen(cc->expr);
			snprintf(cc->expr + l, sizeof cc->expr - l, "%s%u",
				 l ? (cc->op ? "|" : "&") : "", i + 1u);
			break;
		}
		return;
	}
	if (c->what == CH_LEVEL || c->what == CH_VARIANT) {
		struct cond *cc;

		if (c->arg >= v->n_cnd)
			return;
		cc = &v->cnd[c->arg];
		if (c->what == CH_LEVEL) {
			cc->level = c->sel;
		} else {
			cc->var_kind = c->sel;
			/* "custom" is a promise of a name, so the caret goes
			 * where the name will be typed rather than leaving the
			 * word "custom" standing in for one. */
			if (c->sel == 2)
				v->edit = 4 + (int)c->arg;
		}
		return;
	}
	if (c->arg >= v->n_grp)
		return;
	q = &v->grp[c->arg];

	if (c->what == CH_MARKER) {
		uint32_t i, n = 0;

		for (i = 0; i < v->n_decl; i++) {
			if (v->decl[i].grp & (1u << c->arg))
				continue;
			if (!rng_holds(grp_mask(v, c->arg), v->decl[i].mask))
				continue;
			if ((int)n++ != c->sel)
				continue;
			v->decl[i].grp |= 1u << c->arg;
			break;
		}
	} else if (c->what == CH_THRESH) {
		/* The same lower bound the list was built with - see
		 * CH_THRESH there. Hard coding 2 here picked the wrong entry
		 * the moment a shared call made the list start at 1. */
		uint32_t lo = grp_shared(v, c->arg) ? 1u : 2u;

		q->rule = 2;
		q->thresh = (uint32_t)c->sel + lo;
	} else if (c->what == CH_RULE) {
		q->rule = c->sel;
		if (c->sel == 2 && q->thresh < 2u)
			q->thresh = 2;
	} else if (c->what == CH_RANGE) {
		/*
		 * The same list the menu was built from, walked in the same
		 * order - see the note there. Past the last defined range is
		 * the WHOLE-FILE row.
		 */
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(v, rm, ru, 2u * MAX_GROUP);

		q->mask = (c->sel >= 0 && (uint32_t)c->sel < nr)
			? rm[c->sel] : KOF_SCAN_ALL;
	}
}

static void draw_one_chooser(struct out *o, const struct chooser *c, int live)
{
	int i;

	for (i = 0; i < c->n; i++) {
		/* ch_open lifts a long list up the screen and stops at row one,
		 * so on a short terminal a very long one can still reach the
		 * bottom. Painting past it corrupts the rows below rather than
		 * simply not fitting. */
		if (c->row + i > g_rows)
			break;
		out_at(o, c->row + i, c->col);
		/* The parent keeps its highlight so the line the submenu is
		 * qualifying stays pointed at, but in a colour that says the
		 * keyboard is not there any more. */
		out_str(o, i == c->sel ? (live ? A_SEL : "\033[100;97m")
				       : "\033[47;30m");
		/* The ">" sits at the far edge, as the menu bar draws it. */
		if (c->sub[i])
			out_fmt(o, " %-*.*s>", CH_W - 3, CH_W - 3, c->item[i]);
		else
			out_fmt(o, " %-*.*s", CH_W - 2, CH_W - 2, c->item[i]);
		out_str(o, A_OFF);
	}
}

static void draw_chooser(struct out *o, struct view *v)
{
	if (!v->ch.open)
		return;
	if (v->ch_up.open)
		draw_one_chooser(o, &v->ch_up, 0);
	draw_one_chooser(o, &v->ch, 1);
}

/*
 * The screen row for the next panel line, or -1 when it is scrolled out.
 *
 * `*r` counts panel rows whether or not they are drawn, so the two halves - the
 * window and the position in the list - stay one number apart and a scrolled
 * panel does not have to be laid out twice.
 */
/*
 * Where a draft row lands once the panel is scrolled, and whether it lands on
 * the screen at all.
 *
 * `r` counts rows of the draft whether or not they are visible, so one number
 * serves both the layout and the scroll position, and a draft longer than its
 * pane does not have to be laid out twice to find out what fits.
 */
#define PR(rr)     (decl_top() + 1 + (int)(rr) - (int)v->prow_off)
#define PR_VIS(rr) ((int)(rr) >= (int)v->prow_off && \
		    (int)(rr) - (int)v->prow_off < g_decl_rows - 2)

/*
 * The condition rows, in reading order.
 *
 * Built once and walked by everything that cares - the row table, the drawing,
 * the click routing - because reading order is not array order: a nested
 * condition is stored after its parent but drawn between the parent's own rows
 * and whatever follows the parent's block. Walking the array instead put the
 * rule that joins one top level condition to the next above that condition's
 * children rather than below them, which is where it belonged.
 */
enum cseq_kind { CS_COND = 0, CS_MATCH, CS_JOIN, CS_ADD };

static void cseq_put(struct view *v, int kind, uint32_t idx)
{
	if (v->n_cseq >= sizeof v->cseq_kind / sizeof v->cseq_kind[0])
		return;
	v->cseq_kind[v->n_cseq] = (uint8_t)kind;
	v->cseq_idx[v->n_cseq] = idx;
	v->n_cseq++;
}

static void cnd_seq(struct view *v)
{
	uint32_t t, c;

	v->n_cseq = 0;
	for (t = 0; t < v->n_cnd; t++) {
		if (v->cnd[t].parent >= 0)
			continue;
		cseq_put(v, CS_COND, t);
		cseq_put(v, CS_MATCH, t);
		for (c = 0; c < v->n_cnd; c++) {
			if (v->cnd[c].parent != (int)t)
				continue;
			cseq_put(v, CS_COND, c);
			cseq_put(v, CS_MATCH, c);
			if (cnd_more_siblings(v, c))
				cseq_put(v, CS_JOIN, c);
		}
		/* The end of the block, and the way to extend it. Only where
		 * there is a block to extend - a condition has to exist before
		 * anything can be put inside it. */
		cseq_put(v, CS_ADD, t);
		if (cnd_more_siblings(v, t))
			cseq_put(v, CS_JOIN, t);
	}
}

enum prow_kind {
	RW_OPT = 0, RW_RANGES, RW_STRHDR, RW_STR, RW_ADDM,
	RW_MATCH, RW_MARKERS, RW_ADDC, RW_COND, RW_CMATCH,
	RW_MATHDR, RW_CNDHDR, RW_CJOIN
};

static void prow_add(struct view *v, int kind, uint32_t idx)
{
	if (v->n_prow >= sizeof v->prow_kind / sizeof v->prow_kind[0])
		return;
	v->prow_kind[v->n_prow] = (uint8_t)kind;
	v->prow_idx[v->n_prow] = idx;
	v->n_prow++;
}

/* Every row the panel would show, in order, before deciding which fit. */
static void prow_build(struct view *v)
{
	uint32_t i;

	v->n_prow = 0;
	for (i = 0; i < (uint32_t)OPT_COUNT; i++)
		if (v->opt_on[i])
			prow_add(v, RW_OPT, i);
	/*
	 * The scan range row while there is ANY range to show, which is not the
	 * same as "while there is a matcher".
	 *
	 * Gated on n_grp alone, removing the last matcher took the row with it -
	 * and with the row went every DECLARED range that no matcher had been
	 * given yet. Those still existed in rng_add, still blocked the save
	 * ("scan range X is in no matcher"), and now had nowhere to be seen and
	 * no menu to be removed from, because [Update scan range] lives on this
	 * row. A range one can neither use nor get rid of is a draft that cannot
	 * be finished.
	 */
	/*
	 * ALWAYS, like the Matchers and Conditions headings.
	 *
	 * Gated on having a matcher, removing the last one took the row away -
	 * and [+ Add scan range] lives on it, so there was then no way to
	 * declare a range at all: the draft could not be finished and nothing
	 * on the screen said why. A heading that disappears takes its controls
	 * with it, so this one does not disappear.
	 */
	prow_add(v, RW_RANGES, 0);
	if (v->n_decl) {
		prow_add(v, RW_STRHDR, 0);
		for (i = 0; i < v->n_decl; i++)
			prow_add(v, RW_STR, i);
	}
	prow_add(v, RW_MATHDR, 0);
	prow_add(v, RW_ADDM, 0);
	for (i = 0; i < v->n_grp; i++) {
		prow_add(v, RW_MATCH, i);
		prow_add(v, RW_MARKERS, i);
	}
	prow_add(v, RW_CNDHDR, 0);
	prow_add(v, RW_ADDC, 0);
	cnd_seq(v);
	for (i = 0; i < v->n_cseq; i++)
		prow_add(v, RW_COND, i);
}

/*
 * A heading that runs the width of the screen.
 *
 * The panel is four kinds of thing stacked with nothing between them, which is
 * why it read as one long list. A bar per section costs the row the column
 * headings were already taking and gives the eye somewhere to stop.
 */
/*
 * RE-LOCATE THE STRINGS' REGIONS - a small button, in the region column's own
 * heading rather than a sentence at the end of the row.
 *
 * It reads as one of the row buttons the strings already carry ([x] and the
 * rest) because that is what it is: three characters beside the thing it acts
 * on. Spelled out at the end of the heading it was the widest thing on the row
 * and said in five words what its position says by itself.
 */
#define BTN_UPDRGN "[r]"
/* " Strings     word      case         region" - the heading up to and
 * including the region title, so the button's column is measured from it
 * rather than counted by hand. */
#define STR_HDR_PRE " Strings     word      case         region"

static void sec_bar(struct out *o, struct view *v, int row, const char *text)
{
	int i, n = (int)strlen(text);

	(void)v;
	row_start(o, row, 1);
	out_str(o, A_HEAD);
	out_str(o, text);
	for (i = n; i < g_cols; i++)
		out_str(o, " ");
	out_str(o, A_OFF);
}

/*
 * A field slid by the panel's horizontal offset.
 *
 * Only the fields that can overrun their column take it - the comment on a
 * matcher or a condition, and the byte dump of a string. Sliding the whole row
 * would move the labels and the buttons out from under the pointer, which is a
 * panel that scrolls away from the mouse that is scrolling it.
 */

/*
 * The left edge of a condition's rows.
 *
 * A condition's number sits at a column decided by its depth, and every row
 * that belongs to it puts a bar in that same column - a tick under the number,
 * not a bracket drawn around a block. Nesting is shown by the indent alone,
 * which is what makes it possible to draw a child without any line art in front
 * of it at all.
 */
static void cnd_rail(struct out *o, int depth, int bar)
{
	int i, at = depth ? 6 : 1;

	out_str(o, A_DIM);
	for (i = 0; i < at; i++)
		out_str(o, " ");
	out_str(o, bar ? "|" : " ");
	for (i = 0; i < 5; i++)
		out_str(o, " ");
	out_str(o, A_OFF);
}

/*
 * One line of text inside a box, with the caret shown and the view following it.
 *
 * `*off` is how far the text is scrolled inside the box and is adjusted here
 * rather than by the caller: the only thing that should move it is the caret
 * leaving the box, and the caret is what this draws. That is also why there is
 * no wheel binding for it - a field that scrolls under the pointer would fight
 * the panel the pointer is over.
 *
 * The caret is an underline on the character it sits on, and a space when it is
 * past the end. A block cursor would hide the character; this is the same thing
 * every terminal editor does.
 */
/*
 * WHERE THE OPEN FIELD IS, SO A CLICK IN IT CAN BECOME A CARET.
 *
 * Every text box on the panel goes through field_draw, and only the open one is
 * drawn with `editing` set - so one record is enough for all of them, and no
 * caller has to remember to keep a box of its own in step with its drawing.
 *
 * `room` is cleared at the top of every frame: a field whose row scrolled out
 * of view is not drawn, and a stale rectangle would swallow clicks meant for
 * whatever now occupies those columns.
 */
static struct {
	int      row, col, room;
	uint32_t off, len;
} g_fld;

static void field_draw(struct out *o, const char *text, uint32_t caret,
		       uint32_t *off, int room, int editing, const char *ph,
		       int all)
{
	uint32_t len = (uint32_t)strlen(text), i;

	if (!text[0] && !editing) {
		out_fmt(o, "%-.*s", room, ph);
		return;
	}
	if (room < 1)
		room = 1;
	if (caret > len)
		caret = len;
	if (editing) {
		if (caret < *off)
			*off = caret;
		if (caret >= *off + (uint32_t)room)
			*off = caret - (uint32_t)room + 1u;
	}
	/*
	 * And never scrolled further right than the text needs.
	 *
	 * Keeping the caret in view is only half the rule; the other half is
	 * that scrolling right is pointless once what remains would fit. They
	 * were not both applied, so clearing a long comment and typing again
	 * left the window where the long text had pushed it: the caret was on
	 * screen at the left edge and the character just typed sat one column
	 * off it. Every field goes through here, so every field did it.
	 *
	 * The caret may sit one past the last character, which is why the text
	 * this has to fit is len + 1 while editing and len when not.
	 */
	{
		uint32_t want = editing ? len + 1u : len;

		if (*off + (uint32_t)room > want)
			*off = want > (uint32_t)room
			       ? want - (uint32_t)room : 0;
	}
	if (editing) {
		g_fld.row  = o->row_hint;
		g_fld.col  = o->col_base + (int)o->col_hint;
		g_fld.room = room;
		g_fld.off  = *off;
		g_fld.len  = len;
	}
	for (i = 0; i < (uint32_t)room; i++) {
		uint32_t at = *off + i;
		char t[2];

		/*
		 * Through out_str, never out_add.
		 *
		 * Only out_str counts printable columns, and the count is what
		 * every click range on the panel is recorded from. Emitting the
		 * characters with out_add drew them correctly and told the
		 * bookkeeping nothing, so a box holding a long string reported
		 * itself as ending where it began - and clicking the right hand
		 * part of it hit nothing, which looked like a field that had
		 * stopped accepting the caret.
		 */
		t[0] = at < len ? text[at] : ' ';
		t[1] = 0;
		if (editing && all && at < len) {
			out_str(o, "\033[7m");
			out_str(o, t);
			out_str(o, "\033[27m");
		} else if (editing && at == caret) {
			out_str(o, "\033[4m");
			out_str(o, t);
			out_str(o, "\033[24m");
		} else {
			out_str(o, t);
		}
	}
}

/*
 * Point every marker at the region it is actually in, here.
 *
 * A family's markers do not keep one address across its own files: the same
 * five kernel symbol names sit in a data section in the rootkit object and in
 * .rodata - which is CODE, because that segment executes - in the loader that
 * installs it. A rule carried from one to the other looks right on every row
 * and cannot fire, and switching five strings one at a time to find that out is
 * work nobody should do by hand.
 *
 * A marker that is not in this object at all is LEFT ALONE and counted. It may
 * well be a real marker of the family taken from another sample, and deleting a
 * declaration because the file in front of us does not happen to contain it
 * would throw away the researcher's work to tidy up a column.
 */
static void draft_refresh(struct view *v)
{
	uint32_t i, g, moved = 0, gone = 0;

	for (i = 0; i < v->n_decl; i++) {
		struct decl *d = &v->decl[i];

		decl_locate(v, d);
		if (d->at == KOF_BROKEN) {
			gone++;
			continue;
		}
		if (!d->at_mask)
			continue;
		if (d->mask != d->at_mask)
			moved++;
		d->mask = d->at_mask;
		snprintf(d->rgn, sizeof d->rgn, "%.23s", d->at_rgn);
		d->off_rgn = 0;
	}
	/*
	 * And the matchers follow, because a range is not an independent fact:
	 * it is the union of the regions its markers are in, which is how one
	 * gets built in the first place. Leaving them behind would move every
	 * string and still search the old place.
	 */
	for (g = 0; g < v->n_grp; g++) {
		uint32_t m = 0;

		for (i = 0; i < v->n_decl; i++)
			if (v->decl[i].grp & (1u << g))
				m |= v->decl[i].mask;
		if (m)
			v->grp[g].mask = m;
	}
	if (!moved && !gone)
		say_note(v, "Every marker is already in the region searched");
	else if (!gone)
		say_note(v, "Moved %u marker(s) to where they are",
			 moved);
	else
		say_note(v, "%u moved, %u not here - left as declared",
			 moved, gone);
}

/*
 * What the heuristic makes of this object.
 *
 * One place, because two would drift: the dashboard and the status line show
 * the same verdict and a reader who saw them disagree would have no way to tell
 * which was lying. Scored here rather than read back from the scan, because the
 * scan may have had the heuristic switched off, and a screen that showed
 * nothing then would be reporting the option rather than the object.
 *
 * Returns 0 when no model covers this format, which is not the same as a score
 * of zero and must not be shown as one.
 */
/*
 * What the heuristic made of this object.
 *
 * A read, not a computation. The engine scored it while it was scanning, on the
 * object it had in front of it, with facts a viewer cannot see - which unpacker
 * produced which child, and whether that unpacker was a packer or a container.
 * Everything this file needs is in the result it was handed.
 *
 * Returns 0 when the heuristic did not run or no model covers this format,
 * which is not the same as a score of zero and must not be shown as one.
 */
static int heur_of(const struct object *ob, struct kof_heur_facts *out,
		   int32_t *score, const char **guess)
{
	const struct kof_heur_model *hm = kof_heur_default();

	memset(out, 0, sizeof *out);
	out->format       = ob->ctx.format;
	out->anomalies    = ob->heur.heur_anomalies;
	out->flags        = ob->heur.heur_flags;
	*score = ob->heur.heur_score;
	*guess = "Unknown";
	if (!ob->heur.heur_scored)
		return 0;
	/*
	 * Re-run only to recover the WORD, which the result does not carry: the
	 * score is the engine's and is used as given, and this asks the same
	 * model the engine used which trace weighed most. Reading a model to
	 * name a number is not recomputing the number.
	 */
	{
		int32_t ignored = 0;

		kof_heur_score(hm, out, &ignored, guess);
	}
	return 1;
}

/* Would a scan report this object on the heuristic alone. */
static int heur_reports(const struct object *ob, int32_t *score,
			const char **guess)
{
	struct kof_heur_facts hf;

	if (!heur_of(ob, &hf, score, guess))
		return 0;
	return *score >= kof_heur_default()->bar_centinats;
}

/* ---- the disassembly panel ------------------------------------------------
 *
 * WHY IT IS A PANEL AND NOT A DIALOG.
 *
 * The question it answers is "what do these bytes do", and the bytes are on
 * screen already. A box over the top of them would hide the thing being asked
 * about and make the answer something to memorise before dismissing it; a strip
 * under the hex keeps both in view, and scrolling the hex scrolls the
 * disassembly with it. That is also why it has a close button of its own rather
 * than a key to press: it behaves like the panels around it.
 *
 * WHAT IT DECODES, AND THE ONE THING IT CANNOT KNOW.
 *
 * bddisasm needs to be told 32 or 64 bit, and the bytes never say. For an
 * object with a header the collector already worked it out and the panel starts
 * there. For raw bytes - a payload unwrapped out of an encoder, which is the
 * case this is most useful for - there is no header and no answer, so the
 * heading carries the mode and clicking it changes it. Guessing silently would
 * be worse than asking: the same bytes are valid in both modes and mean
 * different things, and a reader who cannot see which was assumed cannot tell.
 */
#define DIS_MIN_ROWS 4
#define DIS_MAX_INSN 16u        /* the longest x86 instruction */

/* The mode to start in: what the object says, or 64 when it says nothing. */
static int dis_default_bits(struct view *v)
{
	struct object *ob = cur_obj(v);

	/*
	 * A PAYLOAD'S WIDTH IS ITS OWN, not its parent's.
	 *
	 * A payload child has no format, so the arch test below cannot answer
	 * for it and the fallback would say 64 - and a 64-bit ELF routinely
	 * carries 32-bit Windows shellcode. Decoded at 64 the fourth byte of a
	 * textbook msf x86 prologue comes out "(data)", because `60` is PUSHAD
	 * in 32-bit mode and does not exist in 64-bit.
	 *
	 * Taken from the stub the payload starts with, since recognising the
	 * stub IS knowing which mode emitted it. Still a guess, and still
	 * overridable - the panel's own bit switch is right there.
	 */
	if (ob && ob->payload_of && ob->buf.p)
		return (int)sc_bits(ob->buf.p, (uint32_t)ob->buf.n, 64u);
	if (ob && ob->fmt) {
		if (ob->ctx.arch == KOF_ARCH_X86)
			return 32;
		if (ob->ctx.arch == KOF_ARCH_X86_64)
			return 64;
	}
	return 64;
}

/*
 * Gather up to n bytes of the region at `at` into buf, stopping at the end.
 *
 * Byte at a time through view_map, because a region is a list of extents and an
 * instruction may sit across the join between two of them. Reading the parent's
 * buffer directly would be faster and would decode bytes that are not adjacent
 * in this region at all.
 */
static unsigned dis_gather(struct view *v, uint64_t at, uint8_t *buf, unsigned n)
{
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	unsigned k = 0;

	if (!bp)
		return 0;
	while (k < n && at + k < v->rgn_len) {
		uint64_t fo = view_map(v, at + k, 0);

		if (fo >= bn)
			break;
		buf[k++] = bp[fo];
	}
	return k;
}

/*
 * Where the panel starts reading.
 *
 * A pinned range starts where it was pinned. An unpinned one follows the HEX
 * SELECTION when there is one, and the hex scroll when there is not - and the
 * selection has to win, because the two panes hold very different amounts. The
 * hex pane shows seventeen rows of sixteen bytes; the panel shows seventeen
 * INSTRUCTIONS, which is rarely more than sixty bytes. Starting both at the top
 * of the scroll meant selecting a byte anywhere below the first few hex rows
 * lit nothing here at all: the answer was real and off the bottom of the panel.
 */
/*
 * Where the panel reads from, settled once a frame before anything is drawn.
 *
 * TWO SEPARATE THINGS, and keeping them separate is the whole of it:
 *
 *   the WINDOW follows the hex scroll, always and exactly. Scrolling is a
 *   deliberate act and nothing may override it.
 *
 *   the HIGHLIGHT belongs to the BYTES, not to the window. It is drawn from
 *   sel_a/sel_b wherever those bytes happen to fall, so scrolling away hides it
 *   and scrolling back shows it again. Nothing clears it.
 *
 * On top of that, one event: a NEW selection made in the hex pane moves the
 * window once, so the reader sees what they just picked. After that the window
 * is the scroll's again.
 *
 * Two earlier rules each failed at one half. "The selection wins while it is on
 * the hex screen" kept the highlight and killed the scroll - the window stayed
 * pinned while the hex moved under it. "The selection wins if there is one" was
 * worse: a selection left over from an old drag pinned the window for good.
 * Neither separated the window from the highlight, which is what a selection in
 * any editor already does.
 */
/* How many bytes the hex pane is showing. The panel is a window inside this. */
static uint64_t dis_hex_shown(const struct view *v)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);

	return (uint64_t)(hex_last() - hex_top() + 1) * per;
}

/*
 * The furthest the panel may be scrolled inside the hex pane's range.
 *
 * THE PANEL IS A MAGNIFIER, NOT A SECOND VIEW OF THE FILE. The hex pane shows
 * about 270 bytes and the panel about 60, so the panel can only ever be looking
 * at part of what the hex shows - and the part is the reader's to choose. What
 * it must never do is show bytes the hex pane is not showing: two panes claiming
 * to be in step while looking at different places is worse than one pane.
 *
 * So the offset is bounded at both ends: zero is the top of the hex view, and
 * the maximum is as far down as it can go while its last row is still inside it.
 */
/*
 * THE SPAN THE CONTROL USES, AND WHY IT IS NOT THE MEASURED ONE.
 *
 * How many bytes the rows actually cover is known only after decoding them, and
 * it changes as the panel scrolls: seventeen instructions might be 52 bytes here
 * and 68 there. Feeding that into the scrollbar and into the clamp made both
 * unstable - the thumb grew and shrank while scrolling, the maximum offset moved
 * under the offset, and the offset was pushed back down by the clamp on the next
 * frame. That is what "the thumb stretches and the position slides back" is.
 *
 * A control has to be steady to be usable, so it is sized from the ROWS instead:
 * four bytes per row, which is close to the average x86 instruction and, more to
 * the point, never changes. The panel may reach a few bytes further or less than
 * the nominal; that is invisible, while a jumping scrollbar is not.
 *
 * The measured value is still kept - dis_span_bytes - and still used for the
 * bracket in the hex pane, which is a statement about what IS shown rather than
 * a control.
 */
static uint64_t dis_span_of(const struct view *v)
{
	int rows = hex_bot() - dis_top() + 1;

	(void)v;
	return rows > 0 ? (uint64_t)rows * 4u : 64u;
}

/*
 * THE LATEST START THAT STILL FILLS THE PANEL, as a region offset.
 *
 * The clamp used to approximate this - stop `rows` bytes before the end, one
 * byte a row - and that reaches the last byte but overshoots when the
 * instructions are longer than a byte: `rows` instructions from `rgn_len - rows`
 * run past the end and the surplus rows come back blank. The exact answer needs
 * the instruction lengths, so it is decoded: the last `rows` instructions span
 * at most rows*DIS_MAX_INSN bytes, so decoding from there forward and keeping
 * the start of the one that leaves exactly `rows` behind is the start from which
 * the last row holds the last instruction and no row is blank.
 *
 * Bounded whatever the region size, because only that trailing window is walked.
 */
static uint64_t dis_sync(struct view *v, uint64_t want);
static unsigned dis_format(struct view *v, uint64_t *at, char *line, size_t cap,
			   uint8_t *bytes_out, unsigned *ix_len_out,
			   int *ok_out, char *text_out, size_t text_cap);

static uint64_t dis_last_start(struct view *v, uint64_t lo, uint64_t end,
			       unsigned rows)
{
	uint64_t back = (uint64_t)rows * DIS_MAX_INSN;
	uint64_t at = end > lo + back ? dis_sync(v, end - back) : lo;
	uint64_t ring[256];
	unsigned n = 0, cap = rows < 256u ? rows : 256u;

	if (!cap)
		return lo;
	if (at < lo)                    /* dis_sync can round to before lo */
		at = lo;
	while (at < end) {
		char line[120];
		uint64_t at0 = at;

		ring[n % cap] = at0;
		n++;
		if (!dis_format(v, &at, line, sizeof line, NULL, NULL, NULL,
				NULL, 0) || at <= at0)
			break;
	}
	/* Fewer than a panelful in the trailing window: it all fits, so the
	 * window can start at the range's beginning. */
	if (n <= cap)
		return lo;
	return ring[n % cap];   /* the oldest kept - exactly `rows` from the end */
}

/* THE LATEST START THAT STILL FILLS THE PANEL over the whole region. */
static uint64_t dis_full_start(struct view *v, unsigned rows)
{
	return dis_last_start(v, 0, v->rgn_len, rows);
}

static int64_t dis_max_bias(struct view *v)
{
	int nr = hex_bot() - dis_top() + 1;
	uint64_t shown, win, full;
	int64_t hi;

	if (nr < 1)
		nr = 1;

	/*
	 * A PINNED RANGE SCROLLS WITHIN ITSELF, to the EXACT last window.
	 *
	 * "View disassembly" on a hex selection pins the panel to that run, and
	 * the run can be far longer than the rows there are to show it - select
	 * a whole region and it is the whole region. The bound cannot be the hex
	 * pane's window, which a pinned panel does not follow; it is the start of
	 * the last window inside the pinned run, decoded rather than guessed the
	 * way dis_full_start does for the whole region. Guessing it as
	 * dis_len - span was the same span overshoot the region bound below used
	 * to have: for a run of one-byte instructions span is far more than the
	 * bytes a panelful shows, so the scroll stopped a span short and the tail
	 * of the run - the last instructions of win_x64_raw among them - could
	 * not be reached. Decoded, a run of one-byte instructions reaches its
	 * tail and a run of long ones leaves no blank row past the end.
	 */
	if (v->dis_len != KOF_BROKEN) {
		uint64_t end = v->dis_at + v->dis_len;

		if (end > v->rgn_len)
			end = v->rgn_len;
		full = dis_last_start(v, v->dis_at, end, (unsigned)nr);
		return full > v->dis_at ? (int64_t)(full - v->dis_at) : 0;
	}

	/*
	 * The panel inside the hex pane's window, bounded at ONE BYTE PER ROW -
	 * the least a row can show - not at span's nominal four. Span, being so
	 * much larger than the bytes one-byte shellcode actually shows, stopped
	 * the scroll a whole span short of where the region bound below wanted
	 * it, so the two disagreed and the smaller (this one) won and cut the
	 * tail off.
	 */
	shown = dis_hex_shown(v);
	win = (uint64_t)nr;
	hi = shown > win ? (int64_t)(shown - win) : 0;

	/*
	 * AND NOT PAST THE REGION'S LAST WINDOW, decoded exactly by
	 * dis_full_start so the final row holds the final instruction and no row
	 * comes back blank. Below rgn_at it means the whole region already fits
	 * from where the panel is; otherwise its offset from rgn_at is the most
	 * the panel may be scrolled.
	 */
	full = dis_full_start(v, (unsigned)nr);
	if (full <= v->rgn_at)
		hi = 0;
	else if (hi > (int64_t)(full - v->rgn_at))
		hi = (int64_t)(full - v->rgn_at);
	return hi;
}

static void dis_follow_hex(struct view *v)
{
	int64_t at, hi;

	/*
	 * A pinned panel does not FOLLOW the hex pane, but its offset still has
	 * to be clamped - the rows it has change with the terminal's height, so
	 * a bias that was legal a frame ago need not be now. Only the second
	 * half below is skipped: where the window starts is dis_at, not the hex
	 * scroll. See dis_start.
	 */
	if (v->dis_len != KOF_BROKEN) {
		hi = dis_max_bias(v);
		if (v->dis_bias < 0)
			v->dis_bias = 0;
		if (v->dis_bias > hi)
			v->dis_bias = hi;
		return;
	}

	/* Kept inside the hex pane's range, every frame - the range changes with
	 * the terminal's height and with how much the last instruction covered,
	 * so a bias that was legal a frame ago need not be now. */
	hi = dis_max_bias(v);
	if (v->dis_bias < 0)
		v->dis_bias = 0;
	if (v->dis_bias > hi)
		v->dis_bias = hi;

	/*
	 * LOCKED TO THE SCROLL, OFFSET BY THE SELECTION.
	 *
	 * See dis_bias. The window is the scroll plus a constant, so a notch of
	 * scroll moves this panel by a notch - always, selection or not - and
	 * the constant is what keeps a selected run on these rows rather than
	 * sixty bytes above them.
	 */
	at = (int64_t)v->rgn_at + v->dis_bias;
	if (at < 0)
		at = 0;
	if ((uint64_t)at > v->rgn_len)
		at = (int64_t)v->rgn_len;
	v->dis_follow = (uint64_t)at;
}

/*
 * A new hex selection: set the bias so the run lands on these rows.
 *
 * Called where the selection is made rather than tested for every frame,
 * because it is an EVENT. Testing it per frame is what made the earlier
 * versions states rather than events, and a state cannot be told from a
 * leftover.
 */
static void dis_bias_to_sel(struct view *v)
{
	uint64_t lo;

	if (!v->dis_open || v->dis_len != KOF_BROKEN)
		return;
	if (v->sel_a == KOF_BROKEN) {
		v->dis_bias = 0;                /* nothing picked: plain sync */
		return;
	}
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	/* A little before it, so the run has something above it to be read
	 * against - an instruction on the first row with nothing before it
	 * reads as the start of something, and it usually is not. */
	if (lo > 16u)
		lo -= 16u;
	else
		lo = 0;
	v->dis_bias = (int64_t)lo - (int64_t)v->rgn_at;
	/*
	 * Clamped here as well as per frame, because a selection made near the
	 * bottom of the hex view would otherwise ask the panel to start past the
	 * end of it - and the reader would be looking at instructions the hex
	 * pane above is not showing.
	 */
	if (v->dis_bias < 0)
		v->dis_bias = 0;
	if (v->dis_bias > dis_max_bias(v))
		v->dis_bias = dis_max_bias(v);
}

static uint64_t dis_start(const struct view *v)
{
	/* Pinned: the run's start plus however far it has been scrolled. The
	 * bias is clamped to the run by dis_follow_hex, so this cannot leave
	 * it. */
	return v->dis_len != KOF_BROKEN
	       ? v->dis_at + (uint64_t)(v->dis_bias > 0 ? v->dis_bias : 0)
	       : v->dis_follow;
}

/*
 * Point the HEX selection at whatever the panel's line selection covers.
 *
 * One selection, seen two ways: the bytes light up in the hex pane, the
 * instructions light up here, and every menu item that already works on a byte
 * range works on this one. The alternative was a second selection with its own
 * copy of copy, declare and find hanging off it.
 */
/* The selection in reading order: (at0,c0) before (at1,c1). */
static void dis_span(const struct view *v, uint64_t *at0, int *c0,
		     uint64_t *at1, int *c1)
{
	uint64_t aa = v->dis_a_at, ba = v->dis_b_at;
	int ac = v->dis_ac, bc = v->dis_bc;

	if (ba < aa || (ba == aa && bc < ac)) {
		uint64_t t = aa; aa = ba; ba = t;
		{ int u = ac; ac = bc; bc = u; }
	}
	*at0 = aa; *c0 = ac; *at1 = ba; *c1 = bc;
}

/*
 * Which columns of row `idx` are selected: [*from, *to), empty when none.
 *
 * The middle rows of a multi-row selection are taken whole, which is what a
 * text selection does everywhere - the first row from the anchor to its end,
 * the last from its start to the cursor.
 */
/*
 * MATCHED BY OVERLAP, NOT BY EQUALITY, because disassembly does not
 * self-synchronise.
 *
 * The selection remembers the offset an instruction STARTED at. Read the same
 * bytes from somewhere else - which is what scrolling does - and the boundaries
 * fall differently: the remembered offset can land in the middle of an
 * instruction, and then no row's start equals it and nothing is lit. That is the
 * highlight "disappearing on scroll", and it is not about the window at all.
 *
 * So a row is selected when its bytes OVERLAP the selected range. The columns
 * are still exact at the two ends: the row holding the first selected byte
 * starts at the anchor's column, the row holding the last ends at the cursor's,
 * and every row between is whole.
 */
/*
 * Does the HEX pane's selection cover the instruction at [at, at+alen)?
 *
 * One function because three places ask it and they must agree: the painter
 * marks the whole row on it, Copy takes the whole row on it, and the panel's
 * right-click leaves the selection alone on it. They were not one function, and
 * the copy simply did not know about this kind of selection - so a range picked
 * in the hex pane lit up here and then copied nothing.
 */
/* Is there a selection at all, and was it made in the hex pane? */
static int dis_hex_sel(const struct view *v)
{
	return v->sel_a != KOF_BROKEN && !v->sel_from_dis;
}

static int dis_hex_marks(const struct view *v, uint64_t at, uint64_t alen)
{
	uint64_t lo, hi;

	if (!dis_hex_sel(v))
		return 0;
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	return at + alen > lo && at <= hi;
}

static int dis_cols(const struct view *v, uint64_t at, uint64_t alen, int len,
		    int *from, int *to)
{
	uint64_t a0, a1;
	int c0, c1;

	*from = *to = 0;
	if (!v->dis_have || !alen)
		return 0;
	dis_span(v, &a0, &c0, &a1, &c1);
	if (at + alen <= a0 || at > a1)
		return 0;               /* no bytes in common */
	*from = (at <= a0 && a0 < at + alen) ? c0 : 0;
	*to   = (at <= a1 && a1 < at + alen) ? c1 + 1 : len;
	if (*from > len)
		*from = len;
	if (*to > len)
		*to = len;
	return *to > *from;
}

static void dis_sync_bytes(struct view *v)
{
	uint64_t a, b;
	int c0, c1, k;

	if (!v->dis_have || v->dis_lines <= 0)
		return;
	dis_span(v, &a, &c0, &b, &c1);
	/*
	 * The bytes of the instructions the selection TOUCHES, whole.
	 *
	 * A character selection can stop halfway through a mnemonic, and half a
	 * mnemonic has no bytes. What the byte range is for is Copy hex and
	 * Declare as hex, and both of those want instructions - so the range is
	 * rounded out to the ones the text sits in.
	 */
	v->sel_a = a;
	v->sel_b = b;
	/* To the END of the instruction the selection stops in: what the byte
	 * range is for is Copy hex and Declare as hex, and both want whole
	 * instructions. */
	for (k = 0; k < v->dis_lines; k++)
		if (v->dis_line_at[k] == b) {
			v->sel_b = b + v->dis_line_len[k] - 1u;
			break;
		}
	v->sel_from_dis = 1;
}


/*
 * How far back to look for an instruction boundary. See dis_sync.
 *
 * Sixty-four bytes is far more than x86 needs: a stream re-synchronises within a
 * handful of instructions, and the longest instruction there is is fifteen
 * bytes. It is a window rather than the whole region because the region can be
 * megabytes and this runs once a frame.
 */
#define DIS_RESYNC 64u

/*
 * THE FIRST INSTRUCTION BOUNDARY AT OR AFTER `want`.
 *
 * x86 IS NOT SELF-DELIMITING, and the panel's start moves in bytes: the scroll
 * offset is a byte count and the hex pane's rows are sixteen bytes, so where the
 * panel begins is almost never where an instruction begins. Decoding from there
 * reads the middle of one instruction as the start of another and produces a
 * listing that does not exist - measured on x86_clear, scrolling turned
 *
 *     00000057  31 db     XOR ebx, ebx        (real, and ndisasm agrees)
 *
 * into
 *
 *     00000058  db f7     FCOMI st0, st7      (not in the file at all)
 *
 * and further down produced a six-byte AND that swallowed the `MOV ecx, esp` at
 * 0x72 - a real instruction that then had no row of its own.
 *
 * So the start is re-synchronised: decode forward from a little way back and
 * take the first boundary that reaches `want`. This is what a disassembler does
 * and it is why the answer is stable - the stream converges on the true
 * boundaries within a few instructions whatever it is entered at.
 */
/*
 * ONE INSTRUCTION, AS A PLAIN LINE: "<offset>  <bytes>  <mnemonic>".
 *
 * The exact text the panel shows and the clipboard gets, from ONE place, so the
 * two cannot drift - the draw builds its rows through this and so does Copy, and
 * "the same string on screen and in the clipboard" is a property of there being
 * one function rather than a promise two blocks of code keep.
 *
 * It advances *at by the instruction's length and returns that length, so a
 * caller walking a range needs nothing else. Data that will not decode is one
 * byte named "(data)".
 *
 * The out-parameters are for the DRAW, which re-emits the line coloured and so
 * needs the pieces: the raw bytes, how many of them the row shows, whether the
 * mnemonic decoded, and the mnemonic on its own. Copy passes NULL for all of
 * them - it wants the flat line and nothing else.
 */
static unsigned dis_format(struct view *v, uint64_t *at, char *line, size_t cap,
			   uint8_t *bytes_out, unsigned *ix_len_out,
			   int *ok_out, char *text_out, size_t text_cap)
{
	uint8_t buf[DIS_MAX_INSN];
	INSTRUX ix;
	char text[ND_MIN_BUF_SIZE];
	unsigned got, j, w;

	if (ix_len_out)
		*ix_len_out = 1;
	if (ok_out)
		*ok_out = 0;
	got = dis_gather(v, *at, buf, DIS_MAX_INSN);
	if (!got)
		return 0;
	if (bytes_out)
		memcpy(bytes_out, buf, DIS_MAX_INSN);
	w = (unsigned)snprintf(line, cap, "%08llx  ",
			       (unsigned long long)view_map(v, *at, 0));
	if (!ND_SUCCESS(NdDecodeEx(&ix, buf, got,
				   v->dis_bits == 32 ? ND_CODE_32 : ND_CODE_64,
				   v->dis_bits == 32 ? ND_DATA_32
						     : ND_DATA_64))) {
		snprintf(line + w, cap - w, "%02x%*s (data)", buf[0], 19, "");
		(*at)++;
		return 1;
	}
	if (ix_len_out)
		*ix_len_out = ix.Length < 7u ? ix.Length : 7u;
	if (ok_out)
		*ok_out = 1;
	for (j = 0; j < ix.Length && j < 7u && w + 3 < cap; j++)
		w += (unsigned)snprintf(line + w, cap - w, "%02x ", buf[j]);
	for (; j < 7u && w + 3 < cap; j++)
		w += (unsigned)snprintf(line + w, cap - w, "   ");
	NdToText(&ix, view_map(v, *at, 0), sizeof text, text);
	dis_shorten(text);
	snprintf(line + w, cap - w, "%s", text);
	if (text_out)
		snprintf(text_out, text_cap, "%s", text);
	*at += ix.Length;
	return ix.Length;
}

static uint64_t dis_sync(struct view *v, uint64_t want)
{
	uint64_t at;
	unsigned guard;

	if (!want)
		return 0;
	at = want > DIS_RESYNC ? want - DIS_RESYNC : 0;

	for (guard = 0; at < want && guard < DIS_RESYNC; guard++) {
		uint8_t buf[DIS_MAX_INSN];
		INSTRUX ix;
		unsigned got = dis_gather(v, at, buf, DIS_MAX_INSN);

		if (!got)
			return want;            /* nothing to read: leave it */
		if (ND_SUCCESS(NdDecodeEx(&ix, buf, got,
					  v->dis_bits == 32 ? ND_CODE_32
							    : ND_CODE_64,
					  v->dis_bits == 32 ? ND_DATA_32
							    : ND_DATA_64)) &&
		    ix.Length)
			at += ix.Length;
		else
			at += 1u;               /* data: one byte, as the panel does */
	}
	/* At or past `want` - never before it, so the panel does not silently
	 * show bytes the scroll had already left behind. */
	return at;
}

static void draw_disasm(struct out *o, struct view *v)
{
	int head = dis_top() - 1;
	int row;
	int col = TREE_W + 3;
	uint64_t at = dis_sync(v, dis_start(v));
	uint64_t end = v->dis_len == KOF_BROKEN ? v->rgn_len
					        : v->dis_at + v->dis_len;
	char note[32];

	if (!g_disasm_rows)
		return;
	if (end > v->rgn_len)
		end = v->rgn_len;

	/*
	 * The heading, with the two controls a reader needs and nothing else:
	 * which mode the bytes are being read in, and a way to close.
	 */
	out_at(o, head, col);
	/*
	 * "x86" and "x64", not "x32" and "x64".
	 *
	 * The width in bits is what the field holds and printing it directly was
	 * the obvious thing, but nobody calls 32-bit Intel "x32" - the engine
	 * itself writes ELF-x86 in every finding, and a panel using a second name
	 * for the same architecture is a name a reader has to translate. x32 is
	 * also a real and different thing (the ILP32 ABI on amd64), so it is not
	 * merely unconventional here, it is taken.
	 */
	snprintf(note, sizeof note, " Disassembly  [%s] ",
		 v->dis_bits == 32 ? "x86" : "x64");
	/* The panel's own palette here too, so nothing in this strip is yellow -
	 * the hex pane above is largely yellow already. */
	out_fmt(o, A_DIM "--" A_OFF A_D_MNEM "%s" A_OFF, note);
	if (v->dis_len != KOF_BROKEN)
		out_fmt(o, A_DIM " selection %llu B " A_OFF,
			(unsigned long long)v->dis_len);
	out_str(o, A_DIM);
	{
		int used = col + 2 + (int)strlen(note) +
			   (v->dis_len != KOF_BROKEN ? 20 : 0);
		int k;

		for (k = used; k < g_cols - 4; k++)
			out_str(o, "-");
	}
	out_str(o, A_OFF);
	out_at(o, head, g_cols - 3);
	out_str(o, A_D_KEY "[x]" A_OFF);

	v->dis_lines = 0;
	for (row = dis_top(); row <= hex_bot(); row++) {
		uint8_t buf[DIS_MAX_INSN];
		char text[ND_MIN_BUF_SIZE];
		char line[120];
		uint64_t at0 = at;              /* before the length is added */
		int from, to, len;
		unsigned ix_len = 1;            /* bytes this row stands for */
		int ok_decode = 0;

		out_at(o, row, col);
		if (at >= end) {
			out_str(o, "\033[K");
			continue;
		}
		/*
		 * Built by dis_format, coloured below. There is one formatter so
		 * the clipboard cannot get a line the screen never showed - see
		 * dis_format and dis_copy.
		 */
		if (!dis_format(v, &at, line, sizeof line, buf, &ix_len,
				&ok_decode, text, sizeof text)) {
			out_str(o, "\033[K");
			continue;
		}
		if (v->dis_lines < (int)(sizeof v->dis_line /
					 sizeof v->dis_line[0])) {
			v->dis_line_at[v->dis_lines]  = at0;
			v->dis_line_len[v->dis_lines] = at - at0;
			snprintf(v->dis_line[v->dis_lines++],
				 sizeof v->dis_line[0], "%s", line);
		}
		/*
		 * Three things can mark a row, drawn in this order.
		 *
		 * The TEXT SELECTION is characters and is drawn as a span, so it
		 * has to be written in three pieces. The HEX selection marks
		 * whole instructions and in two colours, which is the one thing
		 * the hex pane above cannot show: a marker is a run of bytes,
		 * and a run that starts or ends in the MIDDLE of an instruction
		 * is fragile - the same source rebuilt with another register
		 * allocation moves those bytes and the signature quietly stops
		 * matching. Wholly covered is one colour, cut is another.
		 */
		/*
		 * ONE MARK, AND IT IS THE READER'S OWN SELECTION.
		 *
		 * A second marking - the instructions a HEX selection covered,
		 * in two colours for whole and cut - was built and taken back
		 * out. It repeated what the hex pane already shows one row up,
		 * it needed a colour that clashed with none of three others, and
		 * keeping it visible meant holding this panel still while the
		 * hex scrolled under it. Three costs for a fact the reader could
		 * already see. What is marked here is what was dragged out here.
		 */
		len = (int)strlen(line);
		/*
		 * TWO WAYS TO DRAW A ROW, and which one is used depends on
		 * whether the reader has a TEXT selection over it.
		 *
		 * A text selection is characters: it can start mid-mnemonic, so
		 * it is drawn as three flat runs with a background on the
		 * middle one, and the syntax colours give way. Anything else
		 * gets painted properly - offset, bytes, mnemonic, operands -
		 * with the bytes a HEX selection covers lit one at a time.
		 *
		 * Giving way rather than combining: a background plus six
		 * foregrounds is a row nobody can read, and while a reader is
		 * dragging text out, what they want to see is the extent of
		 * what they have got.
		 */
		if (dis_cols(v, at0, at - at0, len, &from, &to)) {
			out_add(o, line, (size_t)from);
			out_str(o, A_SELB);
			out_add(o, line + from, (size_t)(to - from));
			out_str(o, A_OFF);
			out_str(o, line + to);
			out_str(o, "\033[K");
		} else {
			/*
			 * THE WHOLE LINE, when the hex selection touches this
			 * instruction.
			 *
			 * Marking only the covered BYTES was tried and is too
			 * quiet: the bytes are two hex digits in the middle of
			 * a row and the eye does not find them, which is the
			 * opposite of what a highlight is for. An instruction
			 * either is part of what the reader picked or it is
			 * not, and the row is the unit that says so.
			 */
			int marked = dis_hex_marks(v, at0, at - at0);
			unsigned k;
			if (marked) {
				out_str(o, A_D_SEL);
				out_fmt(o, "%s" A_OFF "\033[K", line);
			} else {
				out_str(o, A_D_OFF);
				out_add(o, line, 8);
				out_str(o, A_OFF "  ");
				for (k = 0; k < 7u; k++) {
					if (k < ix_len) {
						out_str(o, A_D_BYTE);
						out_fmt(o, "%02x", buf[k]);
						out_str(o, A_OFF " ");
					} else {
						out_str(o, "   ");
					}
				}
				if (ok_decode)
					dis_paint(o, text);
				else
					out_str(o, A_DIM "(data)" A_OFF);
				out_str(o, "\033[K");
			}
		}
	}
	/*
	 * THE PANEL'S OWN SCROLLBAR, and what it is a bar OVER.
	 *
	 * Not the file: the hex pane's range. The panel is a window inside what
	 * the hex is showing - about sixty bytes of about two hundred and
	 * seventy - and until this bar was here that was invisible: a reader who
	 * selected bytes low in the hex pane saw nothing light up and had no way
	 * to know the panel simply did not reach that far. The bar says how much
	 * of the hex view is being disassembled and where in it the rows are, and
	 * it can be dragged.
	 *
	 * Drawn only when there is somewhere to scroll to. A full-length thumb
	 * on a panel that already covers everything is a control that does
	 * nothing.
	 */
	/*
	 * THE PANEL'S SCROLLBAR.
	 *
	 * A bar over the hex pane's range rather than over the file: the panel
	 * is a window inside what the hex is showing - about sixty bytes of
	 * nearly three hundred - and without this bar that was invisible, so a
	 * reader who selected bytes low in the hex pane saw nothing light up and
	 * had no way to know the panel did not reach that far.
	 *
	 * The TOTAL is the range the offset can actually take, not the hex
	 * pane's whole span. Those differ near the end of a region, where the
	 * hex pane draws rows past the last byte: measured against the hex span
	 * the thumb stopped short of the bottom with the panel already as far
	 * down as it goes, which reads as a bar that can still be dragged.
	 *
	 * Drawn through the shared scrollbar, so this bar looks like every
	 * other one - see the note there.
	 */
	if (dis_max_bias(v) > 0)
		scrollbar(o, g_cols, dis_top(), hex_bot(),
			  (uint64_t)v->dis_bias,
			  (uint64_t)dis_max_bias(v) + dis_span_of(v),
			  dis_span_of(v));
}

/*
 * Open, close, and how many rows it takes.
 *
 * Half of what the hex column has, so both halves stay usable - a panel that
 * took most of the screen would answer the question by hiding the evidence -
 * and never fewer than DIS_MIN_ROWS, because a panel too short to hold an
 * instruction is not a panel.
 */
static void dis_toggle(struct view *v, uint64_t at, uint64_t len)
{
	if (v->dis_open && len == KOF_BROKEN) {
		v->dis_open = 0;
		g_disasm_rows = 0;
		v->dis_have = 0;
		return;
	}
	if (!v->dis_open) {
		v->dis_bits = dis_default_bits(v);
		/*
		 * Nothing selected, spelled out. The struct is cleared to zero
		 * on a file switch and zero is a valid ROW, so a panel opened
		 * after one would come up with its first line already lit.
		 */
		v->dis_have = 0;
		v->dis_dragging = 0;
	}
	/*
	 * Opened from the menu with nothing selected, it moves to CODE.
	 *
	 * Headers, data and the unclaimed tail all decode into something -
	 * every byte does - and none of it means anything. A reader who opens a
	 * disassembly wants the code, so the panel goes and gets it rather than
	 * showing whichever region the tree happened to be on. Moving the TREE
	 * rather than pointing the panel somewhere else keeps the two in step:
	 * the hex shows the same bytes, which is the whole reason the panel is
	 * under it.
	 *
	 * Only on the way open, and only when nothing was selected: a reader who
	 * picked a range meant that range, and one who is already reading a
	 * region did not ask to be moved.
	 */
	if (!v->dis_open && len == KOF_BROKEN) {
		uint32_t k;

		for (k = 0; k < v->n_node; k++)
			if (v->node[k].obj == v->node[v->sel_node].obj &&
			    v->node[k].mask &&
			    !strcmp(v->node[k].label, "CODE")) {
				goto_node(v, k);
				break;
			}
	}
	v->dis_open = 1;
	v->dis_at = at;
	v->dis_len = len;
	/* Somewhere sane for the first frame; dis_follow_hex settles it from
	 * there. */
	v->dis_follow = len == KOF_BROKEN ? v->rgn_at : at;
	v->dis_bias = 0;
	dis_bias_to_sel(v);
}

/*
 * Bring every marker's range back in step with the matchers that search it.
 *
 * Derived state, so it is recomputed from what the draft currently holds
 * rather than updated at each of the half dozen places that can change a
 * matcher's range or take a matcher away. Run from the draw, which is the one
 * point every one of those passes through, and cheap enough to: a draft holds
 * at most MAX_DECL markers and a handful of matchers, and the search below is
 * reached only when the answer actually changed.
 */
static void decl_sync_ranges(struct view *v)
{
	uint32_t i;

	for (i = 0; i < v->n_decl; i++) {
		struct decl *d = &v->decl[i];
		uint32_t m = 0, g;

		for (g = 0; g < v->n_grp; g++)
			if (d->grp & (1u << g))
				m |= v->grp[g].mask;
		/* Searched by nothing: it falls back to where its bytes came
		 * from, and a marker read out of a source file has no such
		 * place - which is the dash the column shows. */
		if (!m)
			m = d->mask0;
		if (m == d->mask)
			continue;
		d->mask = m;
		if (m)
			rng_name_of(v->obj[d->obj < v->n_obj ? d->obj : 0].fmt,
				    m, d->rgn, sizeof d->rgn);
		else
			snprintf(d->rgn, sizeof d->rgn, "-");
		/* The range decides which occurrence the row reports, so the
		 * marker has to be found again under the new one. */
		decl_locate(v, d);
	}
}

static void draw_decl(struct out *o, struct view *v)
{
	int top = decl_top();
	int r = 0;
	uint32_t g, i;
	int c;

	decl_sync_ranges(v);

	/*
	 * Rows that stop being drawn are erased at the end, not all of them at
	 * the start.
	 *
	 * Every row this paints already clears itself to the end of the line,
	 * so erasing the whole area up front only mattered for the rows that
	 * fall off when the draft shrinks - and it cost a visible flash of an
	 * empty panel on any terminal without synchronized output, which is
	 * most of them. The flash showed up as the panel blinking on a click
	 * that changed nothing but the highlighted row.
	 */

	/* ---- what the module declares ---- */
	row_start(o, top, 1);
	c = 2 + (int)o->col_hint;
	out_fmt(o, A_DIM " Family " A_OFF "%s[", v->edit == 1 ? A_SEL : A_ID);
	field_draw(o, v->family, v->caret, &v->fam_off,
		   v->edit == 1 ? 24 : (int)strlen(v->family[0] ? v->family
								: "?"),
		   v->edit == 1, "?", v->field_all);
	out_str(o, "]" A_OFF);
	v->f_c0 = c; v->f_c1 = (int)o->col_hint;

	c = 2 + (int)o->col_hint;
	out_fmt(o, A_DIM "  Type " A_OFF A_ID "[%s]" A_OFF,
		maltype_word[v->maltype % MALTYPE_N]);
	v->t_c0 = c; v->t_c1 = (int)o->col_hint;

	c = 2 + (int)o->col_hint;
	/* Disabled keeps the background and loses contrast, it does not lose the
	 * text - 100;90 is bright black on bright black, the same colour twice,
	 * which is a grey block where a label should be. */
	out_fmt(o, "  " A_ID "[+ Option]" A_OFF);
	v->o_c0 = c; v->o_c1 = (int)o->col_hint;

	{
		/*
		 * Generate, or Save and Save As.
		 *
		 * A draft with no file behind it is being written; one loaded
		 * from a file is being edited, and the two want different
		 * words. Save As stays out of reach while nothing about the
		 * patterns has changed - a second file holding the same
		 * markers is a duplicate, and duplicates are made by accident
		 * rather than on purpose.
		 */
		const char *why = draft_missing(v);
		int near = 0;
		const char *dup = why ? NULL : draft_dup(v, &near);
		int changed = draft_dirty(v);

		c = 2 + (int)o->col_hint;
		if (!v->gen_path[0]) {
			out_fmt(o, "  %s[ Generate ]" A_OFF,
				save_ok(v) ? "\033[42;30m" : "\033[47;90m");
			v->g_c0 = c; v->g_c1 = (int)o->col_hint;
			v->sv_c0 = v->sv_c1 = -1;
		} else {
			out_fmt(o, "  %s[ Save ]" A_OFF,
				save_ok(v) ? "\033[42;30m" : "\033[47;90m");
			v->g_c0 = c; v->g_c1 = (int)o->col_hint;
			c = 2 + (int)o->col_hint;
			out_fmt(o, "  %s[ Save As ]" A_OFF,
				save_as_ok(v) ? "\033[42;30m"
					      : "\033[47;90m");
			v->sv_c0 = c; v->sv_c1 = (int)o->col_hint;
		}
		/*
		 * What is wrong, what is missing, what would be a duplicate and
		 * where this draft lives all moved to the status line.
		 *
		 * They are a running commentary on the draft, and that belongs
		 * where the tool's other running commentary is. Beside the
		 * button they pushed the controls sideways as they changed
		 * length, on the row that already carries every declaration.
		 */
		(void)why; (void)dup; (void)near; (void)changed;
	}

	/* No label: the box says what it is, and the row is already a line of
	 * labels. */
	out_str(o, "  ");
	c = 1 + (int)o->col_hint;
	{
		/*
		 * As wide as the row has left, and scrolled within that.
		 *
		 * A fixed width would either waste the space on a wide terminal
		 * or cut the text short on a narrow one; what is actually
		 * available is known here and nowhere else.
		 */
		size_t len = strlen(v->note);
		/* Less what the New button needs at the right hand end: the
		 * note takes what is left of the row, and something else now
		 * has the end of it. */
		int room = g_cols - c - 3 - NEW_BTN_W;
		uint32_t off;

		if (room < 8)
			room = 8;
		(void)len; (void)off;
		out_fmt(o, "%s[", v->edit == 501 ? A_SEL : A_DIM);
		field_draw(o, v->note, v->caret, &v->note_off, room,
			   v->edit == 501, "Comment...", v->field_all);
		out_str(o, "]" A_OFF);
	}
	v->nt_c0 = c; v->nt_c1 = (int)o->col_hint;

	/*
	 * THROW THE DRAFT AWAY, at the far right of the row.
	 *
	 * Opening a signature to look at it LOADS it into this panel - that is
	 * the point of the panel - and there was no way back to an empty one
	 * short of leaving the program. A rule examined because it was skipped,
	 * or because it did not match, is exactly the case where the next thing
	 * somebody wants is a blank sheet.
	 *
	 * At the far end rather than beside Save: green is what the two buttons
	 * that write a file wear, this one throws the panel away, and a discard
	 * next to a commit is how a misclick happens.
	 */
	out_at(o, decl_top(), g_cols - NEW_BTN_W + 1);
	v->nw_c0 = g_cols - NEW_BTN_W + 1;
	out_fmt(o, " %s[ Discard ]" A_OFF,
		v->n_decl || v->family[0] ? A_ID : "\033[47;90m");
	v->nw_c1 = g_cols;


	/* The optional declarations, one per row, each removable. */
	for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
		char val[40];
		int y;

		if (!v->opt_on[i])
			continue;
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		y = PR(r);
		r++;
		if (i == OPT_ARCH)
			snprintf(val, sizeof val, "%s",
				 arch_word[v->opt_val[i] < ARCH_N
					   ? v->opt_val[i] : 0].word);
		else if (i == OPT_SUBTYPE)
			snprintf(val, sizeof val, "%s",
				 kof_inspect_subtype_name(
					 cur_obj(v)->ctx.format,
					 (uint8_t)v->opt_val[i])
				 ? kof_inspect_subtype_name(
					   cur_obj(v)->ctx.format,
					   (uint8_t)v->opt_val[i]) : "?");
		else
			snprintf(val, sizeof val, "%llu",
				 (unsigned long long)v->opt_val[i]);
		row_start(o, y, 1);
		out_fmt(o, "   %s%-20s" A_OFF " ", A_DIM, opt_word[i]);
		v->opt_c0[i] = 1 + (int)o->col_hint;
		if (v->edit == 200 + (int)i) {
			out_str(o, A_SEL);
			field_draw(o, v->num, v->caret, &v->num_off, 18, 1, "", v->field_all);
			out_str(o, A_OFF);
		} else {
			out_fmt(o, "%s%s" A_OFF, A_ID, val);
		}
		v->opt_c1[i] = (int)o->col_hint;
		out_at(o, y, g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
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
	if (PR_VIS(r)) {
		uint32_t rm[2 * MAX_GROUP];
		int ru[2 * MAX_GROUP];
		uint32_t nr = rng_all(v, rm, ru, 2u * MAX_GROUP), k;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Scan ranges " A_OFF);
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
			out_str(o, A_DIM " none yet" A_OFF);
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
			out_fmt(o, "\033[100;97m[+ Scan range]" A_OFF);
			v->rga_c0 = c0;
			v->rga_c1 = o->col_base + (int)o->col_hint - 1;
		}
	}
	r++;                            /* the scan ranges row, always */

	/*
	 * The strings.
	 *
	 * "found in" rather than a bare region name: a string's region is where
	 * it WAS, and a matcher's range is where it will be LOOKED FOR. The two
	 * use the same words and are not the same fact, and the row that states
	 * provenance should not read like the row that states a search.
	 */
	/* A column heading instead of a preposition on every row: "found in
	 * CODE" said the same word once per string and read like a sentence
	 * where a table belongs. */
	/*
	 * How wide the region column has to be, asked of the rows rather than
	 * guessed.
	 *
	 * It was a fixed eighteen, sized for the widest label the column can
	 * ever hold - "UNCLAIMED>UNCLAIMED" and the like. Almost no draft has
	 * one, so almost every draft showed a region of four or five characters
	 * followed by a dozen spaces and then its size: two facts about the same
	 * marker, sitting at opposite ends of a gap.
	 *
	 * Measured once per frame over every row, so the columns still line up
	 * with each other - which is the thing a fixed width was there to buy -
	 * and the gap is only ever as wide as some row actually needs.
	 */
	{
		/*
		 * Six for the word "region", plus a space and the [r] button
		 * that now sits beside it - the heading has to fit in the
		 * column it names, or the button would land on "size".
		 */
		uint32_t w = 6u + 1u + (uint32_t)(sizeof BTN_UPDRGN - 1);

		for (i = 0; i < v->n_decl; i++) {
			const struct decl *d = &v->decl[i];
			uint32_t n = (uint32_t)strlen(d->rgn);

			if (d->off_rgn)
				n += 1u + (uint32_t)strlen(d->at_rgn);
			if (n > w)
				w = n;
		}
		v->rgn_w = (int)(w > 18u ? 18u : w);
	}
	if (v->n_decl && PR_VIS(r)) {
		char hdr[120];
		uint32_t d2, off = 0;
		int c0;

		/* The heading follows the column, so the two cannot drift. */
		snprintf(hdr, sizeof hdr, STR_HDR_PRE "%*ssize  bytes",
			 v->rgn_w - 6 + 1, "");
		sec_bar(o, v, PR(r), hdr);
		/*
		 * [Update string regions] BELONGS HERE, beside the column it is
		 * about.
		 *
		 * It used to sit on the scan ranges row next to a control about
		 * a matcher's range, and the two read as one pair - but a
		 * string's region is where it WAS FOUND and a matcher's range is
		 * where it will be LOOKED FOR, which is the distinction this
		 * panel spends two column headings making. The button that
		 * re-locates strings goes with the strings.
		 */
		for (d2 = 0; d2 < v->n_decl; d2++)
			off += (uint32_t)(v->decl[d2].off_rgn != 0);
		/*
		 * PLACED PAST THE HEADING, never over it.
		 *
		 * sec_bar has already drawn the heading and padded the rest of
		 * the row with its own background, so the button is written
		 * onto that padding - positioned at the column after the text.
		 *
		 * Repositioning to column one and writing spaces to get there
		 * is what the first attempt did, and it blanked the heading it
		 * was supposed to sit beside: the whole title, "region" column
		 * and all, became a row of spaces with one button on it.
		 */
		{
			int w = (int)sizeof BTN_UPDRGN - 1;
			/*
			 * One column after the word "region", which is inside
			 * the region column's own width - rgn_w is held at a
			 * minimum that leaves room for it, so the heading and
			 * the data rows below still share one column layout.
			 */
			int bcol = (int)sizeof STR_HDR_PRE + 1;

			if (bcol + w <= g_cols) {
				out_at(o, PR(r), bcol);
				o->col_hint = 0;
				c0 = o->col_base;
				out_fmt(o, "%s%s" A_OFF,
					off ? "\033[43;30m" : "\033[100;37m",
					BTN_UPDRGN);
				v->rgf_c0 = c0;
				v->rgf_c1 = o->col_base + (int)o->col_hint - 1;
			} else {
				/* No room on this width: no button, and no
				 * stale columns left answering clicks. */
				v->rgf_c0 = v->rgf_c1 = -1;
			}
		}
	} else if (!v->n_decl) {
		v->rgf_c0 = v->rgf_c1 = -1;
	}
	r += v->n_decl ? 1 : 0;
	v->row_str = PR(r);
	for (i = 0; i < v->n_decl; i++, r++) {
		const struct decl *d = &v->decl[i];
		uint32_t k;
		char sz[24];

		if (!PR_VIS(r)) {
			/*
			 * A ROW THAT IS NOT DRAWN HAS NO CLICK TARGETS.
			 *
			 * Left at last frame's columns, a scrolled-out row's
			 * ranges still answer a click - so a press at those
			 * columns on whatever row now sits there acted on THIS
			 * marker, which is the failure the per-row recording
			 * exists to prevent (see the note on grp_nt). The
			 * condition loop below already clears its own.
			 */
			v->str_wc[i][0] = v->str_wc[i][1] = -1;
			v->str_by[i][0] = v->str_by[i][1] = -1;
			continue;
		}
		row_start(o, PR(r), 1);
		/* Right aligned in a fixed width, so the columns after it do
		 * not step sideways when the list reaches ten. Two digits is
		 * the whole range: MAX_DECL is 32. */
		out_fmt(o, "  %s%2u." A_OFF " %s%-4s" A_OFF " ",
			i == v->sel_decl ? A_SEL : A_DIM, i + 1u,
			A_ID, d->hex ? "hex" : "str");
		v->str_wc[i][0] = 1 + (int)o->col_hint;
		if (d->hex)
			out_fmt(o, A_DIM "%-21s" A_OFF, "");
		else
			out_fmt(o, A_WARN "%-9s %-11s" A_OFF,
				d->fullword ? "fullword" : "substring",
				d->icase ? "ignore-case" : "exact-case");
		v->str_wc[i][1] = (int)o->col_hint;
		/*
		 * The declared range, or - when the bytes are somewhere else
		 * entirely - both, in the colour that says look at this.
		 *
		 * "DATA" alone is what this said for a marker whose bytes are
		 * in CODE, and it is why a rule that cannot possibly fire read
		 * as correct on every row. The arrow is the whole diagnosis:
		 * searched there, found here.
		 */
		/*
		 * HOW MUCH OF THE FILE IT COVERS, WHICH MAY BE A RANGE.
		 *
		 * "6A 40 [4-6] 8D 4D" is six bytes long, or seven, or eight -
		 * the compiler answers both ends and the column shows both,
		 * because one number would have to be the wrong one.
		 */
		if (d->span_max > d->len)
			snprintf(sz, sizeof sz, "%u-%u", d->len, d->span_max);
		else
			snprintf(sz, sizeof sz, "%u", d->len);
		if (d->at == KOF_BROKEN) {
			/*
			 * Declared, and not in this object.
			 *
			 * GREY, not red. The colour is the whole message - the
			 * region stays because that is still where the module
			 * will look - but "absent" is the quiet case: nothing is
			 * wrong with the file, this marker simply is not in it.
			 * Red said "look at me" on every row of a rule being
			 * read against a sample it was not written for, which is
			 * most of them; dim says it without shouting, and is
			 * still far enough off the background to read.
			 */
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				A_DIM, v->rgn_w, v->rgn_w, d->rgn,
				A_SIZE, sz);
		} else if (d->off_rgn) {
			char both[40];

			snprintf(both, sizeof both, "%s>%s", d->rgn,
				 d->at_rgn);
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				A_WARN, v->rgn_w, v->rgn_w, both,
				A_SIZE, sz);
		} else {
			/*
			 * PRESENT - and what that MEANS depends on which way the
			 * panel is being used.
			 *
			 * Drafting a new rule, a marker that is in the file is
			 * the thing you were looking for: green, the colour it
			 * has always had. READING a rule that already exists
			 * against a sample, the same fact is a HIT - this rule
			 * finds this marker in this file - and that is worth the
			 * loud colour, because it is the answer the reader
			 * opened the file to get.
			 *
			 * Which mode it is comes from gen_path, the same field
			 * that decides whether the button above says Generate or
			 * Save: non-empty means the draft was read out of a
			 * signature that is already on disk.
			 */
			out_fmt(o, " %s%-*.*s" A_OFF " %s%5s" A_OFF "  ",
				v->from_rule ? A_BAD : A_LOC,
				v->rgn_w, v->rgn_w, d->rgn,
				A_SIZE, sz);
		}
		v->str_by[i][0] = 1 + (int)o->col_hint;
		if (v->edit == ED_STR + (int)i) {
			/*
			 * The value, in the column the value was in.
			 *
			 * Editing in place rather than in a dialog: the row
			 * around it is the context - which region, how long,
			 * whether it was found - and a box over the top of that
			 * would hide the things being edited against.
			 */
			int room = g_cols - (int)(d->n_hits > 1u
						  ? STR_BTN_PREV + 1u
						  : STR_BTN_E + 1u)
				   - v->str_by[i][0];

			if (room < 8)
				room = 8;
			field_draw(o, v->sedit, v->caret, &v->sedit_off, room,
				   1, d->hex ? "hex pairs" : "text",
				   v->field_all);
		} else if (d->hexs[0]) {
			uint32_t n = (uint32_t)strlen(d->hexs);
			uint32_t from = v->decl_hoff > n ? n : v->decl_hoff;

			out_fmt(o, "%.32s", d->hexs + from);
			if (n > from + 32u)
				out_str(o, "...");
		} else {
			uint32_t from = v->decl_hoff / 2u;

			if (from > d->nbytes)
				from = d->nbytes;
			for (k = from; k < d->nbytes && k < from + 16u; k++)
				out_fmt(o, "%02X", d->bytes[k]);
			if (d->nbytes > from + 16u)
				out_str(o, "...");
		}
		v->str_by[i][1] = (int)o->col_hint;
		/*
		 * Edit before delete, and in a colour that is not the delete's.
		 *
		 * The order is the order of how much they cost to be wrong
		 * about: the reachable-by-accident end of the row should be the
		 * one that can be undone by typing, not the one that removes a
		 * marker. Red stays reserved for the button that destroys.
		 */
		if (d->n_hits > 1u) {
			char cnt[8];

			out_at(o, PR(r), g_cols - (int)STR_BTN_PREV);
			out_fmt(o, "%s[<]" A_OFF, A_ID);
			snprintf(cnt, sizeof cnt, "%u/%u%s",
				 d->cur_hit + 1u, d->n_hits,
				 d->hits_clipped ? "+" : "");
			out_at(o, PR(r), g_cols - (int)STR_CNT);
			out_fmt(o, A_DIM "%5.5s" A_OFF, cnt);
			out_at(o, PR(r), g_cols - (int)STR_BTN_NEXT);
			out_fmt(o, "%s[>]" A_OFF, A_ID);
		}
		out_at(o, PR(r), g_cols - (int)STR_BTN_E);
		out_fmt(o, "%s[e]" A_OFF,
			v->edit == ED_STR + (int)i ? A_SEL : A_ID);
		out_at(o, PR(r), g_cols - (int)STR_BTN_X);
		out_str(o, A_BAD "[x]" A_OFF);
	}

	/* ---- the matchers: what to look for ---- */
	if (PR_VIS(r))
		sec_bar(o, v, PR(r), " Matchers");
	r++;
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->n_c0 = 2;
		out_fmt(o, " " A_ID "[+ Matcher]" A_OFF);
		v->n_c1 = (int)o->col_hint;
	}
	r++;

	v->row_grp = PR(r);
	for (g = 0; g < v->n_grp; g++) {
		const struct group *q = &v->grp[g];
		char rl[16];
		int first = 1;

		if (q->rule == 1)
			snprintf(rl, sizeof rl, "find_any");
		else if (q->rule == 2)
			snprintf(rl, sizeof rl, "find_multi");
		else
			snprintf(rl, sizeof rl, "find_all");

		if (!PR_VIS(r)) {
			/* Scrolled out: this matcher has no click targets this
			 * frame. See the same clearing on the string rows. */
			v->grp_rl[g][0] = v->grp_rl[g][1] = -1;
			v->grp_rg[g][0] = v->grp_rg[g][1] = -1;
			v->grp_th[g][0] = v->grp_th[g][1] = -1;
			v->grp_nt[g][0] = v->grp_nt[g][1] = -1;
		}
		if (PR_VIS(r)) {
			char nm[40], lead[16];

			row_start(o, PR(r), 1);
			/* Nothing to name only when there is neither a marker
			 * to derive a range from nor a range that was
			 * chosen. */
			if (grp_has_range(v, g))
				rng_name_of(cur_obj(v)->fmt, grp_mask(v, g), nm,
					    sizeof nm);
			else
				snprintf(nm, sizeof nm, "-");
			/*
			 * Named fields, not a table.
			 *
			 * The columns were the same width whether or not they
			 * held anything, so every matcher that was not a
			 * threshold carried an empty "threshold" column across
			 * the row - a heading for a thing that was not there.
			 * A field that does not apply is now simply absent.
			 */
			snprintf(lead, sizeof lead, "  %u.", g + 1u);
			out_fmt(o, "%s%-6.6s" A_OFF,
				g == v->cur_grp ? A_SEL : A_DIM, lead);
			v->grp_rl[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_WARN, rl);
			v->grp_rl[g][1] = (int)o->col_hint;
			out_str(o, A_DIM " in " A_OFF);
			v->grp_rg[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, A_LOC, nm);
			v->grp_rg[g][1] = (int)o->col_hint;
			/*
			 * TWO THINGS, AND ONLY ONE OF THEM IS A CONTROL.
			 *
			 * ">= N" is the threshold: it is what the author sets,
			 * and clicking it opens the menu of values. "of N" is
			 * how many markers the matcher currently holds - a
			 * fact about the matcher, changed by adding or removing
			 * a marker and by nothing else.
			 *
			 * The clickable span used to cover both, so clicking
			 * the total - the half that reads most like a number
			 * somebody would want to change - opened the menu for
			 * the other one. The span now ends where the control
			 * does, and the total is text: highlighted, because it
			 * is the number the threshold has to make sense
			 * against, but not a thing to press.
			 */
			v->grp_th[g][0] = v->grp_th[g][1] = -1;
			if (q->rule == 2) {
				out_str(o, A_DIM "   Threshold: " A_OFF);
				v->grp_th[g][0] = 1 + (int)o->col_hint;
				out_fmt(o, "%s>= %u" A_OFF, A_ID, q->thresh);
				v->grp_th[g][1] = (int)o->col_hint;
				out_fmt(o, A_DIM " of " A_OFF "%s%u" A_OFF,
					A_SIZE, grp_count(v, g));
			}
			out_str(o, "   ");
			v->grp_nt[g][0] = 1 + (int)o->col_hint;
			{
				/* Up to the remove control, which keeps the
				 * right hand end of every matcher row. */
				int room = g_cols - v->grp_nt[g][0] - 7;

				if (room < 8)
					room = 8;
				out_fmt(o, "%s[",
					v->edit == 300 + (int)g ? A_SEL
								: A_DIM);
				field_draw(o, q->note, v->caret,
					   &v->grp[g].note_off, room,
					   v->edit == 300 + (int)g,
					   "comment...", v->field_all);
				out_str(o, "]" A_OFF);
			}
			v->grp_nt[g][1] = (int)o->col_hint;
			out_at(o, PR(r), g_cols - 4);
			out_str(o, A_BAD "[x]" A_OFF);
		}
		r++;

		/* The markers are the matcher's own row, because they are what
		 * it searches for and not a separate thing that happens to be
		 * nearby. */
		if (!PR_VIS(r)) {
			r++;
			continue;
		}
		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM "     Markers: " A_OFF);
		for (i = 0; i < v->n_decl; i++) {
			if (!(v->decl[i].grp & (1u << g)))
				continue;
			out_fmt(o, "%s%s%u" A_OFF, first ? "" : ", ", A_ID,
				i + 1u);
			first = 0;
		}
		if (first)
			out_str(o, A_DIM "none yet" A_OFF);
		v->p_c0[g][0] = v->p_c0[g][1] = -1;
		if (decl_free(v)) {
			v->p_c0[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "   " A_ID "[+ String]" A_OFF);
			v->p_c0[g][1] = (int)o->col_hint;
		}
		r++;
	}

	/* ---- the conditions: what it means ---- */
	if (PR_VIS(r))
		sec_bar(o, v, PR(r), " Conditions");
	r++;
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->a_c0 = 2;
		out_fmt(o, " %s[+ Condition]" A_OFF,
			v->n_grp ? A_ID : A_DIM);
		v->a_c1 = (int)o->col_hint;
		/*
		 * Nesting is added from the condition it nests inside, not from
		 * here. "[add inside 1]" up here had to name its parent, which
		 * meant reading a number off one row to know what a button on
		 * another would do; the same button sitting on the parent's own
		 * row needs no number at all.
		 */
		v->b_c0 = v->b_c1 = -1;
	}
	r++;

	v->row_cnd = PR(r);
	for (g = 0; g < v->n_cseq; g++) {
		uint32_t ci = v->cseq_idx[g];
		const struct cond *c2 = &v->cnd[ci];
		int deep = cnd_depth(v, ci);

		if (!PR_VIS(r)) {
			if (v->cseq_kind[g] == CS_COND) {
				v->cnd_lv[ci][0] = v->cnd_lv[ci][1] = -1;
				v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
				v->cnd_vr[ci][0] = v->cnd_vr[ci][1] = -1;
			} else if (v->cseq_kind[g] == CS_MATCH) {
				v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			}
			r++;
			continue;
		}
		row_start(o, PR(r), 1);

		if (v->cseq_kind[g] == CS_COND) {
			char lab[16], lead[24];

			/*
			 * A connector, not just an indent: two spaces of margin
			 * is a difference the eye has to measure, a line drawn
			 * from the parent to the child is one it reads.
			 */
			/*
			 * One vertical rail and nothing else.
			 *
			 * The block used to be drawn with three characters -
			 * "+-" opening a child, "|" continuing it, "`-"
			 * closing it - plus rules of dashes between and under
			 * them. Four kinds of line art to say one thing: these
			 * rows are inside that one. A single bar in a fixed
			 * column says it without being read as anything.
			 */
			cnd_label(v, ci, lab, sizeof lab);
			out_fmt(o, "%*s", deep ? 6 : 1, "");
			out_fmt(o, "%s%-6.6s" A_OFF,
				ci == v->cur_cnd ? A_SEL : A_DIM, lab);
			(void)lead;

			out_str(o, A_DIM "Verdict: " A_OFF);
			v->cnd_lv[ci][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF,
				c2->level == LV_SUSPECT ? A_WARN :
				c2->level == LV_NONE ? A_DIM : A_BAD,
				lvl_word[c2->level % LV_COUNT]);
			v->cnd_lv[ci][1] = (int)o->col_hint;
			v->cnd_vr[ci][0] = v->cnd_vr[ci][1] = -1;
			v->cnd_nm[ci][0] = v->cnd_nm[ci][1] = -1;
			if (c2->level != LV_NONE) {
				out_str(o, A_DIM "   Variant name: " A_OFF);
				v->cnd_vr[ci][0] = 1 + (int)o->col_hint;
				out_fmt(o, "%s%s" A_OFF, A_ID,
					c2->var_kind == 2 ? "Custom" :
					c2->var_kind == 1 ? "Generic" : "Auto");
				v->cnd_vr[ci][1] = (int)o->col_hint;
				/* Custom is a promise of a name, so the box
				 * for it sits beside the word rather than
				 * replacing it. */
				if (c2->var_kind == 2) {
					out_str(o, " ");
					v->cnd_nm[ci][0] = 1 +
							   (int)o->col_hint;
					out_fmt(o, "%s[",
						v->edit == 4 + (int)ci
						? A_SEL : A_WARN);
					field_draw(o, c2->variant, v->caret,
						   &v->cnd_off[ci],
						   v->edit == 4 + (int)ci
						   ? 20
						   : (int)strlen(
							c2->variant[0]
							? c2->variant
							: "name..."),
						   v->edit == 4 + (int)ci,
						   "name...", v->field_all);
					out_str(o, "]" A_OFF);
					v->cnd_nm[ci][1] = (int)o->col_hint;
				}
			}
			/* The comment lives on the row below, beside the
			 * matchers it explains. Two boxes on two rows of one
			 * condition was one box too many to look at. */
			out_at(o, PR(r), g_cols - 4);
			out_str(o, A_BAD "[x]" A_OFF);
			r++;
			continue;
		}

		if (v->cseq_kind[g] == CS_MATCH) {
			/* Indented under the condition it belongs to, and
			 * continuing the stroke while a sibling is still
			 * below. */
			cnd_rail(o, deep, 1);
			out_str(o, A_DIM "Matchers: " A_OFF);
			v->cnd_id0[ci] = 1 + (int)o->col_hint;
			v->cnd_op[ci][0] = v->cnd_op[ci][1] = -1;
			v->cnd_ex[ci][0] = v->cnd_ex[ci][1] = -1;
			{
				char canon[64];

				cnd_canon(v, ci, canon, sizeof canon);
				if (c2->expr[0] &&
				    strcmp(c2->expr, canon) != 0) {
					/* Typed, and not a list. Shown as
					 * written, because rendering it as a
					 * list would show a different
					 * condition from the generated one. */
					v->cnd_id0[ci] = -1;
					v->cnd_ex[ci][0] = 1 +
							   (int)o->col_hint;
					out_str(o, v->edit == 103 + (int)ci
						   ? A_SEL : A_WARN);
					field_draw(o, c2->expr, v->caret,
						   &v->cnd_eoff[ci],
						   v->edit == 103 + (int)ci
						   ? 24
						   : (int)strlen(c2->expr),
						   v->edit == 103 + (int)ci,
						   "", v->field_all);
					out_str(o, A_OFF);
					v->cnd_ex[ci][1] = (int)o->col_hint;
					goto ids_done;
				}
			}
			if (v->n_grp) {
				uint32_t m;
				int first2 = 1;

				for (m = 0; m < v->n_grp; m++) {
					if (!cnd_uses(c2, m))
						continue;
					if (!first2) {
						if (v->cnd_op[ci][0] < 0)
							v->cnd_op[ci][0] = 2 +
							  (int)o->col_hint;
						out_fmt(o, "%s %s " A_OFF,
							c2->op ? A_OR : A_AND,
							c2->op ? "or" : "and");
						v->cnd_op[ci][1] =
							(int)o->col_hint - 1;
					}
					out_fmt(o, "%s%u" A_OFF, A_ID, m + 1u);
					first2 = 0;
				}
				if (first2)
					out_fmt(o, A_DIM "%s" A_OFF,
						cnd_children(v, ci)
						? "group only" : "none yet");
			} else {
				out_str(o, A_DIM "none defined yet" A_OFF);
			}
ids_done:
			v->cnd_mt[ci][0] = v->cnd_mt[ci][1] = -1;
			if (v->n_grp) {
				v->cnd_mt[ci][0] = 1 + (int)o->col_hint;
				out_fmt(o, "   " A_ID "[+ Matcher]" A_OFF);
				v->cnd_mt[ci][1] = (int)o->col_hint;
			}
			/*
			 * No comment box here.
			 *
			 * A note written above a branch in the source is about
			 * the search the branch makes - "matcher 1: Hooks" -
			 * and the search belongs to the matcher. Two places to
			 * put one remark meant the loader had to guess which,
			 * and it guessed the condition.
			 */
			r++;
			continue;
		}

		if (v->cseq_kind[g] == CS_JOIN) {
			/*
			 * How the next condition at this level attaches, as a
			 * rule between the two it joins. A word and a switch -
			 * the sentence that used to be here was a paragraph on
			 * a row of dashes.
			 */
			/* Between two conditions, so it belongs to neither:
			 * no bar, just their indent. */
			out_fmt(o, "%*s", deep ? 6 : 1, "");
			out_str(o, A_DIM "logic " A_OFF);
			v->cnd_jn[ci][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s[%s]" A_OFF,
				c2->join ? A_AND : A_OR,
				c2->join ? "and" : "or");
			v->cnd_jn[ci][1] = (int)o->col_hint;
			r++;
			continue;
		}

		/* CS_ADD: the foot of the block, which is also where another
		 * condition goes into it. */
		v->cnd_kid[ci][0] = v->cnd_kid[ci][1] = -1;
		out_fmt(o, "%*s", 6, "");
		v->cnd_kid[ci][0] = 1 + (int)o->col_hint;
		out_fmt(o, "%s[+ Condition]" A_OFF, v->n_grp ? A_ID : A_DIM);
		v->cnd_kid[ci][1] = (int)o->col_hint;
		r++;
	}

	/* Whatever the draft used to reach and no longer does. */
	{
		int y = PR(r), bot = top + g_decl_rows - 2;

		for (; y <= bot; y++)
			if (y > top)
				row_start(o, y, 1);
	}
	scrollbar(o, g_cols, top + 1, top + g_decl_rows - 2, v->prow_off,
		  v->n_prow, (uint64_t)(g_decl_rows - 2));

}

/*
 * What the gate found, as a name and as a reason.
 *
 * The NAME is the whole of what the status line says. A sentence explaining
 * which measurement fired was tried there and was simply too long - it pushed
 * everything else off the row, and "Unknown packer" already tells a reader both
 * that something packed this and that nothing here knows what. The reason
 * belongs on the dashboard, where there is a line for it.
 *
 * Two wordings for two strengths of claim: dense executable segments select
 * nothing across 1 246 clean binaries, so that one is a statement; a header
 * that cannot be loaded is weaker, because every instance of it in the malware
 * corpus turned out to be a truncated file rather than a packed one.
 */
static const char *emu_why_tag(uint8_t why)
{
	return why == KOF_EMU_UNP_WHY_DENSE  ? "Unknown packer"
	     : why == KOF_EMU_UNP_WHY_BROKEN ? "Possible packer"
	     : why == KOF_EMU_UNP_WHY_LOADER ? "Possible encryptor" : NULL;
}

static const char *emu_why_reason(uint8_t why)
{
	return why == KOF_EMU_UNP_WHY_DENSE
	       ? "executable segments too dense to be code"
	     : why == KOF_EMU_UNP_WHY_LOADER
	       ? "an encrypted block sits in a non-code segment"
	       : "header cannot be loaded as written";
}

static void draw_marker_line(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	/* Wide enough for the action slot, which is the longest thing that lands
	 * here: a dump reports counts, a byte total and a directory name. */
	char name[80], head[24], right[200];
	/* The right hand text is not always a readout: while the draft has the
	 * focus it can be a complaint, and a complaint in the colour of a
	 * readout is one people scroll past. */
	const char *rcol = NULL;
	uint32_t hit = 0, i;

	/* The rule that closes the draft panel, and so the one that separates
	 * the status line from whatever is above it. Drawn here rather than in
	 * draw_decl because it is the status line's border as much as the
	 * panel's, and it has to be there when there is no panel too. */
	if (g_decl_rows) {
		int c2;

		row_start(o, mark_row() - 1, 1);
		out_str(o, A_DIM);
		for (c2 = 0; c2 < g_cols; c2++)
			out_str(o, "-");
		out_str(o, A_OFF);
	}

	row_start(o, mark_row(), 1);

	/*
	 * Which module opened this object, and which version of the format it
	 * found - the left hand end, where it has been, because it is a property
	 * of the object rather than of what is being done to it.
	 *
	 * The version earns its place beside the name: "UPX.ELF" says a packer
	 * was recognised, and the version is what decides whether the layout the
	 * module walked is the one this file actually uses. When they disagree
	 * the recovered bytes are short and nothing else on the screen says why.
	 */
	/*
	 * The colour separates two things this field has always conflated.
	 *
	 * A PACKER stays red. Nothing legitimate ships an executable wrapped in
	 * UPX or Ezuri without a reason, and the wrapper is there to stop the
	 * file being read - which is a fact about intent, and belongs in the
	 * colour the rest of the screen reserves for what is wrong.
	 *
	 * A DECOMPRESSOR OR PARSER goes yellow. "This came out of a zip", "this
	 * came out of an RTF" says only how the object was reached. Archives and
	 * documents are how software is shipped; red there made every object
	 * inside a container look like a finding before a module had run.
	 *
	 * The version stays beside the name and stays dim - it qualifies the
	 * name rather than competing with it, and it is the field that decides
	 * which layout the rest of what the module said belongs to.
	 */
	if (ob->packer[0]) {
		/*
		 * Which sort of unpacker, from the ENGINE - it knows, because
		 * every unpack module declares it. The name table this used to
		 * consult was a guess that would misclassify the twelfth module.
		 *
		 * TWO FIELDS, because the name beside an object means two
		 * different things depending on which object it is. On the file
		 * itself it is the module that OPENED it, and PACKED says
		 * whether that module was a packer. On a child it is the module
		 * that PRODUCED it, and from_packer says the same thing about
		 * that. Either one being true means the name here is a packer's.
		 */
		const char *pcol =
			(ob->heur.from_packer ||
			 (ob->heur.heur_flags &
			  KOF_HEUR_FL(KOF_HEUR_F_PACKED))) ? A_BAD : A_WARN;

		if (ob->packer_ver >= 0)
			out_fmt(o, "%s%s" A_OFF A_DIM " v%lld" A_OFF,
				pcol, ob->packer, ob->packer_ver);
		else
			out_fmt(o, "%s%s" A_OFF, pcol, ob->packer);
		out_str(o, A_DIM "  |  " A_OFF);
	} else if (emu_why_tag(ob->emu_why)) {
		/*
		 * NO MODULE NAMED IT, AND IT STILL LOOKS PACKED.
		 *
		 * The same slot, because it answers the same question - what
		 * got this object into the shape it is in - and a reader who
		 * has learnt to look here for "UPX.ELF v13" should find the
		 * next best answer in the same place rather than nowhere.
		 */
		out_fmt(o, "%s%s" A_OFF,
			ob->emu_why == KOF_EMU_UNP_WHY_DENSE ? A_BAD : A_WARN,
			emu_why_tag(ob->emu_why));
		out_str(o, A_DIM "  |  " A_OFF);
	}

	if (!ob->n_touch) {
		int32_t hsc = 0;
		const char *hguess = "Unknown";

		/*
		 * NO MARKER IS NOT THE SAME AS NOTHING TO SAY.
		 *
		 * "no markers" was the whole of this line for an object no
		 * signature knows, and on an object the heuristic would report
		 * that reads as an all clear - the one reading it must never
		 * have. A scan of the same file prints a finding; this said the
		 * database is quiet, which is true and beside the point.
		 *
		 * Spelled the way the scanner spells it, because it is the same
		 * verdict and a reader should be able to match the two by eye
		 * rather than by working out that they are about one thing.
		 */
		/*
		 * The packer tag wins the line when both apply.
		 *
		 * They are not competing readings of the same evidence - one
		 * says something hid this object's code, the other that its
		 * structure is wrong - but the status line holds one and the
		 * packer is the one worth acting on: it names a button to
		 * press. The heuristic verdict is not lost, it is on the
		 * dashboard a keystroke away, on its own line.
		 */
		if (emu_why_tag(ob->emu_why))
			out_str(o, A_DIM "no markers" A_OFF);
		else if (heur_reports(ob, &hsc, &hguess))
			out_fmt(o, A_BAD "Heur:%s#s%d" A_OFF A_DIM
				"  no marker" A_OFF, hguess, hsc);
		else
			out_str(o, A_DIM "no markers" A_OFF);
	} else {
		char hits[24], skips[24];
		int c;

		for (i = 0; i < ob->n_touch; i++)
			hit += (uint32_t)(ob->touch[i].fired != 0);
		/*
		 * "No rule selected" is a real state - it is what an object
		 * that matched nothing starts in, so that the hex pane does not
		 * light up wherever some unselected rule's marker happened to
		 * land. The counts still mean something there; the name does
		 * not, and reading it would be reading one past the array.
		 */
		if (v->sel_touch < ob->n_touch) {
			touch_name(&ob->touch[v->sel_touch], name, sizeof name);
			touch_head(&ob->touch[v->sel_touch], head, sizeof head);
		} else {
			snprintf(name, sizeof name, "no marker selected");
			head[0] = '\0';
		}

		/*
		 * Capitalised, because they are the labels of two controls
		 * rather than words in a sentence - the same way every other
		 * button on this screen is written.
		 *
		 * "Matched" and "Skipped" rather than "Hit" and "Skip". The
		 * dashboard has said "matched" and "skipped" for as long as it
		 * has existed, and the two screens describing one fact in two
		 * vocabularies is a thing a reader has to translate. They also
		 * say what happened to the OBJECT: "Hit" is jargon for what
		 * happened to the module.
		 */
		snprintf(hits, sizeof hits, "Matched %u", hit);
		snprintf(skips, sizeof skips, "Skipped %u", ob->n_touch - hit);

		c = 1 + (int)o->col_hint;
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
			v->sel_touch < ob->n_touch
			? touch_colour(&ob->touch[v->sel_touch]) : A_DIM,
			name, head);
	}

	/*
	 * The right half.
	 *
	 * A selection is reported as its size and its two offsets, and not as
	 * its contents: the contents are on the screen a few rows up, in colour,
	 * and repeating twenty of them here says nothing the highlight has not.
	 *
	 * Both offsets, because a signature is written against one and a bug
	 * report is written against the other, and which is which is exactly the
	 * thing that gets confused.
	 */
	/*
	 * The draft's own commentary, while the draft is what is being worked
	 * on.
	 *
	 * Only then: it is about a panel, and shown while the hex pane has the
	 * focus it would be answering a question nobody asked, in the space the
	 * selection needs. Same order of urgency it had beside the button -
	 * what is wrong, then what is missing, then what would be a duplicate,
	 * then where this draft lives.
	 */
	if (v->find_msg[0]) {
		snprintf(right, sizeof right, "%s", v->find_msg);
		rcol = A_WARN;
		goto have_right;
	}
	/*
	 * What the last copy did, wherever it was made from.
	 *
	 * Its own slot rather than the panel's commentary below, because that
	 * one only shows while the draft panel has focus and a copy is almost
	 * always made from the hex pane. Put there, the one message that exists
	 * to stop a silent failure was itself silent.
	 */
	/*
	 * AND IT FADES.
	 *
	 * This slot had no expiry at all: it was written when something
	 * happened and cleared only by opening the dashboard. So "opened a3"
	 * from a file switch sat on the status line for the rest of the
	 * session, outranking the selection readout - the reader drags out a
	 * run of bytes, the line still says what happened a minute ago, and the
	 * one number they asked for by dragging never appears.
	 *
	 * A confirmation is worth a few seconds. A FAILURE is worth longer:
	 * it is the message somebody has to act on, and it competes with a
	 * selection they can make again in a second.
	 */
	if (v->act_msg[0]) {
		static char last[sizeof v->act_msg];
		static uint64_t since;
		uint64_t now = now_ms();

		if (strcmp(last, v->act_msg) != 0) {
			snprintf(last, sizeof last, "%s", v->act_msg);
			since = now;
		}
		if (now - since > (v->act_ok ? 4000u : 15000u))
			v->act_msg[0] = 0;
	}
	if (v->act_msg[0]) {
		snprintf(right, sizeof right, "%s", v->act_msg);
		rcol = v->act_ok ? A_SIZE : A_WARN;
		goto have_right;
	}
	/*
	 * A word about the marker list, while the marker list is what is open.
	 *
	 * The panel's commentary below is scoped to the panel having focus,
	 * which is right for it and wrong here: this dialog is over the panel
	 * and the reader is not in it, so a note about the row they just
	 * clicked had nowhere to appear at all.
	 */
	if (v->show_list && v->list_depth && v->warn[0]) {
		snprintf(right, sizeof right, "%s", v->warn);
		rcol = v->warn_bad ? A_BAD : A_WARN;
		goto have_right;
	}
	if (v->pane == 3 && g_decl_rows) {
		const char *why = draft_missing(v);
		int near = 0;
		const char *dup = why ? NULL : draft_dup(v, &near);

		if (v->warn[0]) {
			snprintf(right, sizeof right, "%s", v->warn);
			rcol = v->warn_bad ? A_BAD : A_WARN;
		} else if (why) {
			/* Something required is absent, which is why the
			 * button is greyed - an error, and coloured as one. */
			snprintf(right, sizeof right, "%s", why);
			rcol = A_BAD;
		} else if (dup) {
			/* Both readings are the same kind of thing: a rule in
			 * the tree worth looking at before writing another.
			 * Neither is a failure, and the exact-match one is the
			 * reading that follows a Save As that worked. */
			snprintf(right, sizeof right, "%s %s",
				 near ? "all but one marker of"
				      : "same markers as", dup);
			rcol = A_WARN;
		}
		else if (v->gen_path[0])
			snprintf(right, sizeof right, "%.*s%s",
				 (int)sizeof right - 12, v->gen_path,
				 draft_dirty(v) ? "  (unsaved)" : "");
		else
			right[0] = 0;
		if (right[0])
			goto have_right;
	}
	if (v->sel_a != KOF_BROKEN) {
		uint64_t lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		uint64_t hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;

		/* One offset in front and the other in brackets after it: they
		 * are the same place said twice, not two columns to line up. */
		/* And which hit it is, when the selection is one: after a
		 * search the useful question is not only where this match is
		 * but how many there are and how far through them you are. */
		/* The wording an editor uses. "hit 1/1" reads as a ratio of
		 * something, and the thing it was a ratio of was never said. */
		/*
		 * THE SAME PAIR, BUT THE FIRST NUMBER IS NOT A FILE OFFSET.
		 *
		 * A symbol row resolves to extents like any other row, so both
		 * halves of the pair are real here: view_map gives the position
		 * in the BLOCK and `lo` the position in the row. Only the word
		 * changes, because the block is built and calling that number a
		 * file offset is what led to a marker declared here being
		 * looked for in the file.
		 */
		if (sym_view(v))
			snprintf(right, sizeof right,
				 "%llu B   block %08llx (row: %08llx)",
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
		else if (v->find_n && v->find_i)
			snprintf(right, sizeof right,
				 "match %u of %u   %llu B   offset %08llx "
				 "(region: %08llx)",
				 v->find_i, v->find_n,
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
		else
			snprintf(right, sizeof right,
				 "%llu B   offset %08llx (region: %08llx)",
				 (unsigned long long)(hi - lo + 1u),
				 (unsigned long long)view_map(v, lo, 0),
				 (unsigned long long)lo);
	} else if (ob->broken) {
		/*
		 * The engine did not finish this object, said here because
		 * nothing else on the screen would say it.
		 *
		 * It is on the RIGHT and it is LAST. Right, because it is a
		 * fault and the left hand end is where the object describes
		 * itself; last, because it is a standing condition rather than
		 * a reply - it is true for as long as the object is open, and a
		 * selection or a search the reader just made is the thing they
		 * are waiting on. It comes back the moment they let go.
		 *
		 * Why it matters on this screen in particular: an unpack that
		 * stopped part way still yields an object, and that object
		 * looks entirely ordinary. A signature written against the
		 * CODE of half a recovered image is a signature written against
		 * a coincidence.
		 */
		snprintf(right, sizeof right, "not finished: %s",
			 kof_broken_name(ob->broken));
		rcol = A_BAD;
	} else {
		right[0] = 0;
	}

have_right:
	if (right[0]) {
		int at, room = g_cols - (int)o->col_hint - 4;

		/*
		 * CUT TO FIT, NOT DROPPED FOR NOT FITTING.
		 *
		 * The test used to be "does the whole of it fit", and a message
		 * that did not was simply not drawn - so the longest messages,
		 * which are the ones that explain something, were the ones
		 * nobody ever saw. The hex compiler's refusals are three lines
		 * of advice and vanished entirely; the reader was left with a
		 * marker of length zero and no reason for it.
		 */
		if (room > 8 && (int)strlen(right) > room) {
			right[room - 3] = '.';
			right[room - 2] = '.';
			right[room - 1] = '.';
			right[room] = 0;
		}
		at = g_cols - (int)strlen(right) - 1;

		if (at > (int)o->col_hint + 2) {
			out_at(o, mark_row(), at);
			out_fmt(o, "%s%s" A_OFF,
				rcol ? rcol :
				v->sel_a != KOF_BROKEN ? "\033[44;97m" : A_DIM,
				right);
		}
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
/*
 * How many rows the dialog offers, given the screen it is on.
 *
 * It was a flat four, whatever the terminal. On anything taller than a laptop
 * split that is four rows of a six row list with the rest below the fold, and
 * below the fold is where the interesting marker tends to be - the ones a rule
 * fails on come first because they are declared first. Bounded at a third of
 * the screen because it is an overlay: it is meant to answer a question about
 * what is underneath, not to replace it.
 */
#define LIST_ROWS_MIN 4u
#define LIST_ROWS_MAX 14u

static uint32_t list_rows(void)
{
	int third = (g_rows - 4) / 3;
	uint32_t n = third > 0 ? (uint32_t)third : LIST_ROWS_MIN;

	if (n < LIST_ROWS_MIN)
		n = LIST_ROWS_MIN;
	if (n > LIST_ROWS_MAX)
		n = LIST_ROWS_MAX;
	return n;
}

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

	return n < list_rows() ? n : list_rows();
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
	/* The same mark the object tree uses. Two cursors drawn two ways in one
	 * program is two things to learn for one idea. */
	out_str(o, sel ? "*" : " ");
}

/*
 * The frame around the dialog.
 *
 * Drawn after its contents, because every row inside clears to the end of the
 * line and would take the right edge with it. It is worth having: the dialog
 * opens over the hex and the draft, and without an edge the two run together -
 * a row of the list and a row of whatever it covers look alike.
 *
 * Plain ASCII, like the pane divider: this is meant to be read over ssh on
 * whatever terminal is at the other end.
 */
static void draw_list_box(struct out *o, struct view *v)
{
	int top = list_top(v) - 1, bot = g_rows - 1, i, y;

	for (y = top; y <= bot; y++) {
		out_at(o, y, 1);
		out_str(o, A_DIM);
		if (y == top || y == bot) {
			out_str(o, "+");
			for (i = 2; i < g_cols; i++)
				out_str(o, "-");
			out_str(o, "+" A_OFF);
			continue;
		}
		out_str(o, "| " A_OFF);
		out_at(o, y, g_cols - 1);
		out_str(o, A_DIM " |" A_OFF);
	}
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
				v->list_filter == 1 ? "Hit: " :
				v->list_filter == 2 ? "Skip: " : "";
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
		out_fmt(o, A_DIM " %-52s %-10s%*s" A_OFF, "Signatures",
			"Markers", w - 66, range);
	else
		out_fmt(o, A_DIM " %-14s %6s %8s  %-10s %-12s %-*s" A_OFF,
			"Marker", "db id", "size", "at", "region",
			w - 59 > 0 ? w - 59 : 1, range);

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
				/*
				 * Why a module that matched everything still
				 * did not fire.
				 *
				 * The counts alone are actively misleading
				 * here: a rule ruled out by a precondition
				 * shows 5/5 next to the ones that fired, which
				 * reads as a detection and is the opposite of
				 * what happened. The engine already worked out
				 * the reason and put it in the touch; the list
				 * was throwing it away.
				 */
				const char *no = e->kind == KOF_TOUCH_INELIGIBLE
						 && e->ruled_out
						 ? e->ruled_out : "";
				int room = w - 64 > 0 ? w - 64 : 1;

				out_fmt(o, "%-52.52s %-10s %.*s", name + off,
					head, room, no);
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

			/*
			 * Neither the size nor the content is read out of the
			 * pool here any more. A hex marker's pool entry is a
			 * compiled program, and every place that reached into
			 * it got that wrong at least once - so the spelling
			 * and the span are filled where the pool IS read, and
			 * this row just prints them.
			 */
			char hx[128], span[16];
			int is_hex = st->kind == KOF_STR_HEX;

			/* Both prefilled where the pool is read, so this row
			 * never has to know a program exists. */
			snprintf(hx, sizeof hx, "%s", st->text);
			snprintf(span, sizeof span, "%s", st->span);

			if (is_hex)
				snprintf(kind, sizeof kind, "hex");
			else
				snprintf(kind, sizeof kind, "str: %s-%s",
					 (st->flags & KOF_STR_FULLWORD) ? "fuw"
									: "sub",
					 (st->flags & KOF_STR_ICASE) ? "i" : "c");

			out_str(o, miss ? A_DIM : (st->in_rgn ? A_OFF : A_WARN));
			if (sel)
				out_str(o, "\033[1m");
			out_str(o, sel ? "*" : " ");
			out_fmt(o, "%-14s %6u %8s  ", kind, st->uid, span);
			if (miss)
				/* The word, not a dash: in a column of
				 * offsets a dash reads as "not applicable"
				 * when what it means is "looked for it and it
				 * is not in this object". */
				out_fmt(o, "%-10s ", "absent");
			else
				out_fmt(o, "%-10llu ",
					(unsigned long long)st->at);
			/*
			 * Where it turned out to be, and whether that is
			 * anywhere this module looks.
			 *
			 * The engine works both facts out and hands them over
			 * as `at` and `in_rgn`; this dialog was spending the
			 * second one on the row's colour alone. Colour says
			 * "something about this row is off", it does not say
			 * WHAT, and the answer here is the whole reason a rule
			 * with every marker present still cannot fire. The
			 * panel says it as CODE>DATA and this now says the
			 * same thing in the same words.
			 */
			{
				char rgn[16];

				if (miss) {
					snprintf(rgn, sizeof rgn, "%s", "-");
				} else if (st->sym) {
					/* Found in the symbol block, which is
					 * not in the file - so node_at below
					 * has nothing to say about it and used
					 * to answer "?" for a marker that is
					 * exactly where the rule looks. */
					snprintf(rgn, sizeof rgn, "%s%s",
						 st->sym & KOF_SCAN_SYM_IMP
						 ? "SYM_IMP" : "SYM_EXP",
						 st->in_rgn ? "" : " !");
				} else {
					uint32_t ob_i = v->node[v->sel_node].obj;
					uint32_t nd = node_at(v, ob_i, st->at);
					const char *lab = nd < v->n_node &&
							  v->node[nd].mask
							  ? v->node[nd].label
							  : "?";

					/* The bang is the finding: found, and
					 * not where this module searches. */
					snprintf(rgn, sizeof rgn, "%.10s%s",
						 lab, st->in_rgn ? "" : " !");
				}
				out_fmt(o, "%-12.12s ", rgn);
			}
			/* The marker as it was written - a literal's bytes in
			 * hex, a pattern with its wildcards and gaps intact,
			 * and never the program that implements one. */
			out_fmt(o, "%.40s", hx);
			if (strlen(hx) > 40u)
				out_str(o, "...");
			out_str(o, A_OFF);
		}
	}
	draw_list_box(o, v);
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
	M_GOTO,
	M_FIND_STR,
	M_FIND_HEX,
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
	{ "Copy ASCII",           1, 0 },
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
	{ "Go to",                3, 3 },
	/*
	 * Offered in the panel too: looking at an instruction and wanting to
	 * find the next place those bytes appear is the same question asked
	 * from a different pane.
	 */
	{ "Find string",      3 | 4, 3 },
	{ "Find hex",         3 | 4, 3 }
};

#define MENU_W 24

static int menu_shown(struct view *v, int a)
{
	return (menu_item[a].ctx & v->menu_ctx) != 0;
}

static int menu_enabled(struct view *v, int a)
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
		return !ob->fmt || ob->ctx.arch == KOF_ARCH_X86 ||
		       ob->ctx.arch == KOF_ARCH_X86_64;
	}
	if (a == M_COPY_ASCII || a == M_COPY_HEX)
		return v->sel_a != KOF_BROKEN;
	if (a == M_COPY_OFF_HEX || a == M_COPY_OFF_DEC)
		return 1;
	if (a == M_DECL_HEX) {
		uint64_t lo, hi;

		if (v->sel_a == KOF_BROKEN || v->n_decl >= MAX_DECL)
			return 0;
		lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
		/* Bounded like the literal beside it. Unbounded, a drag over a
		 * whole object declared a marker whose spelling no field could
		 * hold and no row could show. */
		return hi - lo + 1u <= DECL_BYTES_MAX;
	}
	if (a == M_DECL_STR) {
		/* Greyed when the bytes cannot BE a literal, which is a
		 * property of the bytes and not of the user - saying so here
		 * beats a build error two steps later. */
		uint64_t lo, hi, k;
		uint8_t t[512];
		uint32_t n = 0;

		if (v->sel_a == KOF_BROKEN || v->n_decl >= MAX_DECL)
			return 0;
		lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
		if (hi - lo + 1u > sizeof t)
			return 0;
		{
			/*
			 * Through view_bytes, or this judges the wrong bytes.
			 *
			 * It read the object's buffer at what view_map returns,
			 * which on a symbol row is an offset into the built
			 * block - so literal_safe was asked about unrelated
			 * file bytes at the same number, said no, and the item
			 * greyed out over a selection that was plain ASCII on
			 * screen. The failure was silent in the worst way: the
			 * menu simply did nothing, with no way to tell that
			 * from "not implemented".
			 */
			uint64_t bn = 0;
			const uint8_t *bp = view_bytes(v, &bn);

			if (!bp)
				return 0;
			for (k = lo; k <= hi; k++) {
				uint64_t f = view_map(v, k, 0);

				if (f >= bn)
					return 0;
				t[n++] = bp[f];
			}
		}
		return literal_safe(t, n);
	}
	if (a == M_FIND_STR || a == M_FIND_HEX)
		return 1;       /* opens the find dialog, in either mode */
	/* Not wired to anything yet. Shown because the menu is where they will
	 * be, and disabled because a menu item that does nothing teaches people
	 * not to trust the menu. */
	return 0;
}

/* Rows including the rules between groups, which take a line each. */
static int menu_rows(struct view *v)
{
	int i, n = 0, last = -1;

	for (i = 0; i < M_COUNT; i++) {
		if (!menu_shown(v, i))
			continue;
		if (last >= 0 && menu_item[i].group != last)
			n++;
		last = menu_item[i].group;
		n++;
	}
	return n;
}

/* The action on a drawn row, or -1 for a rule or past the end. */
static int menu_at_row(struct view *v, int row)
{
	int i, n = 0, last = -1;

	for (i = 0; i < M_COUNT; i++) {
		if (!menu_shown(v, i))
			continue;
		if (last >= 0 && menu_item[i].group != last)
			n++;
		last = menu_item[i].group;
		if (n++ == row)
			return i;
	}
	return -1;
}

static void menu_open_at(struct view *v, int row, int col)
{
	int i;

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
	int i, r = 0, last = -1;

	for (i = 0; i < M_COUNT; i++) {
		int on;

		if (!menu_shown(v, i))
			continue;
		/* A rule where the kind of action changes: taking bytes out,
		 * turning bytes into a declaration, and going somewhere are
		 * three different intentions and the eye should not have to
		 * read the labels to see that. */
		if (last >= 0 && menu_item[i].group != last) {
			int k;

			out_at(o, v->menu_row + r++, v->menu_col);
			out_str(o, "\033[47;90m");
			/* One short of MENU_W: an item is a leading space plus
			 * MENU_W - 2 of label, so the rule has to be the same
			 * width or it steps out past the menu it divides. */
			for (k = 0; k < MENU_W - 1; k++)
				out_str(o, "-");
			out_str(o, A_OFF);
		}
		last = menu_item[i].group;
		on = menu_enabled(v, i);
		out_at(o, v->menu_row + r++, v->menu_col);
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
		out_fmt(o, " %-*.*s", MENU_W - 2, MENU_W - 2,
			menu_item[i].label);
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
/*
 * The viewer's own clipboard.
 *
 * OSC 52 asks the TERMINAL to set the system clipboard, and most terminals
 * refuse by default - a program that can write the clipboard can also read a
 * password out of it, so VTE and others ship with it off. Nothing here can
 * change that, and a copy that silently does nothing is worse than no copy at
 * all. So the bytes are kept here as well: the system clipboard is attempted,
 * and Ctrl+V inside this program works whether or not the terminal allowed it.
 */
static char   g_clip[8192];
static size_t g_clip_n;
/* Which helper took the last copy, or NULL when only this program has it. */
static const char *g_clip_via;

static void copy_take(const char *bytes, size_t n)
{
	g_clip_n = n < sizeof g_clip ? n : sizeof g_clip;
	memcpy(g_clip, bytes, g_clip_n);
}

/*
 * The system clipboard through a helper program, when the terminal will not.
 *
 * OSC 52 is the right primary because it is the only one that crosses ssh, but
 * it asks the TERMINAL for a favour and the common ones refuse: VTE - so
 * gnome-terminal and xfce4-terminal - ships with clipboard writes disabled, and
 * there is no reply, so the copy fails silently and a clipboard manager never
 * sees a thing. Measured rather than assumed: the sequence goes out correctly
 * with the right bytes in it and nothing arrives at the other end.
 *
 * So a local session gets a local answer. This is the only place this program
 * starts another process, and it is written to be unable to disturb the one
 * thing a TUI cannot afford to lose: the child's output goes to /dev/null and
 * its input is a pipe, so it can never write to the terminal this is drawing on.
 *
 * Returns the helper's name, or NULL when none of them is installed.
 */
static const char *copy_extern(const char *bytes, size_t n)
{
	static const char *const helper[][4] = {
		{ "wl-copy", NULL, NULL, NULL },
		{ "xclip", "-selection", "clipboard", NULL },
		{ "xsel", "-i", "-b", NULL }
	};
	size_t h;

	for (h = 0; h < sizeof helper / sizeof helper[0]; h++) {
		int fds[2];
		pid_t pid;
		int status = 0;
		void (*old)(int);

		if (pipe(fds) != 0)
			return NULL;
		pid = fork();
		if (pid < 0) {
			close(fds[0]);
			close(fds[1]);
			return NULL;
		}
		if (pid == 0) {
			int devnull = open("/dev/null", O_WRONLY);

			dup2(fds[0], STDIN_FILENO);
			if (devnull >= 0) {
				dup2(devnull, STDOUT_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
			close(fds[0]);
			close(fds[1]);
			/*
			 * execvp wants char *const[] and is documented not to
			 * modify what it points at - a signature older than
			 * const itself. The copy is made here rather than
			 * casting the table, so the strings stay const
			 * everywhere they are actually read.
			 */
			{
				char *argv[4];
				size_t a;

				for (a = 0; a < 4u; a++)
					argv[a] = helper[h][a]
						  ? strdup(helper[h][a]) : NULL;
				execvp(argv[0], argv);
			}
			_exit(127);
		}
		close(fds[0]);
		/* A helper that is not installed exits before reading, and the
		 * write would then take this process down with SIGPIPE. */
		old = signal(SIGPIPE, SIG_IGN);
		{
			size_t at = 0;

			while (at < n) {
				ssize_t w = write(fds[1], bytes + at, n - at);

				if (w <= 0)
					break;
				at += (size_t)w;
			}
		}
		close(fds[1]);
		signal(SIGPIPE, old);
		if (waitpid(pid, &status, 0) == pid &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return helper[h][0];
	}
	return NULL;
}

/*
 * THE SYSTEM CLIPBOARD, READ back through a helper - the other half of
 * copy_extern.
 *
 * Ctrl+V used to paste this program's OWN last copy, held in g_clip, because the
 * only clipboard it could reach was the one it wrote. But copy already reaches
 * the system clipboard through wl-copy/xclip/xsel, and the same tools read it:
 * wl-paste, xclip -o, xsel -o. So a paste asks them, and what comes back is what
 * any other program would paste - not just what this one copied.
 *
 * OSC 52 could ask the TERMINAL to send the clipboard, but the reply is even
 * less reliable than the write: most terminals refuse a clipboard READ outright,
 * as an obvious way for a remote program to steal what you copied. When the
 * terminal DOES paste - the user pressing its own paste key - it arrives as a
 * bracketed paste and this is not consulted at all.
 *
 * Writes up to `cap` bytes into `out`, returns how many, or 0 when no helper is
 * installed or the clipboard is empty. The child's stdin is /dev/null and its
 * stderr is too, so it can neither read a key meant for this program nor draw on
 * the screen it is using.
 */
static size_t paste_extern(char *out, size_t cap)
{
	static const char *const helper[][4] = {
		{ "wl-paste", "-n", NULL, NULL },
		{ "xclip", "-o", "-selection", "clipboard" },
		{ "xsel", "-o", "-b", NULL }
	};
	size_t h;

	for (h = 0; h < sizeof helper / sizeof helper[0]; h++) {
		int fds[2];
		pid_t pid;
		int status = 0;
		size_t got = 0;

		if (pipe(fds) != 0)
			return 0;
		pid = fork();
		if (pid < 0) {
			close(fds[0]);
			close(fds[1]);
			return 0;
		}
		if (pid == 0) {
			int devnull = open("/dev/null", O_RDWR);

			if (devnull >= 0) {
				dup2(devnull, STDIN_FILENO);
				dup2(devnull, STDERR_FILENO);
			}
			dup2(fds[1], STDOUT_FILENO);
			close(fds[0]);
			close(fds[1]);
			{
				char *argv[4];
				size_t a;

				for (a = 0; a < 4u; a++)
					argv[a] = helper[h][a]
						  ? strdup(helper[h][a]) : NULL;
				execvp(argv[0], argv);
			}
			_exit(127);
		}
		close(fds[1]);
		while (got < cap) {
			ssize_t r = read(fds[0], out + got, cap - got);

			if (r <= 0)
				break;
			got += (size_t)r;
		}
		close(fds[0]);
		if (waitpid(pid, &status, 0) == pid &&
		    WIFEXITED(status) && WEXITSTATUS(status) == 0 && got)
			return got;
		/* Installed but empty, or not installed (exit 127): try the
		 * next tool rather than returning an empty clipboard as final. */
	}
	return 0;
}

static void copy_osc52(const char *bytes, size_t n)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				  "abcdefghijklmnopqrstuvwxyz0123456789+/";
	struct out o = { 0 };
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
	copy_take(bytes, n);
	g_clip_via = copy_extern(bytes, n);
}

/*
 * The picked lines, into the clipboard.
 *
 * Its own function rather than a branch of menu_run, because the keyboard
 * reaches it too and menu_run answers a question the keyboard has not asked:
 * whether the item is SHOWN, which depends on a menu being open. Routing Ctrl+C
 * through it copied nothing at all - the menu context is zero when no menu is
 * up - and the failure was silent, which is the worst kind for a copy.
 */
static void dis_copy(struct view *v)
{
	struct out d = { 0 };
	int r, rows = 0;

	/*
	 * Either kind of selection will do.
	 *
	 * dis_have is the panel's OWN text selection. Requiring it here is what
	 * made Copy silent on a range picked in the hex pane: the rows were lit,
	 * the menu offered Copy, and this returned before looking at a single
	 * one of them.
	 */
	if (!v->dis_open || v->dis_lines <= 0 ||
	    (!v->dis_have && !dis_hex_sel(v)))
		return;

	/*
	 * A SELECTION SPANNING MORE THAN ONE INSTRUCTION IS COPIED WHOLE, not
	 * only where it shows.
	 *
	 * The panel is a window - it decodes as many instructions as it has rows
	 * and no more - but a selection can be longer than that window, whether it
	 * was made in the hex pane or dragged down the disassembly itself while it
	 * scrolled. Copying only the visible rows cut the clipboard off at whatever
	 * happened to be on screen, so a reader who selected a whole region and
	 * copied got the top of it and silently lost the rest. So the byte range is
	 * decoded here from its first instruction to its last, off the screen
	 * entirely.
	 *
	 * A SINGLE-INSTRUCTION disassembly selection stays row-based: there it IS
	 * the characters on the one row - part of a mnemonic, an operand on its own
	 * - and copying the whole instruction instead would put in the clipboard
	 * more than the reader can see they picked. dis_span's two ends being the
	 * same instruction is what tells the two apart.
	 */
	{
		uint64_t lo = 0, hi = 0;
		int whole = 0;

		if (!v->dis_have && dis_hex_sel(v)) {
			lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
			hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
			whole = 1;
		} else if (v->dis_have) {
			uint64_t a0, a1;
			int c0, c1;

			dis_span(v, &a0, &c0, &a1, &c1);
			if (a0 != a1) {         /* more than one instruction */
				lo = a0;
				hi = a1;        /* the loop takes the a1 one whole */
				whole = 1;
			}
		}

		if (whole) {
			uint64_t at = dis_sync(v, lo);
			uint32_t guard = 0;

			while (at <= hi && at < v->rgn_len &&
			       guard++ < (1u << 20)) {
				char line[120];

				if (!dis_format(v, &at, line, sizeof line,
						NULL, NULL, NULL, NULL, 0))
					break;
				if (rows)
					out_str(&d, "\n");
				out_add(&d, line, strlen(line));
				rows++;
			}
		} else
		for (r = 0; r < v->dis_lines; r++) {
			int len = (int)strlen(v->dis_line[r]);
			int from, to;

			if (!dis_cols(v, v->dis_line_at[r], v->dis_line_len[r],
				      len, &from, &to))
				continue;
			if (to <= from)
				continue;
			if (rows)
				out_str(&d, "\n");
			out_add(&d, v->dis_line[r] + from, (size_t)(to - from));
			rows++;
		}
	}
	if (d.n) {
		copy_osc52(d.p, d.n);
		snprintf(v->act_msg, sizeof v->act_msg, "Copied %d line(s)",
			 rows);
		v->act_ok = 1;
	}
	free(d.p);
}


/*
 * Say where the bytes went.
 *
 * A copy that reports nothing cannot be told from a copy that did nothing, and
 * this one really does fail on the common terminals - so the difference has to
 * be on the screen. Naming the helper when one took it is not decoration: it is
 * how the next person knows whether the clipboard they are about to paste from
 * has been written at all.
 */
static void copy_said(struct view *v, size_t n)
{
	v->act_ok = g_clip_via != NULL;
	if (g_clip_via)
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Copied %u byte(s) via %s", (unsigned)n, g_clip_via);
	else
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Copied %u byte(s) - terminal refused the clipboard", (unsigned)n);
}

/* Copying an offset is copying a number, so it has two spellings and both are
 * worth having: hex to paste back into this tool, decimal for anything that
 * counts bytes. */
static void copy_offset(struct view *v, int hex)
{
	char t[32];

	snprintf(t, sizeof t, hex ? "%llx" : "%llu",
		 (unsigned long long)v->menu_off);
	copy_osc52(t, strlen(t));
	copy_said(v, strlen(t));
}
/*
 * Take the selection into the draft.
 *
 * The region comes from the tree row rather than from anything about the bytes,
 * because that is what the finished declaration will say: KOF_TARGET_RANGE names
 * where to look, and where somebody was looking when they found it is the
 * honest answer to that.
 */

/* ---- editing a declared string as text ------------------------------------ */

/*
 * Is this value one a person can type back?
 *
 * A literal is edited as the characters it is, so a byte that has no character
 * cannot survive the round trip: it would be shown as something, and whatever
 * that something was would be written back as itself. Refusing to open is the
 * only answer that does not quietly change the marker. Hex has no such problem
 * and is always editable - that is what hex is for.
 */
static int decl_text_editable(const struct decl *d)
{
	uint32_t i;

	if (d->hex)
		return 1;
	for (i = 0; i < d->nbytes; i++)
		if (d->bytes[i] < 0x20 || d->bytes[i] >= 0x7f)
			return 0;
	return 1;
}

/*
 * A hex pattern, respaced into pairs.
 *
 * Only when the pattern is nothing but hex digits and spaces. A pattern with
 * structure in it - ??, [4-8], (41|42) - is left exactly as its author wrote
 * it: the digits inside a gap are hex digits too, so pairing them off blindly
 * would turn [4-8] into something else, and an author who has spaced a pattern
 * to show its shape has said something worth keeping.
 */
static void hex_respace(const char *in, char *out, size_t cap)
{
	size_t n = 0;
	uint32_t half = 0;
	const char *p;

	for (p = in; *p; p++)
		if (hexval(*p) < 0 && *p != ' ' && *p != '\t') {
			snprintf(out, cap, "%s", in);
			return;
		}
	/*
	 * Respacing GROWS the text by half, and a spelling that would not fit
	 * after that is left exactly as it was. Spacing is a courtesy; losing
	 * the tail of a pattern to it is not a trade worth making.
	 */
	for (p = in, n = 0; *p; p++)
		if (*p != ' ' && *p != '\t')
			n++;
	if (n + n / 2u + 2u > cap) {
		snprintf(out, cap, "%s", in);
		return;
	}
	n = 0;
	for (p = in; *p && n + 4u < cap; p++) {
		if (*p == ' ' || *p == '\t')
			continue;
		if (half == 2u) {
			out[n++] = ' ';
			half = 0;
		}
		out[n++] = *p;
		half++;
	}
	out[n] = 0;
}

/* Fill the scratch from a declaration and give it the caret. */
static void decl_edit_open(struct view *v, uint32_t i)
{
	struct decl *d = &v->decl[i];

	if (i >= v->n_decl)
		return;
	if (!decl_text_editable(d)) {
		say_note(v, "String %u is not text - edit it as hex", i + 1u);
		return;
	}
	if (d->hex) {
		if (d->hexs[0]) {
			hex_respace(d->hexs, v->sedit, sizeof v->sedit);
		} else {
			uint32_t k;
			size_t n = 0;

			for (k = 0; k < d->nbytes && n + 4u < sizeof v->sedit; k++)
				n += (size_t)snprintf(v->sedit + n,
						      sizeof v->sedit - n,
						      k ? " %02X" : "%02X",
						      d->bytes[k]);
		}
	} else {
		uint32_t k, n = d->nbytes;

		if (n >= sizeof v->sedit)
			n = (uint32_t)sizeof v->sedit - 1u;
		for (k = 0; k < n; k++)
			v->sedit[k] = (char)d->bytes[k];
		v->sedit[n] = 0;
	}
	v->sedit_off = 0;
	v->sel_decl = i;
	v->edit = ED_STR + (int)i;
}

/*
 * Parse the scratch back into the declaration.
 *
 * A hex pattern keeps its spelling in `hexs` - that is what generation writes
 * and what a wildcard lives in - and the concrete prefix of it is decoded into
 * `bytes` so the row can still say how long it is and where it is. A literal is
 * its characters and nothing else.
 *
 * Either way the bytes have changed, so where they are is asked again rather
 * than carried over: the whole point of an edit is that it may no longer be the
 * same run, and a stale offset would light the wrong bytes in the pane.
 */
static void decl_edit_commit(struct view *v, uint32_t i)
{
	struct decl *d = &v->decl[i];
	size_t n = strlen(v->sedit);
	uint8_t *nb;

	if (i >= v->n_decl)
		return;
	if (d->hex) {
		/*
		 * Refused rather than truncated. A hex pattern cut off halfway
		 * is still a valid pattern - a shorter one, matching something
		 * else - so writing it would replace the marker with a marker
		 * nobody asked for, silently.
		 */
		if (n >= sizeof d->hexs) {
			say_note(v, "Hex pattern over %u characters - unchanged",
				 (unsigned)(sizeof d->hexs - 1u));
			return;
		}
		memcpy(d->hexs, v->sedit, n + 1u);
		/*
		 * Refused by the same compiler the build uses, and in its own
		 * words. A pattern the panel accepted and the build then threw
		 * out is a rule that looked right in the viewer and does not
		 * exist in the database.
		 */
		if (!decl_from_hexs(d)) {
			{
				/*
				 * Capitalised here and not at the source: the
				 * same string is printed by ksigbuilder as
				 * "file:line: message", where lowercase is the
				 * convention every compiler follows. The status
				 * line is a sentence on its own and starts like
				 * one.
				 */
				char why[160];

				snprintf(why, sizeof why, "%s", kof_hex_error());
				if (why[0] >= 'a' && why[0] <= 'z')
					why[0] = (char)(why[0] - 32);
				say_note(v, "%s", why);
			}
			return;
		}
	} else {
		nb = realloc(d->bytes, n + 1u);
		if (!nb)
			return;
		d->bytes = nb;
		memcpy(d->bytes, v->sedit, n);
		d->len = (uint32_t)n;
		d->nbytes = d->len;
	}
	if (!d->len) {
		say_note(v, "String %u would be empty - unchanged",
			 i + 1u);
		return;
	}
	decl_locate(v, d);
}

static void decl_remove(struct view *v, uint32_t i)
{
	if (i >= v->n_decl)
		return;
	free(v->decl[i].bytes);
	memmove(&v->decl[i], &v->decl[i + 1u],
		(v->n_decl - i - 1u) * sizeof v->decl[0]);
	v->n_decl--;
	if (v->sel_decl >= v->n_decl && v->n_decl)
		v->sel_decl = v->n_decl - 1u;
}


static void decl_add(struct view *v, int hex)
{
	struct node *n = &v->node[v->sel_node];
	struct decl *d;
	uint64_t lo, hi, k;
	uint32_t i = 0, g;

	if (v->sel_a == KOF_BROKEN || v->n_decl >= MAX_DECL)
		return;

	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;

	d = &v->decl[v->n_decl];
	memset(d, 0, sizeof *d);
	d->len = (uint32_t)(hi - lo + 1u);
	d->bytes = malloc(d->len);
	if (!d->bytes)
		return;
	{
		/* From the view, not from the object: on a symbol row these
		 * offsets are into the built block. See view_bytes. */
		uint64_t bn = 0;
		const uint8_t *bp = view_bytes(v, &bn);

		for (k = lo; k <= hi; k++) {
			uint64_t f = view_map(v, k, 0);

			d->bytes[i++] = (bp && f < bn) ? bp[f] : 0;
		}
	}
	d->nbytes = d->len;
	d->hex = hex;
	/* Fullword by default. A marker is a name, a path, a format string -
	 * something with edges - far more often than it is a fragment of one,
	 * and the default that is usually right is the one worth having. */
	d->fullword = 1;
	d->obj = n->obj;
	/*
	 * The region the bytes are in, looked up from the bytes.
	 *
	 * It used to be whatever the tree cursor was on, which is a different
	 * fact: the hex pane follows a marker into DATA while the cursor stays
	 * on the object row, and a string taken there was recorded as
	 * whole-file even though the status bar named its region correctly one
	 * line below. Wanting to search the whole file is still sayable - the
	 * matcher's own range setting says it - but it should be said, not
	 * inherited from where a cursor happened to be.
	 *
	 * The object row remains the answer when nothing narrower claims the
	 * offset, and the engine has a bit for that: storing zero made "whole"
	 * the absence of a region rather than one of them, which is why a range
	 * built on it contained nothing.
	 */
	if (n->sym) {
		/*
		 * THE ROW IS THE ANSWER, and no lookup is wanted.
		 *
		 * This went through node_at like every other row, which is a
		 * FILE-offset lookup - and view_map on a symbol row returns an
		 * offset into the built block, so whichever region happened to
		 * sit at that distance from zero won. A name taken out of
		 * SYM_EXP at block offset 0x54 was declared HEADERS in libz
		 * and UNCLAIMED in a shorter-headered sample, neither of which
		 * contains the bytes.
		 *
		 * The lookup exists because the hex pane can follow a marker
		 * into another region while the tree cursor stays put, so the
		 * cursor is not evidence. On a symbol row the pane cannot go
		 * anywhere else - the block is one contiguous run - so the row
		 * IS the evidence, and it now carries the scan target to say
		 * so.
		 */
		char lab[sizeof n->label];

		/* Through a local: both point into `struct view`, so the
		 * compiler cannot prove the copy does not overlap itself. */
		snprintf(lab, sizeof lab, "%s", n->label);
		d->mask = d->mask0 = n->mask;
		snprintf(d->rgn, sizeof d->rgn, "%.23s", lab);
	} else {
		/*
		 * Mapped first: `lo` counts bytes along the region being
		 * looked at, not bytes into the file, and the two differ by
		 * the region's start. Handing the view coordinate to a
		 * file-offset lookup named whichever region happens to sit at
		 * that distance from zero - CODE for a string plainly inside
		 * DATA - and then sent the pane there.
		 */
		uint64_t at = view_map(v, lo, 0);
		uint32_t rk = at == KOF_BROKEN ? v->n_node
					       : node_at(v, n->obj, at);
		const struct node *rn = rk < v->n_node ? &v->node[rk] : n;

		d->mask = d->mask0 = rn->mask ? rn->mask : KOF_SCAN_ALL;
		/* The column is narrow and a region word is short; a label
		 * long enough to overrun it is one that would not have fit
		 * on the row either. */
		snprintf(d->rgn, sizeof d->rgn, "%.23s",
			 rn->mask ? rn->label : "WHOLE-FILE");
	}
	d->grp = 0;
	/* Not on a symbol row: there `lo` is a block offset and this field is
	 * a file offset. decl_locate sets it from the search either way. */
	d->at = n->sym ? KOF_BROKEN : view_map(v, lo, 0);
	(void)g;
	v->warn[0] = 0;
	v->sel_decl = v->n_decl;
	v->n_decl++;
	/*
	 * LOCATED, like every other path that produces a declaration.
	 *
	 * `at` was set straight from the selection and n_hits/cur_hit/at_mask
	 * left at zero, so a marker just taken from the pane showed no "n/m"
	 * occurrence count and no [<]/[>] step arrows - those are gated on
	 * n_hits > 1 - however many times its bytes appear. It looked like a
	 * marker that occurs once until the reader pressed "Update string
	 * regions", which is a thing they had no reason to press.
	 */
	decl_locate(v, &v->decl[v->n_decl - 1u]);

	/* The selection has been taken; leaving it lit would invite taking it
	 * twice. */
	v->sel_a = v->sel_b = KOF_BROKEN;
}

static void menu_run(struct view *v, int a)
{
	uint64_t lo, hi, k, n;
	struct out t = { 0 };

	if (!menu_enabled(v, a))
		return;
	if (a == M_COPY_OFF_HEX || a == M_COPY_OFF_DEC) {
		copy_offset(v, a == M_COPY_OFF_HEX);
		v->menu_open = 0;
		return;
	}
	if (a == M_DECL_STR || a == M_DECL_HEX) {
		decl_add(v, a == M_DECL_HEX);
		v->menu_open = 0;
		return;
	}
	if (a == M_COPY_DISASM) {
		dis_copy(v);
		v->menu_open = 0;
		return;
	}
	if (a == M_DISASM) {
		v->dis_open = 0;                /* so the toggle opens */
		if (v->sel_a == KOF_BROKEN) {
			/* Nothing picked: the whole region, unpinned, exactly
			 * as the menu bar opens it. */
			dis_toggle(v, 0, KOF_BROKEN);
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
		v->warn[0] = 0;
		return;
	}
	if (a == M_FIND_STR || a == M_FIND_HEX) {
		v->find_hex = a == M_FIND_HEX;
		v->goto_open = 0;      /* they share the box - see draw_goto */
		v->find[0] = 0;
		v->find_at = KOF_BROKEN;
		v->find_open = 1;
		v->edit = 500;
		v->menu_open = 0;
		v->warn[0] = 0;
		return;
	}
	lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
	hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;
	n = hi - lo + 1u;

	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);

	for (k = 0; k < n; k++) {
		uint64_t bf = view_map(v, lo + k, 0);
		uint8_t c = (bp && bf < bn) ? bp[bf] : 0;

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
	if (t.n) {
		copy_osc52(t.p, t.n);
		copy_said(v, t.n);
	}
	free(t.p);
	v->menu_open = 0;
}

/*
 * The frame that is already on the screen.
 *
 * Repainting is skipped when the new frame is byte for byte the last one, which
 * is what stops button-event tracking from rewriting the screen with what it
 * already says at every report of a pointer that has not left the byte it was
 * on.
 *
 * This used to be a hand-kept list of the fields a frame depends on, and that
 * list did what such lists do: a condition added to the draft moved nothing the
 * list watched, so the screen did not repaint and the button looked dead while
 * quietly working - the clicks landed, and several conditions appeared at once
 * the moment something else moved. Comparing the picture instead cannot fall
 * behind a field, because the picture is the only thing that has to be right.
 */
static char  *g_last;
static size_t g_last_n;

static void draw_find(struct out *o, struct view *v);
static void draw_goto(struct out *o, struct view *v);
static int  goto_click(struct view *v);
static void draw_symbols(struct out *o, struct view *v);
static int  symd_click(struct view *v);
static void symd_scroll(struct view *v, int64_t d);
static void symd_clamp(struct view *v);
static void symd_open(struct view *v);
static void draw_bar(struct out *o, struct view *v);
static void draw_help(struct out *o, struct view *v);
static void draw_prop(struct out *o, struct view *v);
/* Used by prop_build to measure a row it has just written - see prop_cp_row. */
static uint32_t prop_plain(const char *s, char *out, uint32_t cap);

/* The properties page was up on the frame before this one. */
static int g_prop_drawn;

static void redraw(struct view *v)
{
	struct out o = { 0 };
	int wiped = 0, under;

	g_fld.room = 0;
	term_size();
	if (g_winch) {
		/*
		 * The cached frame describes a screen of the old size, and the
		 * terminal has thrown away whatever was on it. Comparing
		 * against it would let an unchanged frame skip the repaint and
		 * leave the screen as the resize left it.
		 */
		g_winch = 0;
		free(g_last);
		g_last = NULL;
		g_last_n = 0;
		term_write("\033[2J");
		wiped = 1;
	}
	/* The panes are laid out around the draft, so its height is settled
	 * before anything asks where it is. */
	{
		/* Groups and their markers, plus the header - capped so the
		 * panel cannot eat the pane it is about. */
		/* How tall the draft is, counted where it is drawn rather than
		 * restated here: the two used to be separate sums, and the one
		 * that fell behind was always this one. */
		uint32_t want;

		prow_build(v);
		want = v->n_prow;

		/*
		 * A draft that just grew shows its new end.
		 *
		 * What was added is the thing being worked on, and it arrives
		 * at the bottom. Keeping the top pinned meant the row you asked
		 * for appeared off the bottom of a panel that looked unchanged,
		 * which reads as the button having done nothing.
		 */
		if (v->n_prow > v->prow_seen)
			v->prow_off = 0xffffffffu;      /* clamped below */
		v->prow_seen = v->n_prow;

		/* Two more than the rows it shows: the heading it starts with
		 * and the rule it ends on, which is what puts a border between
		 * the draft and the status line. */
		/*
		 * Always present, empty or not.
		 *
		 * The family, the type and the generate button live on its
		 * first row, and hiding the whole panel until something had
		 * been declared meant none of them could be reached until
		 * after the first string was taken - the one order of work the
		 * tool happened to be built around.
		 */
		g_decl_rows = (int)(want < v->decl_cap ? want : v->decl_cap)
			      + 2;
		if (g_decl_rows) {
			/* The furthest it can be scrolled, computed before the
			 * comparison rather than inside it: adding the window
			 * to the offset overflows when the offset is the "show
			 * me the end" sentinel, and an offset of minus one
			 * draws every row one line too low. */
			uint32_t vis = (uint32_t)(g_decl_rows - 2);
			uint32_t max_off = v->n_prow > vis ? v->n_prow - vis
							   : 0u;

			if (v->prow_off > max_off)
				v->prow_off = max_off;
		}
	}

	/*
	 * Synchronised output, DEC mode 2026.
	 *
	 * A frame is one write, but a terminal is free to render what it has
	 * received so far - so a screen rewritten row by row is briefly a screen
	 * half old and half new. This asks it to hold the picture until the
	 * frame is complete. Terminals that do not know the mode ignore it,
	 * which is why it can be sent unconditionally.
	 */
	/*
	 * A full-screen modal paints alone.
	 *
	 * The three panes underneath are 15KB of a 16KB frame and every byte of
	 * them is overdrawn by the box a moment later. Synchronised output is
	 * supposed to make that invisible and does, on a terminal that honours
	 * mode 2026 - on one that does not, a write that large is rendered in
	 * pieces and the pieces are the panes being painted before the box
	 * covers them. That is the flash, and it showed up while scrolling
	 * because scrolling is when frames come fastest.
	 *
	 * So they are skipped while the page is up, and drawn on the frame
	 * it OPENS on: that one still has to erase the menu the reader opened
	 * it from, and nothing under a modal can change afterwards because the
	 * modal has the keyboard.
	 */
	under = !v->prop_open || wiped || !g_prop_drawn;
	g_prop_drawn = v->prop_open;

	/*
	 * The panel's height, settled before anything is drawn because every
	 * geometry helper below reads it. Half of what the hex column has, and
	 * never so much that the hex is left with less than the panel.
	 */
	/*
	 * The symbol view takes the whole column.
	 *
	 * The panel disassembles the bytes the hex pane is showing, and this
	 * view is showing none: leaving it open would reserve its rows, cost
	 * the table a third of its height, and fill them with the last region's
	 * instructions - which would read as a disassembly OF THE SYMBOLS.
	 * dis_open itself is left alone, so the panel is still there when the
	 * reader moves back to a region.
	 */
	if (v->dis_open && !sym_view(v)) {
		int room = hex_bot() - hex_top() + 1;

		dis_follow_hex(v);
		int want_rows = room / 2;

		if (want_rows < DIS_MIN_ROWS)
			want_rows = DIS_MIN_ROWS;
		/* Two rows for the hex to keep, plus the heading. */
		if (want_rows > room - 3)
			want_rows = room - 3;
		g_disasm_rows = want_rows > 0 ? want_rows : 0;
		if (!g_disasm_rows)
			v->dis_open = 0;   /* nowhere to put it */
	} else {
		g_disasm_rows = 0;
	}

	out_str(&o, "\033[?2026h");
	if (under) {
		draw_frame(&o, v);
		draw_tree(&o, v);
		draw_hex(&o, v);
		draw_disasm(&o, v);
		draw_decl(&o, v);
		draw_marker_line(&o, v);
		if (v->show_list)
			draw_list(&o, v);
		if (v->menu_open)
			draw_menu(&o, v);
		draw_bar(&o, v);
		if (v->find_open)
			draw_find(&o, v);
		if (v->goto_open)
			draw_goto(&o, v);
		if (v->sym_open)
			draw_symbols(&o, v);
	}
	if (v->prop_open)
		draw_prop(&o, v);
	if (v->help_open)
		draw_help(&o, v);
	draw_chooser(&o, v);
	out_str(&o, "\033[?2026l");

	/* Nothing moved: the frame is the one already on the screen. */
	if (o.n && o.n == g_last_n && !memcmp(o.p, g_last, o.n)) {
		free(o.p);
		return;
	}
	if (o.n) {
		char *keep = realloc(g_last, o.n);

		if (keep) {
			memcpy(keep, o.p, o.n);
			g_last = keep;
			g_last_n = o.n;
		}
	}
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

	if (row < hex_top() || row > hex_last())
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

/*
 * The region row of `obj` that contains `file_off`, or the object row when none
 * does.
 *
 * A marker's region is a property of the bytes, not of what the tree cursor
 * happened to be sitting on when they were taken: selecting a string that is
 * plainly inside DATA and having it recorded as whole-file is the tree's state
 * leaking into the draft. Prefers a region over the whole-object row, because
 * the narrower answer is the one that makes the scan cheaper.
 */
static uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off)
{
	uint32_t k, best = v->n_node;

	for (k = 0; k < v->n_node; k++) {
		uint32_t n, j;

		if (v->node[k].obj != obj)
			continue;
		if (!v->node[k].mask) {
			if (best == v->n_node)
				best = k;               /* the object row */
			continue;
		}
		/* A symbol half is not in the file, so no file offset is ever
		 * in it and the resolver has nothing to say about the bit. */
		if (v->node[k].mask & KOF_SCAN_SYM)
			continue;
		n = kof_scan_resolve_range(&v->obj[obj].ctx, v->node[k].mask,
					   v->probe);
		for (j = 0; j < n; j++)
			if (file_off >= v->probe[j].off &&
			    file_off < v->probe[j].off + v->probe[j].len)
				return k;
	}
	return best;
}

static void view_show(struct view *v, uint64_t file_off);

/*
 * Jump to where a DECLARATION sits, whichever space that is in.
 *
 * A marker scoped to a symbol half has offsets into the built block, so the
 * file-offset jump below cannot be given one: view_unmap would read it as a
 * distance into the file and land on whatever region sits there - UNCLAIMED,
 * on the sample this was found with - which is a real address showing real
 * bytes, and none of them the marker's. So the tree moves to that half's row
 * first and the offset is used directly, the way view_map already treats a
 * symbol row.
 */
static void view_show_in(struct view *v, uint32_t obj, uint8_t sym,
			 uint64_t off)
{
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t r, row;
	uint32_t k;

	if (!sym) {
		view_show(v, off);
		return;
	}
	for (k = 0; k < v->n_node; k++)
		if (v->node[k].obj == obj && v->node[k].sym == sym)
			break;
	if (k >= v->n_node)
		return;                 /* this object has no such half */
	if (k != v->sel_node) {
		v->node[v->sel_node].at = v->rgn_at;
		v->sel_node = k;
		view_select(v);
	}
	/* The row has extents now, so a block offset places in it the same way
	 * a file offset places in a region. */
	r = view_unmap(v, off);
	if (r == KOF_BROKEN)
		return;
	row = r / per;
	v->rgn_at = row > JUMP_LEAD ? (row - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

static void view_show_decl(struct view *v, const struct decl *d, uint64_t off)
{
	view_show_in(v, d->obj, d->sym, off);
}

static void view_show(struct view *v, uint64_t file_off)
{
	uint64_t r = view_unmap(v, file_off);
	uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);
	uint64_t row;

	/*
	 * The offset may not be in the region being looked at.
	 *
	 * A marker is chosen from a list that belongs to the OBJECT, and the
	 * tree may be sitting on a region that does not contain it - in which
	 * case there was nowhere to scroll to and the jump did nothing at all.
	 * So the tree moves first, to a row of this object that holds the
	 * offset, preferring a region over the whole-object row: the narrower
	 * answer is the more useful place to land.
	 */
	if (r == KOF_BROKEN) {
		uint32_t best = node_at(v, v->node[v->sel_node].obj, file_off);

		if (best >= v->n_node)
			return;
		v->node[v->sel_node].at = v->rgn_at;
		v->sel_node = best;
		view_select(v);
		r = view_unmap(v, file_off);
		if (r == KOF_BROKEN)
			return;
	}
	row = r / per;
	v->rgn_at = row > JUMP_LEAD ? (row - JUMP_LEAD) * per : 0;
	if (v->rgn_at > hex_max(v))
		v->rgn_at = hex_max(v);
}

/* ---- search --------------------------------------------------------------- */

/* One hex digit, or -1. */
static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * The pattern as bytes.
 *
 * Hex is read two digits at a time and whitespace between them is ignored, so a
 * pattern pasted out of a hex dump works without editing. An odd digit at the
 * end is dropped rather than padded: half a byte is not a byte, and guessing
 * which half would make the search quietly wrong.
 */
static uint32_t find_bytes(const struct view *v, uint8_t *out, uint32_t cap)
{
	uint32_t n = 0;
	const char *p;

	if (!v->find_hex) {
		for (p = v->find; *p && n < cap; p++)
			out[n++] = (uint8_t)*p;
		return n;
	}
	for (p = v->find; *p && n < cap; ) {
		int hi, lo;

		while (*p == ' ' || *p == '\t')
			p++;
		hi = hexval(*p);
		if (hi < 0)
			break;
		p++;
		while (*p == ' ' || *p == '\t')
			p++;
		lo = hexval(*p);
		if (lo < 0)
			break;
		p++;
		out[n++] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

/*
 * The next occurrence at or after `from`, as a file offset.
 *
 * Searched over the object's bytes rather than over the region being looked at,
 * because the region is a view and the answer is a place in the file. Which of
 * the two the caller wanted is `find_scope`: within one region the hits outside
 * it are skipped, which is not the same as searching a copy of the region -
 * a pattern lying across two extents of one region is in neither of them, and
 * this reports it where it is rather than inventing a join.
 */
static uint64_t find_next(struct view *v, uint64_t from)
{
	uint8_t pat[64];
	uint32_t n = find_bytes(v, pat, sizeof pat);
	/*
	 * WHAT THE PANE IS SHOWING, which on a symbol row is not the file.
	 *
	 * This searched the object's bytes and then dropped any hit that
	 * view_unmap could not place in the region being looked at. A symbol
	 * row has no extents to place anything in, so EVERY hit was dropped
	 * and the search reported "no match" about a marker that is plainly on
	 * the screen - and would have been wrong the other way too, since the
	 * block's layout is ours and its records are nowhere in the file.
	 *
	 * So the search runs over whatever the row is showing. On a symbol row
	 * that makes the answer an offset into the block, which is exactly
	 * what view_map returns there, so everything downstream already agrees.
	 */
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	uint64_t i;

	if (!n || !bp || n > bn)
		return KOF_BROKEN;
	for (i = from; i + n <= bn; i++) {
		uint32_t k;

		for (k = 0; k < n; k++) {
			uint8_t a = bp[i + k], b = pat[k];

			/* Only for text: a hex pattern names bytes, and two
			 * bytes are equal or they are not. */
			if (v->find_icase && !v->find_hex) {
				if (a >= 'A' && a <= 'Z')
					a = (uint8_t)(a - 'A' + 'a');
				if (b >= 'A' && b <= 'Z')
					b = (uint8_t)(b - 'A' + 'a');
			}
			if (a != b)
				break;
		}
		if (k != n)
			continue;
		/* No exception for a symbol row any more: it has extents like
		 * any other, so a hit outside the half being looked at is
		 * skipped the same way. */
		if (v->find_scope == 0 && view_unmap(v, i) == KOF_BROKEN)
			continue;       /* present, but not in this region */
		return i;
	}
	return KOF_BROKEN;
}

/*
 * The last occurrence strictly before `before`.
 *
 * Written as a forward scan that keeps the best answer rather than a reverse
 * one: the match test is the same in both directions and only one of them has
 * to be right.
 */
static uint64_t find_prev(struct view *v, uint64_t before)
{
	uint64_t at = 0, best = KOF_BROKEN, hit;

	for (;;) {
		hit = find_next(v, at);
		if (hit == KOF_BROKEN || hit >= before)
			break;
		best = hit;
		at = hit + 1u;
	}
	return best;
}

/* Run the search, wrapping once at whichever end it reaches. */
static void find_run(struct view *v, int back)
{
	uint64_t at;

	if (back) {
		uint64_t before = v->find_at == KOF_BROKEN ? 0 : v->find_at;

		at = before ? find_prev(v, before) : KOF_BROKEN;
		if (at == KOF_BROKEN) {
			uint64_t bn = 0;

			(void)view_bytes(v, &bn);
			at = find_prev(v, bn);                  /* wrap */
		}
	} else {
		uint64_t start = v->find_at == KOF_BROKEN ? 0
							  : v->find_at + 1u;

		at = find_next(v, start);
		if (at == KOF_BROKEN && start)
			at = find_next(v, 0);           /* wrap */
	}
	if (at == KOF_BROKEN) {
		snprintf(v->find_msg, sizeof v->find_msg, "no match");
		v->find_i = v->find_n = 0;
		return;
	}
	v->find_msg[0] = 0;
	v->find_at = at;
	/*
	 * Which hit this is, counted rather than tracked.
	 *
	 * Kept as a count over the whole object every time instead of a number
	 * carried between searches: the scope, the case folding and the pattern
	 * can all change between one search and the next, and a carried index
	 * would then be counting something that no longer exists.
	 */
	{
		uint64_t p = 0, h;

		v->find_i = v->find_n = 0;
		for (;;) {
			h = find_next(v, p);
			if (h == KOF_BROKEN)
				break;
			v->find_n++;
			if (h == at)
				v->find_i = v->find_n;
			p = h + 1u;
		}
	}
	/* The search ran over whatever the row shows, so the hit is an offset in
	 * that space - view_show alone would fall back to placing it in the
	 * file when the row is a symbol half. */
	view_show_in(v, v->node[v->sel_node].obj, v->node[v->sel_node].sym, at);
	{
		uint64_t r = view_unmap(v, at);

		if (r != KOF_BROKEN) {
			uint8_t pat[64];
			uint32_t n = find_bytes(v, pat, sizeof pat);

			v->sel_a = r;
			v->sel_b = n ? r + n - 1u : r;
		}
	}
}

/* ---- the menu bar ---------------------------------------------------------
 *
 * One row at the top, and the place every command has a name.
 *
 * The context menu on the hex pane stays: it acts on what is under the pointer
 * and is worth having there. This is for the commands that act on the whole
 * session - opening, saving, searching, and the two Help dialogs - which have
 * nowhere else to be discovered. Nothing here is only reachable from here; the
 * chords still work, and the bar is where somebody finds out that they exist.
 */
/*
 * THERE IS NO ANALYSE MENU, AND THAT IS A DECISION.
 *
 * It held Strings and Symbols, and neither has anything behind it. The engine's
 * parsers are shallow on purpose: for a PE they record the sixteen data
 * directories as an RVA and a size and walk none of them, so IMPORT is an index
 * rather than a table; for an ELF they record section names and never read
 * .dynsym or resolve a string table. A symbol list would therefore not be a
 * view of something the engine knows - it would be two new walkers over
 * untrusted structures, written in the front end, duplicating the layer that
 * deliberately stops short of them.
 *
 * What the tool CAN say about an object is what the engine already worked out,
 * and that is one page rather than a menu of them. So it is one item, under
 * File, next to the other things that are about the file in hand.
 */
enum bar_menu {
	BM_FILE = 0, BM_EDIT, BM_ANALYSIS,
	/*
	 * Moving between files, apart from Analysis.
	 *
	 * Stepping to the next sample is not an analysis of the one on screen -
	 * it is leaving it - and having it sit under the same heading as
	 * Dashboard and Dump meant the one item in there that discards work was
	 * filed with the two that only look at things.
	 */
	BM_SWITCH,
	BM_HELP, BM_COUNT
};

/*
 * Dump, next to them, because it is about this file too.
 *
 * The same directory kofexamine --dump writes, from the same code - see
 * kof_dump_object. Here because the viewer is where the question comes up: a
 * region is what the parse decided rather than anything on disk, so the way to
 * check what a rule will actually search is to have the bytes of that region in
 * a file. Reaching for a second tool to get them, on the object already open and
 * already parsed, was the gap.
 *
 * It writes the WHOLE tree - the file and everything the unpackers recovered
 * from it - not the selected node, and that is deliberate. The objects are
 * already collected and already parsed, so dumping one of them and making
 * somebody come back for the next is a menu item that has to be used repeatedly
 * to do one thing.
 */
enum bar_item {
	BI_OPEN = 0, BI_SAVE, BI_SAVE_AS, BI_QUIT,
	BI_FIND, BI_GOTO,
	/*
	 * Analysis is what the tool does TO an object, as against File which is
	 * what it does to the draft. Dashboard and Dump both answer questions
	 * about the bytes in front of the reader and neither writes a signature,
	 * so they belong together and not beside Save.
	 */
	/*
	 * ANALYSIS, in the order a reader works through it: what the object IS,
	 * then what is inside it, then what to DO about it. The rule after
	 * BI_FINDSC is where that turns over - everything above answers a
	 * question, everything below writes something or re-runs the scan.
	 */
	BI_DASH,
	BI_SYMS,
	/* Label replaced at draw time by the mode's own wording - a menu that
	 * offers "Show" and "Hide" side by side always has one of them wrong. */
	BI_DISASM,
	/*
	 * What a heuristic already found, shown on demand.
	 *
	 * It runs nothing: the rule ran during the scan and reported where the
	 * payload is, so this item only displays what is already known. See
	 * bases/heur/scloader_00.c and on_debug.
	 */
	BI_FINDSC,
	BI_UNPACKER,
	BI_DUMP, BI_DUMP_STATIC, BI_DUMP_EMU,
	BI_REBUILD,
	BI_NEXT, BI_PREV,
	BI_KEYS, BI_ABOUT,
	BI_COUNT
};

static const struct {
	const char *label;
	int         menu;
	/* The item this one hangs under, or -1 for a top-level entry. */
	int         parent;
	/*
	 * Draw a rule ABOVE this item.
	 *
	 * On the item BELOW the break rather than the one above it, so
	 * appending to a group does not move the break - which is the
	 * mistake the other spelling invites.
	 *
	 * BOTH the drawer and the hit test must count the extra row. They
	 * are two separate walks over this table and they have disagreed
	 * before - see the note on bar_col - so the row comes from one
	 * helper, bar_gap, that both call.
	 */
	int         sep;
} bar_item[BI_COUNT] = {
	{ "Open...",        BM_FILE, -1, 0 },
	{ "Save",           BM_FILE, -1, 0 },
	{ "Save As...",     BM_FILE, -1, 0 },
	{ "Quit",           BM_FILE, -1, 0 },
	{ "Find...",        BM_EDIT, -1, 0 },
	{ "Go to...",       BM_EDIT, -1, 0 },
	{ "Dashboard",         BM_ANALYSIS, -1, 0 },
	{ "Symbols",           BM_ANALYSIS, -1, 0 },
	{ "Disassembly",       BM_ANALYSIS, -1, 0 },
	{ "Find shellcode in variables", BM_ANALYSIS, -1, 0 },
	{ "Use ... unpacker",  BM_ANALYSIS, -1, 1 },
	{ "Dump",              BM_ANALYSIS, -1, 0 },
	{ "Static unpacker",   BM_ANALYSIS, BI_DUMP, 0 },
	{ "Emu unpacker",      BM_ANALYSIS, BI_DUMP, 0 },
	{ "Rebuild database",  BM_ANALYSIS, -1, 0 },
	/*
	 * "Next" and "Previous", not "Next file" and "Previous file": the menu
	 * they are in is called Switch-File, and repeating the noun in every
	 * item under it is the sort of label that reads like a form.
	 */
	{ "Next",              BM_SWITCH, -1, 0 },
	{ "Previous",          BM_SWITCH, -1, 0 },
	{ "Keyboard",          BM_HELP, -1, 0 },
	{ "About",          BM_HELP, -1, 0 }
};

/* Does this item open a submenu rather than do something. */
static int bar_has_sub(int i)
{
	int k;

	for (k = 0; k < BI_COUNT; k++)
		if (bar_item[k].parent == i)
			return 1;
	return 0;
}

/*
 * The wording an item shows now, which for the unpacker switch is not the
 * wording in the table: a menu entry should say what pressing it does, and what
 * it does depends on which unpacker filled the tree.
 */
static const char *bar_label(struct view *v, int i)
{
	/*
	 * "Use X unpacker", naming the tool that will open the file.
	 *
	 * Two earlier wordings were worse in the same way. "Reopen with"
	 * named the mechanism rather than the result. "Examine with emulator"
	 * named the result but read as though the menu would open the emulator
	 * and show its insides - when what changes is only which unpacker is in
	 * front of the same object. What the reader picks here is who does the
	 * opening, and the label now says exactly that.
	 *
	 * "Emu" rather than "emulator" because the column is narrow and the
	 * word is one a researcher reads without expanding.
	 */
	if (i == BI_UNPACKER) {
		(void)v;
		return "Use Emu unpacker";
	}
	/* Says which way the toggle goes, for the reason above. */
	if (i == BI_DISASM)
		return v->dis_open ? "Hide disassembly" : "Show disassembly";
	return bar_item[i].label;
}

static const char *const bar_name[BM_COUNT] = {
	/*
	 * Hyphenated, because the bar is a row of single words and a title with
	 * a space in it reads as two of them - "Switch" and "File" - which is a
	 * menu that does not exist next to a menu that does.
	 */
	"File", "Edit", "Analysis", "Switch-File", "Help"
};

/*
 * Is an item offered at all, for THIS object.
 *
 * Analysis is where that matters: symbols belong to an executable and a zip has
 * none, so the menu is built from the object in hand rather than from a fixed
 * list. An item that cannot apply is drawn greyed rather than removed, because a
 * menu whose length changes as you move between objects is one you cannot learn.
 */
static int bar_shown(struct view *v, int i)
{
	(void)v;
	return i >= 0 && i < BI_COUNT;
}

/*
 * How many rows this item takes before its own: 1 for a rule above it, else 0.
 *
 * One function, called by BOTH the drawer and the hit test, because they are
 * two walks over the same table and the whole class of bug here is one of them
 * counting a row the other does not. See the note on bar_col for the last time
 * that happened.
 */
static int bar_gap(struct view *v, int i)
{
	return (i > 0 && bar_item[i].sep && bar_shown(v, i)) ? 1 : 0;
}

static int bar_enabled(struct view *v, int i)
{
	switch (i) {
	case BI_OPEN:      return 0;            /* no way in yet */
	case BI_SAVE:      return save_ok(v);
	case BI_SAVE_AS:   return save_as_ok(v);
	/* Off for a viewer that has no file behind it, which is the one case
	 * where there is nowhere for a dump to go: the directory is named after
	 * the file and placed beside it. */
	/* The parent is live whenever either of its children could be. */
	case BI_DUMP:      return v->path && v->path[0];
	case BI_DUMP_STATIC:
	case BI_DUMP_EMU:
		/*
		 * Both may have to rebuild the tree to write the view they
		 * name, and rebuilding it throws the draft away - the same
		 * reason stepping to another file is refused with one open.
		 */
		return v->path && v->path[0] && !draft_edited(v);
	case BI_UNPACKER:  return v->path && v->path[0] && !draft_edited(v);
	/*
	 * x86 only, because bddisasm decodes x86 and nothing else - offering it
	 * on an ARM object would print an answer that is wrong in a way a reader
	 * cannot see. An object with no format at all IS offered: raw bytes out
	 * of an encoder are exactly what this is for, and the mode is then the
	 * reader's to pick.
	 */
	case BI_DISASM: {
		struct object *ob = cur_obj(v);

		if (!ob || !ob->buf.p || !v->rgn_len)
			return 0;
		return !ob->fmt || ob->ctx.arch == KOF_ARCH_X86 ||
		       ob->ctx.arch == KOF_ARCH_X86_64;
	}
	case BI_DASH:      return 1;
	/* Needs a file to step from, and nothing the reader typed that would be
	 * lost - moving on is the one action here that throws work away. */
	case BI_NEXT:
	case BI_PREV:      return v->path && v->path[0] && !draft_edited(v);
	/*
	 * Rebuilding replaces the database this file was examined against, so
	 * the file is examined again - which throws the draft away for the same
	 * reason stepping to another file does.
	 */
	case BI_REBUILD:   return v->basedir[0] && v->dbdir[0] &&
				  !draft_edited(v);
	case BI_QUIT:      return 1;
	case BI_FIND:      return 1;
	case BI_GOTO:      return 1;            /* draw_goto / goto_take */
	/*
	 * Offered only when there is a table to show. An object with neither
	 * half - a PE, or a fully stripped ELF - would open a dialog with two
	 * empty tabs, which is a worse answer than a greyed item: the grey says
	 * the tool looked and found nothing, the empty box says it might not
	 * have looked.
	 */
	/*
	 * Always offered on an object, because BOTH answers are answers.
	 *
	 * Greying it when nothing was found would make "this file carries no
	 * payload" indistinguishable from "this build cannot look" - and the
	 * reader who wants to know is exactly the one who has not looked yet.
	 * The item costs nothing to run: the rule ran during the scan and this
	 * only reports what it said.
	 */
	case BI_FINDSC:    return 1;
	case BI_SYMS: {
		const struct object *o = cur_obj(v);

		return kof_sym_count(o->sym, o->sym_n) != 0;
	}
	case BI_KEYS:
	case BI_ABOUT:     return 1;
	default:           return 0;
	}
}


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
#define BAR_ON   "\033[100;97m"    /* an item that can be used */
#define BAR_OFF  "\033[100;37m"    /* the same panel, dimmer text */
#define BAR_CUR  "\033[107;30m"    /* the row under the cursor */

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
 * Where each menu's block starts on the bar.
 *
 * Derived from what draw_bar actually emits - a space, the name, a space - not
 * from a guess at it. They disagreed by one column per menu, so Help's title sat
 * at 25 while everything that used this number thought it was at 27: its
 * drop-down opened three columns to the right of the word it belongs to, and
 * clicking the left half of "Help" opened Analysis instead.
 */
static int bar_col(int m)
{
	int c = 2, i;

	for (i = 0; i < m; i++)
		c += (int)strlen(bar_name[i]) + 2;
	return c;
}

static void draw_bar(struct out *o, struct view *v)
{
	int m, i, y, bar_sub_row = 0;

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

	/* The drop-down, drawn over whatever is under it. */
	y = 2;
	for (i = 0; i < BI_COUNT; i++) {
		int col = bar_col(v->bar_open);

		if (bar_item[i].menu != v->bar_open || bar_item[i].parent >= 0 ||
		    !bar_shown(v, i))
			continue;
		if (bar_gap(v, i)) {
			int k;

			/* On the panel's own background, so the break reads as
			 * part of the menu rather than a line drawn over it. */
			out_at(o, y, col);
			out_str(o, BAR_ON " ");
			/* U+2500 written out, because G_H is defined with the
			 * dialog glyphs further down and the bar is drawn
			 * before them - the same reason scrollbar() spells its
			 * U+2502 this way. */
			for (k = 0; k < BAR_W - 2; k++)
				out_glyph(o, "\xe2\x94\x80");
			out_str(o, " " A_OFF);
			y++;
		}
		out_at(o, y, col);
		if (i == v->bar_sel || i == v->bar_sub)
			out_str(o, BAR_CUR);
		else if (!bar_enabled(v, i))
			out_str(o, BAR_OFF);
		else
			out_str(o, BAR_ON);
		/*
		 * An item that opens something says so. Without the marker the
		 * two kinds of entry are indistinguishable until one is
		 * pressed, and one of them appears to do nothing.
		 */
		if (bar_has_sub(i))
			out_fmt(o, " %-*s>", BAR_W - 2, bar_label(v, i));
		else
			out_fmt(o, " %-*s", BAR_W - 1, bar_label(v, i));
		out_str(o, A_OFF);
		if (i == v->bar_sub)
			bar_sub_row = y;
		y++;
	}

	/* The open submenu, beside its parent rather than over it. */
	if (v->bar_sub >= 0 && bar_sub_row > 0) {
		int col = bar_col(v->bar_open) + BAR_W;

		y = bar_sub_row;
		for (i = 0; i < BI_COUNT; i++) {
			if (bar_item[i].parent != v->bar_sub || !bar_shown(v, i))
				continue;
			out_at(o, y, col);
			out_str(o, i == v->bar_sel ? BAR_CUR
				   : bar_enabled(v, i) ? BAR_ON : BAR_OFF);
			out_fmt(o, " %-*s", BAR_W - 1, bar_label(v, i));
			out_str(o, A_OFF);
			y++;
		}
	}
}

/*
 * Which item a click on an open drop-down landed on, or -1.
 *
 * The submenu is tested FIRST. It is drawn over whatever is to the right of its
 * parent, so a click inside it is inside the submenu whatever else is there -
 * testing the parent panel first would answer for a column the reader cannot
 * see.
 */
static int bar_item_at(struct view *v, int row, int col)
{
	int y = 2, i, c0 = bar_col(v->bar_open), sub_row = 0;

	for (i = 0; i < BI_COUNT; i++) {
		if (bar_item[i].menu != v->bar_open || bar_item[i].parent >= 0 ||
		    !bar_shown(v, i))
			continue;
		y += bar_gap(v, i);
		if (i == v->bar_sub)
			sub_row = y;
		y++;
	}
	if (v->bar_sub >= 0 && sub_row > 0 &&
	    col >= c0 + BAR_W && col < c0 + 2 * BAR_W) {
		y = sub_row;
		for (i = 0; i < BI_COUNT; i++) {
			if (bar_item[i].parent != v->bar_sub || !bar_shown(v, i))
				continue;
			if (row == y)
				return i;
			y++;
		}
		return -1;
	}
	if (col < c0 || col >= c0 + BAR_W)
		return -1;
	y = 2;
	for (i = 0; i < BI_COUNT; i++) {
		if (bar_item[i].menu != v->bar_open || bar_item[i].parent >= 0 ||
		    !bar_shown(v, i))
			continue;
		/* The rule's own row belongs to nothing: a click on it must not
		 * land on the item under it, which is what skipping the row
		 * without testing it achieves. */
		y += bar_gap(v, i);
		if (row == y)
			return i;
		y++;
	}
	return -1;
}


/* The two Help dialogs. Drawn like the find box: content, then the frame. */
static void draw_help(struct out *o, struct view *v)
{
	/*
	 * Only what somebody would not think to try.
	 *
	 * The arrows, the click, the double click, the right click and the
	 * wheel were listed here and have been taken out: they do what they do
	 * everywhere else, and a help page that spends half its rows on them
	 * buries the four or five things that are actually particular to this
	 * program.
	 */
	static const char *const keys[] = {
		/*
		 * F10 first, and on a row of its own.
		 *
		 * It is the only way into the menu bar, and the one key here a
		 * reader is least likely to try: every other row is a chord
		 * they already know from somewhere else. Alt does not open it -
		 * a terminal cannot report a bare modifier - so this row is the
		 * whole answer to "where is the menu".
		 */
		"F10        the menu bar",    "Esc        leave it",
		"Ctrl+F     find",            "Ctrl+N     next match",
		"Ctrl+C     copy the field",  "Ctrl+V     paste",
		"Ctrl+O     open a file",     "Ctrl+Q     quit",
		"Ctrl+]     next file",       "Ctrl+\\     previous file",
		"Tab        next pane",       "m          the marker list"
	};
	static const char *const about[] = {
		"KOFViewer - the engine's view of a file, navigable.",
		"",
		"Three panes over one object: the tree of what the engine",
		"found in it, the bytes, and the signature being drafted",
		"from them. What the database already knows is on the",
		"status line; what you are writing is below the rule.",
		"",
		"Part of KOFENG."
	};
	const char *const *line = v->help_open == 1 ? keys : about;
	int n = v->help_open == 1 ? (int)(sizeof keys / sizeof keys[0])
				  : (int)(sizeof about / sizeof about[0]);
	int h = n + 4, top = (g_rows - h) / 2, w = 60, left, y, i;

	if (top < 2)
		top = 2;
	left = (g_cols - w) / 2;
	if (left < 2)
		left = 2;

	for (y = top; y < top + h; y++) {
		out_at(o, y, left);
		out_str(o, A_DIM);
		if (y == top || y == top + h - 1) {
			out_str(o, "+");
			for (i = 1; i < w - 1; i++)
				out_str(o, "-");
			out_str(o, "+" A_OFF);
			continue;
		}
		out_str(o, "|");
		for (i = 1; i < w - 1; i++)
			out_str(o, " ");
		out_str(o, "|" A_OFF);
	}
	out_at(o, top + 1, left + 2);
	out_fmt(o, A_ID "%s" A_OFF,
		v->help_open == 1 ? "Keyboard" : "About");
	for (i = 0; i < n; i++) {
		out_at(o, top + 3 + i, left + 2);
		out_fmt(o, A_DIM "%-.*s" A_OFF, w - 4, line[i]);
	}
	out_at(o, top + h - 1, left + 2);
	out_fmt(o, A_DIM " press any key " A_OFF);
}

/* ---- the properties page --------------------------------------------------------
 *
 * What the engine knows about this object, on one scrollable page.
 *
 * The same facts kofexamine prints, and deliberately the same facts: a
 * researcher who has read one should recognise the other, and two tools over
 * one engine disagreeing about what a file is would be worse than either of
 * them missing something. What differs is only that this one can be scrolled
 * and the other one scrolls past.
 *
 * Built as lines rather than drawn directly, because scrolling a page is a
 * window over a list and painting one is not. The per-format blocks are the
 * point of the whole thing - an ELF has segments and a zip has entries, and a
 * page that shows neither because it shows only what they have in common is a
 * page nobody opens twice.
 */
#define PROP_MAX  600
#define PROP_W    200

struct prop_line {
	char        text[PROP_W];
	const char *col;
};

static struct prop_line g_prop[PROP_MAX];
static uint32_t         g_n_prop;

static void prop_add(const char *col, const char *fmt, ...)
{
	va_list ap;

	if (g_n_prop >= PROP_MAX)
		return;
	va_start(ap, fmt);
	vsnprintf(g_prop[g_n_prop].text, PROP_W, fmt, ap);
	va_end(ap);
	g_prop[g_n_prop].col = col;
	g_n_prop++;
}

/* A heading, with a blank line above it unless it opens the page. */
static void prop_head(const char *w)
{
	if (g_n_prop)
		prop_add(A_DIM, "%s", "");
	prop_add(A_OFF, A_BOLD "%s" A_OFF, w);
}

static void prop_perm(char *out, size_t cap, unsigned p)
{
	snprintf(out, cap, "%c%c%c", (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-',
		 (p & 1) ? 'X' : '-');
}

/* "9 of 9 declared", and the count that did not add up said as such. */
static void prop_claimed(const char *label, uint32_t have, uint32_t claimed)
{
	prop_add(A_OFF, A_DIM "  %-11s " A_OFF "%s%u of %u" A_OFF A_DIM
		 " declared" A_OFF, label,
		 have == claimed ? A_SIZE : A_WARN, have, claimed);
}

static void prop_elf(const struct object *ob)
{
	const struct kof_elf_info *e = ob->info;
	char perm[4];
	uint32_t i;

	prop_head("ELF");
	prop_add(A_OFF, A_DIM "  %-11s " A_ID "%s %s" A_OFF A_DIM
		 "   type=" A_OFF A_SIZE "%u" A_OFF A_DIM " machine=" A_OFF
		 A_SIZE "%u" A_OFF, "class",
		 e->elf_class == KOF_ELFCLASS_64 ? "ELF64" : "ELF32",
		 e->elf_data == KOF_ELFDATA_BE ? "big-endian"
					       : "little-endian",
		 e->e_type, e->e_machine);
	prop_perm(perm, sizeof perm, e->entry_perm);
	prop_add(A_OFF, A_DIM "  %-11s " A_LOC "0x%llx" A_OFF A_DIM
		 "  file " A_OFF A_LOC "%llu" A_OFF "  " A_ID "%s" A_OFF,
		 "entry", (unsigned long long)e->entry_addr,
		 (unsigned long long)ob->ctx.entry_off, perm);

	prop_claimed("segments", e->phnum, e->phnum_claimed);
	for (i = 0; i < e->seg_count; i++) {
		const char *w = kof_inspect_ptype_name(e->seg[i].type);
		char num[24];

		if (!w) {
			snprintf(num, sizeof num, "%u", e->seg[i].type);
			w = num;
		}
		prop_perm(perm, sizeof perm, e->seg[i].perm);
		prop_add(A_OFF, "     " A_ID "%-16s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "%-9llu" A_OFF A_DIM "size=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM "vaddr=" A_OFF A_LOC
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
			snprintf(num, sizeof num, "%u", e->sec[i].type);
			w = num;
		}
		prop_add(A_OFF, "     " A_ID "%-20s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "%-9llu" A_OFF A_DIM "size=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM " %s" A_OFF,
			 e->sec[i].name,
			 (unsigned long long)e->sec[i].file_off,
			 (unsigned long long)e->sec[i].file_size, w);
	}
}

static void prop_pe(const struct object *ob)
{
	const struct kof_pe_info *p = ob->info;
	char perm[4];
	uint32_t i;

	prop_head("PE");
	prop_add(A_OFF, A_DIM "  %-11s " A_ID "%s" A_OFF A_DIM "  machine="
	 A_OFF A_LOC "0x%04x" A_OFF A_DIM " characteristics=" A_OFF A_LOC
	 "0x%04x" A_OFF, "image", p->pe32_plus ? "PE32+" : "PE32", p->machine,
	 p->characteristics);
	prop_add(A_OFF, A_DIM "  %-11s lfanew=" A_OFF A_LOC "%llu" A_OFF A_DIM
		 "  gap=" A_OFF A_SIZE "%llu" A_OFF, "stub",
		 (unsigned long long)p->lfanew,
		 (unsigned long long)p->stub_len);
	prop_add(A_OFF, A_DIM "  %-11s end=" A_OFF A_LOC "%llu" A_OFF A_DIM
		 "  declared=" A_OFF A_SIZE "%llu" A_OFF, "headers",
		 (unsigned long long)p->header_end,
		 (unsigned long long)p->size_of_headers);
	prop_perm(perm, sizeof perm, p->entry_perm);
	prop_add(A_OFF, A_DIM "  %-11s rva=" A_OFF A_LOC "0x%llx" A_OFF A_DIM
		 "  file " A_OFF A_LOC "%llu" A_OFF A_DIM "  sec=" A_OFF A_ID
		 "%s" A_OFF "  " A_ID "%s" A_OFF, "entry",
		 (unsigned long long)p->entry_rva,
		 (unsigned long long)ob->ctx.entry_off,
		 p->entry_sec < p->sec_count ? p->sec[p->entry_sec].name
					     : "none", perm);
	prop_add(A_OFF, A_DIM "  %-11s code=" A_OFF A_SIZE "%llu" A_OFF A_DIM
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
		prop_add(A_OFF, A_DIM "  %-11s off=" A_OFF A_LOC "%llu" A_OFF
			 A_DIM "  len=" A_OFF A_SIZE "%llu" A_OFF, "signature",
			 (unsigned long long)p->cert_off,
			 (unsigned long long)p->cert_len);
	if (p->overlay_len)
		prop_add(A_OFF, A_WARN "  %-11s" A_OFF A_DIM " off=" A_OFF A_LOC
			 "%llu" A_OFF A_DIM "  len=" A_OFF A_WARN "%llu" A_OFF,
			 "overlay", (unsigned long long)p->overlay_off,
			 (unsigned long long)p->overlay_len);
	prop_claimed("sections", p->nsec, p->nsec_claimed);
	for (i = 0; i < p->sec_count; i++) {
		prop_perm(perm, sizeof perm, p->sec[i].perm);
		prop_add(A_OFF, "     " A_ID "%-9s" A_OFF A_DIM " off=" A_OFF
			 A_LOC "%-9llu" A_OFF A_DIM "raw=" A_OFF A_SIZE
			 "%-9llu" A_OFF A_DIM "rva=" A_OFF A_LOC "0x%-8llx"
			 A_OFF A_DIM "vsz=" A_OFF A_LOC "0x%-8llx" A_OFF A_ID
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
static uint32_t obj_ancestors(const struct view *v, const struct object *ob,
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

/*
 * One object's identity, as rows.
 *
 * Shared by the object being looked at and by every object above it, so the two
 * cannot describe the same thing differently - the reason this is a function
 * and not a second copy of the block.
 *
 * `full` is what separates them. The object in focus gets a row per fact,
 * because that is what the panel is for. An enclosing object gets size, format
 * and arch folded onto one line: a chain four deep would otherwise be
 * twenty-four rows of context above the thing somebody actually opened.
 */
static void prop_object_rows(struct view *v, const struct object *ob, int full)
{
	const char *base = strrchr(ob->name, '/');
	const char *sub = ob->fmt ? kof_inspect_subtype_name(ob->ctx.format,
							     ob->ctx.subtype)
				  : NULL;
	const char *fmt = ob->fmt ? kof_format_name(ob->ctx.format) : "raw";
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
	if (ob->payload_of && ob->payload_sym[0])
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF
			 A_DIM "   from " A_OFF A_BAD "%s" A_OFF "%s",
			 "name", base, ob->payload_sym,
			 ob->payload_b64 ? A_DIM "  (base64 undone)" A_OFF
					 : "");
	else
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
			 "name", base);

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
		const char *slash = strrchr(v->path, '/');

		/* Ending in a separator, always: a directory row and a name row
		 * sit one above the other in the same column, and without it the
		 * last component reads as another file name. */
		if (!slash) {
			snprintf(dir, sizeof dir, "./");
		} else {
			size_t n = (size_t)(slash - v->path) + 1u;

			if (n >= sizeof dir)
				n = sizeof dir - 1u;
			memcpy(dir, v->path, n);
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
		static const char lab[] = "[ Copy full path ]";
		char plain[PROP_W];
		const char *at;

		v->prop_cp_row = (int32_t)g_n_prop;
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_LOC "%s" A_OFF
			 "  \033[47;30m%s" A_OFF, "folder", dir, lab);
		/*
		 * Measured off the RENDERED row, not counted by hand: the row
		 * is built by a format string with colour escapes in it, and a
		 * column computed from the format drifts the moment the format
		 * changes. prop_plain strips the escapes, which is the same
		 * thing the click path does to find what it selected.
		 */
		prop_plain(g_prop[v->prop_cp_row].text, plain, sizeof plain);
		at = strstr(plain, lab);
		if (at) {
			v->prop_cp_x0 = (int)(at - plain);
			v->prop_cp_x1 = v->prop_cp_x0 + (int)sizeof lab - 2;
		} else {
			v->prop_cp_row = -1;   /* did not fit: no button */
		}
	}

	if (full) {
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_SIZE "%llu" A_OFF
			 A_DIM " bytes" A_OFF, "size",
			 (unsigned long long)ob->buf.n);
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s%s%s" A_OFF,
			 "format", fmt, sub ? " " : "", sub ? sub : "");
		if (ob->fmt)
			prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF,
				 "arch", kof_arch_name(ob->ctx.arch));
	} else {
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_SIZE "%llu" A_OFF
			 A_DIM " bytes   " A_OFF A_ID "%s%s%s%s%s" A_OFF,
			 "size", (unsigned long long)ob->buf.n, fmt,
			 sub ? " " : "", sub ? sub : "",
			 ob->fmt ? " " : "",
			 ob->fmt ? kof_arch_name(ob->ctx.arch) : "");
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
	if (ob->packer[0])
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF "%s%s" A_OFF,
			 top ? "opened by" : "unpacked by",
			 (ob->heur.from_packer ||
			  (ob->heur.heur_flags &
			   KOF_HEUR_FL(KOF_HEUR_F_PACKED))) ? A_BAD : A_WARN,
			 ob->packer);
}

static void prop_build(struct view *v)
{
	struct object *ob = cur_obj(v);
	const char *base = strrchr(ob->name, '/');
	uint32_t i, hit = 0;
	uint64_t total = 0;

	g_n_prop = 0;
	v->prop_cp_row = -1;
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

	if (ob->fmt && ob->info) {
		if (ob->ctx.format == KOF_FMT_ELF)
			prop_elf(ob);
		else if (ob->ctx.format == KOF_FMT_PE)
			prop_pe(ob);
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
			prop_add(A_OFF, A_DIM "  %-11s no parser divides this "
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
		prop_add(A_OFF, "  " A_ID "%-11s" A_OFF A_SIZE "%-10llu" A_OFF
			 A_LOC "%5.1f%%" A_OFF, n->label,
			 (unsigned long long)n->bytes,
			 total ? 100.0 * (double)n->bytes / (double)total : 0.0);
	}
	if (total != ob->buf.n)
		prop_add(A_BAD, "  %-11s regions sum to %llu of %llu",
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
		prop_add(A_WARN, "  RECONSTRUCTED_%s-%s_SHELLCODE",
			 ob->fmt ? kof_format_name(ob->ctx.format) : "RAW",
			 ob->fmt ? kof_arch_name(ob->ctx.arch) : "?");
	} else if (ob->fmt && ob->info && ob->fmt->anomalies) {
		uint64_t anom = ob->fmt->anomalies(ob->info);

		if (!anom)
			prop_add(A_DIM, "  none");
		for (i = 0; i < 64; i++) {
			const char *an;

			if (!(anom >> i & 1))
				continue;
			an = ob->fmt->anomaly_name(i);
			if (an)
				prop_add(A_BAD, "  %s", an);
			else
				prop_add(A_BAD, "  bit%u", i);
		}
	} else {
		prop_add(A_DIM, "  no parser claimed these bytes");
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
		if (ob->packer[0] && ob->packer_ver >= 0)
			prop_add(A_OFF, "  %-11s " A_BAD "%s" A_OFF A_DIM
				 "  v%lld" A_OFF, "unpacker", ob->packer,
				 ob->packer_ver);
		else if (ob->packer[0])
			prop_add(A_OFF, "  %-11s " A_BAD "%s" A_OFF,
				 "unpacker", ob->packer);
		else
			prop_add(A_OFF, "  %-11s %s%s" A_OFF A_DIM "  %s" A_OFF,
				 "verdict",
				 ob->emu_why == KOF_EMU_UNP_WHY_DENSE
				 ? A_BAD : A_WARN,
				 emu_why_tag(ob->emu_why),
				 emu_why_reason(ob->emu_why));
		if (!ob->packer[0])
			prop_add(A_DIM,
				 "  %-11s Analysis > Examine with emulator",
				 "try");
	}

	{
		const struct kof_heur_model *hm = kof_heur_default();
		struct kof_heur_facts hf;
		const char *guess = "Unknown";
		int32_t sc = 0;
		uint32_t k;

		prop_head("Heuristic");
		if (!heur_of(ob, &hf, &sc, &guess)) {
			prop_add(A_DIM, "  no model for this format - not scored");
		} else {
			prop_add(A_OFF, "  %-11s %s%d" A_OFF A_DIM
				 "  of %d to report" A_OFF, "score",
				 sc >= hm->bar_centinats ? A_BAD : A_SIZE,
				 sc, hm->bar_centinats);
			if (sc >= hm->bar_centinats)
				prop_add(A_BAD, "  %-11s %s", "verdict", guess);
			for (k = 0; k < hm->n_anom; k++)
				if (hm->anom[k].format == hf.format &&
				    (hf.anomalies & hm->anom[k].mask))
					prop_add(A_OFF, "     %s+%-6d" A_OFF
						 A_DIM " %s" A_OFF, A_WARN,
						 hm->anom[k].centinats,
						 hm->anom[k].guess);
			for (k = 0; k < hm->n_flag; k++)
				if (hf.flags & KOF_HEUR_FL(hm->flag[k].fact))
					prop_add(A_OFF, "     %s+%-6d" A_OFF
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
	prop_add(A_OFF, "  %s%u" A_OFF A_DIM " matched, " A_OFF A_SIZE "%u"
		 A_OFF A_DIM " skipped" A_OFF, hit ? A_BAD : A_SIZE, hit,
		 ob->n_touch - hit);
	for (i = 0; i < ob->n_touch; i++) {
		const struct kof_touch *t = &ob->touch[i];
		char name[80], head[24];

		touch_name(t, name, sizeof name);
		touch_head(t, head, sizeof head);
		prop_add(A_OFF, "  %s%-44s" A_OFF A_SIZE "%-10s" A_OFF A_WARN
			 "%s" A_OFF, t->fired ? A_BAD : A_ID, name, head,
			 t->kind == KOF_TOUCH_INELIGIBLE && t->ruled_out
			 ? t->ruled_out : "");
	}
}

/*
 * One line onto the screen, colours and all.
 *
 * The lines carry their own SGR because the page is a table of different
 * KINDS of fact - a name, an offset, a size - and one colour per row cannot say
 * which is which. printf's "%-.*s" cannot be used on them: it would count the
 * escape bytes as width and cut a line off in the middle of one, so the width
 * is counted here over printable columns only, the same way field_draw does it.
 */
/*
 * One property line without its colours, so it can be copied.
 *
 * The stored line carries the escapes it is painted with, and those are the
 * reason a page full of facts was a page you had to retype: a selection made
 * with the terminal's own mouse takes the box rules and the neighbouring column
 * with it, and the escapes are invisible until they are pasted somewhere.
 *
 * Column for column with prop_put, deliberately - it is the same walk with
 * out_str replaced by a store - so a click at screen column N lands on the
 * character this writes at index N. Two walks that disagreed would put the word
 * under the cursor one place away from the word that gets copied.
 */
/*
 * WHERE ONE VALUE ENDS AND THE NEXT BEGINS ON THIS PAGE.
 *
 * Not whitespace alone. The page is written as key=value pairs packed on one
 * line - "off=624 size=28 vaddr=0x400270 perm=R--" - so a word bounded only by
 * spaces is the whole pair, and clicking the number handed back "size=28" when
 * the number was the point. Breaking on "=" as well makes each half selectable
 * on its own, which is what a reader clicking a number means.
 *
 * The comma is here for the same reason and the colon is NOT: an offset written
 * "0x400270" has no colon, but a name might, and splitting a name is worse than
 * making somebody drag.
 */
static int prop_break(char c)
{
	return c == ' ' || c == '\t' || c == '=' || c == ',';
}

static uint32_t prop_plain(const char *s, char *out, uint32_t cap)
{
	uint32_t n = 0;

	while (*s) {
		if (*s == '\033') {
			while (*s && *s != 'm')
				s++;
			if (*s)
				s++;
			continue;
		}
		if (n + 1u < cap)
			out[n++] = *s;
		s++;
	}
	out[n] = 0;
	while (n && out[n - 1u] == ' ')
		out[--n] = 0;
	return n;
}

static void prop_put(struct out *o, const char *s, int room, int sa, int sb)
{
	int n = 0, inv = 0;

	while (*s && n < room) {
		if (*s == '\033') {
			const char *e = s;
			char t[32];
			size_t l;

			while (*e && *e != 'm')
				e++;
			if (*e)
				e++;
			l = (size_t)(e - s);
			if (l < sizeof t) {
				memcpy(t, s, l);
				t[l] = 0;
				out_str(o, t);
			}
			s = e;
			continue;
		}
		{
			char t[2];
			int want = sa >= 0 && n >= sa && n <= sb;

			/* The reverse is turned on and off around the run
			 * rather than per character: the line carries its own
			 * colours and re-emitting them inside a reversed span
			 * would cancel it halfway. */
			if (want != inv) {
				out_str(o, want ? A_SEL : A_OFF);
				inv = want;
			}
			t[0] = *s++;
			t[1] = 0;
			out_str(o, t);
			n++;
		}
	}
	out_str(o, A_OFF);
	while (n++ < room)
		out_str(o, " ");
}

/*
 * The page, as a window over the lines.
 *
 * Near full screen on purpose: the sections below the fold are the ones a
 * reader has to go looking for, and a small box would put every section but the
 * first one there.
 *
 * The chrome carries what the chrome is for. Which lines are on screen goes on
 * the bottom rule, where a reader looks for their position in a document; the
 * way out goes top right, where a window's close control is. Neither is a line
 * of the page: a row spent telling you which keys work is a row not spent on
 * the file, and it says the same thing every time you open it.
 */
static void draw_prop(struct out *o, struct view *v)
{
	int top = 2, left = 2, w = g_cols - 4, h = g_rows - 3, y, i;
	int room, inner;
	uint32_t shown;
	char pos[48];
	static const char close[] = "[ Close ]";

	if (w < 30 || h < 6)
		return;
	prop_build(v);
	room = h - 2;
	if (room < 1)
		room = 1;
	inner = w - 4;
	if (g_n_prop > (uint32_t)room) {
		if (v->prop_off > g_n_prop - (uint32_t)room)
			v->prop_off = g_n_prop - (uint32_t)room;
	} else {
		v->prop_off = 0;
	}
	shown = g_n_prop - v->prop_off;
	if (shown > (uint32_t)room)
		shown = (uint32_t)room;


	/* The top rule: the title, then a run of rule, then the way out. */
	out_at(o, top, left);
	out_fmt(o, A_DIM "+- " A_OFF A_BOLD "Properties" A_OFF A_DIM " ");
	v->prop_y = top;
	v->prop_x1 = left + w - 3;
	v->prop_x0 = v->prop_x1 - (int)sizeof close + 2;
	for (i = left + 15; i < v->prop_x0 - 1; i++)
		out_str(o, "-");
	out_str(o, " " A_OFF);
	out_str(o, "\033[47;30m");
	out_str(o, close);
	out_fmt(o, A_OFF A_DIM "-+" A_OFF);

	/*
	 * The bottom rule: where in the page this window is, and what the last
	 * click on it copied.
	 *
	 * The copy note is HERE and not in the status bar, and that is forced
	 * rather than chosen: while this page is up the rows under it are not
	 * repainted - see `under` in draw() - so a message written to the status
	 * line would not appear until the page was closed, by which time it is
	 * about something the reader can no longer see.
	 */
	snprintf(pos, sizeof pos, "%u-%u of %u", v->prop_off + 1u,
		 v->prop_off + shown, g_n_prop);
	out_at(o, top + h - 1, left);
	out_fmt(o, A_DIM "+- %s ", pos);
	i = 4 + (int)strlen(pos);
	if (v->act_msg[0]) {
		int fit = w - 3 - i - 2;

		if (fit > 12) {
			out_fmt(o, A_OFF "%s%.*s" A_OFF A_DIM " ",
				v->act_ok ? A_SIZE : A_WARN, fit,
				v->act_msg);
			i += (int)strlen(v->act_msg) > fit
			   ? fit + 1 : (int)strlen(v->act_msg) + 1;
		}
	}
	for (; i < w - 1; i++)
		out_str(o, "-");
	out_fmt(o, "+" A_OFF);

	/*
	 * One pass per row: the left rule, the line, the right rule.
	 *
	 * It used to blank every interior row and then draw the content over
	 * the blanks, which painted the whole box twice per frame for no
	 * visible difference - and the frame is the thing that has to stay
	 * small, because a large one is what tears.
	 */
	for (y = 0; y < h - 2; y++) {
		out_at(o, top + 1 + y, left);
		out_str(o, A_DIM "|" A_OFF " ");
		if (y < (int)shown) {
			uint32_t idx = v->prop_off + (uint32_t)y;
			int sa = -1, sb = -1;

			if ((int32_t)idx == v->prop_sel_row) {
				sa = v->prop_sel_a < v->prop_sel_b
				   ? v->prop_sel_a : v->prop_sel_b;
				sb = v->prop_sel_a < v->prop_sel_b
				   ? v->prop_sel_b : v->prop_sel_a;
			}
			prop_put(o, g_prop[idx].text, inner, sa, sb);
		}
		else
			for (i = 0; i < inner; i++)
				out_str(o, " ");
		out_str(o, " " A_DIM "|" A_OFF);
	}
}

/*
 * Write the file and everything recovered from it, the way kofexamine --dump
 * would have.
 *
 * The objects are the ones already collected and already parsed, so nothing is
 * scanned again: object 0 is the file and gets the dump directory itself; every
 * other one is something an unpacker produced and gets unpacked.<n>[.<label>]
 * beside it, plus a .regions directory of its own. That numbering is
 * kofexamine's, and it is the same because a researcher who dumps from both
 * should not have to learn where the same bytes went twice.
 *
 * An object the session could not keep - past the budget, so `too_big` - has no
 * bytes here to write. It is counted and named rather than skipped silently,
 * because a dump missing one of its objects looks exactly like a dump of an
 * object that was never there.
 */
/* The status bar has one line and a dump directory sits beside a path that can
 * be any length, so the message names the directory and not the road to it. */
static const char *base_name(const char *path)
{
	const char *s = strrchr(path, '/');

	return s ? s + 1 : path;
}

/* Re-opening is how the tree is rebuilt, and both dumping and switching
 * unpacker need it. Declared here because both come before it. */
static int file_open(struct view *v, const char *path, kof_engine *eng);

/*
 * See the note on BI_UNPACKER: the interpreter, on the selected object.
 *
 * The children it produces are named under that object's own name, so the
 * engine's "//n" convention puts them in the tree exactly where they belong and
 * tree_build needs to know nothing about where they came from.
 */
static void emu_here(struct view *v)
{
	struct object *o = cur_obj(v);
	struct kof_scan_option opt;
	kof_scanner *sc;
	uint32_t before = v->n_obj;

	v->act_ok = 0;
	if (!v->eng) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No database to unpack with");
		return;
	}
	if (!o->buf.p || !o->buf.n) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Object's bytes were not kept");
		return;
	}
	if (o->emu_done) {
		/*
		 * Not an error and not silence: the reader pressed a button and
		 * is owed an answer, and the answer is that this one has been
		 * asked already. Whatever it produced is in the tree below.
		 */
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Emu has already run on this");
		return;
	}
	sc = kof_scanner_new(v->eng);
	if (!sc) {
		snprintf(v->act_msg, sizeof v->act_msg, "Out of memory");
		return;
	}
	/*
	 * SAID BEFORE IT STARTS, AND WRITTEN STRAIGHT TO THE STATUS ROW.
	 *
	 * Interpreting an object takes as long as it takes - seconds on
	 * anything large - and the loop does not come back round until it is
	 * over, so without this the screen sits unchanged and the reader cannot
	 * tell a slow answer from a program that has stopped responding.
	 *
	 * Not a redraw. A full frame is a few kilobytes of escape sequences to
	 * say one thing that fits in the corner, and the frame it would paint
	 * is the one already on the screen. Just the notice, where the result
	 * will appear a moment later.
	 */
	{
		char note[64];
		int at;

		snprintf(note, sizeof note, " Unpacking with Emu... ");
		at = g_cols - (int)strlen(note);
		if (at < 1)
			at = 1;
		{
			char seq[128];
			int n = snprintf(seq, sizeof seq,
					 "\033[%d;%dH" A_WARN "%s" A_OFF,
					 mark_row(), at, note);

			if (n > 0)
				term_write_n(seq, (size_t)n);
		}
	}
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	/* The same level as the ordinary collect - see the note there. A node
	 * re-examined through the interpreter must not lose the heuristics the
	 * first pass would have run on it. */
	opt.heur_level = KOF_HEUR_LEVEL_MAX;
	/*
	 * ONLY, because the reader asked for the interpreter by name. AUTO
	 * would decline the moment a packer module claimed the object - which
	 * on this node it already has, or the node would not be here.
	 */
	opt.emu_use = KOF_EMU_ONLY;
	v->pending_ver = -1;
	v->skip_root = 1;
	kof_scanner_on_debug(sc, on_debug, v);
	kof_scan_bytes(sc, o->buf.p, o->buf.n, o->name, &opt, on_object, v);
	kof_scanner_free(sc);
	v->skip_root = 0;
	/*
	 * Marked whatever came of it. A run that recovered nothing has still
	 * been made, and repeating it would spend the same instructions to
	 * print the same sentence.
	 *
	 * Re-read rather than kept from before the scan: on_object may have
	 * grown v->obj, and a realloc'd array leaves the old pointer dangling.
	 */
	o = &v->obj[v->node[v->sel_node].obj];
	o->emu_done = 1;

	if (v->n_obj == before) {
		/*
		 * A reason, and a short one. Which header field disagreed with
		 * which is a question for the dashboard; here there is one line
		 * and the reader wants to know whether to try something else.
		 */
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Emu recovered nothing");
		return;
	}
	objects_examine_from(v, v->eng, before);
	tree_build(v);
	view_select(v);
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg,
		 "Unpacked %u object(s)", v->n_obj - before);
}

/*
 * SAY WHAT THE REOPEN ACTUALLY PRODUCED, not that a reopen happened.
 *
 * "reopened, unpacked by the emulator" is true of a file the emulator could not
 * touch and of one it took apart, and on the first the reader is left looking
 * at a tree one deep with nothing to say why. The engine already worked out the
 * why - it is on the object, in the same field a truncated archive uses - so
 * this reads it back rather than inventing a second account of it.
 *
 * The common case is worth spelling out: a UPX sample cut short has no entry
 * point left in it, because the stub sits past the compressed data. The static
 * unpacker still recovers the prefix by reading structure; there is nothing for
 * an interpreter to start.
 */
static void say_unpacked(struct view *v)
{
	const char *who = v->emu_mode ? "emulator" : "static unpacker";
	uint32_t kids = v->n_obj ? v->n_obj - 1u : 0;

	v->act_ok = kids != 0;
	/*
	 * No "reopened" prefix. The tree changing under the reader is the one
	 * part they can already see, and the status line is narrow enough that
	 * spending ten columns on it truncated away the REASON - which is the
	 * only part they cannot work out for themselves.
	 */
	if (kids) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%s: recovered %u object(s)", who, kids);
		return;
	}
	if (v->n_obj && v->obj[0].broken) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%s: nothing - %s", who,
			 kof_broken_name(v->obj[0].broken));
		return;
	}
	snprintf(v->act_msg, sizeof v->act_msg,
		 "%s: nothing to open here", who);
}

/*
 * Write the object tree out, from the unpacker named.
 *
 * The tree on screen is what one unpacker made of the file, so dumping the
 * OTHER one's view means rebuilding the tree first - and then what was written
 * is what is on screen, which is the only version of this a reader can check.
 * Producing a directory that does not match the view would be worse than
 * making them ask twice.
 *
 * The directories differ by an _emu suffix so both can exist at once. That is
 * the point of having two: the static unpacker and the interpreter disagreeing
 * about the same file is a finding, and it cannot be seen if one overwrites the
 * other.
 */
static void dump_all(struct view *v, int use_emu)
{
	char dir[KOF_DUMP_PATH_ROOM], sub[KOF_DUMP_PATH_ROOM], why[256];
	struct kof_dump_stat ds;
	uint32_t i, files = 0, kids = 0, skipped = 0;
	uint64_t bytes = 0;

	v->act_ok = 0;
	if (use_emu != (v->emu_mode != 0)) {
		char keep[KOF_DUMP_PATH_ROOM];

		snprintf(keep, sizeof keep, "%s", v->path);
		v->emu_mode = use_emu;
		if (!file_open(v, keep, v->eng))
			return;         /* file_open left the reason */
	}
	/*
	 * Whatever the dump goes on to say, the reader has just had the tree
	 * replaced under them and is owed the reason it looks the way it does.
	 * Written first so a dump message overwrites it - the dump is what they
	 * asked for - and left standing when the dump writes nothing at all.
	 */
	say_unpacked(v);
	if (!kof_dump_dir_for(v->path, dir, sizeof dir)) {
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No dump: path too long");
		return;
	}
	if (use_emu) {
		size_t at = strlen(dir);

		if (at + 5 > sizeof dir) {
			snprintf(v->act_msg, sizeof v->act_msg,
				 "No dump: path too long");
			return;
		}
		memcpy(dir + at, "_emu", 5);
	}
	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];
		const char *into = dir;

		if (o->too_big || !o->buf.n) {
			skipped++;
			continue;
		}
		if (i) {
			/* <number>.<label>, or the number alone. The number is
			 * the identity; the label is there so a directory
			 * listing reads, and the engine already reduced it to a
			 * printable basename - so nothing here has to decide
			 * what to do about a separator or a "..". */
			const char *lab = strrchr(o->name, ':');
			char tag[80];

			if (lab && lab[1])
				snprintf(tag, sizeof tag, "%u.%s", i, lab + 1);
			else
				snprintf(tag, sizeof tag, "%u", i);
			if (!kof_dump_child(dir, tag, o->buf.p, o->buf.n, sub,
					    sizeof sub, why, sizeof why)) {
				snprintf(v->act_msg, sizeof v->act_msg,
					 "Dump stopped: %.120s", why);
				return;
			}
			kids++;
			into = sub;
		}
		if (!kof_dump_object(into, o->buf, o->fmt, &o->ctx, &ds, why,
				     sizeof why)) {
			snprintf(v->act_msg, sizeof v->act_msg,
				 "Dump stopped: %.120s", why);
			return;
		}
		files += ds.regions;
		bytes += ds.region_bytes;
	}

	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg,
		 "Dumped %u region(s), %llu B, %u recovered -> %.60s%s",
		 files, (unsigned long long)bytes, kids, base_name(dir),
		 skipped ? "  (some too large to hold)" : "");
}

/*
 * THE NEXT FILE IN THE SAME DIRECTORY, BY RE-EXEC.
 *
 * Reading a directory of samples one after another is how this tool is used, and
 * quitting and retyping a path between each one is most of the work. This is that
 * loop.
 *
 * Re-exec rather than tearing the view down and rebuilding it, and that is a
 * deliberate trade. Every pointer in the view - the mapping, the object tree, the
 * touch lists, the draft - belongs to one file, and unwinding them in the right
 * order to load another is a page of code whose bugs would all be use-after-free.
 * exec hands the problem to the kernel: the process is replaced, nothing leaks,
 * and every option the viewer was started with survives because argv does.
 *
 * The cost is honest and small: the database is loaded again. That is a second on
 * a large one, against a rewrite that could lose somebody's draft.
 */
/* Defined with the rest of the session's lifetime, at the foot of this file. */


/*
 * The file next to this one in its directory, in either direction.
 *
 * `dir` is +1 for the next name and -1 for the one before it. Ordering is by
 * name rather than by whatever readdir hands back, so stepping forward and then
 * back returns to where it started - which is the only property that makes a
 * pair of these usable as a way of walking a sample directory.
 *
 * Directories, empty files and anything that cannot be stat'ed are skipped
 * rather than ending the walk: a sample directory routinely holds a README and
 * a subdirectory of notes, and stopping at one would put the rest out of reach.
 *
 * Returns 0 and leaves a message when there is nothing that way.
 */
static int neighbour_file(struct view *v, int dir, char *out, size_t cap)
{
	char folder[KOF_DUMP_PATH_ROOM], best[KOF_DUMP_PATH_ROOM];
	const char *base = base_name(v->path);
	size_t lead = (size_t)(base - v->path);
	DIR *d;
	struct dirent *e;
	int found = 0;

	if (lead + 1 >= sizeof folder)
		return 0;
	if (lead) {
		memcpy(folder, v->path, lead);
		folder[lead ? lead - 1 : 0] = 0;   /* drop the separator */
	}
	if (!lead || !folder[0])
		snprintf(folder, sizeof folder, ".");

	d = opendir(folder);
	if (!d) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Cannot read %.60s", folder);
		return 0;
	}
	while ((e = readdir(d)) != NULL) {
		char cand[KOF_DUMP_PATH_ROOM];
		struct stat st;
		int rel = strcmp(e->d_name, base);

		/* On the wrong side of where we are, or where we already are. */
		if (dir > 0 ? rel <= 0 : rel >= 0)
			continue;
		/* Further away than the best so far: nearest wins, which for
		 * "next" is the smallest name above and for "previous" is the
		 * largest name below. */
		if (found) {
			int cmp = strcmp(e->d_name, base_name(best));

			if (dir > 0 ? cmp >= 0 : cmp <= 0)
				continue;
		}
		if ((size_t)snprintf(cand, sizeof cand, "%s/%s", folder,
				     e->d_name) >= sizeof cand)
			continue;
		if (stat(cand, &st) != 0 || !S_ISREG(st.st_mode) ||
		    st.st_size <= 0)
			continue;
		snprintf(best, sizeof best, "%s", cand);
		found = 1;
	}
	closedir(d);

	if (!found) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg, "%.50s is the %s file here",
			 base, dir > 0 ? "last" : "first");
		return 0;
	}
	snprintf(out, cap, "%s", best);
	return 1;
}

/*
 * Step to the neighbouring file.
 *
 * This used to re-exec the program, because the view was full of pointers whose
 * lifetime was one file. It now hands the path to file_open, which keeps the
 * engine - so stepping through a directory of samples no longer reloads the
 * database once per file, and the terminal never leaves raw mode.
 */
static void open_step(struct view *v, int dir)
{
	char next[KOF_DUMP_PATH_ROOM];

	if (!neighbour_file(v, dir, next, sizeof next))
		return;
	if (!file_open(v, next, v->eng))
		return;                 /* file_open left the reason */
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg, "Opened %.60s",
		 base_name(v->path));
}

/*
 * Rebuild the signature database and pick it up, without leaving.
 *
 *
 * WHY IT SHELLS OUT TO make
 *
 * Building a database is two stages and neither is small. Each source is
 * compiled freestanding, then checked for relocations and for writable state,
 * then linked to raw bytes - that is ksigcompiler.sh, seven hundred lines of it
 * wrapped around five tools - and only then does ksigbuilder pack the artefacts.
 * A second implementation of that inside a viewer would be a second thing to
 * keep in step with the first, and the first is where the checks live.
 *
 * So this runs the build that already exists, in the tree it belongs to.
 *
 *
 * FINDING THE TREE
 *
 * Upwards from the bases directory, to the first level holding a Makefile. That
 * is the directory the sources are part of, which is a better answer than the
 * working directory: a viewer started from somewhere else would otherwise
 * rebuild whatever tree it happened to be standing in, or nothing at all.
 *
 *
 * WHAT IT DOES AFTERWARDS
 *
 * Closes the engine, opens the new one, and re-opens the file. Re-opening is
 * the point rather than a side effect: the reason to rebuild from in here is to
 * see whether the rule just written fires, and an engine swapped in under a
 * result computed against the old one would still show the old answer.
 *
 * The build's own output goes to a file and only its last line is shown - a
 * compiler diagnostic is what the reader needs, and the rest of a build log is
 * not, on a status line one row tall.
 */
static int tree_root_of(const char *bases, char *out, size_t cap)
{
	char at[KOF_DUMP_PATH_ROOM];

	if (!realpath(bases, at)) {
		/* A bases directory that does not exist yet is legal - generate
		 * creates it - so fall back to where this was started. */
		if (!getcwd(at, sizeof at))
			return 0;
	}
	for (;;) {
		char mk[KOF_DUMP_PATH_ROOM];
		struct stat st;
		char *slash;

		if ((size_t)snprintf(mk, sizeof mk, "%s/Makefile", at) <
		    sizeof mk && stat(mk, &st) == 0 && S_ISREG(st.st_mode)) {
			size_t n = strlen(at);

			if (n >= cap)
				return 0;
			memcpy(out, at, n + 1u);
			return 1;
		}
		slash = strrchr(at, '/');
		if (!slash || slash == at)
			return 0;
		*slash = 0;
	}
}

static void build_last_line(const char *log, char *out, size_t cap)
{
	FILE *f = fopen(log, "r");
	char line[200];

	out[0] = 0;
	if (!f)
		return;
	while (fgets(line, sizeof line, f)) {
		size_t n = strlen(line);

		while (n && (line[n - 1u] == 10 || line[n - 1u] == 13))
			line[--n] = 0;
		if (n)
			snprintf(out, cap, "%s", line);
	}
	fclose(f);
}

static void rebuild_db(struct view *v)
{
	char root[KOF_DUMP_PATH_ROOM];
	char log[] = "/tmp/kofviewer-build-XXXXXX";
	char here[KOF_DUMP_PATH_ROOM];
	kof_engine *fresh, *old;
	pid_t pid;
	int fd, status = -1;

	if (!tree_root_of(v->basedir, root, sizeof root)) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "No Makefile above %.50s", v->basedir);
		return;
	}
	/* The path to reopen, taken before the file is closed under us. */
	snprintf(here, sizeof here, "%s", v->path);

	fd = mkstemp(log);
	if (fd < 0) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Cannot make a log file");
		return;
	}

	pid = fork();
	if (pid == 0) {
		/* Writable, because execvp takes char *const[] and a string
		 * literal is not one. The same shape the clipboard fork in
		 * this file uses, and for the same reason. */
		static char a0[] = "make", a1[] = "databases";
		char *const args[] = { a0, a1, NULL };

		if (chdir(root) != 0)
			_exit(127);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
		execvp("make", args);
		_exit(127);
	}
	close(fd);
	if (pid < 0) {
		unlink(log);
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg, "Cannot start make");
		return;
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
		char last[200];

		build_last_line(log, last, sizeof last);
		unlink(log);
		v->act_ok = 0;
		if (last[0])
			snprintf(v->act_msg, sizeof v->act_msg,
				 "Build failed: %.130s", last);
		else
			snprintf(v->act_msg, sizeof v->act_msg, "Build failed");
		return;
	}
	unlink(log);

	/*
	 * THE ORDER HERE IS THE WHOLE OF THE CARE.
	 *
	 * A kof_touch holds borrowed pointers into the engine - the module, the
	 * family, every variant name - so the old engine must outlive everything
	 * derived from it, and the swap must not leave the view holding either
	 * half of a torn state.
	 *
	 * So: build the new engine first; hand it to file_open, which tears the
	 * old view down only after it has successfully mapped the new file; and
	 * close the old engine last, when nothing points into it any more. Each
	 * failure returns with the session exactly as it was - the old engine,
	 * the old file, and a message.
	 */
	fresh = kof_engine_open(v->dbdir);
	if (!fresh) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "Built, but %.50s would not load", v->dbdir);
		return;
	}
	/* The sources were just recompiled: whatever this knew about where each
	 * detection name sits is a fact about the tree before the build. */
	src_forget();
	old = v->eng;
	if (!file_open(v, here, fresh)) {
		kof_engine_close(fresh);
		return;                 /* file_open left the reason */
	}
	kof_engine_close(old);
	v->act_ok = 1;
	snprintf(v->act_msg, sizeof v->act_msg, "Database rebuilt from %.60s",
		 root);
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
static void bar_enter_sub(struct view *v, int i)
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
static void bar_open_menu(struct view *v, int menu)
{
	int items[BI_COUNT], n = bar_items_of(v, menu, items, BI_COUNT), i;

	v->bar_open = menu;
	v->bar_sub = -1;
	v->bar_sel = -1;
	for (i = 0; i < n; i++)
		if (bar_enabled(v, items[i])) {
			v->bar_sel = items[i];
			break;
		}
	if (v->bar_sel < 0 && n)
		v->bar_sel = items[0];
}

/* Move the cursor up or down within the open menu, skipping disabled rows so
 * the cursor never rests on something Enter would ignore. */
static void bar_move_item(struct view *v, int dir)
{
	int items[BI_COUNT], n, cur = -1, i, step;

	if (v->bar_open < 0)
		return;
	n = v->bar_sub >= 0 ? bar_kids_of(v, v->bar_sub, items, BI_COUNT)
			    : bar_items_of(v, v->bar_open, items, BI_COUNT);
	for (i = 0; i < n; i++)
		if (items[i] == v->bar_sel)
			cur = i;
	for (step = 0; step < n; step++) {
		cur = (cur + dir + n) % n;
		if (bar_enabled(v, items[cur])) {
			v->bar_sel = items[cur];
			return;
		}
	}
}

static void bar_run(struct view *v, int i)
{
	if (!bar_enabled(v, i)) {
		/*
		 * A greyed item that does nothing when clicked teaches nothing.
		 * The two that can be greyed for a reason worth reading say it.
		 */
		if (i == BI_SAVE || i == BI_SAVE_AS) {
			const char *why = draft_missing(v);

			if (why)
				say_err(v, "%s", why);
			else
				say_note(v, "Nothing to write");
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
	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;
	switch (i) {
	case BI_SAVE:    generate(v, 0); break;
	case BI_SAVE_AS: generate(v, 1); break;
	case BI_FIND:
		v->find_open = 1;
		v->goto_open = 0;              /* they share the box */
		v->edit = 500;
		v->warn[0] = 0;
		break;
	/* The twin of BI_FIND, and it has to be here as well as in
	 * bar_enabled: an item that reports itself live and has no case falls
	 * to `default: break;` - the menu closes and nothing happens, which
	 * is exactly how BI_GOTO looked before the dialog existed. */
	case BI_SYMS:
		symd_open(v);
		return;
	/*
	 * SHOW what the heuristic found, or say plainly that it found nothing.
	 *
	 * Both outcomes are reported, and the negative one goes to the status
	 * line rather than opening an empty dialog - a box with nothing in it
	 * makes the reader work out which of "nothing found" and "nothing
	 * shown" they are looking at.
	 */
	/*
	 * GO TO THE PAYLOAD, which is an object of its own.
	 *
	 * There used to be a dialog here showing the bytes, then the same
	 * dialog showing a disassembly. Both are gone: the payload is a child
	 * object now, so the tree, the hex pane with its selection and its
	 * right-click menu, the disassembly panel, Find, Go to and the draft
	 * are all already pointed at it. A dialog was a second, worse copy of
	 * tools that exist.
	 *
	 * So the item's job is to take the reader THERE - the payload is one
	 * row among however many the tree has - and to say what it looks like,
	 * which is the one thing the dialog said that the tree does not.
	 */
	case BI_FINDSC: {
		uint32_t me = v->node[v->sel_node].obj, k;
		uint32_t kid = 0;

		/*
		 * ALREADY THERE IS AN ANSWER, NOT A FAILURE.
		 *
		 * The reader sees the payload in the tree, clicks it, then asks
		 * to find it - which is the most natural order to do those two
		 * things in, and it reported "no variable in this object looks
		 * like shellcode". The object under the cursor WAS the payload;
		 * the search was for a payload inside it, and a payload does
		 * not carry one.
		 *
		 * The question is about the file, not about whichever row the
		 * cursor is on, so a payload child answers with itself. That
		 * also makes the item idempotent: pressing it twice says the
		 * same thing rather than contradicting itself.
		 */
		if (v->obj[me].payload_of)
			kid = me;

		/* The child of THIS object, found by the name payload_child
		 * built: it is the parent's name with a "//" and the symbol
		 * after it, so a prefix test is exact rather than a guess. */
		for (k = 0; !kid && k < v->n_obj; k++) {
			size_t pn = strlen(v->obj[me].name);

			if (k == me || v->obj[k].depth <= v->obj[me].depth)
				continue;
			if (strncmp(v->obj[k].name, v->obj[me].name, pn) == 0 &&
			    v->obj[k].name[pn] == '/' &&
			    v->obj[k].payload_of) {
				kid = k;
				break;
			}
		}
		if (!kid) {
			snprintf(v->act_msg, sizeof v->act_msg, "%s",
				 "no variable in this object looks like "
				 "shellcode");
			v->act_ok = 1;
			v->menu_open = 0;
			return;
		}
		for (k = 0; k < v->n_node; k++)
			if (v->node[k].obj == kid && !v->node[k].mask &&
			    !v->node[k].sym) {
				goto_node(v, k);
				break;
			}
		snprintf(v->act_msg, sizeof v->act_msg, "%s",
			 sc_kind(v->obj[kid].buf.p,
				 (uint32_t)v->obj[kid].buf.n));
		v->act_ok = 1;
		v->menu_open = 0;
		return;
	}
	case BI_GOTO:
		v->goto_open = 1;
		v->find_open = 0;      /* they share the box - see draw_goto */
		v->gotobuf[0] = 0;
		v->num_fresh = 1;
		v->edit = 520;
		v->warn[0] = 0;
		break;
	case BI_DUMP_STATIC: dump_all(v, 0); break;
	case BI_DUMP_EMU:    dump_all(v, 1); break;
	case BI_UNPACKER: emu_here(v); break;
	case BI_DISASM:   dis_toggle(v, 0, KOF_BROKEN); break;
	case BI_NEXT:    open_step(v, +1); break;
	case BI_PREV:    open_step(v, -1); break;
	case BI_REBUILD: rebuild_db(v); break;
	case BI_DASH:
		/* Whatever the last copy or dump said belongs to the screen
		 * it was said on, not to a page opened afterwards. */
		v->prop_open = 1;
		v->prop_off = 0;
		v->act_msg[0] = 0;
		v->prop_sel_row = -1;
		v->prop_dragging = 0;
		break;
	case BI_KEYS:    v->help_open = 1; break;
	case BI_ABOUT:   v->help_open = 2; break;
	default: break;
	}
}

/* ---- input ---------------------------------------------------------------- */

/*
 * THERE IS NO ALT HERE, and there was.
 *
 * A chord with Alt is ESC-then-the-letter on the wire, and a bit above the key
 * space used to carry the letter through to menu-bar shortcuts. What was wanted
 * is the windowed-editor gesture - tap Alt, the menu bar takes focus - and a
 * terminal never reports a modifier on its own, so that gesture cannot be built
 * at all. What the shortcuts offered instead was a different thing wearing the
 * same key. F10 opens the bar; every other hot key here is Ctrl+key.
 */

enum key {
	K_NONE = 0, K_UP = 256, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN,
	K_HOME, K_END,
	/* Not a key: the terminal changed size while nothing was being typed,
	 * and the loop has to be told so it repaints. */
	K_RESIZE,
	/* A bracketed paste, whose bytes are in g_paste. */
	K_PASTE,
	/* Forward delete - CSI 3 ~, which is a different key from backspace and
	 * arrives as a different sequence. It used to fall through the CSI
	 * decoder's default and come back as 27, so pressing Delete in a field
	 * did what Escape does: dropped the focus, leaving the text alone. */
	K_DEL,
	/*
	 * F10, which is how a text UI activates its menu bar.
	 *
	 * NOT Alt on its own: a terminal never reports a bare modifier. Alt only
	 * exists on the wire attached to a key - Alt+F arrives as ESC 'f' - so
	 * "press Alt to reach the menu" cannot be built, while "press F10" is
	 * what every program with a menu bar in a terminal already uses.
	 */
	K_F10,
	/* Kept contiguous and last: handle() tests the range to let mouse
	 * events past the modes that own the keyboard. */
	K_BACKTAB,
	K_CLICK, K_RCLICK, K_WHEEL_UP, K_WHEEL_DOWN, K_DRAG, K_RELEASE
};

static char   g_paste[4096];    /* the last bracketed paste */
static size_t g_paste_n;

/*
 * WHAT A PASTE SHOULD INSERT, in one place.
 *
 * A bracketed paste is the terminal handing the system clipboard over already,
 * so it is used as given. A Ctrl+V has to go and ASK for it - wl-paste, xclip,
 * xsel - so that it pastes what every other program would; only when none of
 * them answers does it fall back to this program's own last copy, which is the
 * best it can then do.
 *
 * One function because there is more than one field to paste into and they were
 * getting it different: the string editor asked the clipboard tools, the find
 * box read g_clip directly and so pasted only what had been copied inside this
 * program - a Ctrl+V of something yanked from a terminal or a browser put the
 * wrong bytes in the search box, or nothing at all.
 */
static size_t paste_src(int k, const char **out)
{
	static char clip[8192];
	size_t sn;

	if (k == K_PASTE) {
		*out = g_paste;
		return g_paste_n;
	}
	sn = paste_extern(clip, sizeof clip);
	if (sn) {
		*out = clip;
		return sn;
	}
	*out = g_clip;
	return g_clip_n;
}

static int g_mx, g_my;          /* where the last click was, 1 based */
static int g_mod_shift;         /* shift was held for it */
static int g_mod_ctrl;          /* and control, which slides text sideways */

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
	g_mod_ctrl  = (b & 0x10) != 0;

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
	g_mod_ctrl  = (b & 0x10) != 0;
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

/* How long to wait for the rest of an escape sequence before calling the byte a
 * lone Escape. See read_key. */
#define ESC_WAIT_MS 50

/* Is there input already waiting. Used to collapse a burst of key repeats into
 * one frame; never blocks. */
static int key_pending(void)
{
	struct pollfd p;

	p.fd = STDIN_FILENO;
	p.events = POLLIN;
	p.revents = 0;
	return poll(&p, 1, 0) > 0 && (p.revents & POLLIN) != 0;
}

static int read_key(void)
{
	unsigned char c, seq[3];
	ssize_t n;

	/*
	 * A read interrupted by a window change is not end of input.
	 *
	 * There was no handler at all before, so a terminal resized while this
	 * was blocked here went unnoticed until the next keystroke: the screen
	 * kept the layout it had been drawn for, which is what a panel that has
	 * grown or shrunk on its own looks like. Locking a screen resizes the
	 * terminal on most desktops, which is why it showed up after leaving it
	 * alone rather than while working.
	 */
	n = read(STDIN_FILENO, &c, 1);
	if (n != 1) {
		if (n < 0 && errno == EINTR && g_winch)
			return K_RESIZE;
		return K_NONE;
	}
	if (c != 27)
		return c;
	/*
	 * A LONE ESCAPE HAS TO BE ANSWERABLE WITHOUT A SECOND KEY.
	 *
	 * Escape is both a key and the first byte of every sequence, and the
	 * only thing that tells them apart is whether more bytes follow. This
	 * read used to be unconditional, so a lone Escape sat here until the
	 * NEXT keystroke arrived - and that keystroke was then consumed as the
	 * second byte of a sequence that was never sent. What a reader saw was
	 * an Escape that did nothing, a menu that closed only on the second
	 * press, and - worse - every Alt combination after a stray Escape
	 * behaving as plain Escape, because the Alt's own ESC was eaten as the
	 * tail of the pending one.
	 *
	 * Fifty milliseconds, which is what vim's ttimeoutlen uses for the same
	 * decision. A terminal emits a sequence as one write, so the bytes are
	 * already in the buffer when this polls; the wait only ever elapses for
	 * a key pressed by a person, and fifty milliseconds is below what a
	 * person can perceive as lag.
	 */
	{
		struct pollfd p;

		p.fd = STDIN_FILENO;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, ESC_WAIT_MS) <= 0 || !(p.revents & POLLIN))
			return 27;
	}
	if (read(STDIN_FILENO, seq, 1) != 1)
		return 27;
	/*
	 * ESC followed by anything that is not a sequence introducer is Escape.
	 *
	 * It used to be marked as Alt+that character and there were menu
	 * shortcuts on the other end. They are gone: what was wanted was a TAP
	 * of Alt taking the menu bar, which a terminal cannot report at all, and
	 * a chord that is not that gesture is a second way in that nobody asked
	 * for. The hot keys this program has are Ctrl+key.
	 */
	if (seq[0] != '[' && seq[0] != 'O')
		return 27;
	if (read(STDIN_FILENO, seq + 1, 1) != 1)
		return 27;
	if (seq[1] == '<')
		return read_mouse();
	if (seq[1] == '2') {
		/*
		 * Bracketed paste: ESC [ 200 ~ ... ESC [ 201 ~
		 *
		 * Read whole and handed over as one thing, because that is what
		 * it is. Fed through the key handler byte by byte it would be
		 * indistinguishable from someone typing very fast, which is
		 * exactly the confusion the brackets exist to remove.
		 */
		unsigned char t[4];
		size_t pn = 0;

		if (read(STDIN_FILENO, t, 1) != 1)
			return 27;
		/*
		 * CSI 21 ~ is F10 and CSI 200 ~ is a paste, and they share their
		 * first two bytes. Told apart here rather than in the switch
		 * below, because this branch has already consumed the '2' - and
		 * F10 was being swallowed as a malformed paste.
		 */
		if (t[0] == '1') {
			if (read(STDIN_FILENO, t, 1) != 1 || t[0] != '~')
				return 27;
			return K_F10;
		}
		if (t[0] != '0')
			return 27;
		if (read(STDIN_FILENO, t, 1) != 1)
			return 27;
		if (read(STDIN_FILENO, t, 1) != 1 || t[0] != '~')
			return 27;
		g_paste_n = 0;
		for (;;) {
			unsigned char c2;

			if (read(STDIN_FILENO, &c2, 1) != 1)
				break;
			if (c2 == 27) {
				unsigned char e[5];
				size_t k = 0;

				while (k < 5 && read(STDIN_FILENO, e + k, 1)
				       == 1) {
					k++;
					if (e[k - 1] == '~')
						break;
				}
				break;          /* the closing bracket */
			}
			if (pn + 1 < sizeof g_paste)
				g_paste[pn++] = (char)c2;
		}
		g_paste_n = pn;
		return K_PASTE;
	}
	if (seq[1] == 'M')
		return read_mouse_x10();
	switch (seq[1]) {
	case 'A': return K_UP;
	case 'B': return K_DOWN;
	case 'C': return K_RIGHT;
	case 'D': return K_LEFT;
	case 'H': return K_HOME;
	case 'F': return K_END;
	/* Shift+Tab. CSI Z, not a tab with a modifier: the terminal has one
	 * code for it and this is the one. */
	case 'Z': return K_BACKTAB;
	case '3': if (read(STDIN_FILENO, seq + 2, 1) != 1) return 27; return K_DEL;
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
/* Milliseconds on a clock that does not go backwards; only differences are
 * ever taken from it. */
static uint64_t now_ms(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
		return 0;
	return (uint64_t)t.tv_sec * 1000u + (uint64_t)(t.tv_nsec / 1000000);
}

/*
 * Grow a selection out to the whole printable run around it.
 *
 * What a double click means in every text editor, and what a researcher taking
 * a marker actually wants: a string is a run of printable bytes between two
 * that are not, and picking its ends by dragging is the fiddliest thing in this
 * tool. Bounded by the region being looked at, so it cannot walk into bytes the
 * pane is not showing.
 */
static void select_run(struct view *v)
{
	uint64_t bn = 0;
	const uint8_t *bp = view_bytes(v, &bn);
	uint64_t a = v->sel_a, b;

	if (a == KOF_BROKEN || !bp)
		return;
	b = a;
	while (a > 0) {
		uint64_t f = view_map(v, a - 1u, 0);

		if (f == KOF_BROKEN || f >= bn || !byte_text(bp[f]))
			break;
		a--;
	}
	while (b + 1u < v->rgn_len) {
		uint64_t f = view_map(v, b + 1u, 0);

		if (f == KOF_BROKEN || f >= bn || !byte_text(bp[f]))
			break;
		b++;
	}
	v->sel_a = a;
	v->sel_b = b;
}

/*
 * Take one matcher out of a condition's expression.
 *
 * Rewritten from the ids that are left rather than edited in place, because
 * removing "2" from "1&2|3" by deleting characters leaves "1&|3" - and an
 * expression that has to be repaired by hand after every removal is one nobody
 * will use the buttons on. Anything the author typed that is not a plain list -
 * parentheses, a mix of & and | - is preserved only in so far as the join it
 * was written with; that is the price of a list and a text box being the same
 * field.
 */
static void cnd_drop_matcher(struct cond *c, uint32_t g)
{
	char out[64];
	size_t at = 0;
	const char *p = c->expr;
	int first = 1;

	while (*p) {
		if (*p >= '0' && *p <= '9') {
			char *end;
			unsigned long n;

			n = strtoul(p, &end, 10);
			p = end;

			if (n == (unsigned long)g + 1ul)
				continue;
			at += (size_t)snprintf(out + at, sizeof out - at,
					       "%s%lu", first ? "" : (c->op
					       ? "|" : "&"), n);
			first = 0;
			continue;
		}
		p++;
	}
	out[at] = 0;
	snprintf(c->expr, sizeof c->expr, "%s", out);
}

/*
 * A matcher id on a condition's row, clicked to take it back out.
 *
 * The mirror of clicking a marker id inside a matcher, and it has to be the
 * mirror: a list you can only add to is a list that gets rebuilt from scratch
 * every time somebody changes their mind.
 *
 * The ids are laid out as "1, 2, 3", so the nth one starts at a known column
 * and the click lands on a number rather than on an index into anything.
 */
static void cnd_id_click(struct view *v, uint32_t g)
{
	struct cond *c = &v->cnd[g];
	int at = v->cnd_id0[g];
	uint32_t m;

	if (at <= 0)
		return;
	for (m = 0; m < v->n_grp; m++) {
		char num[8];
		int w;

		if (!cnd_uses(c, m))
			continue;
		w = snprintf(num, sizeof num, "%u", m + 1u);
		if (g_mx >= at && g_mx < at + w) {
			cnd_drop_matcher(c, m);
			return;
		}
		at += w + 2;            /* the ", " that follows it */
	}
}

/*
 * Move whatever bar was taken hold of to where the pointer is.
 *
 * The row under the pointer names a fraction of the track, and the fraction
 * names a position in the content. Clamped at both ends rather than checked,
 * because a pointer dragged past the pane is an ordinary thing to do and
 * stopping at the end is what it means.
 */
static void bar_to(struct view *v, int which)
{
	int top, bot;
	uint64_t frac, max;

	if (which == 1) {                       /* the hex pane */
		uint64_t per = (uint64_t)(v->per > 0 ? v->per : 16);

		top = hex_top(); bot = hex_last();
		if (bot <= top)
			return;
		max = hex_max(v);
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->rgn_at = frac * max / (uint64_t)(bot - top);
		v->rgn_at = v->rgn_at / per * per;
	} else if (which == 2) {                /* the object tree */
		uint32_t rows;

		top = hex_top(); bot = hex_bot();
		if (bot <= top || !v->n_node)
			return;
		rows = (uint32_t)(bot - top + 1);
		if (v->n_node <= rows)
			return;
		max = v->n_node - rows;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->tree_top = (uint32_t)(frac * max / (uint64_t)(bot - top));
	} else if (which == 3) {                /* the draft panel */
		uint32_t vis;

		if (g_decl_rows < 3)
			return;
		top = decl_top() + 1;
		bot = decl_top() + g_decl_rows - 2;
		vis = (uint32_t)(g_decl_rows - 2);
		if (bot <= top || v->n_prow <= vis)
			return;
		max = v->n_prow - vis;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->prow_off = (uint32_t)(frac * max / (uint64_t)(bot - top));
	} else if (which == 4) {                /* the disassembly panel */
		/*
		 * The track is the hex pane's range, not the file's - see the
		 * note where this bar is drawn. So the fraction names a place
		 * inside what the hex is showing, and the panel never leaves it.
		 */
		int64_t hi = dis_max_bias(v);

		top = dis_top(); bot = hex_bot();
		if (bot <= top || hi <= 0)
			return;
		frac = (uint64_t)(g_my < top ? 0 : g_my > bot ? bot - top
							     : g_my - top);
		v->dis_bias = (int64_t)(frac * (uint64_t)hi /
					(uint64_t)(bot - top));
	}
}

/* Is the pointer on a scrollbar, and which. 0 for none. */
static int bar_under(struct view *v)
{
	if (g_my >= hex_top() && g_my <= hex_last()) {
		if (g_mx == g_cols && v->rgn_len)
			return 1;
	}
	if (g_my >= hex_top() && g_my <= hex_bot()) {
		if (g_mx == TREE_W)
			return 2;
	}
	/* Before the hex bar's own row test would ever reach here: the panel
	 * owns the bottom of the same column. */
	if (g_disasm_rows && g_mx == g_cols &&
	    g_my >= dis_top() && g_my <= hex_bot() && dis_max_bias(v) > 0)
		return 4;
	if (g_decl_rows && g_mx == g_cols && g_my > decl_top() &&
	    g_my < decl_top() + g_decl_rows - 1)
		return 3;
	return 0;
}

/*
 * The find dialog.
 *
 * A box rather than a line, because searching has more than one setting and a
 * line can only hold the one being typed. Every setting is a control that says
 * its own state, so nothing has to be remembered between openings.
 *
 * Regex is drawn and refused. Leaving it out would invite the question every
 * time; drawing it greyed answers it once and marks the place the work goes.
 */
/*
 * Four rows: a top rule and three of content.
 *
 * No bottom rule. The status line already has one directly beneath, and two
 * horizontal lines with nothing between them read as a mistake rather than as a
 * frame.
 */
/*
 * Five rows: a border, three of content, and a border. It was four and the box
 * had no bottom edge at all - the side bars simply stopped, which reads as a
 * dialog that has been cut off rather than one that ends.
 */
#define FIND_H 5

/*
 * The Go to box: its own height and its own rows, no longer borrowed from the
 * find dialog.
 *
 * Five rows because it has three of content and a border top and bottom, and it
 * spans the FULL WIDTH so that no column of the panel underneath shows through
 * beside it. Sharing find's rows left columns one and two unpainted - find
 * starts its rows at column three - and the two columns of whatever was behind
 * it, read down five rows, is what made the dialog look like it was floating on
 * top of a mess.
 */
#define GOTO_H 5

/* Light box drawing, rounded at the corners, to match the scrollbar's U+2502
 * rather than a row of ASCII dashes. */
#define G_TL "\xe2\x95\xad"     /* U+256D */
#define G_TR "\xe2\x95\xae"     /* U+256E */
#define G_BL "\xe2\x95\xb0"     /* U+2570 */
#define G_BR "\xe2\x95\xaf"     /* U+256F */
#define G_H  "\xe2\x94\x80"     /* U+2500 */
#define G_V  "\xe2\x94\x82"     /* U+2502 - the scrollbar's own */

/* ---- the symbols dialog ----------------------------------------------------
 *
 * The symbol records, decoded, over the top of whatever the reader was looking
 * at. A DIALOG and not a pane, because it answers a question about the object
 * rather than about the bytes on screen: it is opened, read, and closed, and
 * the place the reader was does not move underneath them.
 *
 * The two tree rows show the same records as BYTES, which is what a signature
 * matches. This is the other half of that: the same block, read as what the
 * fields mean. Neither is the "real" one - a reader needs both, and needs to be
 * able to see that they are the same thing, which is why the dialog names the
 * row it is showing rather than inventing a third view of its own.
 */

/* Sized to the screen and then capped. The cap is not tidiness: past about a
 * hundred columns the fields are all in place and the rest is a very long gap
 * between the size and the name, which is harder to read down, not easier. */
static int symd_w(void)
{
	int w = g_cols - 4;

	/*
	 * Wider than it was, and the cap is now derived rather than picked.
	 *
	 * Reordering the columns to follow the record moved the NAME into the
	 * middle, where it has to be a fixed width - a variable column between
	 * fixed ones cannot be read down. So the box has to be wide enough to
	 * hold every column at full size or the name loses characters it did
	 * not have to lose: 5 rec, 8 type, 7 bind, 10 vis, 6 flags, 41 name,
	 * 6 sec, 13 size, 16 value, plus the border, a space and the border.
	 * That is 116 for a table with 64-bit values in it, and there is no
	 * reason to go past what the columns can use: a box wider than its
	 * content is a stripe of empty inside a border. A table whose values
	 * all fit in 32 bits needs twelve fewer, and those twelve fall at the
	 * right edge as a margin rather than being taken off the name - the
	 * name is data, the margin is not.
	 */
	return w > 116 ? 116 : w;
}

static int symd_h(void)
{
	int h = g_rows - 6;

	return h > 28 ? 28 : h;
}

static int symd_x(void) { return (g_cols - symd_w()) / 2 + 1; }
static int symd_y(void) { return (g_rows - symd_h()) / 2 + 1; }

/* How many record rows the box has: its height less the two borders, the tab
 * row and the column heading. */
static int symd_rows(void)
{
	int r = symd_h() - 4;

	return r > 0 ? r : 0;
}

/* The block the dialog is showing. One block now, so the tab decides only which
 * half's records are listed - see symd_rows_of. */
static const uint8_t *symd_block(struct view *v, uint64_t *n)
{
	const struct object *o = cur_obj(v);

	if (n)
		*n = o->sym_n;
	return o->sym;
}

/*
 * THE RECORDS THE TAB LISTS, as block-record indices in reading order.
 *
 * The dialog used to index a block this file had built by copying one half out,
 * so its row n was that copy's record n. There is one block now and the half is
 * the engine's answer, so the rows are the record indices kof_sym_extents
 * covers. Kept in a static rather than rebuilt per row: at most
 * KOF_SYM_MAX_RECS of them, one dialog is open at a time, and the screen is
 * drawn from one thread.
 */
static uint32_t *symd_rows_of(struct view *v, uint32_t *n)
{
	static uint32_t idx[KOF_SYM_MAX_RECS];
	const struct object *o = cur_obj(v);

	*n = v->probe ? sym_half_recs(o, sym_row_mask(v->sym_open), v->probe,
				      KOF_SCAN_MAX_EXTENTS, idx,
				      (uint32_t)(sizeof idx / sizeof *idx))
		      : 0u;
	return idx;
}

static uint64_t symd_max(struct view *v)
{
	uint64_t nb = 0;
	const uint8_t *b;
	uint32_t n, rows = (uint32_t)symd_rows();

	/*
	 * The block is fetched on its OWN LINE, and this is not style.
	 *
	 * It was `sym_count(symd_block(v, &nb), (uint32_t)nb)`, and the order
	 * in which a compiler evaluates two arguments is unspecified: `nb` was
	 * read while it was still zero, sym_count saw a length shorter than a
	 * header and answered zero records, and so this returned a maximum
	 * scroll of zero. Every scroll clamped straight back to the top and the
	 * dialog looked as though its keys were not wired up at all - while the
	 * keys were arriving and doing exactly what they were told.
	 */
	(void)b; (void)nb;
	symd_rows_of(v, &n);
	return n > rows ? n - rows : 0u;
}

static void symd_clamp(struct view *v)
{
	if (v->sym_at > symd_max(v))
		v->sym_at = symd_max(v);
}

/* A row of the box, from its left edge, so col_base + col_hint is an absolute
 * column and every click box recorded below lands where its text is. */
static void symd_row(struct out *o, int y)
{
	out_at(o, y, symd_x());
	o->col_hint = 0;
}

/*
 * Fill to the right border and draw it.
 *
 * Every row of the box has to reach its own edge. Positioning the cursor at
 * the edge and drawing the border there is NOT the same thing: the box sits on
 * top of the hex pane, so whatever the row did not write is still the pane's
 * bytes, and the tab row and the column heading showed a stripe of hex running
 * through the middle of the dialog. col_hint counts BYTES, which is why the box
 * glyphs go through out_glyph and this counts in it rather than in strlen.
 */
static void symd_edge(struct out *o, int w)
{
	while ((int)o->col_hint < w - 1)
		out_str(o, " ");
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF);
}

/*
 * A ROW WRITER THAT CLIPS TO A WINDOW, so the table can be scrolled sideways.
 *
 * The problem it solves: the row is a fixed sequence of columns whose natural
 * width does not depend on the box. When the box is narrower, the row has to
 * stop at the border - and stopping by not writing the tail is what shortened
 * the name column instead, which loses data. Worse, getting that budget wrong
 * by one wrote THROUGH the border and the scrollbar beside it, because nothing
 * here turns autowrap off and a terminal has no clip region.
 *
 * So every field goes through this. It counts columns in the FULL row and emits
 * only those inside [from, to), which makes horizontal scrolling a change of
 * two numbers rather than a different layout, and makes writing past the border
 * impossible rather than merely avoided. The colour is emitted lazily - once,
 * before the first visible character of a run - so a field scrolled off costs
 * no escape sequence, and a field entering from the left is still coloured
 * even though its first characters are not drawn.
 */

struct sclip {
	struct out *o;
	int         vcol;               /* column in the unclipped row */
	int         from, to;           /* the visible window */
	/*
	 * WHERE THE VISIBLE CHARACTERS ARE ALSO WRITTEN, so they can be
	 * selected and copied.
	 *
	 * The row has to be recorded as it is drawn rather than rebuilt
	 * afterwards, because "afterwards" means a second copy of the format
	 * strings and the clipping - and the copy a reader takes would then be
	 * whatever that second version produced, not what they were looking at.
	 * Recorded here, the two cannot differ: there is one walk.
	 *
	 * NULL when a caller does not want a recording, which is what the
	 * heading rows use.
	 */
	char       *rec;
	int         rec_n;
};

static void sclip_puts(struct sclip *c, const char *attr, const char *t)
{
	int on = 0;

	for (; *t; t++, c->vcol++) {
		if (c->vcol < c->from || c->vcol >= c->to)
			continue;
		if (!on) {
			out_str(c->o, attr);
			on = 1;
		}
		out_fmt(c->o, "%c", *t);
		if (c->rec && c->rec_n < DLG_COLS - 1)
			c->rec[c->rec_n++] = *t;
	}
	if (on)
		out_str(c->o, A_OFF);
}

static void sclip_fmt(struct sclip *c, const char *attr, const char *fmt, ...)
{
	char t[96];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	sclip_puts(c, attr, t);
}

/* The name field, which is NUL-padded to a fixed 40 and NOT necessarily
 * terminated - so it is copied out before being written, never passed as a
 * string. Padded to `nw` so the columns after it line up. */
static void sclip_name(struct sclip *c, const uint8_t *r, int nw,
		       const char *attr)
{
	char t[KOF_SYM_NAMELEN + 1];
	int k;

	if (nw > (int)KOF_SYM_NAMELEN)
		nw = (int)KOF_SYM_NAMELEN;
	for (k = 0; k < nw; k++) {
		char ch = (char)r[KOF_SYM_R_NAME + (uint32_t)k];

		if (!ch)
			break;
		t[k] = ch;
	}
	for (; k < nw; k++)
		t[k] = ' ';
	t[k] = 0;
	sclip_puts(c, attr ? attr : A_S_NAME, t);
}

/* ---- selecting and copying a dialog's text ---------------------------------
 *
 * A character selection over the rows a dialog recorded while it drew them.
 * Shared by the symbols and shellcode boxes: both are tables of text a reader
 * wants to paste into a note, and neither is a hex pane whose selection means
 * an extent of a file.
 *
 * The selection is over the TEXT, not over what the text describes. Dragging
 * across a symbols row copies the row as it reads on screen - which is the
 * point, because that is what a reader is looking at when they decide to keep
 * it.
 */

/*
 * Closing a dialog drops the selection in it.
 *
 * One function because there are four places a box closes - two buttons, Escape
 * and q - and a selection left behind by any of them would be painted over
 * whatever box opened next, since the recorded rows are shared. Written as a
 * helper rather than two statements at each site: the first attempt WAS two
 * statements, one of them fell outside an unbraced `if`, and the compiler's
 * misleading-indentation warning is what caught it.
 */
static void dlg_close(struct view *v)
{
	v->sym_open = 0;
	v->dlg_have = 0;
	v->dlg_drag = 0;
}

/* Start a fresh recording. Called by a dialog before it draws its rows, so a
 * box that has just changed what it shows cannot be selected against what it
 * showed before. */
static void dlg_rec_begin(struct view *v, int y0, int x0)
{
	v->dlg_rows = 0;
	v->dlg_y0 = y0;
	v->dlg_x0 = x0;
}

/* Take the row the clipper just wrote. */
static void dlg_rec_row(struct view *v, struct sclip *c)
{
	if (v->dlg_rows >= DLG_ROWS)
		return;
	c->rec[c->rec_n] = 0;
	v->dlg_rows++;
}

/* The buffer the next row should be recorded into, or NULL when full. */
static char *dlg_rec_buf(struct view *v)
{
	return v->dlg_rows < DLG_ROWS ? v->dlg_line[v->dlg_rows] : 0;
}

/*
 * The selection in reading order, as first/last row and the columns on each.
 * Zero when there is nothing selected.
 */
static int dlg_span(const struct view *v, int *r0, int *c0, int *r1, int *c1)
{
	if (!v->dlg_have)
		return 0;
	if (v->dlg_ar < v->dlg_br ||
	    (v->dlg_ar == v->dlg_br && v->dlg_ac <= v->dlg_bc)) {
		*r0 = v->dlg_ar; *c0 = v->dlg_ac;
		*r1 = v->dlg_br; *c1 = v->dlg_bc;
	} else {
		*r0 = v->dlg_br; *c0 = v->dlg_bc;
		*r1 = v->dlg_ar; *c1 = v->dlg_ac;
	}
	return 1;
}

/*
 * Paint the selection over what has already been drawn.
 *
 * A SECOND PASS, on purpose. The alternative is to test every character
 * against the selection inside the clipper, which puts the selection's logic
 * into the one function that must stay simple enough to be obviously right
 * about clipping. Overwriting the span afterwards costs one repositioning per
 * selected row and cannot affect a row that is not selected at all.
 */
static void dlg_paint_sel(struct out *o, struct view *v)
{
	int r0, c0, r1, c1, r;

	if (!dlg_span(v, &r0, &c0, &r1, &c1))
		return;
	for (r = r0; r <= r1 && r < v->dlg_rows; r++) {
		int len = (int)strlen(v->dlg_line[r]);
		int from = (r == r0) ? c0 : 0;
		int to   = (r == r1) ? c1 + 1 : len;

		if (from < 0)
			from = 0;
		if (to > len)
			to = len;
		if (to <= from)
			continue;
		out_at(o, v->dlg_y0 + r, v->dlg_x0 + from);
		out_str(o, A_SEL);
		out_add(o, v->dlg_line[r] + from, (size_t)(to - from));
		out_str(o, A_OFF);
	}
}

/* Which (row, column) of the recorded text a screen position is, or 0 when it
 * is not over the text at all. */
static int dlg_at(const struct view *v, int row, int col, int *r, int *c)
{
	int rr = row - v->dlg_y0, cc = col - v->dlg_x0;

	if (rr < 0 || rr >= v->dlg_rows || cc < 0)
		return 0;
	if (cc >= (int)strlen(v->dlg_line[rr]))
		cc = (int)strlen(v->dlg_line[rr]) - 1;
	if (cc < 0)
		return 0;
	*r = rr;
	*c = cc;
	return 1;
}

/*
 * Copy the selection, rows joined by newlines and trailing blanks dropped.
 *
 * The blanks go because these tables are padded to their column widths, so a
 * row selected whole ends in a run of spaces that is part of the layout and
 * not part of what the reader picked out.
 */
static void dlg_copy(struct view *v)
{
	int r0, c0, r1, c1, r, rows = 0;
	struct out d = { 0 };

	if (!dlg_span(v, &r0, &c0, &r1, &c1))
		return;
	for (r = r0; r <= r1 && r < v->dlg_rows; r++) {
		int len = (int)strlen(v->dlg_line[r]);
		int from = (r == r0) ? c0 : 0;
		int to   = (r == r1) ? c1 + 1 : len;

		if (to > len)
			to = len;
		while (to > from && v->dlg_line[r][to - 1] == ' ')
			to--;
		if (rows)
			out_str(&d, "\n");
		if (to > from)
			out_add(&d, v->dlg_line[r] + from, (size_t)(to - from));
		rows++;
	}
	if (d.n) {
		copy_osc52(d.p, d.n);
		snprintf(v->act_msg, sizeof v->act_msg, "Copied %d line(s)",
			 rows);
		v->act_ok = 1;
	}
	free(d.p);
}

static void draw_symbols(struct out *o, struct view *v)
{
	int x = symd_x(), y = symd_y(), w = symd_w(), h = symd_h();
	int rows = symd_rows(), i;
	uint64_t nb = 0;
	const uint8_t *b = symd_block(v, &nb);
	uint32_t n = 0;
	const uint32_t *rec = symd_rows_of(v, &n);
	int wd = 8, sw, fixed, nw = 0, natural, vis, hmax;
	struct sclip sc;
	const struct object *ob = cur_obj(v);

	if (w < 40 || h < 8)
		return;                 /* no room to draw a box honestly */

	/*
	 * Re-clamped every frame rather than only when it is scrolled, because
	 * the box's height follows the terminal's: making the window taller
	 * shows more records, which moves the last legal offset, and an offset
	 * left past it would draw a table of blank rows.
	 */
	symd_clamp(v);

	/* Same rule as the pane: one width for the whole table, decided by the
	 * whole table, or the column cannot be read down. */
	for (i = 0; (uint32_t)i < n; i++) {
		const uint8_t *r = sym_rec(b, (uint32_t)nb, rec[i]);

		if (r && (sym_u64(r, KOF_SYM_R_VALUE) > 0xffffffffull ||
			  sym_u64(r, KOF_SYM_R_SIZE) > 0xffffffffull)) {
			wd = 16;
			break;
		}
	}
	/*
	 * THE COLUMNS, IN THE ORDER THE RECORD STORES THEM.
	 *
	 * type, bind, vis, flags, name, sec, size, value - the same order as
	 * the bytes in the two SYM rows, so a reader moving between the dialog
	 * and the hex is reading the same sequence twice rather than mentally
	 * transposing it. It used to end value, size, sec, name, which was a
	 * different order from the block it describes.
	 *
	 * The name is a FIXED width because it is no longer last. A variable
	 * column with fixed ones after it cannot be read down - every row's
	 * sec, size and value would start somewhere else. It gets everything
	 * the other columns do not want, up to the 40 a record can hold.
	 */
	sw = wd == 16 ? 12 : 8;             /* the size column */
	/*
	 * The value column is wd + 2: the digits, plus the "0x" in front of
	 * them. Counted here rather than left out, because this number is what
	 * the name column's width is derived from - and a column budget that
	 * forgets a separator is what put a row through the border once
	 * already.
	 */
	fixed = 5 + 8 + 7 + 10 + 6 + 6 + (sw + 1) + (wd + 2);
	/*
	 * THE NAME COLUMN IS AS WIDE AS THE LONGEST NAME IN THIS TABLE, and no
	 * longer sized from what the box has left over.
	 *
	 * Sizing it from the box was what forced the choice between losing
	 * characters off the name and writing past the border. Sizing it from
	 * the DATA removes the choice: the row has one natural width, the box
	 * shows as much of it as it can, and the rest is reached by scrolling
	 * sideways. It also means a table of short names does not carry a
	 * forty-column gutter it never uses.
	 */
	for (i = 0; (uint32_t)i < n; i++) {
		const uint8_t *r = sym_rec(b, (uint32_t)nb, rec[i]);
		int L = 0;

		if (!r)
			continue;
		while (L < (int)KOF_SYM_NAMELEN &&
		       r[KOF_SYM_R_NAME + (uint32_t)L])
			L++;
		if (L > nw)
			nw = L;
	}
	if (nw < 4)
		nw = 4;                     /* the heading says "name" */
	natural = fixed + nw + 1;
	vis = w - 3;
	hmax = natural > vis ? natural - vis : 0;
	if (v->sym_hoff > hmax)
		v->sym_hoff = hmax;
	if (v->sym_hoff < 0)
		v->sym_hoff = 0;
	sc.o = o;
	sc.from = v->sym_hoff;
	sc.to = v->sym_hoff + vis;
	sc.rec = 0;
	sc.rec_n = 0;
	/* Row 0 of the recording is the first RECORD row, not the heading: a
	 * heading is not something a reader selects, and starting the text at
	 * the first row of data is what lets dlg_at be a subtraction. */
	dlg_rec_begin(v, y + 3, x + 2);

	/* Top border, with the title sunk into it. */
	symd_row(o, y);
	out_str(o, A_DIM);
	out_glyph(o, G_TL);
	out_glyph(o, G_H);
	out_str(o, A_OFF A_BOLD " Symbols " A_OFF A_DIM);
	/*
	 * w - 12, counted rather than guessed: the row is one corner, one rule,
	 * the nine characters of " Symbols ", the fill, and the other corner -
	 * so the fill is w - 12 and the row comes to w. It was w - 13, which
	 * drew the box one column narrower at the top than every row under it,
	 * and than every other dialog in the tool.
	 */
	for (i = 0; i < w - 12; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_TR);
	out_str(o, A_OFF);

	/*
	 * The tabs and the close button.
	 *
	 * Both halves are always offered, even the empty one, and each says how
	 * many records it has. A tab that disappeared when it was empty would
	 * make "this object imports nothing" indistinguishable from "there is
	 * no imports tab in this build", and the count is the answer to the
	 * question the reader opened the dialog with.
	 */
	symd_row(o, y + 1);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF " ");
	for (i = 0; i < 2; i++) {
		uint8_t which = i ? SYMN_EXP : SYMN_IMP;
		/* How many records the half holds, counted by the engine's
		 * extents like the tree row's size is. */
		uint32_t cnt = v->probe
			     ? sym_half(ob, sym_row_mask(which), v->probe,
					KOF_SCAN_MAX_EXTENTS, 0)
			     : 0u;

		v->sy_tab[i][0] = o->col_base + (int)o->col_hint;
		out_fmt(o, "%s[ %s %u ]" A_OFF " ",
			v->sym_open == which ? A_SEL : A_ID,
			i ? "SYM_EXP" : "SYM_IMP", cnt);
		v->sy_tab[i][1] = o->col_base + (int)o->col_hint - 1;
	}
	out_fmt(o, A_DIM "%s, %u record%s%s" A_OFF,
		sym_origin_str(b, (uint32_t)nb), n, n == 1 ? "" : "s",
		(nb > KOF_SYM_H_TRUNC && b && b[KOF_SYM_H_TRUNC])
			? ", TRUNCATED" : "");
	/* The close button hard against the right edge, where a close button
	 * is, rather than after text whose length changes with the object. The
	 * gap in front of it is padded, not skipped - see symd_edge. */
	while ((int)o->col_hint < w - 6)
		out_str(o, " ");
	v->sy_close[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[x]" A_OFF, A_WARN);
	v->sy_close[1] = o->col_base + (int)o->col_hint - 1;
	symd_edge(o, w);

	/* Column heading, to the same widths and separators as the rows. */
	symd_row(o, y + 2);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF " ");
	/*
	 * sec is RIGHT-aligned, unlike every other text column here.
	 *
	 * Its values are the short ones - "UND", "ABS", or an index of one to
	 * five digits - and size beside it is a right-aligned number, so
	 * left-aligning sec pushed the two apart by the whole of its unused
	 * width plus the whole of size's leading padding: "ABS" and a size of
	 * 0 sat ten columns apart with nothing in between. Right-aligned, the
	 * two columns meet at their values, which is also how two adjacent
	 * numeric columns should read. The width is unchanged - this is where
	 * the characters sit in the field, not how wide the field is.
	 */
	sc.vcol = 0;
	/*
	 * ONE CALL PER COLUMN, exactly as the rows below do it.
	 *
	 * It was a single format string for the whole heading, and that
	 * silently lost the last column: sclip_fmt renders into a fixed buffer
	 * before clipping, and a heading with a forty-column name field runs
	 * past it, so "value" was truncated away by vsnprintf with nothing to
	 * show that it had been. Per column, no single piece can outgrow the
	 * buffer however wide the name gets, and the heading is built the same
	 * way as the row it labels - which is the only way the two stay in step.
	 */
	sclip_fmt(&sc, A_S_HEAD, "%-4s ",   "rec");
	sclip_fmt(&sc, A_S_HEAD, "%-7s ",   "type");
	sclip_fmt(&sc, A_S_HEAD, "%-6s ",   "bind");
	sclip_fmt(&sc, A_S_HEAD, "%-9s ",   "vis");
	sclip_fmt(&sc, A_S_HEAD, "%-5s ",   "flags");
	sclip_fmt(&sc, A_S_HEAD, "%-*.*s ", nw, nw, "name");
	sclip_fmt(&sc, A_S_HEAD, "%5s ",    "sec");
	sclip_fmt(&sc, A_S_HEAD, "%*s ",    sw, "size");
	sclip_fmt(&sc, A_S_HEAD, "%*s",     wd + 2, "value");
	symd_edge(o, w);

	for (i = 0; i < rows; i++) {
		uint64_t at = v->sym_at + (uint64_t)i;
		const uint8_t *r = (at < (uint64_t)n)
				 ? sym_rec(b, (uint32_t)nb, rec[at]) : 0;
		char fl[8], shn[8];
		const char *mark;

		symd_row(o, y + 3 + i);
		out_str(o, A_DIM);
		out_glyph(o, G_V);
		out_str(o, A_OFF " ");
		sc.rec = dlg_rec_buf(v);
		sc.rec_n = 0;

		if (!r) {
			/* Nothing to draw, but the row still has to be blanked
			 * INSIDE the border: the box is over other content, and
			 * a clear-to-end-of-line would take the rest of the
			 * screen with it. symd_edge does the filling. */
			(void)0;
		} else {
			sym_flag_str(r[KOF_SYM_R_FLAGS], fl);
			sym_shn_str(r, shn, sizeof shn);
			/*
			 * IS THIS THE ROW A HEURISTIC NAMED.
			 *
			 * Compared on the symbol's own VALUE against what the
			 * rule reported - which is exactly why the rule reports
			 * a value and not a record index. This table is the
			 * SPLIT one, imports and exports renumbered from zero,
			 * so an index taken from the engine's block would name
			 * the wrong row here.
			 *
			 * Nothing in this file repeats the test the rule made.
			 * It only asks "was it this one", which is what keeps
			 * the two from ever disagreeing about the answer.
			 *
			 * payload_at is guarded because a rule may report
			 * nothing and zero IS a real symbol value - every
			 * undefined symbol has it - so "no payload" must not be
			 * spelled as an address.
			 */
			mark = (ob->payload_at &&
				sym_u64(r, KOF_SYM_R_VALUE) == ob->payload_at)
			       ? A_S_FOUND : 0;
			sc.vcol = 0;
			/*
			 * DECIMAL, unlike everything else here. It is not a
			 * number the file contains - it is how many records in
			 * this one is, which the reader counts rather than
			 * reads - and printing a count in hex invites it to be
			 * read as an offset into something.
			 */
			sclip_fmt(&sc, mark ? mark : A_S_IDX, "%4llu ",
				  (unsigned long long)at);
			sclip_fmt(&sc, mark ? mark : A_S_TYPE, "%-7s ",
				  sym_type_str(r[KOF_SYM_R_TYPE]));
			sclip_fmt(&sc, mark ? mark : A_S_BIND, "%-6s ",
				  sym_bind_str(r[KOF_SYM_R_BIND]));
			sclip_fmt(&sc, mark ? mark : A_S_VIS, "%-9s ",
				  sym_vis_str(r[KOF_SYM_R_VIS]));
			sclip_fmt(&sc, mark ? mark : A_S_FLAG, "%-5s ", fl);
			/*
			 * The name, in the middle now, and PADDED TO nw so the
			 * three columns after it line up.
			 *
			 * Printed as the bytes the record holds rather than as
			 * a C string: it is NUL-padded to a fixed 40 and not
			 * necessarily terminated, so a %s would run into the
			 * next field. Clipped to nw for the same reason it is
			 * padded to it - nothing here turns autowrap off, so a
			 * name written past the edge would wrap and overwrite
			 * the screen outside the box.
			 */
			sclip_name(&sc, r, nw, mark);
			sclip_puts(&sc, A_OFF, " ");
			sclip_fmt(&sc, mark ? mark : A_S_SHN, "%5s ", shn);
			sclip_fmt(&sc, mark ? mark : A_S_SIZE, "%*llu ", sw,
				  (unsigned long long)sym_u64(r,
							KOF_SYM_R_SIZE));
			/* "0x", because this one IS a number out of the file
			 * and an address at that - and it now sits next to a
			 * decimal size and a decimal record number, where an
			 * unmarked base is a guess. */
			sclip_fmt(&sc, mark ? mark : A_S_VAL, "0x%0*llx", wd,
				  (unsigned long long)sym_u64(r,
							KOF_SYM_R_VALUE));
		}
		symd_edge(o, w);
		if (sc.rec)
			dlg_rec_row(v, &sc);
	}

	/* Bottom border. */
	symd_row(o, y + h - 1);
	out_str(o, A_DIM);
	out_glyph(o, G_BL);
	for (i = 0; i < w - 2; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_BR);
	out_str(o, A_OFF);

	/*
	 * The scrollbar ON the right border, not inside it.
	 *
	 * Inside, it drew a second vertical line one column in from the first,
	 * and since the track is the same dim U+2502 as the border the pair
	 * read as a doubled border with a bright spot in it rather than as a
	 * scrollbar. On the border there is one line, and the bold thumb says
	 * where in the table the reader is. Drawn last so it replaces the
	 * border on the rows it covers, and only when there is more than fits -
	 * the same rule the panes use.
	 */
	if (n > (uint32_t)rows)
		scrollbar(o, x + w - 1, y + 3, y + 3 + rows - 1,
			  v->sym_at, n, (uint64_t)rows);
	/* Last, so the selection is over everything else the box drew. */
	dlg_paint_sel(o, v);
}

/*
 * A click in the dialog. Returns non-zero when it was the dialog's, which is
 * how the caller knows not to route it on to whatever is underneath.
 *
 * EVERY click is swallowed while it is up, inside the box or outside it, which
 * is what makes it a modal rather than a floating panel. Two reasons, and the
 * second is the one that matters: a click on a record must not fall through and
 * select a byte in the pane behind it, and a click on the TREE must not move
 * the cursor to another object - the dialog shows the symbols of whichever
 * object is selected, so that would silently replace the table being read with
 * a different one. Closing is [x], Escape or q.
 */
static int symd_click(struct view *v)
{
	int y = symd_y(), i;

	if (g_my == y + 1) {
		if (g_mx >= v->sy_close[0] && g_mx <= v->sy_close[1]) {
			dlg_close(v);
			return 1;
		}
		for (i = 0; i < 2; i++)
			if (g_mx >= v->sy_tab[i][0] &&
			    g_mx <= v->sy_tab[i][1]) {
				uint8_t which = i ? SYMN_EXP : SYMN_IMP;

				/* Switching tabs goes back to the top. The
				 * offset is a position in THIS table and means
				 * somewhere else in the other one. */
				if (v->sym_open != which) {
					v->sym_open = which;
					v->sym_at = 0;
					v->sym_hoff = 0;
				}
				return 1;
			}
	}
	return 1;
}

/*
 * Sideways, in columns, positive to the right.
 *
 * The upper bound is NOT clamped here: it depends on the longest name in the
 * table and on the box's width, both of which draw_symbols works out, so it
 * clamps there on the way past. Clamping in two places from two different
 * derivations is how the two end up disagreeing.
 */
static void symd_hscroll(struct view *v, int d)
{
	v->sym_hoff += d;
	if (v->sym_hoff < 0)
		v->sym_hoff = 0;
}

/* The wheel and the keys, in one place so they cannot disagree about the
 * clamp. `d` is in records, positive downwards. */
static void symd_scroll(struct view *v, int64_t d)
{
	uint64_t max = symd_max(v);

	if (d < 0) {
		uint64_t up = (uint64_t)(-d);

		v->sym_at = v->sym_at > up ? v->sym_at - up : 0;
	} else {
		v->sym_at += (uint64_t)d;
	}
	if (v->sym_at > max)
		v->sym_at = max;
}

/*
 * Open the dialog on the half that has something in it.
 *
 * Exports first because that is what almost every object has and what a reader
 * asking about a shellcode loader is after, but an object with only imports -
 * a stripped dynamic executable, which is most of them - opens on imports
 * rather than on an empty table it has to be told to leave.
 */
static void symd_open(struct view *v)
{
	const struct object *o = cur_obj(v);

	v->sym_at = 0;
	v->sym_hoff = 0;
	/* Exports first when there are any, since that is the half a reader
	 * opening this is usually after. Both counts come from the engine. */
	v->sym_open = SYMN_EXP;
	if (v->probe &&
	    !sym_half(o, KOF_SCAN_SYM_EXP, v->probe, KOF_SCAN_MAX_EXTENTS, 0) &&
	    sym_half(o, KOF_SCAN_SYM_IMP, v->probe, KOF_SCAN_MAX_EXTENTS, 0))
		v->sym_open = SYMN_IMP;
}

/* ---- the shellcode dialog ---------------------------------------------------
 *
 * What "Find shellcode in variables" shows, and it FINDS NOTHING ITSELF.
 *
 * The heuristic ran during the scan and reported where the payload is - see
 * bases/heur/scloader_00.c and on_debug - so this dialog reads that answer and
 * shows the bytes it points at. That is the whole design: the test lives in one
 * place, in the engine, where it is measured, and the menu item is a way of
 * asking to see what it concluded rather than a second implementation of it.
 *
 * WHY A DIALOG AND NOT A REGION. The bytes are already visible in the hex pane
 * as part of DATA - what is missing is knowing WHICH bytes, and that is one
 * address and one length. A dialog is the shape of "here is the answer to the
 * question you asked", and it closes when the reader is done with it.
 */


static int goto_top(void)
{
	return g_rows - GOTO_H - 1;
}

/* A row of the box, from column one so the border owns the left edge. */
static void goto_row(struct out *o, int y)
{
	out_at(o, y, 1);
	o->col_hint = 0;
}

static int find_top(void)
{
	return g_rows - FIND_H - 1;
}

/*
 * A row of the dialog: positioned, written, then cleared to the edge.
 *
 * Not cleared first. Every row here used to erase to the end of the line before
 * anything was written into it, so each keystroke put the whole dialog through
 * a blank state before it came back - which is what the flicker while typing
 * was.
 */
static void find_row(struct out *o, int y)
{
	out_at(o, y, 3);
	o->col_hint = 0;
}

/*
 * The number typed in, or KOF_BROKEN when it is not one.
 *
 * The parsing itself is in goto_parse.h, where a test can reach it - see the
 * note there on why the base rules are the part worth testing. This only
 * translates that header's "bad" into the engine's KOF_BROKEN, which are the
 * same value but named for two different vocabularies.
 */
static uint64_t goto_value(const struct view *v)
{
	uint64_t n = kof_goto_parse(v->gotobuf);

	return n == KOF_GOTO_BAD ? KOF_BROKEN : n;
}

/*
 * Take the offset there, and SELECT the byte as well as scrolling to it.
 *
 * Scrolling alone puts the answer on the screen and leaves the reader to find
 * which of sixteen columns it was - so the byte is selected, which is also what
 * makes the disassembly panel and every menu item that works on a selection
 * point at it.
 */
static void goto_take(struct view *v)
{
	uint64_t val = goto_value(v), fo;

	if (val == KOF_BROKEN) {
		say_err(v, "%s", "Not a number");
		return;
	}
	fo = v->goto_file ? val : view_map(v, val, 0);
	{
		/*
		 * Bounded by WHAT THE ROW IS SHOWING, not by the file.
		 *
		 * On a symbol row view_map returns an offset into the built
		 * block, so comparing it with the file size let an offset past
		 * the end of a small block through and refused one inside a
		 * large file's block.
		 */
		uint64_t bn = 0;

		(void)view_bytes(v, &bn);
		if (v->goto_file)
			bn = cur_obj(v)->buf.n;
		if (fo == KOF_BROKEN || fo >= bn) {
			say_err(v, "Past the end of the %s",
				v->goto_file ? "file" : "region");
			return;
		}
	}
	view_show_in(v, v->node[v->sel_node].obj,
		     v->node[v->sel_node].sym, fo);
	{
		uint64_t r = view_unmap(v, fo);

		if (r != KOF_BROKEN) {
			v->sel_a = v->sel_b = r;
			v->sel_from_dis = 0;
		}
	}
	v->goto_open = 0;
	v->edit = 0;
	say_note(v, "At file offset 0x%llx", (unsigned long long)fo);
}

/*
 * GO TO, one line: the number, what it is measured from, and what it resolved
 * to.
 *
 * The resolved value is shown while it is being typed rather than after the
 * jump, because an offset typed into the wrong base is the mistake this dialog
 * exists to make, and seeing "0x120 -> file 0x1120" says which base was used
 * before Enter commits to it.
 */
/* Fill the row out to the right border and close it. */
static void goto_edge(struct out *o)
{
	while ((int)o->col_hint < g_cols - 1)
		out_str(o, " ");
	out_glyph(o, G_V);
}

static void draw_goto(struct out *o, struct view *v)
{
	int top = goto_top(), i;
	uint64_t val = goto_value(v);
	int ok = val != KOF_BROKEN;

	if (top < 1 || g_cols < 24)
		return;                 /* no room to draw a box honestly */

	/* Top border. */
	goto_row(o, top);
	out_str(o, A_DIM);
	out_glyph(o, G_TL);
	for (i = 0; i < g_cols - 2; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_TR);
	out_str(o, A_OFF);

	/*
	 * The field and what the number is measured from.
	 *
	 * Every click box is recorded as col_base + col_hint, not 1 + col_hint:
	 * col_hint counts from wherever the row was positioned, so the shorter
	 * form is only right for a row that starts at column one. The find
	 * dialog's boxes have been two columns off for exactly that reason -
	 * see the note on col_base - and this box is not going to repeat it.
	 */
	goto_row(o, top + 1);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF);
	out_fmt(o, A_DIM " Go to " A_OFF);
	v->g_txt[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == 520 ? A_SEL : A_ID);
	field_draw(o, v->gotobuf, v->caret, &v->goto_off, 18,
		   v->edit == 520, "offset", v->field_all);
	out_str(o, "]" A_OFF);
	v->g_txt[1] = o->col_base + (int)o->col_hint - 1;
	out_fmt(o, A_DIM "  as " A_OFF);
	v->g_mode[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s]" A_OFF, A_ID, v->goto_file ? "File" : "Region");
	v->g_mode[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, A_DIM);
	goto_edge(o);
	out_str(o, A_OFF);

	/*
	 * WHAT THE NUMBER RESOLVED TO, while it is being typed.
	 *
	 * An offset typed in the wrong base is the mistake this box invites -
	 * "10" is sixteen here - so it is shown in both bases before Enter
	 * commits to it, and a field that is not a number says so rather than
	 * waiting for the jump to fail.
	 */
	goto_row(o, top + 2);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF);
	if (!v->gotobuf[0])
		out_fmt(o, A_DIM " hex by default - 0x for hex, 0n for decimal"
			A_OFF);
	else if (!ok)
		out_fmt(o, " %snot a number" A_OFF, A_WARN);
	else
		out_fmt(o, A_DIM " = " A_OFF "%s0x%llx" A_OFF A_DIM
			" = %llu, from the %s" A_OFF, A_ID,
			(unsigned long long)val, (unsigned long long)val,
			v->goto_file ? "file" : "region");
	out_str(o, A_DIM);
	goto_edge(o);
	out_str(o, A_OFF);

	goto_row(o, top + 3);
	out_str(o, A_DIM);
	out_glyph(o, G_V);
	out_str(o, A_OFF);
	out_str(o, " ");
	v->g_go[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Go ]" A_OFF, ok ? A_ID : A_DIM);
	v->g_go[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->g_cancel[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_ID "[ Cancel ]" A_OFF);
	v->g_cancel[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, A_DIM);
	goto_edge(o);
	out_str(o, A_OFF);

	/* Bottom border. */
	goto_row(o, top + 4);
	out_str(o, A_DIM);
	out_glyph(o, G_BL);
	for (i = 0; i < g_cols - 2; i++)
		out_glyph(o, G_H);
	out_glyph(o, G_BR);
	out_str(o, A_OFF);
}

/*
 * A click inside the Go to box. Mirrors find_click, including the rule that a
 * click OUTSIDE only takes the caret away - the dialog keeps its place until
 * Cancel or Esc, because losing a half-typed offset to a stray click on the
 * hex pane is the kind of thing a tool only has to do once.
 */
static int goto_click(struct view *v)
{
	int top = goto_top();

	if (g_my < top || g_my >= top + GOTO_H) {
		v->edit = 0;
		return 0;
	}
	if (g_my == top + 1 && g_mx >= v->g_txt[0] && g_mx <= v->g_txt[1]) {
		v->edit = 520;
		return 1;
	}
	if (g_my == top + 1 && g_mx >= v->g_mode[0] && g_mx <= v->g_mode[1]) {
		/* File offsets are what every report and every finding names;
		 * region offsets are what the hex gutter shows. Both are "the
		 * offset" depending on what is being read, so it is a toggle
		 * rather than a guess. */
		v->goto_file = !v->goto_file;
		return 1;
	}
	if (g_my == top + 3) {
		if (g_mx >= v->g_cancel[0] && g_mx <= v->g_cancel[1]) {
			v->goto_open = 0;
			v->edit = 0;
		} else if (g_mx >= v->g_go[0] && g_mx <= v->g_go[1]) {
			goto_take(v);
		}
	}
	return 1;
}

static void draw_find(struct out *o, struct view *v)
{
	int top = find_top(), y, i;

	find_row(o, top + 1);
	out_fmt(o, A_DIM "Find " A_OFF);
	v->f_txt[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == 500 ? A_SEL : A_ID);
	field_draw(o, v->find, v->caret, &v->find_off, 40, v->edit == 500, "", v->field_all);
	out_str(o, "]" A_OFF);
	v->f_txt[1] = o->col_base + (int)o->col_hint - 1;
	out_fmt(o, A_DIM "  as " A_OFF);
	v->f_mode[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s]" A_OFF, A_WARN, v->find_hex ? "Hex" : "Text");
	v->f_mode[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "\033[K");

	find_row(o, top + 2);
	v->f_rx[0] = o->col_base + (int)o->col_hint;
	/* Bright black on white, not on bright black: the same colour twice is
	 * a grey block where a label should be. */
	out_fmt(o, "\033[47;90m[ ] Regex" A_OFF);
	v->f_rx[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "   ");
	v->f_ic[0] = o->col_base + (int)o->col_hint;
	if (v->find_hex)
		out_fmt(o, "\033[47;90m[ ] Ignore case" A_OFF);
	else
		out_fmt(o, "%s[%s] Ignore case" A_OFF, A_ID,
			v->find_icase ? "x" : " ");
	v->f_ic[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "   ");
	v->f_all[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[%s] Search whole object" A_OFF, A_ID,
		v->find_scope ? "x" : " ");
	v->f_all[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "\033[K");

	find_row(o, top + 3);
	v->f_next[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Find next ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_next[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->f_back[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, "%s[ Find previous ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_back[1] = o->col_base + (int)o->col_hint - 1;
	out_str(o, "  ");
	v->f_cancel[0] = o->col_base + (int)o->col_hint;
	out_fmt(o, A_ID "[ Cancel ]" A_OFF);
	v->f_cancel[1] = o->col_base + (int)o->col_hint - 1;
	/* Where the hit is belongs on the status line, which says it already.
	 * Saying it twice made the dialog a row taller for no new fact. */
	out_str(o, "\033[K");

	/*
	 * The frame, drawn after the content because the content rows clear to
	 * the end of the line and would take the right edge with them.
	 *
	 * Light box drawing rounded at the corners, the same glyphs the Go to
	 * box and the scrollbar use - a row of ASCII dashes beside a U+2502
	 * scrollbar looked like two different programs.
	 */
	for (y = top; y < top + FIND_H; y++) {
		out_at(o, y, 1);
		out_str(o, A_DIM);
		if (y == top || y == top + FIND_H - 1) {
			out_str(o, y == top ? G_TL : G_BL);
			for (i = 2; i < g_cols; i++)
				out_str(o, G_H);
			out_str(o, y == top ? G_TR : G_BR);
			out_str(o, A_OFF);
			continue;
		}
		out_str(o, G_V " " A_OFF);
		out_at(o, y, g_cols);
		out_str(o, A_DIM G_V A_OFF);
	}
}

/* Which control a click landed on. */
/*
 * Which control a click landed on, and whether the dialog wanted it at all.
 *
 * A click outside the box is NOT a close. The dialog is a tool for looking
 * through the object, so moving the tree to another region while it is open is
 * an ordinary thing to do - and the next search then runs in the region that is
 * now current, which is the whole point of it staying. Cancel and Esc are what
 * close it, because those are the two things that mean "I am done".
 */
static int find_click(struct view *v)
{
	int top = find_top();

	if (g_my < top || g_my >= top + FIND_H) {
		v->edit = 0;            /* the field loses the caret, not the
					 * dialog its place */
		return 0;
	}
	if (g_my == top + 1 && g_mx >= v->f_txt[0] && g_mx <= v->f_txt[1]) {
		v->edit = 500;
		return 1;
	}
	if (g_my == top + 1 && g_mx >= v->f_mode[0] &&
	    g_mx <= v->f_mode[1]) {
		v->find_hex = !v->find_hex;
		v->find_at = KOF_BROKEN;
		return 1;
	}
	if (g_my == top + 2) {
		if (!v->find_hex && g_mx >= v->f_ic[0] && g_mx <= v->f_ic[1]) {
			v->find_icase = !v->find_icase;
			v->find_at = KOF_BROKEN;
		} else if (g_mx >= v->f_all[0] && g_mx <= v->f_all[1]) {
			v->find_scope = !v->find_scope;
			v->find_at = KOF_BROKEN;
		}
		return 1;
	}
	if (g_my == top + 3) {
		if (g_mx >= v->f_cancel[0] && g_mx <= v->f_cancel[1]) {
			v->find_open = 0;
			v->edit = 0;
		} else if (!v->find[0]) {
			;
		} else if (g_mx >= v->f_next[0] && g_mx <= v->f_next[1]) {
			find_run(v, 0);
		} else if (g_mx >= v->f_back[0] && g_mx <= v->f_back[1]) {
			find_run(v, 1);
		}
	}
	return 1;
}

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
	if (rclick && !((g_my >= hex_top() && g_my <= hex_last() &&
			 g_mx > TREE_W && !v->show_list && !v->menu_open) ||
			(g_disasm_rows && g_my >= dis_top() &&
			 g_my <= hex_bot() && g_mx > TREE_W &&
			 !v->show_list && !v->menu_open)))
		return;

	/*
	 * The help box takes any click, the bar takes the row it owns and
	 * whatever is under an open menu. Both before the panes, for the same
	 * reason the chooser is: what is drawn on top is asked first.
	 */
	if (v->help_open) {
		v->help_open = 0;
		return;
	}
	if (v->bar_open >= 0) {
		int i = bar_item_at(v, g_my, g_mx);

		if (i >= 0) {
			bar_run(v, i);
			return;
		}
	}
	if (g_my == 1) {
		int m;

		v->bar_open = -1;
		for (m = 0; m < BM_COUNT; m++) {
			int c0 = bar_col(m);

			if (g_mx >= c0 &&
			    g_mx < c0 + (int)strlen(bar_name[m]) + 2) {
				v->bar_open = m;
				v->bar_sel = -1;
				v->bar_sub = -1;
				break;
			}
		}
		return;
	}
	if (v->bar_open >= 0) {
		v->bar_open = -1;       /* a click anywhere else closes it */
		v->bar_sub = -1;
		return;
	}

	/*
	 * A CLICK INSIDE THE OPEN FIELD IS A CARET, NOT A CLICK AWAY.
	 *
	 * Ahead of everything that reads the panel, and ahead of `v->edit = 0`
	 * below, because that assignment is what made this impossible: the
	 * strings row already carried a branch for "the click landed in the box
	 * that is open", and it could never be true - edit had been cleared two
	 * screens earlier in the same function. So clicking the character you
	 * wanted to fix closed the box and jumped the pane to the bytes.
	 *
	 * Done here rather than per field so the answer is the same in all of
	 * them: the column under the pointer, plus however far the box is
	 * scrolled, is the character the caret goes to - and past the end of
	 * the text it goes to the end, which is where clicking the empty part
	 * of a box should put it.
	 */
	if (v->edit && g_fld.room > 0 && !v->ch.open && !v->menu_open &&
	    g_my == g_fld.row && g_mx >= g_fld.col &&
	    g_mx < g_fld.col + g_fld.room) {
		uint32_t k = g_fld.off + (uint32_t)(g_mx - g_fld.col);

		v->caret = k > g_fld.len ? g_fld.len : k;
		v->field_all = 0;
		/*
		 * And the field counts as already open.
		 *
		 * field_key puts the caret at the end whenever it sees a field
		 * it has not typed into yet - which is right when a box is
		 * opened by its button, and wrong here: the click has just said
		 * where the caret goes, and the next keystroke would move it
		 * back to the end before inserting anything.
		 */
		v->edit_prev = v->edit;
		return;
	}

	/* Before every other hit test: the box is opaque, and symd_click
	 * swallows anything that lands inside it. */
	/*
	 * THE SYMBOLS DIALOG'S TEXT SELECTION starts here, before the box's own
	 * hit test.
	 *
	 * A press on a row of text is the start of a drag; the close button and
	 * the tabs are tested by the box afterwards, and they are not on a text
	 * row, so the two cannot both claim a click. A press anywhere else
	 * inside the box clears whatever was selected, which is what every
	 * other text selection does and what makes a stray click a way OUT of a
	 * selection rather than something that leaves it stuck on screen.
	 */
	if (v->sym_open) {
		int r, c;

		if (dlg_at(v, g_my, g_mx, &r, &c)) {
			v->dlg_ar = v->dlg_br = r;
			v->dlg_ac = v->dlg_bc = c;
			v->dlg_have = 1;
			v->dlg_drag = 1;
			return;
		}
		v->dlg_have = 0;
		v->dlg_drag = 0;
	}
	if (v->sym_open && symd_click(v))
		return;
	if (v->goto_open && goto_click(v))
		return;
	if (v->find_open && find_click(v))
		return;

	/*
	 * A STRING EDIT IS COMMITTED BEFORE THE FOCUS GOES, not dropped.
	 *
	 * Every other field types straight into the thing it edits, so leaving
	 * it keeps what was typed. A pattern does not: it is typed into a
	 * scratch buffer and parsed back into the declaration when the field
	 * closes, and closing only ever happened on the keyboard path. So
	 * clicking away after editing a pattern threw the edit away without a
	 * word - the row still showed the old bytes, which reads as the edit
	 * having been saved until it is opened again and is not there.
	 */
	if (v->edit >= ED_STR && v->edit < ED_STR + MAX_DECL) {
		uint32_t si = (uint32_t)(v->edit - ED_STR);

		v->edit = 0;
		decl_edit_commit(v, si);
	}

	/* Any click leaves whatever was being typed. The header branch below
	 * puts the focus back if the click landed on a field, so this is the
	 * whole of "click away to stop editing". */
	v->edit = 0;

	if (v->ch.open) {
		int k = g_my - v->ch.row;

		if (g_mx >= v->ch.col && g_mx < v->ch.col + CH_W &&
		    k >= 0 && k < v->ch.n) {
			v->ch.sel = k;
			ch_take(v);
		} else {
			v->ch.open = 0;
			v->ch_up.open = 0;
		}
		return;
	}
	if (v->menu_open) {
		int k = g_my - v->menu_row;

		/* Anywhere off the menu dismisses it. A menu that only closes
		 * on the right key is a menu people leave open. */
		if (g_mx >= v->menu_col && g_mx < v->menu_col + MENU_W &&
		    k >= 0 && k < menu_rows(v)) {
			int a = menu_at_row(v, k);

			if (a >= 0 && menu_enabled(v, a))
				menu_run(v, a);
		}
		v->menu_open = 0;
		return;
	}
	/*
	 * The scrollbars and the divider come AFTER the overlays.
	 *
	 * They are painted underneath, so they have to be tested underneath: a
	 * chooser item that happened to land on the divider row sent the click
	 * to the divider and started a resize instead of choosing anything.
	 * Anything drawn on top of the panes must have first refusal on a
	 * click, which is the same order they are drawn in.
	 */
	{
		int which = bar_under(v);

		if (which) {
			/*
			 * On the thumb, take hold of it where it is; on the
			 * track, jump.
			 *
			 * A bar that recentres under the pointer every time it
			 * is touched cannot be dragged - the first press throws
			 * the view somewhere else and the drag continues from
			 * there, which is what "sometimes lands in the wrong
			 * place" is. One row of track is many bytes of a large
			 * object, so the jump will never be exact; taking hold
			 * of the thumb is how a fine adjustment is made.
			 */
			int top, bot, t0, t1 = 0;
			uint64_t total = 0, shown = 0, off = 0;

			if (which == 1) {
				uint64_t per = (uint64_t)(v->per > 0 ? v->per
								    : 16);
				top = hex_top(); bot = hex_last();
				total = v->rgn_len; off = v->rgn_at;
				shown = (uint64_t)(bot - top + 1) * per;
			} else if (which == 2) {
				top = hex_top(); bot = hex_bot();
				total = v->n_node; off = v->tree_top;
				shown = (uint64_t)(bot - top + 1);
			} else if (which == 4) {
				/*
				 * The disassembly panel's track is what the
				 * panel can reach: the hex pane's range when it
				 * follows the hex, and the PINNED RUN when it
				 * does not. Reading dis_hex_shown either way
				 * made the thumb of a pinned panel describe a
				 * window it does not have.
				 */
				top = dis_top(); bot = hex_bot();
				total = v->dis_len != KOF_BROKEN
					? v->dis_len : dis_hex_shown(v);
				off = (uint64_t)v->dis_bias;
				shown = dis_span_of(v);
			} else {
				top = decl_top() + 1;
				bot = decl_top() + g_decl_rows - 2;
				total = v->n_prow; off = v->prow_off;
				shown = (uint64_t)(g_decl_rows - 2);
			}
			t0 = bar_thumb(top, bot, off, total, shown, &t1);
			v->bar_drag = which;
			if (t0 < 0 || g_my < top + t0 || g_my >= top + t0 + t1)
				bar_to(v, which);
			return;
		}
	}

	/* Pressing the divider starts a resize; the drag handler does the rest.
	 * Tested before anything else claims the row, and only when there is a
	 * panel to resize. */
	/*
	 * A press on a panel ROW starts a line selection.
	 *
	 * The terminal's own selection is not available here - the viewer holds
	 * the mouse, which is what lets it do everything else - so copying a few
	 * instructions out has to be something the panel does itself.
	 */
	if (g_disasm_rows && g_my >= dis_top() && g_my <= hex_bot() &&
	    g_mx > TREE_W) {
		int idx = g_my - dis_top();

		/*
		 * The panel's own menu, which is a SHORT one.
		 *
		 * ctx 4 rather than 1|4: everything the hex pane offers is not
		 * wanted here. "View disassembly" would open what is already
		 * open; copying the ASCII of an instruction is not a thing
		 * anybody does. What is left is copying the text, copying the
		 * bytes behind it, declaring those bytes, and searching - which
		 * are the four questions the selection can answer.
		 */
		if (rclick) {
			/*
			 * The one-row fallback is for a panel with NOTHING
			 * picked - not for one showing a range picked in the
			 * hex pane. It used to fire on that too: the right
			 * click replaced the reader's range with the single row
			 * under the pointer, so the menu that opened offered to
			 * copy one line of what they had selected, and the rest
			 * of the highlight went out as the menu came up.
			 */
			if (!v->dis_have && !dis_hex_sel(v) &&
			    idx < v->dis_lines) {
				int ln = (int)strlen(v->dis_line[idx]);

				v->dis_a_at = v->dis_b_at = v->dis_line_at[idx];
				v->dis_ac = 0;
				v->dis_bc = ln > 0 ? ln - 1 : 0;
				v->dis_have = 1;
				dis_sync_bytes(v);
			}
			v->menu_ctx = 4;
			v->menu_off = v->sel_a != KOF_BROKEN
				      ? view_map(v, v->sel_a, 0) : 0;
			menu_open_at(v, g_my, g_mx);
			return;
		}

		/*
		 * Only where there is text.
		 *
		 * A press past the end of a line used to pick the whole line,
		 * so clicking the empty half of the panel lit a row for no
		 * reason anybody could see. The panel is text, and text is
		 * selected where it is.
		 */
		if (idx < v->dis_lines &&
		    g_mx >= TREE_W + 3 &&
		    g_mx < TREE_W + 3 + (int)strlen(v->dis_line[idx])) {
			int c = g_mx - (TREE_W + 3);

			v->dis_a_at = v->dis_b_at = v->dis_line_at[idx];
			v->dis_ac = v->dis_bc = c;
			v->dis_have = 1;
			v->dis_dragging = 1;
			v->act_msg[0] = 0;
			dis_sync_bytes(v);
		} else {
			/* Somewhere with nothing on it: the selection goes,
			 * rather than being left lit behind the click. */
			v->dis_have = 0;
			v->dis_dragging = 0;
		}
		return;
	}

	/*
	 * The disassembly panel's heading: a close button and a mode switch.
	 *
	 * Before the hex hit test, because the heading sits inside the hex
	 * column and a click there is about the panel rather than about a byte.
	 */
	if (g_disasm_rows && g_my == dis_top() - 1 && g_mx > TREE_W) {
		if (g_mx >= g_cols - 3) {
			v->dis_open = 0;
			g_disasm_rows = 0;
			v->dis_have = 0;
			return;
		}
		/* The mode, where it is written. Anywhere else on the heading
		 * does nothing, so a stray click on a rule is not a state
		 * change nobody asked for. */
		if (g_mx >= TREE_W + 5 && g_mx <= TREE_W + 24) {
			v->dis_bits = v->dis_bits == 64 ? 32 : 64;
			return;
		}
		return;
	}

	if (g_decl_rows && g_my == hex_bot() + 1) {
		v->sizing = 1;
		return;
	}

	if (v->show_list) {
		int row = g_my - list_top(v) - 1;
		int on = g_my > list_top(v) &&
			 g_my <= list_top(v) + (int)list_shown(v);

		if (on && !v->list_depth) {
			uint32_t k = list_nth(v, v->list_off + (uint32_t)row);

			/*
			 * A signature row shows that signature in the draft
			 * panel, the way opening a file in an editor shows the
			 * file. Its markers are reachable from the status bar,
			 * which is where somebody looking for one goes.
			 */
			if (k < ob->n_touch) {
				v->show_list = 0;
				v->list_depth = 0;
				if (draft_dirty(v))
					ch_open(v, CH_SWITCH, k,
						g_rows - 6, 4);
				else
					draft_show(v, k);
			}
			return;
		}
		if (on) {
			/* A marker row moves the hex pane to it. That is the
			 * whole point of listing where each one is. */
			const struct kof_touch *t = &ob->touch[v->sel_touch];
			uint32_t k = v->str_off + (uint32_t)row;

			if (v->sel_touch < ob->n_touch && k < t->n_str) {
				v->sel_str = k;
				if (t->str[k].at != KOF_BROKEN) {
					v->warn[0] = 0;
					/* Through view_show_in: a marker found
					 * in the symbol block has a block
					 * offset, and view_show would place it
					 * in the file. */
					view_show_in(v,
						     v->node[v->sel_node].obj,
						     sym_which_of(
							t->str[k].sym),
						     t->str[k].at);
				} else {
					/*
					 * A marker the module declares and
					 * this object does not have.
					 *
					 * The row prints its bytes in full, so
					 * it reads as present; the only thing
					 * that said otherwise was a dash in a
					 * numeric column, and clicking it did
					 * nothing and said nothing. Silence is
					 * the bug - there is a real answer
					 * here and it is worth a line.
					 */
					say_note(v, "Marker %u is not in this "
					 "object", k + 1u);
				}
			}
			return;
		}
		/* Anywhere off the dialog closes it - one that only closes on
		 * the right key is one people leave open. */
		v->show_list = 0;
		v->list_depth = 0;
		return;
	}
	if (g_decl_rows && g_my >= decl_top() && g_my < mark_row())
		v->pane = 3;
	if (g_decl_rows && g_my == decl_top()) {
		if (g_mx >= v->f_c0 && g_mx <= v->f_c1)
			v->edit = 1;
		else if (g_mx >= v->o_c0 && g_mx <= v->o_c1)
			ch_open(v, CH_OPT, 0, g_my + 1, g_mx);
		else if (g_mx >= v->t_c0 && g_mx <= v->t_c1)
			ch_open(v, CH_TYPE, 0, g_my, g_mx);
		/*
		 * n_c0/n_c1 is NOT tested here: it is the "[+ Matcher]" button
		 * and it is recorded on the MATCHERS row, not on this one. Read
		 * on the header row it claimed columns 2..12, which with a short
		 * or empty family is the blank space just right of the Family
		 * box - so a click there created a matcher nobody asked for. The
		 * matchers row tests it, where it was drawn.
		 */
		else if (g_mx >= v->g_c0 && g_mx <= v->g_c1)
			generate(v, 0);
		else if (v->sv_c0 > 0 && g_mx >= v->sv_c0 && g_mx <= v->sv_c1)
			generate(v, 1);
		else if (g_mx >= v->nw_c0 && g_mx <= v->nw_c1) {
			/* No confirmation. The panel is a draft, not a
			 * document: what it holds was either loaded from a file
			 * that still exists or typed a moment ago, and a dialog
			 * between the button and the blank sheet is a step in
			 * the way of the thing the button is for. */
			if (v->n_decl || v->family[0])
				draft_reset(v);
		} else if (g_mx >= v->nt_c0 && g_mx <= v->nt_c1)
			v->edit = 501;
		return;
	}
	if (g_decl_rows && g_my > decl_top() && g_my < mark_row()) {
		/*
		 * Which row is which is a walk, not arithmetic - and it is the
		 * same walk that drew them. Two copies of that shape would be
		 * two things to keep in step, and the one that drifts is the
		 * one nobody is looking at.
		 */
		int want = g_my - decl_top() - 1 + (int)v->prow_off, r = 0;
		uint32_t g, i;

		/*
		 * AND IT MUST BE A ROW THAT IS ON THE SCREEN.
		 *
		 * The row test above accepts everything up to mark_row() - 1,
		 * which is one row MORE than PR_VIS lays out: the last of those
		 * is the dashed rule draw_marker_line paints, not a draft row.
		 * So a click on the rule resolved to prow_off + g_decl_rows - 2
		 * - the first row past the window - and the walk below happily
		 * found whatever marker, matcher or condition sits there. At the
		 * far right of the row (g_mx >= g_cols - 4) that is the remove
		 * button, so clicking the separator DELETED something that was
		 * not on the screen and could not be seen to go.
		 *
		 * Tested against PR_VIS, the same predicate the drawing uses, so
		 * the two cannot disagree about which rows exist.
		 */
		if (!PR_VIS(want))
			return;

		for (i = 0; i < (uint32_t)OPT_COUNT; i++) {
			if (!v->opt_on[i])
				continue;
			if (r == want) {
				if (g_mx >= g_cols - 4)
					v->opt_on[i] = 0;
				else if (g_mx >= v->opt_c0[i] &&
					 g_mx <= v->opt_c1[i]) {
					if (i == OPT_ARCH)
						ch_open(v, CH_ARCH, 0, g_my,
							g_mx);
					else if (i == OPT_SUBTYPE)
						ch_open(v, CH_SUBTYPE, 0,
							g_my, g_mx);
					else {
						/* A size is typed, so the
						 * field starts from what it
						 * says rather than empty. */
						snprintf(v->num, sizeof v->num,
							 "%llu",
							 (unsigned long long)
							 v->opt_val[i]);
						/* Opened by a click, so it
						 * starts selected: the first
						 * digit replaces rather than
						 * extends, which is what
						 * clicking a number and typing
						 * one means everywhere else. */
						v->num_fresh = 1;
						v->edit = 200 + (int)i;
					}
				}
				return;
			}
			r++;
		}
		{
			if (r == want) {
				uint32_t h;

				/*
				 * A NAME IS THE SUBJECT. Which range was
				 * pressed is passed as the menu's argument, so
				 * every item it offers is about that one.
				 */
				for (h = 0; h < v->n_rng_hs; h++)
					if (g_mx >= v->rng_hs[h][0] &&
					    g_mx <= v->rng_hs[h][1]) {
						ch_open(v, CH_RANGE2, h,
							g_my, g_mx);
						return;
					}
				if (g_mx >= v->rga_c0 && g_mx <= v->rga_c1)
					ch_open(v, CH_RANGE_ADD, 0, g_my, g_mx);
				return;
			}
			r++;
		}
		if (v->n_decl) {
			if (r == want) {
				/* The heading carries [Update string regions]
				 * now - see where it is drawn. */
				if (g_mx >= v->rgf_c0 && g_mx <= v->rgf_c1)
					draft_refresh(v);
				return;
			}
			r++;                    /* the "Strings" heading */
			for (i = 0; i < v->n_decl; i++, r++) {
				if (r != want)
					continue;
				v->sel_decl = i;
				if (g_mx >= g_cols - (int)STR_BTN_X) {
					decl_remove(v, i);
				} else if (g_mx >= g_cols - (int)STR_BTN_E &&
					   g_mx < g_cols - (int)STR_BTN_E + 3) {
					decl_edit_open(v, i);
				} else if (v->decl[i].n_hits > 1u &&
					   g_mx >= g_cols - (int)STR_BTN_PREV &&
					   g_mx < g_cols - (int)STR_BTN_PREV
						   + 3) {
					struct decl *d = &v->decl[i];

					d->cur_hit = (d->cur_hit + d->n_hits
						      - 1u) % d->n_hits;
					view_show_decl(v, d, d->hits[d->cur_hit]);
				} else if (v->decl[i].n_hits > 1u &&
					   g_mx >= g_cols - (int)STR_BTN_NEXT &&
					   g_mx < g_cols - (int)STR_BTN_NEXT
						   + 3) {
					struct decl *d = &v->decl[i];

					d->cur_hit = (d->cur_hit + 1u)
						     % d->n_hits;
					view_show_decl(v, d, d->hits[d->cur_hit]);
				} else if (v->edit == ED_STR + (int)i &&
					   g_mx >= v->str_by[i][0]) {
					/* A click inside the open field is a
					 * click in a text box, not a request to
					 * jump to the bytes. */
					return;
				} else if (!v->decl[i].hex &&
					   g_mx >= v->str_wc[i][0] &&
					   g_mx <= v->str_wc[i][0] + 8) {
					ch_open(v, CH_WORD, i, g_my, g_mx);
				} else if (!v->decl[i].hex &&
					   g_mx >= v->str_wc[i][0] + 10 &&
					   g_mx <= v->str_wc[i][1]) {
					ch_open(v, CH_CASE, i, g_my, g_mx);
				} else if (g_mx >= v->str_by[i][0] &&
					   g_mx <= v->str_by[i][1]) {
					/*
					 * The bytes are the one part of the row
					 * that names a place, so clicking them
					 * goes there - and the pane lights the
					 * run, which is the confirmation that
					 * it is the right one.
					 */
					/*
					 * BACK TO THE ONE YOU WERE ON.
					 *
					 * Not to the first: after stepping to
					 * an occurrence and scrolling the pane
					 * elsewhere, clicking the row is how
					 * you return to it. The first is where
					 * cur_hit starts, so nothing changes
					 * for a marker that occurs once.
					 */
					struct decl *d = &v->decl[i];

					if (d->n_hits) {
						if (d->cur_hit >= d->n_hits)
							d->cur_hit = 0;
						view_show_decl(v, d, d->hits[d->cur_hit]);
					} else if (d->at != KOF_BROKEN) {
						view_show_decl(v, d, d->at);
					} else {
						say_note(v, "String %u is "
							 "not in this object",
							 i + 1u);
					}
				}
				return;
			}
		}

		if (r == want)
			return;                 /* the matchers heading */
		r++;
		if (r == want) {
			if (g_mx >= v->n_c0 && g_mx <= v->n_c1)
				ch_open(v, CH_RULE, MAX_GROUP, g_my, g_mx);
			return;
		}
		r++;

		for (g = 0; g < v->n_grp; g++) {
			if (r == want) {
				v->cur_grp = g;
				v->warn[0] = 0;
				if (g_mx >= g_cols - 4)
					grp_remove(v, g);
				else if (g_mx >= v->grp_rl[g][0] &&
					 g_mx <= v->grp_rl[g][1])
					ch_open(v, CH_RULE, g, g_my, g_mx);
				else if (g_mx >= v->grp_rg[g][0] &&
					 g_mx <= v->grp_rg[g][1])
					ch_open(v, CH_RANGE, g,
						g_my, g_mx);
				else if (v->grp_th[g][0] > 0 &&
					 g_mx >= v->grp_th[g][0] &&
					 g_mx <= v->grp_th[g][1])
					ch_open(v, CH_THRESH, g, g_my - 2,
						g_mx);
				else if (v->grp_nt[g][0] > 0 &&
					 g_mx >= v->grp_nt[g][0] &&
					 g_mx <= v->grp_nt[g][1])
					v->edit = 300 + (int)g;
				return;
			}
			r++;
			if (r == want) {
				/* Where the ids start: past "     Markers: ". */
				int c2 = 15;

				v->cur_grp = g;
				if (v->p_c0[g][0] > 0 &&
				    g_mx >= v->p_c0[g][0] &&
				    g_mx <= v->p_c0[g][1]) {
					ch_open(v, CH_MARKER, g, g_my - 3,
						g_mx);
					return;
				}
				/*
				 * An id on this row is a marker; clicking it
				 * takes it back out of the matcher.
				 *
				 * EACH ID IS MEASURED, the way cnd_id_click
				 * measures the ones on a condition row. Three
				 * columns apiece assumed every id was one digit
				 * and the row prints ", %u": from the first
				 * two-digit id on - MAX_DECL is 32, so ids
				 * reach 32 - every id after it drifted one
				 * column further left, and the click removed
				 * the wrong marker or none. The hit window is
				 * the digits only, not the ", " that joins
				 * them, so the gap between two ids is dead
				 * rather than belonging to whichever is nearer.
				 */
				for (i = 0; i < v->n_decl; i++) {
					char num[8];
					int w;

					if (!(v->decl[i].grp & (1u << g)))
						continue;
					w = snprintf(num, sizeof num, "%u",
						     i + 1u);
					if (g_mx >= c2 && g_mx < c2 + w) {
						v->decl[i].grp &= ~(1u << g);
						return;
					}
					c2 += w + 2;    /* the ", " after it */
				}
				return;
			}
			r++;
		}

		if (r == want)
			return;                 /* the conditions heading */
		r++;
		if (r == want) {
			if (v->n_grp && g_mx >= v->a_c0 && g_mx <= v->a_c1)
				cnd_add(v, 0);
			return;
		}
		r++;

		for (g = 0; g < v->n_cseq; g++, r++) {
			uint32_t ci = v->cseq_idx[g];

			if (r != want)
				continue;
			v->cur_cnd = ci;

			if (v->cseq_kind[g] == CS_JOIN) {
				/*
				 * Only on the word itself, and through a list.
				 *
				 * A whole row that flips the meaning of a
				 * signature when it is clicked anywhere is a
				 * row that gets flipped by accident, and the
				 * accident leaves nothing behind to notice.
				 */
				if (v->cnd_jn[ci][0] > 0 &&
				    g_mx >= v->cnd_jn[ci][0] &&
				    g_mx <= v->cnd_jn[ci][1])
					ch_open(v, CH_LOGIC, ci, g_my - 2,
						g_mx);
				return;
			}
			if (v->cseq_kind[g] == CS_ADD) {
				if (v->n_grp && v->cnd_kid[ci][0] > 0 &&
				    g_mx >= v->cnd_kid[ci][0] &&
				    g_mx <= v->cnd_kid[ci][1])
					cnd_add(v, 1);
				return;
			}
			if (v->cseq_kind[g] == CS_MATCH) {
				if (v->cnd_mt[ci][0] > 0 &&
				    g_mx >= v->cnd_mt[ci][0] &&
				    g_mx <= v->cnd_mt[ci][1])
					ch_open(v, CH_CMATCH, ci, g_my - 3,
						g_mx);
				else if (v->cnd_op[ci][0] > 0 &&
					 g_mx >= v->cnd_op[ci][0] &&
					 g_mx <= v->cnd_op[ci][1])
					v->cnd[ci].op = !v->cnd[ci].op;
				/* A typed expression is a FIELD, not a list of
				 * ids - so it takes the caret rather than
				 * having one of its characters removed. */
				else if (v->cnd_ex[ci][0] > 0 &&
					 g_mx >= v->cnd_ex[ci][0] &&
					 g_mx <= v->cnd_ex[ci][1])
					v->edit = 103 + (int)ci;
				else
					cnd_id_click(v, ci);
				return;
			}

			/* CS_COND */
			if (g_mx >= g_cols - 4) {
				cnd_remove(v, ci);
				return;
			}
			if (g_mx >= v->cnd_lv[ci][0] &&
			    g_mx <= v->cnd_lv[ci][1])
				ch_open(v, CH_LEVEL, ci, g_my, g_mx);
			else if (v->cnd_vr[ci][0] > 0 &&
				 g_mx >= v->cnd_vr[ci][0] &&
				 g_mx <= v->cnd_vr[ci][1])
				ch_open(v, CH_VARIANT, ci, g_my, g_mx);
			else if (v->cnd_nm[ci][0] > 0 &&
				 g_mx >= v->cnd_nm[ci][0] &&
				 g_mx <= v->cnd_nm[ci][1])
				v->edit = 4 + (int)ci;
			return;
		}
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
	if (g_my >= hex_top() && g_my <= hex_last() && g_mx > TREE_W) {
		uint64_t at;

		v->pane = 1;
		if (rclick) {
			int per = v->per > 0 ? v->per : 16;
			int base = TREE_W + 3;
			uint64_t row0 = v->rgn_at +
					(uint64_t)(g_my - hex_top()) *
					(uint64_t)per;

			/* The offset column is its own thing to right-click on:
			 * it names a place, and the bytes name contents. */
			v->menu_ctx = (g_mx >= base && g_mx < base + 8) ? 2 : 1;
			v->menu_off = row0 < v->rgn_len
				      ? view_map(v, row0, 0) : 0;
			menu_open_at(v, g_my, g_mx);
			return;
		}
		if (byte_under(v, g_my, g_mx, &at)) {
			v->find_i = v->find_n = 0;
			/*
			 * A second click on the byte just clicked, soon after,
			 * is a double click. Timed rather than counted because
			 * a terminal reports two presses and nothing else - it
			 * has no notion of a double click to pass on.
			 */
			uint64_t now = now_ms();
			int again = at == v->last_click &&
				    now - v->last_click_ms < 400u;

			v->last_click = at;
			v->last_click_ms = now;
			v->sel_a = v->sel_b = at;
			v->sel_from_dis = 0;    /* the hex pane owns it now */
			dis_bias_to_sel(v);
			v->dragging = 1;
			/*
			 * A deliberate act outranks a stale confirmation.
			 *
			 * The status line's action slot ages out on its own, but
			 * four seconds is still four seconds during which a
			 * reader who has just dragged out a run sees what
			 * happened before it instead of the run they selected.
			 * Selecting bytes is a request for the readout; making
			 * it clears whatever was being announced.
			 */
			v->act_msg[0] = 0;
			v->dragged = 0;
			if (again) {
				select_run(v);
				v->dragging = 0;
				v->dragged = 1;
			}
		} else {
			/*
			 * Inside the pane but on nothing - past the ASCII
			 * column, or the gap between the two halves. The
			 * selection goes, for the reason the disassembly
			 * panel's does: bytes left lit behind a click that
			 * chose nothing are bytes the reader has to remember
			 * they did not choose.
			 */
			v->sel_a = v->sel_b = KOF_BROKEN;
			v->dragging = 0;
			v->dragged = 0;
			dis_bias_to_sel(v);
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

/*
 * ONE TEXT FIELD, FOR EVERY TEXT FIELD.
 *
 * Lifted out of the key handler so that a new box does not get a new editor.
 * Every field in this panel is expected to behave the way a text field behaves
 * anywhere - select all, copy, paste, arrows, Home, End, Delete, backspace,
 * insert at the caret - and the way to guarantee that is for there to be one
 * implementation of it rather than a family of near-copies that drift.
 *
 * `v->edit` names which field is open and is cleared here when it closes, so a
 * caller that has to do something on close - a string declaration, which has to
 * be parsed back out of the text - can see that it happened.
 *
 * Returns 1: a key that reaches a field is consumed by it.
 */
static int field_key(struct view *v, char *buf, size_t cap, int k)
{
	size_t n;

	n = strlen(buf);
	/* A field just opened puts the caret at the end of what is
	 * already in it, which is where typing continues from. */
	if (v->edit != v->edit_prev) {
		v->edit_prev = v->edit;
		v->caret = (uint32_t)n;
		v->field_all = 0;
	}
	if (v->caret > n)
		v->caret = (uint32_t)n;

	/*
	 * Copy and paste, with the keys everything else uses.
	 *
	 * A terminal keeps Ctrl+Shift+C and Ctrl+Shift+V for itself and
	 * passes the unshifted pair straight through, so these are free
	 * to take - and taking them is what makes a text field here
	 * behave like a text field anywhere else.
	 */
	if (k == 0x01) {                /* Ctrl+A */
		v->field_all = n != 0;
		return 1;
	}
	if (k == 0x03) {                /* Ctrl+C */
		copy_osc52(buf, n);
		copy_said(v, n);
		return 1;
	}
	/*
	 * Anything that writes replaces the selection first.
	 *
	 * Done here rather than in each branch so no branch can forget:
	 * a field that is shown as selected and then appends is worse
	 * than one that never offered selection.
	 */
	if (v->field_all && (k == 127 || k == 8 || k == K_DEL ||
			     k == 0x16 || k == K_PASTE ||
			     (k >= 0x20 && k < 0x7f))) {
		buf[0] = 0;
		n = 0;
		v->caret = 0;
		v->field_all = 0;
		if (k == 127 || k == 8 || k == K_DEL)
			return 1;
	}
	if (v->field_all && (k == K_LEFT || k == K_RIGHT ||
			     k == K_HOME || k == K_END || k == 27 ||
			     k == '\r' || k == '\n'))
		v->field_all = 0;
	if (k == 0x16 || k == K_PASTE) {        /* Ctrl+V, or a paste */
		/*
		 * A bracketed paste is the terminal handing over the system
		 * clipboard already - use it as given. A Ctrl+V asks the
		 * clipboard tools for it, so it pastes what any program would;
		 * only when none is installed does it fall back to this
		 * program's own last copy, which is the best it can then do.
		 */
		const char *src;
		size_t sn = paste_src(k, &src), i;

		for (i = 0; i < sn && n + 2u < cap; i++) {
			char c2 = src[i];

			if (c2 < 0x20 || c2 >= 0x7f)
				continue;   /* a field holds a line */
			memmove(buf + v->caret + 1u, buf + v->caret,
				n - v->caret + 1u);
			buf[v->caret++] = c2;
			n++;
		}
		return 1;
	}
	if (k == K_LEFT) {
		if (v->caret)
			v->caret--;
	} else if (k == K_RIGHT) {
		if (v->caret < n)
			v->caret++;
	} else if (k == K_HOME) {
		v->caret = 0;
	} else if (k == K_END) {
		v->caret = (uint32_t)n;
	} else if (k == 27 || k == '\r' || k == '\n') {
		v->edit = 0;
	} else if (k == 127 || k == 8) {
		/* Deletes what is BEFORE the caret, which is what
		 * backspace means; the character under it is what
		 * a delete key takes, below. */
		if (v->caret) {
			memmove(buf + v->caret - 1u, buf + v->caret,
				n - v->caret + 1u);
			v->caret--;
		}
	} else if (k == K_DEL) {
		if (v->caret < n)
			memmove(buf + v->caret, buf + v->caret + 1u,
				n - v->caret);
	} else if (k >= 0x20 && k < 0x7f && n + 2u < cap) {
		memmove(buf + v->caret + 1u, buf + v->caret,
			n - v->caret + 1u);
		buf[v->caret++] = (char)k;
	}
	return 1;
}

/*
 * The keyboard, while the menu bar is open. Returns 1 if it took the key.
 *
 * Left and right move between menus, up and down within one, Enter runs the
 * selected item - a submenu parent opens, everything else acts - and Escape
 * backs out one level. The same model every menu bar in a terminal uses, which
 * is the point: a reader does not have to learn this one.
 */
static int bar_key(struct view *v, int k)
{
	if (v->bar_open < 0)
		return 0;
	switch (k) {
	case K_LEFT:
		/*
		 * Out of a submenu first, and only then along the bar.
		 *
		 * The two directions are what a submenu is navigated with
		 * everywhere, and giving them the job is what lets Escape mean
		 * one thing. It used to walk the bar whatever was open, so the
		 * only way back out of a submenu was Escape - which then had to
		 * be pressed twice to leave the bar, once per level.
		 */
		if (v->bar_sub >= 0) {
			v->bar_sel = v->bar_sub;   /* back onto the parent */
			v->bar_sub = -1;
		} else {
			bar_open_menu(v, (v->bar_open + BM_COUNT - 1) %
					 BM_COUNT);
		}
		return 1;
	case K_RIGHT:
		/* Into the selected submenu when there is one; along the bar
		 * when there is not. */
		if (v->bar_sub < 0 && v->bar_sel >= 0 &&
		    bar_has_sub(v->bar_sel) && bar_enabled(v, v->bar_sel))
			bar_enter_sub(v, v->bar_sel);
		else if (v->bar_sub >= 0)
			break;                  /* already in it; nothing to do */
		else
			bar_open_menu(v, (v->bar_open + 1) % BM_COUNT);
		return 1;
	case K_UP:
		/* Inside an open submenu the arrows walk it; the submenu draws
		 * its own selection, so leave the bar cursor alone. */
		bar_move_item(v, -1);
		return 1;
	case K_DOWN:
		bar_move_item(v, +1);
		return 1;
	case '\r':
	case '\n':
		if (v->bar_sel >= 0)
			bar_run(v, v->bar_sel);
		return 1;
	case 27:
		/*
		 * ONE PRESS LEAVES THE BAR, from however deep in it.
		 *
		 * It used to unwind a level at a time, so leaving a submenu
		 * took two presses - and from the outside that is
		 * indistinguishable from an Escape that was dropped, which is
		 * exactly how it was reported. Escape means "I am done with
		 * this", and the level is not what a reader is counting.
		 */
		v->bar_open = v->bar_sel = v->bar_sub = -1;
		return 1;
	default:
		break;
	}
	return 1;                               /* the open bar swallows the rest */
}

static int handle(struct view *v, int k)
{
	int page = hex_last() - hex_top();

	/*
	 * Ctrl+C with a run of disassembly picked.
	 *
	 * First, because it is about a selection the reader can see, and every
	 * other owner of the keyboard below either has no selection or has its
	 * own copy already. The keyboard equivalent of the menu item, and the
	 * shortcut anybody tries first on highlighted text.
	 */
	/*
	 * F10 opens the menu bar, and closes it again.
	 *
	 * Before every mode below, because the bar is above them on screen and a
	 * reader reaching for the menu means the menu whatever else is up.
	 */
	if (k == K_F10) {
		if (v->bar_open >= 0)
			v->bar_open = v->bar_sel = v->bar_sub = -1;
		else
			bar_open_menu(v, BM_FILE);
		return 1;
	}
	/*
	 * An open bar owns the KEYBOARD, the same way the properties page does -
	 * and only the keyboard.
	 *
	 * bar_key swallows every key it does not use, which is right: a letter
	 * typed under an open menu must not reach the pane behind it. It is
	 * wrong for the mouse, and that is how this broke. A menu opened by
	 * CLICKING the bar could not then be clicked: the click on the item
	 * arrived here as K_CLICK, bar_key swallowed it, and click() - which
	 * holds the whole hit test for menu rows - was never reached. The menu
	 * stayed down, every later click vanished into it, and the program read
	 * as frozen while it was in fact answering every keystroke.
	 *
	 * The range test is the one the enum was made contiguous for.
	 */
	if (v->bar_open >= 0 && !(k >= K_CLICK && k <= K_RELEASE) &&
	    bar_key(v, k))
		return 1;
	/*
	 * Ctrl+C IN A DIALOG COPIES THE DIALOG, tested before every other owner
	 * of that key.
	 *
	 * The box is over everything else, so while one is up it is the only
	 * thing a reader can be selecting in - and the disassembly panel's own
	 * Ctrl+C below would otherwise answer for a selection nobody can see.
	 */
	if (k == 0x03 && v->sym_open && v->dlg_have) {
		dlg_copy(v);
		return 1;
	}
	if (k == 0x03 && v->dis_open && (v->dis_have || dis_hex_sel(v)) &&
	    !v->prop_open && !v->find_open && !v->edit) {
		dis_copy(v);
		return 1;
	}

	/*
	 * THE SYMBOLS DIALOG OWNS THE KEYBOARD WHILE IT IS UP.
	 *
	 * Everything it does not use is swallowed rather than passed down. It
	 * is a modal over the pane, so a Down arrow meant for the table must
	 * not scroll a hex pane the reader cannot see - which is the failure
	 * that makes a dialog feel like it is not really there. The mouse is
	 * NOT swallowed here: click() holds the hit test for the box, the same
	 * arrangement the menu bar above needed and for the same reason.
	 *
	 * Tab switches halves, because two tabs a click apart want a key too,
	 * and it is the key every other tabbed thing uses.
	 */
	if (v->sym_open && !(k >= K_CLICK && k <= K_RELEASE)) {
		int pg = symd_rows() > 1 ? symd_rows() - 1 : 1;

		switch (k) {
		case 27: case 'q': case 'Q':
			dlg_close(v);
			break;
		case '\t':
			v->sym_open = v->sym_open == SYMN_IMP ? SYMN_EXP
							     : SYMN_IMP;
			v->sym_at = 0;
			v->sym_hoff = 0;
			break;
		case K_UP:    symd_scroll(v, -1);            break;
		case K_DOWN:  symd_scroll(v, 1);             break;
		case K_LEFT:  symd_hscroll(v, -4);           break;
		case K_RIGHT: symd_hscroll(v, 4);            break;
		case K_PGUP:  symd_scroll(v, -(int64_t)pg);  break;
		case K_PGDN:  symd_scroll(v, pg);            break;
		case K_HOME:  v->sym_at = 0;                 break;
		case K_END:   v->sym_at = symd_max(v);       break;
		default:      break;
		}
		return 1;
	}

	/*
	 * The properties page owns the keyboard while it is up.
	 *
	 * Unlike the two help boxes it is a page rather than a card, so "any
	 * key closes" is the wrong contract: the keys a reader reaches for are
	 * the ones that move down it. Only the three that mean "done" close it,
	 * and everything else is swallowed so a keystroke meant for the page
	 * does not land on the draft behind it.
	 */
	if (v->prop_open) {
		int room = g_rows - 6;

		if (room < 1)
			room = 1;
		switch (k) {
		case K_UP:
			if (v->prop_off)
				v->prop_off--;
			return 1;
		case K_DOWN:
			v->prop_off++;
			return 1;
		case K_WHEEL_UP:
			v->prop_off = v->prop_off > 3u ? v->prop_off - 3u : 0;
			return 1;
		case K_WHEEL_DOWN:
			v->prop_off += 3u;
			return 1;
		case K_PGUP:
			v->prop_off = v->prop_off > (uint32_t)room
				      ? v->prop_off - (uint32_t)room : 0;
			return 1;
		case K_PGDN:
			v->prop_off += (uint32_t)room;
			return 1;
		case K_HOME:
			v->prop_off = 0;
			return 1;
		case K_END:
			/* Clamped where it is drawn, which is the only place
			 * that knows how many lines there are. */
			v->prop_off = 0xffffffu;
			return 1;
		case K_DRAG:
			if (v->prop_dragging && v->prop_sel_row >= 0) {
				char plain[PROP_W];
				uint32_t pn = prop_plain(
					g_prop[v->prop_sel_row].text,
					plain, sizeof plain);
				int col = g_mx - 4;

				if (col < 0) col = 0;
				if ((uint32_t)col >= pn && pn)
					col = (int)pn - 1;
				/* From where the button went down, so pulling
				 * either way from the click grows the run. */
				v->prop_sel_a = v->prop_anchor;
				v->prop_sel_b = col;
			}
			return 1;
		case K_RELEASE:
			v->prop_dragging = 0;
			return 1;
		case 0x03:                      /* Ctrl+C */
			if (v->prop_sel_row >= 0) {
				char plain[PROP_W];
				uint32_t pn = prop_plain(
					g_prop[v->prop_sel_row].text,
					plain, sizeof plain);
				int a2 = v->prop_sel_a < v->prop_sel_b
				       ? v->prop_sel_a : v->prop_sel_b;
				int b2 = v->prop_sel_a < v->prop_sel_b
				       ? v->prop_sel_b : v->prop_sel_a;

				if (pn && a2 >= 0 && (uint32_t)b2 < pn) {
					copy_osc52(plain + a2,
						   (size_t)(b2 - a2 + 1));
					copy_said(v, (size_t)(b2 - a2 + 1));
				}
			}
			return 1;
		case 27:
		case 'q':
		case '\r':
		case '\n':
			v->prop_open = 0;
			return 1;
		case K_CLICK:
		case K_RCLICK:
			/*
			 * Only the close control closes it.
			 *
			 * A click anywhere used to dismiss the page, which
			 * meant every attempt to scroll it by grabbing at it,
			 * or to click a line to read it more closely, threw
			 * the page away and put the tool back where it was.
			 * A window with a close button is closed by its close
			 * button.
			 */
			if (g_my == v->prop_y && g_mx >= v->prop_x0 &&
			    g_mx <= v->prop_x1) {
				v->prop_open = 0;
				return 1;
			}
			/*
			 * A click SELECTS; Ctrl+C copies. See view.prop_sel_row.
			 *
			 * The word under the cursor to start with, because that
			 * is what a reader means by clicking on a number, and
			 * dragging widens it. Clicking past the end of the text
			 * takes the whole line - the row is still reachable
			 * whole without a second gesture to learn.
			 */
			{
				int line = g_my - 3;    /* top(2) + rule(1) */
				uint32_t idx = v->prop_off + (uint32_t)line;
				char plain[PROP_W];
				uint32_t pn;
				int col = g_mx - 4;

				if (line < 0 || g_my >= g_rows - 2 ||
				    idx >= g_n_prop)
					return 1;
				/*
				 * The folder row's button, before the select
				 * path claims the click. It copies the whole
				 * path in one gesture - see prop_cp_row - and
				 * it is on exactly one row, so it is tested by
				 * row index rather than by looking at the text.
				 */
				if (v->prop_cp_row >= 0 &&
				    (int32_t)idx == v->prop_cp_row &&
				    col >= v->prop_cp_x0 &&
				    col <= v->prop_cp_x1 &&
				    v->path && v->path[0]) {
					size_t pl = strlen(v->path);

					copy_osc52(v->path, pl);
					copy_said(v, pl);
					return 1;
				}
				pn = prop_plain(g_prop[idx].text, plain,
						sizeof plain);
				if (!pn)
					return 1;
				v->prop_sel_row = (int32_t)idx;
				v->prop_anchor = col < 0 ? 0
					       : ((uint32_t)col >= pn
						  ? (int32_t)pn - 1 : col);
				if (col < 0 || (uint32_t)col >= pn ||
				    prop_break(plain[col])) {
					v->prop_sel_a = 0;
					v->prop_sel_b = (int32_t)pn - 1;
				} else {
					int a = col, b = col;

					while (a > 0 && !prop_break(plain[a - 1]))
						a--;
					while ((uint32_t)b + 1u < pn &&
					       !prop_break(plain[b + 1]))
						b++;
					v->prop_sel_a = a;
					v->prop_sel_b = b;
				}
				v->prop_dragging = 1;
			}
			return 1;
		default:
			return 1;
		}
	}
	/*
	 * A field being edited takes every printable key.
	 *
	 * Before the switch rather than inside it: while a name is being typed,
	 * "q" is a letter and not a command, and a text field that quits the
	 * program on one keystroke is the kind of thing people only find out
	 * once.
	 */
	/*
	 * A mode that takes the keyboard must not take the mouse.
	 *
	 * These two branches used to return for every event, mouse included, so
	 * while a chooser was open no click reached the router that would have
	 * dismissed it - and while a name was being typed, clicking anywhere
	 * else left the focus where it was and every key stayed a letter. Both
	 * looked like the mouse had stopped working.
	 */
	if (k >= K_CLICK && k <= K_RELEASE)
		;                       /* fall through to the router below */
	else if (v->ch.open) {
		if (k == 'j' || k == K_DOWN) {
			if (v->ch.sel + 1 < v->ch.n)
				v->ch.sel++;
		} else if (k == 'k' || k == K_UP) {
			if (v->ch.sel)
				v->ch.sel--;
		} else if (k == '\r' || k == '\n') {
			ch_take(v);
		} else if (k == 27 || k == 'q') {
			v->ch.open = 0;
		}
		return 1;
	} else if (v->edit) {
		/*
		 * One editor, several fields. The code says which: 1 the
		 * family, 4+i a condition's custom variant, 103+i a condition's
		 * expression, 200+i an optional size, 300+i a matcher's
		 * comment, 400+i a condition's comment.
		 *
		 * Each band is tested as a band, not as "at least". The size
		 * editor used to claim everything from 200 up, so the comment
		 * boxes added above it opened, took the caret, and then
		 * silently dropped every key that was not a digit.
		 */
		if (v->edit >= 200 && v->edit < 200 + OPT_COUNT) {
			/*
			 * A size, typed as digits and nothing else.
			 *
			 * Bounded on the way in rather than checked on the way
			 * out: a field that accepts a number it will refuse is
			 * a field that wastes the typing. Sixteen digits is far
			 * past any object this engine will be handed, and a
			 * minus sign is simply not a character a size has.
			 */
			int oi = (v->edit - 200) % OPT_COUNT;
			size_t nn = strlen(v->num);

			if (k == 27 || k == '\r' || k == '\n') {
				v->opt_val[oi] = strtoull(v->num, NULL, 10);
				v->edit = 0;
			} else if ((k == 127 || k == 8) && nn) {
				v->num[nn - 1u] = 0;
			} else if (k >= '0' && k <= '9' && nn < 16u) {
				if (v->num_fresh) {
					v->num[0] = 0;
					nn = 0;
				}
				v->num[nn] = (char)k;
				v->num[nn + 1u] = 0;
			}
			v->num_fresh = 0;
			return 1;
		}
		/*
		 * Esc closes the box whether or not the field has the caret.
		 * A click on the pane behind takes the caret away but leaves
		 * the box up - deliberately, so a half-typed offset survives a
		 * stray click - and without this there was then no key that
		 * would put it away, only the Cancel button.
		 */
		if (v->goto_open && k == 27) {
			v->goto_open = 0;
			v->edit = 0;
			return 1;
		}
		if (v->edit == 520) {
			/*
			 * The Go to field: hex digits, the two prefixes, and
			 * the editing a one-line number needs and no more.
			 * Enter jumps, Esc closes without moving - the same
			 * pair every other prompt here uses.
			 */
			size_t nn = strlen(v->gotobuf);

			if (v->edit != v->edit_prev) {
				v->edit_prev = v->edit;
				v->caret = (uint32_t)nn;
				v->field_all = 0;
			}
			if (k == 27) {
				v->goto_open = 0;
				v->edit = 0;
			} else if (k == '\r' || k == '\n') {
				goto_take(v);
			} else if ((k == 127 || k == 8) && nn) {
				v->gotobuf[nn - 1u] = 0;
				v->caret = (uint32_t)(nn - 1u);
			} else if (k == 0x16 || k == K_PASTE) {
				/* An offset is exactly the kind of thing that
				 * gets copied out of a report and pasted in
				 * here, so it takes the system clipboard like
				 * every other field - see paste_src. Only the
				 * characters an offset can hold are kept, so a
				 * pasted "0x1a2b\n" arrives clean. */
				const char *src;
				size_t sn = paste_src(k, &src), i;

				for (i = 0; i < sn &&
				     nn + 1u < sizeof v->gotobuf; i++) {
					char c2 = src[i];

					if (!((c2 >= '0' && c2 <= '9') ||
					      (c2 >= 'a' && c2 <= 'f') ||
					      (c2 >= 'A' && c2 <= 'F') ||
					      c2 == 'x' || c2 == 'X' ||
					      c2 == 'n' || c2 == 'N'))
						continue;
					if (v->num_fresh) {
						v->gotobuf[0] = 0;
						nn = 0;
						v->num_fresh = 0;
					}
					v->gotobuf[nn++] = c2;
					v->gotobuf[nn] = 0;
				}
				v->caret = (uint32_t)nn;
			} else if (((k >= '0' && k <= '9') ||
				    (k >= 'a' && k <= 'f') ||
				    (k >= 'A' && k <= 'F') ||
				    k == 'x' || k == 'X' || k == 'n' || k == 'N')
				   && nn + 1u < sizeof v->gotobuf) {
				if (v->num_fresh) {
					v->gotobuf[0] = 0;
					nn = 0;
				}
				v->gotobuf[nn] = (char)k;
				v->gotobuf[nn + 1u] = 0;
				v->caret = (uint32_t)(nn + 1u);
			}
			v->num_fresh = 0;
			return 1;
		}
		if (v->edit == 500) {
			/*
			 * Typing into the find dialog.
			 *
			 * Enter searches forward and Shift is not consulted for
			 * anything: the dialog has buttons for backwards and for
			 * scope, which is why there is no chord for either. A
			 * terminal cannot tell Ctrl+Shift+F from Ctrl+F without
			 * one of the newer key protocols, and a control that
			 * works on some terminals is worse than a button.
			 */
			size_t n = strlen(v->find);

			if (v->edit != v->edit_prev) {
				v->edit_prev = v->edit;
				v->caret = (uint32_t)n;
				v->field_all = 0;
			}
			if (v->caret > n)
				v->caret = (uint32_t)n;
			if (k == 0x01) {
				v->field_all = n != 0;
				return 1;
			}
			if (k == 0x03) {
				copy_osc52(v->find, n);
				copy_said(v, n);
				return 1;
			}
			/* K_DEL belongs with backspace here: with the whole
			 * field selected, either one means "get rid of it". */
			if (v->field_all && (k == 127 || k == 8 || k == K_DEL ||
					     k == 0x16 || k == K_PASTE ||
					     (k >= 0x20 && k < 0x7f))) {
				v->find[0] = 0;
				n = 0;
				v->caret = 0;
				v->field_all = 0;
				if (k == 127 || k == 8 || k == K_DEL)
					return 1;
			}
			if (v->field_all && (k == K_LEFT || k == K_RIGHT ||
					     k == K_HOME || k == K_END ||
					     k == 27 || k == '\r' || k == '\n'))
				v->field_all = 0;
			if (k == 0x16 || k == K_PASTE) {
				const char *src;
				size_t sn = paste_src(k, &src), i;

				for (i = 0; i < sn && n + 2u < sizeof v->find;
				     i++) {
					char c2 = src[i];

					if (c2 < 0x20 || c2 >= 0x7f)
						continue;
					memmove(v->find + v->caret + 1u,
						v->find + v->caret,
						n - v->caret + 1u);
					v->find[v->caret++] = c2;
					n++;
				}
				return 1;
			}
			if (k == K_LEFT) {
				if (v->caret)
					v->caret--;
			} else if (k == K_RIGHT) {
				if (v->caret < n)
					v->caret++;
			} else if (k == K_HOME) {
				v->caret = 0;
			} else if (k == K_END) {
				v->caret = (uint32_t)n;
			} else if (k == 27) {
				v->edit = 0;
				v->find_open = 0;
			} else if (k == '\r' || k == '\n') {
				v->find_at = KOF_BROKEN;
				find_run(v, 0);
			} else if (k == 0x08 || k == 127) {
				if (v->caret) {
					memmove(v->find + v->caret - 1u,
						v->find + v->caret,
						n - v->caret + 1u);
					v->caret--;
				}
			} else if (k == K_DEL) {
				if (v->caret < n)
					memmove(v->find + v->caret,
						v->find + v->caret + 1u,
						n - v->caret);
			} else if (k >= 0x20 && k < 0x7f &&
				   n + 2u < sizeof v->find) {
				memmove(v->find + v->caret + 1u,
					v->find + v->caret,
					n - v->caret + 1u);
				v->find[v->caret++] = (char)k;
			}
			return 1;
		}
		if (v->edit >= ED_STR && v->edit < ED_STR + MAX_DECL) {
			uint32_t si = (uint32_t)(v->edit - ED_STR);
			/* The cap is the declaration's, not the scratch's: see
			 * DECL_HEXS_CAP. They are the same size today, and
			 * naming the right one is what keeps them that way. */
			int r2 = field_key(v, v->sedit,
					   sizeof v->decl[si].hexs, k);

			/* field_key clears v->edit when the field closes, and
			 * closing is when the text becomes a declaration. */
			if (!v->edit)
				decl_edit_commit(v, si);
			return r2;
		}
		{
		/*
		 * Which box the keys are going into, and how much it holds.
		 *
		 * The cap used to be one number for every field, which was the
		 * smallest of them - so a comment stopped at the length of a
		 * variant name for no reason a typist could see. Each field
		 * carries its own now, taken from the array it is.
		 */
		char *buf;
		size_t cap;

		if (v->edit == 501) {
			buf = v->note;
			cap = sizeof v->note;
		} else if (v->edit == 1) {
			buf = v->family;
			cap = sizeof v->family;
		} else if (v->edit >= 300) {
			buf = v->grp[(v->edit - 300) % MAX_GROUP].note;
			cap = sizeof v->grp[0].note;
		} else if (v->edit >= 103) {
			buf = v->cnd[(v->edit - 103) % MAX_GROUP].expr;
			cap = sizeof v->cnd[0].expr;
		} else {
			buf = v->cnd[(v->edit - 4) % MAX_GROUP].variant;
			cap = sizeof v->cnd[0].variant;
		}
		return field_key(v, buf, cap, k);
		}
	}

	if (page < 1)
		page = 1;

	/*
	 * Any KEY closes the help box - but a mouse event is not a key.
	 *
	 * They arrive here as codes out of the same enum, so a test for "any
	 * key" catches the release of the very click that opened the box: it
	 * appeared and vanished in one gesture. The mouse codes are contiguous
	 * and last in the enum for exactly this kind of test.
	 */
	if (v->help_open && k < K_CLICK) {
		v->help_open = 0;
		return 1;
	}

	switch (k) {
	/*
	 * The chords a text editor has taught everyone.
	 *
	 * Ctrl+Q leaves whatever is open; the bare q still closes a dialog and
	 * still quits when nothing is open, because it was the only way out
	 * before this and muscle memory is not worth breaking to make a point.
	 */
	case 0x11:                      /* Ctrl+Q */
		return 0;
	/*
	 * STEPPING THROUGH A DIRECTORY WITHOUT REACHING FOR THE MENU.
	 *
	 * Ctrl+] is the next file and Ctrl+\ the one before it.
	 *
	 * Ctrl+[ WOULD HAVE BEEN THE OBVIOUS PARTNER AND CANNOT BE USED. A
	 * terminal sends Ctrl+[ as 0x1B, which is the Escape key, byte for
	 * byte - and 0x1B is also how every arrow, function key and mouse
	 * report begins. Binding it here would mean Escape opened a file:
	 * every closed dialog, every abandoned text field, every timed-out
	 * escape sequence. So the pair is the two keys next to it, which are
	 * distinct bytes (0x1C and 0x1D) and reach this loop unaltered because
	 * ISIG is off - see term_setup.
	 *
	 * Guarded by the same test the menu items use rather than a copy of it:
	 * they are one action asked for two ways, and an action that is
	 * available from the keyboard but greyed in the menu is a bug waiting
	 * to be reported.
	 */
	case 0x1d:                      /* Ctrl+] */
		if (bar_enabled(v, BI_NEXT))
			open_step(v, +1);
		else
			say_note(v, "Finish or undo the draft first");
		break;
	case 0x1c:                      /* Ctrl+\ */
		if (bar_enabled(v, BI_PREV))
			open_step(v, -1);
		else
			say_note(v, "Finish or undo the draft first");
		break;
	case 0x06:                      /* Ctrl+F */
		v->find_open = 1;
		v->edit = 500;
		v->warn[0] = 0;
		break;
	case 0x0e:                      /* Ctrl+N, the next hit */
		if (v->find[0])
			find_run(v, 0);
		break;
	case 0x0f:                      /* Ctrl+O */
		say_note(v, "No file picker - pass the file on the "
			    "command line");
		break;
	case 'q':
		if (v->show_list) {
			v->show_list = 0;
			break;
		}
		return 0;
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
	case K_RESIZE:
		break;                  /* the loop redraws after every key */
	case K_CLICK:  click(v, 0); break;
	case K_RCLICK: click(v, 1); break;
	case K_DRAG: {
		uint64_t at;

		/*
		 * A DIALOG'S TEXT SELECTION FIRST: the box is a modal, so a drag
		 * while one is up is the box's, whatever else on screen would
		 * otherwise have taken it. dlg_at clamps to the recorded text, so
		 * dragging past the last row extends to it rather than stopping
		 * the moment the pointer leaves the box.
		 */
		if (v->dlg_drag) {
			int r, c;

			if (dlg_at(v, g_my, g_mx, &r, &c)) {
				v->dlg_br = r;
				v->dlg_bc = c;
			}
			break;
		}
		if (v->bar_drag) {
			bar_to(v, v->bar_drag);
			break;
		}
		if (v->sizing) {
			/*
			 * The divider follows the pointer, and the panel takes
			 * what is above it. Bounded at both ends: a panel taller
			 * than the screen would leave no hex to take bytes from,
			 * and one of zero rows would hide the draft while it was
			 * still being written.
			 */
			int want = g_rows - g_my - 2;

			if (want < 1)
				want = 1;
			if (want > g_rows - 8)
				want = g_rows - 8 > 1 ? g_rows - 8 : 1;
			v->decl_cap = (uint32_t)want;
			break;
		}
		if (v->dis_dragging && g_disasm_rows) {
			int idx = g_my - dis_top();
			int c = g_mx - (TREE_W + 3);
			int len;

			if (idx < 0)
				idx = 0;
			if (idx >= v->dis_lines)
				idx = v->dis_lines - 1;
			if (idx < 0)
				break;
			/* Clamped to the row's own text: a pointer past the end
			 * of a short line selects that line to its end, which is
			 * what dragging over ragged text does everywhere. */
			len = (int)strlen(v->dis_line[idx]);
			if (c < 0)
				c = 0;
			if (c > len - 1)
				c = len > 0 ? len - 1 : 0;
			v->dis_b_at = v->dis_line_at[idx];
			v->dis_bc = c;
			dis_sync_bytes(v);
			break;
		}
		if (v->dragging && byte_under(v, g_my, g_mx, &at)) {
			if (at != v->sel_a)
				v->dragged = 1;
			v->sel_b = at;
			v->sel_from_dis = 0;
			/* The bias tracks the START of the run, so dragging
			 * downward does not drag the panel with it - the run's
			 * head stays where the reader can see it. */
			dis_bias_to_sel(v);
		}
		break;
	}
	case K_RELEASE:
		/* The drag is over; what was picked stays picked, so
		 * Ctrl+C has something to copy after the button comes up. */
		v->dlg_drag = 0;
		v->sizing = 0;
		v->bar_drag = 0;
		/*
		 * The drag ENDS and the selection STAYS.
		 *
		 * The same shape as the hex pane, which is the point: dragging
		 * out a run picks it, and what to do with it is a separate act
		 * through the same right-click menu. Copying on release was
		 * tried and is wrong here - it makes one pane in the tool
		 * behave unlike the other, and it changes the clipboard on a
		 * gesture that in every other pane changes nothing.
		 */
		if (v->dis_dragging) {
			v->dis_dragging = 0;
			break;
		}
		if (v->menu_open)
			break;
		/*
		 * A press and a release on one byte is a click, and on a lit
		 * byte it also says whose marker that byte is - the pane
		 * relights around the signature it belongs to.
		 *
		 * What it does NOT do is drop the caret. It used to, and the
		 * result was that the lit bytes - the ones a researcher is
		 * most likely to want to take - were the only place in the
		 * pane where clicking selected nothing: press, release,
		 * selection gone. Identifying the marker and putting the caret
		 * down are not alternatives.
		 */
		if (v->dragging && !v->dragged && v->sel_a != KOF_BROKEN) {
			int who = hit_owner(v, view_map(v, v->sel_a, 0));

			if (who >= 0)
				v->sel_touch = (uint32_t)who;
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
		dis_bias_to_sel(v);
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

		/*
		 * The dialog first, wherever the pointer is.
		 *
		 * The rule below - the wheel turns whatever it is over - is
		 * about panels laid out side by side. A modal is not one of
		 * those: it is over them, it is the only thing the reader can
		 * be looking at, and scrolling the tree behind it because the
		 * pointer happened to be on the left would move something they
		 * cannot see.
		 */
		if (v->sym_open) {
			/* Shift (or ctrl) turns the wheel sideways, the same
			 * binding the tree, the draft panel and the marker
			 * list already use - see the branch below. */
			if (g_mod_shift || g_mod_ctrl)
				symd_hscroll(v, down ? 4 : -4);
			else
				symd_scroll(v, down ? 3 : -3);
			break;
		}

		/* Shift turns the wheel sideways, the way it does in every
		 * other program that has both. */
		/*
		 * No wheel binding for the text fields.
		 *
		 * They scroll by following their caret, which is the only thing
		 * that should move them - and a field that also moved under the
		 * pointer would fight the panel the pointer is over, which is
		 * exactly what it did.
		 */
		if (g_mod_shift || g_mod_ctrl) {
			/*
			 * Sideways.
			 *
			 * The draft panel is columns of fixed width and one of
			 * them - the comment - holds a sentence. Sliding it is
			 * the only way to read the end of one without making
			 * every other column narrower, so the panel takes the
			 * modified wheel too.
			 */
			uint32_t *h = (v->show_list && g_my > list_top(v) &&
				       g_my <= list_top(v) +
					       (int)list_shown(v))
				      ? &v->list_hoff :
				      (g_decl_rows && g_my > decl_top() &&
				       g_my < mark_row())
				      ? &v->decl_hoff :
				      (g_mx <= TREE_W) ? &v->tree_hoff : NULL;

			if (h) {
				if (down)
					*h += 4u;
				else
					*h = *h > 4u ? *h - 4u : 0u;
			}
			break;
		}
		/*
		 * OVER THE DISASSEMBLY PANEL, THE WHEEL MOVES THE PANEL.
		 *
		 * This is the way out of a conflict that cannot be resolved by
		 * any rule: the hex pane shows about 270 bytes and the panel
		 * about 60, so a selection more than a few hex rows down has no
		 * row in the panel while the two are locked together. Every
		 * automatic answer either stopped the panel following the scroll
		 * or let the highlight leave the rows.
		 *
		 * So the reader gets the wheel. The panel follows the hex by
		 * default and the bracket on the divider says how far it
		 * reaches; pointing at the panel and turning the wheel moves the
		 * panel alone, by one instruction at a time. Nothing has to
		 * guess what was meant.
		 */
		if (g_disasm_rows && g_my >= dis_top() && g_my <= hex_bot() &&
		    g_mx > TREE_W) {
			/* Four bytes: about one instruction, and the same step
			 * whichever way the wheel turns. */
			v->dis_bias += down ? 4 : -4;
			if (v->dis_bias < 0)
				v->dis_bias = 0;
			if (v->dis_bias > dis_max_bias(v))
				v->dis_bias = dis_max_bias(v);
			break;
		}
		if (v->show_list && g_my > list_top(v) &&
		    g_my <= list_top(v) + (int)list_shown(v)) {
			/*
			 * Which list the wheel is over, which is not always
			 * the list of signatures.
			 *
			 * This branch only ever moved sel_touch, so over the
			 * MARKERS of one signature the wheel quietly changed
			 * which signature was selected - and the markers of a
			 * six marker rule past the fourth row could not be
			 * reached with a mouse at all. The arrow keys had the
			 * depth case and the wheel did not, so the list looked
			 * like it was hiding half its rows: the ones on screen
			 * said absent, the one below the fold was the marker
			 * that is actually there.
			 */
			if (v->list_depth) {
				struct object *lo = cur_obj(v);
				const struct kof_touch *lt =
					v->sel_touch < lo->n_touch
					? &lo->touch[v->sel_touch] : NULL;

				if (lt) {
					if (down && v->sel_str + 1 < lt->n_str)
						v->sel_str++;
					else if (!down && v->sel_str)
						v->sel_str--;
					if (v->sel_str < v->str_off)
						v->str_off = v->sel_str;
					if (v->sel_str >= v->str_off +
							  list_shown(v))
						v->str_off = v->sel_str -
							list_shown(v) + 1u;
					if (lt->str[v->sel_str].at != KOF_BROKEN)
						view_show_in(v,
						  v->node[v->sel_node].obj,
						  sym_which_of(
						   lt->str[v->sel_str].sym),
						  lt->str[v->sel_str].at);
				}
			} else if (down && v->sel_touch >=
					   cur_obj(v)->n_touch) {
				/* Out of "nothing selected" and onto the first
				 * rule: the state is entered by opening a file
				 * that matched nothing, and a state the wheel
				 * cannot leave is a state that reads as a
				 * frozen list. */
				v->sel_touch = 0;
			} else if (down && v->sel_touch + 1 <
					   cur_obj(v)->n_touch) {
				v->sel_touch++;
			} else if (!down && v->sel_touch) {
				v->sel_touch--;
			}
		} else if (g_mx <= TREE_W && g_my >= hex_top() &&
			   g_my <= hex_bot()) {
			for (n = 0; n < 3; n++)
				goto_node(v, down ? v->sel_node + 1u
						  : v->sel_node - 1u);
		} else if (g_decl_rows && g_my > decl_top() &&
			   g_my < mark_row()) {
			/* The draft grows past its pane long before the object
			 * does, so the wheel over it moves it and not the hex
			 * behind it. The clamp is left to the next layout,
			 * which is the only place that knows how tall the
			 * panel ended up. */
			if (down)
				v->prow_off += 3u;
			else
				v->prow_off = v->prow_off > 3u
					      ? v->prow_off - 3u : 0u;
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
		if (v->show_list && v->list_depth &&
		    v->sel_touch < cur_obj(v)->n_touch) {
			struct object *o2 = cur_obj(v);
			const struct kof_touch *t2 = &o2->touch[v->sel_touch];

			if (v->sel_str + 1 < list_total(v))
				v->sel_str++;
			if (v->sel_str >= v->str_off + list_shown(v))
				v->str_off = v->sel_str - list_shown(v) + 1u;
			if (t2->str[v->sel_str].at != KOF_BROKEN)
				view_show_in(v, v->node[v->sel_node].obj,
					     sym_which_of(
						t2->str[v->sel_str].sym),
					     t2->str[v->sel_str].at);
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
		if (v->show_list && v->list_depth &&
		    v->sel_touch < cur_obj(v)->n_touch) {
			struct object *o2 = cur_obj(v);
			const struct kof_touch *t2 = &o2->touch[v->sel_touch];

			if (v->sel_str)
				v->sel_str--;
			if (v->sel_str < v->str_off)
				v->str_off = v->sel_str;
			if (t2->str[v->sel_str].at != KOF_BROKEN)
				view_show_in(v, v->node[v->sel_node].obj,
					     sym_which_of(
						t2->str[v->sel_str].sym),
					     t2->str[v->sel_str].at);
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
	"  --db D      load that database. Without it there is one object and\n"
	"              no markers: unpacking is what modules do, and modules\n"
	"              live in a database.\n"
	"  --bases D   the signature source tree, which is also where a drafted\n"
	"              signature is written. A content root or one of its kind\n"
	"              directories both work. Default kofdraft/.\n");
}

/*
 * Everything one FILE owns, and nothing the session owns.
 *
 * Deliberately not view_free: the engine, the two extent buffers and the bases
 * directory outlive any one file, and freeing them here is what would make a
 * file switch cost a database load again.
 */
static void file_close(struct view *v)
{
	uint32_t i, k;

	/*
	 * The draft goes with the file, and its declarations own heap.
	 *
	 * Missed at first, and the shape of the miss is worth keeping: the
	 * declarations were freed by draft_clear on every path that REPLACED a
	 * draft, and by nothing at all on the path that abandoned one. That
	 * cost a few bytes at exit for as long as moving to another file meant
	 * re-execing - and became a leak per file the moment it did not.
	 */
	draft_clear(v);
	for (i = 0; i < v->n_obj; i++) {
		struct object *o = &v->obj[i];

		kof_touch_free(o->touch, o->n_touch);
		for (k = 0; k < o->n_finding; k++)
			free(o->finding[k]);
		free(o->finding);
		free(o->info);
		free(o->sym);
		free(o->own);
		if (o->mapped)
			kof_unmap_file(o->mapped, o->mapped_len);
	}
	v->n_obj = 0;
	if (v->map) {
		kof_unmap_file(v->map, v->map_len);
		v->map = NULL;
		v->map_len = 0;
	}
}

static void view_free(struct view *v)
{
	file_close(v);
	free(v->ext);
	free(v->probe);
}

/*
 * Point the whole view at another file, keeping the session.
 *
 * The new file is opened and mapped BEFORE the old one is let go, so a path
 * that cannot be read leaves the reader looking at what they already had with
 * a message saying why - rather than at an empty screen.
 *
 * Then the view is cleared wholesale and the session's four fields are put
 * back. Clearing wholesale rather than resetting the per-file fields by name is
 * the point: this struct has upwards of eighty members and a switch that
 * enumerated them would go stale the first time one was added, silently, in
 * whichever pane happened to hold the field that was missed.
 *
 * Returns 0 with act_msg set on failure.
 */
static int file_open(struct view *v, const char *path, kof_engine *eng)
{
	struct stat st;
	void       *map;
	uint64_t    len;
	int         fd;
	/* The session. */
	struct kof_range *ext   = v->ext;
	struct kof_range *probe = v->probe;
	uint32_t          cap   = v->decl_cap;
	char basedir[sizeof v->basedir];
	char dbdir[sizeof v->dbdir];
	char keep[KOF_DUMP_PATH_ROOM];
	/*
	 * Kept only when this is the same file being rebuilt - which is what
	 * the menu item does - and dropped when it is a different one.
	 */
	int  emu_mode;

	snprintf(keep, sizeof keep, "%s", path);
	emu_mode = (v->path && strcmp(v->path, keep) == 0) ? v->emu_mode : 0;

	fd = open(keep, O_RDONLY);
	if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0) {
		if (fd >= 0)
			close(fd);
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg,
			 "%.60s is not a regular non-empty file",
			 base_name(keep));
		return 0;
	}
	len = (uint64_t)st.st_size;
	map = kof_map_file_ro(fd, len);
	close(fd);
	if (!map) {
		v->act_ok = 0;
		snprintf(v->act_msg, sizeof v->act_msg, "Cannot map %.60s",
			 base_name(keep));
		return 0;
	}

	snprintf(basedir, sizeof basedir, "%s", v->basedir);
	snprintf(dbdir, sizeof dbdir, "%s", v->dbdir);

	file_close(v);
	memset(v, 0, sizeof *v);

	v->eng   = eng;
	v->ext   = ext;
	v->probe = probe;
	v->decl_cap = cap;
	snprintf(v->basedir, sizeof v->basedir, "%s", basedir);
	snprintf(v->dbdir, sizeof v->dbdir, "%s", dbdir);
	v->emu_mode = emu_mode;

	/* The fields whose cleared value is not their resting value. */
	v->prop_sel_row = -1;
	v->sel_a = v->sel_b = KOF_BROKEN;
	v->find_at = KOF_BROKEN;
	v->bar_open = -1;
	v->bar_sel = -1;
	v->bar_sub = -1;

	snprintf(v->pathbuf, sizeof v->pathbuf, "%s", keep);
	v->path = v->pathbuf;
	v->map = map;
	v->map_len = len;

	if (v->eng)
		objects_collect(v, v->eng);
	if (!v->n_obj) {
		/*
		 * No database, or a scan that produced nothing. The file is
		 * still an object and is still worth looking at - the tree is
		 * just one deep.
		 */
		struct object *o = &v->obj[0];

		memset(o, 0, sizeof *o);
		snprintf(o->name, sizeof o->name, "%s", v->path);
		o->buf = kof_buf_make(v->map, v->map_len);
		v->n_obj = 1;
	}
	objects_examine(v, v->eng);
	tree_build(v);
	view_select(v);

	/*
	 * A file that already matches something opens showing what matched.
	 *
	 * That is nearly always the reason for opening it: a researcher looking
	 * at a detected sample is there to see the rule that caught it, or to
	 * write the one that should have. Starting on an empty panel makes them
	 * go and find it first.
	 */
	{
		struct object *o0 = &v->obj[0];
		uint32_t k;

		for (k = 0; k < o0->n_touch; k++)
			if (o0->touch[k].fired) {
				draft_show(v, k);
				break;
			}
		/*
		 * AND WHEN NOTHING FIRED, NOTHING IS SELECTED.
		 *
		 * The hex pane lights where the SELECTED rule's markers sit, and
		 * a zeroed selection is rule number zero - so opening a file
		 * that matched nothing lit up wherever some arbitrary rule's
		 * marker happened to land, which in a header is often somewhere.
		 * A highlight reads as "this matched", so the pane was reporting
		 * a match that had not happened. Past the end means no rule, and
		 * hit_kind already draws nothing for that.
		 */
		if (k == o0->n_touch)
			v->sel_touch = o0->n_touch;
	}
	/* Whatever was auto-loaded is what this file started as, so it is not
	 * unsaved work. */
	v->saved_hash = draft_hash(v);
	return 1;
}

int main(int argc, char **argv)
{
	const char *path = NULL, *db = NULL, *base = "kofdraft";
	uint64_t last_paint = 0;
	struct view v;
	struct stat st;
	int i, rc = 0;

	memset(&v, 0, sizeof v);
	/* The one preference that is not zero at rest. Everything else file_open
	 * sets, for the first file and for every one after it. */
	v.decl_cap = 12;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--db") && i + 1 < argc)
			db = argv[++i];
		else if (!strcmp(argv[i], "--bases") && i + 1 < argc)
			base = argv[++i];
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

	/*
	 * The tree a drafted signature is written into.
	 *
	 * Checked here rather than at the moment of writing, because the moment
	 * of writing is after the work: a researcher who has spent an hour on a
	 * draft should not be told then that the directory they named does not
	 * exist. A path that is not a directory is refused; one that does not
	 * exist yet is accepted, since generate() creates it, and a researcher
	 * naming a new tree means it.
	 */
	if (stat(base, &st) == 0 && !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "kofviewer: --bases %s is not a directory\n",
			base);
		return 1;
	}
	snprintf(v.basedir, sizeof v.basedir, "%s", base);
	if (db)
		snprintf(v.dbdir, sizeof v.dbdir, "%s", db);

	v.ext = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.ext);
	v.probe = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.probe);
	if (!v.ext || !v.probe) {
		fprintf(stderr, "kofviewer: out of memory\n");
		return 1;
	}

	if (db) {
		v.eng = kof_engine_open(db);
		if (!v.eng)
			fprintf(stderr, "kofviewer: cannot load a database from "
					"%s\n", db);
	}
	if (!file_open(&v, path, v.eng)) {
		fprintf(stderr, "kofviewer: %s\n", v.act_msg);
		kof_engine_close(v.eng);
		free(v.ext);
		free(v.probe);
		return 1;
	}

	if (!term_setup()) {
		rc = 1;
		goto out;
	}
	last_paint = now_ms();
	redraw(&v);
	for (;;) {
		int k = read_key();

		if (k == K_NONE)
			break;
		if (!handle(&v, k))
			break;
		/*
		 * One frame per batch of input, not one per key.
		 *
		 * A held page key repeats faster than a screen can be painted,
		 * and painting every repeat means the terminal is always partway
		 * through a frame - which is what the flash is. Skipping the
		 * paint while more input is already waiting collapses a burst
		 * into a single frame at the position it ends at, and the
		 * intermediate positions were never worth drawing: nobody can
		 * read a pane that is moving.
		 *
		 * The clock is the guard. Without it a key repeating forever
		 * would postpone the frame forever, so anything older than a
		 * frame time gets painted whether or not more is queued.
		 */
		if (key_pending() && now_ms() - last_paint < 33u)
			continue;
		/* redraw decides for itself whether anything changed. */
		redraw(&v);
		last_paint = now_ms();
	}
	term_restore();

out:
	view_free(&v);
	kof_engine_close(v.eng);
	return rc;
}
