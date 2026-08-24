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
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/elf.h>
#include <kofmod/pe.h>

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
#define MAX_GROUP 8

/* Every row the draft panel can ever hold, spelled from the limits rather than
 * counted once: the panel grew three kinds of row after this array was sized,
 * and a table that silently stops short is a panel whose bottom cannot be
 * scrolled to. */
#define MAX_PROW  (OPT_COUNT + 1 + 2 + MAX_DECL + 2 + 2 * MAX_GROUP + 2 + \
		   4 * MAX_GROUP)
#define MAX_RANGE 8

/* A string that no condition uses yet. Declaring one must not invent a place to
 * put it: the condition is the researcher's decision and making it for them is
 * the kind of help that has to be undone before anything else can be done. */
#define GRP_NONE  0xffffffffu

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
	"KOF_FMT_ANY", "KOF_FMT_ELF", "KOF_FMT_PE",
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
	uint32_t len;
	int      hex;               /* KOF_DEFINE_HEXSTR, else KOF_DEFINE_STR */
	uint32_t obj;               /* which object it was taken from */
	uint32_t mask;              /* the region it was taken from */
	char     rgn[24];           /* that region's short name */
	uint32_t grp;               /* which matcher uses it */
	/* Where these bytes are in the object, so the row can jump to them and
	 * the pane can light them. KOF_BROKEN when they are not there at all -
	 * a marker taken from one sample and carried to another. */
	uint64_t at;

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
 * ksigbuilder reads that argument quote to quote and refuses escapes, so the
 * answer is the printable ASCII that needs none. "?" is excluded on top of that
 * and not out of caution: signatures compile with -std=c11, which turns on
 * trigraph replacement, and "??" followed by one of nine characters would become
 * a different character before the compiler ever saw the literal.
 */
/* A byte that reads as text. Wider than literal_safe on purpose: "?" and a
 * backslash are part of a string a researcher is looking at even though they
 * cannot go into a C literal unescaped, and what to do about that is the
 * declaring step's problem, not the selecting step's. */
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
		if (b[i] < 0x20u || b[i] > 0x7eu || b[i] == '"' ||
		    b[i] == '\\' || b[i] == '?')
			return 0;
	return 1;
}

/* ---- a chooser ------------------------------------------------------------
 *
 * One overlay for every "pick one of these" in the draft panel: the condition's
 * rule, its range, its verdict, the malware type. They are the same interaction
 * four times, and four bespoke popups would be four places to get the click
 * routing wrong.
 */
#define CH_ITEMS 16
#define CH_W     38

enum ch_what {
	CH_NONE = 0,
	CH_RULE,        /* find all / any / multi, for a new or existing group */
	CH_RANGE,       /* which declared range a condition searches */
	CH_RANGE2,      /* what to do to the scan ranges */
	CH_RANGE3,      /* and which of them, when there are several */
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

	/*
	 * Which numbering the offset column shows.
	 *
	 * Both are true and they answer different questions: the file offset is
	 * where the bytes are on disk, the region offset is how far into what a
	 * signature actually searches they are. Showing only one made the other
	 * a subtraction the reader had to do by hand.
	 */
	int         off_region;

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

	struct decl  decl[MAX_DECL];
	uint32_t     n_decl, sel_decl;

	struct range rng[MAX_RANGE];
	uint32_t     n_rng, cur_rng;

	struct group grp[MAX_GROUP];       /* matchers */
	uint32_t     n_grp, cur_grp;

	struct cond  cnd[MAX_GROUP];
	uint32_t     n_cnd, cur_cnd;
	char         warn[120];     /* why the last add was refused */
	char         copy_msg[120]; /* where the last copy's bytes went */
	int          copy_ok;       /* and whether anything outside took it */
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
	char        gen_path[600];

	/* Where the header's controls landed, recorded as they are drawn. */
	int         f_c0, f_c1, t_c0, t_c1, v_c0, v_c1, g_c0, g_c1;
	int         n_c0, n_c1;     /* the "+ condition" button */
	int         sv_c0, sv_c1;   /* "Save As", when there is a file */
	int         nt_c0, nt_c1;   /* the module's own note */
	int         nt_len, nt_room;/* its length and the width it is shown in */
	int         grp_len[MAX_GROUP], grp_room[MAX_GROUP];
	int         rng_c0, rng_c1, m_c0, m_c1, s_c0, s_c1, e_c0, e_c1;
	int         rgs_c0, rgs_c1; /* "Update scan range"     - where it looks */
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
	int         a_c0, a_c1, b_c0, b_c1, p_c0, p_c1, o_c0, o_c1;
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
	int         bar_open;       /* which menu is down, -1 for none */
	int         bar_sel;        /* the item under the pointer or the cursor */
	int         help_open;      /* 0 none, 1 keyboard, 2 about */
	int         prop_open;      /* the properties page is up */
	uint32_t    prop_off;       /* the first of its lines on screen */
	int         prop_x0, prop_x1, prop_y;   /* its close control */
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
	int         find_hex;       /* the text is hex digits, not bytes */
	int         find_icase;     /* letters compare either way; text only */
	int         find_regex;     /* declared, refused: see draw_find */
	int         find_scope;     /* 0 this region, 1 the whole object */
	uint64_t    find_at;        /* the last hit, in file offsets */
	uint32_t    find_i, find_n; /* which hit it is, and how many there are */
	uint32_t    find_off;       /* how far the field is scrolled */
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

static void scrollbar(struct out *o, int col, int top, int bot,
		      uint64_t off, uint64_t total, uint64_t shown)
{
	int rows = bot - top + 1, i, t0, t1;

	t0 = bar_thumb(top, bot, off, total, shown, &t1);
	if (t0 < 0)
		return;
	for (i = 0; i < rows; i++) {
		out_at(o, top + i, col);
		if (i >= t0 && i < t0 + t1)
			out_str(o, A_ID "#" A_OFF);
		else
			out_str(o, A_DIM ":" A_OFF);
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
			if (!sel)
				/* An object row can hold a signature; a region
				 * row is a place inside one. Different colours
				 * because they are different kinds of answer,
				 * not different rows of one kind. */
				out_str(o, n->mask ? A_ID : A_BOLD);
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

/*
 * Where a declared string sits in this object, searched for once.
 *
 * A string declared by selecting bytes already knows; one loaded from a
 * database row knows too. One read out of a source file does not - the file
 * says what to look for, not where it was found - and that is the case this is
 * for. Case folding is honoured because the declaration honours it.
 */
static uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off);

static void decl_locate(struct view *v, struct decl *d)
{
	struct object *ob = &v->obj[d->obj < v->n_obj ? d->obj : 0];
	uint64_t i;

	d->at = KOF_BROKEN;
	d->off_rgn = 0;
	d->at_rgn[0] = 0;
	d->at_mask = 0;
	if (!d->len || d->len > ob->buf.n)
		return;
	for (i = 0; i + d->len <= ob->buf.n; i++) {
		uint32_t k;

		for (k = 0; k < d->len; k++) {
			uint8_t a = ob->buf.p[i + k], b = d->bytes[k];

			if (d->icase && !d->hex) {
				if (a >= 'A' && a <= 'Z')
					a = (uint8_t)(a - 'A' + 'a');
				if (b >= 'A' && b <= 'Z')
					b = (uint8_t)(b - 'A' + 'a');
			}
			if (a != b)
				break;
		}
		if (k == d->len) {
			uint32_t nd;

			d->at = i;
			/*
			 * Where it really is, against where it is looked for.
			 *
			 * Only a range that names regions can be contradicted:
			 * an unset mask means nothing has been decided yet, and
			 * KOF_SCAN_ALL cannot be missed.
			 */
			nd = node_at(v, d->obj, i);
			if (nd < v->n_node && v->node[nd].mask) {
				d->at_mask = v->node[nd].mask;
				snprintf(d->at_rgn, sizeof d->at_rgn, "%s",
					 v->node[nd].label);
				if (d->mask && d->mask != KOF_SCAN_ALL &&
				    !(d->mask & v->node[nd].mask))
					d->off_rgn = 1;
			}
			return;
		}
	}
}

/* Is this file offset inside a string the draft declares. */
static int decl_kind(struct view *v, uint64_t off)
{
	uint32_t i;

	for (i = 0; i < v->n_decl; i++) {
		const struct decl *d = &v->decl[i];

		if (d->at == KOF_BROKEN)
			continue;
		if (off >= d->at && off < d->at + d->len)
			return 1;
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
			(unsigned long long)(v->off_region ? at : off));
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
					  : decl_kind(v, fo) ? A_HIT3
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
				  : decl_kind(v, fo) ? A_HIT3
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

	if (t->fired_name)
		snprintf(out, cap, "%s:%s-%s", kof_maltype_name(t->maltype),
			 fam, t->fired_name);
	else if (t->n_names > 1u)
		snprintf(out, cap, "%s:%s (%u variants)",
			 kof_maltype_name(t->maltype), fam, t->n_names);
	else
		snprintf(out, cap, "%s:%s", kof_maltype_name(t->maltype), fam);
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
		n += v->decl[i].grp == GRP_NONE;
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
		if (v->decl[i].grp == g)
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
		n += v->decl[i].grp == g;
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
		if (v->decl[i].grp == g)
			v->decl[i].grp = GRP_NONE;
		else if (v->decl[i].grp != GRP_NONE && v->decl[i].grp > g)
			v->decl[i].grp--;
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
	for (b = 0; b < 32u && at + 1u < cap; b++) {
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
static void rng_ident(const struct kof_inspect_fmt *fmt, uint32_t mask,
		      char *out, size_t cap)
{
	char w[24];
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

static void emit_matcher(FILE *f, struct view *v, uint32_t g)
{
	const struct group *q = &v->grp[g];
	uint32_t i;

	{
		char nm[40];

		rng_ident(cur_obj(v)->fmt, grp_mask(v, g), nm, sizeof nm);
		fprintf(f, "kof_find_str_%s(%s",
			q->rule == 1 ? "any" : q->rule == 2 ? "multi" : "all",
			nm);
	}
	for (i = 0; i < v->n_decl; i++)
		if (v->decl[i].grp == g)
			fprintf(f, ", s%u", i);
	fprintf(f, ")");
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
	 */
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
		for (j = 0; j < d->len; j++)
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

static int draft_dirty(struct view *v)
{
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
	v->gen_path[0] = 0;
	v->gen_ok = 0;
	v->prow_off = 0;
	v->prow_seen = 0;
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

/* The file a fired module was written in, by family and by the line one of its
 * detections sits on. NULL when the tree does not hold it. */
static const char *src_of(struct view *v, const struct kof_touch *t)
{
	uint32_t i, j, k;

	if (!g_src_done) {
		g_src_done = 1;
		g_src = calloc(SRC_MAX, sizeof *g_src);
		if (g_src)
			src_scan(v->basedir, 0);
	}
	if (!g_src || !t->family)
		return NULL;
	for (i = 0; i < g_n_src; i++) {
		if (strcmp(g_src[i].family, t->family) != 0)
			continue;
		for (j = 0; j < t->n_names; j++)
			for (k = 0; k < g_src[i].n_line; k++)
				if (g_src[i].line[k] == t->name_id[j])
					return g_src[i].path;
	}
	return NULL;
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
	if (!fmt)
		return 0;
	for (k = 0; k < fmt->n_regions; k++) {
		const char *w = fmt->region_name(fmt->regions[k]);

		if (w && strstr(e, w))
			m |= fmt->regions[k];
	}
	return m;
}

/* The text between the first pair of quotes, unescaped only as far as
 * ksigbuilder unescapes it - which is not at all. */
static int src_quoted(const char *p, char *out, size_t cap)
{
	const char *q = strchr(p, '"');
	size_t n = 0;

	if (!q)
		return 0;
	for (q++; *q && *q != '"'; q++)
		if (n + 1 < cap)
			out[n++] = *q;
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
				/* The banner only counts as one where it is
				 * written - opening the block. A line of prose
				 * quoting it further down is prose. */
				if (!head_n && !mine &&
				    !strncmp(t, HEAD_BANNER,
					     sizeof HEAD_BANNER - 1))
					mine = 1;
				if (!mine)
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

				d->bytes = malloc(n ? n : 1u);
				if (!d->bytes)
					continue;
				for (k = 0; k < n; k++) {
					char b[3];

					b[0] = text[k * 2u];
					b[1] = text[k * 2u + 1u];
					b[2] = 0;
					d->bytes[k] = (uint8_t)strtoul(b, NULL,
								       16);
				}
				d->len = (uint32_t)n;
				d->hex = 1;
			} else {
				d->len = (uint32_t)strlen(text);
				d->bytes = malloc(d->len ? d->len : 1u);
				if (!d->bytes)
					continue;
				memcpy(d->bytes, text, d->len);
				d->icase = strstr(line, "KOF_CASE_ICASE") != 0;
				d->fullword = strstr(line,
						     "KOF_WORD_FULLWORD") != 0;
			}
			d->obj = v->node[v->sel_node].obj;
			d->grp = GRP_NONE;
			snprintf(d->rgn, sizeof d->rgn, "-");
			str[n_str].idx = v->n_decl;
			n_str++;
			v->n_decl++;
			continue;
		}

		if (strstr(line, "kof_scan(") || strstr(line, "KOF_DEFINE_SCAN"))
			body = 1;
		if (!body)
			continue;

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
					v->decl[k].grp = v->n_grp;
				while (*q == ' ')
					q++;
			}
			if (rule == 2) {
				const char *ge = strstr(p, ">=");

				g->thresh = ge ? (uint32_t)strtoul(ge + 2, NULL,
								   10) : 2u;
			}
			if (pend[0]) {
				snprintf(g->note, sizeof g->note, "%s", pend);
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

		if (d->grp == GRP_NONE || d->grp >= v->n_grp || d->mask)
			continue;
		d->mask = v->grp[d->grp].mask;
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

		if (!st->len)
			continue;
		memset(d, 0, sizeof *d);
		d->bytes = malloc(st->len);
		if (!d->bytes)
			break;
		memcpy(d->bytes, st->bytes, st->len);
		d->len = st->len;
		d->hex = st->kind == KOF_STR_HEX;
		d->icase = (st->flags & KOF_STR_ICASE) != 0;
		d->fullword = (st->flags & KOF_STR_FULLWORD) != 0;
		d->obj = v->node[v->sel_node].obj;
		/*
		 * The region it is in, not the region the module named: the
		 * module's range is not in the pack either, and where the bytes
		 * turned out to be is a fact this can check.
		 */
		/*
		 * Zero, not whole-file, when the string is not in this object.
		 *
		 * A marker that is absent has no region, and calling that
		 * whole-file made one absent string widen the whole matcher's
		 * range to the entire file - the opposite of what the range is
		 * for. A zero contributes nothing to the derived range and the
		 * row shows it as unknown.
		 */
		d->mask = 0;
		snprintf(d->rgn, sizeof d->rgn, "-");
		if (st->at != KOF_BROKEN) {
			uint32_t k = node_at(v, d->obj, st->at);

			if (k < v->n_node && v->node[k].mask) {
				/* Both live in `v`, and snprintf may not be
				 * given a source that overlaps its
				 * destination. */
				char lab[48];

				d->mask = v->node[k].mask;
				snprintf(lab, sizeof lab, "%s",
					 v->node[k].label);
				snprintf(d->rgn, sizeof d->rgn, "%.23s", lab);
			}
		}
		d->grp = 0;
		d->at = st->at;
		v->n_decl++;
	}
	if (!v->n_decl)
		return;

	memset(&v->grp[0], 0, sizeof v->grp[0]);
	v->n_grp = 1;
	v->cur_grp = 0;
	snprintf(v->grp[0].note, sizeof v->grp[0].note,
		 "from %s - the database keeps the strings, not the logic",
		 t->family[0] ? t->family : "the database");

	memset(&v->cnd[0], 0, sizeof v->cnd[0]);
	snprintf(v->cnd[0].expr, sizeof v->cnd[0].expr, "1");
	v->cnd[0].parent = -1;
	v->cnd[0].level = LV_INFECT;
	v->n_cnd = 1;
	v->cur_cnd = 0;
	say_note(v,
		 "loaded %u string(s) from %s - check the matcher, the logic is "
		 "not in the database", v->n_decl,
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
			v->saved_hash = draft_hash(v);
			/* The path shows on its own; `warn` is for things that
			 * are wrong, and a loaded file is not one. */
			v->warn[0] = 0;
			if (rc < 0)
				say_note(v, "only partly read - check it "
					    "against the file");
			return;
		}
		draft_from_touch(v, &ob->touch[idx]);
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
	if (!g_src || !v->n_decl)
		return NULL;
	tgt = draft_tgt(v);
	for (i = 0; i < v->n_decl; i++) {
		pat += pat_of(v->decl[i].bytes, v->decl[i].len,
			      v->decl[i].hex);
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
			uint32_t less = pat - pat_of(v->decl[k].bytes,
						     v->decl[k].len,
						     v->decl[k].hex);

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
static const char *draft_missing(struct view *v)
{
	uint32_t i;

	if (!v->family[0])
		return "name the family";
	if (!v->n_decl)
		return "declare a string";
	if (!v->n_grp)
		return "add a matcher";
	for (i = 0; i < v->n_grp; i++)
		if (!grp_count(v, i))
			return "every matcher needs a string";
	if (!v->n_cnd)
		return "add a condition";
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
			return "every condition needs a matcher";
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
			if (v->decl[i].grp == GRP_NONE) {
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

	if (draft_missing(v))
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

	if (draft_missing(v) || !v->gen_path[0] || !draft_dirty(v))
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
		const char *why = draft_missing(v);
		int near = 0;
		const char *dup;

		if (why) {
			say_err(v, "%s first", why);
			return;
		}
		dup = draft_dup(v, &near);
		if (dup && !near) {
			say_note(v, "same markers as %s - edit that instead",
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
				 as_new ? "nothing changed - a copy would be a "
					  "duplicate"
					: "nothing changed since the last save");
			return;
		}
	}
	struct object *ob = &v->obj[v->decl[0].obj];
	char path[400], safe[48];
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
			say_err(v, "cannot create %.90s", dir);
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
						 "%s/%s_%0*u.c", dir, safe,
						 (int)wide[w], n);
					if (stat(path, &es) != 0) {
						free_one = 1;
						break;
					}
				}
			}
			if (!free_one) {
				say_err(v, "%.40s has no free number left",
					safe);
				return;
			}
		}
	}
	f = fopen(path, "w");
	if (!f) {
		say_err(v, "cannot write %.90s", path);
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
		const char *base = strrchr(ob->name, '/');

		base = base ? base + 1 : ob->name;
		fprintf(f,
			"/*\n"
			" * Generated by KOFViewer.\n"
			" *\n"
			" * Test sample: %s\n", base);
	}
	if (ob->packer[0])
		fprintf(f, " * Unpacked by: %s\n", ob->packer);
	fprintf(f, " */\n");
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
			char nm[40];
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
			if (!(m & KOF_SCAN_ALL))
				for (b = 0; b < 32u; b++) {
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
			for (j = 0; j < d->len; j++)
				fprintf(f, "%02X", d->bytes[j]);
			fprintf(f, "\");\n");
		} else {
			fprintf(f, "KOF_DEFINE_STR(s%u, \"", i);
			for (j = 0; j < d->len; j++)
				fputc(d->bytes[j], f);
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
		say_err(v, "could not write the file");
		return;
	}
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

/*
 * Fill and place a chooser.
 *
 * The contents are built here rather than by each caller so that what a list
 * offers stays next to what picking from it does - two halves of one decision,
 * which drift apart the moment they live in different functions.
 */
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
		 * The ranges this matcher COULD search, worked out from the
		 * markers it holds rather than offered from a list.
		 *
		 * A marker was found in exactly one region - the regions of a
		 * format partition the object, rangelist.h says so - but it
		 * sits inside every range that covers that region, and there
		 * are always at least two: its own, and the whole file. So the
		 * question is never "which range is this string in", it is
		 * "which ranges hold all of them", and that has one narrowest
		 * answer and one widest.
		 */
		uint32_t need = 0;
		char t[CH_W];

		for (i = 0; i < v->n_decl; i++)
			if (v->decl[i].grp == arg)
				need |= v->decl[i].mask;
		if (!need)
			need = KOF_SCAN_ALL;

		c->arg2 = need;
		rng_name_of(cur_obj(v)->fmt, need, t, sizeof t);
		ch_add(c, t);
		/*
		 * And any range the draft has declared that nothing searches.
		 *
		 * Without this, "Add CODE to scan ranges" is a dead end: the
		 * range exists, the save refuses until a matcher names it, and
		 * there is nowhere to name it from. This is that place.
		 */
		for (i = 0; i < v->n_rng_add; i++) {
			uint32_t k, used = 0;

			for (k = 0; k < v->n_grp; k++)
				used += (uint32_t)(grp_has_range(v, k) &&
						   grp_mask(v, k) ==
						   v->rng_add[i]);
			if (used || v->rng_add[i] == need)
				continue;
			rng_name_of(cur_obj(v)->fmt, v->rng_add[i], t,
				    sizeof t);
			ch_add(c, t);
		}
		if (need != KOF_SCAN_ALL)
			ch_add(c, "WHOLE-FILE");
	} else if (what == CH_RANGE2) {
		/*
		 * Four assignments, and one region to make them with.
		 *
		 * The region is not browsed for: it is where this draft's
		 * markers actually are, which the tool worked out when it
		 * located them and which is the reason anyone opens this menu
		 * - the rule says DATA, the bytes are in CODE.
		 *
		 * Every line reads the same way and one word carries the
		 * difference: Switch replaces, Extend keeps and adds, Add
		 * declares a range of its own, and the last is the same
		 * assignment to everything. Written as assignments and not as
		 * verbs like "Scan WHOLE-FILE", which read as an order to go
		 * and scan rather than as a range being set.
		 *
		 * How many ranges the draft has decides how three of them can
		 * be worded at all: with one there is nothing to disambiguate
		 * and the line names it, with several it cannot and says "a
		 * scan range" with an ellipsis - this tool's existing promise
		 * that a choice is still coming, the way File spells Open and
		 * Save As.
		 */
		uint32_t here = 0, k, many = 0;
		uint32_t seen[MAX_GROUP], g;
		char add[40], one[40], t[CH_W];

		one[0] = 0;
		for (k = 0; k < v->n_decl; k++)
			if (v->decl[k].grp != GRP_NONE)
				here |= v->decl[k].at_mask;
		c->arg2 = here;
		v->rng_mask = here;

		for (g = 0; g < v->n_grp; g++) {
			uint32_t mm;
			int dup = 0;

			if (!grp_has_range(v, g))
				continue;
			mm = grp_mask(v, g);
			for (k = 0; k < many; k++)
				dup |= seen[k] == mm;
			if (!dup)
				seen[many++] = mm;
		}
		if (many == 1)
			rng_name_of(cur_obj(v)->fmt, seen[0], one, sizeof one);

		if (here) {
			rng_name_of(cur_obj(v)->fmt, here, add, sizeof add);
			if (many > 1) {
				snprintf(t, sizeof t,
					 "Switch a scan range to %.11s...",
					 add);
				ch_add(c, t);
				snprintf(t, sizeof t,
					 "Extend a scan range with %.9s...",
					 add);
				ch_add(c, t);
			} else {
				snprintf(t, sizeof t,
					 "Switch scan range to %.15s", add);
				ch_add(c, t);
				snprintf(t, sizeof t, "Extend %.12s with %.12s",
					 one, add);
				ch_add(c, t);
			}
			snprintf(t, sizeof t, "Add %.15s to scan ranges", add);
			ch_add(c, t);
		}
		ch_add(c, many > 1 ? "Switch a scan range to WHOLE-FILE..."
				   : "Switch scan range to WHOLE-FILE");
	} else if (what == CH_RANGE3) {
		/*
		 * Which of the draft's ranges the line applies to.
		 *
		 * Only when there is more than one - a list offering a single
		 * answer is a question nobody asked - and opened to the RIGHT
		 * of the line that raised it, the way a submenu belongs beside
		 * its parent rather than on top of it.
		 */
		uint32_t seen[MAX_GROUP], n_seen = 0, k, g;

		for (g = 0; g < v->n_grp; g++) {
			uint32_t mm;
			char t[CH_W];
			int dup = 0;

			if (!grp_has_range(v, g))
				continue;
			mm = grp_mask(v, g);
			for (k = 0; k < n_seen; k++)
				dup |= seen[k] == mm;
			if (dup)
				continue;
			seen[n_seen++] = mm;
			rng_name_of(cur_obj(v)->fmt, mm, t, sizeof t);
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
			if (v->decl[i].grp != GRP_NONE)
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
		/* The chooser is 26 wide; these have to say the difference
		 * inside that. */
		ch_add(c, "or   next only if miss");
		ch_add(c, "and  next as well");
	} else if (what == CH_SWITCH) {
		/*
		 * Three answers, and the one that loses work is not the first.
		 *
		 * Named by what happens rather than by yes and no: "discard"
		 * is a word people read before clicking, "OK" is not.
		 */
		ch_add(c, "keep editing");
		ch_add(c, "write it, then switch");
		ch_add(c, "discard it and switch");
	} else if (what == CH_OPT) {
		/* Only the ones this object can answer for, and only the ones
		 * not already there: a list that offers what it will refuse is
		 * a list that lies about itself. */
		if (!v->opt_on[OPT_SIZE_MIN])
			ch_add(c, opt_word[OPT_SIZE_MIN]);
		if (!v->opt_on[OPT_SIZE_MAX])
			ch_add(c, opt_word[OPT_SIZE_MAX]);
		/*
		 * Architecture and subtype belong to executables and to nothing
		 * else: a zip has no machine and a PDF has no ET_DYN. Offered
		 * on the object in hand rather than from a fixed list, so the
		 * menu answers for the file being looked at.
		 */
		{
			uint8_t fm = cur_obj(v)->ctx.format;
			int exe = fm == KOF_FMT_ELF || fm == KOF_FMT_PE ||
				  fm == KOF_FMT_MACHO;

			if (exe && !v->opt_on[OPT_ARCH] && cur_obj(v)->ctx.arch)
				ch_add(c, opt_word[OPT_ARCH]);
			if (exe && !v->opt_on[OPT_SUBTYPE] &&
			    kof_inspect_subtype_name(fm,
						     cur_obj(v)->ctx.subtype))
				ch_add(c, opt_word[OPT_SUBTYPE]);
		}
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

		/* 1 is find_any and n is find_all, and both already have their
		 * own entry in the rule list. */
		/* The number, and only the number. How many there are to
		 * choose from is not a choice - it is shown beside the field
		 * and follows the markers as they are added. */
		for (i = 2; i + 1u <= n; i++) {
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
	uint32_t g, i;

	for (g = 0; g < v->n_grp; g++) {
		if (!grp_has_range(v, g) || grp_mask(v, g) != was)
			continue;
		v->grp[g].mask = now;
		/* The strings follow, or their row would keep claiming a
		 * region the matcher no longer searches. */
		for (i = 0; i < v->n_decl; i++)
			if (v->decl[i].grp == g) {
				v->decl[i].mask = now;
				rng_name_of(cur_obj(v)->fmt, now,
					    v->decl[i].rgn,
					    sizeof v->decl[i].rgn);
				decl_locate(v, &v->decl[i]);
			}
	}
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
		say_note(v, "%s", "scan range switched");
		break;
	case 1:
		rng_retarget(v, target, target | here);
		say_note(v, "%s", "scan range extended");
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
				say_note(v, "%s", "a matcher already searches "
					 "that range");
				return;
			}
		for (k = 0; k < v->n_rng_add; k++)
			if (v->rng_add[k] == here) {
				say_note(v, "%s", "that range is already "
					 "declared");
				return;
			}
		if (v->n_rng_add >= MAX_GROUP) {
			say_err(v, "%s", "no room for another range");
			return;
		}
		v->rng_add[v->n_rng_add++] = here;
		say_note(v, "%s", "scan range added - give it a matcher");
		break;
	}
	case 3:
		rng_retarget(v, target, KOF_SCAN_ALL);
		say_note(v, "%s", "scan range is now the whole file");
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
			if (v->opt_on[k])
				continue;
			if (k == OPT_ARCH && !ob->ctx.arch)
				continue;
			if (k == OPT_SUBTYPE && (!ob->fmt || !ob->ctx.subtype))
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
		uint32_t seen[MAX_GROUP], ns = 0, g, k;
		int verb;

		for (g = 0; g < v->n_grp; g++) {
			uint32_t mm;
			int dup = 0;

			if (!grp_has_range(v, g))
				continue;
			mm = grp_mask(v, g);
			for (k = 0; k < ns; k++)
				dup |= seen[k] == mm;
			if (!dup)
				seen[ns++] = mm;
		}
		/* With no located marker the list holds WHOLE-FILE alone, so
		 * the row picked is the last verb whatever its index. */
		verb = c->n == 1 ? 3 : c->sel;
		/* "Add" makes a range rather than changing one, so it never
		 * has to ask which. The other three do, and only when the
		 * draft holds more than one. */
		if (verb != 2 && ns > 1) {
			struct chooser up = *c;

			up.open = 1;
			ch_open(v, CH_RANGE3, (uint32_t)verb,
				up.row + up.sel + 1, up.col + CH_W);
			v->ch_up = up;
			return;
		}
		rng_apply(v, verb, ns ? seen[0] : 0, c->arg2);
		return;
	}
	if (c->what == CH_RANGE3) {
		uint32_t seen[MAX_GROUP], ns = 0, g, k;

		for (g = 0; g < v->n_grp; g++) {
			uint32_t mm;
			int dup = 0;

			if (!grp_has_range(v, g))
				continue;
			mm = grp_mask(v, g);
			for (k = 0; k < ns; k++)
				dup |= seen[k] == mm;
			if (!dup)
				seen[ns++] = mm;
		}
		if ((uint32_t)c->sel < ns)
			rng_apply(v, (int)c->arg, seen[c->sel], v->rng_mask);
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
			if (v->decl[i].grp != GRP_NONE)
				continue;
			if (!rng_holds(grp_mask(v, c->arg), v->decl[i].mask))
				continue;
			if ((int)n++ != c->sel)
				continue;
			v->decl[i].grp = c->arg;
			break;
		}
	} else if (c->what == CH_THRESH) {
		q->rule = 2;
		q->thresh = (uint32_t)c->sel + 2u;
	} else if (c->what == CH_RULE) {
		q->rule = c->sel;
		if (c->sel == 2 && q->thresh < 2u)
			q->thresh = 2;
	} else if (c->what == CH_RANGE) {
		/*
		 * Row 0 is the range derived from this matcher's markers, the
		 * last is WHOLE-FILE, and anything between is a range the
		 * draft declared and nothing uses. Resolved by walking the
		 * same list the chooser was built from rather than by an index
		 * into it - the two would drift the moment one gained a row.
		 */
		if (c->sel == 0) {
			q->mask = c->arg2;
		} else {
			uint32_t i, n = 1;

			q->mask = KOF_SCAN_ALL;
			for (i = 0; i < v->n_rng_add; i++) {
				uint32_t k, used = 0;

				for (k = 0; k < v->n_grp; k++)
					used += (uint32_t)(grp_has_range(v, k)
							   && grp_mask(v, k) ==
							   v->rng_add[i]);
				if (used || v->rng_add[i] == c->arg2)
					continue;
				if ((int)n == c->sel) {
					q->mask = v->rng_add[i];
					break;
				}
				n++;
			}
		}
	}
}

static void draw_one_chooser(struct out *o, const struct chooser *c, int live)
{
	int i;

	for (i = 0; i < c->n; i++) {
		out_at(o, c->row + i, c->col);
		/* The parent keeps its highlight so the line the submenu is
		 * qualifying stays pointed at, but in a colour that says the
		 * keyboard is not there any more. */
		out_str(o, i == c->sel ? (live ? A_SEL : "\033[100;97m")
				       : "\033[47;30m");
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
	if (v->n_grp)
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
			if (v->decl[i].grp == g)
				m |= v->decl[i].mask;
		if (m)
			v->grp[g].mask = m;
	}
	if (!moved && !gone)
		say_note(v, "every marker is already in the region it is "
			    "searched for");
	else if (!gone)
		say_note(v, "%u marker(s) moved to the region they are in",
			 moved);
	else
		say_note(v, "%u moved, %u not in this object - left as "
			    "declared", moved, gone);
}

/*
 * Wide enough for the longest thing the region cell can say.
 *
 * It was twelve, which fitted one region name exactly - and then a range became
 * able to cover two, so the cell had to hold "CODE&DATA>HEADERS" and printed
 * half of it. A column sized to the shortest case truncates silently, and a
 * truncated word reads as a bug in the data rather than in the layout.
 */
static const char str_hdr[] =
	" Strings     word      case         region             size  bytes";

static void draw_decl(struct out *o, struct view *v)
{
	int top = decl_top();
	int r = 0;
	uint32_t g, i;
	int c;


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
		int room = g_cols - c - 3;
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
	if (v->n_grp && PR_VIS(r)) {
		uint32_t seen[MAX_GROUP], n_seen = 0, k;

		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Scan ranges " A_OFF);
		for (g = 0; g < v->n_grp; g++) {
			uint32_t m;
			char t[40];
			int dup = 0;

			/*
			 * A matcher with no markers yet searches nothing, so it
			 * has no range to report. It used to report WHOLE-FILE,
			 * because that is what grp_mask falls back to when it
			 * has nothing to derive from - which read as "this
			 * signature will scan the whole file" beside strings
			 * that had all been taken from one region.
			 */
			if (!grp_has_range(v, g))
				continue;
			m = grp_mask(v, g);
			for (k = 0; k < n_seen; k++)
				dup |= seen[k] == m;
			if (dup)
				continue;
			seen[n_seen++] = m;
			rng_name_of(cur_obj(v)->fmt, m, t, sizeof t);
			out_fmt(o, " %s%s" A_OFF, A_LOC, t);
		}
		/* Declared and not yet used by anything. Named so it can be
		 * seen, marked so it cannot be mistaken for a range that is
		 * doing work. */
		for (g = 0; g < v->n_rng_add; g++) {
			char t[40];
			uint32_t q;
			int used = 0;

			for (q = 0; q < n_seen; q++)
				used |= seen[q] == v->rng_add[g];
			if (used)
				continue;
			rng_name_of(cur_obj(v)->fmt, v->rng_add[g], t,
				    sizeof t);
			out_fmt(o, " %s%s (unused)" A_OFF, A_WARN, t);
			n_seen++;
		}
		if (!n_seen)
			out_str(o, A_DIM " none yet" A_OFF);
		/*
		 * The row's two controls, named for the distinction the panel
		 * already draws between its columns: a matcher's range is
		 * where it will be LOOKED FOR, a string's region is where it
		 * WAS FOUND. One button per fact, in the row about both. They
		 * live here rather than beside the strings because both act on
		 * the whole draft.
		 */
		{
			uint32_t d2, off = 0;
			int c0;

			for (d2 = 0; d2 < v->n_decl; d2++)
				off += (uint32_t)(v->decl[d2].off_rgn != 0);

			c0 = 2 + (int)o->col_hint;
			out_fmt(o, "  %s[Update scan range]" A_OFF,
				n_seen ? "\033[100;97m" : "\033[100;37m");
			v->rgs_c0 = c0;
			v->rgs_c1 = (int)o->col_hint;

			c0 = 2 + (int)o->col_hint;
			out_fmt(o, "  %s[Update string regions]" A_OFF,
				off ? "\033[43;30m" : "\033[100;37m");
			v->rgf_c0 = c0;
			v->rgf_c1 = (int)o->col_hint;
		}
	}
	r += v->n_grp ? 1 : 0;

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
	if (v->n_decl && PR_VIS(r))
		sec_bar(o, v, PR(r), str_hdr);
	r += v->n_decl ? 1 : 0;
	v->row_str = PR(r);
	for (i = 0; i < v->n_decl; i++, r++) {
		const struct decl *d = &v->decl[i];
		uint32_t k;

		if (!PR_VIS(r))
			continue;
		row_start(o, PR(r), 1);
		out_fmt(o, "   %s%u." A_OFF " %s%-4s" A_OFF " ",
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
		if (d->at == KOF_BROKEN) {
			/*
			 * Declared, and not in this object.
			 *
			 * The colour is the whole message - red on a row whose
			 * neighbours are not red. Spelling "absent" beside the
			 * region cost more width than the column had and got
			 * truncated to a stray letter. The region stays because
			 * that is still where the module will look.
			 */
			out_fmt(o, " %s%-18.18s" A_OFF " %s%5u" A_OFF "  ",
				A_BAD, d->rgn, A_SIZE, d->len);
		} else if (d->off_rgn) {
			char both[40];

			snprintf(both, sizeof both, "%s>%s", d->rgn,
				 d->at_rgn);
			out_fmt(o, " %s%-18.18s" A_OFF " %s%5u" A_OFF "  ",
				A_WARN, both, A_SIZE, d->len);
		} else {
			out_fmt(o, " %s%-18s" A_OFF " %s%5u" A_OFF "  ",
				A_LOC, d->rgn, A_SIZE, d->len);
		}
		v->str_by[i][0] = 1 + (int)o->col_hint;
		{
			uint32_t from = v->decl_hoff / 2u;

			if (from > d->len)
				from = d->len;
			for (k = from; k < d->len && k < from + 16u; k++)
				out_fmt(o, "%02X", d->bytes[k]);
			if (d->len > from + 16u)
				out_str(o, "...");
		}
		v->str_by[i][1] = (int)o->col_hint;
		out_at(o, PR(r), g_cols - 4);
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

		if (PR_VIS(r)) {
			char nm[40], lead[16], th[24];

			row_start(o, PR(r), 1);
			/* Nothing to name only when there is neither a marker
			 * to derive a range from nor a range that was
			 * chosen. */
			if (grp_has_range(v, g))
				rng_name_of(cur_obj(v)->fmt, grp_mask(v, g), nm,
					    sizeof nm);
			else
				snprintf(nm, sizeof nm, "-");
			if (q->rule == 2)
				snprintf(th, sizeof th, ">= %u of %u",
					 q->thresh, grp_count(v, g));
			else
				th[0] = 0;
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
			v->grp_th[g][0] = v->grp_th[g][1] = -1;
			if (th[0]) {
				out_str(o, A_DIM "   Threshold: " A_OFF);
				v->grp_th[g][0] = 1 + (int)o->col_hint;
				out_fmt(o, "%s%s" A_OFF, A_ID, th);
				v->grp_th[g][1] = (int)o->col_hint;
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
			if (v->decl[i].grp != g)
				continue;
			out_fmt(o, "%s%s%u" A_OFF, first ? "" : ", ", A_ID,
				i + 1u);
			first = 0;
		}
		if (first)
			out_str(o, A_DIM "none yet" A_OFF);
		v->p_c0 = v->p_c1 = -1;
		if (decl_free(v)) {
			v->p_c0 = 1 + (int)o->col_hint;
			out_fmt(o, "   " A_ID "[+ String]" A_OFF);
			v->p_c1 = (int)o->col_hint;
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
						out_fmt(o, A_WARN " %s " A_OFF,
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
			out_fmt(o, A_WARN "[%s]" A_OFF,
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

static void draw_marker_line(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	char name[80], head[24], right[120];
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

	if (ob->packer[0])
		out_fmt(o, A_BAD "%s" A_OFF A_DIM "  |  " A_OFF, ob->packer);

	if (!ob->n_touch) {
		out_str(o, A_DIM "no markers" A_OFF);
	} else {
		char hits[24], skips[24];
		int c;

		for (i = 0; i < ob->n_touch; i++)
			hit += (uint32_t)(ob->touch[i].fired != 0);
		touch_name(&ob->touch[v->sel_touch], name, sizeof name);
		touch_head(&ob->touch[v->sel_touch], head, sizeof head);

		/* Capitalised, because they are the labels of two controls
		 * rather than words in a sentence - the same way every other
		 * button on this screen is written. */
		snprintf(hits, sizeof hits, "Hit %u", hit);
		snprintf(skips, sizeof skips, "Skip %u", ob->n_touch - hit);

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
			touch_colour(&ob->touch[v->sel_touch]), name, head);
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
	if (v->copy_msg[0]) {
		snprintf(right, sizeof right, "%s", v->copy_msg);
		rcol = v->copy_ok ? A_SIZE : A_WARN;
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
		if (v->find_n && v->find_i)
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
	} else if (v->off_region) {
		/*
		 * Only the unusual state is announced. File offsets are what
		 * the column shows unless somebody changed it, so saying so
		 * every time is a label for the expected case - the state worth
		 * a word is the one that would otherwise be read wrong.
		 */
		snprintf(right, sizeof right, "region offsets");
	} else {
		right[0] = 0;
	}

have_right:
	if (right[0]) {
		int at = g_cols - (int)strlen(right) - 1;

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
			uint32_t b;

			/*
			 * A hex marker's pool entry is a compiled program,
			 * not its bytes - so both its size and its content
			 * have to be read back out of that program. Taken at
			 * face value, the ten byte pattern 2F62696E2F7368002D63
			 * showed as 74 bytes of the program's own header.
			 */
			char hx[128], span[16];
			int is_hex = st->kind == KOF_STR_HEX;

			hx[0] = 0;
			if (is_hex) {
				kof_inspect_hex_span(st->bytes, st->len,
						     span, sizeof span);
				kof_inspect_hex_text(st->bytes, st->len,
						     hx, sizeof hx);
			} else {
				snprintf(span, sizeof span, "%u", st->len);
			}

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
			if (is_hex) {
				/* The pattern as it was written, wildcards and
				 * all - not the program that implements it. */
				out_fmt(o, "%.40s", hx);
				if (strlen(hx) > 40u)
					out_str(o, "...");
			} else {
				for (b = 0; b < st->len && b < 20u; b++)
					out_fmt(o, "%02X", st->bytes[b]);
				if (st->len > 20u)
					out_str(o, "...");
			}
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
	M_COPY_ASCII = 0,
	M_COPY_HEX,
	M_COPY_OFF_HEX,
	M_COPY_OFF_DEC,
	M_DECL_STR,
	M_DECL_HEX,
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
	{ "Copy ASCII",           1, 0 },
	{ "Copy hex",             1, 0 },
	{ "Copy offset (hex)",    2, 0 },
	{ "Copy offset (dec)",    2, 0 },
	{ "Declare as string",    1, 1 },
	{ "Declare as hex",       1, 1 },
	{ "Go to",                3, 2 },
	{ "Find string",          3, 2 },
	{ "Find hex",             3, 2 }
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
	if (a == M_COPY_ASCII || a == M_COPY_HEX)
		return v->sel_a != KOF_BROKEN;
	if (a == M_COPY_OFF_HEX || a == M_COPY_OFF_DEC)
		return 1;
	if (a == M_DECL_HEX)
		return v->sel_a != KOF_BROKEN && v->n_decl < MAX_DECL;
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
		for (k = lo; k <= hi; k++)
			t[n++] = cur_obj(v)->buf.p[view_map(v, k, 0)];
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
	copy_take(bytes, n);
	g_clip_via = copy_extern(bytes, n);
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
	v->copy_ok = g_clip_via != NULL;
	if (g_clip_via)
		snprintf(v->copy_msg, sizeof v->copy_msg,
			 "copied %u byte(s) via %s", (unsigned)n, g_clip_via);
	else
		snprintf(v->copy_msg, sizeof v->copy_msg,
			 "copied %u byte(s) - this program only, the terminal "
			 "refused the clipboard", (unsigned)n);
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
	struct object *ob = cur_obj(v);
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
	for (k = lo; k <= hi; k++)
		d->bytes[i++] = ob->buf.p[view_map(v, k, 0)];
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
	{
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

		d->mask = rn->mask ? rn->mask : KOF_SCAN_ALL;
		/* The column is narrow and a region word is short; a label
		 * long enough to overrun it is one that would not have fit
		 * on the row either. */
		snprintf(d->rgn, sizeof d->rgn, "%.23s",
			 rn->mask ? rn->label : "WHOLE-FILE");
	}
	d->grp = GRP_NONE;
	d->at = view_map(v, lo, 0);
	(void)g;
	v->warn[0] = 0;
	v->sel_decl = v->n_decl;
	v->n_decl++;

	/* The selection has been taken; leaving it lit would invite taking it
	 * twice. */
	v->sel_a = v->sel_b = KOF_BROKEN;
}

static void menu_run(struct view *v, int a)
{
	struct object *ob = cur_obj(v);
	uint64_t lo, hi, k, n;
	struct out t = { NULL, 0, 0, 0 };

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
	if (a == M_FIND_STR || a == M_FIND_HEX) {
		v->find_hex = a == M_FIND_HEX;
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
static void draw_bar(struct out *o, struct view *v);
static void draw_help(struct out *o, struct view *v);
static void draw_prop(struct out *o, struct view *v);

/* The properties page was up on the frame before this one. */
static int g_prop_drawn;

static void redraw(struct view *v)
{
	struct out o = { NULL, 0, 0, 0 };
	int wiped = 0, under;

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

	out_str(&o, "\033[?2026h");
	if (under) {
		draw_frame(&o, v);
		draw_tree(&o, v);
		draw_hex(&o, v);
		draw_decl(&o, v);
		draw_marker_line(&o, v);
		if (v->show_list)
			draw_list(&o, v);
		if (v->menu_open)
			draw_menu(&o, v);
		draw_bar(&o, v);
		if (v->find_open)
			draw_find(&o, v);
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
		n = kof_scan_resolve_range(&v->obj[obj].ctx, v->node[k].mask,
					   v->probe);
		for (j = 0; j < n; j++)
			if (file_off >= v->probe[j].off &&
			    file_off < v->probe[j].off + v->probe[j].len)
				return k;
	}
	return best;
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
	struct object *ob = cur_obj(v);
	uint8_t pat[64];
	uint32_t n = find_bytes(v, pat, sizeof pat);
	uint64_t i;

	if (!n || n > ob->buf.n)
		return KOF_BROKEN;
	for (i = from; i + n <= ob->buf.n; i++) {
		uint32_t k;

		for (k = 0; k < n; k++) {
			uint8_t a = ob->buf.p[i + k], b = pat[k];

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
		if (at == KOF_BROKEN)
			at = find_prev(v, cur_obj(v)->buf.n);   /* wrap */
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
	view_show(v, at);
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
enum bar_menu { BM_FILE = 0, BM_EDIT, BM_HELP, BM_COUNT };

enum bar_item {
	BI_OPEN = 0, BI_SAVE, BI_SAVE_AS, BI_PROPS, BI_QUIT,
	BI_FIND, BI_GOTO,
	BI_KEYS, BI_ABOUT,
	BI_COUNT
};

static const struct {
	const char *label;
	int         menu;
} bar_item[BI_COUNT] = {
	{ "Open...",        BM_FILE },
	{ "Save",           BM_FILE },
	{ "Save As...",     BM_FILE },
	{ "Properties",     BM_FILE },
	{ "Quit",           BM_FILE },
	{ "Find...",        BM_EDIT },
	{ "Go to...",       BM_EDIT },
	{ "Keyboard",       BM_HELP },
	{ "About",          BM_HELP }
};

static const char *const bar_name[BM_COUNT] = {
	"File", "Edit", "Help"
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

static int bar_enabled(struct view *v, int i)
{
	switch (i) {
	case BI_OPEN:      return 0;            /* no way in yet */
	case BI_SAVE:      return save_ok(v);
	case BI_SAVE_AS:   return save_as_ok(v);
	case BI_PROPS:     return 1;
	case BI_QUIT:      return 1;
	case BI_FIND:      return 1;
	case BI_GOTO:      return 0;            /* the dialog is not built */
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

#define BAR_W 18

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
	int m, i, y;

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

		if (bar_item[i].menu != v->bar_open || !bar_shown(v, i))
			continue;
		out_at(o, y, col);
		if (i == v->bar_sel)
			out_str(o, BAR_CUR);
		else if (!bar_enabled(v, i))
			out_str(o, BAR_OFF);
		else
			out_str(o, BAR_ON);
		out_fmt(o, " %-*s", BAR_W - 1, bar_item[i].label);
		out_str(o, A_OFF);
		y++;
	}
}

/* Which item a click on an open drop-down landed on, or -1. */
static int bar_item_at(struct view *v, int row, int col)
{
	int y = 2, i, c0 = bar_col(v->bar_open);

	if (col < c0 || col >= c0 + BAR_W)
		return -1;
	for (i = 0; i < BI_COUNT; i++) {
		if (bar_item[i].menu != v->bar_open || !bar_shown(v, i))
			continue;
		if (row == y)
			return i;
		y++;
	}
	return -1;
}


/* The two Help dialogs. Drawn like the find box: content, then the frame. */
static void draw_help(struct out *o, struct view *v)
{
	static const char *const keys[] = {
		"Ctrl+F     find",            "Ctrl+N     next match",
		"Ctrl+C     copy the field",  "Ctrl+V     paste",
		"Ctrl+O     open a file",     "Ctrl+Q     quit",
		"Tab        next pane",       "n          next marker",
		"o          file or region offsets",
		"arrows     move, and move the caret in a field",
		"click      select a byte; drag selects a run",
		"double     select the whole printable run",
		"right      the byte menu",
		"wheel      scrolls whatever is under the pointer"
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

static void prop_build(struct view *v)
{
	struct object *ob = cur_obj(v);
	const char *base = strrchr(ob->name, '/');
	uint32_t i, hit = 0;
	uint64_t total = 0;

	g_n_prop = 0;
	base = base ? base + 1 : ob->name;

	prop_head("Object");
	prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF, "name", base);
	prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_SIZE "%llu" A_OFF A_DIM
		 " bytes" A_OFF, "size", (unsigned long long)ob->buf.n);
	{
		const char *sub = ob->fmt
			? kof_inspect_subtype_name(ob->ctx.format,
						   ob->ctx.subtype) : NULL;

		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s%s%s" A_OFF,
			 "format",
			 ob->fmt ? kof_format_name(ob->ctx.format) : "raw",
			 sub ? " " : "", sub ? sub : "");
	}
	if (ob->fmt)
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_ID "%s" A_OFF, "arch",
			 kof_arch_name(ob->ctx.arch));
	/* Where it came from, when it did not come from the disk. Everything
	 * below describes bytes an unpacker produced, and reading it as the
	 * file on disk would be reading it as the wrong object. */
	if (ob->packer[0])
		prop_add(A_OFF, A_DIM "  %-11s " A_OFF A_WARN "%s" A_OFF,
			 "unpacked by", ob->packer);

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
			    v->node[i].mask)
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
	for (i = 0; i < v->n_node; i++)
		if (v->node[i].obj == v->node[v->sel_node].obj &&
		    v->node[i].mask)
			total += v->node[i].bytes;
	for (i = 0; i < v->n_node; i++) {
		const struct node *n = &v->node[i];

		if (n->obj != v->node[v->sel_node].obj || !n->mask)
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
	if (ob->fmt && ob->info && ob->fmt->anomalies) {
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

	prop_head("Signatures");
	for (i = 0; i < ob->n_touch; i++)
		hit += (uint32_t)(ob->touch[i].fired != 0);
	prop_add(A_OFF, "  %s%u" A_OFF A_DIM " fired, " A_OFF A_SIZE "%u"
		 A_OFF A_DIM " did not" A_OFF, hit ? A_BAD : A_SIZE, hit,
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
static void prop_put(struct out *o, const char *s, int room)
{
	int n = 0;

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

	/* The bottom rule: where in the page this window is. */
	snprintf(pos, sizeof pos, "%u-%u of %u", v->prop_off + 1u,
		 v->prop_off + shown, g_n_prop);
	out_at(o, top + h - 1, left);
	out_fmt(o, A_DIM "+- %s ", pos);
	for (i = 4 + (int)strlen(pos); i < w - 1; i++)
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
		if (y < (int)shown)
			prop_put(o, g_prop[v->prop_off + (uint32_t)y].text,
				 inner);
		else
			for (i = 0; i < inner; i++)
				out_str(o, " ");
		out_str(o, " " A_DIM "|" A_OFF);
	}
}

static void bar_run(struct view *v, int i)
{
	if (!bar_enabled(v, i))
		return;
	v->bar_open = -1;
	v->bar_sel = -1;
	switch (i) {
	case BI_SAVE:    generate(v, 0); break;
	case BI_SAVE_AS: generate(v, 1); break;
	case BI_FIND:
		v->find_open = 1;
		v->edit = 500;
		v->warn[0] = 0;
		break;
	case BI_PROPS:   v->prop_open = 1; v->prop_off = 0; break;
	case BI_KEYS:    v->help_open = 1; break;
	case BI_ABOUT:   v->help_open = 2; break;
	default: break;
	}
}

/* ---- input ---------------------------------------------------------------- */

enum key {
	K_NONE = 0, K_UP = 256, K_DOWN, K_LEFT, K_RIGHT, K_PGUP, K_PGDN,
	K_HOME, K_END,
	/* Not a key: the terminal changed size while nothing was being typed,
	 * and the loop has to be told so it repaints. */
	K_RESIZE,
	/* A bracketed paste, whose bytes are in g_paste. */
	K_PASTE,
	/* Kept contiguous and last: handle() tests the range to let mouse
	 * events past the modes that own the keyboard. */
	K_BACKTAB,
	K_CLICK, K_RCLICK, K_WHEEL_UP, K_WHEEL_DOWN, K_DRAG, K_RELEASE
};

static char   g_paste[4096];    /* the last bracketed paste */
static size_t g_paste_n;

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
	if (read(STDIN_FILENO, seq, 1) != 1)
		return 27;
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

		if (read(STDIN_FILENO, t, 1) != 1 || t[0] != '0')
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
	struct object *ob = cur_obj(v);
	uint64_t a = v->sel_a, b;

	if (a == KOF_BROKEN)
		return;
	b = a;
	while (a > 0) {
		uint64_t f = view_map(v, a - 1u, 0);

		if (f == KOF_BROKEN || !byte_text(ob->buf.p[f]))
			break;
		a--;
	}
	while (b + 1u < v->rgn_len) {
		uint64_t f = view_map(v, b + 1u, 0);

		if (f == KOF_BROKEN || !byte_text(ob->buf.p[f]))
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

		top = hex_top(); bot = hex_bot();
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
	}
}

/* Is the pointer on a scrollbar, and which. 0 for none. */
static int bar_under(struct view *v)
{
	if (g_my >= hex_top() && g_my <= hex_bot()) {
		if (g_mx == g_cols && v->rgn_len)
			return 1;
		if (g_mx == TREE_W)
			return 2;
	}
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
#define FIND_H 4

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

static void draw_find(struct out *o, struct view *v)
{
	int top = find_top(), y, i;

	find_row(o, top + 1);
	out_fmt(o, A_DIM "Find " A_OFF);
	v->f_txt[0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s[", v->edit == 500 ? A_SEL : A_ID);
	field_draw(o, v->find, v->caret, &v->find_off, 40, v->edit == 500, "", v->field_all);
	out_str(o, "]" A_OFF);
	v->f_txt[1] = (int)o->col_hint;
	out_fmt(o, A_DIM "  as " A_OFF);
	v->f_mode[0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s[%s]" A_OFF, A_WARN, v->find_hex ? "Hex" : "Text");
	v->f_mode[1] = (int)o->col_hint;
	out_str(o, "\033[K");

	find_row(o, top + 2);
	v->f_rx[0] = 1 + (int)o->col_hint;
	/* Bright black on white, not on bright black: the same colour twice is
	 * a grey block where a label should be. */
	out_fmt(o, "\033[47;90m[ ] Regex" A_OFF);
	v->f_rx[1] = (int)o->col_hint;
	out_str(o, "   ");
	v->f_ic[0] = 1 + (int)o->col_hint;
	if (v->find_hex)
		out_fmt(o, "\033[47;90m[ ] Ignore case" A_OFF);
	else
		out_fmt(o, "%s[%s] Ignore case" A_OFF, A_ID,
			v->find_icase ? "x" : " ");
	v->f_ic[1] = (int)o->col_hint;
	out_str(o, "   ");
	v->f_all[0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s[%s] Search whole object" A_OFF, A_ID,
		v->find_scope ? "x" : " ");
	v->f_all[1] = (int)o->col_hint;
	out_str(o, "\033[K");

	find_row(o, top + 3);
	v->f_next[0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s[ Find next ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_next[1] = (int)o->col_hint;
	out_str(o, "  ");
	v->f_back[0] = 1 + (int)o->col_hint;
	out_fmt(o, "%s[ Find previous ]" A_OFF, v->find[0] ? A_ID : A_DIM);
	v->f_back[1] = (int)o->col_hint;
	out_str(o, "  ");
	v->f_cancel[0] = 1 + (int)o->col_hint;
	out_fmt(o, A_ID "[ Cancel ]" A_OFF);
	v->f_cancel[1] = (int)o->col_hint;
	/* Where the hit is belongs on the status line, which says it already.
	 * Saying it twice made the dialog a row taller for no new fact. */
	out_str(o, "\033[K");

	for (y = top; y < top + FIND_H; y++) {
		out_at(o, y, 1);
		out_str(o, A_DIM);
		if (y == top) {
			out_str(o, "+");
			for (i = 2; i < g_cols; i++)
				out_str(o, "-");
			out_str(o, "+" A_OFF);
			continue;
		}
		out_str(o, "| " A_OFF);
		out_at(o, y, g_cols);
		out_str(o, A_DIM "|" A_OFF);
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
	if (rclick && !(g_my >= hex_top() && g_my <= hex_bot() &&
			g_mx > TREE_W && !v->show_list && !v->menu_open))
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
				break;
			}
		}
		return;
	}
	if (v->bar_open >= 0) {
		v->bar_open = -1;       /* a click anywhere else closes it */
		return;
	}

	if (v->find_open && find_click(v))
		return;

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
				top = hex_top(); bot = hex_bot();
				total = v->rgn_len; off = v->rgn_at;
				shown = (uint64_t)(bot - top + 1) * per;
			} else if (which == 2) {
				top = hex_top(); bot = hex_bot();
				total = v->n_node; off = v->tree_top;
				shown = (uint64_t)(bot - top + 1);
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
					view_show(v, t->str[k].at);
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
					say_note(v, "marker %u is not in this "
						 "object - nowhere to jump to",
						 k + 1u);
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
		else if (g_mx >= v->n_c0 && g_mx <= v->n_c1)
			ch_open(v, CH_RULE, MAX_GROUP, g_my, g_mx);
		else if (g_mx >= v->g_c0 && g_mx <= v->g_c1)
			generate(v, 0);
		else if (v->sv_c0 > 0 && g_mx >= v->sv_c0 && g_mx <= v->sv_c1)
			generate(v, 1);
		else if (g_mx >= v->nt_c0 && g_mx <= v->nt_c1)
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
		if (v->n_grp) {
			if (r == want) {
				/* The summary carries the draft's two range
				 * controls; the rest of it is a readout. */
				if (g_mx >= v->rgs_c0 && g_mx <= v->rgs_c1)
					ch_open(v, CH_RANGE2, 0, g_my, g_mx);
				else if (g_mx >= v->rgf_c0 && g_mx <= v->rgf_c1)
					draft_refresh(v);
				return;
			}
			r++;
		}
		if (v->n_decl) {
			if (r == want)
				return;         /* the "Strings" heading */
			r++;
			for (i = 0; i < v->n_decl; i++, r++) {
				if (r != want)
					continue;
				v->sel_decl = i;
				if (g_mx >= g_cols - 4) {
					decl_remove(v, i);
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
					if (v->decl[i].at != KOF_BROKEN)
						view_show(v, v->decl[i].at);
					else
						say_note(v, "string %u is "
							 "not in this object",
							 i + 1u);
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
				int c2 = 15;

				v->cur_grp = g;
				if (v->p_c0 > 0 && g_mx >= v->p_c0 &&
				    g_mx <= v->p_c1) {
					ch_open(v, CH_MARKER, g, g_my - 3,
						g_mx);
					return;
				}
				/* An id on this row is a marker; clicking it
				 * takes it back out of the matcher. */
				for (i = 0; i < v->n_decl; i++) {
					if (v->decl[i].grp != g)
						continue;
					if (g_mx >= c2 && g_mx < c2 + 3)
						v->decl[i].grp = GRP_NONE;
					c2 += 3;
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
	if (g_my >= hex_top() && g_my <= hex_bot() && g_mx > TREE_W) {
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
				      ? (v->off_region ? row0
						       : view_map(v, row0, 0))
				      : 0;
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
			v->dragging = 1;
			v->dragged = 0;
			if (again) {
				select_run(v);
				v->dragging = 0;
				v->dragged = 1;
			}
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
			    g_mx <= v->prop_x1)
				v->prop_open = 0;
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
			if (v->field_all && (k == 127 || k == 8 || k == 0x16 ||
					     k == K_PASTE ||
					     (k >= 0x20 && k < 0x7f))) {
				v->find[0] = 0;
				n = 0;
				v->caret = 0;
				v->field_all = 0;
				if (k == 127 || k == 8)
					return 1;
			}
			if (v->field_all && (k == K_LEFT || k == K_RIGHT ||
					     k == K_HOME || k == K_END ||
					     k == 27 || k == '\r' || k == '\n'))
				v->field_all = 0;
			if (k == 0x16 || k == K_PASTE) {
				const char *src = k == K_PASTE ? g_paste
							       : g_clip;
				size_t sn = k == K_PASTE ? g_paste_n
							 : g_clip_n, i;

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
			} else if (k >= 0x20 && k < 0x7f &&
				   n + 2u < sizeof v->find) {
				memmove(v->find + v->caret + 1u,
					v->find + v->caret,
					n - v->caret + 1u);
				v->find[v->caret++] = (char)k;
			}
			return 1;
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
		size_t cap, n;

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
		if (v->field_all && (k == 127 || k == 8 || k == 0x16 ||
				     k == K_PASTE ||
				     (k >= 0x20 && k < 0x7f))) {
			buf[0] = 0;
			n = 0;
			v->caret = 0;
			v->field_all = 0;
			if (k == 127 || k == 8)
				return 1;
		}
		if (v->field_all && (k == K_LEFT || k == K_RIGHT ||
				     k == K_HOME || k == K_END || k == 27 ||
				     k == '\r' || k == '\n'))
			v->field_all = 0;
		if (k == 0x16 || k == K_PASTE) {        /* Ctrl+V, or a paste */
			const char *src = k == K_PASTE ? g_paste : g_clip;
			size_t sn = k == K_PASTE ? g_paste_n : g_clip_n, i;

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
			 * a delete key would take. */
			if (v->caret) {
				memmove(buf + v->caret - 1u, buf + v->caret,
					n - v->caret + 1u);
				v->caret--;
			}
		} else if (k >= 0x20 && k < 0x7f && n + 2u < cap) {
			memmove(buf + v->caret + 1u, buf + v->caret,
				n - v->caret + 1u);
			buf[v->caret++] = (char)k;
		}
		return 1;
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
		say_note(v, "open: not built yet - pass the file on the "
			    "command line");
		break;
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
	case 'o':
		/* Both numbers are true; this says which one the column means. */
		v->off_region = !v->off_region;
		break;
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
		if (v->dragging && byte_under(v, g_my, g_mx, &at)) {
			if (at != v->sel_a)
				v->dragged = 1;
			v->sel_b = at;
		}
		break;
	}
	case K_RELEASE:
		v->sizing = 0;
		v->bar_drag = 0;
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
						view_show(v,
							  lt->str[v->sel_str].at);
				}
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
	"  --db D      load that database. Without it there is one object and\n"
	"              no markers: unpacking is what modules do, and modules\n"
	"              live in a database.\n"
	"  --bases D   the signature source tree, which is also where a drafted\n"
	"              signature is written. A content root or one of its kind\n"
	"              directories both work. Default kofdraft/.\n");
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
		if (o->mapped)
			kof_unmap_file(o->mapped, o->mapped_len);
	}
	free(v->ext);
}

int main(int argc, char **argv)
{
	const char *path = NULL, *db = NULL, *base = "kofdraft";
	kof_engine *eng = NULL;
	uint64_t last_paint = 0;
	struct view v;
	struct stat st;
	int fd, i, rc = 0;

	memset(&v, 0, sizeof v);
	v.sel_a = v.sel_b = KOF_BROKEN;
	v.find_at = KOF_BROKEN;
	v.bar_open = -1;
	v.bar_sel = -1;
	v.decl_cap = 12;
	/* An empty draft is a saved draft: whatever the hash of "nothing" turns
	 * out to be, it must not read as unsaved work. */
	v.saved_hash = draft_hash(&v);

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

	v.ext = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.ext);
	v.probe = malloc(KOF_SCAN_MAX_EXTENTS * sizeof *v.probe);
	if (!v.ext || !v.probe) {
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

	/*
	 * A file that already matches something opens showing what matched.
	 *
	 * That is nearly always the reason for opening it: a researcher looking
	 * at a detected sample is there to see the rule that caught it, or to
	 * write the one that should have. Starting on an empty panel makes them
	 * go and find it first.
	 */
	{
		struct object *o0 = &v.obj[0];
		uint32_t k;

		for (k = 0; k < o0->n_touch; k++)
			if (o0->touch[k].fired) {
				draft_show(&v, k);
				break;
			}
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
	kof_unmap_file(v.map, v.map_len);
	kof_engine_close(eng);
	return rc;
}
