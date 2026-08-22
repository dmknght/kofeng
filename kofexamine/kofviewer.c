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
#define MAX_DECL  32
#define MAX_GROUP 8

/* Every row the draft panel can ever hold, spelled from the limits rather than
 * counted once: the panel grew three kinds of row after this array was sized,
 * and a table that silently stops short is a panel whose bottom cannot be
 * scrolled to. */
#define MAX_PROW  (OPT_COUNT + 1 + 1 + MAX_DECL + 1 + 2 * MAX_GROUP + 1 + \
		   2 * MAX_GROUP)
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

static const char *const opt_word[OPT_COUNT] = {
	"size_min", "size_max", "arch", "subtype"
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
	char     note[80];          /* the author's note, emitted as a comment */
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
struct cond {
	char     expr[64];          /* over matcher ids */
	/*
	 * Why this condition says what it says, in the author's words.
	 *
	 * Written into the generated source as a comment above the branch. The
	 * modules in bases/ all carry one - a marker set is a fact, but why
	 * that set means Mirai and not a false positive is a judgement, and it
	 * is the judgement the next reader needs and cannot recover from the
	 * bytes.
	 */
	char     note[80];
	int      level;             /* 0 INFECT, 1 SUSPECT */
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

	/*
	 * How a literal is compared. Both are properties of KOF_DEFINE_STR and
	 * neither exists for a hex pattern - kofsig.h says why: folding case on
	 * a byte that may be a wildcard means nothing, and a word boundary is a
	 * notion of text.
	 */
	int      fullword;
	int      icase;
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
#define CH_W     26

enum ch_what {
	CH_NONE = 0,
	CH_RULE,        /* find all / any / multi, for a new or existing group */
	CH_RANGE,       /* which declared range a condition searches */
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
	CH_CMATCH       /* which matcher to put into a condition */
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
	uint32_t    tree_hoff, list_hoff;

	struct decl  decl[MAX_DECL];
	uint32_t     n_decl, sel_decl;

	struct range rng[MAX_RANGE];
	uint32_t     n_rng, cur_rng;

	struct group grp[MAX_GROUP];       /* matchers */
	uint32_t     n_grp, cur_grp;

	struct cond  cnd[MAX_GROUP];
	uint32_t     n_cnd, cur_cnd;
	char         warn[120];     /* why the last add was refused */

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
	int         rng_c0, rng_c1, m_c0, m_c1, s_c0, s_c1, e_c0, e_c1;
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
	char        num[24];        /* the size being typed */
	int         num_fresh;      /* nothing typed into it yet */
	int         row_cnd, row_str;
	int         cnd_lv[MAX_GROUP][2], cnd_vr[MAX_GROUP][2];
	int         cnd_nm[MAX_GROUP][2];
	/* The comment boxes, and the condition's own "+ matcher". Recorded per
	 * row as they are drawn, because a row that is scrolled out has no
	 * columns and must not answer a click meant for the one in its place. */
	int         cnd_nt[MAX_GROUP][2], grp_nt[MAX_GROUP][2];
	int         cnd_mt[MAX_GROUP][2];
	int         row_rng, row_grp;
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
			unsigned long n = strtoul(p, (char **)&p, 10);

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

static uint32_t grp_count(struct view *v, uint32_t g)
{
	uint32_t i, n = 0;

	for (i = 0; i < v->n_decl; i++)
		n += v->decl[i].grp == g;
	return n;
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

			at += (size_t)snprintf(out + at, cap - at, "%s%s",
					       at ? "|" : "", t ? t + 1 : w);
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
	rng_name_of(fmt, mask, w, sizeof w);
	for (i = 0; w[i]; i++) {
		if (w[i] == '|' || w[i] == '-')
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
		/* Nothing written means every matcher, joined - the reading
		 * that makes an empty field a default rather than an error. */
		uint32_t g;

		for (g = 0; g < v->n_grp; g++) {
			if (any)
				fprintf(f, " && ");
			emit_matcher(f, v, g);
			any = 1;
		}
		if (!any)
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

static void emit_cond(FILE *f, struct view *v, uint32_t i, int depth)
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
	emit_note(f, c->note, depth);
	for (d = 0; d < depth; d++)
		fputc('\t', f);
	fprintf(f, "if (");
	emit_expr(f, v, c->expr);
	fprintf(f, ")");

	if (!cnd_children(v, i)) {
		fprintf(f, "\n");
		for (d = 0; d <= depth; d++)
			fputc('\t', f);
		fprintf(f, "KOF_SCAN_%s(", c->level ? "SUSPECT" : "INFECT");
		if (c->var_kind == 2 && c->variant[0])
			fprintf(f, "\"%s\"", c->variant);
		else if (c->var_kind == 1)
			fprintf(f, "KOF_MALVAR_GENERIC");
		else
			fprintf(f, "KOF_MALVAR_AUTO");
		fprintf(f, ");\n");
		return;
	}

	fprintf(f, " {\n");
	for (k = 0; k < v->n_cnd; k++)
		if (v->cnd[k].parent == (int)i)
			emit_cond(f, v, k, depth + 1);
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
static void generate(struct view *v)
{
	struct object *ob = &v->obj[v->decl[0].obj];
	char path[400], safe[48];
	uint32_t i, k;
	FILE *f;
	size_t j = 0;

	v->gen_path[0] = 0;
	v->gen_ok = 0;
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
			snprintf(v->gen_path, sizeof v->gen_path,
				 "cannot create %s", dir);
			return;
		}
		snprintf(path, sizeof path, "%s/%s.c", dir, safe);
	}
	f = fopen(path, "w");
	if (!f) {
		snprintf(v->gen_path, sizeof v->gen_path, "cannot write %s",
			 path);
		return;
	}

	fprintf(f,
		"/*\n"
		" * Drafted with kofviewer.\n"
		" *\n"
		" * Authored against: %s\n", ob->name);
	if (ob->packer[0])
		fprintf(f, " * Reached via:      %s\n", ob->packer);
	fprintf(f,
		" *\n"
		" * A signature written here only runs while whatever produced\n"
		" * that object still produces it.\n"
		" */\n\n"
		"#include <kofmod/kofsig.h>\n\n");

	/* The format the object actually is, so the host can rule the module
	 * out without entering it - and so the regions above mean something. */
	{
		static const char *const fmtname[] = {
			"KOF_FMT_ANY", "KOF_FMT_ELF", "KOF_FMT_PE",
			"KOF_FMT_MACHO", "KOF_FMT_SCRIPT", "KOF_FMT_TEXT",
			"KOF_FMT_GZIP", "KOF_FMT_DOCOLE", "KOF_FMT_ZIP",
			"KOF_FMT_DOCZIP", "KOF_FMT_TAR", "KOF_FMT_7Z",
			"KOF_FMT_RAR", "KOF_FMT_XZ", "KOF_FMT_RTF",
			"KOF_FMT_PDF"
		};

		fprintf(f, "KOF_TARGET_FORMAT(%s);\n",
			(ob->fmt && ob->ctx.format <
			 sizeof fmtname / sizeof fmtname[0])
			? fmtname[ob->ctx.format] : "KOF_FMT_ANY");
	}
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

	fprintf(f, "\nKOF_DEFINE_SCAN\n{\n");
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
	for (k = 0; k < v->n_cnd; k++)
		if (v->cnd[k].parent < 0)
			emit_cond(f, v, k, 1);
	fprintf(f, "}\n");

	v->gen_ok = ferror(f) == 0;
	fclose(f);
	snprintf(v->gen_path, sizeof v->gen_path, "%s %s",
		 v->gen_ok ? "wrote" : "failed", path);
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
		if (need != KOF_SCAN_ALL)
			ch_add(c, "WHOLE-FILE");
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
		ch_add(c, "INFECT");
		ch_add(c, "SUSPECT");
	} else if (what == CH_VARIANT) {
		ch_add(c, "auto");
		ch_add(c, "generic");
		ch_add(c, "custom...");
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
			if (cnd_uses(&v->cnd[arg], i))
				continue;
			snprintf(t, sizeof t, "%u  %s", i + 1u,
				 v->grp[i].rule == 1 ? "find_any" :
				 v->grp[i].rule == 2 ? "find_multi" :
				 "find_all");
			ch_add(c, t);
		}
		if (!c->n)
			return;
	} else if (what == CH_OPT) {
		/* Only the ones this object can answer for, and only the ones
		 * not already there: a list that offers what it will refuse is
		 * a list that lies about itself. */
		if (!v->opt_on[OPT_SIZE_MIN])
			ch_add(c, opt_word[OPT_SIZE_MIN]);
		if (!v->opt_on[OPT_SIZE_MAX])
			ch_add(c, opt_word[OPT_SIZE_MAX]);
		if (!v->opt_on[OPT_ARCH] && cur_obj(v)->ctx.arch)
			ch_add(c, opt_word[OPT_ARCH]);
		if (!v->opt_on[OPT_SUBTYPE] && cur_obj(v)->fmt &&
		    cur_obj(v)->ctx.subtype)
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

		/* 1 is find_any and n is find_all, and both already have their
		 * own entry in the rule list. */
		for (i = 2; i + 1u <= n; i++) {
			snprintf(t, sizeof t, ">= %u of %u", i, n);
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

/* What picking the highlighted item does. */
static void ch_take(struct view *v)
{
	struct chooser *c = &v->ch;
	struct group *q;

	c->open = 0;
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
	if (c->what == CH_CMATCH) {
		struct cond *cc;
		uint32_t i, n = 0;

		if (c->arg >= v->n_cnd)
			return;
		cc = &v->cnd[c->arg];
		for (i = 0; i < v->n_grp; i++) {
			size_t l;

			if (cnd_uses(cc, i))
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
				 l ? "&" : "", i + 1u);
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
		q->mask = c->sel ? KOF_SCAN_ALL : c->arg2;
	}
}

static void draw_chooser(struct out *o, struct view *v)
{
	int i;

	if (!v->ch.open)
		return;
	for (i = 0; i < v->ch.n; i++) {
		out_at(o, v->ch.row + i, v->ch.col);
		out_str(o, i == v->ch.sel ? A_SEL : "\033[47;30m");
		out_fmt(o, " %-*.*s", CH_W - 2, CH_W - 2, v->ch.item[i]);
		out_str(o, A_OFF);
	}
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
		    (int)(rr) - (int)v->prow_off < g_decl_rows - 1)

enum prow_kind {
	RW_OPT = 0, RW_RANGES, RW_STRHDR, RW_STR, RW_ADDM,
	RW_MATCH, RW_MARKERS, RW_ADDC, RW_COND, RW_CMATCH
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
	prow_add(v, RW_ADDM, 0);
	for (i = 0; i < v->n_grp; i++) {
		prow_add(v, RW_MATCH, i);
		prow_add(v, RW_MARKERS, i);
	}
	prow_add(v, RW_ADDC, 0);
	for (i = 0; i < v->n_cnd; i++) {
		prow_add(v, RW_COND, i);
		prow_add(v, RW_CMATCH, i);
	}
}

static void draw_decl(struct out *o, struct view *v)
{
	int top = decl_top();
	int r = 0;
	uint32_t g, i;
	int c;

	if (!g_decl_rows)
		return;

	/*
	 * Erase the whole area first.
	 *
	 * The panel changes height as it is built, and a row that stops being
	 * drawn is a row nobody erases - so an old line survived under the new
	 * layout and read as a duplicate of the row that had moved. Clearing
	 * the area costs one escape per row and removes the whole class.
	 */
	for (r = 0; r < g_decl_rows; r++)
		row_start(o, top + r, 1);
	r = 0;

	/* ---- what the module declares ---- */
	row_start(o, top, 1);
	out_fmt(o, A_DIM " define " A_OFF);

	c = 1 + (int)o->col_hint;
	out_fmt(o, A_DIM "family " A_OFF "%s[%s]" A_OFF,
		v->edit == 1 ? A_SEL : A_ID, v->family[0] ? v->family : "?");
	v->f_c0 = c; v->f_c1 = (int)o->col_hint;

	c = 2 + (int)o->col_hint;
	out_fmt(o, A_DIM "  type " A_OFF A_ID "[%s]" A_OFF,
		maltype_word[v->maltype % MALTYPE_N]);
	v->t_c0 = c; v->t_c1 = (int)o->col_hint;

	c = 2 + (int)o->col_hint;
	/* Disabled keeps the background and loses contrast, it does not lose the
	 * text - 100;90 is bright black on bright black, the same colour twice,
	 * which is a grey block where a label should be. */
	out_fmt(o, "  " A_ID "[+ option]" A_OFF);
	v->o_c0 = c; v->o_c1 = (int)o->col_hint;

	c = 2 + (int)o->col_hint;
	out_fmt(o, "  %s[ generate ]" A_OFF,
		v->family[0] && v->n_cnd ? "\033[42;30m" : "\033[47;90m");
	v->g_c0 = c; v->g_c1 = (int)o->col_hint;

	if (v->warn[0])
		out_fmt(o, "  %s%s" A_OFF, A_BAD, v->warn);
	else if (v->gen_path[0])
		out_fmt(o, "  %s%s" A_OFF, v->gen_ok ? A_SIZE : A_BAD,
			v->gen_path);

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
		out_fmt(o, "   %s%-10s" A_OFF " ", A_DIM, opt_word[i]);
		v->opt_c0[i] = 1 + (int)o->col_hint;
		out_fmt(o, "%s%s" A_OFF,
			v->edit == 200 + (int)i ? A_SEL : A_ID,
			v->edit == 200 + (int)i ? v->num : val);
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
			if (!grp_count(v, g))
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
		if (!n_seen)
			out_str(o, A_DIM " none yet" A_OFF);
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
	if (v->n_decl && PR_VIS(r)) {
		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM " Strings    word      case         region"
			"       size  bytes" A_OFF);
	}
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
		if (d->hex)
			out_fmt(o, A_DIM "%-21s" A_OFF, "");
		else
			out_fmt(o, A_WARN "%-9s %-11s" A_OFF,
				d->fullword ? "fullword" : "substring",
				d->icase ? "ignore-case" : "exact-case");
		out_fmt(o, " %s%-12s" A_OFF " %s%5u" A_OFF "  ",
			A_LOC, d->rgn, A_SIZE, d->len);
		for (k = 0; k < d->len && k < 16u; k++)
			out_fmt(o, "%02X", d->bytes[k]);
		if (d->len > 16u)
			out_str(o, "...");
		out_at(o, PR(r), g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
	}

	/* ---- the matchers: what to look for ---- */
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->n_c0 = 2;
		out_fmt(o, " " A_ID "[add matcher]" A_OFF);
		v->n_c1 = (int)o->col_hint;
		r++;
	}

	v->row_grp = PR(r);
	for (g = 0; g < v->n_grp && PR_VIS(r + 1); g++) {
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
			char nm[40];

			row_start(o, PR(r), 1);
			/* Until it holds a marker there is nothing to derive a
			 * range from, and naming one anyway claims a search
			 * that has not been described yet. */
			if (grp_count(v, g))
				rng_name_of(cur_obj(v)->fmt, grp_mask(v, g), nm,
					    sizeof nm);
			else
				snprintf(nm, sizeof nm, "-");
			out_fmt(o, "%s %u. " A_OFF "%s%-11s" A_OFF A_DIM
				"  in " A_OFF "%s%-16s" A_OFF,
				g == v->cur_grp ? A_SEL : A_DIM, g + 1u,
				A_WARN, rl, A_LOC, nm);
			if (q->rule == 2)
				out_fmt(o, A_DIM "  threshold " A_OFF A_ID
					">= %u of %u" A_OFF, q->thresh,
					grp_count(v, g));
			out_str(o, A_DIM "  comment " A_OFF);
			v->grp_nt[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s[%s]" A_OFF,
				v->edit == 300 + (int)g ? A_SEL : A_DIM,
				q->note[0] ? q->note : "...");
			v->grp_nt[g][1] = (int)o->col_hint;
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
		out_fmt(o, A_DIM "     markers: " A_OFF);
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
			out_fmt(o, "   " A_ID "[+ string]" A_OFF);
			v->p_c1 = (int)o->col_hint;
		}
		r++;
	}

	/* ---- the conditions: what it means ---- */
	if (PR_VIS(r)) {
		row_start(o, PR(r), 1);
		v->a_c0 = 2;
		out_fmt(o, " %s[add condition]" A_OFF,
			v->n_grp ? A_ID : A_DIM);
		v->a_c1 = (int)o->col_hint;
		v->b_c0 = 2 + (int)o->col_hint;
		/* Names the parent, so the button says what it will do rather
		 * than what it is called. */
		out_fmt(o, "  %s[add inside %u]" A_OFF,
			v->n_cnd ? A_ID : A_DIM, v->cur_cnd + 1u);
		v->b_c1 = (int)o->col_hint;
	}
	r++;

	v->row_cnd = PR(r);
	for (g = 0; g < v->n_cnd; g++) {
		const struct cond *c2 = &v->cnd[g];
		int kids = (int)cnd_children(v, g);

		if (!PR_VIS(r)) {
			v->cnd_mt[g][0] = v->cnd_mt[g][1] = -1;
			r += 2;
			continue;
		}
		row_start(o, PR(r), 1);
		out_fmt(o, "%s%s %u) " A_OFF "%s[%s]" A_OFF,
			c2->parent >= 0 ? "   " : "",
			g == v->cur_cnd ? A_SEL : A_DIM, g + 1u,
			v->edit == 103 + (int)g ? A_SEL : A_ID,
			c2->expr[0] ? c2->expr : "all matchers");
		if (c2->parent >= 0)
			out_fmt(o, A_DIM "  inside %u" A_OFF, c2->parent + 1);
		if (kids)
			out_fmt(o, A_DIM "  gate for %d" A_OFF, kids);
		else {
			out_str(o, A_DIM "  ->  " A_OFF);
			v->cnd_lv[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s%s" A_OFF, c2->level ? A_WARN : A_BAD,
				c2->level ? "SUSPECT" : "INFECT");
			v->cnd_lv[g][1] = (int)o->col_hint;
			out_str(o, A_DIM "  variant " A_OFF);
			v->cnd_vr[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, A_ID "%s" A_OFF,
				c2->var_kind == 2 ? "custom" :
				c2->var_kind == 1 ? "generic" : "auto");
			v->cnd_vr[g][1] = (int)o->col_hint;
			/* Custom is a promise of a name, so the box for it sits
			 * beside the word rather than replacing it - the choice
			 * stays visible while the name is typed. */
			if (c2->var_kind == 2) {
				out_str(o, " ");
				v->cnd_nm[g][0] = 1 + (int)o->col_hint;
				out_fmt(o, "%s[%s]" A_OFF,
					v->edit == 4 + (int)g ? A_SEL : A_WARN,
					c2->variant[0] ? c2->variant
						       : "name...");
				v->cnd_nm[g][1] = (int)o->col_hint;
			} else {
				v->cnd_nm[g][0] = v->cnd_nm[g][1] = -1;
			}
			out_str(o, A_DIM "  comment " A_OFF);
			v->cnd_nt[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "%s[%s]" A_OFF,
				v->edit == 400 + (int)g ? A_SEL : A_DIM,
				c2->note[0] ? c2->note : "...");
			v->cnd_nt[g][1] = (int)o->col_hint;
		}
		out_at(o, PR(r), g_cols - 4);
		out_str(o, A_BAD "[x]" A_OFF);
		r++;

		/*
		 * The matchers this condition is written over, on its own row
		 * with the control that adds one - the same shape a matcher
		 * uses for its markers, because it is the same relationship one
		 * level up. The expression box above stays editable for the
		 * shapes a list cannot express: "(1&2)|3" is not a set.
		 */
		if (!PR_VIS(r)) {
			v->cnd_mt[g][0] = v->cnd_mt[g][1] = -1;
			r++;
			continue;
		}
		row_start(o, PR(r), 1);
		out_fmt(o, A_DIM "     matchers: " A_OFF);
		if (v->n_grp) {
			uint32_t m;
			int first2 = 1;

			for (m = 0; m < v->n_grp; m++) {
				if (!cnd_uses(c2, m))
					continue;
				out_fmt(o, "%s%s%u" A_OFF, first2 ? "" : ", ",
					A_ID, m + 1u);
				first2 = 0;
			}
			if (first2)
				out_str(o, A_DIM "all of them" A_OFF);
		} else {
			out_str(o, A_DIM "none defined yet" A_OFF);
		}
		v->cnd_mt[g][0] = v->cnd_mt[g][1] = -1;
		if (v->n_grp) {
			v->cnd_mt[g][0] = 1 + (int)o->col_hint;
			out_fmt(o, "   " A_ID "[+ matcher]" A_OFF);
			v->cnd_mt[g][1] = (int)o->col_hint;
		}
		r++;
	}
}

static void draw_marker_line(struct out *o, struct view *v)
{
	struct object *ob = cur_obj(v);
	char name[80], head[24], right[120];
	uint32_t hit = 0, i;

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

		snprintf(hits, sizeof hits, "hit %u", hit);
		snprintf(skips, sizeof skips, "skip %u", ob->n_touch - hit);

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
	if (v->sel_a != KOF_BROKEN) {
		uint64_t lo = v->sel_a < v->sel_b ? v->sel_a : v->sel_b;
		uint64_t hi = v->sel_a < v->sel_b ? v->sel_b : v->sel_a;

		/* One offset in front and the other in brackets after it: they
		 * are the same place said twice, not two columns to line up. */
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

	if (right[0]) {
		int at = g_cols - (int)strlen(right) - 1;

		if (at > (int)o->col_hint + 2) {
			out_at(o, mark_row(), at);
			out_fmt(o, "%s%s" A_OFF,
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

/* Copying an offset is copying a number, so it has two spellings and both are
 * worth having: hex to paste back into this tool, decimal for anything that
 * counts bytes. */
static void copy_offset(struct view *v, int hex)
{
	char t[32];

	snprintf(t, sizeof t, hex ? "%llx" : "%llu",
		 (unsigned long long)v->menu_off);
	copy_osc52(t, strlen(t));
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

static uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off);

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

static void redraw(struct view *v)
{
	struct out o = { NULL, 0, 0, 0 };

	term_size();
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

		g_decl_rows = (v->n_decl || v->n_grp || v->n_cnd)
			      ? (int)(want < 12u ? want : 12u) + 1 : 0;
		if (g_decl_rows &&
		    v->prow_off + (uint32_t)(g_decl_rows - 1) > v->n_prow)
			v->prow_off = v->n_prow > (uint32_t)(g_decl_rows - 1)
				      ? v->n_prow - (uint32_t)(g_decl_rows - 1)
				      : 0u;
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
	out_str(&o, "\033[?2026h");
	draw_frame(&o, v);
	draw_tree(&o, v);
	draw_hex(&o, v);
	draw_decl(&o, v);
	draw_marker_line(&o, v);
	if (v->show_list)
		draw_list(&o, v);
	if (v->menu_open)
		draw_menu(&o, v);
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

/* ---- input ---------------------------------------------------------------- */

enum key {
	K_NONE = 0, K_UP = 256, K_DOWN, K_PGUP, K_PGDN, K_HOME, K_END,
	/* Kept contiguous and last: handle() tests the range to let mouse
	 * events past the modes that own the keyboard. */
	K_BACKTAB,
	K_CLICK, K_RCLICK, K_WHEEL_UP, K_WHEEL_DOWN, K_DRAG, K_RELEASE
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
			generate(v);
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
			if (r == want)
				return;         /* the ranges summary */
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
				if (g_mx >= g_cols - 4)
					decl_remove(v, i);
				else if (!v->decl[i].hex && g_mx >= 12 &&
					 g_mx <= 21)
					ch_open(v, CH_WORD, i, g_my, g_mx);
				else if (!v->decl[i].hex && g_mx >= 23 &&
					 g_mx <= 33)
					ch_open(v, CH_CASE, i, g_my, g_mx);
				return;
			}
		}

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
				if (g_mx >= 5 && g_mx <= 16)
					ch_open(v, CH_RULE, g, g_my, g_mx);
				else if (g_mx >= 18 && g_mx <= 33)
					ch_open(v, CH_RANGE, g,
						g_my, g_mx);
				else if (v->grp_nt[g][0] > 0 &&
					 g_mx >= v->grp_nt[g][0] &&
					 g_mx <= v->grp_nt[g][1])
					v->edit = 300 + (int)g;
				else if (g_mx > 35 && v->grp[g].rule == 2)
					ch_open(v, CH_THRESH, g, g_my - 2,
						g_mx);
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

		if (r == want) {
			if (v->n_grp && g_mx >= v->a_c0 && g_mx <= v->a_c1)
				cnd_add(v, 0);
			else if (v->n_cnd && g_mx >= v->b_c0 &&
				 g_mx <= v->b_c1)
				cnd_add(v, 1);
			return;
		}
		r++;

		for (g = 0; g < v->n_cnd; g++) {
			int off = v->cnd[g].parent >= 0 ? 3 : 0;

			if (r + 1 == want) {
				/* The matcher row. Its ids come back out the
				 * way a matcher's markers do - by clicking the
				 * one to remove. */
				v->cur_cnd = g;
				if (v->cnd_mt[g][0] > 0 &&
				    g_mx >= v->cnd_mt[g][0] &&
				    g_mx <= v->cnd_mt[g][1])
					ch_open(v, CH_CMATCH, g, g_my - 3,
						g_mx);
				return;
			}
			if (r != want) {
				r += 2;
				continue;
			}
			r += 2;
			v->cur_cnd = g;
			if (g_mx >= g_cols - 4) {
				cnd_remove(v, g);
				return;
			}
			if (g_mx >= off + 5 && g_mx <= off + 20)
				v->edit = 103 + (int)g;
			else if (g_mx >= v->cnd_lv[g][0] &&
				 g_mx <= v->cnd_lv[g][1])
				ch_open(v, CH_LEVEL, g, g_my, g_mx);
			else if (g_mx >= v->cnd_vr[g][0] &&
				 g_mx <= v->cnd_vr[g][1])
				ch_open(v, CH_VARIANT, g, g_my, g_mx);
			else if (v->cnd_nm[g][0] > 0 &&
				 g_mx >= v->cnd_nm[g][0] &&
				 g_mx <= v->cnd_nm[g][1])
				v->edit = 4 + (int)g;
			else if (v->cnd_nt[g][0] > 0 &&
				 g_mx >= v->cnd_nt[g][0] &&
				 g_mx <= v->cnd_nt[g][1])
				v->edit = 400 + (int)g;
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

		if (v->edit == 1) {
			buf = v->family;
			cap = sizeof v->family;
		} else if (v->edit >= 400) {
			buf = v->cnd[(v->edit - 400) % MAX_GROUP].note;
			cap = sizeof v->cnd[0].note;
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

		if (k == 27 || k == '\r' || k == '\n') {
			v->edit = 0;
		} else if (k == 127 || k == 8) {
			if (n)
				buf[n - 1u] = 0;
		} else if (k >= 0x20 && k < 0x7f && n + 2u < cap) {
			buf[n] = (char)k;
			buf[n + 1u] = 0;
		}
		return 1;
		}
	}

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
	}
	free(v->ext);
}

int main(int argc, char **argv)
{
	const char *path = NULL, *db = NULL, *base = "kofdraft";
	kof_engine *eng = NULL;
	struct view v;
	struct stat st;
	int fd, i, rc = 0;

	memset(&v, 0, sizeof v);
	v.sel_a = v.sel_b = KOF_BROKEN;

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

	if (!term_setup()) {
		rc = 1;
		goto out;
	}
	redraw(&v);
	for (;;) {
		int k = read_key();

		if (k == K_NONE)
			break;
		if (!handle(&v, k))
			break;
		/* redraw decides for itself whether anything changed. */
		redraw(&v);
	}
	term_restore();

out:
	view_free(&v);
	kof_unmap_file(v.map, v.map_len);
	kof_engine_close(eng);
	return rc;
}
