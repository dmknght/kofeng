#define _GNU_SOURCE

/*
 * kofexaminer_out.c - the examiner's output basics: the colour roles, the state
 * the printers read (the parent format), and the line printers every format's
 * printer uses (offsets, permissions, types, notes). Split from kofexaminer.c by
 * job, no logic changed.
 */

#include "kofexaminer_private.h"


/*
 * What one format offers a tool: how to recognise it, how to parse it, how big
 * its view is, and the names of the things it can report.
 *
 * No name field: the parse sets ctx->format and kof_format_name turns that into
 * one, so a second copy here would be a second thing that could disagree.
 *
 * The same shape as the scanner's parser table and for the same reason - adding a
 * format should be a row, not an edit spread over every consumer.
 */
/* ---- colour ----------------------------------------------------------------
 *
 * Four roles and nothing else, because colour that does not answer a question is
 * noise that makes the colour which does answer one harder to see. Numbers and
 * offsets are deliberately left plain: they are most of the screen, and colouring
 * them would drown the handful of places where a colour means something.
 *
 *   name   the object being described - bold, so a run over a directory can be
 *          scrolled and the boundaries found without reading
 *   bad    something is wrong with the file: an anomaly, a name that escapes its
 *          root, a checksum that disagrees, a region sum that does not add up
 *   warn   something is unusual but not wrong: an encrypted entry, a declared
 *          expansion that is large rather than absurd, a count that does not
 *          match its claim
 *   note   a fact worth finding, carrying no judgement: a container kind
 *   dim    what is almost always uninteresting
 *
 * Off unless stdout is a terminal, and off when NO_COLOR is set whatever the
 * terminal is: this tool's output is piped into grep and diffed against itself,
 * and escape sequences in either is a bug rather than a preference.
 */
/*
 * The format of the object most recently described.
 *
 * Read when a recovered object is announced, to say whether what produced it was
 * a packer or an opener - and the two are not the same news. A zip yielding its
 * entries is a zip doing its job; an ELF that had to be unpacked before anything
 * could be read is a packed executable, which is worth looking at whatever came
 * out of it.
 *
 * The engine cannot answer this - decomp and unp modules compile to one pack
 * kind and it does not tell them apart, which the Makefile says in as many words
 * - so it is derived from the object rather than asked of the module. And it is
 * the PARENT's format that decides, which is what this holds: a recovered object
 * is announced before it is itself examined, so at that moment this is still the
 * format of the thing it came out of.
 */
uint8_t kex_g_parent_format;

const char *kex_C_OFF  = "";
const char *kex_C_NAME = "";
const char *kex_C_BAD  = "";
const char *kex_C_WARN = "";
const char *kex_C_NOTE = "";
const char *kex_C_DIM  = "";

/*
 * The second axis: what KIND of value this is, rather than whether it is trouble.
 *
 * Deliberately drawn from the colours the trouble scale does not use, so the two
 * never have to be told apart by context. A blue number is a number; a red one is
 * a number somebody should look at. Three kinds is all a dump of this shape has:
 *
 *   id     what a thing IS   - class, region and section names, pattern kind
 *   loc    WHERE it is       - file offsets, virtual addresses, hit positions.
 *          Cyan, the same ink the trouble scale uses for a fact carrying no
 *          judgement, because an offset is exactly that. The two never appear in
 *          one column, so sharing an ink costs nothing and keeps the palette at
 *          the number of things a reader can actually hold.
 *   size   HOW MUCH of it    - lengths, byte counts
 *
 * The split is worth the colour because the columns interleave: "off=3316
 * size=0 vaddr=0x128cf4" is three different questions in one line, and reading
 * which is which is most of the work of reading the line.
 */
const char *kex_C_ID   = "";
const char *kex_C_LOC  = "";
const char *kex_C_SIZE = "";

int kex_stdout_is_tty(void)
{
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(1);
#endif
}

void kex_colour_enable(int on)
{
	if (!on)
		return;
#ifdef _WIN32
	/* A Windows console does not interpret escape sequences until asked, and
	 * asking fails on the consoles that never will - so a failure here is a
	 * console without colour rather than an error. */
	{
		HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD m = 0;

		if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &m) ||
		    !SetConsoleMode(h, m | 0x0004u))
			return;
	}
#endif
	kex_C_OFF  = "\033[0m";
	kex_C_NAME = "\033[1m";
	kex_C_BAD  = "\033[31m";
	kex_C_WARN = "\033[33m";
	kex_C_NOTE = "\033[36m";
	/* Bright black rather than SGR 2: "faint" is optional and a fair number
	 * of terminals ignore it, which would silently lose the one distinction
	 * an absent marker has. Grey is a colour and every terminal has it. */
	kex_C_DIM  = "\033[90m";
	kex_C_ID   = "\033[34m";
	kex_C_LOC  = "\033[36m";
	kex_C_SIZE = "\033[32m";
}

/* The two notes every parser prints, so a call site says which it is rather than
 * spelling an escape twice. */
void kex_note_bad(const char *what)
{
	printf("%s   <- %s%s", kex_C_BAD, what, kex_C_OFF);
}

void kex_note_warn(const char *what)
{
	printf("%s   <- %s%s", kex_C_WARN, what, kex_C_OFF);
}

void kex_note_note(const char *what)
{
	printf("%s   <- %s%s", kex_C_NOTE, what, kex_C_OFF);
}

/* "n of m declared", where a disagreement is the thing worth seeing. */
void kex_print_claimed(const char *label, uint32_t have, uint32_t claimed)
{
	if (have == claimed)
		printf("  %-9s %u of %u declared\n", label, have, claimed);
	else
		printf("  %-9s %s%u of %u%s declared\n", label, kex_C_WARN, have,
		       claimed, kex_C_OFF);
}


/* In the order everyone writes them, not the order the bits happen to sit in. */











/* An offset that could not be resolved prints as what it is, not as a number
 * that would be mistaken for one. */
void kex_put_off(const char *label, uint64_t v)
{
	/* "unresolved" is not a value, it is a parse that applies here and could
	 * not finish - the one case on this line worth a second look. */
	if (v == KGENOME_NA)
		printf("%s=%sn/a%s", label, kex_C_DIM, kex_C_OFF);
	else if (v == KGENOME_BROKEN)
		printf("%s=%sunresolved%s", label, kex_C_WARN, kex_C_OFF);
	else
		printf("%s=%s%llu%s", label, kex_C_LOC, (unsigned long long)v,
		       kex_C_OFF);
}

void kex_put_perm(uint32_t p)
{
	/* Writable and executable at once is the one combination on this line
	 * worth seeing from across the room: nothing a compiler emits needs it. */
	const char *c = ((p & 2) && (p & 1)) ? kex_C_BAD : kex_C_ID;

	printf("%s%c%c%c%s", c, (p & 4) ? 'R' : '-', (p & 2) ? 'W' : '-',
	       (p & 1) ? 'X' : '-', kex_C_OFF);
}

/*
 * A segment or section type as the word people write, not the number.
 *
 * Same argument the format line already makes with ET_EXEC against type=2: a
 * reader who knows what PT_GNU_STACK is cannot get that from 1685382481, and a
 * reader who does not is no worse off. Colour was the other option and would not
 * have helped - the problem is not that the number is hard to find on the line.
 *
 * Written here rather than in elf.h because it is a spelling for people. The
 * parser has no use for it and a module cannot print.
 *
 * Unknown values fall back to the number, which is the case the table exists to
 * make rare rather than to hide: an arch-specific type is a real thing to meet
 * and PT_ARM_EXIDX and PT_MIPS_REGINFO are the same number, so naming one would
 * be wrong half the time.
 */
/* The name when there is one, the number when there is not, colour either way -
 * both answer the same question and the column should not change meaning. */
void kex_put_type(const char *(*name)(uint32_t), uint32_t t, int width)
{
	const char *w = name(t);
	char num[24];

	if (!w) {
		snprintf(num, sizeof num, "%u", t);
		w = num;
	}
	printf("%s%-*s%s", kex_C_ID, width, w, kex_C_OFF);
}

