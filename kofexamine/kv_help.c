#define _GNU_SOURCE
#include "kv.h"


/*
 * WHICH SHELF A FORMAT BELONGS ON.
 *
 * Grouped rather than listed, because a flat run of eleven names says only
 * that there are eleven; grouped it says what KIND of thing this build can
 * open, which is the question somebody reading an About box actually has.
 *
 * The groups are here and the members are not: a format added to the engine
 * still appears without anyone remembering to, because the list comes from
 * kof_parser_list. A format nobody classified lands in "Other", which is
 * visible and harmless - the alternative, dropping it, would make the box
 * quietly lie about what the binary can read.
 */
/*
 * WHICH SHELF, and the MEMBERS come from the engine.
 *
 * This was a second list of formats per shelf, written out here - the same
 * hand copy the format menu had, with the same failure: a format added to the
 * engine stayed off the shelf it belonged on until somebody remembered this
 * function. What is peculiar to this box is the ORDER of the shelves and how
 * many there are; which formats are on one is kof_format_group's answer.
 */
/*
 * WHICH ROW OF THE ABOUT BOX A FORMAT BELONGS ON.
 *
 * NOT the engine's own grouping, and deliberately so: kof_format_group says
 * what a format IS to the parser, and this says what a reader is looking for
 * when they scan the list. The two agree about executables, documents and
 * archives and part company over the rest.
 *
 * SCRIPT IS ITS OWN ROW, beside Document and Archive rather than swept into
 * "Other" with the media types. It is a whole side of this engine - a
 * sub-typed format with its own region model - and a box that listed PDF and
 * RAR by name while filing every scripting language under "other" understated
 * what the build can open.
 *
 * REG AND AMSI SIT WITH IT. To the parser a .reg file is text and an AMSI
 * buffer is an event, which is right for routing and unhelpful here: both
 * carry a script, and somebody asking "can this look at PowerShell" wants to
 * find them next to it.
 *
 * LNK DOES NOT. The parser files it under script because what is worth reading
 * in a shortcut is the command line it carries, which is the same job - but a
 * .lnk is a binary structure of its own and nothing in it is a script the way
 * a .ps1 or a .reg is. On a row that then lists PowerShell and Batch beneath
 * it, it would be read as a scripting language.
 *
 * PROCESS IS NOT ON ANY ROW. KOF_EVT_PROC is a live process the scanner is
 * asked about - see --scan-procs - and not a format a file can be opened as.
 * Listed among the file formats it reads as one, and there is no file a reader
 * could bring here to try it.
 */
#define ABOUT_ROW_DROP (-1)

/* The box lost its Project rows the moment the format list grew a row and the
 * script sub-types under it - abt() drops what does not fit, silently. */
#define ABOUT_MAX  48
#define ABOUT_W    200


/*
 * How wide a line is on the screen, which is not how long it is in memory.
 *
 * Two things make those differ. The lines carry their own colours, so strlen
 * counts escape bytes the terminal never draws. And a glyph outside ASCII is
 * several bytes and still one column: About's bullets are three bytes each, so
 * counting bytes measured those lines two columns too wide, page_draw sized the
 * box from the widest line, and the lines holding a bullet were the ones whose
 * right border came up short of the rest.
 *
 * Single-width glyphs only. A double-width one would need a width table, and a
 * freestanding tool has none to consult - the glyphs this program draws are its
 * own choice, so the restriction is on the choosing.
 */
int vis_cols(const char *s)
{
	int n = 0;

	while (*s) {
		if (*s == '\033') {
			while (*s && *s != 'm')
				s++;
			if (*s)
				s++;
			continue;
		}
		if (((unsigned char)*s & 0xc0u) != 0x80u)
			n++;      /* a continuation byte is already counted */
		s++;
	}
	return n;
}
static int fmt_group(uint8_t f)
{
	if (f == KOF_EVT_PROC)
		return ABOUT_ROW_DROP;
	if (f == KOF_FMT_REG || f == KOF_EVT_AMSI)
		return 1;
	if (f == KOF_FMT_LNK)
		return 4;
	switch (kof_format_group(f)) {
	case KOF_FGRP_EXEC:    return 0;
	case KOF_FGRP_SCRIPT:  return 1;
	case KOF_FGRP_DOC:     return 2;
	case KOF_FGRP_ARCHIVE: return 3;
	default:               return 4;
	}
}

/* See the note in the loop that reads it: a format the engine reports without
 * a collector of its own. */
static const uint8_t about_extra[] = { KOF_FMT_DOCZIP };

static struct prop_line g_about[ABOUT_MAX];
static uint32_t g_n_about;

static void abt(const char *fmt, ...)
{
	va_list ap;

	if (g_n_about >= ABOUT_MAX)
		return;
	va_start(ap, fmt);
	vsnprintf(g_about[g_n_about].text, ABOUT_W, fmt, ap);
	va_end(ap);
	g_n_about++;
}

/*
 * The About page, built rather than written out.
 *
 * Three of the four blocks are facts about what is loaded right now - the
 * engine that is linked, the database that was found beside it, the formats
 * this build can parse - and a literal would be a fourth place for them to be
 * wrong. Only the two sentences at the top are prose, and they say what the
 * tool is FOR: reading a file the way the engine reads it.
 *
 * A SECTION TITLE AND A FIELD NAME ARE COLOURED; A VALUE IS NOT. The eye needs
 * help finding the block it wants, not help reading a number once it is there
 * - and a number in colour reads as a warning in a program where colour
 * already means something on every other screen.
 */
static void about_build(struct view *v)
{
	struct kof_version ev;
	struct kof_db_version dv;
	const struct kof_parser *fmts;
	uint32_t nf = 0, k;
	int g;
	static const char *const gname[5] = {
		"Executable", "Script", "Document", "Archive", "Other"
	};

	g_n_about = 0;

	/*
	 * What it is, then what it does, then the one thing the screen behind
	 * this box cannot say.
	 *
	 * The first line is how somebody would describe the program to a
	 * colleague. The list after it is what the panes are FOR, in one line
	 * each - a reader who has just opened the tool can see the bytes, the
	 * disassembly and the tree, but not what any of them are offered for,
	 * and an About that names them is shorter than finding out by clicking.
	 */
	abt(A_BOLD "KOFViewer" A_OFF "  -  a TUI file examiner built on the KOF"
	    " engine.");
	abt("");
	abt("  " A_DIM "-" A_OFF " a hex view of any region, with the"
	    " strings a draft declares");
	abt("    lit where they sit");
	abt("  " A_DIM "-" A_OFF " disassembly beside it, and which"
	    " code refers to which data");
	abt("  " A_DIM "-" A_OFF " the file's structure as the engine"
	    " parsed it - headers,");
	abt("    sections, regions, symbols");
	abt("  " A_DIM "-" A_OFF " the unpackers, so a packed or"
	    " archived payload is examined");
	abt("    as an object of its own");
	abt("  " A_DIM "-" A_OFF " a diagnose draft, from marked bytes to a"
	    " preview of its conditions");
	abt("");

	abt(A_ID "Versions" A_OFF);
	/*
	 * BUILT AGAINST, AND LOADED - shown apart only when they differ.
	 *
	 * The macros are what this file compiled against; the call is what the
	 * library actually is. Linked statically they cannot disagree, so
	 * saying both would be two identical numbers and a reader learning to
	 * skip the line. The day libkofeng is a shared object they can, and
	 * then the disagreement IS the bug being reported.
	 *
	 * MAJOR AND MINOR ONLY. The build stamps are expected to differ: the
	 * engine and this tool can be built - and shipped - at different times.
	 * The INTERFACE is major.minor, so that is what a mismatch is.
	 */
	keng_version(&ev);
	if (ev.major == KOFENG_MAJOR && ev.minor == KOFENG_MINOR)
		abt("  " A_DIM "Engine     " A_OFF " %u.%u   build %u",
		    (unsigned)ev.major, (unsigned)ev.minor, ev.build);
	else
		abt("  " A_DIM "Engine     " A_OFF " %u.%u   build %u   "
		    A_WARN "(this tool was built against %u.%u)" A_OFF,
		    (unsigned)ev.major, (unsigned)ev.minor, ev.build,
		    (unsigned)KOFENG_MAJOR, (unsigned)KOFENG_MINOR);
	if (v->eng && kdb_version(v->eng, &dv))
		abt("  " A_DIM "Database   " A_OFF " %u.%u   build %u",
		    (unsigned)dv.major, (unsigned)dv.minor, dv.build);
	else
		abt("  " A_DIM "Database   " A_OFF " " A_WARN "none loaded" A_OFF);
	abt("  " A_DIM "Module ABI " A_OFF " %u", (unsigned)KOFSIG_ABI_VERSION);
	abt("");

	/*
	 * TWO KINDS OF RECORD, TWO ROWS: a diagnose names a behaviour, an
	 * unpacker produces objects. Separate rows are what let a zero stand
	 * out, and a database with no unpackers is worth noticing.
	 */
	abt(A_ID "Database" A_OFF);
	if (v->eng) {
		abt("  " A_DIM "Diagnoses  " A_OFF " %u",
		    kdb_diagnoses(v->eng));
		abt("  " A_DIM "Unpackers  " A_OFF " %u",
		    kdb_unpackers(v->eng));
	} else {
		abt("  " A_DIM "Diagnoses  " A_OFF " " A_WARN "none loaded" A_OFF);
	}
	abt("");

	abt(A_ID "File formats" A_OFF);
	fmts = kof_parser_list(&nf);
	for (g = 0; g < 5; g++) {
		char row[ABOUT_W];
		uint32_t at = 0;
		int any = 0;

		row[0] = 0;
		for (k = 0; k < nf; k++) {
			if (fmt_group(fmts[k].format) != g)
				continue;
			/* KOF_FMT_SCRIPT is what a script whose language was
			 * not recognised is, and the row it would sit on is
			 * already called Script. Naming it again says the word
			 * twice and nothing else; the languages under the row
			 * are what there is to read. */
			if (fmts[k].format == KOF_FMT_SCRIPT)
				continue;
			any = 1;
			if (at + 1u >= sizeof row)
				break;
			at += (uint32_t)snprintf(row + at, sizeof row - at,
						 " %s",
						 kof_format_name(fmts[k].format));
		}
		/*
		 * AND THE FORMATS THAT ARE REPORTED WITHOUT BEING PARSERS.
		 *
		 * kof_parser_list is the collectors, and one format this build
		 * opens is not one of them: zip_parse decides from the entry
		 * names whether what it has is an ordinary archive or an Office
		 * document, so DocZip has an enum value and a name and no
		 * collector of its own. Left to the parser list alone the box
		 * said nothing about it, which reads as a format this build
		 * cannot open.
		 */
		for (k = 0; k < sizeof about_extra / sizeof about_extra[0]; k++) {
			if (fmt_group(about_extra[k]) != g)
				continue;
			any = 1;
			if (at + 1u >= sizeof row)
				break;
			at += (uint32_t)snprintf(row + at, sizeof row - at,
						 " %s",
						 kof_format_name(about_extra[k]));
		}
		if (!any)
			continue;
		abt("  " A_DIM "%-11s" A_OFF "%s", gname[g], row);
		/*
		 * AND WHICH LANGUAGES, under the Script row.
		 *
		 * "Script" alone is the one row of this list that says nothing
		 * useful: every other name on the page is a format a reader
		 * recognises, and this one is a category. What they want to
		 * know is whether the build knows PowerShell from Batch - and
		 * it does, because a signature can target one - so the sub-
		 * types are named rather than left to be discovered by opening
		 * a file and reading the header pane.
		 *
		 * KOF_SCRIPT_ANY is left out: it is what a script that matched
		 * no language is, not a language.
		 *
		 * Wrapped by hand at the width the box has, because prop_line
		 * does not wrap and a row past the edge is a row nobody reads.
		 */
		if (g == 1) {
			char sub[ABOUT_W];
			uint32_t sat = 0, t;

			sub[0] = 0;
			for (t = KOF_SCRIPT_ANY + 1u;
			     t < (uint32_t)KOF_SCRIPT_TYPE_COUNT; t++) {
				const char *nm = kof_script_type_name((uint8_t)t);
				uint32_t w = (uint32_t)strlen(nm);

				/* Past the width, so this line is emitted and
				 * the next one starts under the same column. */
				if (sat && sat + w + 1u > 47u) {
					/* The leading space the format rows
					 * get from their own " %s" - without
					 * it these sit a column left of the
					 * names they continue. */
					abt("  " A_DIM "%-11s" A_OFF " %s",
					    "", sub);
					sat = 0;
					sub[0] = 0;
				}
				sat += (uint32_t)snprintf(sub + sat,
							  sizeof sub - sat,
							  "%s%s",
							  sat ? " " : "", nm);
			}
			if (sat)
				abt("  " A_DIM "%-11s" A_OFF " %s", "", sub);
		}
	}
	abt("");
	abt(A_ID "Project" A_OFF);
	abt("  " A_DIM "Author       " A_OFF " DmKnght");
	abt("  " A_DIM "License      " A_OFF " MIT");
}

/*
 * The two Help dialogs, over the same page renderer the properties page uses.
 *
 * They differ from it in three flags and in what they list. That was not true a
 * short while ago: About had its own box, its own scroll clamp, its own close
 * button and its own idea of what a click on one meant, and got the last of
 * those wrong on the first attempt because it was the second copy of code that
 * already worked elsewhere.
 */
void draw_help(struct out *o, struct view *v)
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
		"Ctrl+]     previous file",   "Ctrl+\\     next file",
		/*
		 * TAB AND "m" ARE GONE FROM HERE BECAUSE THEY ARE GONE.
		 *
		 * Tab moved the focus between panes and "m" opened the marker
		 * list, both from before this had a mouse. Every bare character
		 * binding was taken out - see the note in handle() - so a page
		 * still listing them would be teaching a key that does nothing,
		 * which is worse than listing nothing at all. The marker list
		 * is the words on the marker line; the panes take a click.
		 */
		"Ctrl+Space read as text or as hex"
	};
	static struct prop_line g_keys[sizeof keys / sizeof keys[0]];
	struct page pg;
	uint32_t i;

	/*
	 * ONE STANDARD, BOTH DIALOGS.
	 *
	 * Keyboard used to close on any key and any click, which was defensible
	 * while it was a fixed cheat sheet drawn by its own code. It is neither
	 * now: it scrolls when the terminal is short, and it is drawn by the
	 * same renderer as everything else. A box that answers the wheel and
	 * also vanishes on the click that starts a drag cannot be read to the
	 * end - so it closes the way every other box here closes.
	 */
	memset(&pg, 0, sizeof pg);
	if (v->help_open == 1) {
		for (i = 0; i < sizeof keys / sizeof keys[0]; i++)
			snprintf(g_keys[i].text, PROP_W, "%s", keys[i]);
		pg.title = "Keyboard";
		pg.line = g_keys;
		pg.n = (uint32_t)(sizeof keys / sizeof keys[0]);
		pg.off = (uint32_t *)&v->help_off;
		pg.close = 1;
		pg.record = 1;
		pg.foot = " Esc closes ";
	} else {
		about_build(v);
		pg.title = "About";
		pg.line = g_about;
		pg.n = g_n_about;
		pg.off = (uint32_t *)&v->help_off;
		pg.close = 1;
		pg.record = 1;
		pg.foot = " Esc closes ";
	}
	page_draw(o, v, &pg);
	v->help_btn_y = pg.btn_y;
	v->help_btn_x0 = pg.btn_x0;
	v->help_btn_x1 = pg.btn_x1;
}
