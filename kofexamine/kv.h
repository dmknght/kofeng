/*
 * kv.h - the one interface between the translation units of kofviewer.
 *
 * kofviewer used to be one 32,000 line file. It is the same program in the same
 * order of functions, cut along the lines below; nothing was rewritten to make
 * the cut. This header holds what the pieces share: the types (struct view is
 * the whole state of a session), the macros, the prototypes of the functions
 * that more than one unit calls, and the few globals that more than one unit
 * touches. A function used by a single unit is `static` in it and is not here.
 *
 *   kv_main        command line, opening a file or a pid, closing, main()
 *   kv_events      the event loop's handlers: handle(), mouse drag/release/wheel
 *   kv_keys        per-modal key handlers (field, bar, chooser, symbols, ...)
 *   kv_click       click dispatch: every pane's click, the hit table
 *   kv_input       terminal input: keys, mouse reports, bracketed paste
 *   kv_screen      redraw(): the frame, in layer order
 *   kv_view        the pane model: which object/region/bytes a pane shows
 *   kv_collect     objects: the scan callback, process snapshot, object table
 *   kv_tree        the tree: rows, labels, the log window
 *   kv_tree_draw   painting the tree pane and the frame
 *   kv_hex         the hex pane
 *   kv_text        the text pane, symbol cell strings
 *   kv_hit         what a byte under the cursor is (declared)
 *   kv_disasm      the disassembler panel
 *   kv_evt         the event-log view (load, boxes, the event panel)
 *   kv_decl        the draft panel: head, strings, matchers, conditions, blocks
 *   kv_marker      the status line
 *   kv_mutation    mutation blocks: segment, mark, rescore
 *   kv_draft       draft lifecycle: wipe
 *   kv_declact     adding a declaration from a selection
 *   kv_chooser     the chooser popup (every pick-one list)
 *   kv_field       text fields and the panel rows around them
 *   kv_menu        the context menus and menu_run
 *   kv_bar         the menu bar: items, enabled/shown rules, run
 *   kv_clip        copy and paste
 *   kv_find        Find
 *   kv_dialogs     the framed dialogs: Decoder, Goto, Find
 *   kv_symd        the Symbols dialog
 *   kv_props       the properties page's rows (per format)
 *   kv_page        the page layer (properties/help) drawing
 *   kv_help        the About / help text
 *   kv_actions     actions that reopen or rescan: emulate, dump, step file, rebuild
 *   kv_paint       colours and glyphs
 *   kv_state       the shared globals
 */
#ifndef KV_H
#define KV_H

/*
 * kofviewer - the engine's view of a file, navigable.
 *
 *   kofviewer [--db <dir>] [--sources <dir>] <file|folder>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <pwd.h>
#endif
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/wait.h>
#endif
#include "kofplat.h"
#include <sys/stat.h>
#include <errno.h>

#include <kofeng.h>
#include "../libkofeng/kofcore/kofplatform.h"
#include <kofcore.h>
#include <kofmod/kofsig.h>
#include <kofmod/kofsym.h>
#include "../libkofeng/analyzers/parsers/binaries/elf/elf_sym.h"
#include "../libkofeng/detectors/linkage/kofdiag.h"
#include "../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"
#include <kofmod/elf.h>
#include <kofmod/pe.h>
#include <kofmod/script.h>
/* kof_parser_of: the region NAMES are per format, and a multi-format draft has
 * to be able to ask each of its formats what a region bit means there. */
#include "../libkofeng/analyzers/parsers/kofformat.h"

#include "kofevtfmt.h"
#include "kofevtlog.h"
#include "kofinspect.h"
#include "codec_ui.h"
#include <kofmod/kofmutation.h>
#include "kofview.h"
#include <celllysis/trueline.h>
#include "../libkofeng/kofcore/rangelist.h"
#include "kofwalk.h"
#include "kofproc.h"
#include <kofmod/proc.h>
/* The two targets a collected record can BE - see evt_decl_target. */
#include <kofmod/amsi.h>
#include "kofeditor.h"

/* The disassembler the emulator already carries: the viewer links the same
 * library, so this costs an include path and nothing else. */
#include <x86/x86.h>
#include "../libkofeng/detectors/heur/kofheur.h"
#include "../libkofeng/scanners/scan.h"
#include "../libkofeng/scanners/objsrc.h"
#include <phenotype/emu_unpack.h>
#include "../libkofeng/detectors/pattern/kofmatch.h"
#include "../libkofeng/databases/pack/hexprog.h"
#include "../libkofeng/analyzers/genome_obj.h"
#include "../libkofeng/databases/pack/dbcore.h"
#include "../libkofeng/databases/dbloader.h"



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
#define A_HIT1  "\033[41;97m"   /* a row that has a verdict */
/*
 * A string the draft itself declares, lit where it sits in the object.
 *
 * A different colour from the database's markers on purpose: one is what the
 * engine already knows, the other is what this draft is claiming, and the whole
 * job of the pane is telling those two apart.
 */
#define A_HIT3  "\033[45;97m"

/*
 * THE MUTATION PALETTE: one colour per highlighted block, cycled.
 *
 * Five, and dim rather than bright. A block is up to a few kilobytes, so a lit
 * one fills screens of hex - a saturated background over that much text is
 * unreadable and hurts to look at, which is the opposite of what a highlight is
 * for. These sit far enough apart to tell two blocks apart and close enough to
 * the page that the bytes stay legible.
 *
 * Cycled by INDEX, so two blocks share a colour only when five lie between
 * them. Adjacent blocks - the ones a reader is comparing - never collide, which
 * is the only case where a repeat would mislead.
 *
 * The same string is used in two places that must agree: the hex pane paints
 * with it, and the block table draws its swatch with it. One array, so they
 * cannot drift.
 */
#define MTN_COLOURS 5


#define TREE_W   31

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
/* "[ Discard ]" with a space in front, so the note box can leave room. */
#define NEW_BTN_W 12
/*
 * AND THE LAST COLUMN IS NOT THEIRS.
 *
 * Every row of the panel below this one ends in the divider the scrollbar is
 * drawn on - see draw_decl - and the head row was laid out from g_cols as
 * though it did not exist, so the closing bracket of Discard was painted on
 * top of it. One column, and the border was broken on exactly the row a reader
 * looks at first.
 */
#define HEAD_RMARGIN 1

/*
 * THE HEADING ROW IS LAID OUT AGAINST FIXED MARKS, NOT AGAINST THE CURSOR.
 *
 * Every box on it used to be as wide as its contents and every box after it
 * started wherever the last one stopped, so the row rearranged itself as the
 * draft was typed into - and clicking a field, which widened it, shoved
 * everything to its right along with it. On a narrow terminal that pushed the
 * Generate button off the end of the row entirely.
 *
 * So: the fields are a fixed width, the buttons are anchored to the RIGHT edge,
 * and the comment takes exactly the gap between them. Nothing on the row moves
 * unless the terminal is resized.
 */
/*
 * The family box, focused or not - and the width the row RESERVES for it,
 * which is what puts the comment box where it sits.
 *
 * Twenty-four was two family names wide. "mirai", "Meterp", "CoinMiner" are
 * what goes in it, so the row carried a dozen blank columns between the name
 * and the comment and the two read as unrelated halves of the row. Fourteen
 * still holds every family name in the tree without scrolling and puts the
 * comment beside the thing it is a comment about.
 */
#define FAM_W     14
#define NOTE_W    40    /* the comment box - a remark, not a paragraph */
#define GEN_BTN_W 12    /* "[ Generate ]" */
/*
 * Where the string editor's codes live in view.edit.
 *
 * One code per declaration, in a band of its own well clear of every other
 * field's. The bands below it are 1, 103+i, 200+i, 300+i, 400+i, 500 and
 * 501, and each is tested as a band rather than as "at least" - a rule this
 * file learned the hard way when the size editor claimed everything from 200
 * up and swallowed the boxes added above it.
 */
/* One edit target per block row, so the caret knows which threshold it is in.
 * Above ED_STR's range, which is per declared string. */
#define ED_GRP_PCT 700
#define ED_STR    600
/* One per matcher, for the step of an AT place - see grp_of. Above ED_GRP_PCT
 * and tested as a band, like every other one. */
#define ED_AT_OFF 800
/*
 * The symbol dialog's filter field. A band of one, well clear of ED_AT_OFF's -
 * every other code here is tested as a band for the reason the note above
 * gives, and a single code that sat inside somebody else's range would be the
 * same fault in a smaller place.
 */
#define ED_SYMFILT 900
/*
 * The tag sources' text boxes: the table's search, a form's name and comment,
 * the chooser's search. A band of four above every other, tested as codes.
 */
#define ED_SYN_SEARCH  1000
#define ED_SYN_NAME    1001
#define ED_SYN_COMMENT 1002
#define ED_SYN_PICK    1003

/* Every row the draft panel can ever hold, spelled from the limits rather than
 * counted once: the panel grew three kinds of row after this array was sized,
 * and a table that silently stops short is a panel whose bottom cannot be
 * scrolled to. */
/* The condition rows are the last term, and a condition became THREE rows -
 * matchers, verdict, variant - plus its JOIN and its ADD. Spelled from the
 * limits for the reason the note above gives: a table that silently stops short
 * is a panel whose bottom cannot be scrolled to. */
/* THE TABLES, which were not counted at all: the block table (a block per row,
 * and a function is a block now - MTN_MAX_BLOCK) and the diagnose table. The array stopped at a hundred rows, so a file with more
 * functions than that showed the first hundred and its panel could not be
 * scrolled to the rest - which is exactly the failure the note above is about. */
#define MAX_PROW  (OPT_COUNT + 1 + 2 + MAX_DECL + 2 + 2 * MAX_GROUP + 2 + \
		   6 * MAX_GROUP + 2 + MTN_MAX_BLOCK + 2 + \
		   KOF_DB_MAX_DIAG + 2)

/*
 * How much encoded text the decoder will hold.
 *
 * A base64 payload out of a dropper is a few hundred bytes; this is past every
 * one measured and still a field a terminal can scroll through without the
 * caret arithmetic becoming the slow part.
 */
#define ENC_IN_MAX 8192u

/*
 * THE CODINGS THE STRING BOX OFFERS - enum kof_codec, in kofinspect.h.
 *
 * The list, the names and both directions live there, because a coding is bytes
 * in and bytes out: it has no terminal in it and nothing about it is this
 * panel's. What is here is the FORM - a field, a chooser, a button and where
 * the answer is drawn.
 */

/* The two text fields, by the edit id the rest of this file uses for focus. */
#define ED_ENC_IN  540
#define ED_ENC_KEY 541

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

/*
 * ONE PALETTE FOR EVERY POPUP - the menu bar's, which is the darker one.
 *
 * The choosers and the right-click menu were drawn on white (47), the bar on
 * bright black (100). Side by side on a dark terminal the white ones glare,
 * and two panels that do the same job should not look like two different
 * programs. Defined here rather than beside the bar because the popups are
 * drawn first and a define is only visible below itself.
 */
#define BAR_ON   "\033[100;97m"    /* an item that can be used */
#define BAR_OFF  "\033[100;37m"    /* the same panel, dimmer text */
#define BAR_CUR  "\033[107;30m"    /* the row under the cursor */

/*
 * The widest a list may get. It is a CAP, not the width: the drawn width is
 * chooser.w, measured from the longest row, so a list of "ELF / PE / MachO"
 * is three columns wider than "MachO" rather than thirty-eight wide with
 * thirty columns of empty highlight after it.
 */
#define CH_W     38
#define CH_W_MIN 12

enum ch_what {
	CH_NONE = 0,
	CH_RULE,        /* find_str or find_at, for a string matcher */
	/*
	 * WHICH OCCURRENCE an AT matcher compares at.
	 *
	 * The marker already knows every place it appears - decl.hits, built by
	 * decl_locate - so the offset is CHOSEN from that list rather than
	 * typed. A number typed by hand is a number that can be wrong in a way
	 * nothing checks; every row here is a place the bytes really are.
	 */
	CH_ATOFF,
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
	CH_ENC_TYPE,    /* which coding the decoder should apply */
	CH_FMT,         /* what to do with one target format - by KIND */
	CH_FMT_SW,      /* which format of that kind to switch to */
	CH_FMT_SW_LANG, /* which language to switch to - a script and its subtype */
	CH_FMT_CAT,     /* which KIND of format - the first half of adding one */
	CH_FMT_ADD,     /* which format of that kind */
	CH_FMT_LANG,    /* which scripting language - format and subtype at once */
	CH_RANGE_EXT,   /* which region to extend the subject range with */
	CH_RANGE_DROP,  /* which region to drop off the subject range */
	CH_TYPE,        /* enum kof_maltype */
	CH_MARKER,      /* which unused marker to put in a matcher */
	CH_THRESH,      /* how many of the matcher's markers must be present */
	CH_OPT,         /* which optional declaration to add */
	CH_ARCH,        /* enum kgenome_arch, all of it */
	CH_SUBTYPE,     /* the format's subtypes, all of them */
	/*
	 * EVERY ATTRIBUTE OF ONE MARKER, IN ONE LIST.
	 *
	 * It was CH_WORD and CH_CASE, two lists behind two columns, and the
	 * two columns were twenty-one of them wide for a pair of facts that
	 * sit at their default on most rows. One column now carries both -
	 * see the attr column in draw_decl_strings - so one list has to
	 * carry both too.
	 *
	 * THE LIST DOES NOT CLOSE WHEN A ROW IS TAKEN, and that is the whole
	 * reason the merge is worth doing: the cell holds two INDEPENDENT
	 * facts, so one visit has to be able to set both. A list that closed
	 * on the first click would let a visit change half the cell, which is
	 * what the two separate columns already did.
	 *
	 * The case row is a tick and the three word rows are one choice of
	 * three, drawn as a tick box and a radio - because with the list
	 * staying open the marker is the only thing left saying what a click
	 * did. See ch_attr_build.
	 */
	CH_ATTR,
	CH_CMATCH,      /* which matcher to put into a condition */
	CH_CMATCH2,     /* what to do to one matcher a condition already names */
	CH_CSWAP,       /* which other matcher to put in its place */
	CH_DECLKIND     /* string, hex or regex - what [+ String] adds */
};

/*
 * A MENU ABOUT A PAIR, and ch_open takes one argument.
 *
 * "This matcher, inside this condition" is two indices, and they are packed
 * into `arg` rather than a second field being added, because ch_open memsets
 * the chooser before it builds the list - so anything a caller writes beside
 * arg is not there while the list is being made. That is not hypothetical: it
 * is exactly the bug recorded beside CH_RANGE_EXT, where a subject read from
 * arg2 came through as zero and the menu never opened. Both indices are bounded
 * by MAX_GROUP, which is 8.
 */
#define CH_PAIR(ci, m)  ((uint32_t)(ci) | ((uint32_t)(m) << 16))
#define CH_PAIR_C(x)    ((x) & 0xffffu)
#define CH_PAIR_M(x)    ((x) >> 16)

struct chooser {
	int      open;
	int      row, col;
	int      what;
	uint32_t arg;               /* which group it is about */
	int      n, sel;
	/*
	 * THE FIRST ROW DRAWN, when the list is taller than the room under it.
	 *
	 * A chooser used to paint from item zero and stop at the bottom of the
	 * screen - so on a short terminal the tail of a long list was invisible
	 * AND unclickable, which is how a draft with many markers ended up with
	 * the last ones unreachable from "+ marker". The cap on CH_ITEMS was
	 * raised for the same symptom once already; the cap was never the
	 * problem.
	 */
	int      off;
	/*
	 * THE DRAWN WIDTH, measured from the rows once they are all added.
	 * Every place that asks how wide the list is - the draw, the click
	 * test, and where a submenu is opened beside it - reads this, so a
	 * list cannot be drawn one width and clicked at another.
	 */
	int      w;
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
	/*
	 * A RULE OFF, AND NOT A ROW THAT CAN BE PICKED.
	 *
	 * The attribute list has two halves that mean different things - one
	 * tick, and one choice of three - and nothing but a gap says where
	 * one ends. A blank item would have been a row the cursor lands on
	 * and a click carries out, so the separator is marked rather than
	 * spelled: the draw paints a rule, the arrows step over it and a
	 * click on it does nothing at all.
	 */
	uint8_t  sep[CH_ITEMS];
	/*
	 * THE EDIT IN PROGRESS, which is not the draft yet - see CH_ATTR.
	 *
	 * The attribute list is a form: its rows move these, its Apply row
	 * writes them into the declaration, and every other way out leaves
	 * the declaration alone. Held here rather than in the draft because a
	 * draft written on each click is a draft edited four times by
	 * somebody trying two combinations before choosing one.
	 */
	int      pend_word, pend_icase;
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
/*
 * 512 WAS SIZED FOR A DIFFERENT POPULATION, and the population changed.
 *
 * It was objects plus a dozen region rows each, which 512 covered with room.
 * The entry table is a row PER THING THE OBJECT HOLDS - a stream, a member, an
 * attachment - and a document may publish a thousand of them, so the old
 * number is now reachable by one ordinary file.
 *
 * Reaching it was also SILENT: tree_add returns when full, and the rows lost
 * are whatever came last - which, because detail rows are added per object
 * inside the walk, could be a LATER OBJECT'S OWN ROW. The object list itself
 * would have gone short with nothing saying so. Raised so that does not happen
 * on real input, and tree_build now spends the last slot saying when it does
 * happen anyway.
 *
 * The cost is the array: a node is about 120 bytes, so this is half a megabyte
 * in a tool that already asks the engine for a 32MB presence table.
 */
#define MAX_TREE 4096

/*
 * Events per window. Under MAX_OBJ so the parent fits beside them, and well
 * under MAX_TREE. Bigger buys nothing: a screen shows tens of rows, and the
 * window follows the selection.
 */
#define LOG_WIN 96u


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
	/* 64, matching obj_label's output: a node built from one used to be
	 * copied into a shorter field and lost its tail. */
	char     label[64];
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
	/*
	 * AN ENTRY ROW IS NOT A REGION EITHER, and gets a flag for the same
	 * reason `sym` did rather than a reserved mask value.
	 *
	 * A region says which bytes are what KIND; an entry says what one thing
	 * IS - a stream, an attachment, a member - and two entries can be the
	 * same kind, so no mask distinguishes them. The bytes come straight
	 * from the entry rather than from resolve_scan, which is why off and len
	 * are here: they are the parser's answer for THIS entry and there is
	 * nothing to resolve.
	 *
	 * A sentinel mask would have had to be excluded by hand everywhere a
	 * mask is resolved, and every place that forgot would have shown the
	 * wrong bytes - the note on `sym` above is that lesson already learned
	 * once.
	 */
	uint8_t  ent;               /* the row IS an entry */
	uint32_t ent_i;             /* which row of ctx->entries */
	/* The exact bytes of an entry row: these bytes, not a resolve. */
	uint64_t ent_off, ent_len;
	uint64_t bytes;

	/*
 * How many pieces of one submission the character-to-byte map holds - the
 * record plus sixty-three continuations, which is about twenty-five kilobytes
 * of content. Past it a selection still copies and still declares; only the
 * highlight in the dump stops, because that is the part that needs to know
 * where each piece is.
 */
#define EVT_SEG_MAX 64

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

/*
 * One clickable RECTANGLE, and what pressing it does.
 *
 * A CALLBACK RATHER THAN A CODE, so the action lives beside the thing that
 * draws it instead of in a switch somewhere else that has to be kept in step.
 * `arg` is whatever that drawer needs - a marker index, a matcher id, a region
 * bit, a menu context.
 *
 * WHICH BUTTON, because the right one is not the left one with a different
 * name. Most spans are left-only; a pane that has a context menu declares a
 * rectangle for the right button and nothing else does. See the note on the
 * right-button gate in click().
 *
 * A ROW IS y0 == y1. Most controls are one row of one drawer, and hit_add is
 * for those; a PANE is many rows and declares itself with hit_zone.
 */
struct view;
struct dframe;

/*
 * WHICH GESTURE A RECTANGLE ANSWERS.
 *
 * The wheel is here for the same reason the right button is: "what is under the
 * pointer" is one question, and answering it in a chain of geometry tests
 * somewhere else means every new scrollable area has to be added to that chain.
 * It was not, twice, for the right button; the wheel's chain had the same shape
 * and the text pane was missing from it in both directions.
 *
 * WHICH WAY it turned is g_wheel, read by the callback the way g_mx and g_my
 * already are - a direction is not a different rectangle, so it does not belong
 * in the mask.
 */
enum {
	HIT_L      = 1u << 0,
	HIT_R      = 1u << 1,
	HIT_WHEEL  = 1u << 2,   /* the wheel, plain */
	HIT_HWHEEL = 1u << 3    /* the wheel with shift or ctrl - sideways */
};

struct hit {
	int16_t   y0, y1, x0, x1;
	uint8_t   btn;
	void    (*fn)(struct view *, uint32_t arg);
	uint32_t  arg;
};

/*
 * Enough for the busiest panel a draft can have: every marker row carries
 * three spans and every matcher four, and MAX_DECL and MAX_GROUP bound both.
 * Registering past it is dropped rather than written past the end - a control
 * that cannot be clicked is a visible fault; a smashed stack is not.
 */
#define HIT_MAX 512u

/* How many regions one object's share-out has room for. Every format's table
 * is far shorter than this; the bound is here so the arrays that hold the
 * share-out are fixed. */
#define MTN_MAX_REGION 32u

/* The two generator buttons on the Mutation blocks heading, as drawn. */


struct kv_syn;                  /* the tag sources - see kv_syn.c */

/* The longest row of the disassembly panel as text, and the longest instruction text with its comments. A comment is the engine's words about the instruction and is not cut to the width of a screen. */
#define DIS_LINE_MAX 320
#define DIS_TEXT_MAX 300

struct view {
	/* The scanner that is running RIGHT NOW, so on_object can ask it what
	 * the database's blocks scored before it is freed. NULL at every other
	 * moment, which is what stops anything else from reaching for it. */
	kof_scanner     *scan_sc;
	/*
	 * MUTATION MODE: the same pane, asking a different question.
	 *
	 * It replaces the draft panel rather than sitting beside it because the
	 * two are alternatives - a signature is written out of patterns or out
	 * of blocks, and a screen offering both at once would be offering a
	 * choice nobody makes halfway.
	 */
	/*
	 * A POINTER, so ticked blocks can outlive opening the next file.
	 *
	 * Everything else about a view is about the file in front of it and is
	 * cleared when another is opened. These are not: a block ticked on one
	 * sample is the QUESTION being asked of the next one, and clearing it
	 * left the score column with nothing to measure. Held the way ext and
	 * probe are - allocated once in main, carried across the clear.
	 */

	uint32_t         n_plg;
	uint32_t         mtn_sel;          /* the row the keyboard is on */
	/*
	 * What the last scoring pass was about, so a frame that changed
	 * neither does not redo it.
	 *
	 * Scoring walks the object, which is the one thing in this panel that
	 * is not free - and the answer only moves when the blocks change or
	 * the reader moves to another object. Both are captured here.
	 */
	uint32_t         mtn_scored_obj;
	uint32_t         mtn_scored_n;
	int              mtn_scored;
	/* The blocks came from the object's own cached carve, so their scores
	 * are certainties and not measurements - see mtn_segment. */
	int              mtn_scores_known;
	/*
	 * FOLDED TABLES.
	 *
	 * The block table is as long as the object has areas - sixty-four rows
	 * on a large one - and a reader working on the matchers below it should
	 * not have to scroll past all of them to get there. Folding is per
	 * table and per session, not per object: it is a property of what the
	 * reader is doing, and a fold that reopened itself whenever the sample
	 * changed would be a fold that never holds.
	 *
	 * The heading and the column row stay in both states; the column row is
	 * what carries the control, and a table whose handle vanished when it
	 * was folded could not be opened again.
	 */
	int              blk_fold, diag_fold;
	/* Which object the table was carved from, so moving to another one
	 * carves that one instead of showing the last one's blocks. */
	uint32_t         mtn_seg_obj;
	int              mtn_segged;

	/* The signature generator's model - see kofeditor.h. */
	struct kof_editor ed;
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



	struct node node[MAX_TREE];
	/* Whether a row was refused for want of space. A truncated list that
	 * does not say so is read as a complete one. */
	uint8_t              tree_cut;
	uint32_t    n_node, sel_node, tree_top;

	/*
	 * AN EVENT LOG, BROWSED AS A WINDOW RATHER THAN LOADED.
	 *
	 * A log holds millions of records and the object array holds MAX_OBJ,
	 * so the objects are a WINDOW over it: LOG_WIN events starting at
	 * log_first, rebuilt when the selection walks off either end. Nothing
	 * of a record is copied - each event object's buf points into the
	 * mapped file at that record's own extent, so the hex pane shows the
	 * real bytes and the memory cost of opening a log is the mapping.
	 *
	 * `log` is a second handle on the same file, used only to ask WHERE a
	 * record is; the bytes come from the mapping. Two handles because the
	 * questions are different and neither wants the other's file position.
	 */
	struct kofevt_log_r *log;
	uint64_t             log_n;      /* records in the file */
	uint64_t             log_first;  /* the window's first record */

	/*
	 * WHICH RECORD EACH ROW STANDS FOR, and where the window stopped.
	 *
	 * Rows are not records any more and the two must not be conflated: the
	 * verb filter hides some, and a continuation is absorbed into the event
	 * in front of it rather than given a row. The paging code used to
	 * recover the last row's record as `log_first + row - 1`, which is only
	 * true when every record in the window got a row - so with a filter on,
	 * turning the page landed somewhere unrelated to where the reader was.
	 */
	uint64_t             log_idx[MAX_OBJ];
	uint64_t             log_next;   /* the first record past the window */

	/*
	 * The tree needs rebuilding before the next frame.
	 *
	 * Set when something learns a fact that changes what rows exist - a
	 * carried image being identified, so its regions can be listed. Acted
	 * on at the top of the frame, because that is the one place where no
	 * caller is holding a node index.
	 */
	int                  tree_dirty;

	/*
	 * WHERE A SCAN'S RESULT FOR ITS OWN ROOT SHOULD GO, or -1.
	 *
	 * A scan reports the object it was given first, and on_object's normal
	 * job is to APPEND what it is told about. That is right when the engine
	 * is walking a file and discovering objects; it is wrong for a row the
	 * tree already has - a carried image, scanned on its own - where the
	 * findings belong to the row a reader is looking at and a second copy
	 * of it would appear beside itself.
	 */
	int                  into_obj;

	/*
	 * HOW MANY OF THOSE RECORDS ARE EVENTS.
	 *
	 * Not the same number as log_n, and the difference is not cosmetic: a
	 * continuation is a record and is not an event, so a log holding one
	 * AMSI submission split over nine chunks has ten records and one event.
	 * Reported as ten, the header told a reader there were nine things in
	 * the file that are not there.
	 *
	 * log_n stays the record count, because that is what indexes the file -
	 * kofevt_log_extent, the window, the paging all count records. This is
	 * only ever shown.
	 */
	uint64_t             log_events;

	/*
	 * WHICH VERBS THIS LOG ACTUALLY CONTAINS, and which of them to show.
	 *
	 * Both are masks of 1u << kof_evt_verb. `log_verbs` is what the file
	 * holds - built once by walking the MAPPING, which costs no I/O - and
	 * it is what the filter submenu offers: a menu listing verbs the log
	 * does not contain is a menu of rows that do nothing.
	 *
	 * `log_keep` is what the object panel shows. It starts equal to
	 * log_verbs, so opening a log shows everything, and Apply narrows it.
	 */
	uint32_t             log_verbs, log_keep;

	/*
	 * HOW MANY OF EACH, counted in the same walk that learns which verbs
	 * the file holds - so it costs nothing beyond the pass already made.
	 *
	 * A mask says a verb is present; a count says whether it is the trace.
	 * "RegSet" and "RegSet 41000" are different facts about a log, and the
	 * second is the one that decides where to look.
	 */
	uint64_t             log_count[32];

	/*
	 * THE SELECTED EVENT, SPELT OUT - the record itself and where the
	 * reader is inside its field list.
	 *
	 * Copied out of the mapping rather than pointed at it, for the reason
	 * log_window already copies: a log written by a build with a different
	 * head has its text at another offset, and a bounded copy into THIS
	 * build's struct is the only read of it that is defined.
	 *
	 * `evt_sel` is a row index, and -1 means the panel is open with
	 * nothing picked - which is the state it starts in, because landing on
	 * a record should show what it says before it starts pointing at one
	 * part of it.
	 */
	struct kof_evt       evt;
	int                  evt_have;   /* the copy above is a real record */
	int                  evt_open;   /* the reader has not closed it */
	int                  evt_n;      /* rows the record yields */
	int                  evt_sel;    /* the row lit in both panes, or -1 */
	int                  evt_scroll; /* first line drawn */
	/*
	 * HOW FAR THE VALUES ARE SHIFTED LEFT.
	 *
	 * The wrap shows the first six lines of a value, which is enough to see
	 * what a thing is and not enough to read a submitted script to its end.
	 * Shifting moves the whole value before it wraps, so the six lines
	 * become a window over it rather than its beginning - and a reader can
	 * reach the tail of an AMSI buffer without the panel eating the pane.
	 */


	/*
	 * THE WHOLE SUBMISSION, gathered from the event and the continuations
	 * behind it.
	 *
	 * The record holds a prefix - four hundred bytes of arena - and the
	 * rest arrives as KOF_EVT_CONT records, which this viewer folds into
	 * the same row. `join` is the raw bytes, in the order they were sent;
	 * `text` is the rendering of them, which is what a pane can show.
	 *
	 * Both are allocated once with the log and reused per selection: a
	 * record's content is bounded by what the collector will send, so a
	 * fixed pair costs the same for every event and there is nothing to
	 * grow or free while walking a log.
	 */
	char                *evt_join;
	size_t               evt_join_len;
	char                *evt_text;
	size_t               evt_text_len;

	/*
	 * The gathered content is UTF-16LE - a NUL above every character.
	 *
	 * Kept because the HEX PANE needs it too, not only the field row: a
	 * dump of a script block is half NUL bytes, and a column of dots
	 * between every letter is the thing that makes it unreadable.
	 */
	int                  evt_wide;

	/*
	 * WHERE THE GATHERED CONTENT SITS IN THE NODE'S BYTES.
	 *
	 * The submission is one string once it is joined, and it is NOT one run
	 * in the file: the record holds the first four hundred bytes of it and
	 * each continuation holds the next, with a seventy-two byte head in
	 * between. So a character in the box maps to a byte in the dump only
	 * through a table of the pieces.
	 *
	 * Without it the sync could only mark a selection inside the FIRST
	 * record, which is the part a reader scrolls past.
	 *
	 * Capped, and the cap is honest: past it the map runs out and the sync
	 * marks nothing rather than marking the wrong bytes.
	 */
	struct { uint32_t at, len; } evt_seg[EVT_SEG_MAX];
	int                  evt_n_seg;

	/*
	 * AN EXECUTABLE CARRIED INSIDE AN EVENT, as a child object.
	 *
	 * Some submissions are a PE image rather than a script. The bytes are
	 * already gathered - kof_evt_join concatenates the raw content and
	 * nothing else, so what comes out is the file, byte for byte, with no
	 * record heads or padding between the pieces. What was missing was
	 * anywhere to LOOK at it: the panel renders text, and a PE rendered as
	 * text is a column of dots.
	 *
	 * So the event grows a child row, and selecting it puts the image in
	 * the hex pane like any other object. `pe_of` is the object index of
	 * the EVENT a child belongs to - zero for every row that is not one -
	 * because the child's bytes are its parent's join, materialised when
	 * the child is picked rather than for every event in the window.
	 */
	uint32_t             pe_of[MAX_OBJ];
	uint32_t             pe_at;   /* where the image starts in the join */

	/*
	 * A RUN OF CHARACTERS PICKED OUT OF ONE ROW'S VALUE.
	 *
	 * The name column and the value column answer different gestures. A
	 * click on the NAME is a question about the record - which bytes is
	 * this - so it lights the field and takes the dump there. A drag across
	 * the VALUE is a question about the text: an AMSI submission is a
	 * script, and what a reader wants from a script is to pull a URL or a
	 * base64 blob out of it and paste it somewhere else.
	 *
	 * Anchored to (row, character), not to screen positions: the value
	 * wraps and the panel scrolls, and a selection anchored to a screen
	 * cell would name a different part of the text after either.
	 */
	int                  evt_txt_a, evt_txt_b;
	int                  evt_txt_drag;

	struct kof_range *ext;
	/*
	 * A SECOND EXTENT BUFFER, for anything that resolves a region that is
	 * not the one on screen.
	 *
	 * `ext` holds the SELECTED region's runs and is what view_map and
	 * view_unmap read - the hex pane's entire sense of where it is. Mutation
	 * mode resolves other regions to carve and to score, and resolving into
	 * `ext` overwrote that: the highlight then mapped through the wrong
	 * runs and landed nowhere, and the pane it was drawn over was reading
	 * the same wreckage.
	 */
	struct kof_range *ext2;
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
	 * KGENOME_BROKEN for "nothing selected", which is distinct from a selection
	 * of length zero.
	 */
	uint64_t    sel_a, sel_b;
	/* The process this view is showing, or 0 when it is a file. What makes
	 * next/prev step through pids instead of through a directory. */
	uint32_t    proc_pid;
	/* The mapped files already given a row - see proc_seen_path. */
#define PROC_SEEN_MAX 256u
	char        seen_path[PROC_SEEN_MAX][256];
	uint32_t    n_seen;
	/* Mapped files this view declined to read, and the bytes it did. */
	uint32_t    proc_skipped;
	uint64_t    proc_skipped_bytes;

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
	 * KGENOME_BROKEN in dis_len means it is not pinned: it follows the hex
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
	/*
	 * The last instruction that set the flags (a CMP or a TEST) and where the next instruction would start, so a conditional jump read right after
	 * it - or after instructions that leave the flags alone - is explained as the comparison it is. Kept by dis_format as it goes; a row that is not
	 * the next of the last one starts from nothing known.
	 */
	struct kgenome_x86_insn dis_fl;
	uint64_t    dis_fl_rip, dis_next;
	uint8_t     dis_fl_ok;
	char        dis_line[64][DIS_LINE_MAX];
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
	uint8_t     dis_line_lbl[64];       /* the row is a label: no bytes, not selectable */
	int         dis_lines;
	int         dragging;
	int         dragged;        /* the pointer moved off the pressed byte */

	/* Which half of the hex pane the menu was opened on. */
	int         menu_ctx;       /* 1 bytes, 2 the offset column,
				     * 4 the disassembly, 8 the event box */
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
	uint32_t    tree_hoff, decl_hoff;

	/* The region column's width for this frame - see draw_decl. */
	int         rgn_w;




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

     /* how far the field is scrolled */


	uint32_t     n_rng, cur_rng;

       /* matchers */




     /* why the last add was refused */
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
      /* 1 it failed, 0 it is only worth knowing */

	/*
	 * What the finished module will declare about itself.
	 *
	 * The type is cycled rather than typed because it is an enum the build
	 * checks - ksigbuilder refuses a word that is not in its table, and a
	 * text box that can produce a build error is a text box that should have
	 * been a list. The other two are free text and belong to whoever is
	 * writing the signature.
	 */





	char        basedir[256];

	/*
	 * How the conditions combine, written the way ClamAV writes it: numbers
	 * for conditions, & and |, parentheses. Free text because the shapes
	 * people want are not a menu - "1&2", "(1&2)|3" - and because an empty
	 * one has an obvious meaning worth keeping as the default: every
	 * condition, joined by &.
	 */


	int         edit;           /* 0 none, 1 family, 2 variant */




	/* Where the header's controls landed, recorded as they are drawn. */
	int         f_c0, f_c1, t_c0, t_c1, v_c0, v_c1, g_c0, g_c1;
	int         n_c0, n_c1;     /* the "+ condition" button */
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
	int         adds_c0, adds_c1; /* "[+ str]" - see BTN_ADDSTR */
	/* The target formats on their row: each name's columns, and the button
	 * that adds one. Recorded where they are drawn, read where they are
	 * clicked - the arrangement every other control here uses. */
	int         fmt_hs[KOF_FMT_COUNT][2];
	uint32_t    n_fmt_hs;
	int         fma_c0, fma_c1;
       /* the region the range menu was built on */
	/*
	 * Ranges the draft declares that no matcher names yet.
	 *
	 * A range normally has no existence apart from a matcher naming one,
	 * which is why the summary row derives itself. "Add CODE to scan
	 * ranges" breaks that for as long as it takes to give the range a
	 * matcher - so it is held here, listed as unused, and refused at save
	 * time rather than turned into an empty matcher nobody asked for.
	 */


	/*
	 * The list a submenu came out of, kept so it can stay on screen.
	 *
	 * A submenu that replaces its parent is not beside it, it is instead of
	 * it - and the reader loses the line they were acting on at the moment
	 * they are asked to qualify it.
	 */
	struct chooser ch_up;
	int         a_c0, a_c1, b_c0, b_c1;
	/*
	 * "[+ String]" - ONE PAIR PER MATCHER, because its column depends on
	 * how many marker ids that matcher's row already printed. A single
	 * shared pair was overwritten by every row in turn, so only the last
	 * matcher's button answered a click and the earlier rows' buttons were
	 * dead while blank space at the last row's column was live.
	 */
	/*
	 * WHERE EVERY CLICKABLE THING IS, RECORDED WHILE IT IS DRAWN.
	 *
	 * The panel's clicks used to be a second walk over the same rows -
	 * click_panel_rows, 390 lines - counting rows in the order the draw
	 * emits them and reaching the controls by a field the draw had left
	 * behind. Two walks of one shape, and nothing making them agree: adding
	 * the Format and [+ Options] rows to the draw and not to the other walk
	 * shifted every click below them by two, and the same drift in
	 * prow_build cost the panel its Conditions rows outright.
	 *
	 * A span is registered by whoever paints it, at the moment it knows
	 * where it landed, and a click is a lookup. The draw becomes the only
	 * place that knows the layout, which is the property the two walks
	 * could not have.
	 *
	 * Last match wins on overlap: rows are painted top down and a later
	 * span is drawn over an earlier one, so the reader is pointing at the
	 * later one.
	 */
	struct hit  hit[HIT_MAX];
	uint32_t    n_hit;

	int         p_c0[MAX_GROUP][2];
	/*
	 * WHERE EACH ITEM OF A MATCHER'S LIST ROW WAS DRAWN - see grp_list.
	 * One array for both kinds of matcher, because a matcher is one kind
	 * or the other and never both.
	 */
	int         grp_it[MAX_GROUP][GRP_SIM_MAX][2];
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
	 * MUTATION MODE SCROLLS THE BLOCK LIST AND NOTHING ELSE.
	 *
	 * The condition and what the database scored are written BELOW the
	 * list, and a carve produces as many as sixty-four blocks against a
	 * panel a dozen rows tall - so scrolled as one column they went off the
	 * bottom and the author lost the two rows that say what the ticking is
	 * building. They are what a reader looks at WHILE ticking, so they hold
	 * still and the list moves inside them.
	 *
	 * mtn_above is how many rows sit above the list and kgenome_mtn_win how many
	 * the list itself gets; the drawing, the clamp, the wheel and the
	 * scrollbar all read these rather than each deriving them again.
	 */
	uint32_t    mtn_above, kgenome_mtn_win;
	/* The threshold being typed, as text - a percentage is edited the way
	 * every other box here is edited, and committed back to the block on
	 * each key. */
	char        grp_pct_buf[8];
	uint32_t    grp_pct_off;
	/* Whether the row-count check is the one showing in `warn` - see the
	 * foot of draw_decl. */
	int         rowchk;
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

	uint32_t    prow_seen;
	/*
	 * A DRAFT THAT WAS LOADED OPENS AT ITS BEGINNING.
	 *
	 * The panel scrolls to the bottom when it grows, because what grew is
	 * the row the reader just asked for. Replacing the whole draft also
	 * makes it grow - by every row at once - and that read as the same
	 * event, so opening a rule from the database landed at the end of it
	 * and the KOF_TARGET_ rows, which are at the top, were off screen. The
	 * options looked as though the rule had not declared any.
	 */
	int         prow_home;      /* how tall the draft was last frame */
     /* what the draft was when it was written */
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

	/*
	 * SEPARATE THE CHILDREN ON DEMAND RATHER THAN ON OPEN.
	 *
	 * The engine's own word and the engine's own flag: kof_scan_option
	 * .heur_off is what gates opening a declared entry into an object of
	 * its own - see kof_objtree_may_open - and it is the same flag
	 * kofscanner spells --heur 0. Not a viewer-only setting beside it,
	 * because a second axis here would be this tool disagreeing with the
	 * engine about what a scan of the same file does.
	 *
	 * WHAT IT IS FOR. Opening a document separates every stream the parse
	 * declared, which on a large one is every decompressor in the database
	 * run before the first row is drawn. A reader who wants to see what the
	 * document SAYS about itself - the entry table, which is one row per
	 * stream with its kind, its name and its filter chain - does not need
	 * any of that work done first. So it can be deferred, and the Analysis
	 * menu asks for it when they want it.
	 *
	 * THE ENTRY ROWS ARE THE POINT OF THE MODE, not a consolation for it.
	 * An entry row is dropped when its content is present as an object of
	 * its own - two rows for one stream, see tree_build - so with nothing
	 * separated the table is shown in full, which is exactly the view a
	 * reader checking the parse wants.
	 *
	 * IT ALSO TURNS THE HEURISTICS OFF, because that is what this one flag
	 * means in the engine. Said plainly in the usage text rather than
	 * worked around: the two were made one flag deliberately, and a viewer
	 * that quietly split them again would be where the two definitions of
	 * --heur 0 drifted apart.
	 */
	int         heur_off;

	/* Set while a sub-scan runs: swallow its echo of the object it was
	 * given. See on_object. */
	int         skip_root;
	/*
	 * WHERE THE OBJECT LIST ENDED BEFORE A RERUN, or 0 for an ordinary
	 * collect. See the dedup in on_object: everything below this index was
	 * already in the tree when the rerun started, so a child that matches
	 * one of them is the same child reported twice.
	 */
	uint32_t    dedup_from;

	/* Which top-level item's submenu is showing, -1 for none. */
	int         bar_sub;

	/*
	 * THE MENU ASKED TO LEAVE.
	 *
	 * A flag and not a return value, because bar_run is reached from a
	 * click handler that returns nothing and from a key handler that
	 * returns "handled" - so there is no one code the two could carry, and
	 * giving the click path a return type means threading it through
	 * everything above it to answer one item.
	 *
	 * The loop reads it immediately after handle(), so nothing runs a frame
	 * after it is set.
	 */
	int         quit;
	int         bar_open;       /* which menu is down, -1 for none */
	int         bar_sel;        /* the item under the pointer or the cursor */
	int         help_open;      /* 0 none, 1 keyboard, 2 about */
	/*
	 * Both help dialogs scroll, and both need somewhere to record where
	 * their Close button landed - a click arrives as a screen position and
	 * nothing else knows the box's geometry once draw_help has returned.
	 * Set while drawing, read while clicking; the same shape the menu bar's
	 * hit test already has.
	 */
	int         help_off;
	int         help_btn_y, help_btn_x0, help_btn_x1;
	/*
	 * THE DECODER, AND IT IS A FORM RATHER THAN A REPORT.
	 *
	 * Text in, a coding chosen, a key when the coding takes one, plaintext
	 * out - the shape of every decoder tab an analyst already knows.
	 *
	 * A FORM AND NOT AN AUTOMATIC TABLE, and the reason is where the text
	 * comes from: usually NOT this file. It is pasted - out of a log, a
	 * pcap, a mail, a screenshot somebody typed back in - and a box that
	 * could only work on bytes already in the object would be closed again
	 * immediately. "Decode selection" fills the field from the hex pane,
	 * which is the convenience; typing or pasting is the normal case.
	 */
	int         enc_open;
	char        enc_in[ENC_IN_MAX];        /* the encoded text */
	char        enc_key[32];               /* for codings that take one */
	uint32_t    enc_in_off, enc_key_off;   /* how far each field scrolled */
	uint32_t    enc_type;                  /* which coding */
	/*
	 * WHICH WAY - 0 decodes, 1 encodes.
	 *
	 * The box was a decoder only, which is half of what a researcher does
	 * with a coding: the pattern that goes into a signature is the ENCODED
	 * form, so "what does cmd.exe look like in hex" is asked as often as
	 * "what does this hex say". One control, because the two directions
	 * share every other field on the form.
	 */
	int         enc_way;
	uint32_t    enc_res_n;                 /* plaintext bytes, 0 for none */
	int         enc_done;                  /* Decode has been pressed */
	/* The controls, recorded where they are drawn and read where they are
	 * clicked - the arrangement every other dialog here uses. */
	int         e_in[2], e_type[2], e_key[2], e_go[2];
	/* The second button - see draw_enc. `e_go` is Decode. */
	int         e_enc[2];
	/*
	 * THE PLAINTEXT WINDOW: how far down and how far across.
	 *
	 * A decoded script is longer than any box and its lines are longer than
	 * any width, so the result is a WINDOW over it rather than a preview of
	 * it. Both offsets are the reader's, moved by the wheel and by dragging
	 * a selection past the edge, and both are clamped where the window is
	 * drawn - which is the only place that knows how much fits.
	 */
	uint32_t    enc_voff, enc_hoff;
	int         enc_txt_y, enc_txt_x, enc_txt_w, enc_txt_h;
	int         prop_open;      /* the properties page is up */
	/*
	 * A SECOND MODAL PAGE STOOD HERE - the call chain the sweep read and
	 * the trace the interpreter produced, as two tabs of one box. Both
	 * went with the chain matcher. The fields are gone rather than left
	 * at zero, because a dialog's state that nothing ever sets is a
	 * dialog the modal id below still counts.
	 */
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
	/*
	 * Where the mouse went DOWN, which is not where the selection starts.
	 *
	 * A click selects the whole word under it, so the selection's ends are
	 * the word's ends. Dragging must grow from the point that was clicked,
	 * not from whichever end the word happened to put there - otherwise
	 * pulling back over the word does nothing until the pointer passes its
	 * far edge, which is what made dragging feel broken.
	 */
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
	/*
	 * WHERE EACH COLUMN OF A RECORDED ROW BEGINS IN ITS BYTES.
	 *
	 * The screen counts GLYPHS and the recording holds BYTES, and the two
	 * stopped agreeing the day these pages grew box rules: G_V is three
	 * bytes and one column, so from the first wall onwards a click at
	 * column N landed on byte N, three or six bytes to the left of what
	 * the reader pointed at. The highlight was drawn from the same wrong
	 * place, which put its edge in the middle of a glyph - a border that
	 * appeared several words away, and a stray character where the reverse
	 * video repainted half of one.
	 *
	 * Folding the glyphs down to ASCII in the recording would have squared
	 * the arithmetic and changed what a selection PAINTS and COPIES, which
	 * is the thing the recording exists to get right. This keeps the real
	 * bytes and adds the translation: dlg_bx[row][col] is the first byte of
	 * that column and dlg_bx[row][cols] is one past the last, so a span in
	 * columns becomes a span in bytes by two lookups.
	 */
	uint16_t    dlg_bx[DLG_ROWS][DLG_COLS + 1];
	uint16_t    dlg_cols[DLG_ROWS];
	/*
	 * WHICH LINE OF THE LIST each recorded row came from, and -1 when the
	 * recorder was not told.
	 *
	 * The recording is of the VISIBLE WINDOW, rebuilt every frame, so a row
	 * number means "third row on screen" and not "third line of the page".
	 * A selection stored as a row number therefore slid onto whatever the
	 * scroll had put there - the text under the highlight changed while the
	 * highlight stayed still. Anchoring on this instead makes a selection
	 * belong to the LINE it was made on, wherever that line goes.
	 */
	int         dlg_src[DLG_ROWS];
	int         dlg_y0, dlg_x0;
	int         dlg_ar, dlg_ac, dlg_br, dlg_bc;
	int         dlg_have;
	int         dlg_drag;
	/*
	 * THE BOX BEING MOVED, and where the grab started.
	 *
	 * A pointer to the frame rather than a code for which dialog: every box
	 * goes through dframe, the frames are static, and a code would be a
	 * second list to keep in step with the first. NULL when nothing is
	 * being moved.
	 */
	struct dframe *dlg_move;
	int         dlg_mx, dlg_my;     /* where the pointer took hold */
	int         dlg_mdx, dlg_mdy;   /* the box's offset when it did */
	/*
	 * THE LAST PRESS IN A DIALOG, so a second one on the same place can be
	 * recognised as a double click.
	 *
	 * Timed rather than counted, for the reason the hex pane's is: a
	 * terminal reports two presses and has no notion of a double click to
	 * pass on. Kept apart from last_click because that one is a byte
	 * OFFSET in the file and this is a place in a recorded page - the same
	 * number would mean two different things, and a click in one pane
	 * would arm a double click in the other.
	 */
	int         dlg_click_r, dlg_click_c;
	uint64_t    dlg_click_ms;

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
	/*
	 * THE SYMBOL FILTER, and why it replaced the line that was there.
	 *
	 * The tab row used to end with ".symtab, 1662 records, TRUNCATED" - the
	 * origin section, a count and a flag. The count is already on both
	 * tabs, the origin is the same for every row in the dialog and never
	 * changes while it is open, and TRUNCATED is a property of the block
	 * the tree row already reports. Three facts, none of them the question
	 * a reader with 1662 symbols in front of them is asking, sitting in the
	 * one place wide enough for the thing they ARE asking: which of these
	 * is called what.
	 *
	 * `sy_filt` is the text, `sy_ficase` folds case, `sy_frx` reads it as a
	 * regular expression. The regex is compiled by the engine -
	 * kof_regex_compile - and walked by kof_hex_walk_flags, which is the
	 * same pair the matcher uses, so a pattern that filters here means the
	 * same thing written into a rule. `sy_frx_bad` is set when the compile
	 * refuses, and then nothing is filtered: a half-typed pattern must not
	 * look like a search that found nothing.
	 */
	char        sy_filt[64];
	uint32_t    sy_foff;            /* how far the field is scrolled */
	int         sy_ficase, sy_frx, sy_frx_bad;
	char        sy_rx_err[96];
	uint8_t     sy_prog[512];
	uint32_t    sy_prog_n;
	int         sy_fbox[2];         /* the text field */
	int         sy_ic_box[2];       /* [ ] ignore case */
	int         sy_rx_box[2];       /* [ ] regex */
	int         goto_file;      /* 1 file offset, 0 offset in this region */
	char        gotobuf[20];
	int         find_hex;       /* the text is hex digits, not bytes */
	int         find_icase;     /* letters compare either way; text only */
	/*
	 * READ THE TEXT AS A REGULAR EXPRESSION.
	 *
	 * The program the engine compiles it to and whether it compiled at all,
	 * beside the flag - a pattern half typed has to leave the search doing
	 * something honest, and what it does is nothing.
	 */
	int         find_regex;
	uint8_t     find_prog[512];
	uint32_t    find_prog_n;
	int         find_rx_bad;
	char        find_rx_err[96];
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
	uint32_t    cnd_eoff[MAX_GROUP];
	/* The search's own message. Shared with the draft panel's it produced
	 * a bare "not found" beside the Generate button, which is an answer to
	 * a question that panel never asked. */
	char        find_msg[128];   /* a regex compiler message is longer than "No match" */
	/* Where each control landed, recorded as it is drawn. */
	int         f_txt[2], f_mode[2], f_rx[2], f_ic[2], f_all[2];
	int         f_next[2], f_back[2], f_cancel[2];

	char        num[24];        /* the size being typed */
	int         num_fresh;      /* nothing typed into it yet */
	int         row_cnd, row_str;
	int         cnd_tg[MAX_GROUP][2];   /* the tag of each condition */
	int         grp_tg[MAX_GROUP][2];   /* the tag of a standalone block matcher */
	/*
	 * THE TAG SOURCES AND THE VIEWS OVER THEM, owned by the session: they
	 * outlive the file being looked at, so the clear that opens another one
	 * keeps the pointer (file_open, proc_open).
	 */
	struct kv_syn *syn;
	/* Whether the output pane is listed under the tables - what the
	 * Generate button toggles. Nothing is written either way. */
	int         gen_preview;
	/* The comment boxes, and the condition's own "+ matcher". Recorded per
	 * row as they are drawn, because a row that is scrolled out has no
	 * columns and must not answer a click meant for the one in its place. */
	int         grp_nt[MAX_GROUP][2];
	/* Where a string row's word/case block and its bytes were drawn. Read
	 * back rather than assumed: the columns move when a field widens, and
	 * a click routed by a remembered number goes to the wrong control. */
	int         str_wc[MAX_DECL][2], str_by[MAX_DECL][2];
	int         grp_rl[MAX_GROUP][2], grp_rg[MAX_GROUP][2];
	/*
	 * AN AT MATCHER'S PLACE IS THREE CONTROLS, NOT ONE.
	 *
	 * The anchor names where to count from and opens a list; the sign
	 * says which way and is pressed; the step is typed. They were one
	 * span that opened the list, so the only way to change the number was
	 * to pick a different occurrence of the marker.
	 *
	 * -1 for a row that has none: a matcher that is not an AT, a row that
	 * is scrolled out, and the sign of an anchor that has no choice of
	 * one - see grp_at_sign_free.
	 */
	int         grp_sg[MAX_GROUP][2], grp_of[MAX_GROUP][2];
	char        at_buf[24];     /* the step being typed, as written */
	uint32_t    at_buf_off;
	int         grp_th[MAX_GROUP][2];
	int         cnd_op[MAX_GROUP][2];
	/* Two per condition: its matcher row and its tag row. */
	uint8_t     cseq_kind[2 * MAX_GROUP];
	uint32_t    cseq_idx[2 * MAX_GROUP];
	uint32_t    n_cseq;
	/*
	 * WHERE EACH MATCHER ID ON A CONDITION'S ROW WAS DRAWN.
	 *
	 * Recorded while drawing, the way every other clickable span on these
	 * rows is, rather than recomputed by the hit test from a start column
	 * and a stride. The stride version has been wrong twice - once when the
	 * ids grew past one digit, once when the separator stopped being ", " -
	 * and both times the failure was a click that removed a matcher the
	 * author had not pointed at. There is nothing to keep in step here: the
	 * columns come from the same pass that printed them.
	 *
	 * -1 means "not drawn": the condition does not name that matcher, or
	 * the row is showing a typed expression rather than a list.
	 */
	int         cnd_ids[MAX_GROUP][MAX_GROUP][2];
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
	 * WHAT IS SELECTED IN THE OPEN FIELD - a RANGE, unordered.
	 *
	 * It was one flag meaning "all of it", which is what Ctrl+A needs and
	 * is not what a text box is. Dragging the pointer through a pattern to
	 * take half of it, which is how anyone copies part of a string
	 * anywhere else, had nothing to express: the box answered a click with
	 * a caret and that was all it did. So the flag became the two ends of a
	 * range, and Ctrl+A is now the case where they are 0 and the length.
	 *
	 * `fld_a` is the anchor and is NOT normalised - a drag leftwards leaves
	 * b before a, and normalising as it moves would pin the anchor to
	 * whichever end the pointer passed last. Read them through fsel_lo and
	 * fsel_hi.
	 *
	 * Only the field that is OPEN can carry one, so they are cleared
	 * wherever the caret is placed afresh.
	 */
	uint32_t    fld_a, fld_b;
	int         fld_drag;       /* the pointer is extending it */
	/*
	 * WHICH FIELD THE RANGE BELONGS TO - `edit` as it was when the range
	 * was made.
	 *
	 * Without it a range outlives the box it was dragged in: open another
	 * field and the old offsets are painted into it, over text they were
	 * never about. Clearing at every place that assigns `edit` would be a
	 * rule thirty call sites have to remember; comparing is a rule kept in
	 * one place - see fsel_range.
	 */
	int         fld_of;
	int         per;            /* bytes a hex row shows, for click mapping */

	/*
	 * THE TEXT PANE, which is this same pane rendered for something meant
	 * to be read - see KV_CAP_TEXT. Same region, same rgn_at, same
	 * selection, same menu; what changes is the layout and what the status
	 * line counts in.
	 *
	 * rgn_at STAYS THE BYTE OFFSET OF THE TOP OF THE PANE, exactly as the
	 * hex view leaves it. That is what lets goto, find, a marker jump and
	 * every scroll key keep working unchanged: they move a byte offset, and
	 * this pane rounds it down to the start of its line to draw.
	 */
	uint32_t    txt_col;        /* horizontal origin, in columns */
	/*
	 * THE LINE NUMBER OF THE TOP ROW, and an anchor to compute it from.
	 *
	 * Counting newlines from the start of the region every frame is one
	 * pass over the whole region per keystroke - three milliseconds on a
	 * ten megabyte script, on every arrow key. So the last answer is kept
	 * and the next one is counted FROM it, which is a few bytes when
	 * scrolling and a full rescan only when something jumps.
	 */
	uint64_t    txt_anchor;     /* a byte offset whose line number is known */
	uint64_t    txt_anchor_ln;  /* that line number, 0 based */
	/*
	 * The longest line the last frame drew, so sideways scrolling can stop
	 * where the text does. Without it the pane scrolls into blank space and
	 * the reader is left pressing a key that empties the screen - which
	 * reads as the key not working rather than as the end of the line.
	 */
	uint32_t    txt_maxlen;
	/*
	 * THE READER ASKED FOR BYTES, on something this would otherwise show
	 * as text.
	 *
	 * Sticky rather than per object: it is a preference about how to read,
	 * not a fact about a file, and a setting that resets when you step to
	 * the next node is one you set again on every node.
	 */
	uint8_t     hex_forced;
};

/* Resolve whichever region the cursor is on, and put the hex pane back where it
 * was the last time this row was looked at. */
/* ---- the event panel -------------------------------------------------------
 *
 * WHY THE TWO PANES SHARE A PALETTE.
 *
 * A field list beside a hex dump is two views of one record, and the question
 * a reader has is always the same: which bytes is this row talking about. Left
 * to prose the answer is an offset they have to count to; given a colour it is
 * a glance. So every row takes a background from a small palette and the bytes
 * it covers take the SAME background - the mapping is the colour, and it goes
 * both ways: a run of odd bytes in the dump names itself by matching a row.
 *
 * Small on purpose. A record yields up to about a dozen rows and a palette that
 * gave each its own hue would be a dozen colours nobody can hold; six that
 * repeat are six a reader can, and two rows sharing one are never adjacent in
 * the dump because the rows are sorted by offset - so a repeat is always half
 * a record away from its twin.
 *
 * 256-colour, like A_S_SHN and for the same reason: the sixteen are spoken for
 * by meanings this tool uses everywhere else - red is a marker the database
 * counted, blue is a drag selection - and a palette built from them would say
 * those things by accident. A terminal without 256-colour ignores the sequence
 * and loses the mapping; it does not break the layout.
 *
 *
 * WHY THE DUMP TAKES THE FOREGROUND AND THE PANEL TAKES THE BACKGROUND.
 *
 * They were both backgrounds to begin with, and on the fixed head that reads
 * well - four bytes of pid in a block of colour is a thing the eye lands on.
 *
 * The head is not where a record is read. Every one of these ends with the
 * text arena, and the arena is where the fact is: the path, the command line,
 * the AMSI submission. It is the last field, it is by far the longest, and it
 * is the one a reader opened the record to see - so it is exactly the field a
 * solid background ruins. A hundred and fifty cells of ground is not a
 * highlight, it is a wall, and it stands over the one part of the record
 * nobody is skimming.
 *
 * So the dump colours the GLYPHS. The hex pane is already a foreground display
 * - byte_colour tells NULs from text that way - so a field colour joins the
 * scheme instead of covering it, and a long field reads as a long run of one
 * ink rather than a slab. The panel's name chip stays a background because it
 * is eleven characters wide and it is the legend: it has to be the strongest
 * statement of "this colour is this row" on the screen, and it can afford to
 * be, because it is short.
 */
/*
 * HOW MUCH OF ONE SUBMISSION IS HELD FOR READING.
 *
 * The collector will send up to sixty-four kilobytes of a script block, and
 * this matches it so that what a reader sees here is what a scanner would get.
 * Two buffers of that size are taken once when a log is opened, not per event:
 * every record can be the big one, so making it conditional would only move
 * the cost to whichever event was selected.
 */

/*
 * A MEGABYTE, NOT THE COLLECTOR'S SIXTY-FOUR KILOBYTES.
 *
 * Matching the collector's spill cap looked right and is the wrong bound: this
 * reads a LOG, and a log holds whatever its producer wrote. Capped at one
 * collector's limit, a submission from any other - or from a later build of
 * this one - was silently shown as a prefix, and a carried image came out
 * 65536 bytes long whatever it really was.
 *
 * Two of these, taken once when a log is opened rather than per event: every
 * record can be the big one, so making it conditional would only move the cost
 * to whichever event was selected.
 */
#define EVT_JOIN_MAX (1024u * 1024u)
#define EVT_TEXT_MAX (1024u * 1024u)

/* ---- how the panel is divided ---------------------------------------------
 *
 * THREE ZONES, because the record has three kinds of thing in it and they want
 * different shapes on screen.
 *
 * The metadata is a table: a dozen short values, each one a number or a word.
 * Laid down the screen one per line it was a tall column of mostly empty rows,
 * and the field a reader had come for - the submission - was pushed off the
 * bottom. Two columns side by side halve that height and waste nothing,
 * because none of these values is wide.
 *
 * The submission is not a table row at all. It is a document: hundreds or
 * thousands of characters that a reader wants to scroll through, select out of
 * and copy. So it gets a box of its own under the table, with the full width
 * and its own scroll, and the table above it stays put while it moves.
 *
 * The warnings sit between them, full width and flush left, because they are
 * about the record as a whole and belong to neither.
 */

/* The object box: tall enough to show a line of context either side of what a
 * reader is looking at, short enough to leave the table and the hex pane their
 * room. */
#define EVT_BOX_ROWS 3

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
 * WHAT THE RULE APPLIES TO, SEEDED FROM THE OBJECT THE FIRST MARKER CAME OFF.
 *
 * That object's format is the one format the reader has already shown they
 * care about. Seeded rather than fixed: everything after this is theirs to add
 * and remove on the Format row.
 *
 * AND THE SUBTYPE WITH IT, FOR A SCRIPT AND NOT FOR AN EXECUTABLE, because the
 * word means different things on the two axes:
 *
 *   - for a script the subtype is the LANGUAGE, and a marker taken out of a
 *     php file is a php marker. Left off, the rule declares no subtype, and a
 *     rule with no subtype is offered every script on the machine - every
 *     python file, every shell script - to be told no. That is the cost the
 *     subtype axis exists to avoid, and paying it by ACCIDENT, because a field
 *     was left blank, is the worst way to pay it.
 *
 *   - for an ELF or a PE the subtype is a LAYOUT VARIANT - relocatable,
 *     executable, shared - and the same bytes routinely appear in all three.
 *     Seeding it there would narrow the rule to whichever kind happened to be
 *     open, and lose the other two silently. So it is not seeded.
 *
 * KV_CAP_TEXT is exactly that line: the formats whose subtype is what the file
 * IS WRITTEN IN rather than how it is laid out.
 */
/* Defined with the event panel, where the record is - see evt_decl_target. */
#define EVT_TARGET_NONE 0xffu

/*
 * Fill and place a chooser.
 *
 * The contents are built here rather than by each caller so that what a list
 * offers stays next to what picking from it does - two halves of one decision,
 * which drift apart the moment they live in different functions.
 */
/*
 * FORMATS BY KIND, because eighteen names in one column is a list nobody reads.
 *
 * The grouping is the reader's question and not the enum's order: somebody
 * adding a format to a rule is thinking "this also applies to documents", not
 * "this also applies to number nine". The enum stays in whatever order the
 * engine needs; this says how to present it.
 *
 * A format missing from every row here would be unreachable, so the last row is
 * a catch-all built by subtraction rather than written out - a format added to
 * the engine turns up under Other until somebody files it, instead of
 * disappearing.
 */
struct fmt_cat {
	/* Which of the engine's groups this row shows - the formats in it and
	 * the word for it both come from there. */
	enum kof_format_group group;
	/*
	 * THIS ROW OPENS LANGUAGES, NOT FORMATS.
	 *
	 * One row has a submenu that is not a list of formats: Scripts holds a
	 * single format and the thing a researcher is choosing between is the
	 * LANGUAGE - php, aspx, jsp. Those are subtypes, so picking one sets the
	 * format AND the subtype together, which is the pair that actually
	 * describes the object. A submenu with one row reading "Script" offered
	 * the reader a click for no information.
	 */
	uint8_t     langs;
};

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
/*
 * A CONDITION IS TWO LINES, IN THE ORDER IT IS DECIDED: the matchers it is made
 * of, and then the tag it finds. A condition no longer names a verdict level or
 * a variant - what an object is called is made from the diseases that matched.
 */
enum cseq_kind { CS_COND = 0, CS_MATCH };

enum prow_kind {
	RW_OPT = 0, RW_RANGES, RW_STRHDR, RW_STR, RW_ADDS, RW_ADDM,
	RW_MATCH, RW_MARKERS, RW_ADDC, RW_COND, RW_CMATCH,
	RW_MATHDR, RW_CNDHDR, RW_CJOIN,
	/* The block table's heading, its column names and its rows - see
	 * draw_decl_blocks, which draws TWO rows before the first block. */
	RW_BLKHDR, RW_BLKCOL, RW_BLK,
	/*
	 * THE SIMILARITY TABLE: its heading, its column names and its three
	 * rows - one per measure. See draw_decl_sim.
	 */
	/* THE DIAGNOSES this file carries - see draw_decl_diag. */
	RW_DIAGHDR, RW_DIAGCOL, RW_DIAG,
	/* The format row and the [+ Options] button - see prow_build. */
	RW_FMTS, RW_OPTBTN,
	/* The title bar of tabs, and the output pane's rows - see
	 * draw_decl_tabs and draw_decl_preview. */
	RW_TABS, RW_PREV
};

#define MENU_W 24

#define PROP_MAX  600
/*
 * BYTES, NOT COLUMNS, and the difference is what cut a table's border.
 *
 * A line carries its own colour escapes and its glyphs may be multi-byte: a
 * 70-column rule drawn from U+2500 is 210 bytes on its own, so at 200 the top
 * and bottom of every wide table lost their right-hand corner while the rows
 * between them - mostly ASCII - fitted and kept theirs. A frame with three
 * sides reads as a drawing bug, which is what it was.
 */
#define PROP_W    512

/* A LINE CARRIES ITS OWN COLOURS, INSIDE ITS TEXT - see prop_put, which draws
 * one. Declared here rather than beside the properties page because more than
 * one dialog builds pages of these. */
struct prop_line {
	char text[PROP_W];
};

/*
 * A page of lines in a box - the shape three dialogs share. Declared here with
 * prop_line because both are the vocabulary of that shared renderer; the
 * renderer itself is defined beside the properties page, which is where its
 * dependencies live.
 */
struct page {
	const char       *title;
	/*
	 * A TAB STRIP IN THE TOP RULE, when the box is two views of one
	 * question rather than one view.
	 *
	 * This existed once and was taken out, because the box was measured
	 * against its content and the two tabs had different content, so it
	 * changed width between the press and the release and left columns
	 * on the screen. That reason is gone - the pages that use this are
	 * `full`, so the width is the terminal's and does not depend on what
	 * is in them - and what replaced it was worse: Tab swapped the whole
	 * body and the title with nothing on screen saying there were two of
	 * anything, so the key read as "go to some other dialog".
	 *
	 * `tab[]` names them, `tab_sel` is the one showing. The title is not
	 * drawn when these are set; the tabs ARE the title.
	 */
	const char       *tab[2];
	int               tab_n;
	int               tab_sel;
	struct prop_line *line;
	uint32_t          n;
	/* The first `fixed` lines stay where they are while the rest scrolls:
	 * a table's tabs, controls and column headings. */
	uint32_t          fixed;
	uint32_t         *off;          /* the caller's scroll; clamped by the draw */
	int               full;         /* fill the screen, or fit the text */
	/* At least this wide, when the lines are narrower: a page whose lines
	 * change as the reader moves must not change its width with them, or
	 * what it was drawn over shows through where it was. */
	int               width;
	int               close;        /* draw a close control */
	int               record;       /* record rows for selection and copy */
	const char       *foot;         /* bottom-rule hint, or NULL */

	/* Written while drawing, read while clicking. */
	int               btn_y, btn_x0, btn_x1;
	int               tab_y, tab_x0[2], tab_x1[2];
	int               top, left, w, h;
	uint32_t          shown;
};

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
	BI_QUIT = 0,
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
	/* The tag sources, as four tables: Analysis is where the tool shows
	 * what it knows, and this is what the diagnose panel's Tag cells pick
	 * from. It needs no object: it is about the directory. */
	BI_SYNTAB,
	/* Label replaced at draw time by the mode's own wording - a menu that
	 * offers "Show" and "Hide" side by side always has one of them wrong. */
	BI_DISASM,
	/* Reads the whole object's code once and names what it finds - see dis_analyse. The panel then shows labels and comments from it. */
	BI_DISANALYSE,
	/*
	 * Where a shellcode loader keeps its payload, shown on demand.
	 *
	 * It runs nothing: the analysis (kofscfind) ran once when the object was
	 * examined and cached its answer on the object, so this item only
	 * displays what is already known. It is a tool analysis - the engine
	 * does not search for loaders.
	 */
	BI_FINDSC,
	/*
	 * WHERE THE INFECTION IS, shown on demand and searched for by nobody.
	 *
	 * The same kind of item as BI_FINDSC and for the same reason: a module
	 * that repairs an infected file had to locate the damage before it
	 * could describe a patch, so the ranges are already in the result. This
	 * displays them.
	 *
	 * IT IS NOT THE VERDICT AND NOT THE REPAIR. The verdict says what the
	 * file has; the repair says how to undo it; this says WHERE, which is
	 * the question a reader looking at the bytes is actually asking - and
	 * the only account there is of the malware's own body, which a repair
	 * deliberately leaves in place.
	 */
	BI_FINDINF,
	/*
	 * The decoder. Beside BI_FINDSC because it answers the same kind of
	 * question - "what is in here that is not in plain sight" - and above
	 * the rules that act, because it only looks.
	 */
	BI_ENCSTR,
	BI_UNPACKER,
	/*
	 * Beside BI_UNPACKER because it is the same machine doing the work -
	 * one runs the object to RECOVER bytes, this one runs it to record
	 * what it ASKED FOR. A reader who has just unpacked something is
	 * exactly the reader who wants the second question answered.
	 */
	/*
	 * TWO DUMPS, AND ONLY ONE OF THEM IS EVER DRAWN.
	 *
	 * BI_DUMP is the executable's: it opens a submenu because there are two
	 * ways to peel such a file - read it, or run it - and which one worked
	 * is the interesting part of the answer.
	 *
	 * BI_DUMP_PLAIN is every other file's. A PDF cannot be run at all; its
	 * members come out by being read and there is no second way, so the
	 * submenu was asking the reader to choose between a thing and nothing.
	 * It acts instead of opening.
	 *
	 * Two ITEMS rather than one that changes shape, because the shape is
	 * what a reader learns: an item that sometimes opens a box and
	 * sometimes fires is an item nobody can predict. Each of these is one
	 * thing, and dump_has_choice decides which exists.
	 */
	BI_DUMP, BI_DUMP_STATIC, BI_DUMP_EMU, BI_DUMP_PLAIN,
	/*
	 * Only ever drawn in the one mode that can use it - see
	 * view.heur_off. Once the children are separated there is nothing for
	 * it to do, and an item that does nothing is hidden rather than
	 * greyed: see the note on `enabled` in kofview.h.
	 */
	BI_SEPARATE,
	BI_REBUILD,
	BI_NEXT, BI_PREV,

	/*
	 * FILTER EVENTS, for a log - a parent with one child per verb and an
	 * Apply below them.
	 *
	 * One slot per possible verb rather than a dynamic list, because
	 * bar_item is a table indexed by this enum and every walk over it -
	 * the drawer, the hit test, the keyboard cursor - agrees only because
	 * they all read the same table. A verb the log does not contain is
	 * hidden by bar_shown, which is the same mechanism that hides Symbols
	 * for an object with none.
	 */
	BI_FILTER,
	BI_FILT_V0, BI_FILT_V1, BI_FILT_V2, BI_FILT_V3, BI_FILT_V4,
	BI_FILT_V5, BI_FILT_V6, BI_FILT_V7, BI_FILT_V8, BI_FILT_V9,
	BI_FILT_V10, BI_FILT_V11, BI_FILT_V12, BI_FILT_V13, BI_FILT_V14,
	BI_FILT_V15, BI_FILT_V16, BI_FILT_V17, BI_FILT_V18, BI_FILT_V19,
	BI_FILT_V20, BI_FILT_V21, BI_FILT_V22, BI_FILT_V23, BI_FILT_V24,
	BI_FILT_V25, BI_FILT_V26, BI_FILT_V27,   /* KOF_EVT_TYPE_COUNT - 2 = 27 verbs */
	BI_FILT_APPLY,

	BI_KEYS, BI_ABOUT,
	BI_COUNT
};

/*
 * A TABLE INSIDE THE DASHBOARD, DECLARED RATHER THAN DRAWN BY HAND.
 *
 * The environment and the connection list are the same widget with different
 * columns: a heading row, a window of rows, and a scroll of its own so a
 * process with forty variables does not push everything below it off the page.
 * Written twice they would drift - one would learn to say how many rows it cut
 * and the other would not - so they are declared, and this draws them.
 *
 * THE SCROLL OFFSET LIVES IN THE VIEW AND IS NAMED BY THE TABLE, because a
 * panel is rebuilt from scratch every frame: an offset kept here would reset
 * to zero on the next keystroke, which is a table that cannot be scrolled at
 * all. Each table names its slot, so adding one is adding an enum value and a
 * declaration - no new drawing code and no new state plumbing.
 *
 * `cell` hands back one column of one row as text it does not own. Returning
 * pointers rather than copying is what lets a caller answer straight out of
 * the record's arena, which is where every string here already lives.
 */
enum prop_tab_id {
	PROP_TAB_FD = 0,
	PROP_TAB_ENV,
	PROP_TAB_NET,
	PROP_TAB_LIB,
	PROP_TAB_COUNT
};
/* The widest a table may be, in columns. The rules are drawn from a glyph that
 * is three bytes, so this is what sizes their buffer. */
#define PROP_TAB_MAX_W 120u

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
/*
 * THE COPY BUTTON'S LABEL, in one place because two things need it: the row
 * that draws it and the click that carries it out.
 *
 * The click finds it by SEARCHING THE DRAWN ROW for this text. That is not the
 * obvious way round - the row could record its own columns - and it is the way
 * round that works: prop_object_rows used to record an index into the full row
 * list while the click path is answered in indices into the rows the page
 * actually put on screen, which begin at the scroll offset. Two different
 * numbers, compared as one.
 */
#define PROP_CP_LABEL "[ Copy full path ]"

/*
 * PICK A FILE OUT OF A DIRECTORY - the first, or the one either side of a name.
 *
 * One walk answering all three questions, because they are one question asked
 * with different comparisons, and two walks are two chances for the ordering to
 * drift. When it drifted the symptom was quiet: the folder opened on the file
 * one rule called first, and the very first step forward skipped it, because
 * the other rule did not think it was a file at all.
 *
 * Ordering is by NAME rather than by whatever readdir hands back, which is the
 * only property that makes forward-then-back return to where it started.
 *
 * `from` is the base name to move away from, and is ignored - may be NULL - for
 * PICK_FIRST. Returns 0 and touches nothing when there is no such file; the
 * caller says so in whatever terms suit where it was called from.
 */
enum { PICK_FIRST = 0, PICK_NEXT = 1, PICK_PREV = -1 };

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
	/*
	 * CTRL+SPACE, which a terminal sends as a NUL byte.
	 *
	 * Named up here rather than passed through as 0, because 0 is this
	 * reader's "no key" - returning the byte closed the program on a chord
	 * nobody had bound. The two meanings needed separating before the key
	 * could be given a job.
	 */
	K_CTRL_SPACE,
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

/*
 * ---- navigating a list that may have submenus -------------------------------
 *
 * ONE KEY TABLE FOR EVERY MENU HERE, because there are two of them and they
 * were drifting. The menu bar grew Left/Right for submenus; the draft panel's
 * choosers grew the same thing again later, spelled separately - two bodies of
 * code that have to agree and nothing making them. What a reader learns
 * pressing one menu has to hold for the other, and that only stays true while
 * the mapping has one home.
 *
 * WHAT IS SHARED IS THE MEANING, NOT THE ACTION. Right is "go inward" in both,
 * but inward opens a submenu in a chooser and, on the menu bar with no submenu
 * under the cursor, steps to the next top-level menu. The caller carries out
 * the intent; it does not get to decide which key produced it.
 */
enum kv_nav {
	KV_NAV_NONE = 0,   /* not a navigation key */
	KV_NAV_PREV,       /* up */
	KV_NAV_NEXT,       /* down */
	KV_NAV_IN,         /* right: into the submenu of the current row */
	KV_NAV_OUT,        /* left: back out to the list this one came from */
	KV_NAV_TAKE,       /* enter */
	KV_NAV_DISMISS     /* escape */
};

/* ---- the shellcode dialog ---------------------------------------------------
 *
 * What "Find shellcode in variables" shows, and it FINDS NOTHING ITSELF.
 *
 * kofscfind ran once when the object was examined and its answer is cached on
 * the object (payload_at, payload_len, payload_bits) - so this dialog reads that
 * answer and shows the bytes it points at. That is the whole design: the test
 * lives in one place, kofscfind.c, where it is measured, and the menu item is a
 * way of asking to see what it concluded rather than a second implementation of
 * it. The engine is not involved: it does not search for loaders.
 *
 * WHY A DIALOG AND NOT A REGION. The bytes are already visible in the hex pane
 * as part of DATA - what is missing is knowing WHICH bytes, and that is one
 * address and one length. A dialog is the shape of "here is the answer to the
 * question you asked", and it closes when the reader is done with it.
 */


/*
 * A CENTRED BOX WITH A SMOOTH BORDER - the frame three dialogs were each
 * drawing for themselves.
 *
 * Find drew no border at all and cleared to the end of the line; Go to drew a
 * full-width box out of G_TL/G_H/G_TR by hand; the properties page has its own
 * inside page_draw. Three implementations of one rectangle, and they disagreed
 * about where a dialog sits - two of them pinned to the bottom edge, which is
 * where a status bar goes, not where a question goes.
 *
 * THE ROWS ARE NOT PRE-FILLED, and that is the constraint the API is shaped
 * around. A frame that painted blank rows for the caller to overwrite would put
 * every row through a blank state inside one frame, which is exactly the
 * flicker-while-typing that find_row's comment records. So a row is opened,
 * written by the caller, and closed - the same three steps goto_row and
 * goto_edge already had, generalised to a box that is not the width of the
 * screen.
 */
struct dframe {
	/*
	 * WHERE THE READER PUT IT, as an offset from where it would otherwise
	 * open.
	 *
	 * An offset and not an absolute position, so a box that has been moved
	 * still follows the terminal when it is resized rather than ending up
	 * off the edge or pinned to a corner. Kept across opens - a reader who
	 * moved the find box out of the way meant it to stay out of the way -
	 * and each box has its own, because they are separate globals.
	 */
	int dx, dy;
	int y, x;                       /* top-left of the box itself */
	int w, h;                       /* including the border */
	int ix;                         /* first column INSIDE, for a row */
	int iw;                         /* columns available inside */
	int btn_y, btn_x0, btn_x1;      /* the close control, or -1 */
	/* What the clip was before the box took it - see dframe_begin. */
	struct out_clip save;
};

/* ===== what the units share: functions ===== */
const char *byte_colour(uint8_t c);
void dis_paint(struct out *o, const char *text);
int hex_top(void);
int hex_bot(void);
int mark_row(void);
int dis_top(void);
int evt_top(void);
int hex_last(void);
int byte_text(uint8_t c);
int literal_safe(const uint8_t *b, uint32_t n);
uint32_t obj_region_bits(const struct object *o, uint32_t *out,
				uint32_t cap);
struct object *cur_obj(struct view *v);
const struct kgenome_func_set *mtn_funcs(struct view *v, struct object *o);
int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user);
void proc_collect(struct view *v, kof_engine *eng, uint32_t pid);
void objects_collect(struct view *v, kof_engine *eng);
const char *sym_byte_colour(const uint8_t *b, uint32_t n, uint64_t off);
int sym_view(const struct view *v);
const uint8_t *sym_block(const struct view *v, uint64_t *n);
uint32_t sym_half(const struct object *o, uint32_t mask,
			 struct kof_range *ext, uint32_t cap, uint64_t *bytes);
uint32_t sym_row_mask(uint8_t which);
uint8_t sym_which_of(uint32_t mask);
uint32_t sym_half_recs(const struct object *o, uint32_t mask,
			      struct kof_range *ext, uint32_t cap,
			      uint32_t *idx, uint32_t idx_cap);
const char *sc_kind(const uint8_t *b, uint32_t n);
void objects_examine_from(struct view *v, kof_engine *eng, uint32_t from);
void objects_examine(struct view *v, kof_engine *eng);
int decl_top(void);
const struct kof_parser *obj_region_vocab(const struct object *o);
void obj_label(const struct object *o, char *out, size_t cap);
void log_scan_verbs(struct view *v);
void log_window(struct view *v);
int log_window_from(struct view *v, uint64_t first);
void tree_build(struct view *v);
uint64_t hex_max(const struct view *v);
int evt_have_rec(const struct view *v);
int evt_live(const struct view *v);
const char *evt_byte_colour(const struct view *v, uint64_t off);
int evt_zones(const struct view *v, int *meta, int *n_meta,
		     int *warn, int *n_warn);
int evt_warn_lines(const struct view *v);
int evt_meta_lines(const struct view *v);
int evt_box_top(const struct view *v);
const char *evt_box_text(const struct view *v, char *buf, size_t cap,
				size_t *len);
int evt_box_total(const struct view *v);
int evt_text_at(const struct view *v, int my, int mx, int *ch);
int evt_meta_at(const struct view *v, int my, int mx);
void evt_reveal_char(struct view *v, int c);
void evt_sync_hex(struct view *v, int reveal);
size_t evt_sel_text(const struct view *v, char *out, size_t cap);
void evt_load(struct view *v);
void view_select(struct view *v);
void goto_node(struct view *v, uint32_t k);
const uint8_t *view_bytes(const struct view *v, uint64_t *n);
uint64_t view_map(const struct view *v, uint64_t at, uint64_t *run);
uint64_t view_unmap(const struct view *v, uint64_t off);
int mtn_kept_any(const struct view *v);
uint32_t mtn_at_byte(const struct view *v);
const char *mtn_lit_at(const struct view *v, uint64_t rgn_off);
void mtn_segment(struct view *v);
void mtn_rescore(struct view *v);
void row_start(struct out *o, int row, int col);
void draw_frame(struct out *o, struct view *v);
void draw_tree(struct out *o, struct view *v);
int in_sel(const struct view *v, uint64_t at);
int decl_kind(struct view *v, uint64_t off);
void sym_flag_str(uint8_t f, char *out);
void sym_shn_str(const uint8_t *r, char *out, size_t n);
uint64_t txt_line_start(struct view *v, const uint8_t *base,
			       uint64_t base_n, uint64_t at);
uint64_t txt_line_end(struct view *v, const uint8_t *base,
			     uint64_t base_n, uint64_t at);
uint64_t txt_line_of(struct view *v, const uint8_t *base,
			    uint64_t base_n, uint64_t at);
uint64_t txt_max_top(struct view *v, const uint8_t *base,
			    uint64_t base_n, int rows);
int txt_bot(const struct view *v);
void draw_text(struct out *o, struct view *v);
int text_under(struct view *v, int row, int col, uint64_t *out,
		      uint64_t *out_line, uint32_t *out_col);
void draft_seed_target(struct view *v);
void txt_hscroll(struct view *v, int by);
uint64_t txt_home_end(struct view *v);
int view_can_text(struct view *v);
void view_toggle_text(struct view *v);
int text_pane(struct view *v);
void draw_hex(struct out *o, struct view *v);
int cmatch_ok(struct view *v, uint32_t c, uint32_t m);
void draft_wipe(struct view *v);
void ch_open(struct view *v, int what, uint32_t arg, int row, int col);
void ch_follow(struct chooser *c);
void ch_take(struct view *v);
int ch_vis(const struct chooser *c);
void draw_chooser(struct out *o, struct view *v);
void prow_build(struct view *v);
void sec_bar(struct out *o, struct view *v, int row, const char *text);
int fsel_range(const struct view *v, uint32_t *lo, uint32_t *hi);
void fsel_clear(struct view *v);
void fsel_set(struct view *v, uint32_t a, uint32_t b);
int field_room(const char *text, const char *ph, int editing, int max);
void field_draw(struct out *o, const char *text, uint32_t caret,
		       uint32_t *off, int room, int editing, const char *ph);
int heur_of(const struct object *ob, struct kof_heur_facts *out,
		   int32_t *score, const char **guess);
int heur_reports(const struct object *ob, int32_t *score,
			const char **guess);
uint64_t dis_hex_shown(const struct view *v);
uint64_t dis_span_of(const struct view *v);
int64_t dis_max_bias(struct view *v);
void dis_follow_hex(struct view *v);
void dis_bias_to_sel(struct view *v);
void dis_span(const struct view *v, uint64_t *at0, int *c0,
		     uint64_t *at1, int *c1);
int dis_hex_sel(const struct view *v);
int dis_cols(const struct view *v, uint64_t at, uint64_t alen, int len,
		    int *from, int *to);
void dis_sync_bytes(struct view *v);
int dis_real_row(const struct view *v, int idx);
unsigned dis_format(struct view *v, uint64_t *at, char *line, size_t cap,
			   uint8_t *bytes_out, unsigned *ix_len_out,
			   int *ok_out, char *text_out, size_t text_cap);
uint64_t dis_sync(struct view *v, uint64_t want);
void draw_evt(struct out *o, struct view *v);
void draw_disasm(struct out *o, struct view *v);
void dis_toggle(struct view *v, uint64_t at, uint64_t len);
void dis_analyse(struct view *v);
void dis_drop_analysis(struct view *v);
int blk_row_shown(const struct view *v, uint32_t i);
int blk_section_shown(struct view *v);
/* The open tab of the diagnose panel, and how tall its output pane is. */
uint32_t preview_rows(const struct view *v);
int mtn_digit(int c);
int at_digit(int c);
void mtn_sync(struct view *v);
uint32_t diag_shown_n(struct view *v);
void draw_decl(struct out *o, struct view *v);
const char *emu_why_tag(uint8_t why);
const char *emu_why_reason(uint8_t why);
void draw_marker_line(struct out *o, struct view *v);
int menu_enabled(struct view *v, int a);
int menu_rows(struct view *v);
int menu_at_row(struct view *v, int row);
void menu_open_at(struct view *v, int row, int col);
void menu_step(struct view *v, int d);
void draw_menu(struct out *o, struct view *v);
void copy_osc52(const char *bytes, size_t n);
void dis_copy(struct view *v);
void copy_said(struct view *v, size_t n);
void copy_offset(struct view *v, int hex);
void decl_edit_open(struct view *v, uint32_t i);
uint8_t evt_decl_target(const struct view *v, uint32_t *mask);
void decl_add_text(struct view *v, const char *text, size_t n,
			  int from_evt);
void decl_add(struct view *v, int hex);
void copy_selection(struct view *v, int as_hex);
void menu_run(struct view *v, int a);
void redraw(struct view *v);
int byte_under(struct view *v, int row, int col, uint64_t *out);
uint32_t node_at(struct view *v, uint32_t obj, uint64_t file_off);
void view_show_in(struct view *v, uint32_t obj, uint8_t sym,
			 uint64_t off, int narrow);
void view_show_decl(struct view *v, const struct decl *d, uint64_t off);
int rx_compile(const char *text, uint8_t *prog, uint32_t cap,
		      uint32_t *n_out, char *err, size_t err_n);
void find_compile(struct view *v);
void find_run(struct view *v, int back);
int bar_has_sub(int i);
int obj_maybe_code(const struct object *o);
int dump_needs_rebuild(const struct view *v, int use_emu);
int bar_enabled(struct view *v, int i);
int bar_col(int m);
void draw_bar(struct out *o, struct view *v);
int bar_item_at(struct view *v, int row, int col);
int vis_cols(const char *s);
void draw_help(struct out *o, struct view *v);
void prop_off(char *out, size_t cap, uint64_t v);
int prop_tab_at(const struct view *v, int row, int col);
int prop_cell_span(const struct view *v, int row, int col,
			  int *c0, int *c1);
uint32_t obj_ancestors(const struct view *v, const struct object *ob,
			      const struct object **out, uint32_t cap);
void prop_build(struct view *v);
void page_draw(struct out *o, struct view *v, struct page *p);
void draw_prop(struct out *o, struct view *v);
const char *base_name(const char *path);
void editor_attach(struct view *v);
void emu_here(struct view *v);
void separate_now(struct view *v);
int tree_has_emu(const struct view *v);
void dump_all(struct view *v, int use_emu);
int dir_pick(const char *folder, const char *from, int which,
		    char *out, size_t cap);
void open_step(struct view *v, int dir);
void rebuild_db(struct view *v);
void bar_enter_sub(struct view *v, int i);
void bar_open_menu(struct view *v, int menu);
void bar_move_item(struct view *v, int dir);
void bar_run(struct view *v, int i);
enum kv_nav kv_nav_key(int key);
int kv_nav_step(int sel, int n, enum kv_nav nav);
size_t paste_src(int k, const char **out);
int key_pending(void);
int read_key(void);
void hex_step(struct view *v, long lines);
void hit_wheel_text(struct view *v, uint32_t arg);
void hit_hwheel_text(struct view *v, uint32_t arg);
uint64_t now_ms(void);
void select_run(struct view *v);
void cnd_id_click(struct view *v, uint32_t g);
void bar_to(struct view *v, int which);
int bar_under(struct view *v);
int symd_rows(void);
void symd_filter_compile(struct view *v);
uint64_t symd_max(struct view *v);
void dlg_close(struct view *v);
void dlg_rec_begin(struct view *v, int y0, int x0);
void dlg_rec_src(struct view *v, uint32_t idx);
int dlg_row_of_src(const struct view *v, int src);
int dlg_col_of_byte(const struct view *v, int row, uint32_t byte);
void dlg_rec_text(struct view *v, const char *plain);
int dlg_span(const struct view *v, int *r0, int *c0, int *r1, int *c1);
void dlg_paint_sel(struct out *o, struct view *v);
int dlg_at(const struct view *v, int row, int col, int *r, int *c);
void dlg_copy(struct view *v);
void draw_symbols(struct out *o, struct view *v);
int symd_click(struct view *v);
void symd_hscroll(struct view *v, int d);
void symd_scroll(struct view *v, int64_t d);
void symd_open(struct view *v);
void enc_do(struct view *v);
void draw_enc(struct out *o, struct view *v);
void enc_open_with(struct view *v, const uint8_t *p, uint32_t n);
size_t enc_sel_text(struct view *v, char *out, size_t cap);
int enc_click(struct view *v, int rclick);
void goto_take(struct view *v);
void draw_goto(struct out *o, struct view *v);
int goto_click(struct view *v);
void draw_find(struct out *o, struct view *v);
int dframe_grab(struct view *v, struct dframe *f);
int find_click(struct view *v);
int click_menu(struct view *v);
void hit_reset(struct view *v);
void hit_zone(struct view *v, int y0, int x0, int y1, int x1,
		     uint8_t btn, void (*fn)(struct view *, uint32_t),
		     uint32_t arg);
void hit_add(struct view *v, int y, int x0, int x1,
		    void (*fn)(struct view *, uint32_t), uint32_t arg);
int hit_run(struct view *v, uint8_t want);
void hit_row_none(struct view *v, uint32_t arg);
void hit_row_addcond(struct view *v, uint32_t arg);
void hit_row_cond(struct view *v, uint32_t g);
void click(struct view *v, int rclick);
int handle_f10(struct view *v, int k);
int handle_bar_key(struct view *v, int k);
int handle_copy_key(struct view *v, int k);
int handle_symd_key(struct view *v, int k);
int handle_enc_key(struct view *v, int k);
int handle_prop_key(struct view *v, int k);
int handle_chooser_key(struct view *v, int k);
void on_drag(struct view *v);
void on_release(struct view *v);
int handle(struct view *v, int k);
int file_open(struct view *v, const char *path, kof_engine *eng);
size_t paste_extern(char *out, size_t cap);

/* ===== what the units share: state ===== */
extern const char *const mtn_colour[MTN_COLOURS];
extern int g_decl_rows;
extern int g_disasm_rows;
extern int g_evt_rows;
extern const char *const opt_word[OPT_COUNT];
extern int g_mx, g_my;
extern int g_wheel;
struct kv_g_fld {
	int      row, col, room;
	uint32_t off, len;
};
extern struct kv_g_fld g_fld;
struct kv_g_fsel { uint32_t lo, hi; };
extern struct kv_g_fsel g_fsel;
extern char   g_clip[8192];
extern size_t g_clip_n;
extern const char *const bar_name[BM_COUNT];
extern struct prop_line g_prop[PROP_MAX];
extern uint32_t         g_n_prop;
extern uint32_t g_prop_tab_off[PROP_TAB_COUNT];
extern uint32_t g_prop_tab_hoff[PROP_TAB_COUNT];
extern int      g_prop_tab_scroll_v[PROP_TAB_COUNT];
extern int      g_prop_tab_scroll_h[PROP_TAB_COUNT];
extern int g_mod_shift;
extern int g_mod_ctrl;
extern struct dframe g_goto_f, g_find_f, g_enc_f;

/* ---- the tag sources: the Syndrome table and the tag chooser ----------------
 *
 * The data is databases/tagsrc.h's - one set of entities loaded from a
 * directory, edited in memory, written back by Save. What is here is the
 * views over it: the table page with a tab for each kind of entity, the
 * Add/Edit form, the pick list (one widget: the tag chooser of the diagnose
 * panel and every multi-select of the tag form), and the result box a Check or
 * a refused Delete speaks in. All four are pages of lines (page_draw) with the
 * clickable spans of each line recorded as it is built (syn_hit).
 */
enum syn_tab { SYN_ACT = 0, SYN_TYP, SYN_FAM, SYN_TAG, SYN_TABS };

/* What a recorded span does. */
enum syn_act {
	SYA_NONE = 0, SYA_TAB, SYA_ROW, SYA_ADD, SYA_EDIT, SYA_DEL, SYA_CHECK,
	SYA_SAVE, SYA_SEARCH, SYA_OK, SYA_CANCEL, SYA_FIELD,
	SYA_PICK, SYA_NEW, SYA_PROW
};

struct syn_hit {
	uint32_t line;          /* the line of the layer */
	int16_t  c0, c1;        /* its printable columns, inclusive */
	uint8_t  act;           /* enum syn_act */
	uint32_t arg;
};

/* One page: its lines, the spans on them and where it was drawn. */
struct syn_layer {
	struct prop_line *line;
	uint32_t          n, cap;
	uint32_t          fixed;        /* lines at the top that do not scroll */
	uint32_t          off;          /* scroll of the rest */
	struct syn_hit   *hit;
	uint32_t          nh, caph;
	int               top, left, w, h;
	uint32_t          shown;
	int               btn_y, btn_x0, btn_x1;
};

/* What a pick list is for. */
enum syn_pick_what {
	PK_NONE = 0, PK_TAG_COND, PK_TAG_GRP, PK_ACT, PK_TYP, PK_FAM, PK_FMT,
	PK_ARCH, PK_SUB
};

#define SYN_FILT 64u

struct syn_prow {
	char     col[4][KOF_TAGSRC_COMMENT_LEN];
	uint64_t id;            /* the entity's, for the tag fields */
	uint16_t idx;           /* the word's, for the attribute fields */
	uint32_t pos;           /* 0 unticked, else the order it was ticked in */
};

struct syn_pick {
	int      open;
	int      what;          /* enum syn_pick_what */
	uint32_t arg;           /* the condition or matcher the tag is for */
	int      multi;
	int      ncol;
	uint32_t ticks;
	char     title[40];
	char     head[4][16];
	char     filt[SYN_FILT];
	uint32_t foff;
	struct syn_prow *row;
	uint32_t n, cap;
	uint32_t *vis, n_vis, cap_vis;  /* the rows the filter lets through */
	uint32_t n_real;        /* of them, the ones that are not "(none)" */
	uint32_t sel;           /* the cursor, in `vis` */
	/* A row (not a `vis` place) the cursor is to start on, or UINT32_MAX:
	 * the filter decides where it is, so it is placed when `vis` is built. */
	uint32_t want;
	struct syn_layer ly;
};

/* The Add/Edit form: a working copy, which the entity gets on OK. */
struct syn_form {
	int      open;
	uint8_t  kind;          /* enum kof_tagsrc_kind */
	int      edit;          /* an existing entity, set index `ent`, or new */
	size_t   ent;
	struct kof_tagent e;
	char     name[KOF_TAGSRC_NAME_LEN];
	char     cmt[KOF_TAGSRC_COMMENT_LEN];
	uint32_t name_off, cmt_off;
	char     err[160];
};

struct kv_syn {
	struct kof_tagset set;
	char     dir[256];
	char     diag_dir[256];
	int      open;          /* the table page is up */
	int      tab;           /* enum syn_tab */
	char     filt[SYN_FILT];
	uint32_t foff;
	uint32_t sel[SYN_TABS];
	uint32_t *rows;         /* set indices the open tab shows */
	uint32_t n_rows, cap_rows;
	struct syn_layer page, res, frm;
	char     res_title[40];
	int      res_open;
	struct syn_form form, parent;   /* parent: the tag form a [+ New] hides */
	int      has_parent;
	struct syn_pick pick;
};

/* kv_syn.c: the lines of a layer and the spans on them. */
void syn_ly_reset(struct syn_layer *ly);
uint32_t syn_ly_line(struct syn_layer *ly);
int  syn_ly_col(const struct syn_layer *ly, uint32_t li);
void syn_ly_put(struct syn_layer *ly, uint32_t li, const char *sgr,
		const char *text);
void syn_ly_hit(struct syn_layer *ly, uint32_t li, int c0, int c1, int act,
		uint32_t arg);

/* kv_syn.c: the model and what the buttons do. */
struct kv_syn *syn_new(const char *dir, const char *diag_dir);
void syn_free(struct kv_syn *s);
void syn_open(struct view *v);
void syn_close(struct view *v);
int  syn_modal(const struct view *v);
int  syn_page_up(const struct view *v);
void syn_rows(struct view *v);
void syn_tab_set(struct view *v, int tab);
void syn_form_open(struct view *v, int kind, int edit);
void syn_form_ok(struct view *v);
void syn_form_cancel(struct view *v);
void syn_form_new(struct view *v, int kind);
void syn_form_pick(struct view *v, int what);
void syn_delete(struct view *v);
void syn_check(struct view *v);
void syn_save(struct view *v);
void syn_pick_tag(struct view *v, int what, uint32_t arg);
void syn_pick_vis(struct view *v);
void syn_pick_home(struct view *v);
void syn_pick_toggle(struct view *v, uint32_t vi);
void syn_pick_ok(struct view *v);
void syn_pick_cancel(struct view *v);
void syn_say(struct view *v, int ok, const char *fmt, ...);
uint32_t syn_dirty(const struct kv_syn *s);
void syn_row_cells(const struct kv_syn *s, const struct kof_tagent *e,
		   int tab, char cell[][160]);

/* kv_syntable.c: drawing, the mouse and the keys. */
void draw_syn(struct out *o, struct view *v);
int  handle_syn_key(struct view *v, int k);
int  syn_click(struct view *v);
void syn_layer_free(struct syn_layer *ly);
int  field_key(struct view *v, char *buf, size_t cap, int k,
	       int (*accept)(int));

/* The title-bar cells of the diagnose panel and of the Syndrome table: one
 * widget. ` Name ` cells with " | " between, the open one reversed; the
 * printable columns of each cell (1-based, inclusive) go to c0 and c1.
 * Returns the length of the text. */
size_t tabbar_text(char *out, size_t cap, const char *const *word, uint32_t n,
		   uint32_t active, int *c0, int *c1);

#endif /* KV_H */
