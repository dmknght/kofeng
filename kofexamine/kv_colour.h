/*
 * kv_colour.h - the colour of every thing the viewer paints.
 *
 * A part of kv.h, included by it and by nothing else; see kv.h for the list of parts.
 */
#ifndef KV_COLOUR_H
#define KV_COLOUR_H



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
/* A button that is drawn and does nothing (the same style the find and decode dialogs give a button that cannot act). */
#define A_BTN_OFF "\033[47;90m"
/* The buttons of the Pathogens form: the affirmative one green, Cancel grey, the destructive one red. */
#define A_BTN_OK  "\033[42;30m"
#define A_BTN_CANCEL "\033[100;97m"
#define A_BTN_DEL "\033[41;97m"
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


#endif /* KV_COLOUR_H */
