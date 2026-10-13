#define _GNU_SOURCE
#include "kv.h"


const char *byte_colour(uint8_t c)
{
	if (c == 0x00)                  return A_B_NUL;
	if (c >= 0x80)                  return A_B_HIGH;
	if (c == 0x09 || c == 0x0a || c == 0x0d || c == 0x20)
					return A_B_WS;
	if (c < 0x20 || c == 0x7f)      return A_B_CTRL;
	return A_B_TEXT;
}

/*
 * Which colour a token of the operand text gets.
 *
 * A classifier and not a parser. genotype's text is regular enough that the
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
 * genotype prints them at the operand's full width, so a push of 34 comes out
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
void dis_shorten(char *t)
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
void dis_paint(struct out *o, const char *text)
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
int hex_top(void)  { return 2; }

/*
 * Bottom-up: the status bar owns the last row, the draft panel the rows above
 * it, and the rule sits between the draft and the hex pane. They were one row
 * short of each other - the rule was being drawn on the draft's header line -
 * which made the two panels look like one.
 */
int hex_bot(void)  { return g_rows - g_decl_rows - 2; }

int mark_row(void) { return g_rows; }

/* The panel's first row. Its heading, which carries the close button, is the
 * row above that, and the row above THAT is left blank as the rule. */
int dis_top(void)  { return hex_bot() - g_disasm_rows + 1; }

int evt_top(void)  { return hex_bot() - g_evt_rows + 1; }

/*
 * The last row the HEX rows may use.
 *
 * Everything about the pane as a whole - the tree, the divider, the rule under
 * both - still asks hex_bot(). Only the things that are about hex BYTES ask
 * this: what fits on screen, which byte a click landed on, how far a page
 * scrolls. Keeping the two questions apart is what lets the panel open without
 * the tree changing height.
 */
int hex_last(void)
{
	if (g_disasm_rows)
		return dis_top() - 2;
	if (g_evt_rows)
		return evt_top() - 2;
	return hex_bot();
}



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
/*
 * A byte that reads as text - what a person is LOOKING AT.
 *
 * Narrower than literal_safe, which is about what can be WRITTEN DOWN: a tab or
 * a newline can be spelled in a literal and cannot be drawn in a hex pane's
 * text column, where they would move the cursor rather than fill a cell. The
 * two were the same set and the comment here said so; they answer different
 * questions and one of them has since grown.
 */
int byte_text(uint8_t c)
{
	return c >= 0x20u && c <= 0x7eu;
}

/*
 * AND THE THREE WHITESPACE BYTES, which this used to refuse.
 *
 * A marker is bytes and a marker that crosses a line has a newline in it.
 * Taking "outside printable ASCII" as "cannot be a literal" meant a selection
 * that happened to include the line ending was refused while the same text
 * without it was accepted - so one string could be declared or not depending on
 * where a drag stopped, with nothing said either way. decl_put_literal writes
 * them as \t \n \r and ksigbuilder reads them back.
 *
 * Everything else outside printable ASCII is still not a literal. Hex is the
 * honest form for it, and the menu offers that instead.
 */
int literal_safe(const uint8_t *b, uint32_t n)
{
	uint32_t i;

	if (!n)
		return 0;
	for (i = 0; i < n; i++) {
		if (b[i] == '\t' || b[i] == '\n' || b[i] == '\r')
			continue;
		if (b[i] < 0x20u || b[i] > 0x7eu)
			return 0;
	}
	return 1;
}
