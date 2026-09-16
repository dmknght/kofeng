/*
 * script_norm.c - see script_norm.h for what this is and what it refuses to be.
 *
 * ONE PASS, LINE BY LINE, WITH THE STRING STATE CARRIED ACROSS.
 *
 * A line is the unit because every operation here is about a line: its indent,
 * whether it is blank, whether it is only a comment, where its brace is. The
 * state machine is carried between lines anyway, because a block comment spans
 * them - and because a line that ENDS inside a string would make every one of
 * those operations wrong, which is what ml_open exists to rule out up front.
 */

#include <string.h>

#include "script_norm.h"

/* ---- the table ------------------------------------------------------------ */

/*
 * BY NAME, NOT BY POSITION.
 *
 * These were positional, so adding a field to the struct meant editing every
 * row - and a row left short takes zeroes for the new fields silently, which
 * for `sq_escapes` is a shell that reads a backslash as an escape and takes the
 * rest of the file into a string. Naming each field makes a missed row a
 * default rather than a shift, and a wrong field a compile error.
 */
static const struct kof_lex lex_php = {
	.line_cmt = { "//", "#", NULL }, .blk_open = "/*", .blk_close = "*/",
	.quotes = "\"'", .ml_open = { "<<<", NULL, NULL },
	.sq_escapes = 1, .stmt_end = ';', .ws_significant = 0,
	.var_sigil = '$', .concat = '.'
};

static const struct kof_lex lex_js = {
	.line_cmt = { "//", NULL, NULL }, .blk_open = "/*", .blk_close = "*/",
	.quotes = "\"'", .ml_open = { "`", NULL, NULL },
	.sq_escapes = 1, .stmt_end = ';', .ws_significant = 0,
	/* No sigil: `foo` is a variable or a function and telling them apart
	 * needs a parse. The folding pass declines - see var_sigil. */
	.var_sigil = 0, .concat = '+'
};

static const struct kof_lex lex_python = {
	.line_cmt = { "#", NULL, NULL },
	.quotes = "\"'", .ml_open = { "\"\"\"", "'''", NULL },
	.sq_escapes = 1,
	.stmt_end = 0,          /* a newline ends a statement */
	.ws_significant = 0, .var_sigil = 0, .concat = '+'
};

static const struct kof_lex lex_perl = {
	.line_cmt = { "#", NULL, NULL },
	.quotes = "\"'", .ml_open = { "<<", NULL, NULL },
	.sq_escapes = 1, .stmt_end = ';', .ws_significant = 0,
	.var_sigil = '$', .concat = '.'
};

static const struct kof_lex lex_ruby = {
	.line_cmt = { "#", NULL, NULL },
	.quotes = "\"'", .ml_open = { "<<~", "<<-", NULL },
	.sq_escapes = 1, .stmt_end = 0, .ws_significant = 0,
	.var_sigil = 0, .concat = '+'
};

/*
 * SHELL, AND THE TWO THINGS THAT MAKE IT DIFFERENT.
 *
 * Whitespace is the argument separator, so nothing is ever closed up; and a
 * backslash inside '...' is a literal backslash, so the next byte is NOT
 * skipped - reading it as an escape would swallow the closing quote and take
 * the rest of the file into a string that never ends.
 */
static const struct kof_lex lex_shell = {
	.line_cmt = { "#", NULL, NULL },
	.quotes = "\"'", .ml_open = { "<<", NULL, NULL },
	.sq_escapes = 0, .stmt_end = 0, .ws_significant = 1,
	.var_sigil = 0, .concat = 0
};

static const struct kof_lex lex_batch = {
	.line_cmt = { "REM", "::", NULL },
	.quotes = "\"", .ml_open = { NULL, NULL, NULL },
	.sq_escapes = 0, .stmt_end = 0, .ws_significant = 1,
	.var_sigil = 0, .concat = 0
};

static const struct kof_lex lex_psh = {
	.line_cmt = { "#", NULL, NULL }, .blk_open = "<#", .blk_close = "#>",
	.quotes = "\"'", .ml_open = { "@\"", "@'", NULL },
	.sq_escapes = 1, .stmt_end = 0, .ws_significant = 0,
	.var_sigil = '$', .concat = '+'
};

/*
 * The "<%" family. One row, because the SYNTAX inside the islands is what this
 * pass sees and all three are C shaped there - see the note in script_parse.c
 * on why the family is handled together.
 */
static const struct kof_lex lex_svr = {
	.line_cmt = { "//", NULL, NULL }, .blk_open = "/*", .blk_close = "*/",
	.quotes = "\"'", .ml_open = { NULL, NULL, NULL },
	.sq_escapes = 1, .stmt_end = ';', .ws_significant = 0,
	.var_sigil = 0, .concat = '+'
};

const struct kof_lex *kof_lex_for(uint8_t script_kind)
{
	switch (script_kind) {
	case KOF_SCRIPT_PHP:    return &lex_php;
	case KOF_SCRIPT_JS:     return &lex_js;
	case KOF_SCRIPT_PYTHON: return &lex_python;
	case KOF_SCRIPT_PERL:   return &lex_perl;
	case KOF_SCRIPT_RUBY:   return &lex_ruby;
	case KOF_SCRIPT_SHELL:  return &lex_shell;
	case KOF_SCRIPT_BAT:    return &lex_batch;
	case KOF_SCRIPT_PSH:    return &lex_psh;
	case KOF_SCRIPT_ASP:
	case KOF_SCRIPT_ASPX:
	case KOF_SCRIPT_JSP:    return &lex_svr;
	/* KOF_SCRIPT_ANY and everything this build has no row for. Not
	 * guessed at - see the header. */
	default:                return NULL;
	}
}

/* ---- the pass ------------------------------------------------------------- */

static int is_ws(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

static int is_word(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

static int at_text(const uint8_t *p, uint32_t n, uint32_t i, const char *t)
{
	uint32_t l = 0;

	if (!t)
		return 0;
	while (t[l])
		l++;
	if (i + l > n)
		return 0;
	return memcmp(p + i, t, l) == 0;
}

static uint32_t text_len(const char *t)
{
	uint32_t l = 0;

	while (t && t[l])
		l++;
	return l;
}

/* Does a line comment start here, and how long is its opener. */
static uint32_t line_cmt_at(const struct kof_lex *lx, const uint8_t *p,
			    uint32_t n, uint32_t i)
{
	int k;

	for (k = 0; k < 3; k++)
		if (at_text(p, n, i, lx->line_cmt[k]))
			return text_len(lx->line_cmt[k]);
	return 0;
}

/*
 * A HEREDOC OPENER IS "<<" AND A LABEL. The label is not decoration - the
 * shell, php, perl and ruby all need it to know where the thing ENDS - so a
 * "<<" with nothing name-shaped after it is not one.
 *
 * Which matters because the openers that begin with "<" are the only ambiguous
 * ones, and they collide with two things that are everywhere:
 *
 *     [] >>>>>>>>> c0d3d by lionaneesh <<<<<<<<<<      an ascii banner
 *     $a << 2                                          a left shift
 *
 * Read as a heredoc, either one makes this pass refuse the whole extent it is
 * in, and a refusal is total: the bytes are kept as they were typed, so the one
 * decorative line in a comment cost the file its entire form. Measured on this
 * corpus: 5 of 76 php shells contain "<<<" and no heredoc anywhere, 914 KB of
 * them, every byte unformed because of a row of angle brackets.
 *
 * ONLY the "<" family is tested this way. Python's \"\"\", a js backtick and
 * PowerShell's @" are openers entire - there is no label to look for and
 * demanding one would let every one of them through.
 */
static int ml_opens_at(const struct kof_lex *lx, const uint8_t *p, uint32_t n,
		       uint32_t i, const char *op)
{
	uint32_t j;

	(void)lx;
	if (!at_text(p, n, i, op))
		return 0;
	if (op[0] != '<')
		return 1;
	j = i + text_len(op);
	/* "<<-EOF" and "<<~EOF" indent-strip the body and are still heredocs. */
	if (j < n && (p[j] == '-' || p[j] == '~'))
		j++;
	while (j < n && (p[j] == ' ' || p[j] == '\t'))
		j++;
	/* The label may be quoted, which is what turns off interpolation. */
	if (j < n && (p[j] == '"' || p[j] == '\''))
		j++;
	return j < n && ((p[j] >= 'a' && p[j] <= 'z') ||
			 (p[j] >= 'A' && p[j] <= 'Z') || p[j] == '_');
}

static int has_multiline(const struct kof_lex *lx, const uint8_t *p, uint32_t n)
{
	uint32_t i;
	int k;

	for (k = 0; k < 3; k++) {
		if (!lx->ml_open[k])
			continue;
		for (i = 0; i < n; i++)
			if (ml_opens_at(lx, p, n, i, lx->ml_open[k]))
				return 1;
	}
	return 0;
}

/*
 * WOULD CLOSING THESE TWO UP MAKE A LONGER TOKEN.
 *
 * "$a + +$b" must not become "$a++$b" and "$a / /re/" must not become a
 * comment. Both are pairs of non-word bytes - but so is "= \"", which closes up
 * perfectly well, so "both non-word" is too blunt a rule and refused far more
 * than it had to.
 *
 * What actually glues is a byte followed by ITSELF - ++ -- // ** << >> && || ::
 * .. == are all of that shape - or a pair that spells a comment opener in this
 * language. Everything else is safe.
 */
static int glues(const struct kof_lex *lx, uint8_t a, uint8_t b)
{
	char pair[3];
	int k;

	if (a == b)
		return 1;
	pair[0] = (char)a;
	pair[1] = (char)b;
	pair[2] = 0;
	if (lx->blk_open && !strcmp(pair, lx->blk_open))
		return 1;
	for (k = 0; k < 3; k++)
		if (lx->line_cmt[k] && !strcmp(pair, lx->line_cmt[k]))
			return 1;
	return 0;
}

/*
 * IS THIS MARKUP RATHER THAN A PROGRAM - asked of bytes, not of a file.
 *
 * WHAT IT IS FOR. The folding pass answers "what does this script build out of
 * its own literals", and the answer is only worth an object when what it built
 * is a PROGRAM. In a pure php shell the html is not written as markup, it is
 * ECHOED from a string - and that string is a constant, so folding joins it and
 * hands over a page of boilerplate. Measured on a shell whose entire body was
 * one echoed page: the fold produced 134 bytes of html, which cleared the
 * 64-byte floor, became the object, and displaced the formed file - so the
 * @system($_GET["c"]) two lines below it never reached the tree at all.
 *
 * THE EVIDENCE IS A CLOSED TAG, TWICE. "<" followed by a letter - or by "/" and
 * a letter - and a ">" within reach of it. Two of them, because one is what an
 * expression like "$a < $b" or a shell redirect produces by accident, and two
 * in the same constant is somebody writing markup.
 *
 * DELIBERATELY NOT A LANGUAGE TEST. A constant holding html is html whichever
 * language assembled it, and asking the lexical table instead would have said
 * nothing about the bytes in hand.
 */
int kof_script_is_markup(const uint8_t *p, uint32_t n)
{
	uint32_t i, tags = 0;

	if (!p || n < 8u)
		return 0;
	for (i = 0; i + 2u < n; i++) {
		uint32_t j;
		uint8_t c;

		if (p[i] != '<')
			continue;
		j = i + 1u;
		if (p[j] == '/')
			j++;
		if (j >= n)
			break;
		c = p[j];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
			continue;
		/*
		 * AND IT HAS TO CLOSE, within a tag's worth of bytes. Without
		 * the bound a single "<" anywhere would find the ">" of a
		 * comparison half a file away and call it a tag.
		 */
		while (j < n && j < i + 64u && p[j] != '>')
			j++;
		if (j < n && j < i + 64u && p[j] == '>' && ++tags >= 2u)
			return 1;
	}
	return 0;
}

enum { ST_OUT = 0, ST_SQ, ST_DQ, ST_BLK };

uint32_t kof_script_norm(const struct kof_lex *lx, const uint8_t *in,
			 uint32_t n, uint8_t *out, uint32_t cap,
			 uint32_t what)
{
	uint32_t i = 0, w = 0;
	int st = ST_OUT;
	/*
	 * DID THE LINE JUST EMITTED END INSIDE A LINE COMMENT - which the brace
	 * rule below has to know and did not. See the note there.
	 */
	int cmt_tail = 0;

	if (!lx || !in || !out || !n || cap < n)
		return 0;
	/*
	 * A MULTI-LINE STRING ANYWHERE MEANS NOTHING IS TOUCHED.
	 *
	 * Every operation below is line shaped, and inside a heredoc a line's
	 * indent is data, a blank line is data and a "#" is data. One cheap scan
	 * up front rather than a second state to get wrong.
	 */
	if (has_multiline(lx, in, n))
		return 0;

	while (i < n) {
		uint32_t ls = i, le, body, start_w = w;
		int only_cmt = 0, blank;
		int resumed = st == ST_SQ || st == ST_DQ;
		int tail = 0;

		/* Where this line ends, newline excluded. */
		le = ls;
		while (le < n && in[le] != '\n')
			le++;

		/*
		 * A STRING THAT IS STILL OPEN OWNS THE LINE, and this is the
		 * case the pass used to assert could not happen.
		 *
		 * It can. A double-quoted php string may hold real newlines -
		 * echoing a block of html is the ordinary way to do it - and
		 * has_multiline does not see one, because it looks for heredoc
		 * and backtick openers and a plain quote is neither. The state
		 * was then thrown away at the end of every line, so the SECOND
		 * line of such a string was walked AS CODE. Measured on a page
		 * echoed from one literal:
		 *
		 *   - its indentation was stripped, its runs of spaces closed
		 *     up and its blank lines dropped - all of it string VALUE;
		 *   - and a line of it reading "// this is not a comment, it is
		 *     text" was DELETED, because at the start of a line a "//"
		 *     is read as a comment. A pass that silently removes a line
		 *     of a file is the one outcome worth never producing.
		 *
		 * So the state carries, and a line that begins inside a string
		 * is copied byte for byte - newline included - until the quote
		 * that closes it. None of the line rules below are asked about
		 * such a line: a blank line is data, an indent is data, and a
		 * comment opener is text.
		 */
		if (resumed) {
			uint32_t j = ls;

			while (j < le) {
				uint8_t c = in[j];

				if (c == '\\' &&
				    (st == ST_DQ || lx->sq_escapes) &&
				    j + 1u < le) {
					out[w++] = c;
					out[w++] = in[j + 1u];
					j += 2u;
					continue;
				}
				out[w++] = c;
				j++;
				if ((st == ST_SQ && c == '\'') ||
				    (st == ST_DQ && c == '"')) {
					st = ST_OUT;
					break;
				}
			}
			if (st != ST_OUT) {
				/* Still open at the end of the line: the
				 * newline is part of the value. */
				if (le < n)
					out[w++] = '\n';
				i = le < n ? le + 1u : le;
				continue;
			}
			/* Closed part way along: what follows is code, and it
			 * is walked below without the line rules. */
			ls = j;
		}

		/*
		 * A BLOCK COMMENT THAT IS STILL OPEN OWNS THE WHOLE LINE.
		 * Nothing on it is code, so it is dropped with the comment
		 * lines - and the close is looked for as the line is walked.
		 */
		if (st == ST_BLK) {
			uint32_t j = ls;

			while (j < le) {
				if (at_text(in, n, j, lx->blk_close)) {
					st = ST_OUT;
					j += text_len(lx->blk_close);
					break;
				}
				j++;
			}
			/* Anything after the close on this line is code and is
			 * kept; a line that is all comment goes. */
			if (st == ST_OUT && j < le)
				ls = j;
			else {
				i = le < n ? le + 1u : le;
				continue;
			}
		}

		/* Leading whitespace: measured either way, dropped on ask. */
		body = ls;
		while (body < le && is_ws(in[body]))
			body++;
		blank = body == le;
		if (blank && !resumed && (what & KOF_NORM_BLANK)) {
			i = le < n ? le + 1u : le;
			continue;
		}
		if (!resumed && (what & KOF_NORM_INDENT))
			ls = body;

		/*
		 * IS THE WHOLE LINE A COMMENT - asked before the line is
		 * walked, and answered by looking at its FIRST content only.
		 *
		 * That is what makes it safe without tracking strings: a
		 * comment opener at the start of a line cannot be inside a
		 * string, because a single-line string cannot reach here from
		 * the line above - see has_multiline. A comment opener in the
		 * MIDDLE of a line is a different question and this pass does
		 * not ask it.
		 */
		if ((what & KOF_NORM_COMMENT) && !blank && !resumed) {
			if (line_cmt_at(lx, in, n, body))
				only_cmt = 1;
			else if (lx->blk_open &&
				 at_text(in, n, body, lx->blk_open)) {
				/* Only when it also closes on this line, or
				 * runs to the end of it. */
				uint32_t j = body + text_len(lx->blk_open);
				uint32_t close = 0;

				while (j < le) {
					if (at_text(in, n, j, lx->blk_close)) {
						close = j +
						    text_len(lx->blk_close);
						break;
					}
					j++;
				}
				if (!close) {
					st = ST_BLK;
					only_cmt = 1;
				} else {
					uint32_t t = close;

					while (t < le && is_ws(in[t]))
						t++;
					only_cmt = t == le;
				}
			}
		}
		if (only_cmt) {
			i = le < n ? le + 1u : le;
			continue;
		}

		/*
		 * A LONE "{" JOINS THE LINE ABOVE IT.
		 *
		 * Not for looks. Allman and K&R are the two ways everyone
		 * writes the same code and they differ in exactly this byte, so
		 * closing it up is what makes one marker match both. Never in a
		 * language where whitespace is syntax - in sh "{" is a command
		 * group and needs the separator it is losing.
		 */
		/*
		 * AND NEVER ONTO A LINE THAT ENDS IN A COMMENT.
		 *
		 * The brace is appended after whatever the line above left, and
		 * what a line comment leaves is "everything to the end of the
		 * line is not code". Joined there the brace is INSIDE the
		 * comment - the block it opened is gone and the program the
		 * form describes is not the program in the file. Found in a
		 * real shell:
		 *
		 *   function Zip($source, $destination) // Thanks to Alix Axel
		 *   {
		 *
		 * became "...$destination)// Thanks to Alix Axel{", and every
		 * brace after it was one level out.
		 */
		if ((what & KOF_NORM_BRACE) && !lx->ws_significant && !resumed &&
		    !cmt_tail &&
		    le == body + 1u && in[body] == '{' && w > 0 &&
		    out[w - 1u] == '\n') {
			w--;                    /* take back the newline */
			/*
			 * AND THE "DID THIS LINE EMIT ANYTHING" MARK MOVES WITH
			 * IT. start_w was taken before this, so after taking
			 * the newline back and writing the brace, w was equal
			 * to it again - the test at the foot of the loop then
			 * read the line as having produced nothing and dropped
			 * the newline that should follow the brace. The next
			 * line was appended to it.
			 */
			start_w = w;
		}

		/* ---- the line itself ---- */
		{
			uint32_t j = ls;

			while (j < le) {
				uint8_t c = in[j];

				if (st == ST_OUT) {
					uint32_t cl;

					if (at_text(in, n, j, lx->blk_open)) {
						st = ST_BLK;
						j += text_len(lx->blk_open);
						continue;
					}
					cl = line_cmt_at(lx, in, n, j);
					if (cl) {
						/* A trailing comment is left
						 * alone - see the header note
						 * on dropping whole lines
						 * only. */
						while (j < le)
							out[w++] = in[j++];
						tail = 1;
						break;
					}
					if (lx->quotes &&
					    strchr(lx->quotes, (int)c)) {
						st = c == '\'' ? ST_SQ : ST_DQ;
						out[w++] = c;
						j++;
						continue;
					}
					if (is_ws(c) &&
					    (what & KOF_NORM_SPACE)) {
						uint32_t e = j;
						uint8_t prev, next;

						while (e < le && is_ws(in[e]))
							e++;
						if (e >= le)
							break;  /* trailing */
						prev = w ? out[w - 1u] : 0;
						next = in[e];
						/*
						 * CLOSED UP UNLESS THE TWO
						 * WOULD BECOME ONE TOKEN.
						 *
						 * Two word bytes glue into one
						 * name. Two bytes that spell a
						 * longer operator glue into it
						 * - see glues. Everything else
						 * closes up, which is the
						 * "eval (" case and also
						 * "$s = \"", where the pair is
						 * non-word on both sides and
						 * perfectly safe.
						 */
						if (!lx->ws_significant && w &&
						    !(is_word(prev) &&
						      is_word(next)) &&
						    !glues(lx, prev, next))
							;       /* closed up */
						else
							out[w++] = ' ';
						j = e;
						continue;
					}
					if (c == '\t')
						c = ' ';
					out[w++] = c;
					j++;
					continue;
				}
				if (st == ST_BLK) {
					if (at_text(in, n, j, lx->blk_close)) {
						st = ST_OUT;
						j += text_len(lx->blk_close);
					} else {
						j++;
					}
					continue;
				}
				/* Inside a string: every byte is a value. */
				if (c == '\\' &&
				    (st == ST_DQ || lx->sq_escapes) &&
				    j + 1u < le) {
					out[w++] = c;
					out[w++] = in[j + 1u];
					j += 2u;
					continue;
				}
				if ((st == ST_SQ && c == '\'') ||
				    (st == ST_DQ && c == '"'))
					st = ST_OUT;
				out[w++] = c;
				j++;
			}
			/*
			 * AND AN OPEN STRING CARRIES TO THE NEXT LINE, which
			 * is the whole of the fix above. This used to reset
			 * it, on the argument that has_multiline had ruled the
			 * case out - it had not, and the reset is what let a
			 * string's second line be walked as code.
			 */
		}

		/* A line that emitted nothing but was not dropped - all of it
		 * was a block comment - leaves no blank behind. */
		if (w == start_w && (what & KOF_NORM_BLANK)) {
			i = le < n ? le + 1u : le;
			continue;
		}
		cmt_tail = tail;
		if (le < n)
			out[w++] = '\n';
		i = le < n ? le + 1u : le;
	}
	return w;
}

/* ---- the folding pass ------------------------------------------------------
 *
 * See the note over kof_script_fold in the header. The shape is a recursive
 * descent over ONE statement that knows four things and no more: a literal, a
 * join, a variable holding a constant, and str_replace over three constants.
 *
 * Everything else evaluates to "not a constant", which is not a failure - it is
 * the answer for most of every script ever written.
 */

#define FOLD_MAX_VARS   64u
#define FOLD_MAX_DEPTH  16u

struct val {
	uint32_t off, n;        /* into the arena - see the note below */
};

struct folder {
	const struct kof_lex *lx;
	const uint8_t *in;
	uint32_t n;

	/*
	 * THE ARENA EVERY CONSTANT LIVES IN, AND VALUES ARE OFFSETS INTO IT.
	 *
	 * Not pointers. The block is grown with realloc and MOVES when it does,
	 * so a struct holding char* would be a use-after-realloc that only
	 * appears on an input big enough to force a growth - which is exactly
	 * the input this pass exists for. Offsets survive the move; pointers
	 * are re-derived at each use and never stored.
	 */
	char    *arena;
	uint32_t a_n, a_cap;

	struct {
		const uint8_t *name;
		uint32_t       name_n;
		struct val     v;
	} var[FOLD_MAX_VARS];
	uint32_t n_var;
};

static int arena_put(struct folder *f, const char *p, uint32_t n)
{
	if (f->a_n + n < f->a_n)
		return 0;
	if (f->a_n + n > f->a_cap) {
		uint32_t want = f->a_cap ? f->a_cap : 4096u;
		char *na;

		while (want < f->a_n + n) {
			if (want > 0x20000000u)
				return 0;
			want *= 2u;
		}
		na = realloc(f->arena, want);
		if (!na)
			return 0;
		f->arena = na;
		f->a_cap = want;
	}
	if (n)
		memcpy(f->arena + f->a_n, p, n);
	f->a_n += n;
	return 1;
}

/* Append a slice of the arena to the arena. Through a bounce buffer would be
 * one copy more; the source is re-read after each growth instead. */
static int arena_put_self(struct folder *f, uint32_t off, uint32_t n)
{
	uint32_t k = 0;

	while (k < n) {
		uint32_t chunk = n - k > 256u ? 256u : n - k;
		char tmp[256];

		memcpy(tmp, f->arena + off + k, chunk);
		if (!arena_put(f, tmp, chunk))
			return 0;
		k += chunk;
	}
	return 1;
}

static int is_name_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	       (c >= '0' && c <= '9') || c == '_';
}

static void skip_ws(const struct folder *f, uint32_t *i)
{
	while (*i < f->n && is_ws(f->in[*i]))
		(*i)++;
}

/* The decoded content of the literal starting at `*i`, which must be a quote. */
static int read_literal(struct folder *f, uint32_t *i, struct val *out)
{
	uint8_t q = f->in[*i];
	uint32_t j = *i + 1u;
	uint32_t start = f->a_n;
	int esc = q == '"' || f->lx->sq_escapes;

	while (j < f->n && f->in[j] != q) {
		uint8_t c = f->in[j];
		char b;

		if (c != '\\' || !esc || j + 1u >= f->n) {
			if (!arena_put(f, (const char *)&c, 1u))
				return 0;
			j++;
			continue;
		}
		/*
		 * "\x41" AND "\101" ARE THE POINT OF THIS. A file that writes
		 * "phar://" as "\160\x68\141\x72\72\57\57" does it so that the
		 * seven bytes never appear, and the decoded form is what a
		 * marker can be written on.
		 */
		{
			uint8_t e = f->in[j + 1u];

			if (e == 'x' || e == 'X') {
				unsigned v = 0, k = 0;

				j += 2u;
				while (k < 2u && j < f->n) {
					uint8_t h = f->in[j];

					if (h >= '0' && h <= '9')
						v = v * 16u + (unsigned)(h - '0');
					else if (h >= 'a' && h <= 'f')
						v = v * 16u + (unsigned)(h - 'a' + 10);
					else if (h >= 'A' && h <= 'F')
						v = v * 16u + (unsigned)(h - 'A' + 10);
					else
						break;
					j++;
					k++;
				}
				if (!k)
					continue;
				b = (char)v;
			} else if (e >= '0' && e <= '7') {
				unsigned v = 0, k = 0;

				j += 1u;
				while (k < 3u && j < f->n &&
				       f->in[j] >= '0' && f->in[j] <= '7') {
					v = v * 8u + (unsigned)(f->in[j] - '0');
					j++;
					k++;
				}
				b = (char)(v & 0xffu);
			} else {
				static const char from[] = "nrtvf";
				static const char to[]   = "\n\r\t\v\f";
				const char *at = strchr(from, (int)e);

				b = at ? to[at - from] : (char)e;
				j += 2u;
			}
		}
		if (!arena_put(f, &b, 1u))
			return 0;
	}
	if (j >= f->n)
		return 0;               /* unterminated: not a constant */
	*i = j + 1u;
	out->off = start;
	out->n = f->a_n - start;
	return 1;
}

static int lookup(const struct folder *f, const uint8_t *name, uint32_t n,
		  struct val *out)
{
	uint32_t k;

	for (k = 0; k < f->n_var; k++)
		if (f->var[k].name_n == n && !memcmp(f->var[k].name, name, n)) {
			*out = f->var[k].v;
			return 1;
		}
	return 0;
}

static int eval(struct folder *f, uint32_t *i, uint32_t depth,
		struct val *out);

/* str_replace(A, B, C): C with every A in it replaced by B. */
static int do_replace(struct folder *f, struct val a, struct val b,
		      struct val c, struct val *out)
{
	uint32_t start = f->a_n, k = 0;

	if (!a.n)
		return 0;               /* replacing nothing would not end */
	while (k < c.n) {
		int same = k + a.n <= c.n &&
			   !memcmp(f->arena + c.off + k, f->arena + a.off, a.n);

		if (same) {
			if (!arena_put_self(f, b.off, b.n))
				return 0;
			k += a.n;
			continue;
		}
		if (!arena_put_self(f, c.off + k, 1u))
			return 0;
		k++;
	}
	out->off = start;
	out->n = f->a_n - start;
	return 1;
}

/* One term: a literal, a variable, or the one call this pass knows. */
static int term(struct folder *f, uint32_t *i, uint32_t depth, struct val *out)
{
	skip_ws(f, i);
	if (*i >= f->n)
		return 0;

	if (f->lx->quotes && strchr(f->lx->quotes, (int)f->in[*i]))
		return read_literal(f, i, out);

	if (f->in[*i] == (uint8_t)f->lx->var_sigil) {
		uint32_t s = *i + 1u, e = s;

		while (e < f->n && is_name_byte(f->in[e]))
			e++;
		if (e == s)
			return 0;
		*i = e;
		return lookup(f, f->in + s, e - s, out);
	}

	/*
	 * str_replace(A, B, C) AND NOTHING ELSE YET.
	 *
	 * It is the one call these generators use to put a cut-up program back
	 * together, and it is safe to apply because all three arguments have to
	 * be constants already - nothing is run and no value from outside the
	 * file is followed.
	 */
	if (*i + 12u <= f->n && !memcmp(f->in + *i, "str_replace(", 12u)) {
		struct val a, b, c;
		uint32_t j = *i + 12u;

		if (!eval(f, &j, depth + 1u, &a))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ',')
			return 0;
		j++;
		if (!eval(f, &j, depth + 1u, &b))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ',')
			return 0;
		j++;
		if (!eval(f, &j, depth + 1u, &c))
			return 0;
		skip_ws(f, &j);
		if (j >= f->n || f->in[j] != ')')
			return 0;
		*i = j + 1u;
		return do_replace(f, a, b, c, out);
	}
	return 0;
}

/* A term, then as many "join term" as follow it. */
static int eval(struct folder *f, uint32_t *i, uint32_t depth, struct val *out)
{
	struct val acc;

	if (depth > FOLD_MAX_DEPTH)
		return 0;
	if (!term(f, i, depth, &acc))
		return 0;

	for (;;) {
		struct val rhs;
		uint32_t save = *i, start;

		skip_ws(f, i);
		if (*i >= f->n || !f->lx->concat ||
		    f->in[*i] != (uint8_t)f->lx->concat) {
			*i = save;
			break;
		}
		(*i)++;
		if (!term(f, i, depth, &rhs)) {
			*i = save;
			break;
		}
		/* The halves are already in the arena and the result has to be
		 * contiguous, so a join is a third copy. That is what keeps the
		 * total bounded by the literals the file contains. */
		start = f->a_n;
		if (!arena_put_self(f, acc.off, acc.n) ||
		    !arena_put_self(f, rhs.off, rhs.n))
			return 0;
		acc.off = start;
		acc.n = f->a_n - start;
	}
	*out = acc;
	return 1;
}

uint32_t kof_script_fold(const struct kof_lex *lx, const uint8_t *in,
			 uint32_t n, uint8_t *out, uint32_t cap)
{
	struct folder f;
	struct val best;
	uint32_t i = 0;

	if (!lx || !in || !n || !out || !cap || !lx->var_sigil)
		return 0;
	memset(&f, 0, sizeof f);
	f.lx = lx;
	f.in = in;
	f.n = n;
	best.off = best.n = 0;

	/*
	 * ONE SWEEP, LEFT TO RIGHT, and that is why no second pass is needed: a
	 * generator writes the pieces before it joins them, so by the time the
	 * join is read every name in it is already known.
	 */
	while (i < n) {
		uint32_t name_s, name_e, at;
		struct val v;

		if (in[i] != (uint8_t)lx->var_sigil) {
			i++;
			continue;
		}
		name_s = i + 1u;
		name_e = name_s;
		while (name_e < n && is_name_byte(in[name_e]))
			name_e++;
		if (name_e == name_s) {
			i++;
			continue;
		}
		at = name_e;
		skip_ws(&f, &at);
		/* An assignment, not a comparison: "==" is not this. */
		if (at >= n || in[at] != '=' ||
		    (at + 1u < n && in[at + 1u] == '=')) {
			i = name_e;
			continue;
		}
		at++;
		if (!eval(&f, &at, 0, &v) || !v.n) {
			i = name_e;
			continue;
		}
		if (f.n_var < FOLD_MAX_VARS) {
			f.var[f.n_var].name = in + name_s;
			f.var[f.n_var].name_n = name_e - name_s;
			f.var[f.n_var].v = v;
			f.n_var++;
		}
		if (v.n > best.n)
			best = v;
		i = at;
	}

	if (best.n > cap)
		best.n = cap;
	if (best.n)
		memcpy(out, f.arena + best.off, best.n);
	free(f.arena);
	return best.n;
}
