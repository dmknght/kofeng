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

static const struct kof_lex lex_php = {
	{ "//", "#", NULL }, "/*", "*/", "\"'",
	{ "<<<", NULL, NULL },
	1,      /* '...' takes \' and \\ - only whether to skip the next byte */
	';', 0
};

static const struct kof_lex lex_js = {
	{ "//", NULL, NULL }, "/*", "*/", "\"'",
	{ "`", NULL, NULL },
	1, ';', 0
};

static const struct kof_lex lex_python = {
	{ "#", NULL, NULL }, NULL, NULL, "\"'",
	{ "\"\"\"", "'''", NULL },
	1,
	0,      /* a newline ends a statement */
	0
};

static const struct kof_lex lex_perl = {
	{ "#", NULL, NULL }, NULL, NULL, "\"'",
	{ "<<", NULL, NULL },
	1, ';', 0
};

static const struct kof_lex lex_ruby = {
	{ "#", NULL, NULL }, NULL, NULL, "\"'",
	{ "<<~", "<<-", NULL },
	1, 0, 0
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
	{ "#", NULL, NULL }, NULL, NULL, "\"'",
	{ "<<", NULL, NULL },
	0, 0, 1
};

static const struct kof_lex lex_batch = {
	{ "REM", "::", NULL }, NULL, NULL, "\"",
	{ NULL, NULL, NULL },
	0, 0, 1
};

static const struct kof_lex lex_psh = {
	{ "#", NULL, NULL }, "<#", "#>", "\"'",
	{ "@\"", "@'", NULL },
	1, 0, 0
};

/*
 * The "<%" family. One row, because the SYNTAX inside the islands is what this
 * pass sees and all three are C shaped there - see the note in script_parse.c
 * on why the family is handled together.
 */
static const struct kof_lex lex_svr = {
	{ "//", NULL, NULL }, "/*", "*/", "\"'",
	{ NULL, NULL, NULL },
	1, ';', 0
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

static int has_multiline(const struct kof_lex *lx, const uint8_t *p, uint32_t n)
{
	uint32_t i;
	int k;

	for (k = 0; k < 3; k++) {
		if (!lx->ml_open[k])
			continue;
		for (i = 0; i < n; i++)
			if (at_text(p, n, i, lx->ml_open[k]))
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

enum { ST_OUT = 0, ST_SQ, ST_DQ, ST_BLK };

uint32_t kof_script_norm(const struct kof_lex *lx, const uint8_t *in,
			 uint32_t n, uint8_t *out, uint32_t cap,
			 uint32_t what)
{
	uint32_t i = 0, w = 0;
	int st = ST_OUT;

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

		/* Where this line ends, newline excluded. */
		le = ls;
		while (le < n && in[le] != '\n')
			le++;

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
		if (blank && (what & KOF_NORM_BLANK)) {
			i = le < n ? le + 1u : le;
			continue;
		}
		if (what & KOF_NORM_INDENT)
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
		if ((what & KOF_NORM_COMMENT) && !blank) {
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
		if ((what & KOF_NORM_BRACE) && !lx->ws_significant &&
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
			 * A STRING CANNOT REACH THE NEXT LINE - has_multiline
			 * ruled out every construct that would let it, so an
			 * open quote here is a malformed file rather than a
			 * span, and carrying the state on would take the rest
			 * of the file into it.
			 */
			if (st == ST_SQ || st == ST_DQ)
				st = ST_OUT;
		}

		/* A line that emitted nothing but was not dropped - all of it
		 * was a block comment - leaves no blank behind. */
		if (w == start_w && (what & KOF_NORM_BLANK)) {
			i = le < n ? le + 1u : le;
			continue;
		}
		if (le < n)
			out[w++] = '\n';
		i = le < n ? le + 1u : le;
	}
	return w;
}
