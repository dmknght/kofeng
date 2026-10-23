#ifndef KGENOME_TEXTUAL_LANG_H
#define KGENOME_TEXTUAL_LANG_H

/*
 * textual_lang.h - what a language gives the part: its name, its id and its lexer.
 *
 * Private to the family. A language directory includes this and textual_private.h and
 * defines one const row; nothing outside the family sees either.
 */

#include "textual_private.h"

/*
 * HOW A LANGUAGE WRITES A LITERAL whose value is given: the delimiter and what each byte of the value is written as, so that reading the literal
 * back (the row's `value`) gives exactly the bytes and the lexer sees ONE string. Everything a byte can be is data here, in this order:
 *   - `refuse`, `seq`, `refuse_ctl`: the value cannot be written at all (the whole literal is not written: the text keeps the expression). A byte
 *     the literal cannot hold (a line break in a vbscript string), a sequence that would end the host (a page's "%>": an island ends at the first
 *     one, a string or not; `seq`), or any control byte when the host language may be one of several that spell it differently (asp: vbscript or jscript).
 *   - `q`: the delimiter. In `dbl` languages it is written twice (vbscript, powershell's single quotes, coldfusion), and `twice` names other bytes
 *     written twice the same way (coldfusion's "#"); there is no escape in these.
 *   - `bs`: bytes written as a backslash and the byte (the delimiter, the backslash, a "$" in a tcl word).
 *   - `letters`: pairs (letter, byte) as a row's `simple` has them: a byte the pair names is written as a backslash and the letter ("\n").
 *   - `ctl`: the other bytes below 0x20, and 0x7f, in the form the language reads exactly: 'x' two hex digits, 'u' four, 'o' three octal digits,
 *     'd' three decimal digits; 0 writes them as they are (php, perl and ruby single quotes hold any byte but the delimiter and the backslash).
 * Bytes from 0x80 are written as they are.
 */
struct kgenome_textual_quote {
	uint8_t     q;
	uint8_t     dbl;
	uint8_t     ctl;
	uint8_t     refuse_ctl;
	const char *bs;
	const char *letters;
	const char *twice;
	const char *refuse;
	const char *seq;        /* sequences the value must not hold: NUL-separated, ended by an empty one ("a\0b\0" is two) */
	/* A language with no literal (batch: a value is written into the text as it is): the only bytes it may write that way, and q is 0. The value is refused when it holds another, and when it is empty. */
	const char *plain;
};

/* The sequences a literal in a page's island must not hold: "%>" ends the island wherever it stands, a string included, and "</script" ends a server
 * script element the same way. */
#define KGENOME_TEXTUAL_PAGE_SEQ "%>\0</script\0"

/* The comment spellings of a row's `gap_comments`. */
#define KGENOME_TEXTUAL_GAP_HASH  1u    /* "#" to the end of the line */
#define KGENOME_TEXTUAL_GAP_LINE  2u    /* "//" to the end of the line */
#define KGENOME_TEXTUAL_GAP_BLOCK 4u    /* the C block comment */

struct kgenome_textual_lang {
	const char *name;
	uint32_t    id;                 /* enum kgenome_textual_lang_id */
	/*
	 * HOW THE TEXT IS WALKED, by what the row says and in this order (kgenome_textual_lex): a PAGE (markup with "<%" islands: asp, aspx, jsp)
	 * is walked by kgenome_textual_page_lex over the row's `page`; a language that is ONE of the shared lexers (vbs: vb; js: ecma with its
	 * flags) is `whole`; any other language walks the text with its own `lex`, which reads lx->p / lx->n, moves lx->pos and delivers spans
	 * through kgenome_textual_emit (the driver finishes the last span). A row sets one of the three: the first two are data, and the
	 * driver is the only caller of the layer they name.
	 */
	void      (*lex)(struct kgenome_textual_lexer *lx);
	const struct kgenome_textual_page        *page;
	const struct kgenome_textual_script_lang *whole;
	/* Would closing up white space between these two bytes make one token of two: "+" "+",
	 * "?" ">". The form keeps a space where this says yes (and where both are name bytes). */
	int       (*glue)(uint8_t a, uint8_t b);
	/* A "{" alone on a line joins the line above. Not for a language where a line break
	 * ends a statement or white space is syntax. */
	uint8_t     join_brace;
	/* Asked before a lone "{" joins (when join_brace): `out` holds the `n` bytes written before the line break in front of
	 * it. 0 keeps the line break, for a language where it may be a statement's end (js: "return\n{"). NULL: always joins. */
	int       (*join_ok)(const uint8_t *out, uint32_t n);
	/* A comment is a gap, and a line break where this says its bytes `c` (the whole comment) hold one that ends a
	 * statement: js's block comment across lines. NULL: always a gap. */
	int       (*comment_break)(const uint8_t *c, uint32_t len);
	/* White space between two tokens is part of the syntax - sh: "ls -la" is not "ls-la" - so it is
	 * kept as one space wherever there was any, and `glue` is not asked. */
	uint8_t     ws_significant;
	/* A byte and the line break after it join two lines (sh, python: the backslash; powershell: the backtick): the break
	 * stays where it is and is not one of the line breaks a form collapses. 1 is the backslash, which is what the rows that
	 * were written first say; any other value is the byte itself. The byte also escapes the one after it. */
	uint8_t     continuation;
	/* VBScript's line rules (vbs): a "_" that is a word of its own and ends its line joins the next line to
	 * it (kgenome_textual_vb_cont) - the break after it stays, and a blank line after it still ends the
	 * statement, so it is not collapsed - and a lone CR is a line break, as the vb lexer reads it. */
	uint8_t     vb_lines;
	/* Code lives in islands: a tag opens one and a tag closes it (php's "<?php" and "?>"), and an
	 * island that held no code goes, tags and all. Not for a language whose one tag is the line that
	 * names its interpreter. */
	uint8_t     islands;
	/* A string that interpolates may spell a byte as an escape (\x41, \101); where the language's escapes
	 * say that plainly the form writes the byte itself (the driver is textual_unescape.c; in sh a double
	 * quoted "\x41" is a backslash and four characters, and has no hook). A language's escapes are its
	 * own - python: exactly two hex digits, \u and \U in a str and not in bytes, octal up to \377, a quote
	 * that is a delimiter in one string and not in another - so the hook gives the driver the function that
	 * reads one escape and the bytes it reserves, and no more: `s` is the whole span, `len` its length and
	 * `open_len` the prefix and quote in front; it writes at most `len` bytes into `out` and answers how
	 * many. Asked for a string that has F_INTERP. */
	uint32_t  (*unescape_str)(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);
	/* A closing tag that follows a literal which was not closed - a text block, a block comment, a verbatim
	 * string: it runs to the tag - gets no line break in front of it, because the break would be part of the
	 * literal and the form never changes one. Not for a language whose open string ends at the line anyway
	 * (the break is then harmless, and what is written today stays). jsp. */
	uint8_t     open_tail;
	/* Python's line rules: a lone CR is a line break, and a continuation backslash takes "\r\n" and
	 * "\r" as its break as well as "\n" (the interpreter reads every ending the same way). */
	uint8_t     universal_eol;
	/* THE SPELLINGS OF A COMMENT THAT THE FORM STEPS OVER between two tokens (kgenome_tform_skip_gap: what follows a literal, what follows a name that may begin a call). A
	 * mask of KGENOME_TEXTUAL_GAP_*; 0 steps over none. It was "#", "//" and the block comment for every language, and in javascript, vbscript, java, c# and coldfusion "#" is
	 * code, in python "//" and the block opener are operators: a line of n literals each followed by one of them walked to the end of its line n times, n^2/2 steps (L7
	 * of the lexer audit), and what the form did after the false comment - no join, no call taken - was wrong as well. lua ("--"), batch and vbscript spell their comments
	 * in ways this does not read, and have 0. */
	uint8_t     gap_comments;
	/* A vertical tab and a form feed are bytes of a word, not blanks (sh: only space, tab and newline end a word; a CR is read as a blank, for CRLF files). The form
	 * keeps them as the code they are: `echo a<VT># b; id` has the word `a<VT>#`, and with the VT closed up to a blank `# b; id` was a comment (L14 of the lexer audit). */
	uint8_t     word_vt_ff;
	/* Would a blank in front of `next` change what the code written so far (its last `n` bytes, `tail`: white space left out except between two words) says? perl: the blank
	 * in `print FH (1)`, where FH is a handle, and `print FH(1)`, a call of FH (L16 of the lexer audit). Asked where `glue` is, with what `glue` cannot know - the word
	 * before the last one. NULL: nothing. */
	int       (*glue_tail)(const uint8_t *tail, uint32_t n, uint8_t next);
	/* A "#!" line at byte 0 names the interpreter: the lexer calls it a comment (it is one), the form keeps it
	 * - the line is how the script says what it is, and a pass that kept it before (the parser's header) must
	 * not lose it. sh delivers it as a tag and does not need this. */
	uint8_t     keep_hashbang;
	/* The byte that joins two string literals into one (php ".", js and java and c# "+", vb "&"), 0 for none; and
	 * whether two literals side by side are joined too (python's "a" "b"). What a decoder is put over is the join. */
	uint8_t     concat;
	uint8_t     concat_adjacent;
	/* A "." in front of a name makes it a member of something else (javascript, python, lua, vbscript): `obj.chr(65)` is that object's method and not the
	 * function of the table. Not php and perl, whose "." joins strings and may stand in front of a call (`'a'.chr(65)`). */
	uint8_t     member_dot;
	/* The join is read (a decoder is offered a joined payload) but a literal is never WRITTEN as the join: the form cannot tell
	 * the language's expression from a command's arguments (powershell: Write-Host "a" + "b" has three), so one literal
	 * would be wrong where it matters. */
	uint8_t     nofold;
	/*
	 * php's two spellings of what is one thing, written one way. "echo" and "print" are constructs that take their
	 * argument with or without brackets - `echo "x"` and `echo("x")` - and the form writes the call: the bracket is
	 * opened in front of the argument and closed at the ";" (or where the block or the text ends) that ends it. And a
	 * double-quoted literal that says nothing a single-quoted one does not (no "$", no backslash, no "'" in it) is
	 * written single-quoted, so that the same text is the same bytes whichever way it was typed.
	 */
	uint8_t     echo_call;
	uint8_t     norm_quote;
	/* "<<<LABEL" and a line break open a text that runs to its closing label (php). The form writes no line break right behind a label that follows "<<<" -
	 * the text it was made from had something between them, or it would not be code - because that break would make the heredoc. */
	uint8_t     heredoc_eol;
	/*
	 * The decoders a literal is put through, from the code in front of it. `tail` holds the last
	 * `n` bytes of code, white space and comments left out, ending where the literal begins.
	 * Writes the kgenome_textual_decoder of each call that wraps the literal as its first
	 * argument, innermost first, into `chain` (room for `cap`), and answers how many. NULL for
	 * a language with no such calls known. `*from` is where in `tail` the outermost of those calls begins, so that the form can
	 * take the calls back out of what it wrote once the literal they wrap has been decoded.
	 */
	uint32_t  (*call_chain)(const uint8_t *tail, uint32_t n, uint8_t *chain, uint32_t cap, uint32_t *from);
	/* The same, for a language whose decoders are called as "name(" - the list and the few spellings that differ (case, "module.name",
	 * "$", a receiver) are data, and kgenome_textual_call_chain reads them. Set `call_chain` instead when the calls are not that shape
	 * (perl's "::" qualifier, java's methods); when both are NULL the language has no decoder it can call by name. */
	const struct kgenome_textual_call_style *calls;
	/*
	 * The VALUE of a string literal of this language (kgenome_textual_value). `lit` is the span's bytes with the
	 * delimiters. Writes at most len - open_len - close_len bytes to `out` and the count to `*n`; answers 0 when the
	 * literal has no value the text gives. NULL: the lib does not know this language's literals.
	 */
	int       (*value)(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			   uint8_t *out, uint32_t *n);
	/* Is this STRING span (`s`, `len` bytes, `open_len` of them its opening delimiter) a literal whose value is the bytes
	 * between its delimiters. 0 keeps it from being handed to a decoder: a js string with an escape, a template with a
	 * ${ }, a regular expression. `chain` is what call_chain wrote for it, so that a literal one decoder cannot read as the
	 * language's own is kept from it (js: "+" under a url decoder, which urldecode turns into a space and decodeURIComponent
	 * does not). NULL: every string is. */
	int       (*payload_ok)(const uint8_t *value, uint32_t len, const uint8_t *chain, uint32_t n_chain);
	/* The functions of bytes a script of this language builds a value with, by name (kgenome_textual_fn_find). `fn_fold`:
	 * the language does not tell cases of a name apart (php). NULL: none known. */
	const struct kgenome_textual_fn_table *fn_table;
	uint8_t                                fn_fold;
	/* The bytes of a TAG span (`close`: one that leaves the language) that are the tag's own, where the span holds more: php's "<?php" takes the one white
	 * space after it and its "?>" the line break (kgenome_textual_islands ends an island at the closing tag's own bytes). NULL: the whole span is the tag. */
	uint32_t  (*tag_own)(const uint8_t *tag, uint32_t len, int close);
	/* HOW A LITERAL WHOSE VALUE IS GIVEN IS WRITTEN (textual_subst.c writes it; its inverse is `value`). Data, read by
	 * kgenome_textual_subst and by nothing else; NULL: the language has no literal this lib will write, and a value is never put
	 * into its text (sh, batch: see the row). */
	const struct kgenome_textual_quote *quote;
	/* A command language's reader of words, commands and assignments (textual.h, "THE WORDS OF A COMMAND LANGUAGE"): sh, batch, tcl. NULL: the language has no words. */
	const struct kgenome_textual_cmd_syntax *cmd;
};

struct kgenome_textual_cmd_syntax {
	uint32_t (*word)(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk);
	int      (*command)(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c);
	uint32_t (*assigns)(const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max);
};

/* The decoders that wrap a literal, innermost first (the row's call_chain or its `calls`); 0 and `*from` = n for a language with neither. */
uint32_t kgenome_textual_lang_chain(const struct kgenome_textual_lang *l, const uint8_t *tail, uint32_t n, uint8_t *chain,
				    uint32_t cap, uint32_t *from);

/* The `glue` of a row whose white space is syntax (`ws_significant`: sh, tcl, ruby, powershell, batch): the form does not ask it for those,
 * and where it does (the gap in front of markup that followed a comment) a gap is kept. */
int kgenome_textual_glue_always(uint8_t a, uint8_t b);

/* Does the chain (what call_chain wrote, innermost first) hold the decoder `dec` anywhere: what a row's `payload_ok` asks. */
static inline int kgenome_textual_chain_has(const uint8_t *chain, uint32_t n_chain, uint8_t dec)
{
	uint32_t k;

	for (k = 0; k < n_chain; k++)
		if (chain[k] == dec)
			return 1;
	return 0;
}

/* The byte a row's `continuation` names: 0 for none, the backslash for 1, otherwise the value. */
static inline uint8_t kgenome_textual_cont_byte(const struct kgenome_textual_lang *l)
{
	return l->continuation == 1u ? (uint8_t)'\\' : l->continuation;
}

/* The row of the expansion operator written at in[p..limit): see textual_cmd.c. */
int kgenome_textual_expand_at(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t p, uint32_t limit, int prefix, uint32_t *len);

/* The row for an id, or NULL when this build has none. The one place languages are listed. */
const struct kgenome_textual_lang *kgenome_textual_lang_find(uint32_t id);

#endif /* KGENOME_TEXTUAL_LANG_H */
