#ifndef KGENOME_TEXTUAL_PRIVATE_H
#define KGENOME_TEXTUAL_PRIVATE_H

/*
 * textual_private.h - what the textual family's files share and nobody else reads: the
 * state of one lex and the one way a span is delivered.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <kofcore.h>

#include "textual.h"

struct kgenome_textual_lexer {
	const uint8_t *p;
	uint32_t       n;
	uint32_t       pos;             /* the first byte not yet in a span */
	kgenome_textual_sink sink;
	void          *user;
	/* The span being grown. Runs of code, and runs of markup, are one span each: the
	 * lexer says "these bytes are code" per token and the driver joins neighbours. */
	struct kgenome_textual_span pend;
	uint8_t        have_pend;
	uint8_t        refused;
	uint8_t        fragment;        /* KGENOME_TEXTUAL_FRAGMENT: lex from inside the language */
	uint32_t       n_span, n_open;
	uint32_t       n_bound;         /* work bounds that fired (kgenome_textual_lex_res.n_bound) */
	/* A page host's own memo, 0 at the start (jsp: 1 once an EL expression failed to close, which
	 * switches EL tracking off for the rest of the text so the scan stays linear). */
	uint32_t       aux;
};

/*
 * The next `len` bytes, [lx->pos, lx->pos + len), as one span of `kind`. Spans are
 * contiguous by construction - there is no offset to pass - so a lexer cannot leave a gap.
 * A CODE or MARKUP span with no flag joins the one before it when that was the same kind.
 * Answers 0 once the sink has refused, and a lexer stops on it.
 */
int kgenome_textual_emit(struct kgenome_textual_lexer *lx, uint32_t len, uint8_t kind, uint8_t flags,
		 uint32_t open_len, uint32_t close_len);

/* ASCII case folding for a name that is lower case letters, digits and "_" in `s`; `p` is as typed. A byte of `s` that is a letter folds `p`; any other byte of
 * `s` (a digit, "_", "(", " ") must be `p` itself: setting bit 5 of `p` is a test for a letter and not a fold, and made 0x13 equal "3" and 0x08 equal "(". */
static inline int kgenome_textual_ci_eq(const uint8_t *p, const char *s, uint32_t n)
{
	uint32_t k;

	for (k = 0; k < n; k++) {
		uint8_t t = (uint8_t)s[k];

		if ((uint8_t)(t - 'a') < 26u ? (uint8_t)(p[k] | 0x20u) != t : p[k] != t)
			return 0;
	}
	return 1;
}

/* A byte that can be in a name: letters, digits, "_" and anything 0x80 or above. */
static inline int kgenome_textual_ident(uint8_t c)
{
	return kof_is_alpha(c) || kof_is_digit(c) || c == '_' || c >= 0x80u;
}

/* The byte that closes a literal opened by `o` where the delimiter is the programmer's (ruby's %q(...), perl's q{...}): a bracket's partner,
 * any other byte itself. */
static inline uint8_t kgenome_textual_close_of(uint8_t o)
{
	return o == '(' ? (uint8_t)')' : o == '[' ? (uint8_t)']' : o == '{' ? (uint8_t)'}' : o == '<' ? (uint8_t)'>' : o;
}

/* A byte a name may START with: a letter, "_" or anything 0x80 or above - a name byte that is not a digit. */
static inline int kgenome_textual_ident_start(uint8_t c)
{
	return kgenome_textual_ident(c) && (uint8_t)(c - '0') >= 10u;
}

/* Two of the questions every row's `glue` asks about a pair of bytes: is it an operator byte of `set` TWICE ("+ +", "< <": closing up
 * makes ++ and <<), and is it one followed by "=" ("+ =": +=). */
static inline int kgenome_textual_glue_twice(uint8_t a, uint8_t b, const char *set)
{
	return a == b && kof_byte_in_set(a, set);
}

static inline int kgenome_textual_glue_assign(uint8_t a, uint8_t b, const char *set)
{
	return b == '=' && kof_byte_in_set(a, set);
}

/* A blank that is not a CR: space, tab, VT, FF. Where a CR is a line break (vbscript, tcl, javascript) this is the white space of a line. */
static inline int kgenome_textual_hblank(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\v' || c == '\f';
}

/* White space inside a line: the bytes that separate tokens without ending a line. */
static inline int kgenome_textual_blank(uint8_t c)
{
	return kgenome_textual_hblank(c) || c == '\r';
}

/* A blank in the language the row `word_vt_ff` is set for (sh): a vertical tab and a form feed are bytes of a word there - only space, tab and newline end one, and a CR is a blank for the
 * CRLF files - so they are not blanks to the form and not to the lexer either (bash: `cat <<VT EOF` waits for the line "VT EOF"). ONE definition for the form's skip of white space
 * (textual_form.c) and sh_lex.c's skip before a here-document's delimiter, which kept the wider set and read `<<\vEOF` as a delimiter "EOF" (heredoc_op, found by the audit that
 * found L14). `word_vt_ff` is the row's own flag: 0 gives kgenome_textual_blank. */
static inline int kgenome_textual_blank_in(uint8_t c, int word_vt_ff)
{
	return kgenome_textual_blank(c) && !(word_vt_ff && (c == '\v' || c == '\f'));
}

/* The first byte of a name in the command languages (sh, batch, tcl): an ASCII letter or "_"; a following byte is kof_is_word_byte. */
static inline int kgenome_textual_name_start(uint8_t c)
{
	return kof_is_alpha(c) || c == '_';
}

/* The state of a word reader that gives literal pieces to a sink (sh and batch read a word the same way: the text, its end and whether the sink
 * has refused a piece), and the one way a piece is handed over. */
struct kgenome_textual_wst {
	const struct kgenome_textual_lang *l;
	const uint8_t *in;
	uint32_t limit;
	const struct kgenome_textual_word_sink *sk;
	int ok;
	uint8_t deep;           /* a group was nested past KGENOME_TEXTUAL_SH_DEPTH (sh) */
};

static inline void kgenome_textual_wst_lit(struct kgenome_textual_wst *s, const uint8_t *p, uint32_t n)
{
	if (s->ok && s->sk && n && !s->sk->lit(s->sk->user, p, n))
		s->ok = 0;
}

/* A line break byte: CR or LF. */
static inline int kgenome_textual_eol_byte(uint8_t c)
{
	return c == '\n' || c == '\r';
}

/* One line break at `i`: "\r\n", "\r" or "\n". Its length, or 0. */
static inline uint32_t kgenome_textual_eol_at(const uint8_t *p, uint32_t n, uint32_t i)
{
	if (i >= n)
		return 0;
	if (p[i] == '\n')
		return 1;
	if (p[i] == '\r')
		return i + 1u < n && p[i + 1u] == '\n' ? 2u : 1u;
	return 0;
}

/* Past a backslash at `i` and the byte it escapes; "\r\n" is one byte for this, and a backslash at the end takes nothing. */
static inline uint32_t kgenome_textual_skip_escape(const uint8_t *p, uint32_t n, uint32_t i)
{
	if (i + 1u >= n)
		return n;
	return i + 2u + (p[i + 1u] == '\r' && i + 2u < n && p[i + 2u] == '\n');
}

/* The code from where the last span ended to `i`, as a span of its own: what comes before a token. */
static inline int kgenome_textual_code_to(struct kgenome_textual_lexer *lx, uint32_t i)
{
	return kgenome_textual_emit(lx, i - lx->pos, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}

/* The text from where the last span ended to `i`, as markup: what comes before a tag, an island or a page's end. */
static inline int kgenome_textual_markup_to(struct kgenome_textual_lexer *lx, uint32_t i)
{
	return kgenome_textual_emit(lx, i - lx->pos, KGENOME_TEXTUAL_MARKUP, 0, 0, 0);
}

/* The first line break (CR or LF) in [i, end), or `end`: where a line comment stops. */
static inline uint32_t kgenome_textual_line_end(const uint8_t *p, uint32_t end, uint32_t i)
{
	while (i < end && p[i] != '\n' && p[i] != '\r')
		i++;
	return i;
}

/*
 * A LITERAL OR A COMMENT, delivered: the code in front of `at`, then [at, to) as one span of `kind`. What every lexer writes when
 * it has found where one ends, so the pair is spelled once. `closed` clear is a literal or a comment the text did not close: it
 * is F_OPEN and has no closing delimiter (`close_len` is ignored). Inline, because the arguments are constants at every call
 * and the lexers' loops are hot.
 */
static inline int kgenome_textual_span_at(struct kgenome_textual_lexer *lx, uint32_t at, uint32_t to, uint8_t kind,
					  uint8_t flags, uint32_t open_len, uint32_t close_len)
{
	return kgenome_textual_code_to(lx, at) && kgenome_textual_emit(lx, to - at, kind, flags, open_len, close_len);
}

static inline int kgenome_textual_lit(struct kgenome_textual_lexer *lx, uint32_t at, uint32_t to, uint8_t kind,
				      uint8_t flags, uint32_t open_len, uint32_t close_len, int closed)
{
	return kgenome_textual_span_at(lx, at, to, kind, (uint8_t)(closed ? flags : flags | KGENOME_TEXTUAL_F_OPEN), open_len,
				       closed ? close_len : 0u);
}

/* Past the quoted string that starts at `j`, a backslash escaping the next byte; 0 when it does not close. */
static inline uint32_t kgenome_textual_skip_quoted(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint8_t q = p[j++];

	while (j < n) {
		if (p[j] == '\\')
			j += 2u;
		else if (p[j] == q)
			return j + 1u;
		else
			j++;
	}
	return 0;
}

/* ---- what several languages share ----------------------------------------------------- */

/*
 * THE DECODERS A LANGUAGE CALLS, read backwards from the literal they wrap - see the lang row's
 * call_chain. `rows` names them; `fold` says the language does not care about case (php), `silence` that
 * "@" may stand before a name (php's), `slash` that a leading "\" names the global one (php's).
 * "(" then a name, and the same again for the call around it, innermost first, stopping at the first
 * name that is not a decoder.
 */
/* A row of a language's function table (kgenome_textual_fn_find). */
struct kgenome_textual_fn_row {
	const char                *name;
	struct kgenome_textual_fn  fn;
};

struct kgenome_textual_fn_table {
	const struct kgenome_textual_fn_row *rows;
	uint32_t                             n;
};

/*
 * THE ROWS OF A FUNCTION TABLE, spelled once (every language's table is made of them; php_fn.c, vbs_fn.c ...). A row is `{ name, { op, min_args, max_args,
 * subject, { param0, param1 }, numeric, form, chr, flags } }`; these say the shapes that recur:
 *   DEC        a decoder over one argument: the decode hook reads it and keeps the call (the form never rewrites it)
 *   STR1       a function of one string whose answer is a string: rewritten when its argument is a literal
 *   CHR        chr(n): one number, no subject, written only when what it makes is printable (a table of chr(0), chr(10) is data), in `flavour`
 *   FN         anything else, with the argument shape and `flags` written out
 * KGENOME_TEXTUAL_FN_NO is "this parameter is not there".
 */
#define KGENOME_TEXTUAL_FN_NO KGENOME_TEXTUAL_FN_NONE
#define KGENOME_TEXTUAL_FN_DEC(n, o) \
	{ n, { .op = KGENOME_TEXTUAL_DEC_##o, .min_args = 1, .max_args = 1, .param = { KGENOME_TEXTUAL_FN_NONE, KGENOME_TEXTUAL_FN_NONE }, \
	       .form = KGENOME_TEXTUAL_FN_FORM_NEVER } }
#define KGENOME_TEXTUAL_FN_STR1(n, o, flags_) \
	{ n, { .op = KGENOME_TEXTUAL_DEC_##o, .min_args = 1, .max_args = 1, .param = { KGENOME_TEXTUAL_FN_NONE, KGENOME_TEXTUAL_FN_NONE }, \
	       .form = KGENOME_TEXTUAL_FN_FORM_ALWAYS, .flags = (flags_) } }
#define KGENOME_TEXTUAL_FN_CHR(n, max_args_, flavour) \
	{ n, { .op = KGENOME_TEXTUAL_DEC_CHR, .min_args = 1, .max_args = (max_args_), .subject = KGENOME_TEXTUAL_FN_NONE, .param = { 0, KGENOME_TEXTUAL_FN_NONE }, \
	       .numeric = 1, .form = KGENOME_TEXTUAL_FN_FORM_PRINTABLE, .chr = (flavour) } }
#define KGENOME_TEXTUAL_FN(n, op_, min_, max_, subject_, p0, p1, numeric_, flags_) \
	{ n, { .op = KGENOME_TEXTUAL_DEC_##op_, .min_args = (min_), .max_args = (max_), .subject = (subject_), .param = { (p0), (p1) }, .numeric = (numeric_), \
	       .form = KGENOME_TEXTUAL_FN_FORM_ALWAYS, .flags = (flags_) } }
/*
 * A ROW WRITTEN FIELD BY FIELD, for what the positional forms cannot say: a method, an operator, a cast, a function only the evaluator reads, and the extras (`.bad`, `.set`,
 * `.list`, `.prec`). The first nine are the same as KGENOME_TEXTUAL_FN's; what follows is designated and says what KIND of row it is - one of the five below - and then the extras.
 * A METHOD's receiver is argument 0, so its subject is 0 and its parameters begin at 1 (see enum kgenome_textual_shape).
 */
#define KGENOME_TEXTUAL_ROW(n, o, min_, max_, subj_, p0_, p1_, num_, fl_, ...) \
	{ n, { .op = KGENOME_TEXTUAL_DEC_##o, .min_args = (min_), .max_args = (max_), .subject = (subj_), .param = { (p0_), (p1_) }, \
	       .numeric = (num_), .flags = (fl_), __VA_ARGS__ } }
#define KGENOME_TEXTUAL_K_CALL      .form = KGENOME_TEXTUAL_FN_FORM_ALWAYS
#define KGENOME_TEXTUAL_K_EVAL      .form = KGENOME_TEXTUAL_FN_FORM_EVAL
#define KGENOME_TEXTUAL_K_METHOD    .shape = KGENOME_TEXTUAL_SHAPE_METHOD, .form = KGENOME_TEXTUAL_FN_FORM_EVAL
#define KGENOME_TEXTUAL_K_OP(prec_) .shape = KGENOME_TEXTUAL_SHAPE_OP, .form = KGENOME_TEXTUAL_FN_FORM_EVAL, .prec = (prec_)
#define KGENOME_TEXTUAL_K_SUFFIX    .shape = KGENOME_TEXTUAL_SHAPE_SUFFIX, .form = KGENOME_TEXTUAL_FN_FORM_EVAL
#define KGENOME_TEXTUAL_K_CAST      .shape = KGENOME_TEXTUAL_SHAPE_CAST, .form = KGENOME_TEXTUAL_FN_FORM_EVAL
#define KGENOME_TEXTUAL_K_CMD       .shape = KGENOME_TEXTUAL_SHAPE_CMD, .form = KGENOME_TEXTUAL_FN_FORM_EVAL
#define KGENOME_TEXTUAL_K_EXPAND    .shape = KGENOME_TEXTUAL_SHAPE_EXPAND, .form = KGENOME_TEXTUAL_FN_FORM_EVAL

struct kgenome_textual_decoder_row {
	const char *name;
	uint8_t     dec;            /* enum kgenome_textual_decoder */
};

struct kgenome_textual_call_style {
	const struct kgenome_textual_decoder_row *rows;
	uint32_t n_rows;
	/* The decoders that are ALSO rows of the language's function table (php's: base64_decode, gzinflate ...) are read from it, not
	 * listed a second time: the rows whose form is NEVER. NULL for a language with no table. */
	const struct kgenome_textual_fn_table *fns;
	uint8_t  fold, silence, slash;
	uint8_t  qualify;           /* a name may be written "module.name": the byte that joins them (python's ".") */
	uint8_t  dollar;            /* "$" is a name byte, so "$atob(" is not atob (js) */
	/* "window.atob(" is the call atob: the words and dots in front are its receiver and go with it when the call is taken
	 * back (js; php's "." joins strings, so there it is not one) */
	uint8_t  receiver;
};

/* The decoders .NET names the same way wherever a language reaches them (a page's c# and vb.net, powershell): lower case, for a row that folds
 * case. A page reads the first KGENOME_TEXTUAL_DOTNET_PAGE rows; powershell has all of them, and one more that only it spells. */
extern const struct kgenome_textual_decoder_row kgenome_textual_dotnet_decoders[];
#define KGENOME_TEXTUAL_DOTNET_PAGE 3u
#define KGENOME_TEXTUAL_DOTNET_ALL  4u

uint32_t kgenome_textual_call_chain(const struct kgenome_textual_call_style *st, const uint8_t *tail,
				    uint32_t n, uint8_t *chain, uint32_t cap, uint32_t *from);

/*
 * C-SHAPED CODE: "//" and the C block comment, strings with backslash escapes, and the three things that
 * differ by language. Lexes [lx->pos, end) and leaves lx->pos at `end`; answers 0 when the sink stopped.
 * What is looked for does not look past `end`: a string or a comment that would is open there.
 */
#define KGENOME_TEXTUAL_CL_REGEX    0x1u    /* js: lexed by kgenome_textual_ecma, below */
#define KGENOME_TEXTUAL_CL_TEMPLATE 0x2u    /* with CL_REGEX: backtick strings with ${...} in them (js) */
#define KGENOME_TEXTUAL_CL_VERBATIM 0x4u    /* c#: @"..." doubles its quote, $"..." has {...}, """...""" is raw, the text of #region is not code */
int kgenome_textual_clike(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t flags);

/* Past the C block comment whose "/" "*" are at `i`, or `end` when the window closes first (`*closed` says which). The search starts after
 * the opener, so slash-star-slash is not a whole comment. The one reader of the form: c-shaped code, php and coldfusion's script. */
uint32_t kgenome_textual_c_block_end(const uint8_t *p, uint32_t end, uint32_t i, int *closed);

/* The "//" comment (to the line break, a CR ends it as an LF does) or the C block comment at `i`, delivered with the code in front of it;
 * p[i] is "/" and p[i + 1] the "/" or "*". The offset after it, and in `*ok` the sink's answer. The reader is shared by every language
 * whose comments are C's (clike, coldfusion's script); php reads "//" itself, for it stops before "?>", and takes the block here. */
uint32_t kgenome_textual_c_comment(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t i, int *ok);

/*
 * ECMASCRIPT: javascript and jscript (textual_ecma.c), which has a lexer of its own because "/" and a
 * template's ${ } need the token before and a nest of brackets. Same contract as kgenome_textual_clike, which
 * hands the CL_REGEX case to it. Flags: backtick templates; a "#!" first line; "<!--" and "-->" comments.
 */
#define KGENOME_TEXTUAL_ECMA_TEMPLATE     0x1u
#define KGENOME_TEXTUAL_ECMA_HASHBANG     0x2u
#define KGENOME_TEXTUAL_ECMA_HTML_COMMENT 0x4u
int kgenome_textual_ecma(struct kgenome_textual_lexer *lx, uint32_t end, uint32_t flags);

/*
 * JAVA: the body of a jsp scriptlet. Same contract as kgenome_textual_clike. What java adds to the C shape,
 * and why it has a lexer of its own (textual_java.c): the source is translated for \uXXXX BEFORE it is
 * lexed, so a quote or a line break may be spelled as an escape.
 */
int kgenome_textual_java(struct kgenome_textual_lexer *lx, uint32_t end);

/* VBSCRIPT: "'" and Rem comments, "..." with the quote doubled, nothing else. Same contract. */
int kgenome_textual_vb(struct kgenome_textual_lexer *lx, uint32_t end);

/* The vb line continuation at `i` ("_", blanks, a line break; "_" a word of its own): its length, or 0.
 * The lexer and the form (lang row `vb_lines`) both ask it, so they cannot disagree on what one is. */
uint32_t kgenome_textual_vb_cont(const uint8_t *p, uint32_t n, uint32_t i);

/* `glue` for vb code: the pairs closing up would make into something else. A row of vb code may use it
 * (vbs does; asp and aspx carry the operators of a second language and keep a union of their own). */
int kgenome_textual_vb_glue(uint8_t a, uint8_t b);

/* One island language of a page that has several: which lexer reads it, and that lexer's flags. */
enum kgenome_textual_page_lexer {
	KGENOME_TEXTUAL_PAGE_VB,        /* kgenome_textual_vb */
	KGENOME_TEXTUAL_PAGE_CLIKE,     /* kgenome_textual_clike, flags KGENOME_TEXTUAL_CL_* (c#) */
	KGENOME_TEXTUAL_PAGE_ECMA       /* kgenome_textual_ecma, flags KGENOME_TEXTUAL_ECMA_* (jscript) */
};

struct kgenome_textual_script_lang {
	const char *word;       /* lower case: a language attribute that begins with it, in any case, names this one */
	uint8_t     lexer;      /* enum kgenome_textual_page_lexer */
	uint32_t    flags;
};

/*
 * A PAGE: markup with "<%" ... "%>" islands in it, as asp, aspx and jsp have. Lexes the whole text; what is
 * inside an island is lexed by `body`, which is given the island's window and must deliver it exactly.
 * An island ends at the first "%>" there is, in a string or a comment too - a page scanner looks for the
 * tag before any language reads the code - so the body never has to find it.
 */
struct kgenome_textual_page {
	int (*body)(struct kgenome_textual_lexer *lx, uint32_t end);
	uint8_t dash_comment;       /* "<%-- ... --%>" is a comment (aspx, jsp) */
	uint8_t server_script;      /* <script runat="server"> ... </script> is an island (asp, aspx) */
	/* The bytes after "<%" that make it a three byte tag ("<%=", "<%!"); NULL is "=!#$" (asp, aspx).
	 * jsp has "=!" only: in a jsp "<%#" and "<%$" are scriptlets that begin with that byte. */
	const char *tag3;
	/* Markup the page host cannot see by looking for "<%": called at every "<" that is not "<%", and, when
	 * set, at every "$" and "#" too, with `at` the offset of that byte. Answers 0 when it is not
	 * something it knows. Otherwise the offset where the scan goes on (> at): either it delivered spans
	 * up to there (lx->pos), or it only vouches that [at, answer) holds no island opener (jsp's EL) and
	 * delivered nothing. It stops the walk by the sink refusing (lx->refused). */
	uint32_t (*markup)(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg, uint32_t at);
	/* THE LANGUAGES AN ISLAND MAY BE IN, by the name a directive or a script element gives them (asp, aspx).
	 * NULL for a page whose `body` is its one language (jsp). langs[0] is the page's when no directive names
	 * one; a name that is in no row is read as langs[0] too. The page's language is the first directive's
	 * Language attribute; a <script runat="server"> with its own language lexes its body in that one. */
	const struct kgenome_textual_script_lang *langs;
	uint32_t n_langs;
	uint8_t  lang_from_script;  /* no Language in a directive: the first server script's names the page's (aspx) */
	uint8_t  fragment_code;     /* a FRAGMENT is island code from its first byte (asp, aspx) */
	uint8_t  directive_code;    /* after <%@ WebHandler|WebService ... %> the rest of the text is code (.ashx, .asmx) */
};
void kgenome_textual_page_lex(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg);

/* [lx->pos, end) as code of the shared lexer `l` names (its `lexer` and `flags`; `word` is not read): what a page does for each island and a row
 * with a `whole` does for its text. Answers 0 once the sink has refused. */
int kgenome_textual_island_lex(struct kgenome_textual_lexer *lx, const struct kgenome_textual_script_lang *l, uint32_t end);

/*
 * WOULD CLOSING THESE TWO UP MAKE SOMETHING ELSE of a page whose islands may be vbscript, jscript or c#: the
 * union of the three languages' two-byte operators (a closing up must never make a longer token, whichever
 * one the island is in), the comment openers, "%>" and "</", which would end the island or the script element
 * the form is being written for, and the tag bytes after "<%" - and vbscript's own rules (kgenome_textual_vb_glue), because the island
 * may be vb. The row of asp and of aspx.
 */
int kgenome_textual_glue_web(uint8_t a, uint8_t b);

/*
 * THE ESCAPES OF A STRING LITERAL, as a table: what each language says after a backslash. `simple` is pairs - the
 * byte after the backslash and the byte it stands for - ended by a NUL. The rest says whether "\x", an octal run, "\u"
 * and "\U" exist, how long, whether a backslash and a line break vanish, and what an escape that is none of
 * these means. kgenome_textual_esc_value reads a literal's content with it; each language directory has its own row.
 */
#define KGENOME_ESC_KEEP   0u       /* an unknown escape stays: backslash and byte (php, python) */
#define KGENOME_ESC_DROP   1u       /* the backslash goes, the byte stays (javascript) */
#define KGENOME_ESC_REFUSE 2u       /* it is an error in the language: the literal has no value */
#define KGENOME_ESC_ANY    255u     /* no limit on the digits of "\u{...}" (javascript: "\u{0000000041}" is "A") */

struct kgenome_textual_esc {
	const char *simple;
	const char *refuse;         /* escape bytes that make the literal valueless ("N" in python) */
	uint8_t xmin, xmax;         /* "\x": digits; xmax 0 = no "\x" */
	uint8_t octal;              /* 0 none; 3 up to three digits wrapped to a byte (php, python bytes); 4 java's and
				     * javascript's (three only when the first is 0-3, so at most \377); 5 up to three digits
				     * as a character, \777 at most (python str) */
	uint8_t u4, u8;             /* "\uHHHH", "\UHHHHHHHH" */
	uint8_t ubrace;             /* "\u{H...}": the most digits it takes, KGENOME_ESC_ANY for as many as there are, 0 for no such escape */
	uint8_t pairs;              /* two utf-16 surrogate escapes in a row are one character (js, java, c#); alone, none has a value */
	uint8_t zero;               /* "\\0" is a NUL when no digit follows (c#, which has no octal) */
	uint8_t cont;               /* a backslash and a line break vanish */
	uint8_t unknown;            /* KGENOME_ESC_* */
	uint8_t chars;              /* "\x" and octal give a CHARACTER (utf-8 above 0x7f), not a byte */
};

/*
 * THE ONE ESCAPE AT p[i] (the backslash, with a byte after it) that the row reads as a number: "\x", an octal run, "\u", "\U" or
 * "\u{...}". Answers its length and in `h` which of the five it is (KGENOME_ESC_AT_*), the digits it took and its value as
 * the digits say it (an octal escape is not wrapped to a byte, a value past U+10FFFF is 0x110000); 0 when it is none of
 * them - the other escapes are `simple`, `cont` and `zero`, which need no scan. The value reader and every language's
 * unescape hook ask this, so a language's rule for what an escape is exists once.
 */
#define KGENOME_ESC_AT_X      1u
#define KGENOME_ESC_AT_OCT    2u
#define KGENOME_ESC_AT_U4     3u
#define KGENOME_ESC_AT_U8     4u
#define KGENOME_ESC_AT_UBRACE 5u

struct kgenome_textual_esc_at {
	uint32_t v;
	uint32_t digits;
	uint8_t  kind;
};

uint32_t kgenome_textual_esc_scan(const struct kgenome_textual_esc *r, const uint8_t *p, uint32_t n, uint32_t i,
				  struct kgenome_textual_esc_at *h);

/* A code point as utf-8, up to six bytes (lua's \u{...} goes to 0x7FFFFFFF; everything up to U+10FFFF is the usual one to four, and a
 * surrogate is written as the three bytes it would have). No check: a caller that must refuse a surrogate or a value past U+10FFFF does.
 * Answers the bytes written; `out` has room for six. */
uint32_t kgenome_textual_utf8_put(uint8_t *out, uint32_t cp);

/* The byte that `e` stands for in a table of pairs "key, value, key, value" ended by a NUL (what the languages call `simple`): 1 and `*v`,
 * or 0 when `e` is not a key. A NUL is never one. */
static inline int kgenome_textual_pair_get(const char *pairs, uint8_t e, uint8_t *v)
{
	for (; pairs[0]; pairs += 2) {
		if ((uint8_t)pairs[0] == e) {
			*v = (uint8_t)pairs[1];
			return 1;
		}
	}
	return 0;
}

/*
 * THE LITERAL for `v` (n bytes) under a row's `quote` (textual_lang.h), written at `out`; with `out` NULL it only answers the length. 0 when the value cannot
 * be written in this language's literal (the row's refusals: a line break in a vbscript string, "%>" in a page): the caller keeps what it had.
 * kgenome_textual_quote_max is the most it can be - what a caller reserves before it writes. The ONE writer of a literal whose value is given:
 * the form's call stage (a call on literals written as its value) and kgenome_textual_subst (a computed value written where it was computed).
 */
struct kgenome_textual_quote;
uint32_t kgenome_textual_quote_write(const struct kgenome_textual_quote *r, const uint8_t *v, uint32_t n, uint8_t *out);
uint64_t kgenome_textual_quote_max(const struct kgenome_textual_quote *r, uint32_t n);

/* The content c[0, cn) as it was typed: a literal whose text is its value (a nowdoc, a single-quoted here-string, the data after ruby's
 * __END__, a batch string). `out` may be `c`. Always 1, so a hook can `return` it. */
int kgenome_textual_value_verbatim(const uint8_t *c, uint32_t cn, uint8_t *out, uint32_t *n);

/* The content c[0, cn) of a literal in which a brace written twice is one brace (python's f-strings, c#'s interpolated strings); a single
 * one opens or closes a field, which is the program's, so the literal has no value: 0. The length in `*n`. `out` may be `c`. */
int kgenome_textual_brace_value(const uint8_t *c, uint32_t cn, uint8_t *out, uint32_t *n);

/* The content c[0, cn) in which each byte of `set` written twice is one (vbscript's and c#'s quote, coldfusion's quote and "#"). A single
 * one is a byte of its own, or - with `refuse` - what the language does not allow, and the literal has no value: 0. `out` may be `c`. */
int kgenome_textual_undouble(const uint8_t *c, uint32_t cn, const char *set, int refuse, uint8_t *out, uint32_t *n);

/* Raw line breaks "\r\n" and "\r" as "\n", as python's tokenizer and javascript's template values read them. `out` may be `p`. */
uint32_t kgenome_textual_lf_value(const uint8_t *p, uint32_t n, uint8_t *out);

/* The value of the content [p, n) under `r`, into `out` (n bytes will do). 1, or 0 when it has none. */
int kgenome_textual_esc_value(const struct kgenome_textual_esc *r, const uint8_t *p, uint32_t n, uint8_t *out,
			      uint32_t *n_out);

/*
 * A STRING WITH ITS SPELLED-OUT BYTES WRITTEN AS THEMSELVES (the form's `unescape_str` hook of every language that has one).
 * The loop, the output cursor, the test for a byte that may be written and the bookkeeping of what a byte written after a kept
 * escape could change are here, once; a language gives what only it knows:
 *   - `at`: the escape at one position - how long it is, the byte it spells, whether that byte may be written at all (a language
 *     may refuse one its escape does not say plainly), and which guards a kept escape leaves (below). A language reads its
 *     escapes with the SAME function as its value hook (kgenome_textual_esc_scan on its row, or its own esc_at).
 *   - the reserved bytes: never written, because they would end the string, begin an escape or interpolate. A byte that is not
 *     printable ASCII is never written, whatever the language says.
 * A GUARD is the neighbour of a kept escape: "\0\x31" written as "\01" is another byte, "\x4\x61" as "\x4a" completes the
 * escape, "\z\x20" as "\z " is skipped. A kept escape sets the guards its own text could be extended by; a written byte
 * or a byte typed in the text keeps a guard only while it is one that extends what the guard names (hex digits, name bytes,
 * blanks) and ends the others at once (an octal or decimal run is ended by whatever follows).
 */
#define KGENOME_UNESC_HEX   1u      /* no hex digit is written: the escape before it took fewer digits than it could */
#define KGENOME_UNESC_OCT   2u      /* no octal digit */
#define KGENOME_UNESC_DEC   4u      /* no decimal digit */
#define KGENOME_UNESC_NAME  8u      /* no name byte (letters, digits, "_", ":"): after "$" and its name */
#define KGENOME_UNESC_BLANK 16u     /* no space: a "\z" or a backslash and a line break takes the blanks after it */

struct kgenome_textual_unesc_hit {
	uint32_t v;                 /* the byte it spells */
	uint8_t  write;             /* v may be written in its place, unless it is reserved or a guard refuses it */
	uint8_t  guard;             /* the guards set when the escape is kept */
};

struct kgenome_textual_unesc;
/* The end of a stretch of the string that is not text - code inside it, an interpolation - starting at s[i], or 0: the bytes of it are kept as typed and
 * no escape in it is read. The driver asks at every byte that is not an escape, so a language that sets it pays for that. */
typedef uint32_t (*kgenome_textual_unesc_skip_fn)(const struct kgenome_textual_unesc *u, uint32_t i);

/* The escape at s[i], a backslash with a byte after it: how many bytes it is, or the bytes kept as typed when it is not written (at
 * least 2); `h` says the rest. 0: the language reads the text as it is not a program, and the whole
 * string is kept as typed (javascript: a "\x" with one digit). */
typedef uint32_t (*kgenome_textual_unesc_fn)(const struct kgenome_textual_unesc *u, uint32_t i,
					     struct kgenome_textual_unesc_hit *h);

struct kgenome_textual_unesc {
	const uint8_t *s;
	uint32_t len;
	kgenome_textual_unesc_fn at;
	kgenome_textual_unesc_skip_fn skip;     /* NULL: none */
	const struct kgenome_textual_esc *row;  /* the table the language's escapes are read with: the value reader's own */
	uint32_t ban[4];            /* the reserved bytes, a bit each, below 0x80 */
	uint32_t ws_ctl;            /* the bytes below 0x20 that a BLANK guard goes on through, a bit each (the space always does) */
	uint8_t  name_after;        /* a byte typed in the text that begins a name guard ("$" in tcl); 0 for none */
};

/* Inline: a language's reserved set is a literal, and what is built is a few bits - a call for each byte of it cost the form 1-3% of its speed. */
static inline void kgenome_textual_unesc_init(struct kgenome_textual_unesc *u, const uint8_t *s, uint32_t len,
					      kgenome_textual_unesc_fn at, const struct kgenome_textual_esc *row)
{
	u->s = s;
	u->len = len;
	u->at = at;
	u->skip = NULL;
	u->row = row;
	u->ban[0] = u->ban[1] = u->ban[2] = u->ban[3] = 0;
	u->ws_ctl = 0;
	u->name_after = 0;
}

static inline void kgenome_textual_unesc_ban_byte(struct kgenome_textual_unesc *u, uint8_t c)
{
	if (c < 0x80u)
		u->ban[c >> 5] |= 1u << (c & 31u);
}

static inline void kgenome_textual_unesc_ban(struct kgenome_textual_unesc *u, const char *set)
{
	for (; *set; set++)
		kgenome_textual_unesc_ban_byte(u, (uint8_t)*set);
}

/* Letters, digits and "_": words 1 to 3 of the bit set are 0x20-0x3f (the digits, bits 16-25), 0x40-0x5f ("A"-"Z", bits 1-26, and "_", bit 31)
 * and 0x60-0x7f ("a"-"z", bits 1-26) - the bytes kgenome_textual_ident answers for from 0x20 to 0x7e (compared byte by byte once, no difference). */
static inline void kgenome_textual_unesc_ban_ident(struct kgenome_textual_unesc *u)
{
	u->ban[1] |= 0x03ff0000u;
	u->ban[2] |= 0x87fffffeu;
	u->ban[3] |= 0x07fffffeu;
}
/* The escape at s[i] that the row the unescape was made with reads as a number (kgenome_textual_esc_scan): what a language's `at` hook asks first. */
static inline uint32_t kgenome_textual_unesc_scan(const struct kgenome_textual_unesc *u, uint32_t i, struct kgenome_textual_esc_at *a)
{
	return kgenome_textual_esc_scan(u->row, u->s, u->len, i, a);
}

/* The string from byte `from` on into `out` (len bytes); what is before it is copied. Answers the bytes written. */
uint32_t kgenome_textual_unesc_run(const struct kgenome_textual_unesc *u, uint32_t from, uint8_t *out);

#endif /* KGENOME_TEXTUAL_PRIVATE_H */
