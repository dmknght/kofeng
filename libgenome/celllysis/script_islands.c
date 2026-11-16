/*
 * script_islands.c - see script_islands.h: the islands of a text at two levels and in two layers, from the one lex
 * (script_private.h) and the function table that lex gave (script_funcs.c).
 *
 * WHAT DECIDES EACH STEP, AND THE SURVEY THAT DECIDED IT (2026-11-14, the engine's own lexer and function table over read-only
 * copies of samples/{php_shells,webshells,Webshell-Collection}, WordPress 6.8 php+js and the MalwareLab scripts: 2094 files,
 * /mnt/games/normtest/fix_island/survey):
 *   - PIECES (row `page`): php 1218 files hold 8751 tagged pieces (p50 1, p90 18, max 341 a file), 65 of them with no code, 1022
 *     without a closing tag (the program's own end: php allows it), 18 `<?=` pieces in 3 files; asp 192 pieces in 17 files (89
 *     `<%=`), aspx 9, jsp 10 (2 `<%=`), cfm 185 tag groups in 4 files.
 *   - BLOCKS ACROSS PIECES (join_*): php 6035 pieces end with a block open (207 files) and 6306 pieces join another: the 8686 pieces
 *     with code make 2651 level-0 islands. asp: 4 pieces in 1 file. jsp, aspx: 0. The join is the common case of a php template, so
 *     it is built, not deferred.
 *   - FUNCTIONS ACROSS PIECES: 327 php functions in 129 files contain a tag (the joined island holds them whole).
 *   - PIECES MIXING FUNCTIONS AND OUTSIDE CODE: 812 php pieces in 697 files (level 1 cuts them as [run][function][run]...).
 *   - SERVER CODE INSIDE CLIENT CODE (client layer): 574 php pieces in 52 files sit inside a <script> element, 1986 in 197 files
 *     inside an html tag's attribute; asp 46 in 13 files, cfm 48 in 3. Client code in the markup of a page: php 279 <script>
 *     elements in 133 files, 175 on* attributes in 28, 10 javascript: urls in 1; asp 9 / 28 / 0.
 * Every number is agent-measured on that corpus (survey.c, scratch).
 * AND WHAT THIS FILE MAKES OF IT (survey2.c over the same 2094 files, the final code):
 *   php   8722 pieces with code -> 2643 level-0 islands (270 of them joined, holding 6349 pieces; 1019 open: a program with no "?>"),
 *         mean island size per file p50 4276 / p90 41540 bytes; level 1: 12006 functions + 3765 runs, 0 clipped; client layer 330
 *         islands, 709 level-1, 272 functions
 *   asp   185 -> 68 (14 joined, 131 pieces), level 1: 59 functions + 84 runs; client 36 / 44
 *   aspx  9 -> 9, level 1: 13 functions + 6 runs; jsp 10 -> 10, 4 + 12; cfm 119 tag groups -> 14 (7 joined, 112 groups), 8 + 15
 *   js    581 texts, level 1: 35926 functions + 29207 runs (one text, one level-0 island)
 *   Against the extents the similarity cut read before (Merge 161's [after the tag, before the closing tag) of every lexer island):
 *   each lies inside a level-0 island, except 15 php pieces in 14 files and 4 asp pieces in 2 files that hold only a comment or white
 *   space (`<?php // Silence is golden.`, a license block): no island, by the design ("a run of whitespace or comments only is not an
 *   island"), so their windows are not fed any more - the one place the feed is not a superset of what it was.
 */

#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <kgenome_budget.h>
#include <textual/textual.h>

#include "script_funcs.h"
#include "script_islands.h"
#include "script_private.h"

/* ---- the table ------------------------------------------------------------------------------------------------------------ */

static int isl_push(struct kgenome_script_islands *s, struct kgenome_script_isl_list *L, const struct kgenome_script_island *e)
{
	if (L->n == L->cap) {
		uint32_t nc = kgenome_grow_cap(L->cap, 16u);
		struct kgenome_script_island *nv = nc ? realloc(L->v, (size_t)nc * sizeof *nv) : NULL;

		if (!nv) {
			s->status = KGENOME_NOMEM;
			return 0;
		}
		L->v = nv;
		L->cap = nc;
	}
	L->v[L->n++] = *e;
	return 1;
}

void kgenome_script_islands_free(struct kgenome_script_islands *s)
{
	uint32_t a, b;

	for (a = 0; a < KGENOME_SCRIPT_ISL_LAYERS; a++)
		for (b = 0; b < 2u; b++)
			free(s->lv[a][b].v);
	kgenome_funcs_free(&s->client_funcs);
	memset(s, 0, sizeof *s);
}

static int blank(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/* ---- the rows: how each language's code is placed in its text (owner: "chia dispatch mỗi ngôn ngữ theo đúng tiêu chuẩn") -------- */

enum blk_kind {
	BLK_NONE = 0,   /* no tags: the text is one piece, nothing to join */
	BLK_PHP,        /* braces, and the alternative syntax `if (...): ... endif;` (php manual, "Alternative syntax for control structures") */
	BLK_PAGE,       /* a server page: the block syntax of each island's language (textual.h, kgenome_textual_page_syntax: braces or vb) */
	BLK_CFML        /* paired cf tags: <cfif> ... </cfif> */
};

struct isl_row {
	uint32_t lang;
	uint8_t  blk;
	/* The tags ARE the statements (cfml: `<cfexecute name="cmd">` is the call): a piece is the tags and the code between, and its tag
	 * bytes are code. Every other page leaves its own tags out of the island (Merge 161, owner 2026-11-06: the "<?php" every file of
	 * the language has is not evidence). */
	uint8_t  tags_code;
	uint8_t  client;        /* its markup is html: the client layer is read in it */
};

static const struct isl_row ROWS[] = {
	{ KGENOME_TEXTUAL_LANG_PHP,  BLK_PHP,  0u, 1u },
	{ KGENOME_TEXTUAL_LANG_ASP,  BLK_PAGE, 0u, 1u },
	{ KGENOME_TEXTUAL_LANG_ASPX, BLK_PAGE, 0u, 1u },
	{ KGENOME_TEXTUAL_LANG_JSP,  BLK_PAGE, 0u, 1u },
	{ KGENOME_TEXTUAL_LANG_CFM,  BLK_CFML, 1u, 1u },
};

static const struct isl_row *row_of(uint32_t lang)
{
	uint32_t i;

	for (i = 0; i < sizeof ROWS / sizeof ROWS[0]; i++)
		if (ROWS[i].lang == lang)
			return &ROWS[i];
	return NULL;
}

/* A byte that is code of the island: CODE that is not white space, any byte of a string literal, and - where the tags are the
 * statements - a tag byte. Not a comment, not markup, not white space: a run of those alone is not an island (owner). */
static int code_byte(const struct kgenome_script_text *t, const struct isl_row *row, uint64_t i)
{
	uint8_t k = t->kind[i];

	if (k == KGENOME_TEXTUAL_STRING)
		return 1;
	if (k == KGENOME_TEXTUAL_CODE)
		return !blank(t->p[i]);
	return k == KGENOME_TEXTUAL_TAG && row && row->tags_code;
}

static int has_code(const struct kgenome_script_text *t, const struct isl_row *row, uint64_t a, uint64_t b)
{
	for (; a < b; a++)
		if (code_byte(t, row, a))
			return 1;
	return 0;
}

/* ---- the pieces of a page ------------------------------------------------------------------------------------------------- */

/*
 * A PIECE is a maximal run of bytes that are not MARKUP: a tag, the code and the comments it opens, its closing tag. `cs`/`ce` is its
 * code: without the opening and closing tag's own bytes (kgenome_textual_tag_own: php's "<?php" span holds one white space after the
 * tag, which is code here as it was in the extent this replaces, scan_ext.c's Merge 161) - or the whole run where the tags are code.
 * `closed` is false when the text ended inside it (the last run is not a tag).
 */
struct piece {
	uint64_t gs, ge, cs, ce;
	uint8_t  code, closed;
};

static uint64_t run_end(const struct kgenome_script_text *t, uint64_t i)
{
	uint8_t k = t->kind[i];

	while (i < t->n && t->kind[i] == k)
		i++;
	return i;
}

static void piece_at(const struct kgenome_script_text *t, const struct isl_row *row, uint64_t gs, uint64_t ge, struct piece *pc)
{
	uint64_t first_end = run_end(t, gs), last = gs, i;

	for (i = gs; i < ge; i = run_end(t, i))
		last = i;
	pc->gs = gs;
	pc->ge = ge;
	pc->cs = gs;
	pc->ce = ge;
	pc->closed = t->kind[last] == KGENOME_TEXTUAL_TAG && last > gs;
	if (!row->tags_code) {
		if (t->kind[gs] == KGENOME_TEXTUAL_TAG) {
			uint64_t own = kgenome_textual_tag_own(t->lang, t->p + gs, (uint32_t)(first_end - gs), 0);

			pc->cs = gs + (own < first_end - gs ? own : first_end - gs);
		}
		if (pc->closed)
			pc->ce = last;
		if (pc->ce < pc->cs)
			pc->ce = pc->cs;
	}
	pc->code = (uint8_t)has_code(t, row, pc->cs, pc->ce);
}

/* ---- the block counters, one per language's specification ------------------------------------------------------------------ */

/*
 * The count of open blocks, carried from one piece to the next: a piece whose blocks are not closed at its end joins the next
 * ("cái gì mở ở mảnh A đóng ở mảnh B thì A..B là một island"). A close with nothing open is not counted below zero (a stray "}"
 * cannot join a piece to one before it). `stack`: the names cfml's paired tags are matched by.
 */
struct blk_state {
	uint64_t depth;
	uint32_t *stack;                /* cfml: a hash of each open tag's name */
	uint32_t n_stack, cap_stack;
	uint8_t  vb_prop;               /* vb: a `Property` header whose Get / Set may follow on the next statement */
	uint8_t  page_syn;              /* the page's own block syntax (kgenome_textual_page_syntax at the end of the text), asked once */
	int      oom;
};

static void blk_close(struct blk_state *b)
{
	if (b->depth)
		b->depth--;
}

static int name_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 0x80u;
}

/* The CODE word starting at `i` (a name byte not preceded by one), folded and compared to `w`; its end in *e. */
static int word_is(const struct kgenome_script_text *t, uint64_t i, uint64_t lim, const char *w, uint64_t *e)
{
	uint64_t k = 0, l = strlen(w);

	if (i + l > lim)
		return 0;
	for (k = 0; k < l; k++)
		if (t->kind[i + k] != KGENOME_TEXTUAL_CODE || kgenome_script_lower(t->p[i + k]) != (uint8_t)w[k])
			return 0;
	if (i + l < lim && t->kind[i + l] == KGENOME_TEXTUAL_CODE && name_byte(t->p[i + l]))
		return 0;
	*e = i + l;
	return 1;
}

/* The next byte from `i` that is code and not white space; comments are skipped as php skips them. `lim` when there is none. */
static uint64_t next_sig(const struct kgenome_script_text *t, uint64_t i, uint64_t lim)
{
	while (i < lim && (t->kind[i] == KGENOME_TEXTUAL_COMMENT || (t->kind[i] == KGENOME_TEXTUAL_CODE && blank(t->p[i]))))
		i++;
	return i;
}

/*
 * PHP: "{" and "}" of the code, and the alternative syntax: `if (...):`, `foreach (...):`, `for (...):`, `while (...):`,
 * `switch (...):`, `declare (...):` open a block that `endif`, `endforeach`, `endfor`, `endwhile`, `endswitch`, `enddeclare` close;
 * `elseif (...):` and `else:` continue it. Keywords in any case (php's own rule). A keyword after "->", "::", "$" or a name byte is
 * a name, not a keyword. The condition's ")" is found in the text's one paren table (script_private.h), so a condition of any length
 * costs one lookup and a hostile chain of `if(if(if(` is not read again from each keyword. `do ... while (x);` has no colon and
 * opens nothing.
 */
static const char *const PHP_OPEN[] = { "if", "foreach", "for", "while", "switch", "declare", NULL };
static const char *const PHP_CLOSE[] = { "endif", "endforeach", "endfor", "endwhile", "endswitch", "enddeclare", NULL };

static int php_member_before(const struct kgenome_script_text *t, uint64_t i)
{
	uint64_t j = i;

	if (j && (t->p[j - 1u] == '$' || (t->kind[j - 1u] == KGENOME_TEXTUAL_CODE && name_byte(t->p[j - 1u]))))
		return 1;
	while (j && t->kind[j - 1u] == KGENOME_TEXTUAL_CODE && blank(t->p[j - 1u]))
		j--;
	return j >= 2u && ((t->p[j - 1u] == '>' && t->p[j - 2u] == '-') || (t->p[j - 1u] == ':' && t->p[j - 2u] == ':'));
}

static void count_php(const struct kgenome_script_text *t, uint64_t a, uint64_t b, struct blk_state *s)
{
	uint64_t i, e, close;
	uint32_t w;

	for (i = a; i < b; i++) {
		uint8_t c = t->p[i];

		if (t->kind[i] != KGENOME_TEXTUAL_CODE)
			continue;
		if (c == '{') {
			s->depth++;
			continue;
		}
		if (c == '}') {
			blk_close(s);
			continue;
		}
		if (!name_byte(c) || (i > a && name_byte(t->p[i - 1u]) && t->kind[i - 1u] == KGENOME_TEXTUAL_CODE))
			continue;
		if (php_member_before(t, i)) {
			while (i + 1u < b && t->kind[i + 1u] == KGENOME_TEXTUAL_CODE && name_byte(t->p[i + 1u]))
				i++;
			continue;
		}
		for (w = 0; PHP_CLOSE[w]; w++)
			if (word_is(t, i, b, PHP_CLOSE[w], &e)) {
				blk_close(s);
				break;
			}
		for (w = PHP_CLOSE[w] ? UINT32_MAX : 0u; w != UINT32_MAX && PHP_OPEN[w]; w++) {
			uint64_t q;

			if (!word_is(t, i, b, PHP_OPEN[w], &e))
				continue;
			q = next_sig(t, e, b);
			if (q < b && t->p[q] == '(' && kgenome_script_paren_close(t, q, &close) && close < b) {
				q = next_sig(t, close + 1u, b);
				if (q < b && t->p[q] == ':')
					s->depth++;
			}
			break;
		}
		while (i + 1u < b && t->kind[i + 1u] == KGENOME_TEXTUAL_CODE && name_byte(t->p[i + 1u]))
			i++;
	}
}

/* Braces of the code (java, c#, jscript, javascript): every CODE "{" and "}". */
static void count_braces(const struct kgenome_script_text *t, uint64_t a, uint64_t b, struct blk_state *s)
{
	uint64_t i;

	for (i = a; i < b; i++) {
		if (t->kind[i] != KGENOME_TEXTUAL_CODE)
			continue;
		if (t->p[i] == '{')
			s->depth++;
		else if (t->p[i] == '}')
			blk_close(s);
	}
}

/*
 * VB (vbscript in asp, vb.net in aspx), statement by statement: a statement ends at a line break, at a ":" that is not ":=", and at
 * the island's end (the tag ends the line as far as the language is concerned: `<% If x Then %>` is a block If). A line that ends
 * in " _" goes on. What the first word (after the modifiers) says:
 *   +1  `If ... Then` with nothing after Then (a block If; `If x Then y` is one line and opens nothing), For / For Each, Do, While,
 *       Select Case, With, Class, Sub, Function, `Property Get|Let|Set` (and a vb.net `Property x` when the next statement is a Get or
 *       a Set), Get / Set as a vb.net accessor (alone or with "("), Try, Using, SyncLock, Namespace, Module, Structure, Enum, Interface
 *   -1  `End <word>` (`End` alone is a statement that stops the program), Next, Loop, Wend
 *   0   everything else, `Declare Sub|Function`, `Delegate`, `MustOverride` (no body), Exit, ElseIf, Else, Case.
 * [Unverified: from the vbscript and vb.net language references, no interpreter here] THE LIMIT: a vb.net `Property x` alone in its piece
 * opens nothing there (whether a Get or a Set follows is the next statement's), so its accessors join each other and the End Property
 * but not the header piece before them.
 */
static const char *const VB_MODS[] = { "public", "private", "friend", "protected", "shared", "default", "static", "overrides",
				       "overridable", "overloads", "shadows", "notoverridable", "readonly", "writeonly", "partial",
				       "async", "iterator", "widening", "narrowing", "notinheritable", "mustinherit", NULL };
static const char *const VB_OPEN[] = { "for", "do", "while", "with", "class", "sub", "function", "try", "using", "synclock",
				       "namespace", "module", "structure", "enum", "interface", NULL };

struct vb_word {
	uint64_t s, e;
};

/* The next word of a statement [i, b): skips white space and comments; a STRING, a punctuation byte or the end is "no word". */
static int vb_word(const struct kgenome_script_text *t, uint64_t *i, uint64_t b, struct vb_word *w)
{
	uint64_t j = next_sig(t, *i, b);

	if (j >= b || t->kind[j] != KGENOME_TEXTUAL_CODE || !name_byte(t->p[j]))
		return 0;
	w->s = j;
	while (j < b && t->kind[j] == KGENOME_TEXTUAL_CODE && name_byte(t->p[j]))
		j++;
	w->e = j;
	*i = j;
	return 1;
}

static int vb_is(const struct kgenome_script_text *t, const struct vb_word *w, const char *s)
{
	uint64_t k, l = strlen(s);

	if (w->e - w->s != l)
		return 0;
	for (k = 0; k < l; k++)
		if (kgenome_script_lower(t->p[w->s + k]) != (uint8_t)s[k])
			return 0;
	return 1;
}

static int vb_in(const struct kgenome_script_text *t, const struct vb_word *w, const char *const *set)
{
	for (; *set; set++)
		if (vb_is(t, w, *set))
			return 1;
	return 0;
}

/* Is the last significant token of the statement [a, b) the word "then". */
static int vb_ends_then(const struct kgenome_script_text *t, uint64_t a, uint64_t b)
{
	uint64_t j = b;

	while (j > a && (t->kind[j - 1u] == KGENOME_TEXTUAL_COMMENT || (t->kind[j - 1u] == KGENOME_TEXTUAL_CODE && blank(t->p[j - 1u]))))
		j--;
	return j >= a + 4u && j - 4u >= a && kgenome_script_lower(t->p[j - 4u]) == 't' && kgenome_script_lower(t->p[j - 3u]) == 'h' &&
	       kgenome_script_lower(t->p[j - 2u]) == 'e' && kgenome_script_lower(t->p[j - 1u]) == 'n' &&
	       t->kind[j - 4u] == KGENOME_TEXTUAL_CODE && (j - 4u == a || !name_byte(t->p[j - 5u]) || t->kind[j - 5u] != KGENOME_TEXTUAL_CODE);
}

static void vb_statement(const struct kgenome_script_text *t, uint64_t a, uint64_t b, struct blk_state *s)
{
	struct vb_word w, x;
	uint64_t i = a, j;
	int prop = s->vb_prop;

	s->vb_prop = 0;
	if (!vb_word(t, &i, b, &w))
		return;
	if (prop && (vb_is(t, &w, "get") || vb_is(t, &w, "set")))
		s->depth++;             /* the vb.net Property whose accessor this is */
	if (vb_is(t, &w, "end")) {
		if (vb_word(t, &i, b, &x))
			blk_close(s);
		return;
	}
	if (vb_is(t, &w, "next") || vb_is(t, &w, "loop") || vb_is(t, &w, "wend")) {
		blk_close(s);
		return;
	}
	if (vb_is(t, &w, "if")) {
		if (vb_ends_then(t, a, b))
			s->depth++;
		return;
	}
	if (vb_is(t, &w, "select")) {
		s->depth++;
		return;
	}
	if (vb_is(t, &w, "get") || vb_is(t, &w, "set")) {
		j = next_sig(t, i, b);
		if (j >= b || t->p[j] == '(')
			s->depth++;     /* an accessor block; `Set x = y` is an assignment */
		return;
	}
	if (vb_is(t, &w, "declare") || vb_is(t, &w, "delegate") || vb_is(t, &w, "mustoverride") || vb_is(t, &w, "exit"))
		return;
	while (vb_in(t, &w, VB_MODS))
		if (!vb_word(t, &i, b, &w))
			return;
	if (vb_is(t, &w, "mustoverride") || vb_is(t, &w, "declare") || vb_is(t, &w, "delegate"))
		return;
	if (vb_is(t, &w, "property")) {
		if (vb_word(t, &i, b, &x) && (vb_is(t, &x, "get") || vb_is(t, &x, "let") || vb_is(t, &x, "set")))
			s->depth++;
		else
			s->vb_prop = 1;
		return;
	}
	if (vb_in(t, &w, VB_OPEN))
		s->depth++;
}

static void count_vb(const struct kgenome_script_text *t, uint64_t a, uint64_t b, struct blk_state *s)
{
	uint64_t st = a, i;

	for (i = a; i < b; i++) {
		uint8_t c = t->p[i];

		if (t->kind[i] == KGENOME_TEXTUAL_TAG || t->kind[i] == KGENOME_TEXTUAL_MARKUP) {
			/* a tag ends the line as far as the language is concerned: `<% End Get %><% End Property %>` is two statements */
			if (i > st)
				vb_statement(t, st, i, s);
			st = i + 1u;
			continue;
		}
		if (t->kind[i] != KGENOME_TEXTUAL_CODE)
			continue;
		if (c == '\n' || c == '\r') {
			uint64_t j = i;

			/* CRLF: the "\r" ends the statement and the "\n" after it an empty one - and a " _" before the "\r" goes on, from either */
			if (c == '\n' && j > st && t->p[j - 1u] == '\r')
				j--;

			/* " _" at the end of a line: the statement goes on */
			while (j > st && (t->p[j - 1u] == ' ' || t->p[j - 1u] == '\t') && t->kind[j - 1u] == KGENOME_TEXTUAL_CODE)
				j--;
			if (j > st && t->p[j - 1u] == '_' && t->kind[j - 1u] == KGENOME_TEXTUAL_CODE &&
			    (j - 1u == st || !name_byte(t->p[j - 2u])))
				continue;
			vb_statement(t, st, i, s);
			st = i + 1u;
		} else if (c == ':' && !(i + 1u < b && t->p[i + 1u] == '=')) {
			vb_statement(t, st, i, s);
			st = i + 1u;
		}
	}
	vb_statement(t, st, b, s);
}

/*
 * CFML: the tags that take an end tag (the cfml reference's block tags) open a block until `</cfname>`; a tag closed with "/>" opens
 * nothing; an end tag closes the nearest open tag of its name and every unclosed one above it, and one whose name is not open
 * closes nothing. A tag whose end tag is optional (cfexecute, cfhttp, cfinvoke, cfmodule ...) is not listed: it opens no block,
 * and its end tag, when written, finds nothing to close. [Unverified: the list is from the cfml reference, no engine here]
 */
static const char *const CF_BLOCK[] = { "cfif", "cfloop", "cffunction", "cfcomponent", "cfinterface", "cfoutput", "cfquery",
					"cftry", "cfcatch", "cffinally", "cfswitch", "cfcase", "cfdefaultcase", "cfsavecontent",
					"cfscript", "cfmail", "cfsilent", "cflock", "cftransaction", "cfthread", "cfform",
					"cfprocessingdirective", "cftimer", "cfdocument", "cfdocumentitem", "cfdocumentsection",
					"cfchart", "cfzip", "cfstoredproc", "cfxml", "cfwhile", NULL };

static uint32_t cf_hash(const uint8_t *p, uint64_t n)
{
	uint32_t h = 2166136261u;
	uint64_t i;

	for (i = 0; i < n; i++)
		h = (h ^ kgenome_script_lower(p[i])) * 16777619u;
	return h;
}

static int cf_block(const uint8_t *p, uint64_t n)
{
	const char *const *w;
	uint64_t k;

	for (w = CF_BLOCK; *w; w++) {
		if (strlen(*w) != n)
			continue;
		for (k = 0; k < n && kgenome_script_lower(p[k]) == (uint8_t)(*w)[k]; k++)
			;
		if (k == n)
			return 1;
	}
	return 0;
}

static void count_cfml(const struct kgenome_script_text *t, uint64_t a, uint64_t b, struct blk_state *s)
{
	uint64_t i;

	for (i = a; i + 3u < b; i++) {
		uint64_t ns, ne, j;
		int end_tag;
		uint32_t h;

		if (t->kind[i] != KGENOME_TEXTUAL_TAG || t->p[i] != '<')
			continue;
		end_tag = t->p[i + 1u] == '/';
		ns = i + 1u + (uint64_t)end_tag;
		if (ns + 2u > b || kgenome_script_lower(t->p[ns]) != 'c' || kgenome_script_lower(t->p[ns + 1u]) != 'f')
			continue;
		for (ne = ns; ne < b && t->kind[ne] == KGENOME_TEXTUAL_TAG && name_byte(t->p[ne]); ne++)
			;
		h = cf_hash(t->p + ns, ne - ns);
		if (end_tag) {
			uint32_t k = s->n_stack;

			while (k && s->stack[k - 1u] != h)
				k--;
			if (k) {
				s->n_stack = k - 1u;
				s->depth = s->n_stack;
			}
			i = ne - 1u;
			continue;
		}
		if (!cf_block(t->p + ns, ne - ns)) {
			i = ne - 1u;
			continue;
		}
		/* the tag's own end: the first TAG ">" after its name; "/>" closes it at once */
		for (j = ne; j < b && !(t->kind[j] == KGENOME_TEXTUAL_TAG && t->p[j] == '>'); j++)
			;
		if (j < b && j > ne && t->p[j - 1u] == '/' && t->kind[j - 1u] == KGENOME_TEXTUAL_TAG) {
			i = j;
			continue;
		}
		if (s->n_stack == s->cap_stack) {
			uint32_t nc = kgenome_grow_cap(s->cap_stack, 16u);
			uint32_t *ns2 = nc ? realloc(s->stack, (size_t)nc * sizeof *ns2) : NULL;

			if (!ns2) {
				s->oom = 1;
				return;
			}
			s->stack = ns2;
			s->cap_stack = nc;
		}
		s->stack[s->n_stack++] = h;
		s->depth = s->n_stack;
		i = ne - 1u;
	}
}

static void count_piece(const struct kgenome_script_text *t, const struct isl_row *row, const struct piece *pc, struct blk_state *s)
{
	switch (row->blk) {
	case BLK_PHP:
		count_php(t, pc->gs, pc->ge, s);
		break;
	case BLK_CFML:
		count_cfml(t, pc->gs, pc->ge, s);
		break;
	case BLK_PAGE: {
		/* The page's language is read once (a directive or the first server script names it: the walk is over the whole page);
		 * a <script runat="server"> piece may name its own, and only such a piece asks its tag. */
		uint8_t syn;

		if (!s->page_syn)
			s->page_syn = (uint8_t)kgenome_textual_page_syntax(t->lang, t->p, (uint32_t)t->n, (uint32_t)t->n);
		syn = s->page_syn;
		if (t->p[pc->gs] == '<' && pc->gs + 1u < t->n && (t->p[pc->gs + 1u] | 0x20u) == 's')
			syn = (uint8_t)kgenome_textual_page_syntax(t->lang, t->p, (uint32_t)t->n, (uint32_t)pc->gs);
		if (syn == KGENOME_TEXTUAL_SYN_VB)
			count_vb(t, pc->cs, pc->ce, s);
		else
			count_braces(t, pc->cs, pc->ce, s);
		break;
	}
	default:
		break;
	}
}

/* ---- level 0 ------------------------------------------------------------------------------------------------------------- */

struct l0_open {
	struct kgenome_script_island cur;
	int open;
	uint32_t pieces_with_code;
};

static int l0_flush(struct kgenome_script_islands *s, struct kgenome_script_isl_list *L, struct l0_open *o)
{
	o->open = 0;
	if (o->cur.pieces > 1u) {
		o->cur.flags |= KGENOME_SCRIPT_ISL_F_JOINED;
		s->n_joined += o->cur.pieces;
	}
	o->cur.parent = L->n;
	return isl_push(s, L, &o->cur);
}

/*
 * THE PIECES OF A TEXT AND THEIR JOINS, into level 0 of the server layer. A text whose language has no tags (row NULL) is one island,
 * the whole of it - the extent the similarity cut always had for such a text - when it holds any code.
 */
static void level0_server(const struct kgenome_script_text *t, struct kgenome_script_islands *s)
{
	const struct isl_row *row = row_of(t->lang);
	struct kgenome_script_isl_list *L = &s->lv[KGENOME_SCRIPT_ISL_SERVER][0];
	struct blk_state bs;
	struct l0_open o;
	uint64_t i = 0;

	if (!row) {
		struct kgenome_script_island e;

		if (!has_code(t, NULL, 0, t->n))
			return;
		memset(&e, 0, sizeof e);
		e.len = t->n;
		e.func = KGENOME_FUNCS_NONE;
		e.lang = (uint8_t)t->lang;
		(void)isl_push(s, L, &e);
		return;
	}
	memset(&bs, 0, sizeof bs);
	memset(&o, 0, sizeof o);
	while (i < t->n && s->status == KGENOME_OK) {
		struct piece pc;
		uint64_t ge;

		if (t->kind[i] == KGENOME_TEXTUAL_MARKUP) {
			i = run_end(t, i);
			continue;
		}
		for (ge = i; ge < t->n && t->kind[ge] != KGENOME_TEXTUAL_MARKUP; ge = run_end(t, ge))
			;
		piece_at(t, row, i, ge, &pc);
		i = ge;
		if (!pc.code && !o.open)
			continue;       /* a tag with nothing in it, a page comment: no island, and it opens nothing */
		s->n_pieces++;
		if (!o.open) {
			memset(&o.cur, 0, sizeof o.cur);
			o.cur.off = pc.cs;
			o.cur.func = KGENOME_FUNCS_NONE;
			o.cur.lang = (uint8_t)t->lang;
			o.open = 1;
		}
		o.cur.pieces++;
		o.cur.len = (pc.ce > o.cur.off ? pc.ce : o.cur.off) - o.cur.off;
		if (!pc.closed && pc.ge == t->n)
			o.cur.flags |= KGENOME_SCRIPT_ISL_F_OPEN;
		count_piece(t, row, &pc, &bs);
		if (bs.oom) {
			s->status = KGENOME_NOMEM;
			break;
		}
		if (!bs.depth && !l0_flush(s, L, &o))
			break;
	}
	if (o.open) {
		if (bs.depth)
			o.cur.flags |= KGENOME_SCRIPT_ISL_F_OPEN;       /* a block the text never closed */
		(void)l0_flush(s, L, &o);
	}
	free(bs.stack);
}

/* ---- level 1 ------------------------------------------------------------------------------------------------------------- */

/*
 * ONE LEVEL-0 ISLAND CUT IN SEQUENCE by the outermost functions whose extent meets it (owner-agreed design point 2): a FUNC island per
 * function, clipped to the level-0 island (a function that crosses its edge - only where the function table's own reading of the blocks
 * and the join's disagree - is cut there and flagged, so one layer never overlaps itself), and a RUN for each stretch between them that
 * holds code. `t` is the text the island's bytes were lexed in, `delta` where that text begins in the object, `fs` its functions in
 * that text's offsets (sorted and disjoint: script_funcs.c builds them so), `func_base` the index of fs->v[0] in the layer's table, and
 * *pf the walk's place in `fs`, carried from one island to the next.
 */
struct l1_req {
	const struct kgenome_script_text *t;
	const struct isl_row *row;
	const struct kgenome_func_set *fs;
	uint64_t delta;
	uint32_t layer, idx, func_base;
};

static int l1_emit(struct kgenome_script_islands *s, const struct l1_req *rq, uint64_t a, uint64_t b, uint8_t kind, uint32_t func,
		   uint16_t flags)
{
	struct kgenome_script_island e;

	if (kind == KGENOME_SCRIPT_ISL_RUN && !has_code(rq->t, rq->row, a, b))
		return 1;       /* white space, comments, markup: not an island */
	memset(&e, 0, sizeof e);
	e.off = a + rq->delta;
	e.len = b - a;
	e.parent = rq->idx;
	e.func = func;
	e.kind = kind;
	e.flags = flags;
	e.lang = (uint8_t)rq->t->lang;
	return isl_push(s, &s->lv[rq->layer][1], &e);
}

static int l1_cut(struct kgenome_script_islands *s, const struct l1_req *rq, uint32_t *pf)
{
	const struct kgenome_script_island *p0 = &s->lv[rq->layer][0].v[rq->idx];
	const struct kgenome_func_set *fs = rq->fs;
	uint64_t off = p0->off - rq->delta, end = off + p0->len, cur = off;
	uint32_t f = *pf;

	while (f < fs->n && fs->v[f].off + fs->v[f].len <= off)
		f++;
	for (; f < fs->n && fs->v[f].off < end; f++) {
		uint64_t fe = fs->v[f].off + fs->v[f].len;
		uint64_t a = fs->v[f].off > cur ? fs->v[f].off : cur;
		uint64_t b = fe < end ? fe : end;

		if (b <= a)
			continue;
		if ((a > cur && !l1_emit(s, rq, cur, a, KGENOME_SCRIPT_ISL_RUN, KGENOME_FUNCS_NONE, 0)) ||
		    !l1_emit(s, rq, a, b, KGENOME_SCRIPT_ISL_FUNC, rq->func_base + f,
			     (a != fs->v[f].off || b != fe) ? KGENOME_SCRIPT_ISL_F_CLIPPED : 0u))
			return 0;
		cur = b;
		if (fe > end)
			break;          /* it goes on into the next level-0 island */
	}
	*pf = f;
	return end <= cur || l1_emit(s, rq, cur, end, KGENOME_SCRIPT_ISL_RUN, KGENOME_FUNCS_NONE, 0);
}

static void level1_server(const struct kgenome_script_text *t, struct kgenome_script_islands *s, const struct kgenome_func_set *fs)
{
	struct l1_req rq = { .t = t, .row = row_of(t->lang), .fs = fs, .layer = KGENOME_SCRIPT_ISL_SERVER };
	uint32_t f = 0;

	for (rq.idx = 0; rq.idx < s->lv[KGENOME_SCRIPT_ISL_SERVER][0].n && s->status == KGENOME_OK; rq.idx++)
		if (!l1_cut(s, &rq, &f))
			break;
}

/* ---- the client layer ---------------------------------------------------------------------------------------------------- */

/*
 * THE JAVASCRIPT OF THE MARKUP (owner-agreed design point 4: the server language is partitioned first, the client language on the
 * markup it leaves, as a layer of its own). Read from the MARKUP bytes of the server's lex only - a "<script" written inside a php
 * string is not an element - as an html parser reads them [WHATWG html, 13.2 "Parsing HTML documents", from memory]:
 *   - <script> ... </script>: the body is code when the element has no `src` (a script with src runs the file and not its body) and
 *     its `type` is absent, empty, a javascript mime type or "module" (anything else is a data block: "text/template",
 *     "application/ld+json"); a `language` attribute alone names vbscript (an hta, old IE) or a javascript. The body ends at the first
 *     "</script" of the markup followed by white space, "/" or ">", in a string or not; not closed, it runs to the end (F_OPEN).
 *   - an attribute whose name is on + letters: its value is a function body the browser compiles (F_ATTR);
 *   - an attribute value that begins (after white space) with "javascript:": the rest of the value (F_ATTR).
 * A comment "<!-- -->" and the body of <style> and <textarea> hold no tags. A server piece inside a tag (`<a href="<?= $u ?>">`) is
 * bytes the walk steps over as part of the value they sit in.
 * THE WALK IS BOUNDED: a tag's attributes are read once and the walk never goes back, so each byte is read a bounded number of times;
 * an attribute's quote that never closes ends the tag at the text's end (the rest is that value), so a page of "<a \"" cannot make it
 * quadratic.
 */
struct client_region {
	uint64_t off, len;
	uint32_t lang;
	uint16_t flags;
};

struct client_walk {
	const struct kgenome_script_text *t;
	struct client_region *v;
	uint32_t n, cap;
	int oom;
};

static int cr_push(struct client_walk *w, uint64_t off, uint64_t end, uint32_t lang, uint16_t flags)
{
	if (end <= off)
		return 1;
	if (w->n == w->cap) {
		uint32_t nc = kgenome_grow_cap(w->cap, 16u);
		struct client_region *nv = nc ? realloc(w->v, (size_t)nc * sizeof *nv) : NULL;

		if (!nv) {
			w->oom = 1;
			return 0;
		}
		w->v = nv;
		w->cap = nc;
	}
	w->v[w->n].off = off;
	w->v[w->n].len = end - off;
	w->v[w->n].lang = lang;
	w->v[w->n].flags = flags;
	w->n++;
	return 1;
}

static int mk(const struct kgenome_script_text *t, uint64_t i)
{
	return t->kind[i] == KGENOME_TEXTUAL_MARKUP;
}

/* Does [i, i + len) of the markup spell `w`, in any case. */
static int mk_is(const struct kgenome_script_text *t, uint64_t i, const char *w)
{
	uint64_t k, l = strlen(w);

	if (i + l > t->n)
		return 0;
	for (k = 0; k < l; k++)
		if (!mk(t, i + k) || kgenome_script_lower(t->p[i + k]) != (uint8_t)w[k])
			return 0;
	return 1;
}

static int span_is(const struct kgenome_script_text *t, uint64_t s, uint64_t e, const char *w)
{
	uint64_t k, l = strlen(w);

	if (e - s != l)
		return 0;
	for (k = 0; k < l; k++)
		if (kgenome_script_lower(t->p[s + k]) != (uint8_t)w[k])
			return 0;
	return 1;
}

/* The end tag `</name` of a raw text element from `i`, followed by white space, "/" or ">": its offset, or n. */
static uint64_t mk_end_tag(const struct kgenome_script_text *t, uint64_t i, const char *name)
{
	uint64_t l = strlen(name);

	for (; i + 2u + l <= t->n; i++) {
		const uint8_t *q = memchr(t->p + i, '<', (size_t)(t->n - i));

		if (!q)
			break;
		i = (uint64_t)(q - t->p);
		if (i + 2u + l > t->n)
			break;
		if (mk(t, i) && t->p[i + 1u] == '/' && mk_is(t, i + 2u, name) &&
		    (i + 2u + l == t->n || blank(t->p[i + 2u + l]) || t->p[i + 2u + l] == '/' || t->p[i + 2u + l] == '>'))
			return i;
	}
	return t->n;
}

struct attr {
	uint64_t ns, ne, vs, ve;
	uint8_t  has_value;
};

/*
 * The next attribute of the tag from *pi, or 0 at the tag's ">" (markup) or the end. Bytes that are not markup (a server piece) are
 * part of whatever they sit in. A quoted value runs to the same quote in the markup. html's attribute rule, as textual_page.c's
 * attr_next reads a server page's directive - not that function: this one steps over the server's own pieces inside a tag, which that
 * one, reading a page before any lex, has no way to tell.
 */
static int isl_attr_next(const struct kgenome_script_text *t, uint64_t *pi, struct attr *a)
{
	uint64_t i = *pi, n = t->n;

	while (i < n && (!mk(t, i) || blank(t->p[i]) || t->p[i] == '/'))
		i++;
	if (i >= n || t->p[i] == '>') {
		*pi = i;
		return 0;
	}
	a->ns = i++;
	while (i < n && !(mk(t, i) && (blank(t->p[i]) || t->p[i] == '=' || t->p[i] == '>' || t->p[i] == '/')))
		i++;
	a->ne = i;
	while (i < n && mk(t, i) && blank(t->p[i]))
		i++;
	a->has_value = i < n && mk(t, i) && t->p[i] == '=';
	a->vs = a->ve = i;
	if (a->has_value) {
		for (i++; i < n && mk(t, i) && blank(t->p[i]); i++)
			;
		if (i < n && mk(t, i) && (t->p[i] == '"' || t->p[i] == '\'')) {
			uint8_t q = t->p[i];

			a->vs = ++i;
			while (i < n && !(mk(t, i) && t->p[i] == q))
				i++;
			a->ve = i;
			if (i < n)
				i++;
		} else {
			a->vs = i;
			while (i < n && !(mk(t, i) && (blank(t->p[i]) || t->p[i] == '>')))
				i++;
			a->ve = i;
		}
	}
	*pi = i;
	return 1;
}

/* A `type` that runs as javascript: empty, "module", or a javascript mime type (html: "JavaScript MIME type essence match"). */
static int js_type(const struct kgenome_script_text *t, uint64_t s, uint64_t e)
{
	static const char *const mime[] = { "module", "text/javascript", "application/javascript", "application/ecmascript",
					    "application/x-ecmascript", "application/x-javascript", "text/ecmascript", "text/jscript",
					    "text/livescript", "text/x-ecmascript", "text/x-javascript", "text/javascript1.0",
					    "text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
					    "text/javascript1.5", NULL };
	const char *const *m;
	uint64_t k;

	while (s < e && blank(t->p[s]))
		s++;
	while (e > s && blank(t->p[e - 1u]))
		e--;
	if (s == e)
		return 1;
	for (k = s; k < e && t->p[k] != ';'; k++)
		;
	for (m = mime; *m; m++)
		if (span_is(t, s, k, *m))
			return 1;
	return 0;
}

/* What a <script> tag's attributes say its body is: KGENOME_TEXTUAL_LANG_JS, _VBS, or 0 (no code: a src, a data block). */
static uint32_t script_lang(const struct kgenome_script_text *t, uint64_t i, uint64_t *tag_end)
{
	struct attr a;
	uint32_t lang = KGENOME_TEXTUAL_LANG_JS;
	int has_type = 0, src = 0;

	while (isl_attr_next(t, &i, &a)) {
		if (span_is(t, a.ns, a.ne, "src"))
			src = 1;
		else if (span_is(t, a.ns, a.ne, "type") && a.has_value) {
			has_type = 1;
			if (!js_type(t, a.vs, a.ve))
				lang = span_is(t, a.vs, a.ve, "text/vbscript") ? KGENOME_TEXTUAL_LANG_VBS : 0u;
		} else if (span_is(t, a.ns, a.ne, "language") && a.has_value && !has_type) {
			uint64_t s = a.vs;

			while (s < a.ve && blank(t->p[s]))
				s++;
			if (a.ve - s >= 8u && span_is(t, s, s + 8u, "vbscript"))
				lang = KGENOME_TEXTUAL_LANG_VBS;
			else if (!((a.ve - s >= 10u && span_is(t, s, s + 10u, "javascript")) ||
				   (a.ve - s >= 7u && span_is(t, s, s + 7u, "jscript")) ||
				   (a.ve - s >= 10u && span_is(t, s, s + 10u, "ecmascript")) ||
				   (a.ve - s >= 10u && span_is(t, s, s + 10u, "livescript"))))
				lang = 0;
		}
	}
	*tag_end = i < t->n ? i + 1u : t->n;
	return src ? 0u : lang;
}

/* The attributes of a tag that carry code: on* and a javascript: url. */
static int tag_attrs(struct client_walk *w, uint64_t i, uint64_t *tag_end)
{
	const struct kgenome_script_text *t = w->t;
	struct attr a;

	while (isl_attr_next(t, &i, &a)) {
		uint64_t s = a.vs;

		if (!a.has_value || a.ve <= a.vs)
			continue;
		if (a.ne - a.ns > 2u && kgenome_script_lower(t->p[a.ns]) == 'o' && kgenome_script_lower(t->p[a.ns + 1u]) == 'n') {
			uint64_t k;

			for (k = a.ns + 2u; k < a.ne && ((t->p[k] | 0x20u) >= 'a' && (t->p[k] | 0x20u) <= 'z'); k++)
				;
			if (k == a.ne && !cr_push(w, a.vs, a.ve, KGENOME_TEXTUAL_LANG_JS, KGENOME_SCRIPT_ISL_F_ATTR))
				return 0;
			continue;
		}
		while (s < a.ve && blank(t->p[s]))
			s++;
		if (a.ve - s > 11u && span_is(t, s, s + 11u, "javascript:") &&
		    !cr_push(w, s + 11u, a.ve, KGENOME_TEXTUAL_LANG_JS, KGENOME_SCRIPT_ISL_F_ATTR))
			return 0;
	}
	*tag_end = i < t->n ? i + 1u : t->n;
	return 1;
}

static void client_regions(struct client_walk *w)
{
	const struct kgenome_script_text *t = w->t;
	uint64_t i = 0, n = t->n;

	while (i < n && !w->oom) {
		const uint8_t *q = memchr(t->p + i, '<', (size_t)(n - i));
		uint64_t ns, ne, te;

		if (!q)
			break;
		i = (uint64_t)(q - t->p);
		if (!mk(t, i) || i + 1u >= n) {
			i++;
			continue;
		}
		if (mk_is(t, i, "<!--")) {
			uint64_t e = i + 4u;

			while (e + 3u <= n && !(t->p[e] == '-' && t->p[e + 1u] == '-' && t->p[e + 2u] == '>'))
				e++;
			i = e + 3u <= n ? e + 3u : n;
			continue;
		}
		ns = i + 1u;
		if (!(((t->p[ns] | 0x20u) >= 'a' && (t->p[ns] | 0x20u) <= 'z') && mk(t, ns))) {
			i++;
			continue;
		}
		for (ne = ns; ne < n && mk(t, ne) && (name_byte(t->p[ne]) || t->p[ne] == '-' || t->p[ne] == ':'); ne++)
			;
		if (span_is(t, ns, ne, "script")) {
			uint32_t lang = script_lang(t, ne, &te);
			uint64_t end = mk_end_tag(t, te, "script");

			if (lang && !cr_push(w, te, end, lang, end == n ? KGENOME_SCRIPT_ISL_F_OPEN : 0u))
				return;
			i = end < n ? end + 2u : n;
			continue;
		}
		if (!tag_attrs(w, ne, &te))
			return;
		if (span_is(t, ns, ne, "style") || span_is(t, ns, ne, "textarea")) {
			uint64_t end = mk_end_tag(t, te, span_is(t, ns, ne, "style") ? "style" : "textarea");

			i = end < n ? end + 2u : n;
			continue;
		}
		i = te > i ? te : i + 1u;
	}
}

/*
 * The client layer: each region lexed in its own language as code from its first byte (the one lex of THAT language over those bytes:
 * a byte of the page is lexed once per layer it is in), its functions read by that language's strategy, its level 0 the region when
 * it holds code, its level 1 cut by those functions.
 */
static void client_layer(const struct kgenome_script_text *t, struct kgenome_script_islands *s)
{
	struct client_walk w;
	struct kgenome_fntab_list cl;
	uint32_t r;

	memset(&w, 0, sizeof w);
	memset(&cl, 0, sizeof cl);
	w.t = t;
	client_regions(&w);
	if (w.oom)
		s->status = KGENOME_NOMEM;
	for (r = 0; r < w.n && s->status == KGENOME_OK; r++) {
		struct kgenome_script_text ct;
		struct kgenome_func_set fs;
		struct kgenome_script_island e;
		uint32_t k;

		if (!kgenome_script_text_make(w.v[r].lang, KGENOME_TEXTUAL_FRAGMENT, t->p + w.v[r].off, w.v[r].len, &ct)) {
			s->status = KGENOME_NOMEM;
			break;
		}
		if (has_code(&ct, NULL, 0, ct.n)) {
			struct l1_req rq = { .t = &ct, .fs = &fs, .delta = w.v[r].off, .layer = KGENOME_SCRIPT_ISL_CLIENT };
			uint32_t f = 0;

			kgenome_script_funcs_of_text(&ct, &fs);
			if (fs.status != KGENOME_OK)
				s->status = fs.status;
			memset(&e, 0, sizeof e);
			e.off = w.v[r].off;
			e.len = w.v[r].len;
			e.parent = s->lv[KGENOME_SCRIPT_ISL_CLIENT][0].n;
			e.func = KGENOME_FUNCS_NONE;
			e.flags = w.v[r].flags;
			e.lang = (uint8_t)w.v[r].lang;
			rq.idx = e.parent;
			rq.func_base = cl.n;
			if (isl_push(s, &s->lv[KGENOME_SCRIPT_ISL_CLIENT][0], &e))
				(void)l1_cut(s, &rq, &f);
			for (k = 0; k < fs.n && s->status == KGENOME_OK; k++) {
				fs.v[k].off += w.v[r].off;
				if (fs.v[k].name_len)
					fs.v[k].name_off += (uint32_t)w.v[r].off;
				if (!kgenome_fntab_list_add(&cl, &fs.v[k]) && cl.status == KGENOME_NOMEM)
					s->status = KGENOME_NOMEM;
			}
			cl.partial |= fs.partial;
			kgenome_funcs_free(&fs);
		}
		kgenome_script_text_free(&ct);
	}
	free(w.v);
	s->client_funcs.v = cl.v;
	s->client_funcs.n = cl.n;
	s->client_funcs.status = cl.status;
	s->client_funcs.partial = cl.partial;
	s->client_funcs.ccase = (uint8_t)KGENOME_FNTAB_C_SCRIPT;
	s->client_funcs.state = cl.partial ? KGENOME_FNTAB_PARTIAL : KGENOME_FNTAB_COMPLETE;
}

/* ---- the one call -------------------------------------------------------------------------------------------------------- */

void kgenome_script_islands_of_text(const struct kgenome_script_text *t, const struct kgenome_func_set *funcs, uint32_t want,
				    struct kgenome_script_islands *s)
{
	const struct isl_row *row = row_of(t->lang);

	memset(s, 0, sizeof *s);
	level0_server(t, s);
	if (s->status == KGENOME_OK)
		level1_server(t, s, funcs);
	if ((want & KGENOME_SCRIPT_PART_CLIENT) && row && row->client && s->status == KGENOME_OK)
		client_layer(t, s);
}

void kgenome_script_parts(const struct kgenome_script_parts_req *rq, struct kgenome_script_parts *out)
{
	struct kgenome_script_text t;
	uint32_t a, b;

	memset(out, 0, sizeof *out);
	if (!rq->in || !rq->n || rq->n > 0xffffffffu)
		return;
	if (!kgenome_script_text_make(rq->lang, rq->flags, rq->in, rq->n, &t)) {
		if (kgenome_textual_lang_known(rq->lang)) {
			out->funcs.status = KGENOME_NOMEM;
			out->isl.status = KGENOME_NOMEM;
		}
		return;
	}
	kgenome_script_funcs_of_text(&t, &out->funcs);
	if (rq->want & KGENOME_SCRIPT_PART_ISLANDS)
		kgenome_script_islands_of_text(&t, &out->funcs, rq->want, &out->isl);
	kgenome_script_text_free(&t);
	out->bytes = (uint64_t)out->funcs.n * sizeof *out->funcs.v + (uint64_t)out->isl.client_funcs.n * sizeof *out->isl.client_funcs.v;
	for (a = 0; a < KGENOME_SCRIPT_ISL_LAYERS; a++)
		for (b = 0; b < 2u; b++)
			out->bytes += (uint64_t)out->isl.lv[a][b].cap * sizeof *out->isl.lv[a][b].v;
}

void kgenome_script_parts_free(struct kgenome_script_parts *p)
{
	kgenome_funcs_free(&p->funcs);
	kgenome_script_islands_free(&p->isl);
	p->bytes = 0;
}
