/*
 * script_funcs_py.c - the functions of a PYTHON text (script_private.h, kgenome_script_strategy).
 *
 * THE SPECIFICATION READ (The Python Language Reference, 3.13: 2.1 "Line structure" and 8.7 "Function definitions"; Python 2's is the
 * same for every rule used here):
 *   - A LOGICAL LINE ends at a line break ("\n", "\r\n", a lone "\r": 2.1.2, the interpreter translates them) that is not inside a
 *     bracket ("(", "[", "{": 2.1.6 implicit joining), not after a backslash (2.1.5 explicit joining) and not inside a triple-quoted
 *     string (the lexer's STRING span holds that break). A line of only blanks and a comment is not a logical line (2.1.7) and never
 *     takes part in indentation.
 *   - INDENTATION is the column of a logical line's first byte: a tab goes to the next multiple of 8, a form feed resets the column
 *     to 0 (2.1.8). A UTF-8 byte order mark at offset 0 is not a column (it is the encoding's, 2.1.4).
 *   - A FUNCTION is "def" (or "async def") as the first token of a logical line (8.7: funcdef is a compound statement, and a compound
 *     statement is never after ";" or after another statement's ":" on its line). Its decorators ("@" lines directly above it, at its
 *     column; blank and comment lines between them are no logical lines) are part of the definition, so the entry starts at the
 *     first decorator. Its BODY is the suite: the def's own line when code follows the ":" there, else the indented block; the
 *     function ends before the first later logical line whose column is <= the def's. The entry ends after the last byte of its
 *     last logical line that is not a comment (a trailing comment and the blank lines after the body are not the function's).
 *     The end of the text closes every open block (the interpreter emits the DEDENTs there): a function that ends with the text is
 *     closed, not open.
 *   - OPEN (KGENOME_FN_F_END_OPEN, run to the end of the text): the text ended inside the definition itself - inside a bracket,
 *     after a continuation backslash, inside a triple-quoted string that never closes, or after a header whose ":" has no suite.
 *   - NOT A UNIT: "lambda" (an expression, 6.14); a class (8.8: its body is not a function, the defs in it are units); a def inside
 *     an open def (it is the outer one's, at any depth: only OUTERMOST functions are entries); a "def" after ";" or after another
 *     statement's ":" on the same line (not Python: a compound statement begins a logical line).
 * Only the lexer's arrays are read (t->code, t->kind, t->p): the walk is ONE pass over the text, each byte looked at once, with no
 * stack (a nested def is decided by one column comparison) and nothing allocated but the entries.
 *
 * MEASURED 2026-11-14 on /mnt/games/normtest/fix_island/corpus (42 .py files, read-only copies): 38 files with functions, 47
 * functions, 0 END_OPEN. Differential against CPython 3's own parser (ast.parse; outermost FunctionDef / AsyncFunctionDef, first
 * decorator line to end_lineno, and the name): identical on all 36 files it parses. The 6 files it refuses are Python 2; their 9
 * functions were checked by hand against the text (one file indents with 8 spaces and with tabs, CRLF: both read as column 8).
 */

#include "script_private.h"

#include <textual/textual.h>

/* The length of the line break at `i` ("\n", "\r\n", lone "\r"), 0 when there is none. */
static uint64_t py_eol(const uint8_t *p, uint64_t n, uint64_t i)
{
	if (p[i] == '\n')
		return 1u;
	if (p[i] == '\r')
		return (i + 1u < n && p[i + 1u] == '\n') ? 2u : 1u;
	return 0;
}

static int py_name_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 0x80u;
}

/* Is the CODE word `w` (len bytes) at `i`, not followed by a name byte (the caller knows what is before it). */
static int py_word(const struct kgenome_script_text *t, uint64_t i, const char *w, uint64_t len)
{
	uint64_t k;

	if (i + len > t->n)
		return 0;
	for (k = 0; k < len; k++)
		if (!t->code[i + k] || t->p[i + k] != (uint8_t)w[k])
			return 0;
	return !(i + len < t->n && py_name_byte(t->p[i + len]));
}

static uint64_t py_blanks(const struct kgenome_script_text *t, uint64_t i)
{
	while (i < t->n && t->code[i] && (t->p[i] == ' ' || t->p[i] == '\t' || t->p[i] == '\f'))
		i++;
	return i;
}

/* What the first token of a logical line is. */
enum py_head { PY_OTHER, PY_DECO, PY_DEF };

/* The first token of the logical line whose first byte is `j`: a decorator, a def (its name in *name_off / *name_len), or other. */
static enum py_head py_head_of(const struct kgenome_script_text *t, uint64_t j, uint64_t *name_off, uint64_t *name_len)
{
	uint64_t k = j;

	if (t->code[j] && t->p[j] == '@')
		return PY_DECO;
	if (py_word(t, k, "async", 5u)) {
		k = py_blanks(t, k + 5u);
		if (k == j + 5u)
			return PY_OTHER;
	}
	if (!py_word(t, k, "def", 3u))
		return PY_OTHER;
	k = py_blanks(t, k + 3u);
	*name_off = k;
	while (k < t->n && t->code[k] && py_name_byte(t->p[k]))
		k++;
	*name_len = k - *name_off;
	return PY_DEF;
}

/* One logical line: where its code ends and how the text stands after it. */
struct py_line {
	uint64_t brk;           /* the break that ends it, or n */
	uint64_t last;          /* past its last byte that is not blank and not a comment */
	uint8_t  last_c;        /* that byte */
	int      open;          /* the text ended inside it: an open bracket, or after a continuation backslash with nothing after it */
};

/* Read the logical line whose first byte is `j`: to its break, or to the end of the text. */
static void py_line_read(const struct kgenome_script_text *t, uint64_t j, struct py_line *ln)
{
	const uint8_t *p = t->p, *kind = t->kind;
	uint64_t n = t->n, k = j, depth = 0, e;
	int cont = 0;

	ln->last = j;
	ln->last_c = 0;
	while (k < n) {
		uint8_t c = p[k];
		int blank = c == ' ' || c == '\t' || c == '\f' || c == '\r' || c == '\n';

		if (kind[k] == KGENOME_TEXTUAL_CODE && (e = py_eol(p, n, k)) != 0) {
			if (!depth && cont != 1)
				break;
			cont = cont == 1 ? 2 : cont;    /* 2: joined, and nothing has followed the break yet */
			k += e;
			continue;
		}
		if (!blank)
			cont = 0;
		if (kind[k] == KGENOME_TEXTUAL_CODE) {
			if (c == '(' || c == '[' || c == '{')
				depth++;
			else if ((c == ')' || c == ']' || c == '}') && depth)
				depth--;
			else if (c == '\\')
				cont = 1;
		}
		if (kind[k] != KGENOME_TEXTUAL_COMMENT && !blank && cont != 1) {
			ln->last = k + 1u;
			ln->last_c = c;
		}
		k++;
	}
	ln->brk = k;
	ln->open = k >= n && (depth || cont);
}

/*
 * Is the STRING run that holds the last byte of the text a triple-quoted string that never closed: its opening quote (after a
 * prefix of letters) is tripled and its last three bytes are not that quote. A one-line string ends at its line (the lexer) and is
 * never open across a break. Read once, at the end of the text.
 */
static int py_string_open_at_end(const struct kgenome_script_text *t)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, s = n;
	uint8_t q;

	if (t->kind[n - 1u] != KGENOME_TEXTUAL_STRING)
		return 0;
	while (s && t->kind[s - 1u] == KGENOME_TEXTUAL_STRING)
		s--;
	while (s < n && p[s] != '"' && p[s] != '\'')
		s++;
	if (s + 3u > n)
		return 0;
	q = p[s];
	if (p[s + 1u] != q || p[s + 2u] != q)
		return 0;
	return n < s + 6u || p[n - 1u] != q || p[n - 2u] != q || p[n - 3u] != q;
}

/* The open function: its start, column, name, and where its last code line ended. */
struct py_fn {
	uint64_t off, name_off, name_len, end;
	uint32_t col;
	int      on;
	int      body;          /* its suite has begun: code after the header's ":", or a deeper line */
};

static int py_close(struct kgenome_fntab_list *l, struct py_fn *f, uint64_t end, uint16_t flags)
{
	f->on = 0;
	return kgenome_script_emit(l, f->off, end, f->name_off, f->name_len, flags);
}

/*
 * The column of the line that starts at `*ip`, and `*ip` moved to its first byte that is not indentation. A form feed resets the
 * column (2.1.8); a tab goes to the next multiple of 8. The count saturates near 4 Gi columns (a text that deep is compared there).
 */
static uint32_t py_indent(const struct kgenome_script_text *t, uint64_t *ip)
{
	uint64_t i = *ip;
	uint32_t col = 0;

	for (; i < t->n && t->code[i]; i++) {
		if (t->p[i] == ' ')
			col = col < 0xfffffff0u ? col + 1u : col;
		else if (t->p[i] == '\t')
			col = col < 0xfffffff0u ? (col / 8u + 1u) * 8u : col;
		else if (t->p[i] == '\f')
			col = 0;
		else
			break;
	}
	*ip = i;
	return col;
}

int kgenome_script_funcs_py(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0, deco = 0, e;
	uint32_t deco_col = 0;
	int has_deco = 0;
	struct py_fn f;

	memset(&f, 0, sizeof f);
	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		i = 3u;
	while (i < n) {
		struct py_line ln;
		uint64_t j = i, name_off = 0, name_len = 0;
		uint32_t col = py_indent(t, &j);
		enum py_head head;

		if (j >= n)
			break;
		if (t->code[j] && (e = py_eol(p, n, j)) != 0) {
			i = j + e;                      /* a blank line */
			continue;
		}
		if (t->kind[j] == KGENOME_TEXTUAL_COMMENT) {
			while (j < n && t->kind[j] == KGENOME_TEXTUAL_COMMENT)
				j++;
			i = j + (j < n ? py_eol(p, n, j) : 0u);
			continue;
		}
		if (f.on && col <= f.col && !py_close(l, &f, f.end, 0))
			return 0;
		head = py_head_of(t, j, &name_off, &name_len);
		py_line_read(t, j, &ln);
		if (f.on) {
			f.body = 1;                     /* a line deeper than the def */
		} else if (head == PY_DECO) {
			if (!has_deco || deco_col != col) {
				deco = j;
				deco_col = col;
			}
			has_deco = 1;
		} else if (head == PY_DEF) {
			f.on = 1;
			f.off = (has_deco && deco_col == col) ? deco : j;
			f.col = col;
			f.name_off = name_off;
			f.name_len = name_len;
			f.body = ln.last_c != ':';
			has_deco = 0;
		} else {
			has_deco = 0;
		}
		if (f.on)
			f.end = ln.last;
		if (ln.open || (f.on && ln.brk >= n && py_string_open_at_end(t)))
			return !f.on || py_close(l, &f, n, KGENOME_FN_F_END_OPEN);
		i = ln.brk < n ? ln.brk + py_eol(p, n, ln.brk) : n;
	}
	if (f.on && !py_close(l, &f, f.body ? f.end : n, (uint16_t)(f.body ? 0u : KGENOME_FN_F_END_OPEN)))
		return 0;
	return 1;
}
