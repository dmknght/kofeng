/*
 * script_funcs_bat.c - the SUBROUTINES of a Windows batch text (script_private.h, kgenome_script_strategy).
 *
 * THE SPECIFICATION READ (cmd.exe's own help: "call /?", "goto /?", "exit /?"; there is no cmd.exe on this machine, so every rule
 * here is from that documentation and is [Unverified] against the interpreter):
 *   - Batch has no function declaration. A SUBROUTINE is a label ":name" at the start of a line (blanks before it allowed; "::" is
 *     a comment, the lexer's) that "CALL :name" names somewhere in the text, any case ("call /?": "CALL :label arguments"). A label
 *     nobody calls is a GOTO target, part of the code around it, and is not a unit. ":eof" is the end of the script, not a label.
 *   - It RETURNS at "GOTO :EOF" (or "GOTO EOF") and "EXIT /B". The entry runs from the label's ":" to the end of the line that holds
 *     the first such return at the subroutine's own top level: the first command of a line, or a command after a single "&" (an
 *     unconditional sequence), outside every "( ... )" block. DECIDED, and why: a return inside a block, on a line that begins with
 *     IF or FOR (cmd parses the rest of that line as the IF's or FOR's command, "&" included), or after "&&", "||" or "|" runs only
 *     on a condition (or in a pipe's own cmd), so the subroutine's code after it is still the subroutine's.
 *   - Without such a return it runs to the last non-blank line before the next label that starts another subroutine (cmd would fall
 *     through into it, but that code is the other subroutine's), and without one of those to the end of the text, OPEN
 *     (KGENOME_FN_F_END_OPEN: cmd returns at the end of the file, but nothing in the text says where the subroutine was meant to end).
 *   - A line ends at "\n" only; a CR is a blank (the lexer's rule). A UTF-8 byte order mark at the start of a line is not part of it.
 * Read from the lexer's arrays only: labels, "call", "goto" and "exit" are CODE bytes; REM and "::" lines are COMMENT, a quoted
 * word is STRING. ONE PASS over the lines collects the labels, the call targets and the returns; the calls are sorted once and every
 * label is looked up (O(n log n) in the number of calls), and one merge of the labels with the returns gives every end.
 *
 * MEASURED 2026-11-14 on /mnt/games/normtest/fix_island/corpus (17 .bat / .cmd files, read-only copies): 1 subroutine, 1 END_OPEN
 * (unzip.bat ":UnZipFile": no GOTO :EOF or EXIT /B after it before the end of the file; checked by hand). One file of the 17 holds a
 * "CALL :label" at all (grep): the corpus has almost no subroutines, so this strategy is measured by its tests.
 *
 * LIMITS, named: a parenthesis is counted wherever it is code, so an unbalanced ")" in ECHO text ("echo :)") can close a block
 * early or never; "CALL" to a label held in a variable ("call :%name%") names nothing here; a duplicated label is a unit at each
 * of its lines (cmd jumps to the first after the call).
 */

#include <stdlib.h>

#include "script_private.h"

#include <textual/textual.h>

struct bat_label {
	uint64_t off, name_off, name_len, line, prev_end;
};

struct bat_ret {
	uint64_t line, end;
};

struct bat_name {
	const uint8_t *p;
	uint64_t len;
};

struct bat_walk {
	const struct kgenome_script_text *t;
	struct bat_label *lab;
	struct bat_ret *ret;
	struct bat_name *call;
	uint64_t nlab, caplab, nret, capret, ncall, capcall;
	uint64_t depth;
	int nomem;
};

static int bat_name_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' ||
	       c >= 0x80u;
}

static int bat_blank(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r';
}

/* Where a label's or a call target's name ends: at a blank or a byte cmd reads as a delimiter or an operator. */
static uint64_t bat_label_end(const uint8_t *p, uint64_t i, uint64_t le)
{
	while (i < le && !bat_blank(p[i]) && !strchr("&|<>()+=;,", p[i]))
		i++;
	return i;
}

/* Is the word `w` (lower case) at `i`, any case, CODE, not followed by a name byte. Its end, or 0. */
static uint64_t bat_word(const struct kgenome_script_text *t, uint64_t i, uint64_t le, const char *w)
{
	uint64_t k, len = strlen(w);

	if (i + len > le)
		return 0;
	for (k = 0; k < len; k++)
		if (!t->code[i + k] || kgenome_script_lower(t->p[i + k]) != (uint8_t)w[k])
			return 0;
	return (i + len < le && bat_name_byte(t->p[i + len])) ? 0 : i + len;
}

static uint64_t bat_blanks(const struct kgenome_script_text *t, uint64_t i, uint64_t le)
{
	while (i < le && t->code[i] && (bat_blank(t->p[i]) || t->p[i] == '@'))
		i++;
	return i;
}

/* Is the command at `i` a return: "goto :eof", "goto eof", "exit /b". */
static int bat_is_return(const struct kgenome_script_text *t, uint64_t i, uint64_t le)
{
	uint64_t k;

	if ((k = bat_word(t, i, le, "goto")) != 0) {
		k = bat_blanks(t, k, le);
		if (k < le && t->p[k] == ':')
			k++;
		return bat_word(t, k, le, "eof") != 0;
	}
	if ((k = bat_word(t, i, le, "exit")) != 0) {
		k = bat_blanks(t, k, le);
		return k + 2u <= le && t->code[k] && t->p[k] == '/' && kgenome_script_lower(t->p[k + 1u]) == 'b' &&
		       !(k + 2u < le && ((t->p[k + 2u] | 0x20u) >= 'a' && (t->p[k + 2u] | 0x20u) <= 'z'));
	}
	return 0;
}

/* Grow `*v` (of `*cap` items of `size` bytes) to hold one more. */
static int bat_grow(void **v, uint64_t *cap, uint64_t n, size_t size)
{
	uint64_t c = *cap ? *cap * 2u : 64u;
	void *nv;

	if (n < *cap)
		return 1;
	if (c > SIZE_MAX / size)
		return 0;
	nv = realloc(*v, (size_t)c * size);
	if (!nv)
		return 0;
	*v = nv;
	*cap = c;
	return 1;
}

static void bat_add_call(struct bat_walk *w, uint64_t s, uint64_t e)
{
	void *v = w->call;

	if (!bat_grow(&v, &w->capcall, w->ncall, sizeof *w->call)) {
		w->nomem = 1;
		return;
	}
	w->call = v;
	w->call[w->ncall].p = w->t->p + s;
	w->call[w->ncall].len = e - s;
	w->ncall++;
}

/*
 * A line that is not a label, [ls, le), its first byte after a byte order mark at `j`: its calls, its blocks, and whether it returns at the top level (then `ce` is recorded,
 * the end of its last byte that is not blank).
 */
static void bat_line(struct bat_walk *w, uint64_t ls, uint64_t j, uint64_t le, uint64_t ce)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t k = bat_blanks(t, j, le), e;
	int cmdpos = 1, cond = 0, returned = 0;

	while (k < le && !w->nomem) {
		uint8_t c = p[k];

		if (!t->code[k]) {
			k++;
			cmdpos = 0;
			continue;
		}
		if (cmdpos && !bat_blank(c) && c != '@') {
			cmdpos = 0;
			if (!w->depth && (bat_word(t, k, le, "if") || bat_word(t, k, le, "for")))
				cond = 1;
			if (!w->depth && !cond && !returned && bat_is_return(t, k, le)) {
				void *v = w->ret;

				returned = 1;
				if (!bat_grow(&v, &w->capret, w->nret, sizeof *w->ret)) {
					w->nomem = 1;
					return;
				}
				w->ret = v;
				w->ret[w->nret].line = ls;
				w->ret[w->nret].end = ce;
				w->nret++;
			}
		}
		if (c == '(') {
			w->depth++;
		} else if (c == ')') {
			if (w->depth)
				w->depth--;
		} else if (c == '&' || c == '|') {
			if (k + 1u < le && p[k + 1u] == c) {
				cond = 1;               /* && and ||: the rest of the line runs on a condition */
				k++;
			} else if (c == '|') {
				cond = 1;               /* a pipe's commands run in a cmd of their own */
			}
			cmdpos = 1;
		} else if ((k == j || !t->code[k - 1u] || !bat_name_byte(p[k - 1u])) && (e = bat_word(t, k, le, "call")) != 0) {
			uint64_t m = bat_blanks(t, e, le);

			if (m < le && t->code[m] && p[m] == ':')
				bat_add_call(w, m + 1u, bat_label_end(p, m + 1u, le));
			k = e;
			continue;
		}
		k++;
	}
}

static int bat_cmp(const void *a, const void *b)
{
	const struct bat_name *x = a, *y = b;
	uint64_t i, m = x->len < y->len ? x->len : y->len;

	for (i = 0; i < m; i++) {
		uint8_t cx = kgenome_script_lower(x->p[i]), cy = kgenome_script_lower(y->p[i]);

		if (cx != cy)
			return cx < cy ? -1 : 1;
	}
	return x->len < y->len ? -1 : x->len > y->len ? 1 : 0;
}

/* Collect the labels, the calls and the returns, one line at a time. */
static void bat_collect(struct bat_walk *w)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0, last_ce = 0;

	while (i < n && !w->nomem) {
		const uint8_t *nl = memchr(p + i, '\n', (size_t)(n - i));
		uint64_t ls = i, le = nl ? (uint64_t)(nl - p) : n, ce = le, j = ls;

		while (ce > ls && (bat_blank(p[ce - 1u]) || p[ce - 1u] == '\f'))
			ce--;
		if (j + 3u <= le && p[j] == 0xefu && p[j + 1u] == 0xbbu && p[j + 2u] == 0xbfu)
			j += 3u;
		while (j < le && (p[j] == ' ' || p[j] == '\t'))
			j++;
		if (j < le && t->code[j] && p[j] == ':' && !(j + 1u < le && p[j + 1u] == ':')) {
			uint64_t ne = bat_label_end(p, j + 1u, le);
			void *v = w->lab;

			if (!bat_grow(&v, &w->caplab, w->nlab, sizeof *w->lab)) {
				w->nomem = 1;
				return;
			}
			w->lab = v;
			w->lab[w->nlab].off = j;
			w->lab[w->nlab].name_off = j + 1u;
			w->lab[w->nlab].name_len = ne - (j + 1u);
			w->lab[w->nlab].line = ls;
			w->lab[w->nlab].prev_end = last_ce;
			w->nlab++;
		} else {
			bat_line(w, ls, j, le, ce);
		}
		if (ce > j)
			last_ce = ce;
		i = le + 1u;
	}
}

/* Is the label `b` a subroutine: named by a call, and not ":eof". */
static int bat_called(const struct bat_walk *w, const struct bat_label *b)
{
	struct bat_name key;

	key.p = w->t->p + b->name_off;
	key.len = b->name_len;
	if (!key.len || (key.len == 3u && bat_cmp(&key, &(struct bat_name){ (const uint8_t *)"eof", 3u }) == 0))
		return 0;
	return w->ncall && bsearch(&key, w->call, (size_t)w->ncall, sizeof *w->call, bat_cmp) != NULL;
}

int kgenome_script_funcs_bat(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	struct bat_walk w;
	uint64_t li, r = 0, prev = 0;
	int ok = 1, have = 0;

	memset(&w, 0, sizeof w);
	w.t = t;
	bat_collect(&w);
	if (!w.nomem && w.ncall)
		qsort(w.call, (size_t)w.ncall, sizeof *w.call, bat_cmp);
	/* every called label, in order: its end is its first top-level return before the next called label */
	for (li = 0; li <= w.nlab && ok && !w.nomem; li++) {
		const struct bat_label *b = li < w.nlab ? &w.lab[li] : NULL;

		if (b && !bat_called(&w, b))
			continue;
		if (have) {
			const struct bat_label *a = &w.lab[prev];

			while (r < w.nret && w.ret[r].line <= a->line)
				r++;
			if (r < w.nret && (!b || w.ret[r].line < b->line))
				ok = kgenome_script_emit(l, a->off, w.ret[r].end, a->name_off, a->name_len, 0);
			else if (b)
				ok = kgenome_script_emit(l, a->off, b->prev_end, a->name_off, a->name_len, 0);
			else
				ok = kgenome_script_emit(l, a->off, t->n, a->name_off, a->name_len, KGENOME_FN_F_END_OPEN);
		}
		have = 1;
		prev = li;
	}
	free(w.lab);
	free(w.ret);
	free(w.call);
	return ok && !w.nomem;
}
