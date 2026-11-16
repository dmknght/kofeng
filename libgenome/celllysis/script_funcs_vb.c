/*
 * script_funcs_vb.c - the functions of a VB text (script_private.h, kgenome_script_strategy): VBScript (a .vbs), the VBScript of a
 * classic ASP page, and VB.NET (an ASPX page's server code).
 *
 * THE SPECIFICATION READ (the VBScript Language Reference: Sub, Function, Property Get/Let/Set, Class, Rem, Exit, End statements;
 * the Visual Basic language specification for VB.NET: 7 "Types", 9.2 "Methods", 9.7 "Properties", 11.1 "Lambda expressions",
 * 13.1 "Lines" and "Line continuation"):
 *   - Case does not matter. STATEMENTS are separated by line breaks ("\n", "\r\n", a lone "\r", as the lexer reads them) and ":";
 *     " _" at the end of a line continues the statement on the next (the lexer's rule, textual_vb.c). In an ASP page every byte the
 *     lexer does not call code, a string or a comment (a tag "<%", "%>", the markup between islands) ends a statement too, so that
 *     "<% Sub f() %> html <% End Sub %>" is ONE function spanning islands, the markup included.
 *   - A FUNCTION is a statement "[<attributes>] [modifiers] Sub|Function name ..." or "... Property Get|Let|Set name ...", ended by
 *     the statement "End Sub", "End Function" or "End Property" ("End" and the word may be on two lines joined by " _"). The entry
 *     runs from the attribute, else the first modifier, else the keyword, to the end of the closing word. Modifiers: Public, Private,
 *     Friend, Protected, Shared, Default, Static, Overrides, Overridable, MustOverride, Overloads, Shadows, NotOverridable, Async,
 *     Iterator, and VB.NET's ReadOnly, WriteOnly, Partial, Widening, Narrowing. "Exit Sub" / "Exit Function" return and are not an
 *     end; "End" alone ends the program and "End If" etc. close other blocks: none of them is the end.
 *   - A VB.NET "[modifiers] Property name ..." (no Get/Let/Set) is a function only when its body follows: the next statement is
 *     "Get" or "Set"; otherwise it is an auto-implemented property, one statement, and not a unit.
 *   - NO BODY, NOT A UNIT: "Declare Sub|Function ... Lib", "Delegate Sub|Function", "MustOverride Sub|Function|Property", and every
 *     member of an "Interface ... End Interface". A Class / Module / Structure is not a function; its methods are units.
 *   - LAMBDAS (VB.NET) are nested in the method they are written in: "Function(x) x + 1" is one expression; a multi-line one
 *     ("Sub(x)" or "Function(x) [As T]" ending its line) is closed by its own "End Sub" / "End Function", which is counted and does
 *     not end the method.
 *   - A Sub / Function / Property statement while a function is open cannot be in a valid text (VB has no nested named
 *     procedures): the open one is closed there, OPEN (KGENOME_FN_F_END_OPEN, "the end is the next start", funcs.h) - so one missing
 *     "End Sub" does not swallow every function after it. At the end of the text an open function runs to it, OPEN.
 *   - Strings ("..."), comments (' and Rem) are the lexer's spans and never read. "[name]" (an escaped identifier) is code read
 *     as one piece ("[Sub]" at a statement's head is a name).
 * ONE PASS over the text, each byte read a bounded number of times (the blanks after a ")" that closes a lambda's parameters are
 * read twice), no stack: the lambdas open inside the function are a counter.
 *
 * MEASURED 2026-11-14 on /mnt/games/normtest/fix_island/corpus (read-only copies). 6 .vbs: 3 files with functions, 30 functions,
 * 0 END_OPEN - equal, file by file, to a line grep of Sub/Function declarations and of End Sub/End Function (17, 12, 1); the other 3
 * files hold "Function" only inside strings (a PowerShell payload). 17 .asp pages lexed by the asp lexer: 6 files, 59 functions,
 * 0 END_OPEN; checked by hand against the text: pouya.asp 23 (21 Sub/Function + 2 Property Get), Manisso.asp 19 (17 + 2),
 * kacak.asp 4 and proxy.asp 6 (each has one more "function" in a grep: JavaScript in the page's markup, not server code). No VB.NET
 * page on the machine (the 5 .aspx are C#): the VB.NET shapes are measured by the tests only.
 *
 * LIMITS, named: a VB.NET "Operator" and a "Custom Event"'s accessors are not units (their bodies stay in the remainder); a
 * lambda in another lambda's parameter list replaces the pending one; in an ASP page this strategy reads every island as VB
 * (a JScript island is the caller's to route elsewhere).
 */

#include "script_private.h"

#include <textual/textual.h>

struct vb_walk {
	const struct kgenome_script_text *t;
	struct kgenome_fntab_list *l;
	int      stmt;                  /* the next code begins a statement */
	uint64_t paren;
	int      lam;                   /* a "Sub(" / "Function(" whose ")" has not closed */
	uint64_t lam_paren;
	uint64_t nest;                  /* multi-line lambdas open in the function */
	int      iface;                 /* inside Interface ... End Interface */
	int      prop_wait;             /* a VB.NET Property header: a unit only if Get / Set follows */
	uint64_t prop_off, prop_name_off, prop_name_len;
	int      on;
	uint64_t off, name_off, name_len;
	int      nomem;
};

static int vb_name_start(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80u;
}

static int vb_name_byte(uint8_t c)
{
	return vb_name_start(c) || (c >= '0' && c <= '9');
}

static uint64_t vb_eol(const uint8_t *p, uint64_t n, uint64_t i)
{
	if (p[i] == '\n')
		return 1u;
	if (p[i] == '\r')
		return (i + 1u < n && p[i + 1u] == '\n') ? 2u : 1u;
	return 0;
}

/* Is the "_" at `i` a continuation: a whole word, only blanks after it to a line break. Past the break, or 0. */
static uint64_t vb_cont(const struct kgenome_script_text *t, uint64_t i)
{
	const uint8_t *p = t->p;
	uint64_t k = i + 1u, e;

	if (p[i] != '_' || (i && t->code[i - 1u] && vb_name_byte(p[i - 1u])))
		return 0;
	while (k < t->n && t->code[k] && (p[k] == ' ' || p[k] == '\t'))
		k++;
	if (k >= t->n || !t->code[k] || (e = vb_eol(p, t->n, k)) == 0)
		return 0;
	return k + e;
}

/* Past blanks and continuations. */
static uint64_t vb_skip(const struct kgenome_script_text *t, uint64_t i)
{
	uint64_t k;

	while (i < t->n && t->code[i]) {
		if (t->p[i] == ' ' || t->p[i] == '\t')
			i++;
		else if ((k = vb_cont(t, i)) != 0)
			i = k;
		else
			break;
	}
	return i;
}

/* The end of the code word at `i` (i itself when none starts there). */
static uint64_t vb_word_end(const struct kgenome_script_text *t, uint64_t i)
{
	if (i >= t->n || !t->code[i] || !vb_name_start(t->p[i]))
		return i;
	while (i < t->n && t->code[i] && vb_name_byte(t->p[i]))
		i++;
	return i;
}

/* Is [s, e) the word `w` (lower case), any case. */
static int vb_is(const struct kgenome_script_text *t, uint64_t s, uint64_t e, const char *w)
{
	uint64_t k, len = strlen(w);

	if (e - s != len)
		return 0;
	for (k = 0; k < len; k++)
		if (kgenome_script_lower(t->p[s + k]) != (uint8_t)w[k])
			return 0;
	return 1;
}

static int vb_modifier(const struct kgenome_script_text *t, uint64_t s, uint64_t e)
{
	static const char *const mods[] = {
		"public", "private", "friend", "protected", "shared", "default", "static", "overrides", "overridable",
		"mustoverride", "overloads", "shadows", "notoverridable", "async", "iterator", "readonly", "writeonly", "partial",
		"widening", "narrowing",
	};
	uint64_t k;

	for (k = 0; k < sizeof mods / sizeof mods[0]; k++)
		if (vb_is(t, s, e, mods[k]))
			return 1;
	return 0;
}

/*
 * The escaped identifier "[...]" at `i` that closes on its line: past it, or 0. A DATE LITERAL ("#10:30:00#") is not skipped: the
 * ":" in its time begins a "statement" whose head is a number or AM / PM, never a keyword, so reading it as a separator changes no
 * answer (a mutant that skipped it survived every test: no input tells the two apart).
 */
static uint64_t vb_piece(const struct kgenome_script_text *t, uint64_t i)
{
	const uint8_t *p = t->p;
	uint64_t k;

	for (k = i + 1u; k < t->n && t->code[k] && !vb_eol(p, t->n, k); k++)
		if (p[k] == ']')
			return k + 1u;
	return 0;
}

/* The name at `k`: a word or "[escaped]". Its end. */
static uint64_t vb_name(const struct kgenome_script_text *t, uint64_t k)
{
	uint64_t e;

	if (k < t->n && t->code[k] && t->p[k] == '[' && (e = vb_piece(t, k)) != 0)
		return e;
	return vb_word_end(t, k);
}

static void vb_emit(struct vb_walk *w, uint64_t end, uint16_t flags)
{
	w->on = 0;
	w->nest = 0;
	if (!kgenome_script_emit(w->l, w->off, end, w->name_off, w->name_len, flags))
		w->nomem = 1;
}

/* A function begins at `start`, named [no, ne). One that is open cannot hold it: it ends here, open. */
static void vb_open(struct vb_walk *w, uint64_t start, uint64_t no, uint64_t ne)
{
	if (w->on)
		vb_emit(w, start, KGENOME_FN_F_END_OPEN);
	w->on = 1;
	w->nest = 0;
	w->off = start;
	w->name_off = no;
	w->name_len = ne - no;
}

static void vb_stmt_end(struct vb_walk *w)
{
	w->stmt = 1;
	w->paren = 0;
	w->lam = 0;
}

/* "End" at the head of a statement, the word after it at [s, e): a closer. */
static void vb_end(struct vb_walk *w, uint64_t s, uint64_t e)
{
	const struct kgenome_script_text *t = w->t;

	if (vb_is(t, s, e, "interface")) {
		w->iface = 0;
	} else if (vb_is(t, s, e, "sub") || vb_is(t, s, e, "function") || vb_is(t, s, e, "property")) {
		if (!w->on)
			return;
		if (w->nest)
			w->nest--;
		else
			vb_emit(w, e, 0);
	}
}

/* The statement that begins at `i`: its attribute, modifiers and head word. Answers where the walk goes on. */
static uint64_t vb_head(struct vb_walk *w, uint64_t i)
{
	const struct kgenome_script_text *t = w->t;
	uint64_t k = i, e, start = t->n, h, he, nx, ne;
	int must = 0, wait = w->prop_wait;

	w->stmt = 0;
	w->prop_wait = 0;
	if (t->p[k] == '<') {
		/* an attribute block on the statement: "<WebMethod()> Public Function ..." */
		uint64_t j = k + 1u;

		while (j < t->n && t->code[j] && t->p[j] != '>' && !vb_eol(t->p, t->n, j))
			j++;
		if (j >= t->n || !t->code[j] || t->p[j] != '>')
			return i + 1u;
		start = k;
		k = vb_skip(t, j + 1u);
	}
	while ((e = vb_word_end(t, k)) > k && vb_modifier(t, k, e)) {
		if (start == t->n)
			start = k;
		must |= vb_is(t, k, e, "mustoverride");
		k = vb_skip(t, e);
	}
	h = k;
	he = vb_word_end(t, h);
	if (start == t->n)
		start = h;
	if (he == h)
		return h > i ? h : i + 1u;
	if (wait && (vb_is(t, h, he, "get") || vb_is(t, h, he, "set")) && !w->iface)
		vb_open(w, w->prop_off, w->prop_name_off, w->prop_name_off + w->prop_name_len);
	nx = vb_skip(t, he);
	ne = vb_name(t, nx);
	if (vb_is(t, h, he, "end")) {
		vb_end(w, nx, vb_word_end(t, nx));
		return ne > nx ? ne : he;
	}
	if (vb_is(t, h, he, "interface")) {
		if (!w->on)
			w->iface = 1;
		return he;
	}
	if (must || w->iface)
		return he;
	if (vb_is(t, h, he, "sub") || vb_is(t, h, he, "function")) {
		vb_open(w, start, nx, ne);
		return ne > nx ? ne : he;
	}
	if (vb_is(t, h, he, "property")) {
		uint64_t ge = vb_word_end(t, nx);

		if (vb_is(t, nx, ge, "get") || vb_is(t, nx, ge, "let") || vb_is(t, nx, ge, "set")) {
			uint64_t no = vb_skip(t, ge);

			vb_open(w, start, no, vb_name(t, no));
			return ge;
		}
		w->prop_wait = 1;               /* VB.NET: a unit if its next statement is Get or Set */
		w->prop_off = start;
		w->prop_name_off = nx;
		w->prop_name_len = ne - nx;
		return ne > nx ? ne : he;
	}
	return he;
}

/* A ")" closed a lambda's parameters at `after`: the lambda is multi-line when its line ends there, or "As T" follows. */
static void vb_lambda_close(struct vb_walk *w, uint64_t after)
{
	const struct kgenome_script_text *t = w->t;
	uint64_t k = vb_skip(t, after);

	w->lam = 0;
	if (k >= t->n || !t->code[k] || vb_eol(t->p, t->n, k) || vb_is(t, k, vb_word_end(t, k), "as"))
		w->nest++;
}

/* A byte of code after the statement's head, at `i`. Answers where the walk goes on. */
static uint64_t vb_code(struct vb_walk *w, uint64_t i)
{
	const struct kgenome_script_text *t = w->t;
	const uint8_t *p = t->p;
	uint64_t e;
	uint8_t c = p[i];

	if (vb_name_start(c)) {
		e = vb_word_end(t, i);
		if (w->on && (vb_is(t, i, e, "sub") || vb_is(t, i, e, "function")) && !(i && p[i - 1u] == '.')) {
			uint64_t k = vb_skip(t, e);

			if (k < t->n && t->code[k] && p[k] == '(') {
				w->lam = 1;
				w->lam_paren = w->paren;
			}
		}
		return e;
	}
	if (c >= '0' && c <= '9')
		return vb_word_end(t, i) > i ? vb_word_end(t, i) : i + 1u;
	if (c == '(') {
		w->paren++;
	} else if (c == ')') {
		if (w->paren)
			w->paren--;
		if (w->lam && w->paren == w->lam_paren)
			vb_lambda_close(w, i + 1u);
	}
	return i + 1u;
}

int kgenome_script_funcs_vb(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0, e;
	struct vb_walk w;

	memset(&w, 0, sizeof w);
	w.t = t;
	w.l = l;
	w.stmt = 1;
	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		i = 3u;
	while (i < n && !w.nomem) {
		uint8_t k = t->kind[i], c = p[i];

		if (k != KGENOME_TEXTUAL_CODE) {
			uint64_t r = i;

			while (r < n && t->kind[r] == k)
				r++;
			if (k == KGENOME_TEXTUAL_STRING)
				w.stmt = 0;
			else if (k != KGENOME_TEXTUAL_COMMENT)
				vb_stmt_end(&w);        /* a tag or the markup between islands */
			i = r;
		} else if ((e = vb_eol(p, n, i)) != 0) {
			vb_stmt_end(&w);
			i += e;
		} else if (c == ' ' || c == '\t') {
			i++;
		} else if ((e = vb_cont(t, i)) != 0) {
			i = e;
		} else if (c == ':') {
			vb_stmt_end(&w);
			i++;
		} else if (c == '[' && (e = vb_piece(t, i)) != 0) {
			w.stmt = 0;
			i = e;
		} else if (w.stmt) {
			i = vb_head(&w, i);
		} else {
			i = vb_code(&w, i);
		}
	}
	if (w.on && !w.nomem)
		vb_emit(&w, n, KGENOME_FN_F_END_OPEN);
	return !w.nomem;
}
