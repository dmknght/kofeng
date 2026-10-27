/*
 * diag_text.c - the TEXT route of the diagnose scan: what a script does, as the same nodes and links a binary's imports make.
 *
 * A script has no import table and no system call. What it asks of the system it asks by calling a function the runtime
 * provides, so a NODE is a call (or a construct, or a request variable) whose NAME is a row of the target's table
 * (nucleo_names_<lang>.c), and a LINK is a value flowing from one node into an argument of another: the call it is nested in,
 * or the variable it was assigned to and then used through. The nodes carry the capability words every other route does, so
 * a diagnose is written once - "something decoded, and what it made was run" - and is matched by the one matcher.
 *
 * ONE WALK FOR EVERY LANGUAGE. What the walk assumes of the language it reads - how a variable is written, what joins a qualifier to a
 * name, what ends a statement, which calls have a meaning of their own for their arguments - is the language's PROFILE ROW
 * (kgenome_dtx_lang, diag_text_lang_<name>.c), and php is one row of it. There is one tokenizer, one assignment walk, one set of scopes, one
 * evaluator; a language that needs something the row cannot say has a named hook in its row and the reason beside it.
 *
 * ONE READING OF THE TEXT. The lexer (kgenome_textual_lex) says what each byte is - code, string, comment, markup - and the
 * tokens are cut from its spans, so a name inside a comment or a literal is never a call. Nothing here reads the bytes a
 * second time to decide that.
 *
 * WHAT IT FOLLOWS AND WHAT IT DOES NOT, which is the same line the binary routes draw. It follows nesting and assignment
 * (textual order, one name one set of producers), a function name kept in a literal (`$f = 'sys' . 'tem'; $f($x)`), and a
 * call through a request value (`$_POST[0]($_POST[1])`). It does not follow control flow, functions the script defines, or
 * a value through an array it builds: a link it cannot prove is not recorded, and "not recorded" is an answer a diagnose
 * has to be able to live with - see KGENOME_DIAG_LINK_UNKNOWN for what the binary routes say when they lose a value.
 *
 * WHERE THE PARTS ARE: this file is the tokenizer (the lexer's spans into tokens), the links, the flow of a value into a frame, an assignment and the frames; the calls the walk makes and
 * the walk loop itself are diag_text_walk.c (moved out of this file when it reached the size ceiling: nothing in it changed); the language rows are
 * diag_text_lang_<name>.c and the one list of them diag_text_lang.c; how a qualified name is read ("os.system", "Runtime.exec") is
 * diag_text_chain.c (and the class of an object a call makes, diag_text_class.c); the scope of a variable diag_text_scope.c; the constant evaluator
 * diag_text_eval.c; the entry (the scan, the names, the constants told) diag_text_route.c. A call written without a bracket - `Execute x`,
 * `o.Run cmd`, a tag - is diag_text_stmt.c; a command line (sh, batch, powershell, tcl) diag_text_cmd.c; a string that holds code (a backtick,
 * `#{x}`, `$(cmd)`) diag_text_interp.c.
 *
 * COST: one lex, one pass over the tokens, one set of tables that grows with the text. Every allocation is charged to the
 * scan's ledger, and one refused stops the route with a status; nothing is cut silently.
 */

#include <stdlib.h>

#include "diag_text_walk.h"
#include <textual/textual.h>

int kgenome_dtx_charge(struct kgenome_dtx *x, uint64_t n)
{
	if (kgenome_ledger_charge(&x->s->led, n))
		return 1;
	kgenome_diag_note(x->s, KGENOME_OVER_BUDGET);
	x->oom = 1;
	return 0;
}

void kgenome_dtx_cut_at(struct kgenome_dtx *x, const char *file, int line)
{
	kgenome_diag_note_at(x->s, KGENOME_TRUNCATED, file, line);
}

int kgenome_dtx_oa_grow(struct kgenome_dtx *x, void **tab, uint32_t *cap, uint32_t n, uint32_t first, size_t elem, kgenome_oatab_hash_fn hash)
{
	uint32_t nc = kgenome_oatab_want(n, *cap, first);

	if (!nc)
		return 1;
	if (!kgenome_dtx_charge(x, (uint64_t)nc * elem))
		return 0;
	if (!kgenome_oatab_rehash(tab, cap, nc, elem, hash, x, &x->probes)) {
		kgenome_diag_note(x->s, KGENOME_NOMEM);
		x->oom = 1;
		return 0;
	}
	return 1;
}

static int continues_line(const struct kgenome_dtx *x, uint32_t off);

int kgenome_dtx_push(struct kgenome_dtx *x, uint32_t off, uint32_t len, uint8_t k, uint8_t open, uint8_t close, uint8_t fl)
{
	if (x->nt && x->t[x->nt - 1u].k == 'T' && k == 'P' && continues_line(x, off))
		x->nt--;
	if (x->nt == x->cap) {
		uint32_t nc = x->cap ? x->cap * 2u : 1024u;
		struct kgenome_dtx_tok *nv;

		if (!kgenome_dtx_charge(x, (uint64_t)(nc - x->cap) * sizeof *x->t))
			return 0;
		nv = realloc(x->t, (size_t)nc * sizeof *x->t);
		if (!nv) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			x->oom = 1;
			return 0;
		}
		x->t = nv;
		x->cap = nc;
	}
	x->t[x->nt++] = (struct kgenome_dtx_tok){ off, len, k, open, close, fl };
	return 1;
}

/* A line that begins with one of these goes on from the one before: the statement-end the line break made is taken back. */
static int continues_line(const struct kgenome_dtx *x, uint32_t off)
{
	return kof_byte_in_set(x->in[off], ".?:&|*%^<>=,");
}

/* A byte of a name: letters, digits and "_", and what the language's row adds (php's namespace backslash, js's "$"). Not isalnum: the sink asks
 * for every byte of the text, and a call into the C library per byte was a tenth of the route. */
int kgenome_dtx_identc(const struct kgenome_dtx *x, uint8_t c)
{
	const char *e;

	if (kof_is_word_byte(c) || c >= 0x80u)
		return 1;
	e = x->lang->ident_extra;
	return (c == '\\' && x->lang->ident_bs) || kof_byte_in_set(c, e);
}

/* A byte a command word may begin with, or hold, besides the name bytes: `-c`, `/bin/sh`, `./x`, `C:\\x.exe`. Only for a command line (row `cmd`). */
static int cmdc(const struct kgenome_dtx *x, uint8_t c, int first)
{
	const char *set = first ? x->lang->cmd_start : x->lang->cmd_bytes;

	return kof_byte_in_set(c, set);
}

/* White space, and the NUL byte: no language of the table has a token that is a NUL, an interpreter either stops at one or skips it, and as a token of its own it stood between a
 * line break and the first word of the line and kept that word from beginning a statement (G12). */
static int space_(uint8_t c)
{
	return c == ' ' || c == 0 || (uint8_t)(c - '\t') < 5u;
}

/* The first non-space byte at or after `j` (in the whole text, not the span: a name's "(" may be on the next span), or 0. */
static uint8_t next_byte(const struct kgenome_dtx *x, uint32_t j)
{
	while (j < x->n_in && space_(x->in[j]))
		j++;
	return j < x->n_in ? x->in[j] : 0u;
}

/* Is this name one of the row's keywords: the first byte and the length say no for nearly every name before the list is read. */
static int is_keyword(const struct kgenome_dtx *x, const uint8_t *p, uint32_t len)
{
	return len >= x->kwmin && len <= x->kwmax && (x->kwfirst[p[0] >> 3] >> (p[0] & 7u) & 1u) &&
	       (kgenome_dtx_word_in(x->lang->keywords, p, len, x->lang->fold) || kgenome_dtx_word_in(x->lang->stmt_words, p, len, x->lang->fold) ||
		kgenome_dtx_word_in(x->lang->stmt_lead, p, len, x->lang->fold));
}

/* A bare name that is a variable: no digit begins it, it is no keyword of the language, and no call follows it. Members (what a join
 * precedes) are decided by the walk, which has the tokens in front of it. */
static int is_bare_var(const struct kgenome_dtx *x, uint32_t off, uint32_t len)
{
	return next_byte(x, off + len) != '(' && (uint8_t)(x->in[off] - '0') >= 10u && !is_keyword(x, x->in + off, len);
}

/*
 * THE END OF A STATEMENT THAT THE TEXT DOES NOT WRITE AS A BYTE. Python, ruby and lua have no ";", and js and vb may leave it out, so the line
 * break is the token the assignment walk ends a right side at - without it `x = decode(y)` followed by `eval(x)` is ONE statement and the
 * eval would be a producer of x. Not where the line goes on: inside a "(" or "[" (a call's arguments over several lines), after an operator,
 * a comma, a dot or a backslash, before one that begins the next line (a method chain), or after vb's "_". A `{` is no bracket here: it opens
 * a block as often as a literal, and what is inside a literal ends at a comma. The token is dropped again when the next one is such a
 * continuation (kgenome_dtx_sink).
 */
/* KNOWN DEFECT REV-D4 (2026-10-24, R) [sev L]: ends_statement decides vb's "_" continuation again (a one-byte I/V token "_" before the break) while the lexer already decided it in kgenome_textual_vb_cont.
 * Trigger: `a = b _ 'note` (a "_" before a comment is no continuation for the lexer) or "_" closed up on a name. Effect: the graph row may keep a statement open that the lexer ended, or end one it continued.
 * Reproducer: none yet (needs a red test over a vbs/aspx text with "_ '"). Fix: read the lexer's decision (a span flag for the continuation) and delete the byte test here. */
static int ends_statement(const struct kgenome_dtx *x)
{
	const struct kgenome_dtx_tok *t;

	if (!x->nt || x->depth > 0)
		return 0;
	t = &x->t[x->nt - 1u];
	if (t->k == 'T')
		return 0;
	if (t->k == 'P')
		return !kof_byte_in_set(x->in[t->off], "+-*/%=<>&|^,.([{!?:~\\");
	return !(x->lang->cont_us && (t->k == 'I' || t->k == 'V') && t->len == 1u && x->in[t->off] == '_');
}

int kgenome_dtx_push_term(struct kgenome_dtx *x, uint32_t off)
{
	if (!ends_statement(x))
		return !x->oom;
	return kgenome_dtx_push(x, off, 0, 'T', 0, 0, 0);
}

/* The end of the name that begins at `j` and closes with "}" at or before `end`: where the "}" is, 0 when something other than a name byte comes first. */
static uint32_t braced_end(const struct kgenome_dtx *x, uint32_t j, uint32_t end)
{
	uint32_t from = j;

	while (j < end && kgenome_dtx_identc(x, x->in[j]))
		j++;
	return j > from && j < end && x->in[j] == '}' ? j : 0u;
}

/* The lexer's spans, cut into tokens as they arrive: code is names, variables and punctuation, a string is one token, and
 * comments and markup are nothing - except where the language says the end of a line or of an island is the end of a statement. */
int kgenome_dtx_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct kgenome_dtx *x = u;
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t j = sp->off + x->shift, end = j + sp->len;
	const uint8_t cmd = l->cmd, sigil = (uint8_t)l->sigil;         /* the loop below is the hot one: what a row says is read once, not at every byte */

	if (sp->kind == KGENOME_TEXTUAL_STRING) {
		/* a string is one token unless the row reads what it holds: every string that interpolates, or one that begins like a command (the openers' first bytes are a set made once) */
		if (!l->interp_all && !(l->interp && sp->open_len && (x->cmdfirst[x->in[j] >> 3] >> (x->in[j] & 7u) & 1u)))
			return kgenome_dtx_push(x, j, sp->len, 'S', (uint8_t)sp->open_len, (uint8_t)sp->close_len, sp->flags);
		return kgenome_dtx_sink_str(x, sp, j);
	}
	if (sp->kind != KGENOME_TEXTUAL_CODE) {
		if (sp->kind == KGENOME_TEXTUAL_TAG && l->tag_calls)
			return kgenome_dtx_sink_tag(x, sp, j);
		if (l->island_term && (sp->kind == KGENOME_TEXTUAL_TAG || sp->kind == KGENOME_TEXTUAL_MARKUP))
			return kgenome_dtx_push_term(x, j);
		return !x->oom;
	}
	while (j < end) {
		uint8_t c = x->in[j];
		uint32_t k;

		if (space_(c)) {
			if (l->eol_term && (c == '\n' || c == '\r') && kgenome_dtx_eol(x->in, x->n_in, j) && !kgenome_dtx_push_term(x, j))
				return 0;
			j++;
			continue;
		}
		if (sigil && c == sigil && j + 1u < end && kgenome_dtx_identc(x, x->in[j + 1u])) {
			for (k = j + 1u; k < end && kgenome_dtx_identc(x, x->in[k]); k++)
				;
			if (!kgenome_dtx_push(x, j + 1u, k - j - 1u, 'V', 0, 0, 0))
				return 0;
			j = k;
		} else if (kgenome_dtx_identc(x, c) || (kof_byte_in_set(c, l->ident_pre) && j + 1u < end && kgenome_dtx_identc(x, x->in[j + 1u])) ||
			   (cmd && cmdc(x, c, 1))) {
			/* a name; in a command line it holds the bytes of a path and an option too ("-c", "/bin/sh"), which a name of another language does not */
			if (cmd)
				for (k = j + 1u; k < end && (kgenome_dtx_identc(x, x->in[k]) || cmdc(x, x->in[k], 0)); k++)
					;
			else
				for (k = j + 1u; k < end && kgenome_dtx_identc(x, x->in[k]); k++)
					;
			/* a bare-variable language: a name that is not a call, a member or a keyword is a variable (a member is made 'I' when the
			 * walk meets it: see kgenome_dtx_member) */
			if (!kgenome_dtx_push(x, j, k - j, !sigil && !cmd && !kgenome_dtx_join_before(x, x->nt) && is_bare_var(x, j, k - j) ? 'V' : 'I', 0, 0, 0))
				return 0;
			j = k;
		} else if (cmd && sigil && c == sigil && j + 2u < end && x->in[j + 1u] == '{' && (k = braced_end(x, j + 2u, end)) != 0) {
			/* `${name}`: a variable, written with its braces; one with anything else inside is an expansion this does not read */
			if (!kgenome_dtx_push(x, j + 2u, k - j - 2u, 'V', 0, 0, 0))
				return 0;
			j = k + 1u;
		} else {
			if ((c == '(' || c == '[') && cmd != 2u)
				x->depth++;
			else if ((c == ')' || c == ']') && x->depth > 0)
				x->depth--;
			else if (c == '{') {
				if (x->nds == x->cdstk && !kgenome_dtx_grow(x, (void **)&x->dstk, &x->cdstk, x->nds + 1u, sizeof *x->dstk))
					return 0;
				x->dstk[x->nds++] = x->depth;
				x->depth = 0;
			} else if (c == '}') {
				if (x->nds)
					x->depth = x->dstk[--x->nds];
			}
			if (!kgenome_dtx_push(x, j, 1u, 'P', 0, 0, 0))
				return 0;
			j++;
		}
	}
	return !x->oom;
}

int kgenome_dtx_is_term(const struct kgenome_dtx *x, uint32_t i)
{
	return i < x->nt && (x->t[i].k == 'T' || kgenome_dtx_is_p(x, i, ';') || (x->lang->sep && kgenome_dtx_is_p(x, i, (char)x->lang->sep)));
}

/* The capability a name has in the language's table (0 when it is none). A name that does not fit is REFUSED, never cut. */
uint16_t kgenome_dtx_cap_of(struct kgenome_dtx *x, uint32_t i)
{
	return kgenome_dtx_cap(x, x->in + x->t[i].off, x->t[i].len, NULL);
}

/* ---- the walk ------------------------------------------------------------- */

void kgenome_dtx_link(struct kgenome_dtx *x, int32_t from, int32_t to, uint32_t arg)
{
	struct kgenome_diag_hit *h;

	if (from < 0 || to < 0 || from == to)
		return;
	h = kgenome_diag_hit_of(x->s, (uint32_t)to);
	if (!h)
		return;
	if ((uint32_t)from >= KGENOME_DTX_PSEUDO) {     /* a parameter's or a return's slot: the producers are not known until the text is read (diag_text_sum.c) */
		kgenome_dtx_sum_pend(x, (uint32_t)from, (uint32_t)to, kgenome_diag_role_of_arg(h->cap, arg));
		return;
	}
	kgenome_diag_note_in(x->s, h, (uint16_t)from, kgenome_diag_role_of_arg(h->cap, arg), KGENOME_DIAG_KIND_PRODUCED);
}

/* The capability of a producer that is a node, NONE for a slot of a summary (it is no node). */
uint16_t kgenome_dtx_prod_cap(const struct kgenome_dtx *x, uint32_t p)
{
	return p < KGENOME_DTX_PSEUDO && p < x->s->n_hit ? x->s->hit[p].cap : (uint16_t)KGENOME_NUCLEO_NONE;
}

void kgenome_dtx_link_role(struct kgenome_dtx *x, int32_t from, int32_t to, uint8_t role)
{
	struct kgenome_diag_hit *h;

	if (from < 0 || to < 0 || from == to)
		return;
	h = kgenome_diag_hit_of(x->s, (uint32_t)to);
	if (!h)
		return;
	if ((uint32_t)from >= KGENOME_DTX_PSEUDO) {
		kgenome_dtx_sum_pend(x, (uint32_t)from, (uint32_t)to, role);
		return;
	}
	kgenome_diag_note_in(x->s, h, (uint16_t)from, role, KGENOME_DIAG_KIND_PRODUCED);
}

/* A value produced here (a node, or a variable's producers): into the argument of the call it sits in, or - at the top of
 * an assignment's right side - into the variable being assigned. */
/* A value produced inside the arguments a call-with-an-out-argument reads, through calls that are no node: kept for what that
 * call writes. 1 when it was taken there (then it goes nowhere else: the call returns no value the program uses). */
/* One producer into the sources of an OUT call's frame: a repeat is one, and past the room the frame has the rest are lost and the scan says so (a node and a slot have a list each). */
static void out_src(struct kgenome_dtx *x, struct kgenome_dtx_frame *f, uint32_t p)
{
	uint8_t i;

	if (p >= KGENOME_DTX_PSEUDO) {
		for (i = 0; i < f->npsrc; i++)
			if (f->psrc[i] == p)
				return;
		if (f->npsrc < KGENOME_DTX_PDEFS)
			f->psrc[f->npsrc++] = p;
		else
			kgenome_dtx_cut(x);
		return;
	}
	for (i = 0; i < f->nsrc; i++)
		if (f->src[i] == p)
			return;
	if (f->nsrc < KGENOME_DTX_OUTP_MAX_SRC)
		f->src[f->nsrc++] = p;
	else
		kgenome_dtx_cut(x);
}

static int capture_out(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v)
{
	struct kgenome_dtx_frame *f;
	uint32_t k;
	uint8_t i;

	/* the first frame from the top that is not a plain grouping (`dec`, set when it was pushed): the ones between do nothing to a value */
	if (w->ovf || !w->nf)
		return 0;
	k = w->fr[w->nf - 1u].dec;
	if (!k)
		return 0;
	f = &w->fr[k - 1u];
	if (f->site >= 0)
		return 0;
	if (f->drop)
		return 1;               /* nothing that is made inside it goes anywhere */
	if (!(f->op->src >> f->arg & 1u))
		return 0;
	if (node >= 0)
		out_src(x, f, (uint32_t)node);
	for (i = 0; v && i < v->n_def; i++)
		out_src(x, f, v->def[i]);
	for (i = 0; v && i < v->n_pdef; i++)
		out_src(x, f, v->pdef[i]);
	return 1;
}

/* The capabilities whose first argument (or the one a call row names) is what they act on, and whose other arguments are data. */
static int is_valued(uint16_t cap)
{
	return cap == KGENOME_NUCLEO_EVAL || cap == KGENOME_NUCLEO_DECODE || cap == KGENOME_NUCLEO_CREATE || cap == KGENOME_NUCLEO_DYNCALL ||
	       cap == KGENOME_NUCLEO_DYNLOAD;
}

/*
 * THE TWO PLACES A VALUE IS KEPT FOR A SUMMARY (diag_text_sum.c), in addition to where it goes anyway: the arguments of a call of a function the text defines, and the expression of a
 * `return`. A value is part of one only until a NODE takes it - what a node is given is data for it and the node is what comes out - and not inside a call that makes another
 * kind of value (`drop`): the same two stops the walk's own flow has. Everything between the value and the bracket that holds it is a call whose result is made of its arguments, so
 * `f(g($x))` gives f's parameter what flowed into g's, as it gives any unknown call's result.
 */
static void sum_taps(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v)
{
	uint32_t k;
	int open = 1;

	if (!w->nufn && !w->ret_fn)
		return;
	for (k = w->nf; k > 0 && !w->ovf; k--) {
		const struct kgenome_dtx_frame *f = &w->fr[k - 1u];

		if (w->ret_fn && k - 1u < w->ret_nf)    /* outside the function the return is in */
			break;
		if (f->site >= 0 || f->drop) {
			open = 0;
			break;
		}
		if (f->ufn) {
			kgenome_dtx_sum_arg(x, f->ufn, f->uscope, f->arg, node, v);
			if (kgenome_dtx_sum_bound(x, f->ufn, f->uscope, f->arg)) {
				open = 0;               /* the call's result is what the function returns, not what it was given: nothing it ignores is returned by an enclosing function */
				break;
			}
		}
	}
	if (w->ret_fn && open && !w->ovf)
		kgenome_dtx_sum_ret(x, w->ret_fn, node, v);
}

/*
 * THE CALL OF A FUNCTION THE TEXT DEFINES STANDS FOR WHAT THE FUNCTION RETURNS (G3). A value inside an argument that a parameter holds is the summary's - the edge from the parameter's
 * slot (sum_taps), and the call's return slot flowing where the call stands once its bracket closes - and it does not also pass through the call as the operand of its result: that is
 * how a call is read when nothing is known about it. 1 when the value is taken by such a call, between it and the first node or call whose result is another kind of value.
 */
static int taken_by_call(const struct kgenome_dtx_walk *w, struct kgenome_dtx *x)
{
	uint32_t k;

	if (!w->nufn)
		return 0;
	for (k = w->nf; k > 0 && !w->ovf; k--) {
		const struct kgenome_dtx_frame *f = &w->fr[k - 1u];

		/* a frame outside the assignment or the `return` the value belongs to is not where it goes: `define(id, deps, function () { var xhr = new XMLHttpRequest(); ... })` holds the value
		 * in a variable of the function written inside its argument, and the call does not take it (the same stops sum_taps has) */
		if ((w->asg && k - 1u < w->a_nf) || (w->ret_fn && k - 1u < w->ret_nf))
			return 0;
		if (f->site >= 0 || f->drop)
			return 0;
		if (f->ufn && kgenome_dtx_sum_bound(x, f->ufn, f->uscope, f->arg))
			return 1;
	}
	return 0;
}

void kgenome_dtx_flow(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v)
{
	uint32_t i;
	int32_t cons = -1;
	uint32_t arg = 0;

	if (v && v->lost)               /* a variable read with less than it was given (a producer was pushed out of its list): said */
		kgenome_dtx_cut(x);
	if (w->drop_next) {             /* the operand of a numeric cast: `(int)$a` is a number */
		w->drop_next = 0;
		return;
	}
	if (capture_out(x, w, node, v))
		return;
	if (x->sum) {
		sum_taps(x, w, node, v);
		if (taken_by_call(w, x))
			return;
	}

	if (w->nsf) {
		const struct kgenome_dtx_frame *f = &w->fr[w->sfi[w->nsf - 1u]];

		cons = f->site;
		arg = f->arg;
		/* an argument that is not the one the node acts on is data for what it runs, not what runs */
		if (cons >= 0 && is_valued(x->s->hit[cons].cap)) {
			if (arg != (f->op ? f->op->val : 0u))
				return;
			arg = 0;                /* the argument the node acts on is the one its roles are written for */
		}
	}
	if (cons >= 0 && (!w->asg || w->nsf > w->a_nsf)) {
		if (node >= 0)
			kgenome_dtx_link(x, node, cons, arg);
		if (v)
			for (i = 0; i < kgenome_dtx_var_nprod(v); i++)
				kgenome_dtx_link(x, (int32_t)kgenome_dtx_var_prod(v, i), cons, arg);
	} else if (w->asg && w->av && !(x->lang->cmd && w->nf > w->a_nf) &&
		   (!x->lang->fn_opaque || x->scope[w->cur < x->nt ? w->cur : x->nt - 1u] == w->a_scope)) {
		if (node >= 0)
			kgenome_dtx_var_def(w->av, (uint32_t)node);
		if (v)
			for (i = 0; i < kgenome_dtx_var_nprod(v); i++)
				kgenome_dtx_var_def(w->av, kgenome_dtx_var_prod(v, i));
	} else if (x->lang->cmd) {
		kgenome_dtx_cmd_out(w, node, v);        /* what a segment made and nothing took: the input of the command after a "|" */
	}
}

/* The request has been poured into the variables of the scope token `tok` is in (see struct kgenome_dtx, extract_src). */
static void note_extract(struct kgenome_dtx *x, int32_t node, uint32_t tok)
{
	x->extract_src = node;
	x->extract_scope = x->scope[tok];
}

/* A right side of the file's own text, kept to be evaluated once every assignment is known (struct kgenome_dtx_cand). */
void kgenome_dtx_cand_add(struct kgenome_dtx *x, uint32_t rs, uint32_t re)
{
	if (x->ncand == x->ccand) {
		uint32_t nc = x->ccand ? x->ccand * 2u : 64u;
		struct kgenome_dtx_cand *nv;

		if (!kgenome_dtx_charge(x, (uint64_t)(nc - x->ccand) * sizeof *nv))
			return;
		nv = realloc(x->cand, (size_t)nc * sizeof *nv);
		if (!nv) {
			kgenome_diag_note(x->s, KGENOME_NOMEM);
			x->oom = 1;
			return;
		}
		x->cand = nv;
		x->ccand = nc;
	}
	x->cand[x->ncand].rs = rs;
	x->cand[x->ncand++].re = re;
}

void kgenome_dtx_end_assign(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	if (w->asg && w->av == &x->vdyn) {
		/* an assignment to a variable whose name is not constant: whatever it was given is in a variable of the sender's choosing */
		uint8_t k;

		for (k = 0; k < x->vdyn.n_def; k++)
			if (kgenome_dtx_prod_cap(x, x->vdyn.def[k]) == KGENOME_NUCLEO_REQUEST)
				note_extract(x, (int32_t)x->vdyn.def[k], w->cur < x->nt ? w->cur : x->nt - 1u);
		w->asg = 0;
		w->av = NULL;
		return;
	}
	if (w->asg && w->av && !w->a_member) {
		struct kgenome_dtx_var *v = w->av;

		if (v->n_set < 255u && !w->a_append)
			v->n_set++;
		if (v->n_app < 255u && w->a_append)
			v->n_app++;
		if (!w->a_append) {
			kgenome_dtx_seg_clear(v);
			v->unknown = 0;
			/* a right side of more than one token is a value the program computes: the evaluator will be asked what it comes to */
			if (x->on_const && !x->layer && w->cur > w->a_rs + 1u && w->cur <= x->nt)
				kgenome_dtx_cand_add(x, w->a_rs, w->cur);
		}
		(void)kgenome_dtx_seg_add(x, v, w->a_rs, w->cur);
	}
	w->asg = 0;
	w->av = NULL;
	w->a_member = 0;
}

/* A node. `name` is the table's spelling of what made it, or NULL: a callee that is whatever a value says has no name, and
 * is told as "eval" - a call of a value is that act, and the gate that reads names must be able to find it. */
int32_t kgenome_dtx_add_node(struct kgenome_dtx *x, uint32_t tok, uint16_t cap, const char *name, uint16_t flags)
{
	struct kgenome_diag_hit *h = kgenome_diag_hit_add(x->s, x->layer ? x->layer_at : x->t[tok].off, cap, flags);

	if (!h)
		return -1;
	if (x->on_node && name)
		x->on_node(x->user, name);
	if (x->stages & KGENOME_DTX_ST_PATH)
		kgenome_dtx_ident_note(x, (int32_t)(x->s->n_hit - 1u), tok);
	return (int32_t)(x->s->n_hit - 1u);
}

/* The text of a name token, NUL ended, in `b` (`n` bytes); NULL when it does not fit. */
const char *kgenome_dtx_tok_name(const struct kgenome_dtx *x, uint32_t i, char *b, size_t n)
{
	if (x->t[i].len >= n)
		return NULL;
	memcpy(b, x->in + x->t[i].off, x->t[i].len);
	b[x->t[i].len] = 0;
	return b;
}

void kgenome_dtx_push_frame(struct kgenome_dtx_walk *w, int32_t site, uint8_t stmt, const struct kgenome_dtx_callsem *op, uint8_t drop)
{
	if (w->nf >= w->cap_fr) {
		uint32_t nc = w->cap_fr ? w->cap_fr * 2u : KGENOME_DTX_FRAMES_FIRST;
		struct kgenome_dtx_frame *nf;
		uint32_t *ns;

		if (!kgenome_dtx_charge(w->x, (uint64_t)(nc - w->cap_fr) * (sizeof *nf + sizeof *ns))) {      /* refused: said by the charge, and the walk stops */
			w->ovf++;
			return;
		}
		nf = realloc(w->fr, (size_t)nc * sizeof *nf);
		if (nf)
			w->fr = nf;
		ns = nf ? realloc(w->sfi, (size_t)nc * sizeof *ns) : NULL;
		if (ns)
			w->sfi = ns;
		if (!ns) {              /* not followed, and counted, as past the bound: the answer is the bracket depth that fit */
			kgenome_diag_note(w->x->s, KGENOME_NOMEM);
			w->x->oom = 1;
			w->ovf++;
			return;
		}
		w->cap_fr = nc;
	}
	w->fr[w->nf].site = site;
	w->fr[w->nf].arg = 0;
	w->fr[w->nf].stmt = stmt;
	w->fr[w->nf].op = op;
	w->fr[w->nf].drop = drop;
	w->fr[w->nf].paren = 0;
	w->fr[w->nf].ufn = 0;
	w->fr[w->nf].uscope = 0;
	w->fr[w->nf].dstv = NULL;
	w->fr[w->nf].nsrc = 0;
	w->fr[w->nf].npsrc = 0;
	w->fr[w->nf].dec = site >= 0 || drop || (op && (op->flags & KGENOME_DTX_CS_OUT)) ? w->nf + 1u : (w->nf ? w->fr[w->nf - 1u].dec : 0u);
	if (site >= 0)
		w->sfi[w->nsf++] = w->nf;
	w->nf++;
}

void kgenome_dtx_pop_frame(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	if (w->ovf) {
		w->ovf--;
		return;
	}
	if (!w->nf)
		return;
	w->nf--;
	if (w->ret_fn && w->nf < w->ret_nf)     /* the bracket the return was written inside has closed: so has the return */
		w->ret_fn = 0;
	if (w->fr[w->nf].op && (w->fr[w->nf].op->flags & KGENOME_DTX_CS_OUT) && w->fr[w->nf].op->dst == KGENOME_DTX_CS_NO_DST) {
		uint8_t k;

		for (k = 0; k < w->fr[w->nf].nsrc; k++)
			if (kgenome_dtx_prod_cap(x, w->fr[w->nf].src[k]) == KGENOME_NUCLEO_REQUEST)
				note_extract(x, (int32_t)w->fr[w->nf].src[k], w->cur);
	}
	if (w->fr[w->nf].op && (w->fr[w->nf].op->flags & KGENOME_DTX_CS_OUT) && w->fr[w->nf].dstv) {
		struct kgenome_dtx_var *d = w->fr[w->nf].dstv;
		uint8_t k;

		d->unknown = 1;         /* what the call wrote is not a value the program holds */
		kgenome_dtx_seg_clear(d);
		for (k = 0; k < w->fr[w->nf].nsrc; k++)
			kgenome_dtx_var_def(d, w->fr[w->nf].src[k]);
		for (k = 0; k < w->fr[w->nf].npsrc; k++)
			kgenome_dtx_var_def(d, w->fr[w->nf].psrc[k]);
	}
	if (w->fr[w->nf].site >= 0 && w->nsf)
		w->nsf--;
	if (w->fr[w->nf].ufn) {                 /* the call of a function the text defines has closed: it stands for what that function returns */
		w->nufn--;
		kgenome_dtx_sum_call_value(x, w, w->fr[w->nf].ufn, w->fr[w->nf].uscope);
	}
	if (w->asg && w->nf < w->a_nf)
		kgenome_dtx_end_assign(x, w);
}
