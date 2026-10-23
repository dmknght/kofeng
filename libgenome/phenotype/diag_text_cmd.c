/*
 * diag_text_cmd.c - a COMMAND LINE read as calls: sh, batch, powershell and tcl write what they ask of the system as the first word of a command, and the rest of the line
 * is that command's arguments.
 *
 * ONE RULE FOR THE FOUR, parameterised by the row (kgenome_dtx_lang.cmd_*): a COMMAND is the first word of a SEGMENT, a segment ends at the bytes the row says (`;` `&` `|`
 * `(` `)` `{` `}` for a shell; `=` and `{` too for powershell), at a line break, and a segment may begin after the words that hand the command on (`sudo`, `then`, `do`, `else`,
 * `start`, `call`: `cmd_lead`; the options and the `NAME=value` that stand between are skipped). The rows are looked up for that word and for no other: a word inside `echo` is
 * an argument and is not a node (the table's rows are spelled "at the start of a command"). A command that is a row is a node whose frame takes its arguments to the end of the
 * segment, as every call without a bracket does (diag_text_stmt.c): `curl -s u`, `Invoke-Expression $x`, `exec $cmd`.
 *
 * WHAT A PIPE CARRIES. `A | B` is B taking what A made: the values the segment produced that nothing took (`acc`) are the input of the next command, so `curl u | sh` is a fetch that
 * reaches a command, and `echo $x | base64 -d | sh` is the sender's value reaching a decode that reaches a command. `;`, `&&`, `||` and the line break carry nothing.
 *
 * THE NAME OF A COMMAND is the last piece of the path it is written with (`/bin/sh`, `C:\Windows\System32\cmd.exe`, `%SystemRoot%\system32\cmd.exe`), without the extension of a
 * program (`.exe .com .bat .cmd`), and tcl's `::` as ".". A name that does not fit the buffer is refused. A command that the table spells with its subcommand (tcl's
 * `file delete`, `binary decode`) is looked up joined first. A word that begins like a path the table has as a row anywhere it stands (bash's `/dev/tcp/h/p`) is a node
 * wherever it is. A variable at the head (`$cmd args`, `& $x`) is a call of a value, as `$f()` is in php: a node of data-call when the program wrote its name or the sender
 * made it.
 *
 * WHAT IT CANNOT SEE is the lexer's: a braced body of tcl is a string, a here-document is a string, a quoted command line (`cmd /c "curl u | sh"`, `sh -c 'x'`) is a string
 * unless the row says its interpolation is read. A quoted word at the head is read for its text, not for what it holds.
 */

#include <string.h>

#include "diag_text_walk.h"
#include <celllysis/nucleo.h>

/* The values the segment produced that nothing took, kept for the "|" that may follow (called by the walk's flow). */
void kgenome_dtx_cmd_out(struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v)
{
	uint8_t k, j;

	for (k = 0; node >= 0 && k < w->nacc; k++)
		if (w->acc[k] == (uint32_t)node)
			node = -1;
	if (node >= 0) {
		if (w->nacc < KGENOME_DTX_ACC_MAX)
			w->acc[w->nacc++] = (uint32_t)node;
		else
			kgenome_dtx_cut(w->x);          /* a segment that made more values than a pipeline carries: the ones past it do not reach the next command, and it is said */
	}
	for (k = 0; v && k < v->n_def; k++) {
		for (j = 0; j < w->nacc && w->acc[j] != v->def[k]; j++)
			;
		if (j < w->nacc)
			continue;
		if (w->nacc < KGENOME_DTX_ACC_MAX)
			w->acc[w->nacc++] = v->def[k];
		else
			kgenome_dtx_cut(w->x);
	}
}

void kgenome_dtx_cmd_reset(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	(void)x;
	w->cmd_pos = 1;
	w->cmd_lead = 0;
	w->cmd_pass = 0;
	w->nacc = 0;
	w->npipe = 0;
}

/* The command of the segment before a "|" is the input of the next one; the statement it was in is over. */
static void pipe_end(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	uint32_t keep[KGENOME_DTX_ACC_MAX];
	uint8_t n = w->nacc;

	memcpy(keep, w->acc, sizeof keep);
	kgenome_dtx_end_stmt(x, w);
	memcpy(w->pipe_in, keep, sizeof keep);
	w->npipe = n;
}

/* Is token `i` the same byte as token `before` and touching it (the second of "||" and "&&"). */
static int glued_to(const struct kgenome_dtx *x, uint32_t i, uint32_t before)
{
	return i < x->nt && before < x->nt && x->t[before].k == 'P' && x->t[i].k == 'P' && x->t[before].off + x->t[before].len == x->t[i].off &&
	       x->in[x->t[before].off] == x->in[x->t[i].off];
}

/* Does token `i` touch the one before it: nothing between them but the "$" or "${" a variable's token leaves in front of its name. */
int kgenome_dtx_touches(const struct kgenome_dtx *x, uint32_t i)
{
	uint32_t k;

	for (k = x->t[i - 1u].off + x->t[i - 1u].len; k < x->t[i].off; k++)
		if (x->in[k] != '$' && x->in[k] != '{')
			return 0;
	return 1;
}

/* The value of `name=value` is the word it touches: the next token that does not touch the one before it, outside any bracket, is the next command. */
static void assignment_ends(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	if (x->lang->cmd_assign == 1u && w->asg && i && i >= w->a_rs && w->nf <= w->a_nf && x->t[i - 1u].k != 'T' && !kgenome_dtx_touches(x, i))
		kgenome_dtx_end_stmt(x, w);
}

/* A group opens: the segment before it is kept (what it made so far and what a pipe brought), the group starts with nothing, and a command is due in it unless it is `${x}`. */
void kgenome_dtx_cmd_open(struct kgenome_dtx_walk *w, int due)
{
	if (w->ngroup < KGENOME_DTX_GROUP_MAX) {
		memcpy(w->acc_stk[w->ngroup], w->acc, sizeof w->acc);
		memcpy(w->pipe_stk[w->ngroup], w->pipe_in, sizeof w->pipe_in);
		w->nacc_stk[w->ngroup] = w->nacc;
		w->npipe_stk[w->ngroup] = w->npipe;
	} else {
		kgenome_dtx_cut(w->x);          /* a group deeper than the stack keeps: what the segment around it made is not given back when it closes, and it is said */
	}
	w->ngroup++;
	w->nacc = 0;
	w->npipe = 0;
	w->cmd_pos = (uint8_t)due;
	w->cmd_lead = 0;
	w->cmd_pass = 0;
}

/* The group closes: its value is what its last segment made, and the segment around it is as it was; after a group the segment goes on with arguments. */
int kgenome_dtx_cmd_close(struct kgenome_dtx_walk *w)
{
	if (!w->ngroup) {
		w->cmd_pos = 1;                 /* a ")" with no "(": the end of a case pattern, which a command follows */
		w->nacc = 0;
		return 0;
	}
	memcpy(w->gout, w->acc, sizeof w->gout);
	w->ngout = w->nacc;
	w->ngroup--;
	if (w->ngroup < KGENOME_DTX_GROUP_MAX) {
		memcpy(w->acc, w->acc_stk[w->ngroup], sizeof w->acc);
		memcpy(w->pipe_in, w->pipe_stk[w->ngroup], sizeof w->pipe_in);
		w->nacc = w->nacc_stk[w->ngroup];
		w->npipe = w->npipe_stk[w->ngroup];
	} else {
		w->nacc = 0;
		w->npipe = 0;
	}
	w->cmd_pos = 0;
	w->cmd_lead = 0;
	w->cmd_pass = 0;
	return 1;
}

void kgenome_dtx_cmd_flush(struct kgenome_dtx *x, struct kgenome_dtx_walk *w)
{
	uint8_t k, n = w->ngout;
	uint32_t out[KGENOME_DTX_ACC_MAX];

	memcpy(out, w->gout, sizeof out);
	w->ngout = 0;
	for (k = 0; k < n; k++)
		kgenome_dtx_flow(x, w, (int32_t)out[k], NULL);
}

int kgenome_dtx_cmd_punct(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	const struct kgenome_dtx_lang *l = x->lang;
	char c = (char)x->in[x->t[i].off];
	int ends = kof_byte_in_set((uint8_t)c, l->cmd_ends);

	assignment_ends(x, w, i);
	if ((c == '|' || c == '&') && ends) {
		if (i && glued_to(x, i, i - 1u))
			return 0;               /* the second of a pair: the first ended the segment */
		if (c == '|' && !glued_to(x, i + 1u, i))
			pipe_end(x, w);
		else
			kgenome_dtx_end_stmt(x, w);
		return 0;
	}
	if (ends && (c == '(' || c == '[' || c == '{')) {
		kgenome_dtx_cmd_open(w, !(c == '{' && i && kgenome_dtx_is_p(x, i - 1u, '$') && x->t[i - 1u].off + 1u == x->t[i].off));
		return 0;
	}
	if ((c == ')' && strchr(l->cmd_ends, '(')) || (c == ']' && strchr(l->cmd_ends, '[')) || (c == '}' && strchr(l->cmd_ends, '{')))
		return !kgenome_dtx_cmd_close(w);
	if (ends) {                             /* ";" and the like: the walk ends the statement; "=" begins a value, a command may be it */
		w->cmd_pos = 1;
		w->cmd_lead = 0;
		return 0;
	}
	if (w->cmd_pos && kof_byte_in_set((uint8_t)c, l->cmd_pass)) {
		w->cmd_pass = 1;                /* the call operator: `& $x`, `. $x` (and bytes that are no part of a command: `@`, `!`) */
		return 0;
	}
	if (w->cmd_pos)
		w->cmd_pos = 0;                 /* `[`, `<` and the like are a command or a redirection, not a segment's end */
	return 0;
}

/* The text of a quoted word without its quotes. */
static uint32_t quoted_text(const struct kgenome_dtx *x, uint32_t i, const uint8_t **p)
{
	const struct kgenome_dtx_tok *t = &x->t[i];

	if (t->len < (uint32_t)t->open + t->close || (t->fl & (KGENOME_TEXTUAL_F_OPEN | KGENOME_TEXTUAL_F_HERE)))
		return 0;
	*p = x->in + t->off + t->open;
	return t->len - t->open - t->close;
}

/* The name of the command written `p`/`n`, as its table spells it, in `b`: 0 when there is none or it does not fit. */
static uint32_t command_name(const struct kgenome_dtx *x, const uint8_t *p, uint32_t n, char *b, uint32_t cap)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t k, base = 0, end = n, out = 0, e;

	for (k = 0; k < n; k++)
		if (p[k] == '/' || p[k] == '\\')
			base = k + 1u;
	if (base >= n)
		return 0;
	for (e = 0; l->cmd_exts && l->cmd_exts[e]; e++) {
		uint32_t el = (uint32_t)strlen(l->cmd_exts[e]), j;

		if (end - base <= el)
			continue;
		for (j = 0; j < el && kof_lower_byte((uint8_t)p[end - el + j]) == (uint8_t)l->cmd_exts[e][j]; j++)
			;
		if (j == el) {
			end -= el;
			break;
		}
	}
	for (k = base; k < end && out + 1u < cap; k++) {
		if (l->cmd_ns && p[k] == ':' && k + 1u < end && p[k + 1u] == ':') {
			b[out++] = '.';
			k++;
		} else {
			b[out++] = (char)p[k];
		}
	}
	if (k < end)
		return 0;               /* does not fit: refused, never cut */
	b[out] = 0;
	return out;
}

/* A word that begins as a path the table has as a row wherever it is written ("/dev/tcp/host/port"): the row, else NULL. */
static const char *path_row(const struct kgenome_dtx *x, const uint8_t *p, uint32_t n)
{
	uint32_t k;

	for (k = 0; x->lang->cmd_paths && x->lang->cmd_paths[k]; k++) {
		size_t pl = strlen(x->lang->cmd_paths[k]);

		if (n > pl && p[pl] == '/' && !memcmp(p, x->lang->cmd_paths[k], pl))
			return x->lang->cmd_paths[k];
	}
	return NULL;
}

/*
 * The command at node `n`: its input is what the pipe before it carried, and its frame takes the arguments to the end of the segment. A word that only hands the command on (`lead`:
 * `busybox`, `nohup`, `sudo`) takes none, so the command after it is not an argument of it; and the segment's output is that command's too (`nohup curl u | sh`).
 */
static void command_node(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, int32_t n, int lead)
{
	uint8_t k;
	int via_lead = w->cmd_lead;

	for (k = 0; n >= 0 && k < w->npipe; k++)
		kgenome_dtx_link(x, (int32_t)w->pipe_in[k], n, 0);
	w->npipe = 0;
	kgenome_dtx_flow(x, w, n, NULL);
	if (via_lead && n >= 0)
		kgenome_dtx_cmd_out(w, n, NULL);
	if (!lead)
		kgenome_dtx_push_frame(w, n, 1, NULL, 0);
}

/* The head of a segment has been read: what is left of the line is arguments, unless the word handed the command on. */
static void command_read(struct kgenome_dtx_walk *w, int lead)
{
	if (lead) {
		w->cmd_lead = 1;
		return;
	}
	w->cmd_pos = 0;
	w->cmd_lead = 0;
	w->cmd_pass = 0;
	if (w->npipe) {                         /* a command that makes no node passes its input along */
		memcpy(w->acc, w->pipe_in, sizeof w->acc);
		w->nacc = w->npipe;
		w->npipe = 0;
	}
}

/* `name=value`: a word that is a plain name, followed by "=" that touches it. */
static int is_assignment(const struct kgenome_dtx *x, uint32_t i)
{
	uint32_t k;
	const struct kgenome_dtx_tok *t = &x->t[i];

	if (!x->lang->cmd_assign || i + 1u >= x->nt || !kgenome_dtx_is_p(x, i + 1u, '=') || t->off + t->len != x->t[i + 1u].off || kgenome_dtx_is_p(x, i + 2u, '='))
		return 0;
	for (k = 0; k < t->len; k++)
		if (!(kof_is_alnum(x->in[t->off + k]) || x->in[t->off + k] == '_'))
			return 0;
	return 1;
}

/* A variable at the head of a command, `$cmd args`, `& $x`: the call of a value. 1 when it made a node. */
static int value_call(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	uint32_t used;
	struct kgenome_dtx_var *v;
	int32_t n;

	if (kgenome_dtx_is_p(x, i + 1u, '=') || !(x->lang->cmd_var || w->cmd_pass))
		return 0;
	v = kgenome_dtx_var_for(x, i, &used, 0);
	n = v ? kgenome_dtx_target_node(x, v, i, x->nt, 1) : -1;
	if (n < 0)
		return 0;
	x->site[i] = n;
	command_node(x, w, n, 0);
	return 1;
}

/* The table's answer for the command `b`, with its subcommand where the row says the command is an ensemble (tcl's `file delete`). */
static uint16_t command_cap(struct kgenome_dtx *x, uint32_t i, char *b, uint32_t cap)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t bl = (uint32_t)strlen(b), sl;
	uint16_t c = kgenome_dtx_cap(x, (const uint8_t *)b, bl, NULL);

	if (c != KGENOME_NUCLEO_NONE || !l->cmd_sub || i + 1u >= x->nt || x->t[i + 1u].k != 'I' || !kgenome_dtx_word_in(l->cmd_sub, (const uint8_t *)b, bl, l->fold))
		return c;
	sl = x->t[i + 1u].len;
	if (bl + 1u + sl >= cap)
		return KGENOME_NUCLEO_NONE;
	b[bl] = '.';
	memcpy(b + bl + 1u, x->in + x->t[i + 1u].off, sl);
	b[bl + 1u + sl] = 0;
	return kgenome_dtx_cap(x, (const uint8_t *)b, bl + 1u + sl, NULL);
}

/* Is token `i` a word of `list`. */
static int is_listed(const struct kgenome_dtx *x, uint32_t i, const char *const *list)
{
	return x->t[i].k == 'I' && kgenome_dtx_word_in(list, x->in + x->t[i].off, x->t[i].len, x->lang->fold);
}

/*
 * The command after the condition of the statement whose head word is token `i` (`if [/i] [not] exist X cmd`, `if [not] A==B cmd`, `if A neq B cmd`): the index of its first
 * token, or 0 when the tokens are not that shape. A operand is one token (a word, a string or a variable). The row says which words begin a condition and which tests it has.
 */
static uint32_t after_condition(const struct kgenome_dtx *x, uint32_t i)
{
	const struct kgenome_dtx_cond *c = x->lang->cond;
	uint32_t j = i + 1u;

	if (!c || !is_listed(x, i, c->head))
		return 0;
	while (j < x->nt && (is_listed(x, j, c->mods) || (x->t[j].k == 'I' && kof_byte_in_set(x->in[x->t[j].off], x->lang->cmd_opt))))
		j++;
	if (is_listed(x, j, c->unary))
		j += 2u;
	else if (j + 3u < x->nt && kgenome_dtx_is_p(x, j + 1u, '=') && kgenome_dtx_is_p(x, j + 2u, '='))
		j += 4u;
	else if (j + 2u < x->nt && is_listed(x, j + 1u, c->binary))
		j += 3u;
	else
		return 0;
	return j < x->nt ? j : 0u;
}

int kgenome_dtx_cmd_word(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	const struct kgenome_dtx_lang *l = x->lang;
	struct kgenome_dtx_tok *t = &x->t[i];
	const uint8_t *p = x->in + t->off;
	uint32_t n = t->len;
	char b[KGENOME_DTX_NAME];
	const char *row;
	uint16_t cap;
	uint32_t after;
	int lead;

	assignment_ends(x, w, i);
	if (t->k == 'I' && kgenome_dtx_member(x, i))
		return 0;                               /* `).DownloadString`: the member of an object */
	if (t->k == 'S')
		n = quoted_text(x, i, &p);
	if ((t->k == 'I' || t->k == 'S') && n && (row = path_row(x, p, n)) != NULL) {       /* `3<>/dev/tcp/h/p` wherever it stands */
		int32_t nd = kgenome_dtx_add_node(x, i, kgenome_dtx_cap(x, (const uint8_t *)row, (uint32_t)strlen(row), NULL), row, 0);

		x->site[i] = nd;
		kgenome_dtx_flow(x, w, nd, NULL);
	}
	if (t->k == 'I' && kgenome_dtx_word_in(l->cmd_rearm, p, n, l->fold)) {
		w->cmd_pos = 1;                         /* `do` and `else` of batch follow a ")" and begin a command wherever they stand */
		w->cmd_lead = 1;
		return 1;
	}
	if (!w->cmd_pos || (t->k == 'S' && (t->fl & KGENOME_TEXTUAL_F_HERE)))
		return 0;                               /* an argument, or the body of a here-document (data; the next line is a command) */
	if (t->k == 'V') {
		if (is_assignment(x, i) || kgenome_dtx_is_p(x, i + 1u, '='))
			return 0;                       /* the walk begins the assignment; the value's end brings the command back */
		if (value_call(x, w, i)) {
			command_read(w, 0);
			return 1;
		}
		command_read(w, 0);
		return 0;
	}
	if (t->k != 'I' && t->k != 'S') {
		command_read(w, 0);
		return 0;
	}
	if (t->k == 'S' && !l->cmd_var && !w->cmd_pass) {
		command_read(w, 0);                     /* powershell: a string at the head is a value, and a command only after the call operator (`& "x.exe"`) */
		return 1;
	}
	if (w->cmd_lead && ((t->k == 'I' && kof_byte_in_set(x->in[t->off], l->cmd_opt)) || t->k == 'S'))
		return 1;                               /* an option of sudo, env, xargs, start; `start "title" cmd`: the command is still to come */
	if (t->k == 'I' && is_assignment(x, i)) {
		t->k = 'V';                             /* `FOO=bar cmd`: an assignment; the walk reads it as one and the command follows it */
		return 0;
	}
	if (!n || !command_name(x, p, n, b, sizeof b)) {
		command_read(w, 0);
		return 1;
	}
	if (t->k == 'I' && (after = after_condition(x, i)) != 0) {
		w->cmd_next = after;                    /* a condition: its operands are skipped, and the command is the token after them */
		return 1;
	}
	lead = kgenome_dtx_word_in(l->cmd_lead, (const uint8_t *)b, (uint32_t)strlen(b), l->fold);
	cap = command_cap(x, i, b, sizeof b);
	if (cap != KGENOME_NUCLEO_NONE) {
		int32_t nd = kgenome_dtx_add_node(x, i, cap, b, 0);

		x->site[i] = nd;
		command_node(x, w, nd, lead);
	}
	command_read(w, lead);
	return 1;
}
