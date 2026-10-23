/*
 * textual_form_call.c - the call stage of the form: a call on literals is written as the literal it evaluates to. See the note below, and
 * kgenome_textual_fn_form in textual.h for which calls. The writer is textual_form.c; what the two share is textual_form_private.h.
 */

#include <string.h>

#include "textual_form_private.h"

/*
 * CALLS ON LITERALS, the stage between the lexer and the writer. A call of a function the language's table says the form
 * rewrites (kgenome_textual_fn_form), with literals for arguments, is what a script writes to keep a name from a scan:
 *
 *     $f = str_replace('k', '', 'ckrekatek_fuknkkction');   $c = chr(115) . chr(121) . 'stem';
 *
 * and the form shows what the call IS, the literal it evaluates to, so that a marker on 'create_function' finds it and the
 * join above is one literal. WHAT THE CALL MEANS IS NOT COMPUTED HERE: the table says which function it is and
 * which of its arguments is which, kgenome_textual_fn_run applies it with the caller's hook (the engine's, kuncoat's - the
 * evaluator of the TEXT route asks the same two), and the lang row's `quote` writes the literal.
 *
 * THE CALL IS READ AHEAD AND NOT WRITTEN. At the first byte of a name the input is looked at - the name, "(", and how the first
 * argument begins - and only a call that could be one is taken: `foo($x)` and `trim($s)` are never held (the first byte
 * after "(" is "$"), so the stage costs a test per name followed by "(" and nothing for the rest of the text. A taken
 * call goes to the log (struct kgenome_tform_item) instead of the output, and when it is not what it looked like - one byte that is
 * not a literal, a number or a call of the same kind, or an operator after an argument - the log is written as typed, through
 * code_token_byte and string_piece, so what comes out is what would have come out with no stage. That is why a call
 * that is a join's operand is still joined: the literal it became goes through string_piece, the way a typed one does.
 *
 * AND THE RESULT TAKES THE PLACE OF THE CALL, which is what `decoded_` is not: the decoders' calls stay, renamed, because the
 * literal inside them is still an argument and the call still says what it was put through. A call on constants has no
 * argument left to keep - its answer is its value - and a `decoded_str_replace('k','','ckrekatek')` in front of nothing a
 * reader could use would only be one more token to read. The call is counted (n_calls, n_fn) so that the engine knows the view
 * is a different text.
 *
 * ROOM. The literal is written into the top of the output buffer (above `cap`, which is lowered) because it has to
 * wait there while joins around it are read, and what has been written below must not reach it. A call is
 * taken only when the whole of the pending text and twice the bytes held at the top still fit what the caller gave
 * (`cap0`): a call that would not leave room for the rest stays as typed, counted in n_refused. Nothing is cut to fit.
 */

/* A bucket of `call_prefix` for the three bytes at `p` (lower case where the language folds it, the caller's rule: a name is letters and "_"). */
static inline uint32_t call_hash(const uint8_t *p)
{
	return ((uint32_t)(p[0] | 0x20u) * 31u ^ (uint32_t)(p[1] | 0x20u) * 7u ^ (uint32_t)(p[2] | 0x20u)) & 255u;
}

/* What the table's rewritten functions look like (see struct kgenome_tform): the bytes a name begins with, the hashes of its first three, its shortest and its
 * longest. Turns the stage off when the table has none, or a name the log cannot hold. */
void kgenome_tform_call_table(struct kgenome_tform *f)
{
	const struct kgenome_textual_fn_table *t = f->lang->fn_table;
	uint32_t i;

	f->call_min = 0xffu;
	/* a name of the table is spelt with letters and "_" only, so `w[0] & ~0x20` is its capital */
	for (i = 0; i < t->n; i++) {
		const char *w = t->rows[i].name;
		uint32_t len = (uint32_t)strlen(w);

		/* the rows the form rewrites: a call by name, on literals. A method, an operator and a cast are the evaluator's (a receiver in front of the name is not
		 * something this stage reads ahead), and so is a function it marks EVAL. */
		if (t->rows[i].fn.form == KGENOME_TEXTUAL_FN_FORM_NEVER || t->rows[i].fn.form == KGENOME_TEXTUAL_FN_FORM_EVAL ||
		    t->rows[i].fn.shape != KGENOME_TEXTUAL_SHAPE_CALL)
			continue;
		f->call_prefix[call_hash((const uint8_t *)w)] = 1;
		/* a name with a "." in it is a function spelt with its receiver (String.fromCharCode): the scan of a name goes through the dots */
		if (strchr(w, '.'))
			f->call_dots = 1;
		if (t->rows[i].fn.max_args > KGENOME_TFORM_CALL_ARGS)
			f->fold_calls = 0;
		f->call_heads[(uint8_t)w[0]] = 1;
		if (f->lang->fn_fold) {
			f->call_heads[(uint8_t)(w[0] | 0x20)] = 1;
			f->call_heads[(uint8_t)(w[0] & ~0x20)] = 1;
		}
		if (len < f->call_min)
			f->call_min = (uint8_t)len;
		if (len > f->call_max)
			f->call_max = (uint8_t)len;
	}
	f->call_heads['\\'] = 1;
	/* the hash reads three bytes of any name that is long enough to be looked up, so a shorter one cannot be handled; the table has none */
	if (!f->call_max || f->call_max >= KGENOME_TFORM_CALL_TOKEN || f->call_min < 3u)
		f->fold_calls = 0;
}

/* Is `c` the first byte of a name (or of the "\" before one). */
static inline int call_head(uint8_t c)
{
	return kof_is_alpha(c) || c == '_' || c == '\\';
}

/*
 * Is a call the stage takes written at `pos`: a name the table has and the form rewrites, "(", and an argument that begins as a
 * literal, a number or such a call. Answers how many bytes the name takes (a "\" in front of it included), 0 for no. Reads the
 * input ahead of the stream and writes nothing. `depth` is how many calls are open.
 */
static uint32_t call_name_at(const struct kgenome_tform *f, uint32_t pos, uint32_t depth, struct kgenome_textual_fn *fn)
{
	const uint8_t *in = f->in;
	uint32_t n = f->n, i = pos, e, k, len, j, e2;

	if (in[i] == '\\')
		i++;
	if (i + 3u > n || !call_head(in[i]) || in[i] == '\\' || !f->call_prefix[call_hash(in + i)])
		return 0;
	/* the cheap refusals first - most names are not followed by "(", and most of those that are begin with "$" or a name that is
	 * not the table's - then where the name stands, then the table */
	for (e = i; e < n && e - i <= f->call_max && kgenome_textual_ident(in[e]); e++)
		;
	/* `String.fromCharCode`: the names of a dotted spelling, joined by "." with nothing between them */
	while (f->call_dots && e + 1u < n && e - i <= f->call_max && in[e] == '.' && kgenome_textual_ident_start(in[e + 1u]))
		for (e++; e < n && e - i <= f->call_max && kgenome_textual_ident(in[e]); e++)
			;
	len = e - i;
	if (len < f->call_min || len > f->call_max)
		return 0;
	k = kgenome_tform_skip_gap(f, e);
	if (k >= n || in[k] != '(')
		return 0;
	k = kgenome_tform_skip_gap(f, k + 1u);
	if (k >= n)
		return 0;
	if (in[k] == '\'' || in[k] == '"' || kof_is_digit(in[k]) || in[k] == '-' || in[k] == '+') {
		/* a literal or a number */
	} else if (call_head(in[k])) {
		struct kgenome_textual_fn inner;

		if (depth + 1u >= KGENOME_TFORM_CALL_DEPTH || !call_name_at(f, k, depth + 1u, &inner))
			return 0;
	} else {
		return 0;
	}
	/* a name of its own: not the tail of another ($strrev, ->trim, ::trim, ns\trim), and not a class's constructor (`new strtr('a', 'b', 'c')`;
	 * a definition, `function trim(`, is never asked about: its first parameter begins with "$"). That the byte before is not one that
	 * continues a name is not asked here: the caller knows it (prev_name in code_span_body), and the byte before a nested call is "(", "," or a gap. */
	if (pos) {
		uint8_t prev = in[pos - 1u];

		/* a "." in front is member access where the language says so - but `..` (lua's join) and a "." that joins are not */
		if (f->lang->member_dot && prev == '.' && !(pos >= 2u && in[pos - 2u] == '.'))
			return 0;
		if (prev == '$' || prev == '\\' ||
		    (pos >= 2u && ((prev == '>' && in[pos - 2u] == '-') || (prev == ':' && in[pos - 2u] == ':'))))
			return 0;
	}
	for (j = pos; j && kof_is_space_byte(in[j - 1u]); j--)
		;
	for (e2 = j; j && e2 - j < 9u && kgenome_textual_ident(in[j - 1u]); j--)
		;
	if (e2 - j == 3u && kgenome_textual_ci_eq(in + j, "new", 3u))
		return 0;
	if (!kgenome_textual_fn_find(f->lang->id, in + i, len, fn) || fn->form == KGENOME_TEXTUAL_FN_FORM_NEVER || fn->form == KGENOME_TEXTUAL_FN_FORM_EVAL)
		return 0;
	return e - pos;
}

/* The log written as it was typed. Nothing is open after it. */
void kgenome_tform_call_abort(struct kgenome_tform *f)
{
	uint8_t pend = f->pend;
	uint32_t i, k, n = f->n_it;

	f->nframe = 0;
	f->n_it = 0;
	for (i = 0; i < n; i++) {
		const struct kgenome_tform_item *it = &f->it[i];

		f->pend = it->pend;
		if (it->kind == KGENOME_TFORM_CI_STR)
			kgenome_tform_string_piece(f, &it->s, it->end, it->from);
		else
			for (k = 0; k < it->n; k++)
				kgenome_tform_code_token_byte(f, it->t[k]);
	}
	f->pend = pend;
}

/* A byte of code that is not white space, as a log item (the white space before it goes with it). */
static void call_code(struct kgenome_tform *f, uint8_t c, uint32_t pos)
{
	struct kgenome_tform_item *it = &f->it[f->n_it++];

	it->kind = KGENOME_TFORM_CI_CODE;
	it->pend = f->pend;
	it->n = 1;
	it->t[0] = c;
	it->from = pos;
	it->end = pos + 1u;
	f->pend = 0;
}

static void call_push(struct kgenome_tform *f, uint32_t pos, uint32_t ntok, const struct kgenome_textual_fn *fn)
{
	struct kgenome_tform_frame *fr;
	struct kgenome_tform_item *it;

	/* what was made at the top of the output is given back when a call that nothing else holds begins: a held literal (a join still being
	 * read) or the log of an open call may be reading it, and nothing else does. It is not given back sooner, so a text of thousands of
	 * calls holds the literals of one join at a time. (`cap` was lowered to keep them: it is lowered no further than the room check allowed.) */
	if (!f->nframe && !f->held.on && f->syn_used) {
		f->syn_used = 0;
		f->cap = f->cap0;
	}
	fr = &f->fr[f->nframe++];
	it = &f->it[f->n_it];

	fr->fn = *fn;
	fr->from = pos;
	fr->first = f->n_it++;
	fr->phase = KGENOME_TFORM_PH_NAME;
	fr->n_args = 0;
	fr->join = 0;
	it->kind = KGENOME_TFORM_CI_CODE;
	it->pend = f->pend;
	it->n = (uint8_t)ntok;
	memcpy(it->t, f->in + pos, ntok);
	it->from = pos;
	it->end = pos + ntok;
	f->pend = 0;
}

/* The item just logged is an argument of `fr`, or the next piece of the one a "." left open. */
static void call_arg(struct kgenome_tform_frame *fr, uint8_t item)
{
	if (fr->join) {
		fr->arg_z[fr->n_args - 1u] = item;
		fr->join = 0;
	} else {
		fr->arg_a[fr->n_args] = fr->arg_z[fr->n_args] = item;
		fr->n_args++;
	}
	fr->phase = KGENOME_TFORM_PH_NEXT;
}

/* A literal where the open call wants an argument: logged. Anything else, and the call is written as typed. */
int kgenome_tform_call_string(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	struct kgenome_tform_frame *fr = &f->fr[f->nframe - 1u];
	struct kgenome_tform_item *it = &f->it[f->n_it];

	if (f->n_it >= KGENOME_TFORM_CALL_ITEMS || fr->phase != KGENOME_TFORM_PH_ARG || (s->flags & (KGENOME_TEXTUAL_F_OPEN | KGENOME_TEXTUAL_F_HERE))) {
		kgenome_tform_call_abort(f);
		return 0;
	}
	it->kind = KGENOME_TFORM_CI_STR;
	it->pend = f->pend;
	it->s = *s;
	it->from = s->off;
	it->end = s->off + s->len;
	f->pend = 0;
	call_arg(fr, f->n_it++);
	return 1;
}

/*
 * The ")" of the innermost call: run it. 1 when the call was written as its literal (the ")" is consumed); 0 when it was not and the
 * log has been written as typed (the caller writes the ")"). `pos` is the ")" in the input.
 */
static uint32_t call_resolve(struct kgenome_tform *f, uint32_t pos)
{
	struct kgenome_tform_frame *fr = &f->fr[f->nframe - 1u];
	struct kgenome_textual_arg a[KGENOME_TFORM_CALL_ARGS];
	struct kgenome_textual_span syn;
	uint64_t room, need;
	uint8_t *scr, *res;
	uint32_t i, v = 0, rn = 0, rcap, amax, top, from0, from = fr->from, nv, qn;
	uint8_t first = fr->first, pend0 = f->it[first].pend;

	if (f->w + 8u >= f->cap || f->cap > 0xffffffffu)
		goto refuse;
	room = f->cap - f->w - 8u;
	scr = f->out + f->w + 8u;        /* free: nothing is written while a call is read, and what is held is not in the output */
	for (i = 0; i < fr->n_args; i++) {
		const struct kgenome_tform_item *it0 = &f->it[fr->arg_a[i]];
		uint32_t k;

		if (it0->kind == KGENOME_TFORM_CI_CODE) {                     /* a number: its text */
			a[i].p = it0->t;
			a[i].n = it0->n;
			continue;
		}
		a[i].p = scr + v;
		a[i].n = 0;
		for (k = fr->arg_a[i]; k <= fr->arg_z[i]; k++) {
			const struct kgenome_tform_item *it = &f->it[k];

			if (it->kind != KGENOME_TFORM_CI_STR)                 /* the "." between the pieces */
				continue;
			if (it->s.len < it->s.open_len + it->s.close_len || it->s.len - it->s.open_len - it->s.close_len > room - v)
				goto refuse;
			nv = 0;
			if (!f->lang->value(kgenome_tform_sp(f, &it->s), it->s.len, it->s.open_len, it->s.close_len, it->s.flags, scr + v, &nv))
				goto refuse;
			a[i].n += nv;
			v += nv;
		}
	}
	/* the answer, then its literal: 3 * rn + 2 <= what is left, so neither reaches the top of the buffer. An answer longer than a third of the
	 * room is refused by the hook (it is not given more), which is what the cap below says. */
	if (room - v < 5u)
		goto refuse;
	res = scr + v;
	rcap = (uint32_t)((room - v - 2u) / 3u > 0xffffffffu ? 0xffffffffu : (room - v - 2u) / 3u);
	if (!kgenome_textual_fn_run(&fr->fn, a, fr->n_args, f->apply, f->apply_user, res, rcap, &rn))
		goto refuse;
	if (fr->fn.form == KGENOME_TEXTUAL_FN_FORM_PRINTABLE) {
		for (i = 0; i < rn; i++)
			if (res[i] < 0x20u || res[i] > 0x7eu)
				goto keep;      /* not an error: the idiom of a table of bytes, left as it is */
	}
	if (!f->lang->quote)
		goto refuse;
	amax = (uint32_t)kgenome_textual_quote_max(f->lang->quote, rn);
	from0 = f->fr[0].from;
	if (f->held.on && f->held.p[0].from < from0)
		from0 = f->held.p[0].from;
	need = (uint64_t)f->w + 2u * ((uint64_t)f->syn_used + amax) + KGENOME_TEXTUAL_FORM_CAP(f->n - from0);
	if (need > f->cap0)
		goto refuse;
	top = (uint32_t)(f->cap - amax);
	qn = kgenome_textual_quote_write(f->lang->quote, res, rn, f->out + top);
	if (!qn)                /* a value this language cannot write as one literal stays the call */
		goto refuse;
	syn = (struct kgenome_textual_span){ .off = top, .len = qn, .open_len = 1, .close_len = 1,
					     .kind = KGENOME_TEXTUAL_STRING, .flags = KGENOME_TFORM_F_SYN };
	f->syn_used += amax;
	f->cap = f->cap0 - f->syn_used;
	f->n_calls++;
	f->n_fn[fr->fn.op]++;
	f->nframe--;
	f->n_it = first;
	if (f->nframe) {
		struct kgenome_tform_frame *par = &f->fr[f->nframe - 1u];
		struct kgenome_tform_item *it = &f->it[f->n_it];

		it->kind = KGENOME_TFORM_CI_STR;
		it->pend = pend0;
		it->s = syn;
		it->from = from;
		it->end = pos + 1u;
		call_arg(par, f->n_it++);
	} else {
		f->pend = pend0;
		kgenome_tform_string_piece(f, &syn, pos + 1u, from);
	}
	return 1;
refuse:
	f->n_refused++;
keep:
	kgenome_tform_call_abort(f);
	return 0;
}

/* A byte of code while a call is open. How many bytes were taken (a nested call's name: all of it), 0 when the log was written as typed. */
static uint32_t call_byte(struct kgenome_tform *f, uint8_t c, uint32_t pos)
{
	struct kgenome_tform_frame *fr = &f->fr[f->nframe - 1u];
	struct kgenome_textual_fn fn;
	uint32_t ntok;

	if (f->n_it + 2u > KGENOME_TFORM_CALL_ITEMS)
		goto stop;
	if (fr->phase == KGENOME_TFORM_PH_NUM) {
		struct kgenome_tform_item *it = &f->it[fr->arg_z[fr->n_args - 1u]];

		if (kof_is_digit(c)) {
			if (it->n >= KGENOME_TFORM_CALL_TOKEN)
				goto stop;
			it->t[it->n++] = c;
			it->end = pos + 1u;
			return 1;
		}
		/* the number ends. A leading zero is octal in php, and is not read as decimal here. */
		if ((it->t[0] == '0' && it->n > 1u) || ((it->t[0] == '-' || it->t[0] == '+') && it->t[1] == '0' && it->n > 2u))
			goto stop;
		fr->phase = KGENOME_TFORM_PH_NEXT;
	}
	switch (fr->phase) {
	case KGENOME_TFORM_PH_NAME:
		if (c != '(')
			break;
		call_code(f, c, pos);
		fr->phase = KGENOME_TFORM_PH_ARG;
		return 1;
	case KGENOME_TFORM_PH_ARG:
		if (!fr->join && (kof_is_digit(c) || ((c == '-' || c == '+') && pos + 1u < f->n && kof_is_digit(f->in[pos + 1u])))) {
			call_code(f, c, pos);
			fr->arg_a[fr->n_args] = fr->arg_z[fr->n_args] = (uint8_t)(f->n_it - 1u);
			fr->n_args++;
			fr->phase = KGENOME_TFORM_PH_NUM;
			return 1;
		}
		if (call_head(c) && f->nframe < KGENOME_TFORM_CALL_DEPTH && (ntok = call_name_at(f, pos, f->nframe, &fn)) != 0) {
			call_push(f, pos, ntok, &fn);
			return ntok;
		}
		break;
	default:        /* KGENOME_TFORM_PH_NEXT */
		if (c == ',' && fr->n_args < fr->fn.max_args) {
			call_code(f, c, pos);
			fr->phase = KGENOME_TFORM_PH_ARG;
			return 1;
		}
		if (c == ')')           /* too few arguments is for the call to refuse (kgenome_textual_fn_run): one place says how many a function takes */
			return call_resolve(f, pos);
		/* literals joined: the argument goes on (a number is not joined to anything) */
		if (c == f->lang->concat && c && f->it[fr->arg_a[fr->n_args - 1u]].kind == KGENOME_TFORM_CI_STR) {
			call_code(f, c, pos);
			fr->join = 1;
			fr->phase = KGENOME_TFORM_PH_ARG;
			return 1;
		}
		break;
	}
stop:
	kgenome_tform_call_abort(f);
	return 0;
}

/*
 * A byte of code that code_span_body found could be the start of a call (a name of the table begins with it and the byte before is not a name's), or
 * that comes while a call is open. How many bytes the stage took (a name: all of it), 0 when it took none and the writer has the byte.
 */
uint32_t kgenome_tform_call_take(struct kgenome_tform *f, uint8_t c, uint32_t pos)
{
	struct kgenome_textual_fn fn;
	uint32_t n;

	if (f->nframe)
		return call_byte(f, c, pos);
	n = call_name_at(f, pos, 0, &fn);
	if (n)
		call_push(f, pos, n, &fn);
	return n;
}

