/*
 * diag_text_stmt.c - the calls that are written without a bracket, for the languages whose row says so: `include "f"`, `system "id"`, `Execute x`, `o.Run cmd, 0, True`,
 * and the reads that are the request without being a call: `Request["x"]`, a server control's `txtArg.Text`.
 *
 * ONE FRAME FOR EVERY CALL. A call with a bracket takes what flows into it from its argument list (a frame, `struct kgenome_dtx_frame`, pushed at the "("); a call without one takes
 * it from where its name is to where the statement ends, and that is the same frame with `stmt` set: the node is made at the name, the frame is pushed, and the
 * walk's own end of a statement pops it. What flows into it, and the role each argument has, is what the walk does for any call - there is no second way to follow a value
 * into a call. A statement ends at a ";", the row's `sep` (vb ":"), the line break or island end the lexer's tokens carry ('T'), and the words the row says begin the
 * next one (`then`, `else`).
 *
 * WHAT IS A CALL HERE AND WHAT IS NOT is the row's: a word of `stmt_words` that is no member (`conn.Execute sql` is not `Execute`) and is followed by something that begins
 * an argument; and, for a language whose members may be called either way (vb), a member that is a row - at the head of a statement its arguments are the rest of it, anywhere
 * else it is a read (`x = o.Run`, `Request.Form`, `.nodeTypedValue`) and takes none.
 */

#include <string.h>

#include "diag_text_walk.h"
#include <celllysis/nucleo.h>

/* Does a token begin an argument: not the end of the statement, a closing bracket, an operator or a separator, and not the block the row says follows a word that is
 * also a block's (`eval {`). Whatever else may. */
static int starts_arg(const struct kgenome_dtx *x, uint32_t j)
{
	const struct kgenome_dtx_tok *t;

	if (j >= x->nt || x->t[j].k == 'T')
		return 0;
	t = &x->t[j];
	if (t->k == 'P') {
		uint8_t c = x->in[t->off];
		const uint8_t one[2] = { c, 0 };

		return !kof_byte_in_set(c, ")]}=,;:.?|&<>") && !(x->lang->sep && c == x->lang->sep) && !kgenome_dtx_word_in(x->lang->stmt_block, one, 1u, 0);
	}
	return !(t->k == 'I' && kgenome_dtx_word_in(x->lang->stmt_block, x->in + t->off, t->len, x->lang->fold));
}

int kgenome_dtx_stmt_start(const struct kgenome_dtx *x, uint32_t i)
{
	if (!i || kgenome_dtx_is_term(x, i - 1u))
		return 1;
	return x->t[i - 1u].k == 'I' && kgenome_dtx_word_in(x->lang->stmt_lead, x->in + x->t[i - 1u].off, x->t[i - 1u].len, x->lang->fold);
}

int kgenome_dtx_stmt_call(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i, uint16_t cap, const char *name, uint16_t flags)
{
	int32_t n = kgenome_dtx_add_node(x, i, cap, name, flags);

	x->site[i] = n;
	kgenome_dtx_flow(x, w, n, NULL);
	kgenome_dtx_push_frame(w, n, 1, NULL, 0);
	return 1;
}

int kgenome_dtx_stmt_tok(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	const struct kgenome_dtx_tok *t = &x->t[i];
	char nb[KGENOME_DTX_NAME];
	uint16_t cap;

	if (kgenome_dtx_member(x, i) || kgenome_dtx_is_p(x, i + 1u, '(') || !starts_arg(x, i + 1u))
		return 0;
	cap = kgenome_dtx_cap(x, x->in + t->off, t->len, NULL);
	if (cap == KGENOME_NUCLEO_NONE)
		return 0;
	return kgenome_dtx_stmt_call(x, w, i, cap, kgenome_dtx_tok_name(x, i, nb, sizeof nb), 0);
}

/*
 * A MEMBER THAT NAMES A ROW, with no bracket after it: `o.Run cmd, 0, True`, `x = o.nodeTypedValue`, `For Each k In Request.Form`. Called for the member's token `i`, the last of its chain.
 * At the head of a statement the rest of it is the call's arguments.
 */
static int bare_member(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	char b[KGENOME_DTX_NAME];
	struct kgenome_dtx_chain_res cr = { 0 };
	uint32_t len = kgenome_dtx_chain_full(x, i, b, sizeof b, &cr, 0), off = 0;
	uint16_t cap = len ? kgenome_dtx_chain_cap(x, &cr, b, len, &off) : KGENOME_NUCLEO_NONE;
	int32_t n;

	if (cap == KGENOME_NUCLEO_NONE)
		return 1;
	n = kgenome_dtx_call_node(x, i, cap, b + off, len - off, cr.flags);
	kgenome_dtx_flow(x, w, n, NULL);
	kgenome_dtx_receiver_into(x, i, n);
	if (n >= 0 && kgenome_dtx_stmt_start(x, cr.root) && starts_arg(x, i + 1u))
		kgenome_dtx_push_frame(w, n, 1, NULL, 0);
	return 1;
}

/*
 * A READ OF A SERVER CONTROL'S TEXT, `txtArg.Text` (webforms): the control is declared in the markup, so the code has only the name, and what it reads is what the sender
 * posted - the request, as `Request.Form["txtArg"]` would be. Read as the request when the member is one of the row's (`Text`, `Value`), its object is a name the program
 * never assigns and does not take as a parameter (a local that holds a string is not a control), and it is read, not written (`lblOut.Text = r`).
 */
static int ctl_read(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	uint32_t jl = kgenome_dtx_join_before(x, i), root, used;
	const uint8_t *nm;
	uint32_t nl;
	int32_t n;

	if (!x->lang->ctl_row || !i || i < jl + 1u || kgenome_dtx_join_after(x, i + 1u) || kgenome_dtx_is_p(x, i + 1u, '(') ||
	    !kgenome_dtx_word_in(x->lang->ctl_members, x->in + x->t[i].off, x->t[i].len, x->lang->fold))
		return 0;
	root = i - jl - 1u;
	if (x->t[root].k != 'V' || kgenome_dtx_member(x, root))
		return 0;
	if (kgenome_dtx_is_p(x, i + 1u, '=') && !kgenome_dtx_is_p(x, i + 2u, '='))
		return 0;                               /* a write */
	if (!kgenome_dtx_var_key(x, root, &nm, &nl) || kgenome_dtx_var_for(x, root, &used, 0) || kgenome_dtx_declared(x, x->scope[root], nm, nl))
		return 0;
	n = kgenome_dtx_add_node(x, i, KGENOME_NUCLEO_REQUEST, x->lang->ctl_row, 0);
	x->site[i] = n;
	kgenome_dtx_flow(x, w, n, NULL);
	return 1;
}

int kgenome_dtx_member_tok(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	if (x->lang->bare_members && !kgenome_dtx_join_after(x, i + 1u))
		return bare_member(x, w, i);
	if (x->lang->ctl_row)
		(void)ctl_read(x, w, i);
	return 1;
}

/* The word is the request object read through an index or a call (`Request["x"]`, `Request("x")`): the node, and `*pend` is it for the bracket that follows. */
int kgenome_dtx_req_obj(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i, int32_t *pend)
{
	const struct kgenome_dtx_tok *t = &x->t[i];
	int32_t n;

	if (!kgenome_dtx_is_p(x, i + 1u, '[') && !kgenome_dtx_is_p(x, i + 1u, '('))
		return 0;
	if (t->k == 'S' || !kgenome_dtx_is_word(x, i, x->lang->req_obj) || kgenome_dtx_member(x, i))
		return 0;
	n = kgenome_dtx_add_node(x, i, KGENOME_NUCLEO_REQUEST, x->lang->req_row, 0);
	x->site[i] = n;
	kgenome_dtx_flow(x, w, n, NULL);
	if (kgenome_dtx_is_p(x, i + 1u, '('))
		*pend = n;              /* the call's own bracket takes what is inside it */
	return 1;
}

/* The name of a tag that is a row, `<cfexecute`: a call whose arguments are its attributes, to the end of the tag. */
void kgenome_dtx_tag(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	const char *spelled = NULL;
	uint16_t cap = kgenome_dtx_cap(x, x->in + x->t[i].off, x->t[i].len, &spelled);

	if (cap != KGENOME_NUCLEO_NONE)
		(void)kgenome_dtx_stmt_call(x, w, i, cap, spelled, 0);
}

/* `name=value` inside the arguments of a call names an argument and assigns nothing: in the brackets of a call (python's keyword arguments, cfml's), and among a tag's attributes. */
int kgenome_dtx_names_arg(const struct kgenome_dtx *x, const struct kgenome_dtx_walk *w)
{
	const struct kgenome_dtx_frame *f;

	if (!w->nf || w->ovf)
		return 0;
	f = &w->fr[w->nf - 1u];
	return (x->lang->kwargs && f->paren) || (x->lang->tag_calls && f->stmt);
}
