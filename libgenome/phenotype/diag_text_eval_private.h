/*
 * diag_text_eval_private.h - what the two files of the constant evaluator share: diag_text_eval.c (literals, calls of the table's functions, variables, the join) and
 * diag_text_eval_ops.c (what is written AROUND a value: a method, an operator, a suffix, a cast, a list). NOT PART OF THE SURFACE.
 *
 * ONE EVALUATOR, ONE ROW TABLE. A method or an operator is not a second way to run a function: its row is in the same table as php's str_replace
 * (textual.h, enum kgenome_textual_shape), the arguments are collected here by where the language writes them, and the row runs through the one
 * function that runs a row (kgenome_dtx_ev_run_row -> kgenome_textual_fn_run with the engine's hook), so `"abc".replace("a", "b")`, `replace("abc", "a", "b")` and
 * `"abc" -replace "a", "b"` are the same call of the same op with the same rules about its arguments. What is new here is only the READING of the shape.
 */

#ifndef KGENOME_DIAG_TEXT_EVAL_PRIVATE_H
#define KGENOME_DIAG_TEXT_EVAL_PRIVATE_H

#include "diag_text_private.h"

#define KGENOME_DTX_EV_DEPTH 32   /* variables evaluated one inside another (an alias chain: `$b = $a; $c = $b; ...`); a cycle is told apart and is no cut, see kgenome_dtx_eval_var */
#define KGENOME_DTX_EV_VMAX  (1u << 20)
#define KGENOME_DTX_EV_ARGS  16u    /* String.fromCharCode(104, 116, ...) takes one argument a character */
/* Expressions inside one another in the recursion: see KGENOME_DTX_EV_NEST in diag_text_eval.c. */
#define KGENOME_DTX_EV_NEST  256u

struct kgenome_dtx_ev {
	struct kgenome_dtx *x;
};

/*
 * A LIST of values: ONE BUFFER in the form kuncoat's SPLIT writes and its JOIN reads (kofcore/kofstrlist.h) - a length and the bytes, element after element. The evaluator only
 * keeps track of whether a value is one (`on`): the cutting and the joining are kuncoat's ops, called through the row like every other. A list lives inside one term (a
 * literal or a split makes it, a join uses it) and one left at the end of an expression is not a constant.
 */
struct kgenome_dtx_list {
	uint8_t  *p;
	uint32_t  n, cap;
	uint8_t   on;
};
void kgenome_dtx_ev_list_free(struct kgenome_dtx_list *l);
/* One more element at the end. 0 when the bytes would pass KGENOME_DTX_EV_VMAX or memory. */
int kgenome_dtx_ev_list_add(struct kgenome_dtx *x, struct kgenome_dtx_list *l, const uint8_t *p, uint32_t n);

/* ---- diag_text_eval.c ---- */
/* `x` is told why a value or a list was refused room: past KGENOME_DTX_EV_VMAX is a bound that fired (kgenome_dtx_ev_cut), and memory refused is KGENOME_NOMEM - either way the scan says so. */
int kgenome_dtx_ev_val_room(struct kgenome_dtx *x, struct kgenome_dtx_val *v, uint32_t n, int exact);
int kgenome_dtx_ev_val_put(struct kgenome_dtx *x, struct kgenome_dtx_val *v, const uint8_t *p, uint32_t n);
/* A bound of the evaluator fired and an expression was left unread: the scan's status says it (KGENOME_TRUNCATED) and `kgenome_diag_scan_eval_cut` counts it. */
void kgenome_dtx_ev_cut_at(struct kgenome_dtx *x, const char *file, int line);
#define kgenome_dtx_ev_cut(x) kgenome_dtx_ev_cut_at((x), __FILE__, __LINE__)
/* One expression of tokens [*i, end): the joins of its terms and the operators looser than them. Appended to `out`. `L`, when not NULL, may be handed a list as the value
 * of the whole expression (and then nothing is appended); NULL refuses one. */
int kgenome_dtx_ev_expr(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L);
/* The joins of terms alone, without the operators looser than the join: what the right side of such an operator is. */
int kgenome_dtx_ev_join_level(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L);
/* One term: a primary and what is written after it (methods, suffixes). */
int kgenome_dtx_ev_term(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L);
/* How many tokens the operator that joins two strings is at token `i` (0 when it is none): the row's. */
uint32_t kgenome_dtx_ev_join(const struct kgenome_dtx *x, uint32_t i);
/* A scalar row run over a[0..n): the answer appended to `o`. 0 when the row refuses or the hook does. */
int kgenome_dtx_ev_run_row(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, const struct kgenome_dtx_val *a, uint32_t n, struct kgenome_dtx_val *o);

/* ---- diag_text_eval_ops.c ---- */
/* The tables of a text's rows of each shape, once (kgenome_dtx_open). */
void kgenome_dtx_ev_ops_open(struct kgenome_dtx *x);
/* Run row `f` over the values a[0..n) (a receiver or a left side first), `lin` the list it reads if it reads one: the answer is a string in `res` or a list in `lout`. */
int kgenome_dtx_ev_apply(struct kgenome_dtx_ev *e, const struct kgenome_textual_fn *f, struct kgenome_dtx_val *a, uint32_t n, const struct kgenome_dtx_list *lin, struct kgenome_dtx_val *res,
	     struct kgenome_dtx_list *lout);
/* What is written after the value in out[base..] of a term: methods and suffixes, as many as follow. A list in `L` is the receiver of the first. */
int kgenome_dtx_ev_postfix(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, uint32_t base, int *built, struct kgenome_dtx_list *L);
/* WHERE an operator or a postfix is read: the cursor (moved past what is taken), the end of the expression, the token its left side began at, where that left side's value begins in
 * `out`, and the flag that says a value was computed. */
struct kgenome_dtx_at {
	uint32_t *i;
	uint32_t  end, from, base;
	int      *built;
};
/* The operators of precedence `prec` (1 tighter than the join, 0 looser) that follow, left to right. The left side is out[at->base..] (or the list in `L`). */
int kgenome_dtx_ev_ops(struct kgenome_dtx_ev *e, const struct kgenome_dtx_at *at, struct kgenome_dtx_val *out, uint8_t prec, struct kgenome_dtx_list *L);
/* A list literal, or a cast, at token *i in the place of a primary. 1 when one was read (a list in `L`, a string appended to `out`), 0 when none begins there, -1 when one does and is not constant. */
int kgenome_dtx_ev_list_primary(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_list *L);
int kgenome_dtx_ev_cast(struct kgenome_dtx_ev *e, uint32_t *i, uint32_t end, struct kgenome_dtx_val *out, int *built, struct kgenome_dtx_list *L);
/* The literals a method or a suffix changes where they stand, kept as expressions to evaluate with the right sides of assignments (kgenome_dtx_cand_add). */
void kgenome_dtx_ev_floating_cands(struct kgenome_dtx *x);
/* The token of the "(" of a call whose name is written `[type]::name` at token i (powershell's static members): the name's bytes, or 0. */
uint32_t kgenome_dtx_ev_static_callee(const struct kgenome_dtx *x, uint32_t i, uint32_t end, uint32_t *noff, uint32_t *nlen);
/* The arguments of the call whose "(" is token `open`, each evaluated, a[first..): how many, -1 when one is not constant or there are too many. With `listarg`, the last may be a list (in `lst`). */
int kgenome_dtx_ev_args(struct kgenome_dtx_ev *e, uint32_t open, struct kgenome_dtx_val *a, uint32_t first, int listarg, struct kgenome_dtx_list *lst);

#endif /* KGENOME_DIAG_TEXT_EVAL_PRIVATE_H */
