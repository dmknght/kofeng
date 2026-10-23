/*
 * diag_text_walk.h - the state of the one walk (diag_text.c) and the few things the files that read statements (diag_text_stmt.c, diag_text_cmd.c) ask of it.
 * NOT PART OF THE SURFACE.
 *
 * A statement that is a call without a bracket - `Execute x`, `o.Run cmd, 0, True`, `system "id"`, `curl u | sh`, `<cfexecute name=..>` - is read with the frame
 * a bracket makes (`struct kgenome_dtx_frame`, `stmt` set): the node is made where the name is, the frame takes what flows in until the statement ends, and the end of the
 * statement pops it. There is no second way to follow a value into a call.
 */

#ifndef KGENOME_DIAG_TEXT_WALK_H
#define KGENOME_DIAG_TEXT_WALK_H

#include "diag_text_private.h"

#define KGENOME_DTX_OUTP_MAX_SRC 8u
#define KGENOME_DTX_ACC_MAX      8u         /* values a pipeline carries from one command to the next */
#define KGENOME_DTX_GROUP_MAX    64u        /* groups of a command line whose segment is kept while they are read; deeper ones are counted and read as a part of the segment they are in */

struct kgenome_dtx_frame {
	int32_t  site;          /* the node this bracket is the argument list of, or -1 */
	uint32_t arg;           /* which argument the walk is in */
	uint8_t  stmt;          /* the arguments of a call that has no bracket: it ends with the statement (an include, `Execute x`, a command line) */
	const struct kgenome_dtx_callsem *op;       /* the call's row, when it has one; for OUT, what it reads is collected in src */
	uint8_t  drop;                  /* nothing produced inside flows out: a subscript, or a call whose result is another kind of value */
	uint8_t  paren;                 /* the bracket is a "(": a call's arguments or a grouping (a keyword argument is only read inside one) */
	uint32_t ufn;                   /* the call of a function the text defines (the first of its name, diag_text_sum.c): what flows into these arguments is what its parameters hold - and, where a parameter holds
					 * the argument, the call's result does not carry it (kgenome_dtx_sum_bound); 0 none */
	uint32_t uscope;                /* the scope the call is written in */
	struct kgenome_dtx_var *dstv;   /* the variable at its written argument */
	uint32_t src[KGENOME_DTX_OUTP_MAX_SRC];
	uint32_t psrc[KGENOME_DTX_PDEFS];       /* the slots of summaries that flowed into the arguments it reads (kept apart: see struct kgenome_dtx_var) */
	uint8_t  nsrc, npsrc;
	/* The frame at or below this one that decides where a value goes: a node's arguments (site), a call that makes another kind of value (drop) or one that collects what it reads
	 * (an OUT row) - index + 1, 0 none. The frames between are plain groupings a value passes through, and a value that asks "which frame takes me" walked all of them: a text of n
	 * unclosed brackets and n nodes was n*n steps (a depth the text chooses; the walk keeps no bound of it, G18). Set when the frame is pushed, and none of those three changes after. */
	uint32_t dec;
};

struct kgenome_dtx_walk {
	/*
	 * THE FRAMES GROW. They were two arrays of KGENOME_DTX_FRAMES (4096) in the walk, calloc'ed with it for every scan - 275 KB zeroed for a text whose bracket depth
	 * is a handful (measured by callgrind on 300 real javascript files: the clear was 5.9% of lex + form + route, 1417 calls of 75 thousand instructions
	 * each). They start at KGENOME_DTX_FRAMES_FIRST and double as deep as the text nests, a growth the scan's ledger allows (a text of a million "(" is a hostile one, and its bound
	 * is the budget, as for every table that grows with the text); a growth refused is said (OVER_BUDGET, or NOMEM) and what is deeper is counted (`ovf`) and not followed.
	 */
	struct kgenome_dtx_frame *fr;
	struct kgenome_dtx *x;                       /* the text the walk reads: the ledger the frames are charged to, and the scan that is told when they are refused */
	uint32_t     nf, ovf, cap_fr;
	uint32_t    *sfi;                        /* indexes in fr of the frames that are a node's arguments (as many as fr: a frame is at most one of them) */
	uint32_t     nsf;
	/* the assignment being read */
	int          asg;
	struct kgenome_dtx_var *av;
	uint32_t     a_nf, a_nsf;
	uint32_t     a_scope;           /* the scope the assignment was written in: a value made inside a function written on its right side is not the variable's */
	uint32_t     cur;               /* the token being walked: where a right side ends when something ends it */
	uint32_t     a_rs;              /* where the right side being read begins */
	int          drop_next;         /* the next value produced is the operand of a numeric cast */
	int          a_append;          /* it is the right side of ".=" */
	int          a_member;          /* the assignment is `obj.field = v`: it gives the object what v holds and leaves the object's own value (its segments) as it was */
	/* the `return` being read (KGENOME_DTX_ST_SUM): the function it is in (its scope id) and the frames open where it began; what flows into it, outside the arguments of a node, is returned */
	uint32_t     ret_fn, ret_nf;
	uint32_t     nufn;              /* the open frames that are the arguments of a call of a function the text defines: with none, and no `return` open, a value is kept nowhere for a summary */
	/* a language that writes commands (kgenome_dtx_lang.cmd): where the next command is, and what flows along a pipeline */
	uint8_t      cmd_pos;           /* the next word is a command: a segment began, or a word that hands the command on (sudo, then) came */
	uint8_t      cmd_lead;          /* the word before was one of those: options and assignments stand between it and the command */
	uint8_t      cmd_pass;          /* a call operator came (`&`): the variable or string after it is the command */
	uint32_t     cmd_next;          /* the tokens before this one are the operands of a condition: they are skipped */
	/* the groups of a command line (`$( )`, `( )`, `{ }`, a backtick): what the segment before one made is kept while the group is read, and what the group made is what it is worth where it stands */
	uint32_t     ngroup;
	uint32_t     acc_stk[KGENOME_DTX_GROUP_MAX][KGENOME_DTX_ACC_MAX], pipe_stk[KGENOME_DTX_GROUP_MAX][KGENOME_DTX_ACC_MAX];
	uint8_t      nacc_stk[KGENOME_DTX_GROUP_MAX], npipe_stk[KGENOME_DTX_GROUP_MAX];
	uint32_t     gout[KGENOME_DTX_ACC_MAX];     /* the value of the group that just closed, to flow once its frames are closed */
	uint8_t      ngout;
	uint32_t     acc[KGENOME_DTX_ACC_MAX];      /* what the segment so far has produced that nothing took: its output, when a "|" follows */
	uint8_t      nacc;
	uint32_t     pipe_in[KGENOME_DTX_ACC_MAX];  /* the output of the segment before a "|": the input of the command that comes next */
	uint8_t      npipe;
};

/* The tokens [from, to) walked. */
void kgenome_dtx_walk_range(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t from, uint32_t to);
/* A closing bracket: the calls without a bracket begun inside it end first. */
void kgenome_dtx_close_frame(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* The block ('c' or 'b') whose token is `i`, walked: the index of its last token. */
uint32_t kgenome_dtx_block(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* A value produced here (a node, or a variable's producers) goes into the argument of the call it sits in, or the variable being assigned. */
void kgenome_dtx_flow(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v);
/* The node a name makes, told by the table's spelling. -1 when the scan is full. */
int32_t kgenome_dtx_add_node(struct kgenome_dtx *x, uint32_t tok, uint16_t cap, const char *name, uint16_t flags);
void kgenome_dtx_push_frame(struct kgenome_dtx_walk *w, int32_t site, uint8_t stmt, const struct kgenome_dtx_callsem *op, uint8_t drop);
void kgenome_dtx_pop_frame(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* A statement ends: the frames of the calls it held without a bracket close, and an assignment is over. */
void kgenome_dtx_end_stmt(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* A value flows from node `from` into node `to` as its argument `arg`. */
void kgenome_dtx_link(struct kgenome_dtx *x, int32_t from, int32_t to, uint32_t arg);
/* The text of a name token, NUL ended, in `b` (`n` bytes); NULL when it does not fit. */
const char *kgenome_dtx_tok_name(const struct kgenome_dtx *x, uint32_t i, char *b, size_t n);

/* ---- statements without a bracket (diag_text_stmt.c) ---- */
/* Is token `i` the first of a statement: the first token, one after a statement end, or one after a word the row says a statement follows (then, else, call). */
int kgenome_dtx_stmt_start(const struct kgenome_dtx *x, uint32_t i);
/*
 * A NAME OF THE ROW'S `stmt_words` THAT IS A CALL WITHOUT A BRACKET, at token `i` (`Execute x`, `system "id"`; the caller has found the word): 1 when it was read - a node, and
 * the frame that takes its arguments to the end of the statement. 0 for a member, a name with a bracket after it, or one with nothing that begins an argument.
 */
int kgenome_dtx_stmt_tok(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* The node of a call made at token `i` whose arguments run to the end of the statement. */
int kgenome_dtx_stmt_call(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i, uint16_t cap, const char *name, uint16_t flags);
/* The name of a tag that is a call (a 'g' token). */
void kgenome_dtx_tag(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* Does `name=value` here name an argument and assign nothing. */
int kgenome_dtx_names_arg(const struct kgenome_dtx *x, const struct kgenome_dtx_walk *w);
/* A member (a token after a join) that is no call by its bracket: a bare call (vb), a server control's text read as the request. 1 always: the token is consumed. */
int kgenome_dtx_member_tok(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* `Request["x"]`, `Request("x")`: 1 when token `i` is the request object read that way. `*pend` is the node when a bracket call follows. */
int kgenome_dtx_req_obj(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i, int32_t *pend);
/* The node of a call named by the chain whose last token is `at` (a name, a built class: `flags`), and the receiver's value flowing into it. */
int32_t kgenome_dtx_call_node(struct kgenome_dtx *x, uint32_t at, uint16_t cap, const char *b, uint32_t len, uint16_t flags);
void kgenome_dtx_receiver_into(struct kgenome_dtx *x, uint32_t i, int32_t n);
/* What diag_text_walk.c (the calls and the loop) asks of diag_text.c (the tokens, the links, the flow into a frame, an assignment): the capability a token's name has, the capability of the
 * producer `p` (a node or a slot of a summary), one link with the role it plays, and the end of an assignment. */
uint16_t kgenome_dtx_cap_of(struct kgenome_dtx *x, uint32_t i);
uint16_t kgenome_dtx_prod_cap(const struct kgenome_dtx *x, uint32_t p);
void kgenome_dtx_link_role(struct kgenome_dtx *x, int32_t from, int32_t to, uint8_t role);
void kgenome_dtx_end_assign(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* Is `nm` a parameter the scope `sc` declared for itself. */
int kgenome_dtx_declared(struct kgenome_dtx *x, uint32_t sc, const uint8_t *nm, uint32_t nl);
/* The name at token `tok` is the variable of scope `target` when it is written in scope `scope` (`global`, `use`, a parameter, a `Dim`). 0 when memory or the budget is refused (said). */
int kgenome_dtx_alias_add(struct kgenome_dtx *x, uint32_t scope, uint32_t tok, uint32_t target);

/* ---- a command line (diag_text_cmd.c) ---- */
/* Does token `i` touch the one before it: nothing between them but the "$" or "${" a variable's token leaves in front of its name. */
int kgenome_dtx_touches(const struct kgenome_dtx *x, uint32_t i);
/* The word at token `i` of a command line: the command, or an argument. 1 when the token was read here. */
int kgenome_dtx_cmd_word(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* A punctuation token of a command line: it may end a segment, begin one, or pass what the segment made along a pipe. 1 when it is a ")" with nothing open (a case pattern's): not a bracket to close. */
int kgenome_dtx_cmd_punct(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i);
/* A group of a command line opens (`due`: a command is its first word) and closes (0 when none is open); what it made flows where it stands once the walk has closed its frames (flush). */
void kgenome_dtx_cmd_open(struct kgenome_dtx_walk *w, int due);
int kgenome_dtx_cmd_close(struct kgenome_dtx_walk *w);
void kgenome_dtx_cmd_flush(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* A statement of a command language ends. */
void kgenome_dtx_cmd_reset(struct kgenome_dtx *x, struct kgenome_dtx_walk *w);
/* The values a command line's segment produced that nothing took: the input of the command after the "|" (called by the walk's flow). */
void kgenome_dtx_cmd_out(struct kgenome_dtx_walk *w, int32_t node, const struct kgenome_dtx_var *v);
/* The node a variable's value makes when it names what is run: the call of a value (data-call), or the name the program wrote out of constants. -1 for none. */
int32_t kgenome_dtx_target_node(struct kgenome_dtx *x, const struct kgenome_dtx_var *v, uint32_t tok, uint32_t open, int by_name);


/* ---- the summaries (diag_text_sum.c) ---- */
/* The call whose chain starts at `head`, written in scope `cs`, has closed: what its functions return is the value it stands for. */
void kgenome_dtx_sum_call_value(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t head, uint32_t cs);

#endif /* KGENOME_DIAG_TEXT_WALK_H */
