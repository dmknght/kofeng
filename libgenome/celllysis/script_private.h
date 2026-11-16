#ifndef KGENOME_CELLLYSIS_SCRIPT_PRIVATE_H
#define KGENOME_CELLLYSIS_SCRIPT_PRIVATE_H

/*
 * script_private.h - what the parts of the `script` family share: the ONE lex of a text (script_funcs.c makes it),
 * the function strategies of the languages that are not brace-delimited (one file each, script_funcs_<lang>.c), and
 * the island builder (script_islands.c). Private to celllysis; the surface is script_funcs.h and script_islands.h.
 *
 * ONE LEX, MANY READERS (owner, 2026-11-14: "lex once; no work done twice"). kgenome_script_parts lexes the text once
 * with the language's own lexer (textual/textual.h) and keeps, per byte, what that lex said: `kind` (the span kind:
 * markup, tag, code, string, comment) and `code` (a CODE byte, and also the code of an eval()-literal that was followed,
 * see script_funcs.c). Every function strategy and the island builder read these two arrays and never lex again.
 */

#include <stdint.h>
#include <string.h>

#include <genotype/image/fntab.h>

struct kgenome_script_text {
	const uint8_t *p;
	uint64_t       n;
	uint32_t       lang;            /* enum kgenome_textual_lang_id */
	uint32_t       flags;           /* KGENOME_TEXTUAL_FRAGMENT */
	uint8_t       *code;            /* n bytes: 1 for a CODE byte (the strategies only read it) */
	uint8_t       *kind;            /* n bytes: enum kgenome_textual_kind of the span holding the byte */
	/* THE PAREN TABLE: every code "(" with the code ")" that closes it, in order of the "(" (script_funcs.c), built once with the
	 * lex and read by every header shape and by the island builder's php conditions (kgenome_script_paren_close). */
	uint32_t      *par_open, *par_close;
	uint32_t       n_par;
	/* script_funcs.c's own: the eval()-literal spans followed as code (php), and whether one was not */
	void          *evals;
	uint8_t        eval_skipped;
};

/*
 * A FUNCTION STRATEGY of one language: appends that language's OUTERMOST functions to `l` (kgenome_fntab_list_add), in start
 * order and disjoint, each with kind KGENOME_FN_SCRIPT, end_source KGENOME_FN_E_SCRIPT and its name's span (name_len 0 for an
 * anonymous one); one whose end the text never reached runs to the end of the text with KGENOME_FN_F_END_OPEN and the strategy
 * sets KGENOME_FNTAB_P_ENDS in l->partial. Answers 0 only on an allocation failure. Each is written to its language's own
 * specification, in its own file, and never calls another (owner, 2026-11-14: "mỗi ngôn ngữ tổ chức một lexer riêng").
 */
typedef int (*kgenome_script_strategy)(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);

int kgenome_script_funcs_py(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_ruby(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_lua(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_tcl(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_bat(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_vb(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);
int kgenome_script_funcs_cfm(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);

/* cfscript's `function` declarations of a cfml text: the brace walk with cfml's row (script_funcs.c), for script_funcs_cfm.c. */
void kgenome_script_cfscript_funcs(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);

/*
 * THE ONE LEX of a text, for a strategy's test and for kgenome_script_parts: `code` and `kind` are allocated here (2n bytes) and
 * given back by kgenome_script_text_free. 0 on an allocation failure or a text this lib does not lex (no row, empty, over 4 GiB).
 */
int kgenome_script_text_make(uint32_t lang, uint32_t flags, const uint8_t *p, uint64_t n, struct kgenome_script_text *out);
void kgenome_script_text_free(struct kgenome_script_text *t);

/* The ")" that closes the code "(" at `open`: 0 when it has none. */
int kgenome_script_paren_close(const struct kgenome_script_text *t, uint64_t open, uint64_t *close);

/* The islands of a text from its one lex and its function table (script_islands.c; `want` is kgenome_script_parts_req.want). */
struct kgenome_script_islands;
void kgenome_script_islands_of_text(const struct kgenome_script_text *t, const struct kgenome_func_set *funcs, uint32_t want,
				    struct kgenome_script_islands *s);

/* The function table of a text from its one lex: the strategy of its language (script_funcs.c). */
void kgenome_script_funcs_of_text(const struct kgenome_script_text *t, struct kgenome_func_set *out);

/* The eval()-literal flags of a table (KGENOME_FN_F_EVAL_ISLAND on an entry that starts in a followed literal, P_EVAL_SKIP): script_text.c. */
void kgenome_script_eval_flag(const struct kgenome_script_text *t, struct kgenome_fntab_list *l);

/*
 * How far one RUN of a header is read before a candidate is given up (script_funcs.c's header comment says why the number is what it
 * is), and the eval()-literal search's lookahead: one number.
 */
#define KGENOME_SCRIPT_LOOKAHEAD 512u

/* A php name byte: [A-Za-z0-9_\x80-\xff] (php's own lexer rule). */
static inline int kgenome_script_php_name(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c >= 0x80u;
}

/* One entry of a strategy's answer: [off, end) with its name's span. 0 only on an allocation failure. */
static inline int kgenome_script_emit(struct kgenome_fntab_list *l, uint64_t off, uint64_t end, uint64_t name_off,
				      uint64_t name_len, uint16_t flags)
{
	struct kgenome_func f;

	memset(&f, 0, sizeof f);
	f.off = off;
	f.len = end - off;
	f.kind = KGENOME_FN_SCRIPT;
	f.end_source = KGENOME_FN_E_SCRIPT;
	f.flags = flags;
	f.name_off = (uint32_t)name_off;
	f.name_len = (uint32_t)name_len;
	if (flags & KGENOME_FN_F_END_OPEN)
		l->partial |= KGENOME_FNTAB_P_ENDS;
	return kgenome_fntab_list_add(l, &f) || l->status != KGENOME_NOMEM;
}

/* The ASCII letter `c` folded to lower case; every other byte as it is. */
static inline uint8_t kgenome_script_lower(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32u) : c;
}

#endif /* KGENOME_CELLLYSIS_SCRIPT_PRIVATE_H */
