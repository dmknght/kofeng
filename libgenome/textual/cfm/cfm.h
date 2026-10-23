#ifndef KGENOME_TEXTUAL_CFM_H
#define KGENOME_TEXTUAL_CFM_H

/*
 * cfm.h - the cfm directory's one header, private to the family: its row, its lexer and what its files share.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_cfm;

void kgenome_textual_cfm_lex(struct kgenome_textual_lexer *lx);

/* lx->aux, the lexer's memo (one lex, so one text): a "#" that found no closing "#" is not read again, which keeps the
 * scan linear - a text of n/2 "#x" would otherwise read to the end n/2 times. */
#define KGENOME_CFM_MEMO_STR  0x1u      /* a string's "#...#" failed once: no string interpolates for the rest of the text */
#define KGENOME_CFM_MEMO_HASH 0x2u      /* the same for a "#...#" in markup and in a tag */

/* What a window of code is: cfscript (and a script component, and a fragment), the inside of a tag, or the body of a "#...#". */
enum kgenome_cfm_mode { KGENOME_CFM_SCRIPT, KGENOME_CFM_TAG, KGENOME_CFM_EXPR };

/*
 * Delivers [lx->pos, end) as code, strings and comments. In KGENOME_CFM_TAG it stops at the tag's end - the ">" or the "/>" - and
 * answers where (lx->pos is there); otherwise it answers `end`. Look at lx->refused after it.
 */
uint32_t kgenome_textual_cfm_code(struct kgenome_textual_lexer *lx, uint32_t end, enum kgenome_cfm_mode mode);

/* "<!---" at `at` in p[0, end): where the comment ends (it nests), and whether it did. */
uint32_t kgenome_textual_cfm_comment_end(const uint8_t *p, uint32_t end, uint32_t at, int *closed);

/* The "#...#" at `at` in markup: the offset after its closing "#", or 0 (and the memo is set) when it is not one. */
uint32_t kgenome_textual_cfm_hash(struct kgenome_textual_lexer *lx, uint32_t at);

/* A cf tag at `i`: "<cfname" or "</cfname". The offset after the name (0 for none), and where the name begins in *name_at. */
uint32_t kgenome_textual_cfm_tag_name(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *name_at);

/* The tag's end at `i`: ">" or "/", white space and ">". Its length, or 0. */
uint32_t kgenome_textual_cfm_closer(const uint8_t *p, uint32_t n, uint32_t i);

int kgenome_textual_cfm_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);
extern const struct kgenome_textual_call_style kgenome_textual_cfm_calls;

#endif /* KGENOME_TEXTUAL_CFM_H */
