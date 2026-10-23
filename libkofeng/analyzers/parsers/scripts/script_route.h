/*
 * script_route.h - which lexer of the lib a script is read with, if any.
 *
 * The parsers directory routes and the lib reads: this says which language of
 * libgenome/textual a script kind is, and nothing about how it is read. A kind with no
 * lexer there is answered 0 and is not formed. Today that is KOF_SCRIPT_ANY only: the other fifteen kinds are lexed by the lib. What a script computes is the
 * lib's too (objctx_script_consts.c), for every language its evaluator serves.
 */

#ifndef KOFENG_SCRIPT_ROUTE_H
#define KOFENG_SCRIPT_ROUTE_H

#include <stdint.h>

/* enum kgenome_textual_lang_id for a KOF_SCRIPT_* kind, or KGENOME_TEXTUAL_LANG_NONE (0). */
uint32_t kof_script_textual_lang(uint8_t kind);

/*
 * Is byte `at` of a script of `kind` CODE - outside every string and every comment, as the lib's lexer reads that kind (kgenome_textual_lex over the
 * bytes up to it). 1 when the kind has no lexer: "cannot tell" and "is code" are the same answer here, the safe one for the sniff that asks (a tag named
 * by a file whose first line says another language: is it in that language's code, or in a string or a comment of it). This replaced the table-driven
 * kof_lex_is_code_at, which read the comment openers and quotes of script_norm.c's rows a second time.
 */
int kof_script_is_code_at(uint8_t kind, const uint8_t *p, uint32_t n, uint32_t at);

#endif /* KOFENG_SCRIPT_ROUTE_H */
