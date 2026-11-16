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

/*
 * IS THIS SCRIPT OBJECT CODE FROM ITS FIRST BYTE (owner-agreed island design point 5, 2026-11-14: "the child declares its language and
 * that it starts in code mode"). The one carrier is the object's own entry: `ctx->entry_off` 0 - the code is entered at byte 0 - for a
 * text its producer declared code (an eval()/create_function() argument the text route resolved: objctx_script.c declares it so), and
 * KOF_NA for every script the parser read (its code is entered at a tag, or the language has no tags). It replaced the parse's
 * `tag_len == 0` read as a flag, which a made-up kof_script_info for the island carried.
 */
struct kof_obj_ctx;
int kof_script_from_code(const struct kof_obj_ctx *ctx);

/*
 * WHAT AN ENTRY KIND SAYS ABOUT A SCRIPT OBJECT: KOF_ENT_SCRIPT ("code meant to run") is code from its first byte - an island the text
 * route resolved, a pdf's javascript action. A host that rebuilds a context from an object's bytes (a tool: the parse sets KOF_NA) passes
 * the engine's kof_result.entry_kind here, so its context says what the engine's did: kof_script_mark_code.
 */
int kof_script_entry_is_code(uint32_t entry_kind);
void kof_script_mark_code(struct kof_obj_ctx *ctx);

/*
 * THE FUNCTIONS AND THE ISLANDS OF A SCRIPT OBJECT, from one lex - the engine-side adapter for kgenome_script_parts
 * (libgenome/celllysis/script_islands.h), which takes the lib's own language id and cannot translate KOF_SCRIPT_* itself (a lib never
 * includes kofmod/script.h). The one call every place that needs a script's function table or islands makes (objctx_diag.c's funcs_of,
 * the similarity cut of a context with no live scan, kofexamine), exactly as kof_genome_obj is for ELF/PE. The language is ctx->subtype,
 * code-from-the-first-byte is kof_script_from_code(ctx); `p`/`n` the object's bytes; `want` KGENOME_SCRIPT_PART_*.
 */
struct kgenome_script_parts;
void kof_script_parts_build(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n, uint32_t want, struct kgenome_script_parts *out);

/* The function table alone (kof_script_parts_build with no islands): the tools' table of names. */
struct kgenome_func_set;
void kof_script_funcs_build(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n, struct kgenome_func_set *out);

/*
 * THE ISLANDS THE MEASURE READS: the level-0 islands of the server layer (script_islands.h), in file order and never overlapping, as
 * places, allocated to their number (no cap: the module ABI's kof_script_info.island holds 256 and this does not); the count, 0 when there
 * are none. `*out` is malloc'd (NULL when 0): the caller frees it.
 */
struct kgenome_script_islands;
struct kgenome_diag_text_place;
uint32_t kof_script_places(const struct kgenome_script_islands *isl, struct kgenome_diag_text_place **out);

/*
 * THE OBFSCORE OF A SCRIPT OBJECT (EXPERIMENTAL, owner 2026-11-14): kgenome_diag_text_obf over the object's bytes `p`, `n`, the language
 * and the string functions (kof_script_apply) the engine's own text scan reads it with (objctx_textscan.c), and the islands of the engine's
 * table (kof_script_parts_build, kof_script_places), so a tool with no live scan shows the scan's number and not a second one. One record
 * per island, one for the text no island holds, one per layer of code it computes; `out` is zeroed first and empty when the kind has no
 * lexer. kgenome_diag_text_obf_free returns what it holds.
 */
struct kgenome_diag_text_obf_set;
void kof_script_obf(const struct kof_obj_ctx *ctx, const uint8_t *p, uint64_t n, struct kgenome_diag_text_obf_set *out);

#endif /* KOFENG_SCRIPT_ROUTE_H */
