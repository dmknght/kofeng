#ifndef KGENOME_CELLLYSIS_SCRIPT_FUNCS_H
#define KGENOME_CELLLYSIS_SCRIPT_FUNCS_H

/*
 * script_funcs.h - the functions of a SCRIPT, as file extents: the text analogue of
 * genotype/image/funcs.h's kgenome_funcs_build for ELF/PE.
 *
 * A script carries no symbol table and no unwind data, so its function table is read from the
 * one thing it does have: its own language's declaration shape, read against the lexer's own
 * code/string/comment classification (textual/textual.h) with no scope stack, no alias tracking
 * and no diagnose-scan lifetime - a mutation unit needs only the byte span and, since Merge 157,
 * the name. This lives in celllysis ("reading code without running it") and not in phenotype: it
 * decodes nothing and runs nothing.
 *
 * EVERY LEXED LANGUAGE HAS A STRATEGY (island package, 2026-11-14), each to its own specification: the brace walk for php, javascript
 * (with its arrows and keyword-less methods), perl, powershell, shell, java (jsp), c# (aspx) and cfscript (script_funcs.c), and a file of
 * its own for python (indentation), ruby, lua and vb (keywords that end with `end` / `End`), tcl (proc) and batch (a called label) -
 * script_funcs_<lang>.c behind script_private.h; coldfusion's <cffunction> is script_funcs_cfm.c. A language with neither would answer
 * PARTIAL with KGENOME_FNTAB_P_NO_TABLE - never an empty COMPLETE, which says "no functions" - and a language this build has no lexer for
 * answers no table at all (C_NONE), as kgenome_funcs_build answers a format it does not know. The text is lexed ONCE (script_private.h,
 * kgenome_script_text_make) and the islands of the same text are built from the same lex (script_islands.h, kgenome_script_parts).
 *
 * EVAL()-LITERAL ISLANDS (PHP only, 2026-11-10): a call the language's own nucleo vocabulary
 * (nucleo.h) names KGENOME_NUCLEO_EVAL, given a single closed, non-interpolating, escape-free
 * STRING literal as its one argument, is followed as a further fragment of the SAME language -
 * its own functions and code are found by this same mechanism, recursively, up to a depth cap -
 * instead of staying opaque string data. See script_funcs.c's own header comment, above
 * kgenome_script_funcs_build's eval-island functions, for the exact shape recognised and why a
 * variable, a concatenation, a decode call or an interpolating/escaped string is explicitly not
 * (the shortest honest answer: this file can only name a span of the OBJECT'S OWN BYTES, and only
 * a bare literal's bytes ARE that value without decoding any of those other shapes would need).
 */

#include <stdint.h>

struct kgenome_func_set;

/*
 * One request: `lang` is enum kgenome_textual_lang_id (textual/textual.h); `in`/`n` is the WHOLE
 * object's bytes - the caller (kof_script_funcs_build, the engine's adapter) does not pre-split by
 * region, exactly as kgenome_funcs_build does not for ELF/PE: mutation_units.c's by_function() keeps
 * only the entries that lie wholly inside the region in hand (fn_in). `flags` is
 * KGENOME_TEXTUAL_FRAGMENT for a text that is code from its first byte and carries no opening tag
 * of its own (a php island an eval() argument resolved to): the lexer is asked to read it so, the
 * same flag kgenome_textual_lex and kgenome_textual_islands take. It replaced a copy of the
 * island with a made-up "<?php\n" in front of it (script_route.c, 2026-11-10), which the engine's
 * scan feed and kofexaminer asked for and kofviewer's blocks table did not (SP-11).
 */
struct kgenome_script_funcs_req {
	uint32_t       lang;
	uint32_t       flags;           /* KGENOME_TEXTUAL_FRAGMENT */
	const uint8_t *in;
	uint64_t       n;
};

void kgenome_script_funcs(const struct kgenome_script_funcs_req *rq, struct kgenome_func_set *out);

/* The same, for a whole file (flags 0): the callers that read one. */
void kgenome_script_funcs_build(uint32_t lang, const uint8_t *data, uint64_t data_n,
			    struct kgenome_func_set *out);

#endif /* KGENOME_CELLLYSIS_SCRIPT_FUNCS_H */
