/*
 * diag_text_lang_jsp.c - the profile row of Java as a jsp page runs it.
 *
 * Methods have no keyword: a `name(...) {` whose name is no statement is the scope (`shape`). The page's islands each end a statement (`<% %>`).
 * A fully qualified name ("java.lang.Runtime.getRuntime().exec") is looked up without its package (`ns_drop`); `new X(..).m()` is one act of X.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue",
	"default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if", "implements", "import", "instanceof",
	"int", "interface", "long", "native", "new", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super",
	"switch", "synchronized", "throw", "throws", "transient", "try", "void", "volatile", "while", NULL };
static const char *const concat[] = { "+", NULL };
static const char *const joins[] = { ".", NULL };
static const char *const ctl[] = { "if", "for", "while", "switch", "catch", "synchronized", NULL };
static const char *const casts[] = { "int", "long", "double", "float", "short", "byte", "boolean", "char", NULL };

static const struct kgenome_dtx_callsem callsems[] = {
	{ "Integer.parseInt", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Long.parseLong", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
	{ "Double.parseDouble", KGENOME_DTX_CS_CLEAN, 0, 0, 0 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_jsp = {
	.id = KGENOME_TEXTUAL_LANG_JSP,
	.typed = 1, .target = KGENOME_NUCLEO_T_JAVA,
	.ident_extra = "$", .keywords = keywords,
	.append = "+=", .concat = concat, .joins = joins, .chain = 1, .data_call = 1, .ns_drop = 1, .typed_decl = 1,
	.island_term = 1, .num_casts = casts,
	.ret_kw = "return",
	.lexical = 1, .fn_opaque = 1, .blocks = KGENOME_DTX_BLK_BRACE, .arrow = "->", .shape = 1, .ctl_words = ctl,
	.callsem = callsems, .n_callsem = sizeof callsems / sizeof callsems[0],
};
