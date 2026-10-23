/*
 * diag_text_lang_cfml.c - the profile row of coldfusion: tags and cfscript, one table (T_CFML), names that do not care about case (variables neither).
 *
 * A TAG that is a row (`<cfexecute ..>`, `<cffile ..>`, `<cfinclude ..>`, `<cfhttp ..>`) is a call whose arguments are its attributes (`tag_calls`): the lexer gives the tag's name as part
 * of a TAG span and the route reads it from there, every tag ends the statement before it and its ">" ends it, and `name=value` among the attributes names an argument. An attribute's string
 * interpolates `#expr#` (`interp`), which is read as the code it is: `arguments="#form.cmd#"` is the request flowing into the command. A tag that is no row (`cfset`, `cfif`, `cfoutput`) is
 * code only: `<cfset x = form.cmd>` is an assignment. A request is the scope `form`, `url` or `cookie` (a row of the table: the key after it is the matcher's), and a java object is
 * `createObject("java", "java.lang.Runtime")`, whose members are rows of the Java table (`classfns`); `createObject("com", ..)` is COM.
 * NOT READ: a java object of the tag form (`<cfobject type="java" class=..>`), `cfscript` components' own scopes (every name is the top level's), `cfinvoke`/`invoke` by a value.
 */

#include "diag_text_private.h"
#include <celllysis/nucleo.h>

static const char *const keywords[] = { "var", "function", "return", "if", "else", "elseif", "for", "while", "do", "in", "break", "continue", "switch", "case", "default", "try",
	"catch", "finally", "throw", "new", "true", "false", "null", "and", "or", "not", "eq", "neq", "gt", "lt", "gte", "lte", "is", "contains", "mod", NULL };
static const char *const concat[] = { "&", NULL };
static const char *const joins[] = { ".", NULL };

static const struct kgenome_dtx_classfn classfns[] = {
	{ .name = "createObject", .arg = 1, .type = 1, .type_word = "java", .target = KGENOME_NUCLEO_T_JAVA, .ns_drop = 1 },
	{ .name = "createObject", .arg = 1, .type = 1, .type_word = "com", .target = KGENOME_NUCLEO_T_VBS, .versions = 1 },
};

const struct kgenome_dtx_lang kgenome_dtx_lang_cfml = {
	.id = KGENOME_TEXTUAL_LANG_CFM,
	.typed = 1, .target = KGENOME_NUCLEO_T_CFML, .fold = 1, .fold_vars = 1, .keywords = keywords,
	.append = "&=", .concat = concat, .joins = joins, .chain = 1, .kwargs = 1,
	.tag_calls = "<cf", .interp = 4, .interp_all = 1,
	.classfns = classfns, .n_classfns = sizeof classfns / sizeof classfns[0],
	.blocks = KGENOME_DTX_BLK_BRACE,
};
