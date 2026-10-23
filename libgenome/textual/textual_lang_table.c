/*
 * textual_lang_table.c - the languages this build has a lexer for. Adding one is a
 * directory and a line here.
 */

#include "textual_lang.h"
#include "php/php.h"
#include "sh/sh.h"
#include "js/js.h"
#include "vbs/vbs.h"
#include "asp/asp.h"
#include "jsp/jsp.h"
#include "aspx/aspx.h"
#include "py/py.h"
#include "perl/perl.h"
#include "ruby/ruby.h"
#include "lua/lua.h"
#include "tcl/tcl.h"
#include "bat/bat.h"
#include "psh/psh.h"
#include "cfm/cfm.h"

static const struct kgenome_textual_lang *const lang_row[KGENOME_TEXTUAL_LANG_COUNT] = {
	[KGENOME_TEXTUAL_LANG_PHP] = &kgenome_textual_lang_php,
	[KGENOME_TEXTUAL_LANG_SH] = &kgenome_textual_lang_sh,
	[KGENOME_TEXTUAL_LANG_JS] = &kgenome_textual_lang_js,
	[KGENOME_TEXTUAL_LANG_VBS] = &kgenome_textual_lang_vbs,
	[KGENOME_TEXTUAL_LANG_ASP] = &kgenome_textual_lang_asp,
	[KGENOME_TEXTUAL_LANG_JSP] = &kgenome_textual_lang_jsp,
	[KGENOME_TEXTUAL_LANG_ASPX] = &kgenome_textual_lang_aspx,
	[KGENOME_TEXTUAL_LANG_PY] = &kgenome_textual_lang_py,
	[KGENOME_TEXTUAL_LANG_PERL] = &kgenome_textual_lang_perl,
	[KGENOME_TEXTUAL_LANG_RUBY] = &kgenome_textual_lang_ruby,
	[KGENOME_TEXTUAL_LANG_LUA] = &kgenome_textual_lang_lua,
	[KGENOME_TEXTUAL_LANG_TCL] = &kgenome_textual_lang_tcl,
	[KGENOME_TEXTUAL_LANG_BAT] = &kgenome_textual_lang_bat,
	[KGENOME_TEXTUAL_LANG_PSH] = &kgenome_textual_lang_psh,
	[KGENOME_TEXTUAL_LANG_CFM] = &kgenome_textual_lang_cfm,
};

const struct kgenome_textual_lang *kgenome_textual_lang_find(uint32_t id)
{
	return id < KGENOME_TEXTUAL_LANG_COUNT ? lang_row[id] : NULL;
}
