/*
 * script_route.c - see script_route.h.
 */

#include <kofmod/script.h>
#include <textual/textual.h>

#include "script_route.h"

uint32_t kof_script_textual_lang(uint8_t kind)
{
	switch (kind) {
	case KOF_SCRIPT_PHP:    return KGENOME_TEXTUAL_LANG_PHP;
	case KOF_SCRIPT_SHELL:  return KGENOME_TEXTUAL_LANG_SH;
	case KOF_SCRIPT_JS:     return KGENOME_TEXTUAL_LANG_JS;
	case KOF_SCRIPT_PYTHON: return KGENOME_TEXTUAL_LANG_PY;
	case KOF_SCRIPT_VBS:    return KGENOME_TEXTUAL_LANG_VBS;
	case KOF_SCRIPT_ASP:    return KGENOME_TEXTUAL_LANG_ASP;
	case KOF_SCRIPT_ASPX:   return KGENOME_TEXTUAL_LANG_ASPX;
	case KOF_SCRIPT_JSP:    return KGENOME_TEXTUAL_LANG_JSP;
	case KOF_SCRIPT_PERL:   return KGENOME_TEXTUAL_LANG_PERL;
	case KOF_SCRIPT_RUBY:   return KGENOME_TEXTUAL_LANG_RUBY;
	case KOF_SCRIPT_LUA:    return KGENOME_TEXTUAL_LANG_LUA;
	case KOF_SCRIPT_TCL:    return KGENOME_TEXTUAL_LANG_TCL;
	case KOF_SCRIPT_BAT:    return KGENOME_TEXTUAL_LANG_BAT;
	case KOF_SCRIPT_PSH:    return KGENOME_TEXTUAL_LANG_PSH;
	case KOF_SCRIPT_CFM:    return KGENOME_TEXTUAL_LANG_CFM;
	default:                return KGENOME_TEXTUAL_LANG_NONE;
	}
}

/* The span that holds byte `at`: is it code. */
struct code_at {
	uint32_t at;
	int      code;
};

static int code_at_sink(void *u, const struct kgenome_textual_span *s)
{
	struct code_at *c = u;

	if ((uint64_t)s->off + s->len <= c->at)
		return 1;
	/* A HEREDOC BODY COUNTS AS CODE here, as it did: the table this replaced did not read one, so a tag inside one was in code, and tests/unit/script_islands.c pins
	 * the answer ("a shell script that heredocs php -> php": a dropper that writes a php shell out of a heredoc carries one, and php's rules must run on it). */
	c->code = s->kind == KGENOME_TEXTUAL_CODE || s->kind == KGENOME_TEXTUAL_TAG || (s->kind == KGENOME_TEXTUAL_STRING && (s->flags & KGENOME_TEXTUAL_F_HERE));
	return 0;
}

/* A FRAGMENT is code from its first byte: the table this replaced read the language's rules from byte 0 whatever the file opened with, and a file's
 * language here is named by its shebang, so a php tag - the thing the sniff asks about - is not what leaves markup. */
int kof_script_is_code_at(uint8_t kind, const uint8_t *p, uint32_t n, uint32_t at)
{
	uint32_t lang = kof_script_textual_lang(kind);
	struct code_at c = { at, 1 };
	struct kgenome_textual_lex_req rq = { .in = p, .n = at + 1u, .lang = lang, .flags = KGENOME_TEXTUAL_FRAGMENT, .sink = code_at_sink, .user = &c };
	struct kgenome_textual_lex_res res;

	if (!lang || !p || at >= n)
		return 1;       /* nothing to say it is not */
	(void)kgenome_textual_lex(&rq, &res);
	return c.code;
}
