/*
 * textual_cmd.c - the words, commands and assignments of the command languages (sh, batch, tcl): the three calls of textual.h ("THE WORDS OF A COMMAND LANGUAGE"), which find
 * the language's row and ask its reader (the row's `cmd`, sh/sh_cmd.c, bat/bat_cmd.c, tcl/tcl_cmd.c). Nothing is read here: what a quote, an escape or a name is, is each
 * language's, written once in its own file; the expansion operators a language spells are rows of its function table (shape EXPAND), and the readers look them up there.
 */

#include "textual_lang.h"

uint32_t kgenome_textual_word_read(uint32_t lang, const uint8_t *in, uint32_t from, uint32_t limit, uint32_t ctx, const struct kgenome_textual_word_sink *sk)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	if (!l || !l->cmd || !in || from > limit)
		return 0;
	return l->cmd->word(l, in, from, limit, ctx, sk);
}

int kgenome_textual_cmd_read(uint32_t lang, const uint8_t *in, uint32_t from, uint32_t limit, struct kgenome_textual_cmd *c)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	if (!l || !l->cmd || !in || from >= limit)
		return 0;
	return l->cmd->command(l, in, from, limit, c);
}

uint32_t kgenome_textual_cmd_assigns(uint32_t lang, const uint8_t *in, const struct kgenome_textual_cmd *c, struct kgenome_textual_assign *a, uint32_t max)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	return l && l->cmd && l->cmd->assigns ? l->cmd->assigns(in, c, a, max) : 0u;
}

int kgenome_textual_has_words(uint32_t lang)
{
	const struct kgenome_textual_lang *l = kgenome_textual_lang_find(lang);

	return l && l->cmd;
}

/* The row of the expansion operator written at in[p..limit): the longest spelling of the language's EXPAND rows that is there and, for `prefix`, whether the row says it stands in front of the name.
 * Its index in the table, or -1; `*len` its length. Shared by the readers of the shell and of batch, which spell their operators in the table. */
int kgenome_textual_expand_at(const struct kgenome_textual_lang *l, const uint8_t *in, uint32_t p, uint32_t limit, int prefix, uint32_t *len)
{
	uint32_t k, best = 0;
	int row = -1;
	const char *name;
	struct kgenome_textual_fn f;

	for (k = 0; kgenome_textual_fn_row(l->id, k, &name, &f); k++) {
		uint32_t n = (uint32_t)strlen(name);

		if (f.shape != KGENOME_TEXTUAL_SHAPE_EXPAND || ((f.flags & KGENOME_TEXTUAL_FN_PREFIXOP) != 0) != (prefix != 0) || n <= best || n > limit - p || memcmp(in + p, name, n))
			continue;
		best = n;
		row = (int)k;
	}
	*len = best;
	return row;
}
