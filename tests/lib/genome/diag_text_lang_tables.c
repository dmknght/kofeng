/*
 * genome / diag_text_lang_tables - the word lists of a profile row that the route matches ONE-SIDED are spelled the way the match expects.
 *
 * In a language that folds (row `fold`: php, vbscript, aspx, batch, powershell, cfml) a name read from the text is lower-cased and compared to the list's entry as it stands
 * (kgenome_dtx_word_in, diag_text_cmd.c's cmd_exts): an entry with a capital in it can never match, and nothing says so - the row is read, the word is never found. That is what
 * the callsem table did to vbscript's CInt, CLng, CDbl, Len, IsNumeric ... and aspx's int.Parse (S2-4, found by the first test that asked whether `CInt(Request("x"))` carries the
 * request); callsem_named folds both sides now, and every OTHER list is held to the old rule here: all lower case in a row that folds. A list this test does not name is matched by
 * kgenome_dtx_name_eq, which folds both sides (pathsem, opts, the chain names), and may be spelled as the language spells it.
 *
 * usage: diag_text_lang_tables
 */

#include <stdio.h>
#include <string.h>

#include <phenotype/diag_text_private.h>
#include <textual/textual.h>

static int fails;

static void lower_list(const struct kgenome_dtx_lang *l, const char *what, const char *const *list)
{
	unsigned k;

	for (k = 0; list && list[k]; k++) {
		const char *p;

		for (p = list[k]; *p; p++)
			if (*p >= 'A' && *p <= 'Z') {
				printf("  FAIL language %u (folds): %s entry \"%s\" has a capital and can never match a lower-cased name\n", (unsigned)l->id, what, list[k]);
				fails++;
				break;
			}
	}
}

int main(void)
{
	unsigned id, rows = 0, folding = 0;

	for (id = 1; id < 64u; id++) {
		const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(id);

		if (!l)
			continue;
		rows++;
		if (!l->fold)
			continue;
		folding++;
		lower_list(l, "keywords", l->keywords);
		lower_list(l, "stmt_words", l->stmt_words);
		lower_list(l, "stmt_block", l->stmt_block);
		lower_list(l, "stmt_lead", l->stmt_lead);
		lower_list(l, "num_casts", l->num_casts);
		lower_list(l, "scope_objs", l->scope_objs);
		lower_list(l, "load_names", l->load_names);
		lower_list(l, "ctl_members", l->ctl_members);
		lower_list(l, "ctl_words", l->ctl_words);
		lower_list(l, "blk_open", l->blk_open);
		lower_list(l, "blk_open_first", l->blk_open_first);
		lower_list(l, "cmd_lead", l->cmd_lead);
		lower_list(l, "cmd_rearm", l->cmd_rearm);
		lower_list(l, "cmd_exts", l->cmd_exts);
		lower_list(l, "cmd_sub", l->cmd_sub);
	}
	if (rows != 15u || folding < 4u) {
		printf("  FAIL %u rows, %u that fold: the test did not find the rows it audits\n", rows, folding);
		fails++;
	}
	printf("diag_text_lang_tables: %u rows, %u fold, %s\n", rows, folding, fails ? "FAILED" : "ok");
	return fails != 0;
}
