/*
 * diag_text_lang.c - the languages the TEXT route serves: the one list of profile rows (kgenome_dtx_lang), the answer to "can the route read this
 * language" that the engine asks, and the name lookups the walk and the evaluator share.
 *
 * ONE LIST. A language is served exactly when it has a row here; the engine's gate, its symbol block and the route's own selection all ask
 * kgenome_diag_text_serves, so "the TEXT route can read this script" has one answer and adding a language is a row and a line below. The rows of
 * the languages whose calls are statements without a bracket (vbscript and asp, sh, batch, powershell, tcl, cfml) say what the walk needs of them
 * in the same fields: diag_text_stmt.c, diag_text_cmd.c and diag_text_interp.c read them.
 */

#include <stdlib.h>
#include <string.h>

#include "diag_text_private.h"
#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>

static const struct kgenome_dtx_lang *const rows[] = {
	&kgenome_dtx_lang_php,
	&kgenome_dtx_lang_js,
	&kgenome_dtx_lang_py,
	&kgenome_dtx_lang_perl,
	&kgenome_dtx_lang_ruby,
	&kgenome_dtx_lang_lua,
	&kgenome_dtx_lang_jsp,
	&kgenome_dtx_lang_aspx,
	&kgenome_dtx_lang_vbs,
	&kgenome_dtx_lang_asp,
	&kgenome_dtx_lang_sh,
	&kgenome_dtx_lang_bat,
	&kgenome_dtx_lang_psh,
	&kgenome_dtx_lang_tcl,
	&kgenome_dtx_lang_cfml,
};

const struct kgenome_dtx_lang *kgenome_dtx_lang_find(uint32_t id)
{
	uint32_t i;

	for (i = 0; i < sizeof rows / sizeof rows[0]; i++)
		if (rows[i]->id == id)
			return rows[i];
	return NULL;
}

/* What the sink asks of every name, answered from three small sets made once per scan out of the row's lists (not a second list: the lists stay the truth). */
void kgenome_dtx_prefilters(struct kgenome_dtx *x)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t k, list;

	x->kwmin = 255u;
	for (list = 0; list < 3u; list++) {
		const char *const *words = list == 0 ? l->keywords : list == 1 ? l->stmt_words : l->stmt_lead;

		for (k = 0; words && words[k]; k++) {
			const uint8_t *w = (const uint8_t *)words[k];
			size_t n = strlen(words[k]);

			x->kwfirst[w[0] >> 3] = (uint8_t)(x->kwfirst[w[0] >> 3] | 1u << (w[0] & 7u));
			if (l->fold) {
				uint8_t u = kof_upper_byte(w[0]);

				x->kwfirst[u >> 3] = (uint8_t)(x->kwfirst[u >> 3] | 1u << (u & 7u));
			}
			if (n < x->kwmin)
				x->kwmin = (uint8_t)n;
			if (n > x->kwmax)
				x->kwmax = (uint8_t)(n > 255u ? 255u : n);
		}
	}
	for (k = 0; l->cmd_str && l->cmd_str[k]; k++) {
		uint8_t c = (uint8_t)l->cmd_str[k][0];

		x->cmdfirst[c >> 3] = (uint8_t)(x->cmdfirst[c >> 3] | 1u << (c & 7u));
	}
	for (k = 0; l->joins && l->joins[k]; k++) {
		uint8_t c = (uint8_t)l->joins[k][strlen(l->joins[k]) - 1u];

		x->jlast[c >> 3] = (uint8_t)(x->jlast[c >> 3] | 1u << (c & 7u));
	}
}

int kgenome_diag_text_serves(uint32_t lang)
{
	return kgenome_dtx_lang_find(lang) != NULL;
}

int kgenome_diag_text_reads_view(uint32_t lang)
{
	const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(lang);

	return l && l->reads_view;
}

unsigned kgenome_diag_text_target(uint32_t lang)
{
	const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(lang);

	return l ? l->target : 0u;
}

int kgenome_dtx_word_in(const char *const *list, const uint8_t *p, uint32_t n, int fold)
{
	uint32_t k, j;
	uint8_t c0 = n ? (fold ? kof_lower_byte(p[0]) : p[0]) : 0u;

	for (k = 0; list && list[k]; k++) {
		/* the first byte settles most words, and this runs for every name of the text */
		if ((uint8_t)list[k][0] != c0 || strlen(list[k]) != n)
			continue;
		for (j = 0; j < n && (fold ? kof_lower_byte(p[j]) : p[j]) == (uint8_t)list[k][j]; j++)
			;
		if (j == n)
			return 1;
	}
	return 0;
}

int kgenome_dtx_is_word(const struct kgenome_dtx *x, uint32_t i, const char *w)
{
	size_t n = strlen(w);

	if (x->t[i].len != n)
		return 0;
	for (size_t k = 0; k < n; k++)
		if ((x->lang->fold ? kof_lower_byte(x->in[x->t[i].off + k]) : x->in[x->t[i].off + k]) != (uint8_t)w[k])
			return 0;
	return 1;
}

/* Does the name fit a table lookup: not empty, shorter than the buffer the lookup copies it to, and with no "@" (a table's `@` ends a name - a version suffix - so a name holding one would be cut
 * to another name). The one refusal kgenome_dtx_cap and kgenome_dtx_cap_in share. */
static int name_fits(const uint8_t *p, uint32_t n)
{
	return n && n < KGENOME_DTX_NAME && !memchr(p, '@', n);
}

/*
 * THE ONE LOOKUP OF A NAME IN THE LANGUAGE'S TABLE. The table has no buffer of its own and ends a comparison at an "@" (symbol versions: "socket@GLIBC"),
 * so this one refuses what it cannot answer exactly: a name that does not fit KGENOME_DTX_NAME is not a row (no row is that long), and one with an
 * "@" in it is not the name before it - a ruby `@ivar` must not be read as the call whose name it begins with. Refused, never cut: a cut name
 * would be another name.
 */
uint16_t kgenome_dtx_cap(struct kgenome_dtx *x, const uint8_t *p, uint32_t n, const char **spelled)
{
	char b[KGENOME_DTX_NAME];
	uint16_t cap, id;
	struct kgenome_dtx_capc *c = NULL;

	if (spelled)
		*spelled = NULL;
	if (!name_fits(p, n))
		return KGENOME_NUCLEO_NONE;
	/*
	 * A MEMO of the answers, because the table is searched row by row and a text asks about every name in it: measured on a 1 MB minified js
	 * (callgrind), the search was 46% of the route. The answer is a pure function of the name, so a name asked twice is asked once; a slot
	 * holds a name of up to CAPC_NAME bytes and a longer one goes to the table each time.
	 */
	if (!x->capc && kgenome_dtx_charge(x, KGENOME_DTX_CAPC * sizeof *x->capc))
		x->capc = calloc(KGENOME_DTX_CAPC, sizeof *x->capc);
	if (x->capc && n <= KGENOME_DTX_CAPC_NAME) {
		uint32_t h = kgenome_dtx_name_hash(x->seed, p, n, 0);

		c = &x->capc[h & (KGENOME_DTX_CAPC - 1u)];
		if (c->len == n && !memcmp(c->name, p, n)) {
			cap = c->cap;
			id = c->id;
			goto have;
		}
	}
	memcpy(b, p, n);
	b[n] = 0;
	cap = kgenome_nucleo_name_lookup(x->lang->target, b, &id);
	if (c) {
		c->len = (uint8_t)n;
		memcpy(c->name, p, n);
		c->cap = cap;
		c->id = id;
	}
have:
	if (cap != KGENOME_NUCLEO_NONE && spelled)
		*spelled = kgenome_nucleo_name_of(id);
	return cap;
}

/* The same lookup in the table of another target, for the capability alone (its one caller, the call chain's reading of a COM class, asks no spelling): no memo (a class of COM is looked up once per member), and the same refusal of a name that does not fit. */
uint16_t kgenome_dtx_cap_in(struct kgenome_dtx *x, unsigned target, const uint8_t *p, uint32_t n)
{
	char b[KGENOME_DTX_NAME];

	if (!target || target == x->lang->target)
		return kgenome_dtx_cap(x, p, n, NULL);
	if (!name_fits(p, n))
		return KGENOME_NUCLEO_NONE;
	memcpy(b, p, n);
	b[n] = 0;
	return kgenome_nucleo_cap_of_name(target, b);
}

/*
 * A NAME THE ROUTE TOLD, as a row: by the language's own table, then by the tables its objects' classes are rows of (`classfns`: COM is written once, in the VBS table, so a
 * js or powershell script's "WScript.Shell.Run" is a row of that table and not of its own). The id of the row (0 for none) and the table it was found in. The one answer for the names
 * block a script's imports are, and for the gate that reads it.
 */
uint16_t kgenome_dtx_name_row(const struct kgenome_dtx_lang *l, const char *name, unsigned *target, uint16_t *cap)
{
	uint32_t k;
	uint16_t id, c = kgenome_nucleo_name_lookup(l->target, name, &id);

	if (target)
		*target = l->target;
	for (k = 0; !id && k < l->n_classfns && strchr(name, '.'); k++) {          /* a class's member is qualified; a bare name is the language's or none */
		if (l->classfns[k].target == l->target)
			continue;
		c = kgenome_nucleo_name_lookup(l->classfns[k].target, name, &id);
		if (id && target)
			*target = l->classfns[k].target;
	}
	if (cap)
		*cap = c;     /* a lookup that found no row answers NONE, so a name with no row has no capability to carry over from an earlier table */
	return id;
}

uint16_t kgenome_diag_text_cap_of_name(uint32_t lang, const char *name)
{
	const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(lang);
	uint16_t cap;

	if (!l || !kgenome_dtx_name_row(l, name, NULL, &cap))
		return KGENOME_NUCLEO_NONE;
	return cap;
}
