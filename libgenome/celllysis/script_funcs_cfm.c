/*
 * script_funcs_cfm.c - THE FUNCTIONS OF A COLDFUSION TEXT (script_private.h, kgenome_script_strategy), two declarations of one language
 * [cfml reference: <cffunction>, "Defining functions in CFScript"; Unverified: no cf engine here]:
 *   - the tag `<cffunction name="f" ...>` ... `</cffunction>`: the function runs from its "<" to the ">" of its end tag; one closed by "/>"
 *     has no body and is the tag; one with no end tag before the next `<cffunction` or the end of the text has no body that ends (END_OPEN
 *     to the next start or the end). The name is the value of its `name` attribute. cffunction does not nest.
 *   - cfscript's `function f(...) {`: the brace walk with cfml's row (script_funcs.c), over cfscript and over a script component.
 * The two are merged in start order, a cfscript function inside a <cffunction> (a <cfscript> block in its body) being nested in it.
 * Survey (2026-11-14): the 4 cfm files of the corpus hold no <cffunction> and no cfscript function; the tests are the evidence.
 */

#include "script_private.h"

#include <textual/textual.h>

static int cf_name_byte(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* Is the TAG at `i` "<cffunction" (`end`: "</cffunction"), a whole name. */
static int cf_func_tag(const struct kgenome_script_text *t, uint64_t i, int end)
{
	static const char w[] = "cffunction";
	uint64_t k, s = i + 1u + (uint64_t)end;

	if (s + sizeof w - 1u > t->n || t->kind[i] != KGENOME_TEXTUAL_TAG || t->p[i] != '<' || (end && t->p[i + 1u] != '/'))
		return 0;
	for (k = 0; k < sizeof w - 1u; k++)
		if (kgenome_script_lower(t->p[s + k]) != (uint8_t)w[k])
			return 0;
	return s + k == t->n || !cf_name_byte(t->p[s + k]);
}

/* The tag's ">" (a TAG byte) from `i`, and the `name` attribute's value inside it. */
static uint64_t cf_tag_end(const struct kgenome_script_text *t, uint64_t i, uint64_t *ns, uint64_t *nl, int *self)
{
	uint64_t j;

	*ns = *nl = 0;
	*self = 0;
	for (j = i + 1u; j < t->n && !(t->kind[j] == KGENOME_TEXTUAL_TAG && t->p[j] == '>'); j++) {
		if (!*nl && t->kind[j] == KGENOME_TEXTUAL_CODE && j + 4u < t->n && kgenome_script_lower(t->p[j]) == 'n' &&
		    kgenome_script_lower(t->p[j + 1u]) == 'a' && kgenome_script_lower(t->p[j + 2u]) == 'm' &&
		    kgenome_script_lower(t->p[j + 3u]) == 'e' && !cf_name_byte(t->p[j - 1u])) {
			uint64_t v = j + 4u;

			while (v < t->n && (t->p[v] == ' ' || t->p[v] == '\t'))
				v++;
			if (v < t->n && t->p[v] == '=') {
				for (v++; v < t->n && (t->p[v] == ' ' || t->p[v] == '\t'); v++)
					;
				if (v < t->n && (t->p[v] == '"' || t->p[v] == '\''))
					v++;
				*ns = v;
				while (v < t->n && cf_name_byte(t->p[v]))
					v++;
				*nl = v - *ns;
			}
		}
	}
	*self = j < t->n && j > i && t->p[j - 1u] == '/';
	return j < t->n ? j + 1u : t->n;
}

int kgenome_script_funcs_cfm(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	struct kgenome_fntab_list cs, tags;
	uint64_t i;
	uint32_t a = 0, b = 0;
	int ok = 1;

	memset(&cs, 0, sizeof cs);
	memset(&tags, 0, sizeof tags);
	kgenome_script_cfscript_funcs(t, &cs);
	for (i = 0; i < t->n && ok; i++) {
		uint64_t ns, nl, e, j;
		int self;

		if (!cf_func_tag(t, i, 0))
			continue;
		e = cf_tag_end(t, i, &ns, &nl, &self);
		if (self) {
			/* `<cffunction ... />` has no body: the function is the tag */
			ok = kgenome_script_emit(&tags, i, e, ns, nl, 0);
			i = e - 1u;
			continue;
		}
		for (j = e; j < t->n && !cf_func_tag(t, j, 1) && !cf_func_tag(t, j, 0); j++)
			;
		if (j < t->n && cf_func_tag(t, j, 1)) {
			uint64_t ns2, nl2;
			int s2;

			e = cf_tag_end(t, j, &ns2, &nl2, &s2);
			ok = kgenome_script_emit(&tags, i, e, ns, nl, 0);
		} else {
			ok = kgenome_script_emit(&tags, i, j, ns, nl, KGENOME_FN_F_END_OPEN);
			e = j;
		}
		i = e ? e - 1u : i;
	}
	/* merge in start order; a cfscript function inside a tag function is nested in it */
	while (ok && (a < cs.n || b < tags.n)) {
		if (b < tags.n && (a >= cs.n || tags.v[b].off <= cs.v[a].off)) {
			uint64_t te = tags.v[b].off + tags.v[b].len;

			ok = kgenome_fntab_list_add(l, &tags.v[b]) || l->status != KGENOME_NOMEM;
			while (a < cs.n && cs.v[a].off < te)
				a++;
			b++;
		} else {
			ok = kgenome_fntab_list_add(l, &cs.v[a]) || l->status != KGENOME_NOMEM;
			a++;
		}
	}
	l->partial |= cs.partial | tags.partial;
	if (cs.status == KGENOME_NOMEM || tags.status == KGENOME_NOMEM)
		ok = 0;
	kgenome_fntab_list_free(&cs);
	kgenome_fntab_list_free(&tags);
	return ok;
}
