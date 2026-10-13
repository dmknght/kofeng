#include "kofdisease.h"

#include <stdio.h>
#include <string.h>

#include <kofmod/kofsig.h>   /* kof_maltype_from_name, kof_maltype_ident */
#include "../../kofcore/kofcore.h"   /* kof_skip_blank */

/* A disease is a diagnose-shaped name: one id for both, defined once in the
 * module ABI (kof_diag_id32_), which is what the macros in a module compute. */
uint32_t kof_disease_id(const char *name)
{
	return kof_diag_id32_(name);
}

const char *kof_disease_check(const char *s)
{
	size_t l = strlen(s);
	const char *c;

	if (!l)
		return "a disease is not empty";
	if (l > KOF_DIAG_DISEASE_LEN)
		return "a disease is at most 63 characters";
	for (c = s; *c; c++)
		if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') ||
		      *c == '-' || *c == '_' || *c == '/'))
			return "a disease is lower-case letters, digits, - _ and /";
	if (s[0] == '/' || s[l - 1u] == '/' || strstr(s, "//"))
		return "a disease is layer/behaviour, not a path with an empty part";
	return NULL;
}

const char *kof_disease_decl_parse(const char *p, struct kof_disease_decl *d)
{
	char tok[40];
	size_t n = 0;
	int mt = 0;
	const char *q = strchr(p, '('), *why;
	char name[KOF_DIAG_DISEASE_LEN + 2u];

	memset(d, 0, sizeof *d);
	if (!q)
		return "KOF_DECLARE_DISEASE(KOF_MALTYPE_..., \"layer/behaviour\")";
	q = kof_skip_blank(q + 1);
	while (*q && *q != ',' && *q != ')' && *q != ' ' && *q != '\t' &&
	       *q != '\n' && *q != '\r' && n + 1u < sizeof tok)
		tok[n++] = *q++;
	tok[n] = 0;
	if (!kof_maltype_from_name(tok, &mt))
		return "the first argument of KOF_DECLARE_DISEASE is a KOF_MALTYPE_ word";
	q = kof_skip_blank(q);
	if (*q != ',')
		return "KOF_DECLARE_DISEASE wants a type and a name";
	q = kof_skip_blank(q + 1);
	if (*q != '"')
		return "the second argument of KOF_DECLARE_DISEASE is a quoted layer/behaviour";
	q++;
	for (n = 0; *q && *q != '"'; q++) {
		if (n >= KOF_DIAG_DISEASE_LEN)
			return "a disease is at most 63 characters";
		name[n++] = *q;
	}
	name[n] = 0;
	if (*q != '"')
		return "the name in KOF_DECLARE_DISEASE is not closed";
	q = kof_skip_blank(q + 1);
	if (*q != ')')
		return "KOF_DECLARE_DISEASE takes two arguments";
	why = kof_disease_check(name);
	if (why)
		return why;
	d->type = (uint8_t)mt;
	memcpy(d->name, name, n + 1u);
	return NULL;
}

size_t kof_disease_decl_print(const struct kof_disease_decl *d, char *out,
			      size_t cap)
{
	int n;

	if (d->type >= (uint8_t)KOF_MALTYPE_COUNT || kof_disease_check(d->name))
		return 0;
	n = snprintf(out, cap, "KOF_DECLARE_DISEASE(%s, \"%s\");",
		     kof_maltype_ident(d->type), d->name);
	return n > 0 ? (size_t)n : 0;
}

int kof_disease_decl_same(const struct kof_disease_decl *a,
			  const struct kof_disease_decl *b)
{
	return a->type == b->type && !strcmp(a->name, b->name);
}
