#include "syndsrc.h"
#include <kofmod/kofsig.h>
#include "../detectors/pathogen/diseases/kofdisease.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void say(const struct kof_dsrc_report *r, int *n, int line, const char *msg)
{
	(*n)++;
	if (r && r->error)
		r->error(r->ud, line, msg);
}

int kof_ssrc_parse(const char *text, size_t n, struct kof_ssrc *p,
		   const struct kof_dsrc_report *r)
{
	char *code = malloc(n + 1u);
	char arg[160];
	int errs = 0;
	unsigned lineno = 1;
	size_t at = 0;

	memset(p, 0, sizeof *p);
	if (!code) {
		say(r, &errs, 0, "out of memory");
		return errs;
	}
	memcpy(code, text, n);
	code[n] = 0;
	kof_dsrc_blank_comments(code, n);
	while (at < n) {
		size_t e = at, len;
		char line[512];
		const char *q;

		while (e < n && code[e] != '\n')
			e++;
		len = e - at < sizeof line - 1u ? e - at : sizeof line - 1u;
		memcpy(line, code + at, len);
		line[len] = 0;
		if ((q = strstr(line, "KOF_SYNDROME_TYPE(")) != NULL) {
			int t = 0;

			if (!kof_dsrc_arg(q, 0, arg, sizeof arg) ||
			    !kof_maltype_from_name(arg, &t))
				say(r, &errs, (int)lineno,
				    "KOF_SYNDROME_TYPE wants a KOF_MALTYPE_ word");
			else
				p->type_mask |= 1u << t;
		} else if ((q = strstr(line, "KOF_SYNDROME_HAS(")) != NULL) {
			size_t L;
			uint32_t i;

			if (!kof_dsrc_arg(q, 0, arg, sizeof arg) ||
			    (L = strlen(arg)) < 3u || arg[0] != '"' ||
			    arg[L - 1u] != '"' || L - 2u > KOF_DIAG_DISEASE_LEN) {
				say(r, &errs, (int)lineno,
				    "KOF_SYNDROME_HAS wants a quoted disease of at "
				    "most 63 characters");
			} else {
				arg[L - 1u] = 0;
				const char *why = kof_disease_check(arg + 1);

				if (why)
					say(r, &errs, (int)lineno, why);
				else if (p->n_dis >= KOF_SSRC_MAX_DIS)
					say(r, &errs, (int)lineno,
					    "a sample is not described by that many behaviours");
				else {
					for (i = 0; i < p->n_dis; i++)
						if (!strcmp(p->dis[i], arg + 1))
							break;
					if (i < p->n_dis)
						say(r, &errs, (int)lineno,
						    "that behaviour is already listed");
					else
						memcpy(p->dis[p->n_dis++], arg + 1,
						       strlen(arg + 1) + 1u);
				}
			}
		}
		at = e < n ? e + 1u : e;
		lineno++;
	}
	free(code);
	if (!p->type_mask)
		say(r, &errs, 0, "a syndrome names a type: KOF_SYNDROME_TYPE");
	if (!p->n_dis)
		say(r, &errs, 0, "a syndrome lists a behaviour: KOF_SYNDROME_HAS");
	return errs;
}
