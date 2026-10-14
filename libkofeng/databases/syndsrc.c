#include "syndsrc.h"
#include <kofmod/kofsig.h>
#include "../analyzers/diseases/kofdisease.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		kof_dsrc_say_err(r, &errs, 0, "out of memory");
		return errs;
	}
	memcpy(code, text, n);
	code[n] = 0;
	kof_dsrc_blank_comments(code, n);
	while (at < n) {
		size_t e = at;
		const char *line = code + at, *q;

		/* THE LINE IS READ WHERE IT IS: ended at its newline in the private
		 * copy, not copied into a buffer. It was copied into 512 bytes and cut
		 * there, so a declaration after column 511 was never seen and nothing
		 * said so. */
		while (e < n && code[e] != '\n')
			e++;
		code[e] = 0;
		if ((q = strstr(line, "KOF_DECLARE_SYNDROME_TYPE(")) != NULL) {
			int t = 0;

			if (!kof_dsrc_arg(q, 0, arg, sizeof arg) ||
			    !kof_maltype_from_name(arg, &t))
				kof_dsrc_say_err(r, &errs, (int)lineno,
				    "KOF_DECLARE_SYNDROME_TYPE wants a KOF_MALTYPE_ word");
			else
				p->type_mask |= 1u << t;
		} else if ((q = strstr(line, "KOF_DECLARE_SYNDROME_HAS(")) != NULL) {
			size_t L;
			uint32_t i;

			if (!kof_dsrc_arg(q, 0, arg, sizeof arg) ||
			    (L = strlen(arg)) < 3u || arg[0] != '"' ||
			    arg[L - 1u] != '"' || L - 2u > KOF_DIAG_DISEASE_LEN) {
				kof_dsrc_say_err(r, &errs, (int)lineno,
				    "KOF_DECLARE_SYNDROME_HAS wants a quoted disease of at "
				    "most 63 characters");
			} else {
				arg[L - 1u] = 0;
				const char *why = kof_disease_check(arg + 1);

				if (why)
					kof_dsrc_say_err(r, &errs, (int)lineno, why);
				else if (p->n_dis >= KOF_SSRC_MAX_DIS)
					kof_dsrc_say_err(r, &errs, (int)lineno,
					    "a sample is not described by that many behaviours");
				else {
					for (i = 0; i < p->n_dis; i++)
						if (!strcmp(p->dis[i], arg + 1))
							break;
					if (i < p->n_dis)
						kof_dsrc_say_err(r, &errs, (int)lineno,
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
		kof_dsrc_say_err(r, &errs, 0, "a syndrome names a type: KOF_DECLARE_SYNDROME_TYPE");
	if (!p->n_dis)
		kof_dsrc_say_err(r, &errs, 0, "a syndrome lists a behaviour: KOF_DECLARE_SYNDROME_HAS");
	return errs;
}

size_t kof_ssrc_print_type(unsigned maltype, char *out, size_t cap)
{
	int n;

	if (maltype >= (unsigned)KOF_MALTYPE_COUNT)
		return 0;
	n = snprintf(out, cap, "KOF_DECLARE_SYNDROME_TYPE(%s);", kof_maltype_ident(maltype));
	return n > 0 ? (size_t)n : 0;
}

size_t kof_ssrc_print_dis(const char *disease, char *out, size_t cap)
{
	int n;

	if (kof_disease_check(disease))
		return 0;
	n = snprintf(out, cap, "KOF_DECLARE_SYNDROME_HAS(\"%s\");", disease);
	return n > 0 ? (size_t)n : 0;
}

size_t kof_ssrc_source(const struct kof_ssrc *p, const char *why, char *out,
		       size_t cap)
{
	size_t at = 0, l;
	unsigned t;
	uint32_t i;
	char line[160];

	if (!p->type_mask || !p->n_dis)
		return 0;
	for (i = 0; i < p->n_dis; i++)
		if (!kof_ssrc_print_dis(p->dis[i], line, sizeof line))
			return 0;
#define PUT(s) do { const char *s_ = (s); size_t l_ = strlen(s_); \
		if (cap && at < cap) { size_t room_ = cap - at - 1u; \
			memcpy(out + at, s_, l_ < room_ ? l_ : room_); } \
		at += l_; } while (0)
	if (why && *why) {
		const char *c;

		PUT("/*\n * ");
		for (c = why; *c; c++) {
			char ch[3] = { *c, 0, 0 };

			if (*c == '\n') {
				PUT("\n * ");
				continue;
			}
			/* a comment ends at the first star-slash: never write one */
			if (*c == '*' && c[1] == '/') {
				PUT("* ");
				continue;
			}
			PUT(ch);
		}
		PUT("\n */\n\n");
	}
	for (t = 0; t < (unsigned)KOF_MALTYPE_COUNT; t++)
		if ((p->type_mask >> t) & 1u) {
			l = kof_ssrc_print_type(t, line, sizeof line);
			if (!l)
				return 0;
			PUT(line);
			PUT("\n");
		}
	for (i = 0; i < p->n_dis; i++) {
		kof_ssrc_print_dis(p->dis[i], line, sizeof line);
		PUT(line);
		PUT("\n");
	}
#undef PUT
	if (cap)
		out[at < cap ? at : cap - 1u] = 0;
	return at;
}
