/*
 * ksb_uses.c - Which diagnoses a source reads: the scan of the tree and the
 *    reader's report hooks.
 */

#include "ksb.h"

#include <databases/syndsrc.h>

/*
 * ---- WHICH SIGNATURE READS WHICH DIAGNOSE --------------------------------
 *
 * Worked out from the sources, never declared. A verdict names a diagnose in
 * exactly one place, the call - kof_diag(NAME) or kof_diag_share(cap, A, B) -
 * and that is also the only statement of it that cannot be wrong about what
 * the verdict does. This reads those calls out of every module source in the
 * tree and keeps (diagnose, signature) pairs; the diagnoses are written with
 * the signatures that read them, and the engine runs only the ones somebody
 * does.
 *
 * COMMENTS ARE STRIPPED FIRST. These sources explain themselves at length and
 * more than one of them writes the call out in a comment as an example; a
 * scan that counted those would call a diagnose used by a verdict that only
 * mentions it.
 */

static void uses_add(struct ksb_ctx *ksb, const char *diag, const char *user)
{
	unsigned i;

	for (i = 0; i < ksb->diag.n_uses; i++)
		if (!strcmp(ksb->diag.uses[i].diag, diag) &&
		    !strcmp(ksb->diag.uses[i].user, user))
			return;
	if (ksb->diag.n_uses >= DIAG_USE_MAX) {
		fprintf(stderr, "ksigbuilder: more than %u diagnose uses - "
			"the rest are not recorded\n", DIAG_USE_MAX);
		return;
	}
	snprintf(ksb->diag.uses[ksb->diag.n_uses].diag, sizeof ksb->diag.uses[0].diag, "%s", diag);
	snprintf(ksb->diag.uses[ksb->diag.n_uses].user, sizeof ksb->diag.uses[0].user, "%s", user);
	ksb->diag.n_uses++;
}

/* What uses_note is handed back by the reader: the context and the source the
 * diagnoses are being read for. */
struct uses_user {
	struct ksb_ctx *ksb;
	const char *user;
};

/* Every diagnose one verdict source reads, as (diagnose, user). */
static void uses_note(void *ud, const char *diag)
{
	const struct uses_user *u = ud;
	struct ksb_ctx *ksb = u->ksb;

	uses_add(ksb, diag, u->user);
}

/*
 * THE VERDICT IS READ BY THE ONE READER - kof_dsrc_parse, which the editor and
 * the diagnose build use - and not by a scan of its own for the call names: two
 * readers of one grammar are two places for it to differ. A source that names
 * kof_diag and that reader refuses is an error here, as it is everywhere.
 */
void ksb_uses_scan(struct ksb_ctx *ksb, const char *path)
{
	static struct kof_dsrc d;
	const struct kof_dsrc_report rep = { ksb_dsrc_error, ksb_dsrc_warn, ksb };
	size_t n = 0;
	char *t = ksb_slurp(path, &n), user[DIAG_USER_LEN];
	const char *base = strrchr(path, '/'), *dot;

	if (!t)
		return;
	base = base ? base + 1 : path;
	snprintf(user, sizeof user, "%s", base);
	dot = strrchr(user, '.');
	if (dot)
		user[dot - user] = 0;
	/* Only a source that reads a diagnose goes to the diagnose reader: its
	 * vocabulary for a target is the diagnose's, and an ordinary signature
	 * names others. */
	{
		char *code = malloc(n + 1u);

		if (code) {
			memcpy(code, t, n);
			code[n] = 0;
			kof_dsrc_blank_comments(code, n);
			if (strstr(code, "kof_diag")) {
				ksb->src_name = path;
				memset(&d, 0, sizeof d);
				kof_dsrc_parse(t, n, &d, &rep);
				if (d.has_cond) {
					struct uses_user uu = { ksb, user };

					kof_dsrc_cond_names(&d.cond, uses_note, &uu);
				}
			}
			free(code);
		}
	}
	free(t);
}

void ksb_dsrc_error(void *ud, int line, const char *msg)
{
	struct ksb_ctx *ksb = ud;

	ksb_err(ksb, line, msg);
}

void ksb_dsrc_warn(void *ud, const char *msg)
{
	struct ksb_ctx *ksb = ud;

	fprintf(stderr, "%s: warning: %s\n", ksb->src_name, msg);
}
