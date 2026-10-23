/*
 * ksb_uses.c - Which diagnoses a source reads: the scan of the tree and the
 *    reader's report hooks.
 */

#include "ksb.h"
#include <databases/diagsrc.h>


/*
 * ---- WHICH MODULE READS WHICH DIAGNOSE -----------------------------------
 *
 * Worked out from the sources, never declared. A module names a diagnose in
 * exactly one place, the call - kof_diag(NAME) or kof_diag_share(cap, A, B) -
 * and that is also the only statement of it that cannot be wrong about what
 * the module does. This reads those calls out of every module source in the
 * tree and keeps (diagnose, module) pairs; the diagnoses are written with
 * the modules that read them, and the engine runs only the ones somebody
 * does (or that declare a disease).
 *
 * COMMENTS ARE STRIPPED FIRST. These sources explain themselves at length and
 * more than one of them writes the call out in a comment as an example; a
 * scan that counted those would call a diagnose used by a module that only
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

/* Every diagnose one module source reads, as (diagnose, user). */
static void uses_note(void *ud, const char *diag)
{
	const struct uses_user *u = ud;
	struct ksb_ctx *ksb = u->ksb;

	uses_add(ksb, diag, u->user);
}

/*
 * THE CALLS ARE READ BY THE ONE READER - kof_dsrc_reads, in the library - and not
 * by a scan of this program's own for the call names: two readers of one grammar
 * are two places for it to differ. Nothing is required of the module's shape.
 */
void ksb_uses_scan(struct ksb_ctx *ksb, const char *path)
{
	size_t n = 0;
	char *t = ksb_slurp(path, &n), user[DIAG_USER_LEN];
	const char *base = strrchr(path, '/'), *dot;
	struct uses_user uu;

	if (!t)
		return;
	base = base ? base + 1 : path;
	snprintf(user, sizeof user, "%s", base);
	dot = strrchr(user, '.');
	if (dot)
		user[dot - user] = 0;
	uu.ksb = ksb;
	uu.user = user;
	kof_dsrc_reads(t, n, uses_note, &uu);
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
