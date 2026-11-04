#define _GNU_SOURCE

/*
 * kofeditor_save.c - saving: the generator's output (draft_generate and its variants), the filesystem it writes through and the plan to put back what a failed save removed.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


/*
 * WRITE THE OUTPUT: one `<type>_<family>_<tag>_NN.c` per unit into `dir` (the tree's bases/diagnoses).
 * ALL OR NOTHING: every unit is checked first - the header has a family and a variant, every unit a
 * type and a tag, no file of that name exists - and when any check fails NOTHING is written and `msg`
 * says which unit and why. A file is created with "wx" and never replaced: an existing file is
 * refused and named. Returns the number of files written, or -1 on a refusal (msg is the reason).
 * A write that fails part way removes the files this call made.
 */
int draft_generate(struct kof_editor *e, const char *dir, char *msg, size_t cap)
{
	return draft_generate_with(e, dir, msg, cap, 1);
}

/* ---- THE SAVE: what was added is written, what was removed is deleted --------------------------------------------------- */

static FILE *fs_create(void *ud, const char *path)
{
	(void)ud;
	return fopen(path, "wbx");
}

static int fs_unlink(void *ud, const char *path)
{
	(void)ud;
	return unlink(path);
}

static const struct draft_fs fs_real = { NULL, fs_create, fs_unlink };

/* A file this Save deletes: kept whole in memory until the Save is over, so a failure part way can put it back. */
struct del_plan {
	uint32_t id;
	char   name[DRAFT_LINK_MAX];
	char  *bytes;
	size_t n;
	mode_t mode;
	int    keep;            /* a unit that says the same was added again: the file stays */
	int    gone;            /* deleted by this call */
};

/* Append to the status line; when it does not fit the end says so. */
static void say_add(char *msg, size_t cap, const char *fmt, ...)
{
	size_t at = strlen(msg);
	va_list ap;
	int w;

	if (at + 1u >= cap)
		return;
	va_start(ap, fmt);
	w = vsnprintf(msg + at, cap - at, fmt, ap);
	va_end(ap);
	if (w >= 0 && (size_t)w >= cap - at && cap > 4u)
		memcpy(msg + cap - 4u, "...", 4u);
}

/* " a, b, c" - the names (stems) of the files `names[i]` for the flagged entries. */
static void say_names(char *msg, size_t cap, const char *const *names, const int *flag, uint32_t n)
{
	uint32_t i, first = 1;

	for (i = 0; i < n; i++) {
		size_t L;
		char stem[200];

		if (!flag[i])
			continue;
		snprintf(stem, sizeof stem, "%s", names[i]);
		L = strlen(stem);
		if (L > 2u && !strcmp(stem + L - 2u, ".c"))
			stem[L - 2u] = 0;
		say_add(msg, cap, "%s%s", first ? " " : ", ", stem);
		first = 0;
	}
}

static void put_back(const char *dir, struct del_plan *dp, uint32_t nd, char *msg, size_t cap)
{
	uint32_t z;

	for (z = 0; z < nd; z++) {
		char path[4400];
		FILE *f;

		if (!dp[z].gone)
			continue;
		snprintf(path, sizeof path, "%s/%s.c", dir, dp[z].name);
		f = fopen(path, "wbx");
		if (f && fwrite(dp[z].bytes, 1, dp[z].n, f) == dp[z].n && fclose(f) == 0) {
			(void)chmod(path, dp[z].mode);
			dp[z].gone = 0;
			continue;
		}
		if (f)
			fclose(f);
		say_add(msg, cap, " [%s.c could not be put back]", dp[z].name);
	}
}

/* `with_form` 0 writes the catalog lines only, which is the seam the writer's own tests use; Generate passes 1. */
int draft_generate_with(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form)
{
	return draft_generate_fs(e, dir, msg, cap, with_form, &fs_real);
}

/*
 * THE HEADER COMMENT in front of a unit's new text (kof_dsrc_head, diagsrc.h): the sample's file name and the digest the properties
 * pane shows for the object (obj_sha256, cached in the object), the host's date today, the engine's numbers.
 *
 * The name is the FILE's (the top-level segment of the object's name, kobj_toplevel_len). A draft with no object writes no sample
 * line. The researcher is not written: this tool has no account name to give (the old generator asked the system for it; that code
 * went with the old editor) and a guess would sign it for somebody. A failure leaves the text as it was.
 */
static void unit_head(struct kof_editor *e, struct kofeditor_unit_out *u)
{
	struct kof_dsrc_meta m;
	char name[256], today[24];
	struct object *ob = e->obj && e->n_obj && e->cur < *e->n_obj ? &e->obj[e->cur] : NULL;
	time_t now = time(NULL);
	struct tm tmv;
	size_t hn = 0;
	char *t;

	memset(&m, 0, sizeof m);
	if (ob) {
		size_t k = kobj_toplevel_len(ob->name);

		snprintf(name, sizeof name, "%.*s", (int)(k < sizeof name - 1u ? k : sizeof name - 1u), ob->name);
		obj_sha256(ob);
		m.name = kof_path_base(name);
		m.sha256 = ob->sha256[0] ? ob->sha256 : NULL;
	}
	if (localtime_r(&now, &tmv) == NULL || !strftime(today, sizeof today, "%Y-%m-%d", &tmv))
		return;
	m.date = today;
	t = kof_dsrc_head(u->text, u->n, &m, NULL, &hn);
	if (!t)
		return;
	free(u->text);
	u->text = t;
	u->n = hn;
}

/*
 * SAVE: ADD and REMOVE by one mechanism, the link (see draft_link_unit). The plan comes first and the disk is not touched until all of
 * it is sound:
 *   a unit with no link is NEW: written to a new file (a file in the tree that already says the same is not written again);
 *   a unit whose link was loaded and whose content still equals its file is UNTOUCHED;
 *   a unit whose link was loaded and whose content is not its file's is MODIFIED: editing a diagnose is not done, so it is reported,
 *     not written (no new duplicate) and its file is not deleted;
 *   a loaded link that no matcher or condition carries any more is REMOVED: its file is deleted - the file must still be the regular
 *     file that was loaded (name and body hash), or the Save refuses.
 * Then the new files are created and the removed ones unlinked; a failure part way puts back every file this call deleted (from the
 * copy kept in memory) and removes every file it created. Returns the number of files written, or -1 on a refusal (msg is the reason).
 */
int draft_generate_fs(struct kof_editor *e, const char *dir, char *msg, size_t cap, int with_form, const struct draft_fs *fs)
{
	struct kofeditor_unit_out *u = NULL;
	struct kof_dsrc *d = NULL, *old = NULL, *cand = NULL;
	struct draft_unit ul[DRAFT_UNIT_MAX];
	struct del_plan dp[DRAFT_LOADED_MAX];
	int present[DRAFT_UNIT_MAX], linked[DRAFT_UNIT_MAX], towrite[DRAFT_UNIT_MAX], gone_link[DRAFT_LOADED_MAX];
	const char *names[DRAFT_UNIT_MAX];
	char delnames[DRAFT_LOADED_MAX][DRAFT_LINK_MAX + 3];
	const char *delp[DRAFT_LOADED_MAX];
	int delflag[DRAFT_LOADED_MAX];
	uint32_t n, k, i, nsame = 0, nmod = 0, nnew = 0, nd = 0, ndel = 0;
	int rc = -1;
	const char *why;

	msg[0] = 0;
	memset(dp, 0, sizeof dp);
	memset(gone_link, 0, sizeof gone_link);
	u = calloc((size_t)MAX_GROUP * 2u + 2u, sizeof *u);
	d = calloc(1, sizeof *d);
	old = calloc(1, sizeof *old);
	cand = calloc(1, sizeof *cand);
	if (!u || !d || !old || !cand) {
		snprintf(msg, cap, "out of memory");
		goto out;
	}
	n = draft_units(e, ul, DRAFT_UNIT_MAX);
	for (k = 0; k < n; k++) {
		kofeditor_unit_name_in(e, dir, ul, k, u);
		if (!ul[k].is_grp) {
			const struct cond *c = &e->dr.cnd[ul[k].idx];

			snprintf(u[k].label, sizeof u[k].label, "condition %u", ul[k].idx + 1u);
			why = kofeditor_draft_unit_gap(e, ul[k].utype, ul[k].tag);
			if (!why && cnd_foreign(e, c))
				why = "it names a matcher that is not on this tab";
		} else {
			snprintf(u[k].label, sizeof u[k].label, "block matcher %u", ul[k].idx + 1u);
			why = kofeditor_draft_unit_gap(e, ul[k].utype, ul[k].tag);
		}
		if (why) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, why);
			goto out;
		}
	}
	{
		struct stat st;

		if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
			snprintf(msg, cap, "Not written: %s is not a directory", dir);
			goto out;
		}
	}
	/* THE LINKS. One diagnose, one carrier: a link two matchers or conditions carry is a draft that cannot say what is removed. */
	for (i = 0; i < e->dr.n_loaded; i++)
		if (kofeditor_link_carriers(e, e->dr.loaded[i].id) > 1u) {
			snprintf(msg, cap, "Not written: two units are linked to %s.c", e->dr.loaded[i].name);
			goto out;
		}
	for (k = 0; k < n; k++) {
		const uint32_t lid = *kofeditor_unit_link_of(e, &ul[k]);
		const char *lk = lid && kofeditor_loaded_find(e, lid) >= 0 ? e->dr.loaded[kofeditor_loaded_find(e, lid)].name : "";
		char *have;
		size_t on = 0;
		mode_t mode;

		linked[k] = 0;
		if (!lk[0])
			continue;
		have = kofeditor_tree_file(dir, lk, &on, &mode);
		if (!have) {
			if (!kofeditor_tree_missing(dir, lk)) {
				snprintf(msg, cap, "Not written: %s.c is not a regular file that can be read", lk);
				goto out;
			}
			/* The file is gone: nothing to modify and nothing to delete; the unit is new. */
			gone_link[kofeditor_loaded_find(e, lid)] = 1;
			continue;
		}
		linked[k] = kofeditor_unit_in_file(e, lk, ul, k, have, on, with_form, d, old, cand, NULL) ? 1 : 2;
		free(have);
		snprintf(u[k].fn, sizeof u[k].fn, "%s.c", lk);
		nmod += linked[k] == 2;
		nsame += linked[k] == 1;
	}
	/* A loaded link that nothing carries is a removal; one that a matcher carries which is no unit (its kind was changed) is a modification. */
	for (i = 0; i < e->dr.n_loaded; i++) {
		const char *nm = e->dr.loaded[i].name;
		uint32_t units = 0, carried = kofeditor_link_carriers(e, e->dr.loaded[i].id);

		if (gone_link[i])
			continue;
		for (k = 0; k < n; k++)
			units += *kofeditor_unit_link_of(e, &ul[k]) == e->dr.loaded[i].id;
		if (carried > units) {
			nmod++;
			continue;
		}
		if (carried)
			continue;
		{
			size_t on = 0;
			mode_t mode;
			uint64_t h = 0;
			char *have = kofeditor_tree_file(dir, nm, &on, &mode);

			if (!have) {
				if (!kofeditor_tree_missing(dir, nm)) {
					snprintf(msg, cap, "Not written: %s.c is not a regular file that can be read, so it is not deleted", nm);
					goto out;
				}
				gone_link[i] = 1;
				continue;
			}
			if (!kofeditor_text_identity(have, on, nm, d, &h) || h != e->dr.loaded[i].hash) {
				snprintf(msg, cap, "Not written: %s.c is not the diagnose that was loaded (it changed), so it is not deleted", nm);
				free(have);
				goto out;
			}
			dp[nd].id = e->dr.loaded[i].id;
			snprintf(dp[nd].name, sizeof dp[nd].name, "%s", nm);
			dp[nd].bytes = have;
			dp[nd].n = on;
			dp[nd].mode = mode;
			nd++;
		}
	}
	if (!n && !nd && !nmod) {
		snprintf(msg, cap, "Nothing to write: add a condition or a block matcher first");
		goto out;
	}
	for (k = 0; k < n; k++) {
		char bad[260];
		size_t len = strlen(u[k].fn);

		present[k] = 0;
		if (linked[k])
			continue;
		if (len < 3u || len - 2u >= KOF_DSRC_NAME_LEN) {
			snprintf(msg, cap, "Not written: the name %s is too long for a diagnose", u[k].fn);
			goto out;
		}
		if (kofeditor_unit_resolve(e, dir, ul, k, u, with_form, d, old, cand, &present[k], bad, sizeof bad) < 0) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, bad);
			goto out;
		}
		nsame += present[k] != 0;
		/* A unit added again that says what a file to be deleted says IS that diagnose: the file stays, and the unit takes its link. */
		for (i = 0; present[k] && i < nd; i++) {
			char fn[DRAFT_LINK_MAX + 3];

			snprintf(fn, sizeof fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
			dp[i].keep |= !strcmp(fn, u[k].fn);
		}
	}
	/* The text of every file, before the first is created. */
	for (k = 0; k < n; k++) {
		char stem[200], bad[260];

		towrite[k] = !linked[k] && !present[k];
		if (!towrite[k])
			continue;
		snprintf(stem, sizeof stem, "%s", u[k].fn);
		stem[strlen(stem) - 2u] = 0;
		u[k].text = kofeditor_unit_text(e, stem, &ul[k], d, &u[k].n, with_form, bad, sizeof bad);
		if (!u[k].text) {
			snprintf(msg, cap, "Not written: %s %s", u[k].label, bad);
			goto out;
		}
		/* kofeditor_unit_in_file compares what the draft says (a form read back ignores comments); the catalog-only seam (with_form 0) compares bytes and writes none. */
		if (with_form)
			unit_head(e, &u[k]);
		nnew++;
	}
	for (k = 0; k < n; k++) {
		char path[4400];
		FILE *f;

		if (!towrite[k])
			continue;
		snprintf(path, sizeof path, "%s/%s", dir, u[k].fn);
		f = fs->create(fs->ud, path);
		if (!f || fwrite(u[k].text, 1, u[k].n, f) != u[k].n) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot create %s in %s", u[k].fn, dir);
			/* Only a file this call created is removed: "wx" failing means somebody else's. */
			if (f) {
				fclose(f);
				(void)remove(path);
			}
			for (z = 0; z < k; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
		if (fclose(f) != 0) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot finish %s in %s", u[k].fn, dir);
			for (z = 0; z <= k; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
	}
	for (i = 0; i < nd; i++) {
		char path[4400];
		struct stat st;

		if (dp[i].keep)
			continue;
		snprintf(path, sizeof path, "%s/%s.c", dir, dp[i].name);
		/* The exact file, and only if it is still a regular file (not a link put there since the plan). */
		if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || fs->unlink(fs->ud, path) != 0) {
			uint32_t z;

			snprintf(msg, cap, "Not written: cannot delete %s.c from %s; nothing was changed", dp[i].name, dir);
			put_back(dir, dp, nd, msg, cap);
			for (z = 0; z < n; z++) {
				if (!towrite[z])
					continue;
				snprintf(path, sizeof path, "%s/%s", dir, u[z].fn);
				(void)remove(path);
			}
			goto out;
		}
		dp[i].gone = 1;
		ndel++;
	}
	/* Done: the draft's own record follows the disk. */
	for (k = 0; k < n; k++) {
		uint32_t *lk = kofeditor_unit_link_of(e, &ul[k]);

		if (!linked[k] && *lk)
			*lk = 0;                       /* its file was gone: a new unit now */
		for (i = 0; present[k] && i < nd; i++) {
			char fn[DRAFT_LINK_MAX + 3];

			snprintf(fn, sizeof fn, "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
			if (dp[i].keep && !strcmp(u[k].fn, fn))
				*lk = dp[i].id;
		}
	}
	for (i = e->dr.n_loaded; i-- > 0; ) {
		int drop = gone_link[i];
		uint32_t z;

		for (z = 0; z < nd; z++)
			drop |= dp[z].gone && dp[z].id == e->dr.loaded[i].id;
		if (drop) {
			memmove(&e->dr.loaded[i], &e->dr.loaded[i + 1u], (e->dr.n_loaded - i - 1u) * sizeof e->dr.loaded[0]);
			e->dr.n_loaded--;
		}
	}
	/* A unit just written IS a loaded diagnose from now on: it takes the id the engine derives for its name (kof_diag_id32_, the engine's own
	 * function), so that taking it out later deletes the file written here and a second Save does not see it as new. */
	for (k = 0; k < n; k++) {
		char stem[DRAFT_LINK_MAX];
		uint64_t h = 0;
		uint32_t nid;

		if (!towrite[k] || strlen(u[k].fn) - 2u >= DRAFT_LINK_MAX)
			continue;
		snprintf(stem, sizeof stem, "%.*s", (int)strlen(u[k].fn) - 2, u[k].fn);
		nid = kof_diag_id32_(stem);
		if (!nid || e->dr.n_loaded >= DRAFT_LOADED_MAX || kofeditor_loaded_find(e, nid) >= 0 || kofeditor_link_carriers(e, nid) || *kofeditor_unit_link_of(e, &ul[k]) ||
		    !kofeditor_text_identity(u[k].text, u[k].n, stem, d, &h))
			continue;
		*kofeditor_unit_link_of(e, &ul[k]) = nid;
		e->dr.loaded[e->dr.n_loaded].id = nid;
		snprintf(e->dr.loaded[e->dr.n_loaded].name, sizeof e->dr.loaded[0].name, "%s", stem);
		e->dr.loaded[e->dr.n_loaded++].hash = h;
	}
	for (k = 0; k < n; k++)
		names[k] = u[k].fn;
	for (i = 0; i < nd; i++) {
		snprintf(delnames[i], sizeof delnames[i], "%.*s.c", (int)DRAFT_LINK_MAX - 1, dp[i].name);
		delp[i] = delnames[i];
		delflag[i] = dp[i].gone;
	}
	if (!nnew && !ndel && !nmod) {
		snprintf(msg, cap, "Nothing new to write: the %u diagnose%s already in %s say%s the same", n, n == 1u ? "" : "s", dir, n == 1u ? "s" : "");
	} else {
		if (nnew) {
			snprintf(msg, cap, "Wrote %u file%s to %s:", nnew, nnew == 1u ? "" : "s", dir);
			say_names(msg, cap, names, towrite, n);
			if (nsame)
				say_add(msg, cap, " (%u already there, unchanged)", nsame);
		} else if (nsame) {
			snprintf(msg, cap, "%u unchanged", nsame);
		}
		if (ndel) {
			say_add(msg, cap, "%sDeleted %u file%s from %s:", msg[0] ? "; " : "", ndel, ndel == 1u ? "" : "s", dir);
			say_names(msg, cap, delp, delflag, nd);
		}
		if (nmod)
			say_add(msg, cap, "%s%u modified diagnose%s not saved: editing is not done", msg[0] ? "; " : "", nmod, nmod == 1u ? "" : "s");
	}
	rc = (int)nnew;
out:
	if (u)
		for (k = 0; k < (uint32_t)MAX_GROUP * 2u + 2u; k++)
			free(u[k].text);
	for (i = 0; i < DRAFT_LOADED_MAX; i++)
		free(dp[i].bytes);
	free(u);
	free(d);
	free(old);
	free(cand);
	return rc;
}
