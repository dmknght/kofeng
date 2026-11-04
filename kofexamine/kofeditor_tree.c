#define _GNU_SOURCE

/*
 * kofeditor_tree.c - reading the tree a draft is saved into: the text of a unit file, its identity, and the check that a name may be a link.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"


/* What the reader said first about a text it was given: the writer reads its own output back. */
struct first_err {
	char msg[200];
	int  line;
	int  n;
};

static void first_err_cb(void *ud, int line, const char *m)
{
	struct first_err *f = ud;

	if (!f->n++) {
		snprintf(f->msg, sizeof f->msg, "%s", m);
		f->line = line;
	}
}

/*
 * THE TEXT OF ONE UNIT'S FILE: the catalog lines and, with `with_form`, its detection declarations; then the text is READ
 * BACK by the reader the builder uses (parse and resolve) and a file that would not build is a refusal here, naming the
 * line - Generate never writes a source ksigbuilder would reject for what the panel said. `with_form` 0 is the seam the
 * writer's own tests use (names, running ids, all-or-nothing): the catalog lines alone, nothing read back. Returns the text
 * (malloc'd) or NULL with `why` set.
 */
char *kofeditor_unit_text(const struct kof_editor *e, const char *stem, const struct draft_unit *u, struct kof_dsrc *d,
		       size_t *n, int with_form, char *why, size_t cap)
{
	char *text;
	uint32_t q;

	draft_unit_items(e, stem, u->utype, u->tag, d);
	if (with_form) {
		const char *r = draft_unit_form(e, u->is_grp, u->idx, d);

		if (r) {
			snprintf(why, cap, "%s", r);
			return NULL;
		}
		for (q = 0; q < d->n; q++) {
			char one[8192];

			if (!kof_dsrc_print(&d->item[q], one, sizeof one)) {
				snprintf(why, cap, "one of its declarations cannot be written as source");
				return NULL;
			}
		}
	}
	text = kof_dsrc_patch("", 0, d, n);
	if (!text) {
		snprintf(why, cap, "out of memory");
		return NULL;
	}
	if (with_form) {
		struct kof_dsrc *back = calloc(1, sizeof *back);
		struct kof_dsrc_view v;
		struct first_err fe = { "", 0, 0 };
		const struct kof_dsrc_report rep = { first_err_cb, NULL, &fe };

		if (!back) {
			free(text);
			snprintf(why, cap, "out of memory");
			return NULL;
		}
		(void)kof_dsrc_parse(text, *n, back, &rep);
		if (!fe.n)
			(void)kof_dsrc_resolve(back, &v, &rep);
		else
			memset(&v, 0, sizeof v);
		kof_dsrc_view_free(&v);
		free(back);
		if (fe.n) {
			snprintf(why, cap, "the source it would write does not read: %s (line %d)", fe.msg, fe.line);
			free(text);
			return NULL;
		}
	}
	return text;
}

/* The bytes of a file, malloc'd (NUL added); NULL when it cannot be read whole. */
static char *file_bytes(FILE *f, size_t *n)
{
	char *p = NULL;
	size_t cap = 0, len = 0, got;

	for (;;) {
		char *q;

		if (len + 4097u > cap) {
			cap = cap ? cap * 2u : 8192u;
			q = realloc(p, cap);
			if (!q) {
				free(p);
				return NULL;
			}
			p = q;
		}
		got = fread(p + len, 1, 4096u, f);
		len += got;
		if (got < 4096u)
			break;
	}
	if (ferror(f)) {
		free(p);
		return NULL;
	}
	p[len] = 0;
	*n = len;
	return p;
}

/* Whether the diagnose already in `have` (its file `stem`.c, `on` bytes) says what unit k of the draft would write: both are read and
 * resolved by the builder's reader and compared by the builder's own identity (kof_dsrc_view_same: family, variant, type, tag and what it
 * looks for - the local labels of blocks and matchers, comments and spacing do not count); with `with_form` 0 the bytes are compared.
 * `id`, when given, receives the file's name and kof_dsrc_view_body_hash (only a with_form comparison reads it; else it is left alone). */
int kofeditor_unit_in_file(const struct kof_editor *e, const char *stem, const struct draft_unit *ul, uint32_t k, const char *have, size_t on,
			int with_form, struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, struct draft_loaded *id)
{
	size_t cn = 0;
	char *want;
	char bad[260];
	int same = 0;

	want = kofeditor_unit_text(e, stem, &ul[k], d, &cn, with_form, bad, sizeof bad);
	if (!want)
		return 0;
	if (!with_form) {
		same = on == cn && !memcmp(have, want, cn);
	} else {
		struct first_err fo = { "", 0, 0 }, fc = { "", 0, 0 };
		const struct kof_dsrc_report ro = { first_err_cb, NULL, &fo }, rc = { first_err_cb, NULL, &fc };
		struct kof_dsrc_view vo, vc;

		memset(&vo, 0, sizeof vo);
		memset(&vc, 0, sizeof vc);
		(void)kof_dsrc_parse(have, on, old, &ro);
		(void)kof_dsrc_parse(want, cn, cand, &rc);
		if (!fo.n && !fc.n) {
			(void)kof_dsrc_resolve(old, &vo, &ro);
			(void)kof_dsrc_resolve(cand, &vc, &rc);
			same = !fo.n && !fc.n && kof_dsrc_view_same(&vo, &vc);
			if (same && id) {
				snprintf(id->name, sizeof id->name, "%s", vo.name);
				id->hash = kof_dsrc_view_body_hash(&vo);
			}
		}
		kof_dsrc_view_free(&vo);
		kof_dsrc_view_free(&vc);
	}
	free(want);
	return same;
}

/*
 * WHERE UNIT k GOES in `dir`, which is a question about the files that are already there and not only about the draft: the running id
 * of a name counts the draft's own units, so a new unit of a type, family and tag that the tree already has would name a file that exists.
 * A diagnose in the tree that says the same as the unit IS the unit (`*present`: nothing to write, the file is named); otherwise the unit
 * takes the first `<prefix>_NN.c` that is free in `dir` and among the units before it. A file is still never replaced. 0, or -1 with `why`.
 *
 * THE DIRECTORY IS READ AS IT IS BEFORE THIS SAVE: a file this Save is about to delete is still there, so its number is taken and a new
 * unit never gets the name of a file removed in the same call (a number comes back only in a later Save, when the file is really gone).
 */
int kofeditor_unit_resolve(const struct kof_editor *e, const char *dir, const struct draft_unit *ul, uint32_t k, struct kofeditor_unit_out *u, int with_form,
			struct kof_dsrc *d, struct kof_dsrc *old, struct kof_dsrc *cand, int *present, char *why, size_t cap)
{
	char prefix[160], fn[200], path[4400];
	uint32_t nn;

	*present = 0;
	kofeditor_tag_prefix(e, ul[k].utype, ul[k].tag, prefix, sizeof prefix);
	for (nn = 1; nn <= 99u; nn++) {
		FILE *f;
		char stem[200];
		int same = 0;
		size_t on = 0;
		char *have;

		snprintf(fn, sizeof fn, "%s_%02u.c", prefix, nn);
		snprintf(path, sizeof path, "%s/%s", dir, fn);
		f = fopen(path, "rb");
		if (!f)
			continue;
		have = file_bytes(f, &on);
		snprintf(stem, sizeof stem, "%s", fn);
		stem[strlen(stem) - 2u] = 0;
		if (have)
			same = kofeditor_unit_in_file(e, stem, ul, k, have, on, with_form, d, old, cand, NULL);
		free(have);
		fclose(f);
		if (same) {
			snprintf(u[k].fn, sizeof u[k].fn, "%s", fn);
			*present = 1;
			return 0;
		}
	}
	nn = kofeditor_unit_free_number(dir, prefix, u, k);
	if (!nn) {
		snprintf(why, cap, "has no free number: 01 to 99 are taken in %s", dir);
		return -1;
	}
	snprintf(u[k].fn, sizeof u[k].fn, "%s_%02u.c", prefix, nn);
	return 0;
}

/* ---- THE LINK between a unit and the diagnose it was loaded from ------------------------------------------------------ */

/* A link is a diagnose name used as a file stem in the tree: letters, digits, '_' and '-' only, so it cannot hold a path, a dot or a NUL. */
int kofeditor_link_name_ok(const char *n)
{
	size_t i, len = n ? strlen(n) : 0;

	if (!len || len >= DRAFT_LINK_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if (!isalnum((unsigned char)n[i]) && n[i] != '_' && n[i] != '-')
			return 0;
	return 1;
}

/* The regular file `dir`/`name`.c, read whole (malloc'd, NUL added) with its mode: NULL for a missing file, a symlink, a directory, anything
 * else that is not a regular file, or one over 1 MiB. O_NOFOLLOW as well as lstat, so a link swapped in between is refused too. */
char *kofeditor_tree_file(const char *dir, const char *name, size_t *n, mode_t *mode)
{
	char path[4400];
	struct stat st;
	FILE *f;
	char *b;
	int fd;

	if (!kofeditor_link_name_ok(name) || snprintf(path, sizeof path, "%s/%s.c", dir, name) >= (int)sizeof path)
		return NULL;
	if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (off_t)(1 << 20))
		return NULL;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	f = fdopen(fd, "rb");
	if (!f) {
		close(fd);
		return NULL;
	}
	b = file_bytes(f, n);
	fclose(f);
	*mode = st.st_mode & 07777u;
	return b;
}

/* Whether `dir`/`name`.c is simply not there (ENOENT): the one reason a file of a link may be left out of a Save quietly. Any other file that
 * cannot be read as a regular file (a symlink, a directory, too big, unreadable) is something to refuse about, not to skip. */
int kofeditor_tree_missing(const char *dir, const char *name)
{
	char path[4400];
	struct stat st;

	return kofeditor_link_name_ok(name) && snprintf(path, sizeof path, "%s/%s.c", dir, name) < (int)sizeof path && lstat(path, &st) != 0 && errno == ENOENT;
}

/* The identity of a diagnose source: it reads and resolves, and its own name is `name`. 1 and the body hash, or 0. */
int kofeditor_text_identity(const char *text, size_t n, const char *name, struct kof_dsrc *d, uint64_t *hash)
{
	struct first_err fe = { "", 0, 0 };
	const struct kof_dsrc_report rep = { first_err_cb, NULL, &fe };
	struct kof_dsrc_view v;
	int ok;

	memset(&v, 0, sizeof v);
	(void)kof_dsrc_parse(text, n, d, &rep);
	if (!fe.n)
		(void)kof_dsrc_resolve(d, &v, &rep);
	ok = !fe.n && !strcmp(v.name, name);
	if (ok)
		*hash = kof_dsrc_view_body_hash(&v);
	kof_dsrc_view_free(&v);
	return ok;
}
