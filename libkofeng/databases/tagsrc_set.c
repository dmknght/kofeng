/*
 * SWITCHED OFF (owner, 2026-10-27): the Syndrome table and its tag-source backend (kofexamine/kv_syn.c, kv_syntable.c,
 * libkofeng/databases/tagsrc*, ksigbuilder/ksb_tags.c) stay in the tree and are to be removed later, when asked. The menu item
 * is Manage > Syndromes, listed and greyed. Do not extend this code.
 */
/*
 * tagsrc_set.c - the directory of tag sources as one set: load, find, add,
 * remove, count and save. See tagsrc.h.
 */

#define _GNU_SOURCE
#ifdef _WIN32
#define _CRT_RAND_S
#endif
#include "tagsrc_int.h"
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofplatform_file.h"
#include <dirent.h>
#include <sys/stat.h>

#define ID_TRIES 64u
/* A diagnose source is read to count the tags it names; one past this is not
 * a diagnose and its tags are not counted. */
#define DIAG_READ_MAX (4u * 1024u * 1024u)

void kof_tagset_init(struct kof_tagset *s)
{
	memset(s, 0, sizeof *s);
}

void kof_tagset_free(struct kof_tagset *s)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		free(s->e[i].text);
	free(s->e);
	free(s->prob);
	memset(s, 0, sizeof *s);
}

/* ---- problems ----------------------------------------------------------- */

static void prob_add(struct kof_tagset *s, const char *file, const char *msg)
{
	struct kof_tagprob *p;

	if (s->n_prob == s->cap_prob) {
		size_t nc = s->cap_prob ? s->cap_prob * 2u : 8u;
		struct kof_tagprob *g = realloc(s->prob, nc * sizeof *g);

		if (!g)
			return;
		s->prob = g;
		s->cap_prob = nc;
	}
	p = &s->prob[s->n_prob++];
	snprintf(p->file, sizeof p->file, "%s", file);
	snprintf(p->msg, sizeof p->msg, "%s", msg);
}

struct load_cx {
	struct kof_tagset *s;
	const char        *file;
};

static void load_error(void *ud, int line, const char *msg)
{
	struct load_cx *x = ud;
	char m[160];

	if (line > 0)
		snprintf(m, sizeof m, "line %d: %s", line, msg);
	else
		snprintf(m, sizeof m, "%s", msg);
	prob_add(x->s, x->file, m);
}

/* ---- entities ------------------------------------------------------------ */

static struct kof_tagent *grow(struct kof_tagset *s)
{
	if (s->n == s->cap) {
		size_t nc = s->cap ? s->cap * 2u : 32u;
		struct kof_tagent *g = realloc(s->e, nc * sizeof *g);

		if (!g)
			return NULL;
		s->e = g;
		s->cap = nc;
	}
	memset(&s->e[s->n], 0, sizeof s->e[0]);
	return &s->e[s->n++];
}

struct kof_tagent *kof_tagset_find(const struct kof_tagset *s, unsigned kind,
				   uint64_t id)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		if (!s->e[i].removed && s->e[i].id == id &&
		    (!kind || s->e[i].kind == kind))
			return &s->e[i];
	return NULL;
}

const char *kof_tagset_name(const struct kof_tagset *s, unsigned kind,
			    uint64_t id)
{
	const struct kof_tagent *e = kof_tagset_find(s, kind, id);

	return e ? e->name : NULL;
}

size_t kof_tagset_join(const struct kof_tagset *s, unsigned kind,
		       const uint64_t *ids, uint32_t n, char *out, size_t cap)
{
	size_t at = 0;
	uint32_t i;

	if (!cap)
		return 0;
	out[0] = 0;
	for (i = 0; i < n && at + 1u < cap; i++) {
		const char *nm = kof_tagset_name(s, kind, ids[i]);
		int w = snprintf(out + at, cap - at, "%s%s", i ? ", " : "",
				 nm ? nm : "?");

		if (w < 0)
			break;
		at = at + (size_t)w < cap ? at + (size_t)w : cap - 1u;
	}
	return at;
}

/* A file's bytes, at most `max` and one past it to say it was longer. */
static char *read_capped(const char *path, size_t max, size_t *n, int *big)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	size_t got;

	*big = 0;
	if (!f)
		return NULL;
	buf = malloc(max + 2u);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, max + 1u, f);
	fclose(f);
	if (got > max) {
		*big = 1;
		free(buf);
		return NULL;
	}
	buf[got] = 0;
	*n = got;
	return buf;
}

static int name_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

/* The `*.c` names of a directory, sorted: nothing depends on readdir order. */
static char **list_c(const char *dir, size_t *n_out)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char **v = NULL;
	size_t n = 0, cap = 0;

	*n_out = 0;
	if (!d)
		return NULL;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char *c;

		if (de->d_name[0] == '.' || l < 3u ||
		    strcmp(de->d_name + l - 2u, ".c") != 0)
			continue;
		if (n == cap) {
			char **g = realloc(v, (cap ? cap * 2u : 32u) * sizeof *g);

			if (!g)
				break;
			v = g;
			cap = cap ? cap * 2u : 32u;
		}
		c = malloc(l + 1u);
		if (!c)
			break;
		memcpy(c, de->d_name, l + 1u);
		v[n++] = c;
	}
	closedir(d);
	if (n)
		qsort(v, n, sizeof *v, name_cmp);
	*n_out = n;
	return v;
}

static void free_names(char **v, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

/* One file into the set, or into the problem list. */
static void load_one(struct kof_tagset *s, const char *name)
{
	char path[KOF_TAGSRC_PATH];
	struct load_cx cx;
	struct kof_dsrc_report rep;
	struct kof_dsrc *d = NULL;
	struct kof_tagent *e;
	char *text;
	size_t n = 0;
	int big = 0, errs;

	cx.s = s;
	cx.file = name;
	rep.error = load_error;
	rep.warn = NULL;
	rep.ud = &cx;
	if (snprintf(path, sizeof path, "%s/%s", s->dir, name) >=
	    (int)sizeof path) {
		prob_add(s, name, "path too long");
		return;
	}
	text = read_capped(path, KOF_TAGSRC_FILE_MAX, &n, &big);
	if (!text) {
		prob_add(s, name, big ? "file larger than 65536 bytes: "
					"refused, not read"
				      : "cannot be read");
		return;
	}
	d = calloc(1, sizeof *d);
	e = d ? grow(s) : NULL;
	if (!e) {
		prob_add(s, name, "out of memory");
		free(d);
		free(text);
		return;
	}
	errs = kof_tagsrc_parse(text, n, d, &rep);
	if (!errs)
		errs = kof_tagsrc_entity(d, e, &rep);
	if (errs) {
		s->n--;                         /* not an entity: a problem */
		free(d);
		free(text);
		return;
	}
	snprintf(e->path, sizeof e->path, "%s", path);
	e->text = text;
	e->text_n = n;
	free(d);
}

int kof_tagset_load(struct kof_tagset *s, const char *dir)
{
	size_t n, i;
	char **names;

	kof_tagset_free(s);
	kof_tagset_init(s);
	snprintf(s->dir, sizeof s->dir, "%s", dir);
	names = list_c(dir, &n);
	if (!names && !n) {
		DIR *d = opendir(dir);

		if (!d)
			return 0;
		closedir(d);
	}
	for (i = 0; i < n; i++)
		load_one(s, names[i]);
	free_names(names, n);
	return 1;
}

/* ---- ids ------------------------------------------------------------------ */

static uint64_t os_rand(void *ud)
{
	uint64_t v = 0;
#ifdef _WIN32
	unsigned a = 0, b = 0;

	(void)ud;
	rand_s(&a);
	rand_s(&b);
	v = ((uint64_t)a << 32) | b;
#else
	FILE *f = fopen("/dev/urandom", "rb");

	(void)ud;
	if (f) {
		if (fread(&v, sizeof v, 1, f) != 1)
			v = 0;
		fclose(f);
	}
#endif
	return v;
}

int kof_tagset_new_id(const struct kof_tagset *s,
		      uint64_t (*gen)(void *ud), void *ud, uint64_t *out)
{
	unsigned t;
	size_t i;

	if (!gen)
		gen = os_rand;
	for (t = 0; t < ID_TRIES; t++) {
		uint64_t id = gen(ud);
		int taken = id < KOF_TAGSRC_ID_SEED_MAX;

		/* Removed ones count too: their file is still on disk. */
		for (i = 0; i < s->n && !taken; i++)
			taken = s->e[i].id == id;
		if (!taken) {
			*out = id;
			return 1;
		}
	}
	return 0;
}

static int path_taken(const struct kof_tagset *s, const char *path)
{
	struct stat st;
	size_t i;

	for (i = 0; i < s->n; i++)
		if (!strcmp(s->e[i].path, path))
			return 1;
	return stat(path, &st) == 0;
}

struct kof_tagent *kof_tagset_add(struct kof_tagset *s,
				  const struct kof_tagent *proto,
				  uint64_t (*gen)(void *ud), void *ud,
				  const char **why)
{
	struct kof_tagent *e;
	unsigned t;
	const char *dummy;

	if (!why)
		why = &dummy;
	*why = NULL;
	if (proto->kind <= KOF_TAGSRC_K_NONE ||
	    proto->kind >= KOF_TAGSRC_K_COUNT) {
		*why = "not a kind of entity";
		return NULL;
	}
	if (!kof_tagsrc_name_ok(proto->name)) {
		*why = "the name is empty or has bad characters";
		return NULL;
	}
	for (t = 0; t < ID_TRIES; t++) {
		struct kof_tagent n;
		char file[160], path[KOF_TAGSRC_PATH];
		uint64_t id;

		if (!kof_tagset_new_id(s, gen, ud, &id)) {
			*why = "no free id: the generator kept answering "
			       "ids that exist";
			return NULL;
		}
		n = *proto;
		n.id = id;
		kof_tagsrc_file_name(&n, file, sizeof file);
		if (snprintf(path, sizeof path, "%s/%s", s->dir, file) >=
		    (int)sizeof path) {
			*why = "path too long";
			return NULL;
		}
		if (path_taken(s, path))
			continue;       /* another entity's file: a new id */
		if (!(e = grow(s))) {
			*why = "out of memory";
			return NULL;
		}
		*e = n;
		e->text = NULL;
		e->text_n = 0;
		e->fresh = e->dirty = 1;
		e->removed = 0;
		e->used = 0;
		snprintf(e->path, sizeof e->path, "%s", path);
		return e;
	}
	*why = "every id tried names a file that exists";
	return NULL;
}

void kof_tagset_remove(struct kof_tagset *s, struct kof_tagent *e)
{
	size_t i = (size_t)(e - s->e);

	if (i >= s->n)
		return;
	if (!e->fresh) {
		e->removed = 1;
		e->dirty = 1;
		return;
	}
	free(e->text);
	memmove(e, e + 1, (s->n - i - 1u) * sizeof *e);
	s->n--;
}

/* ---- who names whom -------------------------------------------------------- */

static int names(const struct kof_tagent *tag, const struct kof_tagent *e)
{
	uint32_t i;

	if (tag->removed || tag->kind != KOF_TAGSRC_K_TAG)
		return 0;
	switch (e->kind) {
	case KOF_TAGSRC_K_ACTIVITY:
		for (i = 0; i < tag->n_act; i++)
			if (tag->act[i] == e->id)
				return 1;
		return 0;
	case KOF_TAGSRC_K_TYPE:
		for (i = 0; i < tag->n_typ; i++)
			if (tag->typ[i] == e->id)
				return 1;
		return 0;
	case KOF_TAGSRC_K_FAMILY:
		return tag->has_fam && tag->fam == e->id;
	default:
		return 0;
	}
}

size_t kof_tagset_refs(const struct kof_tagset *s, const struct kof_tagent *e,
		       const struct kof_tagent **out, size_t cap)
{
	size_t i, n = 0;

	for (i = 0; i < s->n; i++)
		if (names(&s->e[i], e)) {
			if (out && n < cap)
				out[n] = &s->e[i];
			n++;
		}
	return n;
}

void kof_tagset_count(struct kof_tagset *s)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		if (s->e[i].kind != KOF_TAGSRC_K_TAG)
			s->e[i].used = (uint32_t)kof_tagset_refs(s, &s->e[i],
								  NULL, 0);
}

/* A KOF_DIAG_TAG(<id>) call in a diagnose source: one more use of the tag. */
static void diag_uses(struct kof_tagset *s, const char *code)
{
	static const char macro[] = "KOF_DIAG_TAG";
	const char *p = code;

	while ((p = strstr(p, macro)) != NULL) {
		char a[40];
		int ok = (p == code || !(isalnum((unsigned char)p[-1]) ||
					 p[-1] == '_')) &&
			 p[sizeof macro - 1u] == '(';

		p += sizeof macro - 1u;
		if (ok && kof_dsrc_arg(p, 0, a, sizeof a)) {
			char *end = NULL;
			unsigned long long id = strtoull(a, &end, 0);
			struct kof_tagent *t;

			if (end && !*end &&
			    (t = kof_tagset_find(s, KOF_TAGSRC_K_TAG, id)))
				t->used++;
		}
	}
}

void kof_tagset_count_diagnoses(struct kof_tagset *s, const char *dir)
{
	size_t i, n;
	char **v;

	for (i = 0; i < s->n; i++)
		if (s->e[i].kind == KOF_TAGSRC_K_TAG)
			s->e[i].used = 0;
	if (!dir || !dir[0] || !(v = list_c(dir, &n)))
		return;
	for (i = 0; i < n; i++) {
		char path[KOF_TAGSRC_PATH];
		size_t len = 0;
		int big = 0;
		char *text;

		if (snprintf(path, sizeof path, "%s/%s", dir, v[i]) >=
		    (int)sizeof path)
			continue;
		text = read_capped(path, DIAG_READ_MAX, &len, &big);
		if (!text)
			continue;
		kof_dsrc_blank_comments(text, len);
		diag_uses(s, text);
		free(text);
	}
	free_names(v, n);
}

/* ---- save ------------------------------------------------------------------ */

static int save_fail(char *why, size_t cap, const char *what,
		     const struct kof_tagent *e)
{
	if (why && cap)
		snprintf(why, cap, "%s %s", what, e->path);
	return -1;
}

int kof_tagset_save(struct kof_tagset *s, char *why, size_t why_cap)
{
	size_t i, out = 0;
	struct stat st;

	if (why && why_cap)
		why[0] = 0;
	for (i = 0; i < s->n; i++) {
		struct kof_tagent *e = &s->e[i];
		char *text;
		size_t n = 0;

		if (!e->dirty)
			continue;
		if (e->removed) {
			if (remove(e->path) != 0 && stat(e->path, &st) == 0)
				return save_fail(why, why_cap,
						 "cannot remove", e);
			out++;
			continue;
		}
		if (e->fresh) {
			if (stat(e->path, &st) == 0)
				return save_fail(why, why_cap, "a file named "
						 "like this exists, not "
						 "overwritten:", e);
			(void)kof_mkdir(s->dir, 0777);
			text = kof_tagsrc_new(e, s, &n);
		} else {
			text = kof_tagsrc_patch(e->text, e->text_n, e, s, &n);
		}
		if (!text)
			return save_fail(why, why_cap, "cannot be written:", e);
		if (!kof_write_file_atomic(e->path, text, n)) {
			free(text);
			return save_fail(why, why_cap, "cannot write", e);
		}
		free(e->text);
		e->text = text;
		e->text_n = n;
		e->dirty = e->fresh = 0;
		out++;
	}
	/* What was removed is gone from disk: out of the set as well. */
	for (i = 0; i < s->n;) {
		if (s->e[i].removed) {
			free(s->e[i].text);
			memmove(&s->e[i], &s->e[i + 1u],
				(s->n - i - 1u) * sizeof s->e[0]);
			s->n--;
		} else {
			i++;
		}
	}
	return (int)out;
}
