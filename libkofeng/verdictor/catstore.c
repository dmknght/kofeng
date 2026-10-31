#define _GNU_SOURCE

/*
 * catstore.c - the id function and the directory of source files the two catalogs share (famcat_store.c, tagcat_store.c). The contract is
 * catstore.h. NOT a loader for hostile input in depth: a small line reader with named bounds; an unknown line is counted, never
 * trusted.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../kofcore/kofmod/kofname.h"   /* kof_comment_char */
#include "../kofcore/kofplatform.h"
#include "../kofcore/kofplatform_file.h"
#include "catstore.h"

/* ---- ids: a function of the name ---------------------------------------------------------------------------------------- */

/* FNV-1a over the key, then the murmur3 finaliser: FNV alone leaves the low bits of a short key weak, and the id is compared whole. */
uint64_t kof_catid_hash(void *ud, const char *key, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ud;
	for (i = 0; i < len; i++)
		h = (h ^ (uint8_t)key[i]) * 0x100000001b3ull;
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdull;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ull;
	h ^= h >> 33;
	return h;
}

int kof_catid_valid(uint64_t id)
{
	return id >= KOF_CATID_SEED_MAX;
}

/* Append `s` lower-cased (ASCII; a name is letters, digits, '-' and '_') to key[cap]; 0 when it does not fit. */
static int key_put(char *key, size_t cap, size_t *at, const char *s)
{
	for (; *s; s++) {
		if (*at + 1u >= cap)
			return 0;
		key[(*at)++] = *s >= 'A' && *s <= 'Z' ? (char)(*s + 32) : *s;
	}
	return 1;
}

uint64_t kof_catid_of(kof_catid_hash_fn fn, void *ud, char kind, const char *a, const char *b)
{
	char key[2u * (KOF_NAME_MAX + 2u) + 4u];
	size_t at = 0u;
	uint64_t id;

	if (!a || !a[0] || (b && !b[0]) || (kind == 'V') != (b != NULL))
		return 0u;
	key[at++] = kind;
	key[at++] = ':';
	if (!key_put(key, sizeof key, &at, a) || (b && (!key_put(key, sizeof key, &at, ".") || !key_put(key, sizeof key, &at, b))))
		return 0u;
	id = (fn ? fn : kof_catid_hash)(ud, key, at);
	/* A hash inside the reserved range is moved out of it by a fixed rule (never by chance, never by retry), so the same name makes
	 * the same id on every machine; the top bit set puts the result above KOF_CATID_SEED_MAX. A second name that lands on the same
	 * number is a collision like any other and is refused by the catalog. */
	if (!kof_catid_valid(id)) {
		id = (id + 0x9e3779b97f4a7c15ull) * 0xff51afd7ed558ccdull;
		id |= 0x8000000000000000ull;
	}
	return id;
}

/* ---- the text of a file ----------------------------------------------------------------------------------------------- */

const char *kof_catfmt_lit(const char *p, char *out, size_t cap)
{
	size_t n = 0;

	if (*p != '"')
		return NULL;
	for (p++; *p && *p != '"'; p++) {
		if (*p == '\\' || n + 1u >= cap)
			return NULL;
		out[n++] = *p;
	}
	if (*p != '"')
		return NULL;
	out[n] = 0;
	return p + 1;
}

const char *kof_catfmt_skip(const char *p)
{
	while (*p == ' ' || *p == '\t')
		p++;
	return p;
}

const char *kof_catfmt_after(const char *t, const char *kw)
{
	size_t n = strlen(kw);

	if (strncmp(t, kw, n))
		return NULL;
	t = kof_catfmt_skip(t + n);
	return *t == '(' ? kof_catfmt_skip(t + 1) : NULL;
}

int kof_catfmt_call_end(const char *p)
{
	p = kof_catfmt_skip(p);
	return p[0] == ')' && p[1] == ';' && !*kof_catfmt_skip(p + 2);
}

const char *kof_catfmt_ident(const char *p, char *out, size_t cap)
{
	size_t k = 0;

	for (; (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_'; p++)
		if (k + 1u < cap)
			out[k++] = *p;
	if (cap)
		out[k] = 0;
	return p;
}

int kof_catfmt_lines(const char *text, size_t len, kof_catfmt_line fn, void *user, uint32_t *ignored, const char **why)
{
	size_t pos = 0;
	uint32_t ign = 0u;
	const char *w = "";
	char line[KOF_CATSTORE_LINE_MAX + 1u];

	while (pos < len) {
		const char *e = memchr(text + pos, '\n', len - pos);
		size_t n = e ? (size_t)(e - (text + pos)) : len - pos;
		char *t = line, *end;
		int rc;

		if (n > KOF_CATSTORE_LINE_MAX) {
			w = "line too long";
			goto fail;
		}
		memcpy(line, text + pos, n);
		line[n] = 0;
		pos += n + (e ? 1u : 0u);
		if (strlen(line) != n) {                    /* a NUL inside the line: not text */
			rc = fn(user, NULL, &w);
		} else {
			while (*t == ' ' || *t == '\t')
				t++;
			for (end = t + strlen(t); end > t && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'); end--)
				;
			*end = 0;
			rc = fn(user, t, &w);
		}
		if (rc < 0)
			goto fail;
		if (rc > 0)
			ign++;
	}
	if (ignored)
		*ignored = ign;
	return 1;
fail:
	if (ignored)
		*ignored = 0u;
	if (why)
		*why = w;
	return 0;
}

/* ---- the comment above an item ------------------------------------------------------------------------------------------- */

enum kof_catcomment kof_catcomment_check(const char *comment)
{
	size_t i;

	if (!comment)
		return KOF_CATCOMMENT_OK;
	if (strnlen(comment, KOF_CATSTORE_COMMENT_MAX + 1u) > KOF_CATSTORE_COMMENT_MAX)
		return KOF_CATCOMMENT_TOO_LONG;
	for (i = 0; comment[i]; i++)
		if (!kof_comment_char((unsigned char)comment[i]))
			return KOF_CATCOMMENT_BAD_CHAR;
	return KOF_CATCOMMENT_OK;
}

const char *kof_catcomment_text(enum kof_catcomment st)
{
	switch (st) {
	case KOF_CATCOMMENT_BAD_CHAR: return "comment: no * or / and printable only";
	case KOF_CATCOMMENT_TOO_LONG: return "comment is over 120 characters";
	default: break;
	}
	return "";
}

void kof_catpend_clear(struct kof_catpend *p)
{
	p->len = 0;
	p->text[0] = 0;
}

int kof_catpend_line(struct kof_catpend *p, const char *t)
{
	size_t n;

	if (t[0] != '/' || t[1] != '/')
		return 0;
	t += 2;
	if (*t == ' ')
		t++;
	n = strlen(t);
	if (!n)
		return 1;
	if (p->len && p->len < sizeof p->text - 1u)
		p->text[p->len++] = ' ';
	if (n > sizeof p->text - 1u - p->len)
		n = sizeof p->text - 1u - p->len;
	memcpy(p->text + p->len, t, n);
	p->len += n;
	p->text[p->len] = 0;
	return 1;
}

/* ---- the directory ---------------------------------------------------------------------------------------------------- */

void kof_catstore_init(struct kof_catstore *s)
{
	memset(s, 0, sizeof *s);
}

static int name_cmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

static int is_regular(const char *path)
{
	struct stat st;

	return kof_lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Read a whole file up to KOF_CATSTORE_FILE_MAX into buf[KOF_CATSTORE_FILE_MAX + 1]; returns the length, or SIZE_MAX with *why. */
static size_t read_file(const char *path, char *buf, const char **why)
{
	FILE *f;
	size_t n;

	if (!is_regular(path)) {
		*why = "not a regular file";
		return SIZE_MAX;
	}
	f = fopen(path, "rb");
	if (!f) {
		*why = "cannot be opened";
		return SIZE_MAX;
	}
	n = fread(buf, 1, KOF_CATSTORE_FILE_MAX + 1u, f);
	if (ferror(f))
		n = SIZE_MAX, *why = "read error";
	else if (n > KOF_CATSTORE_FILE_MAX)
		n = SIZE_MAX, *why = "file too big";
	fclose(f);
	return n;
}

enum kof_catstore_io kof_catstore_dir_size(const char *dir, uint64_t *bytes, uint32_t *files)
{
	struct dirent *de;
	DIR *d;

	*bytes = 0u;
	*files = 0u;
	if (!dir || !dir[0])
		return KOF_CATSTORE_IO_NO_DIR;
	d = opendir(dir);
	if (!d)
		return errno == ENOENT ? KOF_CATSTORE_IO_OK : KOF_CATSTORE_IO_FAIL;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char path[1024];
		struct stat st;

		if (de->d_name[0] == '.' || l < 3u || strcmp(de->d_name + l - 2u, ".c") || l > KOF_CATSTORE_FILENAME_MAX)
			continue;
		if (snprintf(path, sizeof path, "%s/%s", dir, de->d_name) >= (int)sizeof path || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
			continue;
		*bytes += (uint64_t)st.st_size < KOF_CATSTORE_FILE_MAX ? (uint64_t)st.st_size : KOF_CATSTORE_FILE_MAX;
		(*files)++;
	}
	closedir(d);
	return KOF_CATSTORE_IO_OK;
}

#define BAD_SHOWN 3u

static void no_dir(struct kof_catstore *s, const char *what, const char *option)
{
	snprintf(s->note, sizeof s->note, "no %s directory (--bases or %s)", what, option);
}

enum kof_catstore_io kof_catstore_load(struct kof_catstore *s, const char *dir, const struct kof_catstore_in *in)
{
	static const char big[] = "name too long";
	char (*names)[KOF_CATSTORE_FILENAME_MAX + 1u];
	char (*bad)[KOF_CATSTORE_FILENAME_MAX + 1u], path[1024], *buf;
	const char *why[BAD_SHOWN];
	uint32_t n_name = 0u, i, over = 0u;
	struct dirent *de;
	DIR *d;
	size_t at;

	kof_catstore_init(s);
	if (!dir || !dir[0]) {
		no_dir(s, in->what, in->option);
		return KOF_CATSTORE_IO_NO_DIR;
	}
	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT)
			return KOF_CATSTORE_IO_OK;          /* nothing saved yet: an empty catalog */
		snprintf(s->note, sizeof s->note, "cannot read %.120s: %s", dir, strerror(errno));
		return KOF_CATSTORE_IO_FAIL;
	}
	names = malloc(KOF_CATSTORE_FILES_MAX * sizeof *names);
	bad = malloc(BAD_SHOWN * sizeof *bad);
	buf = malloc(KOF_CATSTORE_FILE_MAX + 1u);
	if (!names || !buf || !bad) {
		free(names);
		free(bad);
		free(buf);
		closedir(d);
		snprintf(s->note, sizeof s->note, "out of memory");
		return KOF_CATSTORE_IO_FAIL;
	}
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);

		if (de->d_name[0] == '.' || l < 3u || strcmp(de->d_name + l - 2u, ".c"))
			continue;
		if (l > KOF_CATSTORE_FILENAME_MAX) {
			if (s->n_bad < BAD_SHOWN) {
				snprintf(bad[s->n_bad], sizeof bad[0], "%.*s...", (int)(sizeof bad[0] - 5u), de->d_name);
				why[s->n_bad] = big;
			}
			s->n_bad++;
		} else if (n_name < KOF_CATSTORE_FILES_MAX) {
			memcpy(names[n_name++], de->d_name, l + 1u);
		} else {
			over++;
		}
	}
	closedir(d);
	qsort(names, n_name, sizeof *names, name_cmp);
	for (i = 0; i < n_name; i++) {
		const char *w = "";
		uint32_t ign = 0u;
		size_t n;
		int ok = 0;

		if (snprintf(path, sizeof path, "%s/%s", dir, names[i]) >= (int)sizeof path) {
			w = "path too long";
		} else if ((n = read_file(path, buf, &w)) != SIZE_MAX) {
			ok = in->load(in->user, buf, n, &ign, &w);
		}
		if (ok) {
			memcpy(s->file[s->n_file++], names[i], strlen(names[i]) + 1u);
			s->n_ignored += ign;
		} else {
			if (s->n_bad < BAD_SHOWN) {
				memcpy(bad[s->n_bad], names[i], strlen(names[i]) + 1u);
				why[s->n_bad] = w;
			}
			s->n_bad++;
		}
	}
	/* ONE line, the part a person needs first at the left (the dialog's rule cuts the right): the files not loaded by name, the lines
	 * not understood, then why the first file failed. */
	at = 0;
	if (s->n_bad || over) {
		at += (size_t)snprintf(s->note, sizeof s->note, "not loaded:");
		for (i = 0; i < s->n_bad && i < BAD_SHOWN; i++)
			at += (size_t)snprintf(s->note + at, sizeof s->note - at, i ? ", %s" : " %s", bad[i]);
		if (s->n_bad > BAD_SHOWN)
			at += (size_t)snprintf(s->note + at, sizeof s->note - at, " +%u more", (unsigned)(s->n_bad - BAD_SHOWN));
		if (over)
			at += (size_t)snprintf(s->note + at, sizeof s->note - at, " %u files over the limit of %u not read",
					       (unsigned)over, (unsigned)KOF_CATSTORE_FILES_MAX);
	}
	if (s->n_ignored)
		at += (size_t)snprintf(s->note + at, sizeof s->note - at, "%s%u line%s ignored", at ? "; " : "", (unsigned)s->n_ignored,
				       s->n_ignored == 1u ? "" : "s");
	if (s->n_bad)
		snprintf(s->note + at, sizeof s->note - at, " (%s: %s)", bad[0], why[0]);
	free(names);
	free(bad);
	free(buf);
	return KOF_CATSTORE_IO_OK;
}

/* ---- save ------------------------------------------------------------------------------------------------------------- */

/* Is `name` a file the store knows (loaded or written)? Letter case ignored: on a file system that ignores it, "Mirai.c" is the
 * file "mirai.c" would overwrite, and it is ours. */
static int known_at(const struct kof_catstore *s, const char *name)
{
	uint32_t i;

	for (i = 0; i < s->n_file; i++)
		if (!strcasecmp(s->file[i], name))
			return (int)i;
	return -1;
}

/* The same by exact name: the list entry a write is recorded in. */
static int listed_at(const struct kof_catstore *s, const char *name)
{
	uint32_t i;

	for (i = 0; i < s->n_file; i++)
		if (!strcmp(s->file[i], name))
			return (int)i;
	return -1;
}

static enum kof_catstore_io save_fail(struct kof_catstore *s, enum kof_catstore_io io, const char *what, const char *name)
{
	snprintf(s->note, sizeof s->note, "%s %s%s%s", what, name, errno && io == KOF_CATSTORE_IO_FAIL ? ": " : "",
		 errno && io == KOF_CATSTORE_IO_FAIL ? strerror(errno) : "");
	return io;
}

/* Does `a` name the very file `b` does (the same name on a file system that ignores letter case, or the same inode)? */
static int same_file(const char *a, const char *b)
{
	struct stat x, y;

	return kof_lstat(a, &x) == 0 && kof_lstat(b, &y) == 0 && x.st_ino != 0 && x.st_ino == y.st_ino && x.st_dev == y.st_dev;
}

enum kof_catstore_io kof_catstore_save(struct kof_catstore *s, const char *dir, const struct kof_catstore_out *o)
{
	char name[KOF_CATSTORE_FILENAME_MAX + 1u], other[KOF_CATSTORE_FILENAME_MAX + 1u], path[1024], path2[1024];
	uint8_t written[KOF_CATSTORE_FILES_MAX];
	struct stat st;
	uint32_t i, j;
	char *buf;

	s->note[0] = 0;
	errno = 0;
	if (!dir || !dir[0]) {
		no_dir(s, o->what, o->option);
		return KOF_CATSTORE_IO_NO_DIR;
	}
	if (o->n > KOF_CATSTORE_FILES_MAX) {
		snprintf(s->note, sizeof s->note, "more than %u files", (unsigned)KOF_CATSTORE_FILES_MAX);
		return KOF_CATSTORE_IO_FAIL;
	}
	/* The whole catalog is checked before anything is written. */
	for (i = 0; i < o->n; i++) {
		o->name(o->user, i, name, sizeof name);
		for (j = 0; j < i; j++) {
			o->name(o->user, j, other, sizeof other);
			if (!strcmp(name, other))
				return save_fail(s, KOF_CATSTORE_IO_COLLISION, "two items would share the file", name);
		}
		if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "path too long", name);
		if (kof_lstat(path, &st) == 0 && known_at(s, name) < 0)
			return save_fail(s, KOF_CATSTORE_IO_COLLISION, "a file that was not loaded is in the way:", name);
	}
	{
		uint32_t extra = 0u;

		for (i = 0; i < s->n_file; i++) {
			int hit = 0;

			for (j = 0; j < o->n; j++) {
				o->name(o->user, j, name, sizeof name);
				hit |= !strcmp(name, s->file[i]);
			}
			extra += !hit;
		}
		if (o->n + extra > KOF_CATSTORE_FILES_MAX)
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "too many files in", dir);
	}
	if (stat(dir, &st) != 0) {
		if (kof_mkdir(dir, 0777) != 0)
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "cannot create", dir);
	} else if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return save_fail(s, KOF_CATSTORE_IO_FAIL, "not a directory:", dir);
	}
	buf = malloc(KOF_CATSTORE_FILE_MAX);
	if (!buf)
		return save_fail(s, KOF_CATSTORE_IO_FAIL, "out of memory", "");
	memset(written, 0, sizeof written);
	/* Write: every file, directly (open, write, close). A file written is known from then on, so a failure half way leaves the store
	 * describing the directory as it is. */
	for (i = 0; i < o->n; i++) {
		size_t n = o->text(o->user, i, buf, KOF_CATSTORE_FILE_MAX);
		FILE *f;
		int k, bad;

		o->name(o->user, i, name, sizeof name);
		snprintf(path, sizeof path, "%s/%s", dir, name);
		errno = 0;
		if (n >= KOF_CATSTORE_FILE_MAX) {
			free(buf);
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "file would be too big:", name);
		}
		f = kof_fopen_trunc_mode(path, 0666);
		bad = !f || fwrite(buf, 1, n, f) != n;
		if (f)
			bad |= fclose(f) != 0;
		if (bad) {
			int e = errno ? errno : EIO;

			free(buf);
			errno = e;
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "cannot write", name);
		}
		k = listed_at(s, name);
		if (k < 0) {
			memcpy(s->file[s->n_file], name, strlen(name) + 1u);
			k = (int)s->n_file++;
		}
		written[k] = 1u;
	}
	free(buf);
	/* Remove the files of items that are gone (known files nothing was written to), unless one is the same file as a written one. */
	for (i = 0; i < s->n_file;) {
		int same = 0;

		if (written[i]) {
			i++;
			continue;
		}
		snprintf(path, sizeof path, "%s/%s", dir, s->file[i]);
		for (j = 0; j < s->n_file && !same; j++) {
			snprintf(path2, sizeof path2, "%s/%s", dir, s->file[j]);
			same = written[j] && same_file(path, path2);
		}
		errno = 0;
		if (!same && unlink(path) != 0 && errno != ENOENT)
			return save_fail(s, KOF_CATSTORE_IO_FAIL, "cannot remove", s->file[i]);
		memmove(s->file[i], s->file[i + 1u], (size_t)(s->n_file - i - 1u) * sizeof s->file[0]);
		memmove(&written[i], &written[i + 1u], s->n_file - i - 1u);
		s->n_file--;
	}
	return KOF_CATSTORE_IO_OK;
}
