/*
 * kofdb.c - load the database into an immutable engine.
 *
 * The tables grow while loading and are frozen when it returns. That is why the
 * growable state lives in a local builder rather than in the engine: the engine has
 * no capacity fields, so there is nothing in it that suggests it can still change.
 */

#include "../kofdb/kofdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

/*
 * A blob is raw code with no header, so there is nothing to validate properly; that
 * comes with the packed container, where a record has to carry length, entry offset
 * and integrity anyway. Until then, two guards for the mistake that actually happens:
 * handing over a build intermediate instead of the blob.
 */
#define KOF_BLOB_MAX_CODE (4u * 1024u * 1024u)

static int blob_plausible(const uint8_t *p, size_t len, const char *path)
{
	if (len == 0 || len > KOF_BLOB_MAX_CODE) {
		fprintf(stderr, "kofdb: %s: implausible blob size %zu\n", path, len);
		return 0;
	}
	/* The intermediates are an .o and a linked .elf. Copying either into
	 * executable memory and jumping to offset 0 executes an ELF header. */
	if (len >= 4 && memcmp(p, "\177ELF", 4) == 0) {
		fprintf(stderr, "kofdb: %s looks like an ELF image, not a blob\n",
			path);
		return 0;
	}
	return 1;
}

/* Growable state, alive only while loading. */
struct builder {
	struct kof_engine e;
	uint32_t cap_mods, cap_str, cap_rng, cap_name;
	size_t   code_used;
	char   **paths;
	uint32_t n_paths;
};

static size_t round_up(size_t v, size_t a)
{
	return (v + a - 1) / a * a;
}

static size_t page_size_of(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	return ps > 0 ? (size_t)ps : 4096u;
}

/*
 * Reserve the code arena writable, copy blobs in, then flip the whole arena to read
 * plus execute in one step. No page is ever writable and executable at once.
 *
 * One arena for every blob, not one per module: per-module mapping costs an mmap and
 * an mprotect each - measured at 3.35us - which at ten thousand modules is tens of
 * milliseconds of syscall before a byte is scanned.
 */
static int arena_open(struct builder *b, size_t cap)
{
	size_t ps = page_size_of();
	b->e.code_cap = round_up(cap, ps);
	b->code_used = 0;
	b->e.code = mmap(NULL, b->e.code_cap, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (b->e.code == MAP_FAILED) {
		b->e.code = NULL;
		return 0;
	}
	return 1;
}

/* Blobs are kept 16 byte aligned so an entry point is never misaligned for the
 * target's calling convention. */
static long arena_add(struct builder *b, const uint8_t *blob, size_t len)
{
	size_t off = round_up(b->code_used, 16);
	if (off > b->e.code_cap || len > b->e.code_cap - off)
		return -1;
	memcpy(b->e.code + off, blob, len);
	b->code_used = off + len;
	return (long)off;
}

/*
 * Read a whole file, refusing one that is too big to be what we are reading.
 *
 * The cap is checked against the stat size, before the allocation rather than after
 * the read: a database directory is a directory, and anything at all can be dropped
 * into it under a name ending in .blob. Allocating first and judging the contents
 * afterwards means an 8GB file named *.blob costs 8GB of address space to find out it
 * was never a blob - measured, and it also doubles because the arena is sized from the
 * same st_size. Deciding from the size alone costs a stat.
 */
static uint8_t *read_whole(const char *path, size_t cap, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	FILE *f;

	/* stat() rather than fstat(fileno()): fileno is POSIX and this is built as
	 * strict ISO C11 so the library stays portable. */
	if (stat(path, &st) != 0 || st.st_size <= 0)
		return NULL;
	if ((uint64_t)st.st_size > (uint64_t)cap) {
		fprintf(stderr, "kofdb: %s: %llu bytes is too large for a blob\n",
			path, (unsigned long long)st.st_size);
		return NULL;
	}
	f = fopen(path, "rb");
	if (!f)
		return NULL;
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*out_len = (size_t)st.st_size;
	return buf;
}

#define GROW(field, count, cap, init)                                        \
	do {                                                                 \
		if ((count) == (cap)) {                                      \
			uint32_t nc_ = (cap) ? (cap) * 2u : (init);           \
			void *nv_ = realloc((field), nc_ * sizeof *(field));  \
			if (!nv_)                                            \
				return 0;                                    \
			(field) = nv_;                                       \
			(cap) = nc_;                                         \
		}                                                            \
	} while (0)

static int name_push(struct builder *b, uint32_t id, const char *text)
{
	GROW(b->e.name_tab, b->e.n_name, b->cap_name, 256);
	b->e.name_tab[b->e.n_name].id = id;
	snprintf(b->e.name_tab[b->e.n_name].text,
		 sizeof b->e.name_tab[b->e.n_name].text, "%s", text);
	b->e.n_name++;
	return 1;
}

static int str_push(struct builder *b, const struct kof_str_ent *s)
{
	GROW(b->e.str_tab, b->e.n_str, b->cap_str, 128);
	b->e.str_tab[b->e.n_str++] = *s;
	return 1;
}

static int rng_push(struct builder *b, uint32_t mask)
{
	GROW(b->e.rng_tab, b->e.n_rng, b->cap_rng, 128);
	b->e.rng_tab[b->e.n_rng++] = mask;
	return 1;
}

const char *kof_db_name(const struct kof_engine *e, const struct kof_module *m,
			uint32_t name_id)
{
	uint32_t i;
	for (i = 0; i < m->n_names; i++)
		if (e->name_tab[m->name_base + i].id == name_id)
			return e->name_tab[m->name_base + i].text;
	return NULL;
}

/* Swap ".blob" for another extension. */
static int sibling_path(const char *blob_path, const char *ext, char *out,
			size_t cap)
{
	size_t n = strlen(blob_path);
	if (n < 5 || n - 5 + strlen(ext) + 1 > cap)
		return 0;
	memcpy(out, blob_path, n - 5);
	memcpy(out + n - 5, ext, strlen(ext) + 1);
	return 1;
}

static void names_load(struct builder *b, struct kof_module *m, const char *bp)
{
	char path[4096], line[256];
	FILE *f;

	m->name_base = b->e.n_name;
	m->n_names   = 0;

	if (!sibling_path(bp, ".names", path, sizeof path))
		return;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "kofdb: no name table at %s; detections will "
				"report as unknown\n", path);
		return;
	}
	while (fgets(line, sizeof line, f)) {
		char *tab = strchr(line, '\t'), *nl;
		if (!tab)
			continue;
		*tab++ = 0;
		nl = strchr(tab, '\n');
		if (nl)
			*nl = 0;
		if (!name_push(b, (uint32_t)strtoul(line, 0, 10), tab))
			break;
		m->n_names++;
	}
	fclose(f);
}

/*
 * Declared strings and ranges.
 *
 * Tab separated, kind in column one: 'r' for a range mask, 's' for a string with the
 * literal last so nothing in it has to be escaped to keep the columns parseable.
 */
static void strs_load(struct builder *b, struct kof_module *m, const char *bp)
{
	char path[4096], line[KOF_STR_MAX_LEN + 128];
	FILE *f;

	m->str_base = b->e.n_str;
	m->n_str    = 0;
	m->rng_base = b->e.n_rng;
	m->n_rng    = 0;

	if (!sibling_path(bp, ".strs", path, sizeof path))
		return;
	f = fopen(path, "r");
	if (!f)
		return;                 /* a module may declare neither */

	while (fgets(line, sizeof line, f)) {
		char *p = line, *tab;

		if (p[0] == 'r' && p[1] == '\t') {
			unsigned long mask;
			p += 2;
			tab = strchr(p, '\t');
			if (!tab)
				continue;
			mask = strtoul(tab + 1, 0, 10);
			if (!rng_push(b, (uint32_t)mask))
				break;
			m->n_rng++;
			continue;
		}
		if (p[0] == 's' && p[1] == '\t') {
			struct kof_str_ent e;
			unsigned long v[4];
			int i;
			size_t len;

			memset(&e, 0, sizeof e);
			p += 2;
			for (i = 0; i < 4; i++) {
				tab = strchr(p, '\t');
				if (!tab)
					break;
				*tab = 0;
				v[i] = strtoul(p, 0, 10);
				p = tab + 1;
			}
			if (i != 4)
				continue;   /* malformed row: skip it, not the file */

			len = strlen(p);
			while (len && (p[len - 1] == '\n' || p[len - 1] == '\r'))
				p[--len] = 0;
			/* The recorded length is authoritative: it is what the
			 * generator measured, and trusting strlen would silently
			 * truncate a literal containing a NUL once escapes exist. */
			if (v[3] != len || len == 0 || len > KOF_STR_MAX_LEN)
				continue;

			e.icase    = (uint8_t)v[1];
			e.fullword = (uint8_t)v[2];
			e.len      = (uint16_t)len;
			memcpy(e.bytes, p, len);
			if (!str_push(b, &e))
				break;
			m->n_str++;
		}
	}
	fclose(f);
}

/*
 * Preconditions, and the record that says these bytes are a module at all.
 *
 * Mandatory, and that is the whole point of it. The blob is raw code entered at
 * offset 0, so the loader has no way to look at the bytes and tell a module from
 * anything else - a stray 200 byte file named *.blob was copied into executable
 * memory and called, which is a crash at best. The build emits .meta beside every
 * blob it produces, so its absence means the build did not produce this file.
 * Refusing then is not a policy choice, it is the only evidence available.
 *
 * `blob_len` is checked against what was actually read: it catches a truncated or
 * half written blob paired with an intact record. It is an integrity check, not an
 * authenticity one - anyone who can write the blob can write the record beside it,
 * so the boundary here is the permissions on the database directory. Authenticity
 * belongs to the signed container that replaces these loose files.
 *
 * Within a record that exists, a missing field still means unconstrained, and that
 * is the safe direction: an unconstrained module gets run, so a stale field costs
 * time rather than detections.
 *
 * Zero on refusal.
 */
static int meta_load(struct kof_module *m, const char *bp, size_t blob_len)
{
	char path[4096], line[128];
	uint64_t want_len = 0;
	FILE *f;

	m->target_mask = 0xffffffffu;
	m->scan_mask   = 0;
	m->size_min    = 0;
	m->arch_mask   = 0;

	if (!sibling_path(bp, ".meta", path, sizeof path))
		return 0;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "kofdb: %s has no .meta beside it, so it is not "
				"something the build produced; refused\n", bp);
		return 0;
	}
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "target=", 7) == 0)
			m->target_mask = (uint32_t)strtoul(line + 7, 0, 10);
		else if (strncmp(line, "scan_mask=", 10) == 0)
			m->scan_mask = (uint32_t)strtoul(line + 10, 0, 10);
		else if (strncmp(line, "size_min=", 9) == 0)
			m->size_min = strtoull(line + 9, 0, 10);
		else if (strncmp(line, "arch_mask=", 10) == 0)
			m->arch_mask = (uint32_t)strtoul(line + 10, 0, 10);
		else if (strncmp(line, "blob_len=", 9) == 0)
			want_len = strtoull(line + 9, 0, 10);
	}
	fclose(f);

	if (want_len == 0) {
		fprintf(stderr, "kofdb: %s: the record beside it declares no "
				"blob_len; refused\n", bp);
		return 0;
	}
	if (want_len != (uint64_t)blob_len) {
		fprintf(stderr, "kofdb: %s: %zu bytes, but the record beside it "
				"says %llu; refused\n", bp, blob_len,
			(unsigned long long)want_len);
		return 0;
	}

	if (m->target_mask == 0)
		m->target_mask = 0xffffffffu;
	return 1;
}

/* Collect *.blob from a directory so a whole set can be named at once. */
static int collect_blobs(struct builder *b, const char *dir)
{
	struct dirent *de;
	DIR *d = opendir(dir);
	uint32_t cap = 0;

	if (!d)
		return 0;
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name), n;
		char *p;
		if (l < 6 || strcmp(de->d_name + l - 5, ".blob") != 0)
			continue;
		if (b->n_paths == cap) {
			uint32_t nc = cap ? cap * 2 : 64;
			char **nv = realloc(b->paths, nc * sizeof *nv);
			if (!nv)
				break;
			b->paths = nv;
			cap = nc;
		}
		/* snprintf with the size it was allocated from, not sprintf: the
		 * arithmetic is exact today, and the point is that it stays checked
		 * where it is written rather than in a separate line above it. */
		n = strlen(dir) + l + 2;
		p = malloc(n);
		if (!p)
			break;
		snprintf(p, n, "%s/%s", dir, de->d_name);
		b->paths[b->n_paths++] = p;
	}
	closedir(d);
	return b->n_paths > 0;
}

static int one_path(struct builder *b, const char *path)
{
	b->paths = malloc(sizeof *b->paths);
	if (!b->paths)
		return 0;
	b->paths[0] = kof_strdup(path);
	if (!b->paths[0])
		return 0;
	b->n_paths = 1;
	return 1;
}

struct kof_engine *kof_db_load(const char *path)
{
	struct builder b;
	struct kof_engine *out;
	struct stat sb;
	size_t total = 0;
	uint32_t i;

	memset(&b, 0, sizeof b);

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		if (!collect_blobs(&b, path)) {
			fprintf(stderr, "kofdb: no .blob files in %s\n", path);
			goto fail;
		}
	} else if (!one_path(&b, path)) {
		goto fail;
	}

	/*
	 * Size the arena from the files, but only from the ones that could be blobs.
	 * A file over the cap is going to be refused below, so counting it here would
	 * reserve address space for a module that never loads - and since anyone can
	 * drop anything into a database directory, that turns one large file into an
	 * arbitrarily large mapping. The 64 is per-blob alignment slack.
	 */
	for (i = 0; i < b.n_paths; i++)
		if (stat(b.paths[i], &sb) == 0 && sb.st_size > 0 &&
		    (uint64_t)sb.st_size <= (uint64_t)KOF_BLOB_MAX_CODE)
			total += (size_t)sb.st_size + 64;
	if (!arena_open(&b, total ? total : 4096)) {
		fprintf(stderr, "kofdb: cannot reserve the code arena\n");
		goto fail;
	}

	b.e.mods = calloc(b.n_paths, sizeof *b.e.mods);
	if (!b.e.mods)
		goto fail;
	b.cap_mods = b.n_paths;

	for (i = 0; i < b.n_paths; i++) {
		struct kof_module *m = &b.e.mods[b.e.n_mods];
		uint8_t *blob;
		size_t len;
		long off;

		blob = read_whole(b.paths[i], KOF_BLOB_MAX_CODE, &len);
		if (!blob) {
			fprintf(stderr, "kofdb: cannot read %s\n", b.paths[i]);
			continue;
		}
		/*
		 * Everything that can refuse these bytes runs before they reach
		 * executable memory. The arena is made executable as a whole later,
		 * so a blob copied in is a blob that will be entered; there is no
		 * second chance to change our mind about it further down.
		 */
		if (!blob_plausible(blob, len, b.paths[i]) ||
		    !meta_load(m, b.paths[i], len)) {
			free(blob);
			continue;
		}
		off = arena_add(&b, blob, len);
		free(blob);
		if (off < 0) {
			fprintf(stderr, "kofdb: arena full at %s\n", b.paths[i]);
			break;
		}

		/* Entry offset is zero within each blob; build.sh asserts it. */
		m->fn = (kof_scan_fn)(void *)(b.e.code + off);
		names_load(&b, m, b.paths[i]);
		strs_load(&b, m, b.paths[i]);

		/* Assigned after strs_load, which is what knows the counts. */
		m->memo_base = b.e.memo_size;
		b.e.memo_size += m->n_str * m->n_rng;
		b.e.scan_mask |= m->scan_mask;

		b.e.n_mods++;
	}

	if (b.e.n_mods == 0)
		goto fail;

	if (mprotect(b.e.code, b.e.code_cap, PROT_READ | PROT_EXEC) != 0) {
		fprintf(stderr, "kofdb: cannot make the arena executable\n");
		goto fail;
	}

	out = malloc(sizeof *out);
	if (!out)
		goto fail;
	*out = b.e;
	/* A path is only needed to find the files beside the blob. Nothing keeps one
	 * afterwards, so the engine owns no strings and there is no ownership to get
	 * wrong. */
	for (i = 0; i < b.n_paths; i++)
		free(b.paths[i]);
	free(b.paths);
	return out;

fail:
	if (b.e.code)
		munmap(b.e.code, b.e.code_cap);
	for (i = 0; i < b.n_paths; i++)
		free(b.paths[i]);
	free(b.paths);
	free(b.e.mods);
	free(b.e.str_tab);
	free(b.e.rng_tab);
	free(b.e.name_tab);
	return NULL;
}

void kof_db_free(struct kof_engine *e)
{
	if (!e)
		return;
	free(e->mods);
	free(e->str_tab);
	free(e->rng_tab);
	free(e->name_tab);
	if (e->code)
		munmap(e->code, e->code_cap);
	free(e);
}