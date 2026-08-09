/*
 * ksigbuilder - pack signature artefacts into a database.
 *
 *   ksigbuilder <artefact-dir> <out-dir>
 *
 * One half of the toolchain; ksigcompiler.sh beside it is the other. That one turns
 * a source into an artefact, this one turns artefacts into .ksig packs, and neither
 * does the other's job - so each can be run, tested and replaced on its own, and
 * driving them in sequence is a Makefile rule rather than a mode of either.
 *
 * The division is by what each is good at. Compiling a module is a wrapper around
 * ld, nm, readelf and size, which is what a shell script is for. Packing is a byte
 * layout with invariants to hold, which is what C is for - and this links the very
 * builder the engine reads with, so the format has one implementation rather than a
 * writer and a reader that agree by inspection.
 *
 * This is the product tool. tools/kofdbc is the test harness for the writer
 * underneath it, and the two exist separately for the same reason kofscanner and
 * tools/kofrun do.
 *
 *
 * GROUPING
 *
 * One pack per (kind, target_mask, arch_mask). Every part of that key is derived
 * from an artefact - kind from which entry point the module exported, the rest from
 * the .meta record - so nobody decides where a module goes and there is nowhere for
 * a decision to be wrong.
 *
 * By the exact mask value, not by "a format". A pack holding exactly the modules
 * whose target_mask is M has any_target == M, so testing an object against the pack
 * gives the same answer as testing it against every module in it: the pack-level
 * test skips exactly what the per-module test would have skipped, at one comparison
 * instead of N. Any coarser grouping - by platform, by family, by category - forces
 * the union wider than its members and starts losing modules it should have run.
 *
 * A module targeting PE and ELF together therefore gets its own pack with
 * any_target = PE|ELF, which still rules out Mach-O, script and text. That is not
 * an exception to the rule; it is the rule applied to a mask with two bits set.
 *
 * Measured on 4004 modules, this produces 4 packs and skips almost nothing for an
 * ELF object. That is the honest result: grouping is a coarse cut and does not
 * carry scale. What carries scale is the inverted index, which is built here too
 * once it exists - see kofpack.h.
 *
 *
 * FAILURE IS FATAL
 *
 * Any artefact that cannot be read stops the run. Skipping it would produce a
 * database missing a signature, and nothing downstream can tell that from a
 * database that was never meant to have it - a detection that does not happen is
 * not something a test notices.
 */

/* Before any include, not after: opendir and readdir are POSIX, and a feature test
 * macro placed after the first include has no effect at all. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "../libkofeng/kofdb/kofpackw.h"
#include "../libkofeng/kofdb/kofpack.h"

/* Everything read out of one artefact set, owned until its pack is written. */
struct artefact {
	char    *stem;                   /* the path without the .blob */
	uint8_t *code;
	uint32_t code_len;

	uint32_t kind;
	uint32_t target_mask, scan_mask, arch_mask;
	uint64_t size_min;

	struct kof_pw_str  *str;
	uint32_t            n_str;
	uint32_t           *rng;
	uint32_t            n_rng;
	struct kof_pw_name *name;
	uint32_t            n_names;

	/* The literals and name texts the descriptors above point into. */
	uint8_t *str_bytes;
	char    *name_text;
};

static void artefact_free(struct artefact *a)
{
	free(a->stem);
	free(a->code);
	free(a->str);
	free(a->rng);
	free(a->name);
	free(a->str_bytes);
	free(a->name_text);
}

/* <stem> + <ext> into a fresh string. */
static char *sibling(const char *stem, const char *ext)
{
	size_t a = strlen(stem), b = strlen(ext);
	char *p = malloc(a + b + 1);

	if (!p)
		return NULL;
	memcpy(p, stem, a);
	memcpy(p + a, ext, b + 1);
	return p;
}

static char *join_path(const char *dir, const char *leaf)
{
	size_t n = strlen(dir) + strlen(leaf) + 2;
	char *p = malloc(n);

	if (!p)
		return NULL;
	snprintf(p, n, "%s/%s", dir, leaf);
	return p;
}

/*
 * Read a whole file, refusing one too large to be what is being read.
 *
 * The cap is checked against the stat size before the allocation, not after the
 * read: an artefact directory is a directory, and a file of any size can be in it
 * under a name ending in .blob.
 */
static uint8_t *read_whole(const char *path, size_t cap, size_t *out_len)
{
	struct stat st;
	uint8_t *buf;
	FILE *f;

	if (stat(path, &st) != 0 || st.st_size <= 0)
		return NULL;
	if ((uint64_t)st.st_size > (uint64_t)cap) {
		fprintf(stderr, "ksigbuilder: %s: %llu bytes is too large for a "
				"blob\n", path, (unsigned long long)st.st_size);
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

/*
 * The .meta record. Mandatory, and so is every field it must carry.
 *
 * The loader can afford a permissive default for a missing field because a wrong
 * guess there costs scan time. A wrong guess here is baked into a database and
 * costs detections, so there are no defaults: an incomplete record is a build that
 * went wrong and the only useful thing to do with it is stop.
 */
static int meta_load(struct artefact *a)
{
	char *path = sibling(a->stem, ".meta"), line[128];
	FILE *f;
	uint64_t blob_len = 0;
	int have_target = 0, have_kind = 0, ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "ksigbuilder: %s: no record beside the blob\n",
			a->stem);
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		if (strncmp(line, "target=", 7) == 0) {
			a->target_mask = (uint32_t)strtoul(line + 7, 0, 10);
			have_target = 1;
		} else if (strncmp(line, "scan_mask=", 10) == 0) {
			a->scan_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "size_min=", 9) == 0) {
			a->size_min = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "arch_mask=", 10) == 0) {
			a->arch_mask = (uint32_t)strtoul(line + 10, 0, 10);
		} else if (strncmp(line, "blob_len=", 9) == 0) {
			blob_len = strtoull(line + 9, 0, 10);
		} else if (strncmp(line, "kind=", 5) == 0) {
			a->kind = (uint32_t)strtoul(line + 5, 0, 10);
			have_kind = 1;
		}
	}
	fclose(f);

	if (!have_target || a->target_mask == 0) {
		fprintf(stderr, "ksigbuilder: %s: record declares no target\n",
			a->stem);
		goto out;
	}
	if (!have_kind) {
		fprintf(stderr, "ksigbuilder: %s: record declares no kind\n",
			a->stem);
		goto out;
	}
	if (a->kind != KOF_PACK_DETECT && a->kind != KOF_PACK_UNPACK) {
		fprintf(stderr, "ksigbuilder: %s: unknown kind %u\n", a->stem,
			a->kind);
		goto out;
	}
	if (blob_len != a->code_len) {
		fprintf(stderr, "ksigbuilder: %s: blob is %u bytes, record says "
				"%llu\n", a->stem, a->code_len,
			(unsigned long long)blob_len);
		goto out;
	}
	ok = 1;
out:
	free(path);
	return ok;
}

/* id<TAB>text per line. Absent is allowed: a module may report nothing by name. */
static int names_load(struct artefact *a)
{
	char *path = sibling(a->stem, ".names"), line[256];
	FILE *f;
	size_t text_cap = 0, text_len = 0;
	uint32_t cap = 0, i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* nothing to report by name */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *tab = strchr(line, '\t'), *nl;
		size_t tl;

		if (!tab)
			continue;
		*tab++ = 0;
		nl = strchr(tab, '\n');
		if (nl)
			*nl = 0;
		tl = strlen(tab) + 1;

		if (text_len + tl > text_cap) {
			size_t nc = text_cap ? text_cap * 2 : 512;
			char *nt;
			while (nc < text_len + tl)
				nc *= 2;
			nt = realloc(a->name_text, nc);
			if (!nt)
				goto out;
			a->name_text = nt;
			text_cap = nc;
		}
		if (a->n_names == cap) {
			uint32_t nc = cap ? cap * 2 : 8;
			struct kof_pw_name *nv = realloc(a->name, nc * sizeof *nv);
			if (!nv)
				goto out;
			a->name = nv;
			cap = nc;
		}
		memcpy(a->name_text + text_len, tab, tl);
		/* An offset now, a pointer once the buffer stops moving: it is
		 * reallocated as it grows, so a pointer taken here would dangle. */
		a->name[a->n_names].id   = (uint32_t)strtoul(line, 0, 10);
		a->name[a->n_names].text = (const char *)(uintptr_t)text_len;
		a->n_names++;
		text_len += tl;
	}
	fclose(f);
	for (i = 0; i < a->n_names; i++)
		a->name[i].text = a->name_text + (uintptr_t)a->name[i].text;
	ok = 1;
out:
	free(path);
	return ok;
}

/*
 * Declared strings and ranges. Tab separated, kind in column one: 'r' for a range
 * mask, 's' for a string with the literal last so nothing in it needs escaping to
 * keep the earlier columns parseable.
 */
static int strs_load(struct artefact *a)
{
	char *path = sibling(a->stem, ".strs"), line[KOF_STR_MAX_LEN + 128];
	FILE *f;
	size_t bytes_cap = 0, bytes_len = 0;
	uint32_t scap = 0, rcap = 0, i;
	int ok = 0;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f) {
		ok = 1;                  /* a module may declare neither */
		goto out;
	}
	while (fgets(line, sizeof line, f)) {
		char *p = line, *tab;

		/* r <id> <mask> */
		if (p[0] == 'r' && p[1] == '\t') {
			p += 2;
			tab = strchr(p, '\t');
			if (!tab)
				continue;
			if (a->n_rng == rcap) {
				uint32_t nc = rcap ? rcap * 2 : 8;
				uint32_t *nv = realloc(a->rng, nc * sizeof *nv);
				if (!nv)
					goto out;
				a->rng = nv;
				rcap = nc;
			}
			a->rng[a->n_rng++] = (uint32_t)strtoul(tab + 1, 0, 10);
		/* s <id> <icase> <fullword> <len> <literal> */
		} else if (p[0] == 's' && p[1] == '\t') {
			unsigned long v[4], icase, fullw, len;
			char *lit;
			size_t actual;
			int k;

			p += 2;
			for (k = 0; k < 4; k++) {
				tab = strchr(p, '\t');
				if (!tab)
					break;
				*tab = 0;
				v[k] = strtoul(p, 0, 10);
				p = tab + 1;
			}
			if (k != 4) {
				fprintf(stderr, "ksigbuilder: %s: malformed string "
						"row\n", a->stem);
				goto out;
			}
			icase = v[1];
			fullw = v[2];
			len   = v[3];
			lit   = p;

			actual = strlen(lit);
			while (actual && (lit[actual - 1] == '\n' ||
					  lit[actual - 1] == '\r'))
				lit[--actual] = 0;

			/* The recorded length is authoritative - it is what the
			 * pattern compiler measured. Disagreeing with it is a
			 * build that went wrong, not a row to skip. */
			if (len == 0 || len > KOF_STR_MAX_LEN || actual != len) {
				fprintf(stderr, "ksigbuilder: %s: string of declared "
						"length %lu does not match its "
						"literal\n", a->stem, len);
				goto out;
			}
			if (bytes_len + len > bytes_cap) {
				size_t nc = bytes_cap ? bytes_cap * 2 : 1024;
				uint8_t *nb;
				while (nc < bytes_len + len)
					nc *= 2;
				nb = realloc(a->str_bytes, nc);
				if (!nb)
					goto out;
				a->str_bytes = nb;
				bytes_cap = nc;
			}
			if (a->n_str == scap) {
				uint32_t nc = scap ? scap * 2 : 8;
				struct kof_pw_str *nv = realloc(a->str,
								nc * sizeof *nv);
				if (!nv)
					goto out;
				a->str = nv;
				scap = nc;
			}
			memcpy(a->str_bytes + bytes_len, lit, len);
			a->str[a->n_str].bytes    = (const uint8_t *)(uintptr_t)bytes_len;
			a->str[a->n_str].len      = (uint16_t)len;
			a->str[a->n_str].icase    = (uint8_t)icase;
			a->str[a->n_str].fullword = (uint8_t)fullw;
			a->n_str++;
			bytes_len += len;
		}
	}
	fclose(f);
	for (i = 0; i < a->n_str; i++)
		a->str[i].bytes = a->str_bytes + (uintptr_t)a->str[i].bytes;
	ok = 1;
out:
	free(path);
	return ok;
}

static int artefact_load(struct artefact *a, const char *blob_path)
{
	size_t n = strlen(blob_path), len = 0;

	memset(a, 0, sizeof *a);
	a->stem = malloc(n - 5 + 1);
	if (!a->stem)
		return 0;
	memcpy(a->stem, blob_path, n - 5);
	a->stem[n - 5] = 0;

	a->code = read_whole(blob_path, KOF_BLOB_MAX_CODE, &len);
	if (!a->code) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", blob_path);
		return 0;
	}
	/* The same guard the loader applies, applied where a failure is a build
	 * failure rather than something a customer's machine discovers. */
	if (len >= 4 && memcmp(a->code, "\177ELF", 4) == 0) {
		fprintf(stderr, "ksigbuilder: %s is an ELF image, not a blob\n",
			blob_path);
		return 0;
	}
	a->code_len = (uint32_t)len;

	return meta_load(a) && names_load(a) && strs_load(a);
}

/* A set of artefacts sharing one grouping key, which is one pack. */
struct group {
	uint32_t  kind, target_mask, arch_mask;
	uint32_t *member;                /* indices into the artefact array */
	uint32_t  n, cap;
};

static int group_add(struct group *g, uint32_t idx)
{
	if (g->n == g->cap) {
		uint32_t nc = g->cap ? g->cap * 2 : 16;
		uint32_t *nv = realloc(g->member, nc * sizeof *nv);
		if (!nv)
			return 0;
		g->member = nv;
		g->cap = nc;
	}
	g->member[g->n++] = idx;
	return 1;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *f = fopen(path, "wb");
	size_t w;

	if (!f) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", path);
		return 0;
	}
	w = fwrite(data, 1, len, f);
	if (fclose(f) != 0 || w != len) {
		fprintf(stderr, "ksigbuilder: short write to %s\n", path);
		return 0;
	}
	return 1;
}

static const char *kind_name(uint32_t k)
{
	return k == KOF_PACK_UNPACK ? "unpack" : "detect";
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <artefact-dir> <out-dir>\n"
		"\n"
		"  <artefact-dir>  holds <name>.blob and the .meta, .strs and .names\n"
		"                  beside each one, as ksigcompiler.sh emits them\n",
		argv0);
}

int main(int argc, char **argv)
{
	const char *workdir = NULL, *outdir = NULL;
	int i, rc = 1;

	struct artefact *arts = NULL;
	uint32_t n_arts = 0, cap_arts = 0, a, j;
	struct group *groups = NULL;
	uint32_t n_groups = 0, cap_groups = 0;
	DIR *d = NULL;
	struct dirent *de;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			fprintf(stderr, "%s: unrecognised argument '%s'\n",
				argv[0], argv[i]);
			usage(argv[0]);
			return 2;
		} else if (!workdir)
			workdir = argv[i];
		else if (!outdir)
			outdir = argv[i];
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!workdir || !outdir) {
		usage(argv[0]);
		return 2;
	}

	d = opendir(workdir);
	if (!d) {
		fprintf(stderr, "ksigbuilder: cannot read %s\n", workdir);
		goto done;
	}
	while ((de = readdir(d)) != NULL) {
		size_t l = strlen(de->d_name);
		char *p;

		if (l < 6 || strcmp(de->d_name + l - 5, ".blob") != 0)
			continue;
		if (n_arts == cap_arts) {
			uint32_t nc = cap_arts ? cap_arts * 2 : 64;
			struct artefact *nv = realloc(arts, nc * sizeof *nv);
			if (!nv)
				goto done;
			arts = nv;
			cap_arts = nc;
		}
		p = join_path(workdir, de->d_name);
		if (!p)
			goto done;
		if (!artefact_load(&arts[n_arts], p)) {
			artefact_free(&arts[n_arts]);
			free(p);
			goto done;
		}
		free(p);
		n_arts++;
	}
	closedir(d);
	d = NULL;

	if (n_arts == 0) {
		fprintf(stderr, "ksigbuilder: no .blob artefacts in %s\n", workdir);
		goto done;
	}

	/* Linear scan over the groups: the number of distinct precondition tuples
	 * is small and does not grow with the number of signatures, which is the
	 * property that makes this cheap however large the set gets. */
	for (a = 0; a < n_arts; a++) {
		struct group *g = NULL;
		for (j = 0; j < n_groups; j++)
			if (groups[j].kind == arts[a].kind &&
			    groups[j].target_mask == arts[a].target_mask &&
			    groups[j].arch_mask == arts[a].arch_mask) {
				g = &groups[j];
				break;
			}
		if (!g) {
			if (n_groups == cap_groups) {
				uint32_t nc = cap_groups ? cap_groups * 2 : 8;
				struct group *nv = realloc(groups, nc * sizeof *nv);
				if (!nv)
					goto done;
				groups = nv;
				cap_groups = nc;
			}
			g = &groups[n_groups++];
			memset(g, 0, sizeof *g);
			g->kind        = arts[a].kind;
			g->target_mask = arts[a].target_mask;
			g->arch_mask   = arts[a].arch_mask;
		}
		if (!group_add(g, a))
			goto done;
	}

	printf("%u module(s) -> %u pack(s)\n", n_arts, n_groups);

	for (j = 0; j < n_groups; j++) {
		struct group *g = &groups[j];
		struct kof_pw_mod *pm;
		uint8_t *img;
		size_t img_len = 0;
		char path[4096];

		pm = calloc(g->n, sizeof *pm);
		if (!pm)
			goto done;
		for (a = 0; a < g->n; a++) {
			const struct artefact *s = &arts[g->member[a]];
			pm[a].code        = s->code;
			pm[a].code_len    = s->code_len;
			pm[a].target_mask = s->target_mask;
			pm[a].scan_mask   = s->scan_mask;
			pm[a].arch_mask   = s->arch_mask;
			pm[a].size_min    = s->size_min;
			pm[a].str         = s->str;
			pm[a].n_str       = s->n_str;
			pm[a].rng         = s->rng;
			pm[a].n_rng       = s->n_rng;
			pm[a].name        = s->name;
			pm[a].n_names     = s->n_names;
		}

		img = kof_pack_build(g->kind, pm, g->n, &img_len);
		free(pm);
		if (!img) {
			fprintf(stderr, "ksigbuilder: cannot build pack %u\n", j);
			goto done;
		}

		/* The name states the key, so a directory listing says what is in
		 * each file without opening any of them. */
		snprintf(path, sizeof path, "%s/%s-t%u-a%u.ksig", outdir,
			 kind_name(g->kind), g->target_mask, g->arch_mask);
		if (!write_file(path, img, img_len)) {
			free(img);
			goto done;
		}
		printf("  %-44s %5u module(s)  %8zu bytes\n", path, g->n, img_len);
		free(img);
	}

	rc = 0;
done:
	if (d)
		closedir(d);
	for (a = 0; a < n_arts; a++)
		artefact_free(&arts[a]);
	free(arts);
	for (j = 0; j < n_groups; j++)
		free(groups[j].member);
	free(groups);
	return rc;
}