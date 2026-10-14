/*
 * ksb_util.c - The small shared helpers: the error report, whole-file reads
 *    and writes, path joins.
 */

#include "ksb.h"

void ksb_err(struct ksb_ctx *ksb, int line, const char *msg)
{
	fprintf(stderr, "%s:%d: error: %s\n", ksb->src_name, line, msg);
	ksb->errors++;
}

/* Read the whole source. Needed because a macro invocation may wrap onto further
 * lines and its arguments have to be readable past the end of the line the macro
 * name is on. Signature sources are a few hundred lines, so there is no reason to
 * stream. */

char *ksb_slurp(const char *path, size_t *len_out)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long n;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	n = ftell(f);
	if (n < 0) { fclose(f); return NULL; }
	rewind(f);
	buf = malloc((size_t)n + 2);
	if (!buf) { fclose(f); return NULL; }
	if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf); fclose(f); return NULL;
	}
	fclose(f);
	buf[n] = 0;
	buf[n + 1] = 0;
	*len_out = (size_t)n;
	return buf;
}

/* <stem> + <ext> into a fresh string. */
char *ksb_sibling(const char *stem, const char *ext)
{
	size_t a = strlen(stem), b = strlen(ext);
	char *p = malloc(a + b + 1);

	if (!p)
		return NULL;
	memcpy(p, stem, a);
	memcpy(p + a, ext, b + 1);
	return p;
}

char *ksb_join_path(const char *dir, const char *leaf)
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
uint8_t *ksb_read_whole(const char *path, size_t cap, size_t *out_len)
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

int ksb_write_file(const char *path, const uint8_t *data, size_t len)
{
	/* Temp in the same directory, fsync, rename: a pack that a scanner has
	 * mapped is never truncated - see kof_write_file_atomic. */
	if (!kof_write_file_atomic(path, data, len)) {
		fprintf(stderr, "ksigbuilder: cannot write %s\n", path);
		return 0;
	}
	return 1;
}
