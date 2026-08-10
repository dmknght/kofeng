/*
 * objsrc.c - lifetimes for object bytes.
 *
 * Nothing here knows what an object is. It owns mappings, buffers and descriptors,
 * counts references, and releases each kind the way that kind needs releasing. The
 * whole file is about one question - when do these bytes stop being valid - which
 * is why it is not in scan.c with the code that reads them.
 *
 * One struct for all three kinds rather than a tagged union: each field is a
 * resource to release if it is set, and release order falls out of the order they
 * are checked. Adding a fourth kind is adding a field, not a case to every switch.
 */

/* Before any include. O_TMPFILE is a GNU extension and mmap is POSIX; a feature
 * test macro after the first include does nothing at all. */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "objsrc.h"
#include "../kofeng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct kof_objsrc {
	const uint8_t *p;
	uint64_t       n;
	uint32_t       refs;

	/* Each set field is a resource this source owns. */
	void              *map;      /* munmap(map, map_len) */
	size_t             map_len;
	uint8_t           *heap;     /* free() */
	struct kof_objsrc *parent;   /* unref: a window keeps its parent alive */

	/* Non-zero only for bytes the engine produced, which are the only ones it
	 * had to find memory for. */
	uint64_t           produced;
};

static struct kof_objsrc *src_new(void)
{
	struct kof_objsrc *s = calloc(1, sizeof *s);

	if (s)
		s->refs = 1;
	return s;
}

struct kof_objsrc *kof_src_file(const char *path, int *err)
{
	struct kof_objsrc *s;
	struct stat sb;
	int fd;

	*err = KOF_ERR_OPEN;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return NULL;
	}
	s = src_new();
	if (!s) {
		close(fd);
		return NULL;
	}
	if (sb.st_size > 0) {
		s->map = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (s->map == MAP_FAILED) {
			s->map = NULL;
			close(fd);
			free(s);
			*err = KOF_ERR_READ;
			return NULL;
		}
		s->map_len = (size_t)sb.st_size;
		s->p = s->map;
		s->n = (uint64_t)sb.st_size;
	}
	/* The descriptor is closed at once: a mapping keeps the file alive on its
	 * own, and one open descriptor per object in flight would be a descriptor
	 * spent on nothing. */
	close(fd);
	*err = 0;
	return s;
}

struct kof_objsrc *kof_src_window(struct kof_objsrc *parent, uint64_t off,
				  uint64_t len)
{
	struct kof_objsrc *s;
	uint64_t got;

	if (!parent)
		return NULL;
	/* Clipped, not refused: the offsets come from a parser reading a file, so
	 * a range that runs past the end is the normal hostile case rather than a
	 * programming error. */
	got = kof_clip_len(parent->n, off, len);
	if (got == 0)
		return NULL;

	s = src_new();
	if (!s)
		return NULL;
	s->parent = kof_src_ref(parent);
	s->p = parent->p + off;
	s->n = got;
	return s;
}

struct kof_objsrc *kof_src_heap(uint8_t *bytes, uint64_t len)
{
	struct kof_objsrc *s = src_new();

	if (!s) {
		free(bytes);
		return NULL;
	}
	s->heap = bytes;
	s->p = bytes;
	s->n = len;
	s->produced = len;
	return s;
}

struct kof_objsrc *kof_src_fd(int fd, uint64_t len)
{
	struct kof_objsrc *s = src_new();

	if (!s) {
		close(fd);
		return NULL;
	}
	if (len > 0) {
		s->map = mmap(NULL, (size_t)len, PROT_READ, MAP_PRIVATE, fd, 0);
		if (s->map == MAP_FAILED) {
			s->map = NULL;
			close(fd);
			free(s);
			return NULL;
		}
		s->map_len = (size_t)len;
		s->p = s->map;
		s->n = len;
	}
	/* Charged as produced even though it is file backed: a temporary directory
	 * is very often tmpfs, where these pages are memory and are capped by a
	 * mount option this code cannot see. */
	s->produced = len;
	close(fd);
	return s;
}

struct kof_objsrc *kof_src_ref(struct kof_objsrc *s)
{
	if (s)
		s->refs++;
	return s;
}

void kof_src_unref(struct kof_objsrc *s)
{
	while (s && --s->refs == 0) {
		struct kof_objsrc *parent = s->parent;

		if (s->map)
			munmap(s->map, s->map_len);
		free(s->heap);
		free(s);
		/* Iterating rather than recursing: a chain of windows can be as deep
		 * as the object tree, and releasing the root of one should not put
		 * that depth on the C stack. */
		s = parent;
	}
}

kof_buf kof_src_buf(const struct kof_objsrc *s)
{
	return s ? kof_buf_make(s->p, s->n) : kof_buf_make(NULL, 0);
}

uint64_t kof_src_produced(const struct kof_objsrc *s)
{
	return s ? s->produced : 0;
}

int kof_src_tmpfile(void)
{
	static const char *const dirs[] = { NULL, "/tmp", "/var/tmp" };
	const char *env = getenv("TMPDIR");
	uint32_t i;

	for (i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
		const char *d = dirs[i] ? dirs[i] : env;
		char path[4096];
		int fd;

		if (!d || !*d)
			continue;
#ifdef O_TMPFILE
		/* No directory entry is ever created, so there is nothing to
		 * traverse to, nothing to race, and nothing to clean up. */
		fd = open(d, O_TMPFILE | O_RDWR | O_EXCL, 0600);
		if (fd >= 0)
			return fd;
#endif
		/* Same property one syscall later: the name exists only between
		 * these two calls, and never holds anything. */
		if ((size_t)snprintf(path, sizeof path, "%s/kofXXXXXX", d) >=
		    sizeof path)
			continue;
		fd = mkstemp(path);
		if (fd >= 0) {
			unlink(path);
			return fd;
		}
	}
	return -1;
}