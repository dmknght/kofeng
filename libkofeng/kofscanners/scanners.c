/*
 * scanners.c - the orchestrator, and the one producer that exists.
 *
 * Two jobs that belong together because one drives the other:
 *
 *   a producer turns something into bytes                (a file, for now)
 *   the orchestrator walks the objects those bytes contain
 *
 * A producer never calls the scanner; the scanner calls a producer and then scans what
 * it got, so dependencies point one way and there is no wrapping-and-calling-back.
 *
 * What is deliberately not here yet, with the reason:
 *
 *   - format dispatch. scan.c has one parser wired in; a table of {probe, parse}
 *     belongs in kofparsers once there is a second format to put in it.
 *   - archive children. No unpacker or extractor exists. Note the order that will be
 *     needed when there is: the signature pass runs *before* extraction, because the
 *     extractor is the thing an archive exploit attacks - ClamAV parses first and only
 *     raw-scans afterwards, which is why its early scan sits behind a self-protection
 *     flag.
 *   - byte budgets. Nothing is decompressed yet, so there is no amplification to cap.
 */

/* lstat and the dirent walk are POSIX and the tree builds as strict ISO C11, so the
 * feature level has to be asked for - and before any include, or it does nothing. */
#define _POSIX_C_SOURCE 200809L

#include "scan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/*
 * Map a file read only.
 *
 * mmap rather than read: only the pages a scan actually touches are faulted in, so
 * scoping a search to a region cuts I/O and not merely CPU. It is also what makes an
 * embedded object free later - a child at an offset inside its parent is a window into
 * the same mapping, needing no copy.
 */
struct mapping {
	void    *map;
	uint64_t len;
};

static int map_file(struct mapping *s, const char *path)
{
	struct stat sb;
	int fd;

	s->map = NULL;
	s->len = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return KOF_ERR_OPEN;
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
		close(fd);
		return KOF_ERR_OPEN;
	}
	if (sb.st_size > 0) {
		s->map = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (s->map == MAP_FAILED) {
			s->map = NULL;
			close(fd);
			return KOF_ERR_READ;
		}
	}
	close(fd);
	s->len = (uint64_t)sb.st_size;
	return 0;
}

static void unmap_file(struct mapping *s)
{
	if (s->map)
		munmap(s->map, (size_t)s->len);
	s->map = NULL;
}

/*
 * Iterative, with its own stack of pending directories.
 *
 * Not recursive, and no depth ceiling: a filesystem may legally be deeper than any
 * number picked here, and putting the limit on the C stack makes the failure mode a
 * stack overflow - a crash, in a library, out of a directory tree. On the heap, running
 * out is reported instead. max_depth is policy for callers who want it, not a safety
 * net.
 *
 * Paths grow rather than living in a fixed buffer, so an over-long one fails visibly
 * instead of being skipped without a word.
 */
struct pending {
	char    *path;
	uint32_t depth;
};

struct walk {
	struct kof_scanner *sc;
	const struct kof_policy *pol;
	kof_on_object cb;
	void *user;

	struct pending *stack;
	size_t          n, cap;

	char   *path_buf;     /* reusable, holds the entry currently being examined */
	size_t  path_cap;

	int      aborted;
	int      out_of_memory;
	uint64_t objects;
};

static int push_dir(struct walk *w, const char *path, size_t len, uint32_t depth)
{
	if (w->n == w->cap) {
		size_t nc = w->cap ? w->cap * 2 : 64;
		struct pending *nv = realloc(w->stack, nc * sizeof *nv);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->stack = nv;
		w->cap = nc;
	}
	w->stack[w->n].path = kof_strdup_n(path, len);
	if (!w->stack[w->n].path) {
		w->out_of_memory = 1;
		return 0;
	}
	w->stack[w->n].depth = depth;
	w->n++;
	return 1;
}

/* Grow the reusable buffer to hold at least `need` bytes including the terminator. */
static int path_reserve(struct walk *w, size_t need)
{
	if (need <= w->path_cap)
		return 1;
	{
		size_t nc = w->path_cap ? w->path_cap : 256;
		char *nv;
		while (nc < need)
			nc *= 2;
		nv = realloc(w->path_buf, nc);
		if (!nv) {
			w->out_of_memory = 1;
			return 0;
		}
		w->path_buf = nv;
		w->path_cap = nc;
	}
	return 1;
}

static void scan_file(struct walk *w, const char *path)
{
	struct kof_result res;
	struct mapping src;

	res.n = 0;
	res.dropped = 0;

	if (map_file(&src, path) != 0) {
		kof_scan_count_unreadable(w->sc);
		return;
	}

	/*
	 * One layer. When there are archive children this becomes the same stack the
	 * directory walk uses: scan the layer, then push each child a producer yields.
	 */
	kof_scan_object(w->sc, kof_buf_make(src.map, src.len), path, &res);
	unmap_file(&src);

	w->objects++;
	if (w->cb && w->cb(path, &res, w->user) != 0)
		w->aborted = 1;
}

static void read_dir(struct walk *w, const char *dir, uint32_t depth)
{
	size_t dir_len = strlen(dir);
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d) {
		/* Unreadable, or a path the system would not accept. Counted, because a
		 * subtree that silently vanishes reads as a subtree with nothing in it. */
		kof_scan_count_unreadable(w->sc);
		return;
	}
	while (!w->aborted && !w->out_of_memory && (de = readdir(d)) != NULL) {
		size_t nl, total;
		struct stat sb;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		nl = strlen(de->d_name);
		total = dir_len + 1 + nl + 1;
		if (!path_reserve(w, total))
			break;
		memcpy(w->path_buf, dir, dir_len);
		w->path_buf[dir_len] = '/';
		memcpy(w->path_buf + dir_len + 1, de->d_name, nl + 1);

		/* lstat, not stat: a symlink is not followed unless asked for, so a link
		 * pointing at an ancestor cannot turn this into a loop. */
		if ((w->pol->follow_symlinks ? stat : lstat)(w->path_buf, &sb) != 0) {
			kof_scan_count_unreadable(w->sc);
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (!w->pol->recurse_dirs)
				continue;
			if (w->pol->max_depth && depth + 1 > w->pol->max_depth)
				continue;
			push_dir(w, w->path_buf, dir_len + 1 + nl, depth + 1);
		} else if (S_ISREG(sb.st_mode)) {
			scan_file(w, w->path_buf);
		}
		/* anything else - socket, device, fifo - is not an object */
	}
	closedir(d);
}

int kof_scan_walk(struct kof_scanner *sc, const char *path,
		  const struct kof_policy *pol, kof_on_object cb, void *user)
{
	struct walk w;
	struct stat sb;
	int rc;

	memset(&w, 0, sizeof w);
	w.sc   = sc;
	w.pol  = pol;
	w.cb   = cb;
	w.user = user;

	if ((pol->follow_symlinks ? stat : lstat)(path, &sb) != 0)
		return KOF_ERR_OPEN;

	if (!S_ISDIR(sb.st_mode)) {
		scan_file(&w, path);
		rc = w.objects ? (int)w.objects : KOF_ERR_OPEN;
		free(w.path_buf);
		return rc;
	}

	if (!pol->recurse_dirs) {
		return KOF_ERR_OPEN;
	}

	{
		/* A trailing slash would put "//" in every child path. */
		size_t n = strlen(path);
		while (n > 1 && path[n - 1] == '/')
			n--;
		if (!push_dir(&w, path, n, 0))
			goto done;
	}

	/* Depth first, by taking from the end: a directory's children are examined
	 * before its siblings, which keeps the pending set small and the page cache
	 * warm. Breadth first would hold a whole level at once. */
	while (!w.aborted && !w.out_of_memory && w.n > 0) {
		struct pending p = w.stack[--w.n];
		read_dir(&w, p.path, p.depth);
		free(p.path);
	}

done:
	while (w.n > 0)
		free(w.stack[--w.n].path);
	free(w.stack);
	free(w.path_buf);
	/* Running out of heap mid-walk is reported, not fatal: what was scanned before
	 * it is still a result, and the caller can tell the walk was cut short. */
	return (int)w.objects;
}