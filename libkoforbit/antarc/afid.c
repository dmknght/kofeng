/*
 * afid.c - see afid.h.
 *
 * One stat, and the fields chosen are argued in fidset.h. What is NOT here is
 * as deliberate as what is: no access time, because reading a file changes it
 * and a scanner keying on one would invalidate every entry by looking at it;
 * no mode bits, because a chmod across a tree changes no content and would
 * throw the cache away for nothing.
 */

#define _GNU_SOURCE

#include <string.h>
#include <sys/stat.h>

#include "afid.h"

static void from_stat(const struct stat *st, struct kof_fid *out)
{
	uint64_t dev = (uint64_t)st->st_dev;
	uint64_t ino = (uint64_t)st->st_ino;

	memset(out, 0, sizeof *out);
	/*
	 * The low eight bytes of each, and the rest left zero.
	 *
	 * Sixteen is what Windows needs - a volume GUID and a 128 bit file
	 * reference - and one struct that is eight bytes wider than Linux needs
	 * is better than two structs that mean the same thing. The zeroes cost
	 * nothing: they are hashed like everything else and they are the same
	 * on every Linux file, so they carry no information and remove none.
	 */
	memcpy(out->volume, &dev, sizeof dev);
	memcpy(out->node, &ino, sizeof ino);
	out->size = (uint64_t)st->st_size;
	/*
	 * NANOSECONDS, and ctime as well as mtime.
	 *
	 * mtime is what a writer sets and what a writer can set BACK. ctime
	 * moves when the inode changes and is not settable through the normal
	 * interface - utimensat moves atime and mtime and leaves ctime at the
	 * moment of the call. So a file rewritten and stamped back to its old
	 * mtime still has a ctime that says something happened.
	 *
	 * That is not a defence - root can set the clock, and a filesystem can
	 * be edited offline - it is one more thing an attacker has to get
	 * right, and it costs nothing to ask for.
	 */
	out->born = (uint64_t)st->st_ctime * 1000000000ull +
		    (uint64_t)st->st_ctim.tv_nsec;
	out->written = (uint64_t)st->st_mtime * 1000000000ull +
		       (uint64_t)st->st_mtim.tv_nsec;
}

int kof_fid_of(const char *path, struct kof_fid *out)
{
	struct stat st;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (!path || !path[0])
		return 0;
	/*
	 * lstat, not stat: a symlink is its own file and its own identity. Two
	 * links to one target would otherwise share a key, so calling one clean
	 * would speak for the other - and a link is exactly what an attacker
	 * points somewhere else afterwards.
	 */
	if (lstat(path, &st) != 0)
		return 0;
	if (!S_ISREG(st.st_mode))
		return 0;       /* only a regular file has content to cache */
	from_stat(&st, out);
	return 1;
}

int kofa_fid_of_fd(int fd, struct kof_fid *out)
{
	struct stat st;

	if (!out)
		return 0;
	memset(out, 0, sizeof *out);
	if (fd < 0 || fstat(fd, &st) != 0)
		return 0;
	if (!S_ISREG(st.st_mode))
		return 0;
	from_stat(&st, out);
	return 1;
}
