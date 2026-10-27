/*
 * aproc_int.h - what the two units of the process walk share (aproc.c, aproc_pmem.c).
 * Private to libkoforbit/antarc/.
 */

#ifndef KOFANTARC_APROC_INT_H
#define KOFANTARC_APROC_INT_H

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include "aproc.h"
#include "apagemap.h"

#define APATH_MAX 4096

/*
 * Parse the fields this library wants out of /proc/<pid>/stat.
 *
 * THE COMM FIELD IS WHY THIS IS NOT A scanf. It is the executable's name in
 * parentheses, it is not escaped, and it may contain both spaces and
 * parentheses - a process can be called "foo) 1 2 3 (bar". Every parser that
 * splits on whitespace gets a wrong ppid for those, and only for those, which
 * is the kind of bug that survives for years. The only correct split is at the
 * LAST ')' in the line.
 */
struct a_stat {
	uint32_t ppid;
	uint32_t flags;
	uint64_t start_time;
	char     comm[64];
	/* Set by kofa_read_stat when the open or the read FAILED (as opposed to
	 * the text being malformed); only meaningful with KOFA_ERR_OS. */
	uint8_t  io_err;
};

int kofa_read_stat(uint32_t pid, struct a_stat *out);

/* What a failed open or read of a /proc/<pid>/ file means, from its errno: the
 * process left (ENOENT, ESRCH: KOFA_ERR_GONE, routine), it was refused (EACCES,
 * EPERM: KOFA_ERR_DENIED), or anything else - EMFILE, ENFILE, ENOMEM, EIO, EINTR -
 * is the machine failing the walk and is KOFA_ERR_OS, never "gone". */
int kofa_proc_errno_status(int e);
void kofa_read_exe(uint32_t pid, char *buf, size_t cap, uint32_t *flags);

#endif /* KOFANTARC_APROC_INT_H */
