/* See kofpath.h. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "kofpath.h"

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define KOF_DIRNAME "kofeng"

const char *kof_path_why(int rc)
{
	switch (rc) {
	case KOF_PATH_OK:          return "ok";
	case KOF_PATH_NO_HOME:     return "no home directory for this account";
	case KOF_PATH_TOO_LONG:    return "the path does not fit";
	case KOF_PATH_MKDIR:       return "could not be created";
	case KOF_PATH_NOT_DIR:     return "exists and is not a directory";
	case KOF_PATH_FOREIGN:     return "is owned by somebody else";
	case KOF_PATH_WIDE_OPEN:   return "can be written by group or world";
	case KOF_PATH_UNSUPPORTED: return "not supported on this platform";
	default:                   return "?";
	}
}

#ifndef _WIN32

/*
 * Make one directory, tolerating that it is already there. Not a whole path:
 * every path this file builds has exactly one component that may be missing,
 * so a recursive mkdir would be code with no caller and one more way to
 * create something in the wrong place.
 */
static int mk(const char *p)
{
	if (mkdir(p, 0700) == 0)
		return 1;
	return errno == EEXIST;
}

/*
 * OPEN IT, THEN ASK ABOUT THE HANDLE.
 *
 * stat() answers about a name, and a name can be replaced between the answer
 * and the use - the classic swap. fstat on the descriptor that will be used
 * answers about the directory itself, so what is checked is what is opened.
 */
static int check(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0)
		return KOF_PATH_NOT_DIR;
	if (fstat(fd, &st) != 0) {
		close(fd);
		return KOF_PATH_NOT_DIR;
	}
	close(fd);

	if (!S_ISDIR(st.st_mode))
		return KOF_PATH_NOT_DIR;
	/*
	 * OURS, by effective uid. Root owning it is accepted when we ARE root
	 * and not otherwise - a directory somebody else owns is a directory
	 * somebody else can replace the contents of.
	 */
	if (st.st_uid != geteuid())
		return KOF_PATH_FOREIGN;
	/*
	 * And private. A verdict cache that group or world may write is a file
	 * in which anyone can declare their own payload clean, and a served
	 * hit looks exactly like a file that was examined.
	 */
	if (st.st_mode & (S_IWGRP | S_IWOTH))
		return KOF_PATH_WIDE_OPEN;
	return KOF_PATH_OK;
}

int kof_path_dir(int kind, char *out, size_t cap)
{
	struct passwd pw, *res = NULL;
	char pwbuf[4096];
	char parent[1024];
	const char *sub;

	if (!out || cap < 2)
		return KOF_PATH_TOO_LONG;
	out[0] = '\0';

	if (geteuid() == 0) {
		/* A service's state does not live in root's home: it lives
		 * where a package manager and an operator expect it. */
		if (snprintf(out, cap, "/var/%s/%s",
			     kind == KOF_PATH_STATE ? "lib" : "cache",
			     KOF_DIRNAME) >= (int)cap)
			return KOF_PATH_TOO_LONG;
		if (!mk(out))
			return KOF_PATH_MKDIR;
		return check(out);
	}

	/*
	 * THE PASSWORD DATABASE, NOT THE ENVIRONMENT - see kofpath.h for the
	 * measurement that settled it. geteuid and not getuid: a setuid tool
	 * keeps the state of the account it is running as.
	 */
	if (getpwuid_r(geteuid(), &pw, pwbuf, sizeof pwbuf, &res) != 0 ||
	    !res || !pw.pw_dir || !pw.pw_dir[0])
		return KOF_PATH_NO_HOME;

	sub = (kind == KOF_PATH_STATE) ? ".local" : ".cache";
	if (snprintf(parent, sizeof parent, "%s/%s", pw.pw_dir, sub) >=
	    (int)sizeof parent)
		return KOF_PATH_TOO_LONG;
	if (!mk(parent))
		return KOF_PATH_MKDIR;

	if (kind == KOF_PATH_STATE) {
		char mid[1024];

		if (snprintf(mid, sizeof mid, "%s/state", parent) >=
		    (int)sizeof mid)
			return KOF_PATH_TOO_LONG;
		if (!mk(mid))
			return KOF_PATH_MKDIR;
		if (snprintf(out, cap, "%s/%s", mid, KOF_DIRNAME) >= (int)cap)
			return KOF_PATH_TOO_LONG;
	} else {
		if (snprintf(out, cap, "%s/%s", parent, KOF_DIRNAME) >=
		    (int)cap)
			return KOF_PATH_TOO_LONG;
	}
	if (!mk(out))
		return KOF_PATH_MKDIR;
	return check(out);
}

#else  /* _WIN32 */

/*
 * SHGetKnownFolderPath AND NOT %LOCALAPPDATA%, for the reason the POSIX side
 * does not read $HOME: an environment variable describes the process that set
 * it. FOLDERID_LocalAppData is the account's own, and FOLDERID_ProgramData is
 * where a service's state belongs.
 *
 * NOT VERIFIED ON A WINDOWS BUILD. This half was written on a host with no
 * Windows toolchain; the API and the folder ids are from the documentation,
 * and the ownership check the POSIX side performs has no equivalent here yet -
 * the right one is a DACL check, which is not a line of code. Until that
 * exists a Windows caller gets a path and no assurance about who can write it,
 * and kofpath.h's promise is therefore only kept on POSIX. Said here rather
 * than discovered.
 */
int kof_path_dir(int kind, char *out, size_t cap)
{
	PWSTR w = NULL;
	char base[1024];
	int n;

	if (!out || cap < 2)
		return KOF_PATH_TOO_LONG;
	out[0] = '\0';

	if (SHGetKnownFolderPath(kind == KOF_PATH_STATE
				 ? &FOLDERID_ProgramData
				 : &FOLDERID_LocalAppData,
				 0, NULL, &w) != S_OK || !w)
		return KOF_PATH_NO_HOME;
	n = WideCharToMultiByte(CP_UTF8, 0, w, -1, base, (int)sizeof base,
				NULL, NULL);
	CoTaskMemFree(w);
	if (n <= 0)
		return KOF_PATH_TOO_LONG;

	if (snprintf(out, cap, "%s\\%s", base, KOF_DIRNAME) >= (int)cap)
		return KOF_PATH_TOO_LONG;
	if (!CreateDirectoryA(out, NULL) &&
	    GetLastError() != ERROR_ALREADY_EXISTS)
		return KOF_PATH_MKDIR;
	return KOF_PATH_OK;
}

#endif

int kof_path_file(int kind, const char *leaf, char *out, size_t cap)
{
	char dir[1024];
	int rc;

	if (!out || !leaf || !leaf[0])
		return KOF_PATH_TOO_LONG;
	/*
	 * A BARE NAME. Anything with a separator in it is a path somebody
	 * built out of something they were given, and this is the last place
	 * that can still refuse it.
	 */
	if (strchr(leaf, '/') || strchr(leaf, '\\') || strstr(leaf, ".."))
		return KOF_PATH_TOO_LONG;

	rc = kof_path_dir(kind, dir, sizeof dir);
	if (rc != KOF_PATH_OK) {
		snprintf(out, cap, "%s", dir);
		return rc;
	}
#ifdef _WIN32
	if (snprintf(out, cap, "%s\\%s", dir, leaf) >= (int)cap)
#else
	if (snprintf(out, cap, "%s/%s", dir, leaf) >= (int)cap)
#endif
		return KOF_PATH_TOO_LONG;
	return KOF_PATH_OK;
}
