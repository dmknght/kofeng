/*
 * platform_nofollow.c - the platform layer's answer to "is this a regular file, not a link",
 * the reader that will not follow one, and the reentrant local time (kofplatform_file.h,
 * kofplatform_os.h).
 *
 * WHY A TEST OF ITS OWN: the signature editor (kofexamine/kofeditor_tree.c, kofeditor_save.c)
 * refuses a link where a diagnose source should be - reading through one, or deleting a file a
 * link was swapped in for, would act on a file outside the tree. It spelled that with lstat,
 * O_NOFOLLOW, O_CLOEXEC and localtime_r, none of which a Windows build has, so kofexaminer.exe and
 * kofviewer.exe did not compile (W-D1, W-D2, 2026-11-16). The platform functions carry the meaning
 * on both systems, and this test is written once for both: it runs in `make unit` on Linux and is
 * cross-built and run under wine for the Windows half (a reparse point is the link there).
 *
 * The oracle for the time is the C library's own localtime() (not reentrant, used once here).
 * Scratch files go under build/test, never /tmp.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE        /* symlink, fcntl's FD_CLOEXEC, and what kofplatform.h calls (it says so) */
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../../libkofeng/kofcore/kofplatform.h"

static unsigned checks, fails;

#define CK(cond, ...) do { \
	checks++; \
	if (!(cond)) { \
		printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

static char dir[160];

static void path_of(char *out, size_t cap, const char *leaf)
{
	snprintf(out, cap, "%s/%s", dir, leaf);
}

#ifdef _WIN32
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#endif

/* A file symlink, the way each system makes one. 0 on success.
 * On Windows the success is checked by listing the directory entry (FindFirstFileA does not follow a
 * link): wine 10 answers TRUE from CreateSymbolicLinkA and makes nothing (measured 2026-11-16), and a
 * link that is not there would make every link case below test a missing file instead. */
static int make_link(const char *target, const char *link)
{
#ifdef _WIN32
	WIN32_FIND_DATAA fd;
	HANDLE h;

	if (!CreateSymbolicLinkA(link, target, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
		return -1;
	h = FindFirstFileA(link, &fd);
	if (h == INVALID_HANDLE_VALUE)
		return -1;
	FindClose(h);
	return 0;
#else
	return symlink(target, link);
#endif
}

static int write_file(const char *p, const char *text)
{
	FILE *f = fopen(p, "wb");

	if (!f)
		return -1;
	fputs(text, f);
	return fclose(f);
}

/* The read side never hands a child process the descriptor: FD_CLOEXEC on POSIX, a handle that is
 * not inheritable on Windows. */
static int not_inherited(FILE *f)
{
#ifdef _WIN32
	DWORD fl = 0;
	HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));

	return h != INVALID_HANDLE_VALUE && GetHandleInformation(h, &fl) && !(fl & HANDLE_FLAG_INHERIT);
#else
	int fl = fcntl(fileno(f), F_GETFD);

	return fl >= 0 && (fl & FD_CLOEXEC);
#endif
}

static void t_kind_and_read(void)
{
	char reg[256], lnk[256], dangling[256], miss[256], deep[256], sub[256], buf[16];
	struct stat st;
	FILE *f;
	size_t n;
	int have_link;

	path_of(reg, sizeof reg, "reg.c");
	path_of(lnk, sizeof lnk, "lnk.c");
	path_of(dangling, sizeof dangling, "dangling.c");
	path_of(miss, sizeof miss, "missing.c");
	path_of(deep, sizeof deep, "nodir/x.c");
	path_of(sub, sizeof sub, "sub");

	CK(write_file(reg, "abc") == 0, "write the regular file");

	/* a regular file: accepted, its size read, and opened */
	memset(&st, 0, sizeof st);
	CK(kof_path_kind(reg, &st) == KOF_PATH_REGULAR && st.st_size == 3, "a regular file is REGULAR, size 3");
	f = kof_fopen_read_nofollow(reg);
	CK(f != NULL, "a regular file is opened");
	if (f) {
		n = fread(buf, 1, sizeof buf, f);
		CK(n == 3 && memcmp(buf, "abc", 3) == 0, "and reads what was written");
		CK(not_inherited(f), "the descriptor is not inherited by a child (O_CLOEXEC / no handle inheritance)");
		fclose(f);
	}

	/* missing: MISSING, never ERROR, and nothing is opened */
	errno = 0;
	CK(kof_path_kind(miss, &st) == KOF_PATH_MISSING && errno == ENOENT, "a missing file is MISSING with ENOENT");
	CK(kof_path_kind(deep, &st) == KOF_PATH_MISSING, "a file under a missing directory is MISSING");
	CK(kof_fopen_read_nofollow(miss) == NULL, "a missing file is not opened");

	/* a directory: OTHER (neither a file to read nor a link) */
	CK(kof_mkdir(sub, 0700) == 0, "make a subdirectory");
	CK(kof_path_kind(sub, &st) == KOF_PATH_OTHER, "a directory is OTHER");

	/* a link to the regular file: LINK, and the opener refuses it */
	have_link = make_link("reg.c", lnk) == 0;   /* a link's target is relative to the link's own directory */
	if (!have_link) {
		printf("  this host made no symlink here (no privilege, or wine): the link cases did NOT run\n");
	} else {
		f = fopen(lnk, "rb");
		CK(f != NULL, "the link is live (an ordinary fopen follows it), so the refusal below is a refusal");
		if (f)
			fclose(f);
		CK(kof_path_kind(lnk, &st) == KOF_PATH_LINK, "a symlink is LINK, not the file it points at");
		errno = 0;
		f = kof_fopen_read_nofollow(lnk);
		CK(f == NULL, "the opener refuses a symlink");
		if (f)
			fclose(f);
		/* a dangling link is a LINK too: "missing" is said only of a name that is not there */
		CK(make_link("missing.c", dangling) == 0, "make a dangling symlink");
		CK(kof_path_kind(dangling, &st) == KOF_PATH_LINK, "a dangling symlink is LINK, not MISSING");
		CK(kof_fopen_read_nofollow(dangling) == NULL, "and is not opened");
		CK(kof_path_kind(reg, &st) == KOF_PATH_REGULAR && st.st_size == 3, "the target is untouched");
	}

	remove(lnk);
	remove(dangling);
	remove(reg);
#ifdef _WIN32
	RemoveDirectoryA(sub);
#else
	rmdir(sub);
#endif
}

static void t_localtime(void)
{
	const time_t when[] = { 0, 86400 * 365, 1700000000, 2000000000 };
	size_t i;

	for (i = 0; i < sizeof when / sizeof when[0]; i++) {
		struct tm mine, *ref;
		struct tm oracle;

		memset(&mine, 0x55, sizeof mine);
		CK(kof_localtime(&when[i], &mine) == &mine, "kof_localtime answers into the caller's struct (%lld)", (long long)when[i]);
		ref = localtime(&when[i]);
		CK(ref != NULL, "the oracle answers");
		if (!ref)
			continue;
		oracle = *ref;
		CK(mine.tm_year == oracle.tm_year && mine.tm_mon == oracle.tm_mon && mine.tm_mday == oracle.tm_mday &&
		   mine.tm_hour == oracle.tm_hour && mine.tm_min == oracle.tm_min && mine.tm_sec == oracle.tm_sec &&
		   mine.tm_wday == oracle.tm_wday && mine.tm_yday == oracle.tm_yday,
		   "kof_localtime agrees with localtime() (%lld)", (long long)when[i]);
	}
}

int main(void)
{
#ifdef _WIN32
	unsigned long pid = (unsigned long)GetCurrentProcessId();
#else
	unsigned long pid = (unsigned long)getpid();
#endif

	snprintf(dir, sizeof dir, "build/test/platform_nofollow_%lu", pid);
	if (kof_mkdir(dir, 0700) != 0) {
		printf("platform_nofollow: no build/test directory - nothing tested\n");
		return 1;
	}
	t_kind_and_read();
	t_localtime();
#ifdef _WIN32
	RemoveDirectoryA(dir);
#else
	rmdir(dir);
#endif
	printf("platform_nofollow: %u checks, %u failed\n", checks, fails);
	return fails != 0;
}
