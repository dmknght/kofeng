/*
 * kofplatform_file.h - paths and files: the separator, positional and whole writes,
 * the temp and cache directories, absolute paths, the openers that refuse a
 * symlink, rename over an existing file. *
 * A part of <kofplatform.h>, which includes it: include kofplatform.h, not this. Split
 * from it by purpose; the text is unchanged.
 */

#ifndef KOFENG_KOFPLATFORM_FILE_H
#define KOFENG_KOFPLATFORM_FILE_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "kofplatform_os.h"


/*
 * THE LAST PATH SEPARATOR, and it is not the same character on both systems.
 *
 * Windows accepts '/' as well as '\\' and mixes them freely - an argument typed
 * at a shell, a path built by this program and a path from the registry can
 * all end up in one string - so both count there.
 *
 * On POSIX only '/' counts, and treating '\\' as a separator would be a bug
 * rather than a kindness: a backslash is a perfectly legal character inside a
 * filename, so a file genuinely called "a\\b" would have its name cut in half.
 *
 * Returns a pointer past the separator, or the whole string when there is
 * none - which is what every caller wants for a display name.
 */
/* The separator to WRITE when joining a path. Both work on Windows; this is
 * the one that looks native in a message a person reads. */
#ifdef _WIN32
#define KOF_PATH_SEP '\\'
#else
#define KOF_PATH_SEP '/'
#endif

/*
 * COLLAPSE REPEATED SEPARATORS, and on Windows KEEP THE ONES THAT MEAN
 * SOMETHING.
 *
 * WHY THE ENGINE NEEDS THIS AT ALL. "//" is the separator an object name is
 * composed with - "archive.zip//3:entry" - and kobj_toplevel_len finds the
 * first one to tell a file from what came out of it. A filesystem path may
 * carry one too: a shell writing "$dir/" then "/name" makes one. The top level
 * file then reads as a CHILD of a directory that does not exist, and a caller
 * that decides anything by "is this the top level" - how many files were
 * scanned, whether a repair may be written - decides it wrongly.
 *
 * WHY IT IS HERE AND NOT IN THE WALK. It was in the walk, spelled for POSIX,
 * which is the shape this header exists to stop: a separator is '/' on one
 * platform and '/' or '\' on the other, and kof_path_sep_last three lines
 * down already knew that. One copy that knows both beats two copies that each
 * know one.
 *
 * AND WINDOWS IS NOT POSIX WITH A DIFFERENT SLASH. Two leading separators are
 * a PREFIX there, not a doubled one:
 *
 *     \\server\share\file     a UNC path - the pair IS the syntax
 *     \\?\C:\very\long\path   the extended-length prefix
 *     \\.\PhysicalDrive0       a device path
 *
 * Collapsing those turns a working path into one that names something else or
 * nothing at all, so the leading pair is kept and only what follows is
 * squashed. POSIX has no such rule - Linux reads "//x" as "/x" - and a name
 * this engine cannot spell unambiguously is worse than the ordinary spelling,
 * so there the pair collapses like any other run.
 *
 * Returns the length written, or 0 when it would not fit.
 */
static inline int kof_is_path_sep(char c)
{
#ifdef _WIN32
	return c == '/' || c == '\\';
#else
	return c == '/';
#endif
}

static inline size_t kof_path_squash(const char *in, char *out, size_t cap)
{
	size_t i = 0, n = 0;

	if (!in || !out || !cap)
		return 0;

#ifdef _WIN32
	/* The prefix, verbatim: see the note above. Only a PAIR, and only at
	 * the very start - three separators is not a longer prefix, it is a
	 * pair and a stray. */
	if (kof_is_path_sep(in[0]) && kof_is_path_sep(in[1])) {
		if (cap < 3u)
			return 0;
		out[n++] = in[i++];
		out[n++] = in[i++];
	}
#endif
	while (in[i]) {
		char c = in[i++];

		if (kof_is_path_sep(c) && n && kof_is_path_sep(out[n - 1]))
			continue;
		if (n + 1u >= cap)
			return 0;
		out[n++] = c;
	}
	/* And the trailing one, which every caller used to strip by hand. */
	while (n > 1u && kof_is_path_sep(out[n - 1u]))
		n--;
	out[n] = 0;
	return n;
}

static inline const char *kof_path_sep_last(const char *p)
{
	const char *s = NULL, *q;

	for (q = p; *q; q++) {
#ifdef _WIN32
		if (*q == '/' || *q == '\\')
#else
		if (*q == '/')
#endif
			s = q;
	}
	return s;
}

/* The name after it, or the whole string when there is none - which is what a
 * caller showing a display name wants. */
static inline const char *kof_path_base(const char *p)
{
	const char *s = kof_path_sep_last(p);

	return s ? s + 1 : p;
}

/*
 * WHERE SCRATCH FILES GO. Never NULL.
 *
 * TMPDIR is the POSIX spelling and Windows does not set it - it sets TMP, and
 * TEMP behind that. A caller that knows only the first name falls back to
 * "/tmp", which on Windows is a path that does not exist, and the failure
 * arrives as "cannot make a work directory" with nothing saying why.
 *
 * The current directory is the last resort rather than a failure: a test that
 * writes its scratch files beside the build output is untidy, and one that
 * cannot run at all is worse.
 */
/*
 * Write the whole buffer, or say it failed. Two problems, one function.
 *
 * THE COUNT. POSIX write() takes a size_t; Windows's takes an unsigned int,
 * and every caller in this tree had a size_t to give it. clang says so -
 * "implicit conversion loses integer precision" at four separate call sites -
 * and it is right: a length past 4GB does not merely warn, it writes the wrong
 * number of bytes. Chunking below the limit makes the cast true rather than
 * hopeful, and puts the platform difference in one place instead of four.
 *
 * THE SHORT WRITE. A write() that returns less than it was asked for has not
 * failed; it has been interrupted, or filled a pipe. Two of those four callers
 * compared the return against the full length and treated anything else as an
 * error, which is a bug that only shows up on the large objects this scanner
 * exists to read. Looping is the whole fix, and the two callers that already
 * looped were each carrying their own copy of it.
 *
 * Returns 1 on success and 0 on failure, like the rest of this header - not
 * the byte count, because no caller wanted one and a partial answer is what
 * the loop is here to remove.
 */
#define KOF_WRITE_CHUNK 0x10000000u  /* 256MB - comfortably inside an int */

/*
 * READ AND WRITE AT AN OFFSET, LEAVING THE FILE POSITION WHERE IT WAS.
 *
 * The one caller is a sink that is being appended to and has to look back at
 * what it already wrote - an unpacker whose header depends on something buried
 * in the content it has just produced. Seeking and not putting the position
 * back would append the next bytes over the old ones, so the position is saved
 * and restored around the access.
 *
 * Return the byte count, unlike kof_write_all above: a caller reading a
 * structure wants to know it got all of it, and a short read here is an
 * ordinary answer rather than a failure.
 */
static inline uint64_t kof_pos_io(int fd, uint64_t off, void *buf, uint64_t n,
				  int writing)
{
	unsigned char *p = (unsigned char *)buf;
	uint64_t done = 0;
#ifdef _WIN32
	__int64 keep = _lseeki64(fd, 0, SEEK_CUR);

	if (keep < 0 || _lseeki64(fd, (__int64)off, SEEK_SET) < 0)
		return 0;
#else
	off_t keep = lseek(fd, 0, SEEK_CUR);

	if (keep < 0 || lseek(fd, (off_t)off, SEEK_SET) < 0)
		return 0;
#endif
	while (done < n) {
		unsigned int want = n - done > KOF_WRITE_CHUNK
				  ? KOF_WRITE_CHUNK : (unsigned int)(n - done);
#ifdef _WIN32
		int k = writing ? _write(fd, p + done, want)
				: _read(fd, p + done, want);
#else
		ssize_t k = writing ? write(fd, p + done, want)
				    : read(fd, p + done, want);
#endif

		if (k <= 0)
			break;
		done += (uint64_t)k;
	}
#ifdef _WIN32
	_lseeki64(fd, keep, SEEK_SET);
#else
	lseek(fd, keep, SEEK_SET);
#endif
	return done;
}

static inline int kof_write_all(int fd, const void *buf, uint64_t n)
{
	const unsigned char *p = (const unsigned char *)buf;

	while (n) {
		unsigned int want = n > KOF_WRITE_CHUNK
				  ? KOF_WRITE_CHUNK : (unsigned int)n;
#ifdef _WIN32
		int k = _write(fd, p, want);
#else
		ssize_t k = write(fd, p, want);
#endif

		if (k <= 0)
			return 0;
		p += (size_t)k;
		n -= (uint64_t)k;
	}
	return 1;
}

/*
 * WHERE A TEMPORARY FILE MAY GO, from the platform and not from the
 * environment.
 *
 * This read TMPDIR, then TMP and TEMP, and that was wrong twice over. An
 * engine that is EMBEDDED does not get to decide where the host process
 * writes by reading that process's environment - the host owns that, and a
 * variable set for something else silently became engine policy. And an
 * environment variable is an input nobody validated: wherever the environment
 * is attacker-influenced, so was this path, and for a scanner started from a
 * service manager or a cron entry that is not nowhere.
 *
 * Windows HAS the call Windows programs are expected to use, and
 * GetTempPathA consults the documented places itself. POSIX has no such call,
 * and the honest answer is the standard's own constant: P_tmpdir, which
 * <stdio.h> defines and which is "/tmp" on every system this builds for. A
 * constant is not a lookup and cannot be steered.
 *
 * Returns a pointer that outlives the call - a static buffer on Windows, a
 * literal elsewhere - because every caller treats it as one.
 */
#ifdef _WIN32
static inline const char *kof_tmpdir(void)
{
	static char buf[4096];
	DWORD n = GetTempPathA((DWORD)sizeof buf, buf);

	if (!n || n >= sizeof buf)
		return ".";
	return buf;
}
#else
static inline const char *kof_tmpdir(void)
{
#ifdef P_tmpdir
	return P_tmpdir;
#else
	return "/tmp";
#endif
}
#endif

/*
 * IS `path` INSIDE `dir`, and if so, where does the part below it begin?
 *
 * Returns NULL when it is not, so a caller can tell "not in the tree" from "at
 * the top of it", which is an empty string rather than a null.
 *
 * Separators are compared as equals, and on Windows so is case. That is not
 * politeness: the two strings arriving here come from different places and
 * spell the same directory differently. A build names its sources the way they
 * were typed and its content tree the way GNU make's $(abspath) writes one -
 * forward slashes - while kof_abs_path answers through _fullpath, which writes
 * backslashes. Compared byte for byte the answer is "not inside" for a path
 * that plainly is, and the caller falls back to a bare basename: which is how
 * two sources both called shellcode_00.c, in different directories, came to
 * write over each other's artefacts and leave two modules out of the database
 * with nothing reporting it.
 *
 * The boundary is checked, not just the prefix - ".../bases" must not match
 * ".../basesuffix/x.c".
 */
static inline const char *kof_path_under(const char *path, const char *dir)
{
	size_t i;

	if (!path || !dir || !dir[0])
		return NULL;
	for (i = 0; dir[i]; i++) {
		char a = path[i], b = dir[i];

		if (!a)
			return NULL;
		if (a == '\\')
			a = '/';
		if (b == '\\')
			b = '/';
#ifdef _WIN32
		if (a >= 'A' && a <= 'Z')
			a = (char)(a - 'A' + 'a');
		if (b >= 'A' && b <= 'Z')
			b = (char)(b - 'A' + 'a');
#endif
		if (a != b)
			return NULL;
	}
	/* `dir` may or may not have been written with a trailing separator;
	 * either way what follows it has to start on one, or `path` is a
	 * different name that merely begins with these bytes. */
	if (i && (dir[i - 1] == '/' || dir[i - 1] == '\\'))
		return path + i;
	if (path[i] != '/' && path[i] != '\\')
		return NULL;
	while (path[i] == '/' || path[i] == '\\')
		i++;
	return path + i;
}

/*
 * An absolute path, with the platform's own resolver.
 *
 * Here rather than in a tool because more than one asks: the viewer resolves
 * the bases directory a draft is written into, and the database builder
 * resolves a source before working out where it sits inside the content tree.
 * Two copies of a path rule are two things to get differently wrong.
 */
#ifdef _WIN32
static inline int kof_abs_path(const char *in, char *out, size_t cap)
{
	char buf[4096];

	if (!_fullpath(buf, in, sizeof buf))
		return 0;
	if (strlen(buf) >= cap)
		return 0;
	memcpy(out, buf, strlen(buf) + 1u);
	return 1;
}
#else
static inline int kof_abs_path(const char *in, char *out, size_t cap)
{
	char buf[4096];

	if (!realpath(in, buf))
		return 0;
	if (strlen(buf) >= cap)
		return 0;
	memcpy(out, buf, strlen(buf) + 1u);
	return 1;
}
#endif

/*
 * Cut a file to `len`, with the platform's own call.
 *
 * Here beside the rest of the file primitives because a caller that repairs
 * an infected binary needs it and there is no portable spelling: POSIX has
 * truncate, Windows needs a handle and SetEndOfFile.
 */
#ifdef _WIN32
/*
 * OPEN AN EXISTING FILE TO REPAIR IT, AND SEEK IN IT WITH 64 BITS.
 *
 * Two things the repair path needs and plain fopen/fseek do not give it.
 *
 * NOT FOLLOWING A LINK. The file was identified by scanning THAT file; if the
 * name now points somewhere else, the thing to do is fail, not write into
 * whatever it points at. On POSIX that is O_NOFOLLOW. Windows has reparse
 * points rather than symlinks and _open cannot refuse them, so this side is
 * the same open the rest of this header does and the guarantee is the ACL's -
 * said here rather than implied, because the two platforms are not equal on
 * this point.
 *
 * SIXTY-FOUR BIT OFFSETS. fseek takes a long, and on mingw-w64 a long is
 * thirty-two bits: casting a uint64 offset to it is a wrap, and a wrapped
 * offset does not fail - it seeks somewhere else and the sixteen bytes of a
 * repair land in the middle of the user's file. An infected object larger than
 * 4 GB is unusual and the scanner maps one whole, so the offset really can get
 * there.
 */
/*
 * REFUSE A REPARSE POINT, which is what O_NOFOLLOW means on this side.
 *
 * _open cannot say it, so the handle is taken with
 * FILE_FLAG_OPEN_REPARSE_POINT - which opens the LINK rather than following it
 * - and then the attributes are read back and a reparse point is refused
 * outright. Opening the link and writing to it would be no better than
 * following it; the POSIX side refuses, so this refuses.
 *
 * A JUNCTION IS THE REASON THIS IS NOT ONLY ABOUT SYMLINKS. A directory
 * junction needs no privilege to create on any Windows since Vista, and a
 * file symlink needs one only outside Developer Mode - so "an unprivileged
 * process cannot plant one" is not true here the way it is on Linux.
 */
static inline HANDLE kof_win_open_nofollow(const char *path, DWORD access,
					   DWORD disposition, DWORD share)
{
	BY_HANDLE_FILE_INFORMATION bi;
	HANDLE h = CreateFileA(path, access, share, NULL, disposition,
			       FILE_ATTRIBUTE_NORMAL |
			       FILE_FLAG_OPEN_REPARSE_POINT, NULL);

	if (h == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;
	if (GetFileInformationByHandle(h, &bi) &&
	    (bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		CloseHandle(h);
		return INVALID_HANDLE_VALUE;
	}
	return h;
}

static inline FILE *kof_fopen_rw(const char *path)
{
	HANDLE h = kof_win_open_nofollow(path, GENERIC_READ | GENERIC_WRITE,
					 OPEN_EXISTING, 0);
	int fd;
	FILE *fp;

	if (h == INVALID_HANDLE_VALUE)
		return NULL;
	fd = _open_osfhandle((intptr_t)h, _O_RDWR | _O_BINARY);
	if (fd < 0) {
		CloseHandle(h);
		return NULL;
	}
	fp = _fdopen(fd, "r+b");
	if (!fp)
		_close(fd);        /* which closes the handle too */
	return fp;
}

static inline int kof_fseek64(FILE *f, uint64_t off)
{
	return _fseeki64(f, (__int64)off, SEEK_SET) == 0;
}

static inline int kof_truncate_file(const char *path, uint64_t len)
{
	/* Through the same refusal kof_fopen_rw uses: this is the OTHER half of
	 * a repair, and cutting a file the name merely points at is the same
	 * mistake as writing into one. */
	HANDLE h = kof_win_open_nofollow(path, GENERIC_WRITE, OPEN_EXISTING, 0);
	LARGE_INTEGER li;
	int ok;

	if (h == INVALID_HANDLE_VALUE)
		return 0;
	li.QuadPart = (LONGLONG)len;
	ok = SetFilePointerEx(h, li, NULL, FILE_BEGIN) && SetEndOfFile(h);
	CloseHandle(h);
	return ok;
}
#else
/* See the Windows side for why the repair path needs its own opener, its own
 * seek and its own truncate. O_NOFOLLOW here is the real thing. */
static inline FILE *kof_fopen_rw(const char *path)
{
	int fd = open(path, O_RDWR | O_NOFOLLOW);
	FILE *fp;

	if (fd < 0)
		return NULL;
	fp = fdopen(fd, "r+b");
	if (!fp)
		close(fd);
	return fp;
}

static inline int kof_fseek64(FILE *f, uint64_t off)
{
	return fseeko(f, (off_t)off, SEEK_SET) == 0;
}

static inline int kof_truncate_file(const char *path, uint64_t len)
{
	/*
	 * ftruncate ON AN O_NOFOLLOW HANDLE, not truncate() ON A PATH.
	 *
	 * truncate(2) resolves the path and follows a symlink, so the opener
	 * beside this one refusing to follow links bought nothing: a repair is
	 * a patch AND a cut, and cutting the file a name merely points at is
	 * the same mistake as writing into it. Caught by unit_cure, which
	 * asserts both halves rather than the one that had been thought about.
	 */
	int fd = open(path, O_WRONLY | O_NOFOLLOW);
	int ok;

	if (fd < 0)
		return 0;
	ok = ftruncate(fd, (off_t)len) == 0;
	close(fd);
	return ok;
}
#endif

/*
 * THE USER'S OWN DIRECTORY, from the system and not from the environment.
 *
 * HOME, XDG_CACHE_HOME and LOCALAPPDATA are all environment variables, and a
 * library that reads them takes its idea of where the user lives from
 * whatever the process was started with. That is the host's decision, and it
 * is also an unvalidated input: a service started with a planted HOME writes
 * its cache wherever the planter chose.
 *
 * The system knows without being told. POSIX has the passwd database and the
 * real user id, which is what the user IS rather than what the environment
 * claims. Windows has SHGetFolderPathA and CSIDL_LOCAL_APPDATA, which is the
 * call the platform documents for exactly this - and LOCAL rather than
 * roaming, because a cache keyed on a volume serial means nothing on another
 * machine.
 *
 * Returns 0 and leaves `out` untouched when the system will not say.
 */
/*
 * THE BOUNDS ARE CHECKED BY SUBTRACTION, NEVER BY ADDITION.
 *
 * "n + need >= cap" reads correctly and is the bug it is meant to prevent: the
 * sum is a size_t, and a length near the top of the range wraps to something
 * small, the test passes, and the copy that follows is exactly the overflow
 * the line was written to stop. "cap - n < need", with n < cap established
 * first, cannot wrap because both operands are already known to be in range.
 */
#ifdef _WIN32
static inline int kof_user_cache_dir(char *out, size_t cap)
{
	char buf[MAX_PATH];
	size_t n;

	if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, buf) != S_OK)
		return 0;
	buf[sizeof buf - 1u] = '\0';
	n = strlen(buf);
	if (n >= cap || cap - n < 1u)
		return 0;
	memcpy(out, buf, n + 1u);
	return 1;
}
#else
static inline int kof_user_cache_dir(char *out, size_t cap)
{
	/*
	 * getpwuid_r AND NOT getpwuid, because this is a library and the
	 * engine runs its scan on several threads - see the --jobs option.
	 * getpwuid returns a pointer into one static record shared by every
	 * caller in the process, so two threads asking at once read each
	 * other's answer. The _r form writes into storage the caller owns.
	 */
	struct passwd pw, *res = NULL;
	char pbuf[1024];
	size_t n;
	static const char tail[] = "/.cache";

	if (getpwuid_r(getuid(), &pw, pbuf, sizeof pbuf, &res) != 0 || !res)
		return 0;
	if (!res->pw_dir || !res->pw_dir[0])
		return 0;
	n = strlen(res->pw_dir);
	/* n bytes, then the tail and its NUL. Subtraction only. */
	if (n >= cap || cap - n < sizeof tail)
		return 0;
	memcpy(out, res->pw_dir, n);
	memcpy(out + n, tail, sizeof tail);
	return 1;
}
#endif

/*
 * CREATE A FILE THAT DID NOT EXIST, AND OWN IT ALONE.
 *
 * fopen(path, "wb") is the wrong call for anything written beside a target and
 * renamed over it. It follows a symlink, so a name an attacker can predict -
 * and "<the cache>.tmp" is exactly that - lets them choose the file the write
 * lands in. It also takes its permissions from the umask, so a cache of what
 * this machine has already decided about its own files is commonly world
 * readable.
 *
 * O_CREAT|O_EXCL refuses to open anything that is already there, symlink
 * included, and 0600 says who the file is for. On Windows the equivalent is
 * _O_EXCL with _S_IREAD|_S_IWRITE, where the ACL a new file inherits does the
 * rest.
 *
 * Returns NULL when the name is taken, which the caller should treat as a
 * failure to save and not as a reason to try a different name: a name that is
 * taken when it should not be is the attack, not an accident.
 */
static inline FILE *kof_fopen_new(const char *path)
{
	int fd;
	FILE *fp;

#ifdef _WIN32
	fd = _open(path, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
		   _S_IREAD | _S_IWRITE);
#else
	fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0600);
#endif
	if (fd < 0)
		return NULL;
#ifdef _WIN32
	fp = _fdopen(fd, "wb");
	if (!fp)
		_close(fd);
#else
	fp = fdopen(fd, "wb");
	if (!fp)
		close(fd);
#endif
	return fp;
}

/*
 * CREATE OR TRUNCATE, WITHOUT FOLLOWING A LINK, owned by this user alone.
 *
 * kof_fopen_new is for a name that must not already exist - a temporary about
 * to be renamed over a target. This is for the other case: a file the caller
 * legitimately rewrites, a log being (re)opened. It still refuses to follow a
 * symlink, because a writer that follows one writes wherever the link points,
 * and it still creates 0600 rather than whatever the umask happens to be -
 * these files hold process names and command lines.
 */
/*
 * THE SAME, WITH THE CALLER SAYING WHO THE FILE IS FOR.
 *
 * kof_fopen_trunc's 0600 is right for what it was written for - a log of
 * process names and command lines, evidence copied off somebody's machine -
 * and wrong for a file that is SOURCE. A signature draft is a .c the analyst
 * will build, commit and share; handing it back owner-only turns a security
 * fix into a build failure for the next account that touches the tree.
 *
 * So the refusal to follow a link - which is the part that matters, and which
 * no caller should have to opt out of - is kept, and only the mode is the
 * caller's. Pass 0600 for evidence, 0666 for a file the umask should decide.
 *
 * WINDOWS IGNORES `mode`, and that is not an omission: there is no mode to
 * set. kof_win_open_nofollow creates the file with the ACL it inherits from
 * its directory, which is the platform's own answer to the same question.
 */
static inline FILE *kof_fopen_trunc_mode(const char *path, int mode)
{
	int fd;
	FILE *fp;

#ifdef _WIN32
	(void)mode;
	{
		/* Created or truncated, and never through a link - see
		 * kof_win_open_nofollow. OPEN_ALWAYS rather than CREATE_ALWAYS
		 * so an existing reparse point is REFUSED instead of being
		 * replaced; the truncation is done below, on a handle that has
		 * already been shown to be a real file. */
		HANDLE h = kof_win_open_nofollow(path, GENERIC_WRITE,
						 OPEN_ALWAYS, 0);

		if (h == INVALID_HANDLE_VALUE)
			return NULL;
		if (!SetEndOfFile(h)) {
			CloseHandle(h);
			return NULL;
		}
		fd = _open_osfhandle((intptr_t)h, _O_WRONLY | _O_BINARY);
		if (fd < 0)
			CloseHandle(h);
	}
#else
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW,
		  (mode_t)mode);
#endif
	if (fd < 0)
		return NULL;
#ifdef _WIN32
	fp = _fdopen(fd, "wb");
	if (!fp)
		_close(fd);
#else
	fp = fdopen(fd, "wb");
	if (!fp)
		close(fd);
#endif
	return fp;
}

static inline FILE *kof_fopen_trunc(const char *path)
{
	return kof_fopen_trunc_mode(path, 0600);
}

/*
 * REPLACE `to` WITH `from`, atomically where the platform can.
 *
 * POSIX rename() already does this over an existing file, and doing it in one
 * step is the point: removing the target first leaves a window in which the
 * name does not exist, and a name that does not exist is a name somebody else
 * can create. Windows refuses rename onto an existing file, so there the
 * remove is unavoidable - and MoveFileExA with MOVEFILE_REPLACE_EXISTING is
 * the call that avoids it.
 */
static inline int kof_rename_over(const char *from, const char *to)
{
#ifdef _WIN32
	return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING) != 0;
#else
	return rename(from, to) == 0;
#endif
}

/*
 * WRITE A FILE SO THAT NO READER EVER SEES IT HALF WRITTEN, AND NO MAPPING OF
 * THE OLD ONE IS DISTURBED.
 *
 * A published database pack is mapped by every engine that opened it
 * (kof_map_file_ro) and read in place. fopen(path, "wb") on such a file
 * truncates the SAME inode: a reader that has it mapped faults with SIGBUS on
 * the next page it touches, and one that opens it mid-write sees a prefix. So
 * a pack is never written under its final name. It is written to a sibling
 * temporary in the SAME directory (a rename across file systems is a copy),
 * flushed to disk, and renamed over the final name. The old inode stays valid
 * for whoever mapped it - on POSIX until the last unmap - and the new name
 * points at a file that is complete or does not exist. Power loss leaves the
 * old file or the new one, never a mixture, because the data is on disk BEFORE
 * the name moves; the directory is flushed after, so the move itself survives.
 *
 * The temporary is created O_EXCL (a stale one from a crashed run is skipped,
 * not reused) and, unlike kof_fopen_new, with the mode the umask decides: a
 * pack is read by scanners running as other accounts. Its name never ends in
 * .ksig or .kdig, so a loader scanning the directory cannot mistake it for a
 * pack. On every failure it is removed.
 *
 * WINDOWS: MoveFileEx(REPLACE_EXISTING) is REFUSED while any process has the
 * target mapped or open without FILE_SHARE_DELETE. That is not worked around
 * here; the caller gets 0 and the old file is intact. See install_update_design.md.
 * [Not compiled on Windows: written against the documented CRT/Win32 calls.]
 *
 * Returns 1 when `path` now holds exactly `data`, 0 otherwise (nothing changed).
 */
static inline int kof_write_file_atomic(const char *path, const void *data,
					size_t len)
{
	char tmp[4096 + 48];
	size_t n = path ? strlen(path) : 0;
	unsigned long pid;
	int fd = -1, ok = 0, k;

	if (!path || !n || n > 4096u || (len && !data))
		return 0;
#ifdef _WIN32
	pid = (unsigned long)GetCurrentProcessId();
#else
	pid = (unsigned long)getpid();
#endif
	for (k = 0; k < 16 && fd < 0; k++) {
		snprintf(tmp, sizeof tmp, "%s.tmp%lu.%d", path, pid, k);
#ifdef _WIN32
		fd = _open(tmp, _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
			   _S_IREAD | _S_IWRITE);
#else
		fd = open(tmp, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0666);
#endif
	}
	if (fd < 0)
		return 0;
	ok = kof_write_all(fd, data, (uint64_t)len);
#ifdef _WIN32
	if (ok && _commit(fd) != 0)
		ok = 0;
	if (_close(fd) != 0)
		ok = 0;
#else
	if (ok && fsync(fd) != 0)
		ok = 0;
	if (close(fd) != 0)
		ok = 0;
#endif
	if (ok && !kof_rename_over(tmp, path))
		ok = 0;
	if (!ok) {
		remove(tmp);
		return 0;
	}
#ifndef _WIN32
	/* The directory entry, so the rename itself is durable. Best effort: a
	 * file system that cannot fsync a directory has still done the rename. */
	{
		char dir[4096 + 2];
		const char *sl = strrchr(path, '/');
		int dfd;

		if (!sl)
			memcpy(dir, ".", 2);
		else if (sl == path)
			memcpy(dir, "/", 2);
		else {
			memcpy(dir, path, (size_t)(sl - path));
			dir[sl - path] = 0;
		}
		dfd = open(dir, O_RDONLY);
		if (dfd >= 0) {
			(void)fsync(dfd);
			close(dfd);
		}
	}
#endif
	return 1;
}

#endif /* KOFENG_KOFPLATFORM_FILE_H */
