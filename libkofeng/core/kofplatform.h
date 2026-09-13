/*
 * kofplatform.h - the OS calls the host library needs and mingw-w64 does not carry
 * over from POSIX unchanged.
 *
 * Internal to libkofeng; signature modules never see this.
 *
 * Most of this codebase uses open/read/close/stat/opendir directly rather than
 * wrapped - mingw-w64 implements those on top of the Win32 file APIs, so source
 * that already works on POSIX also works unchanged there. Two things are not
 * carried over, for two different reasons:
 *
 *   mmap/mprotect/munmap  Windows has no mmap at all, and the W^X transition on an
 *                          anonymous arena is a VirtualProtect, not an mprotect on
 *                          the same address the mapping call returned.
 *
 *   lstat                 Windows has reparse points, not POSIX symlinks, and
 *                          mingw-w64's stat() does not resolve them the way a
 *                          POSIX stat() resolves a symlink - so unlike the mmap
 *                          family this is not a like-for-like substitution, only
 *                          the closest thing available. A directory walk that
 *                          relies on lstat to keep a symlink cycle from becoming an
 *                          infinite loop should be re-verified against real reparse
 *                          points before this is trusted on Windows; kof_lstat is a
 *                          placeholder for that decision, not a resolution of it.
 *
 *   memmem                 mingw-w64 sits on MSVC's corecrt, which never carried
 *                          this GNU/BSD extension the way glibc, the BSDs and musl
 *                          do. The POSIX side of kof_memmem calls the real one -
 *                          glibc's has used the Two-Way algorithm internally since
 *                          2.9, worst case O(n) - and the Windows side is a plain
 *                          Knuth-Morris-Pratt search, chosen over reimplementing
 *                          Two-Way by hand for the same reason the rest of this
 *                          file delegates instead of reimplementing: a matcher this
 *                          project's own detections run through is not where a
 *                          hand-rolled algorithm should be debuted. KMP gives the
 *                          same worst-case bound with a much smaller surface to get
 *                          wrong - a single failure-function loop - at the cost of
 *                          the O(n*m)-avoiding case only, not memmem's average-case
 *                          tuning.
 *
 * The return convention for the mapping calls is NULL on failure, on both
 * platforms - POSIX's MAP_FAILED is ((void *)-1), a sentinel this header does not
 * forward, so a caller checks one pointer against one value regardless of which OS
 * answered it.
 */

#ifndef KOFENG_KOFPLATFORM_H
#define KOFENG_KOFPLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>          /* getenv - kof_tmpdir below */
#include <sys/stat.h>

#ifdef _WIN32

#include <windows.h>
#include <io.h>

#include <string.h>
#include <locale.h>

/*
 * A FILE THIS COULD NOT OPEN IS A FILE NOBODY SCANNED, AND ON WINDOWS THAT WAS
 * EVERY FILE WHOSE NAME LEFT THE ANSI CODEPAGE.
 *
 * Two separate losses, and both happen before any code in this tree runs.
 *
 * ARGV ARRIVES ALREADY DESTROYED. A Windows process is given its command line
 * as UTF-16 and the C runtime converts it to the ANSI codepage to build the
 * narrow argv that main() receives. Anything the codepage cannot spell is
 * best-fit mapped or replaced with a question mark, irreversibly. Measured on
 * this host, ACP 1252, the path "chartest\hoa don Duc.bin" with Vietnamese
 * diacritics:
 *
 *     narrow argv   68 F3 61 20 64 6F 6E 20 D0 3F 63    "h.a don .?c"
 *     wide, as UTF-8 68 C3 B3 61 20 C4 91 C6 A1 6E 20 C4 90 E1 BB A9 63
 *
 * `don` was `don` with two diacritics, `Duc` had three; one became 0x3F. The
 * name is gone, so fopen(argv[1]) fails and the tool reports a file it cannot
 * open - which is indistinguishable from a permission error and is NOT
 * indistinguishable from a clean scan, but is very much indistinguishable from
 * "this file was checked" in a summary that counts what it managed.
 *
 * THE NARROW PATH FUNCTIONS DO NOT SPEAK UTF-8 EITHER. Even handed correct
 * UTF-8 bytes, fopen and stat convert them through the ANSI codepage and look
 * for a file that does not exist. Measured: fopen FAILED, stat FAILED, on the
 * name above, with the bytes correct.
 *
 * So a payload named with one character outside the machine's codepage cannot
 * be opened by any tool in this tree. That is not a display problem; it is a
 * hole a person can walk a file through, and it costs them one keystroke.
 *
 *
 * WHAT THIS DOES, AND WHY IT IS TWO CALLS AND NOT A REWRITE.
 *
 * setlocale(LC_CTYPE, ".UTF8") makes the UCRT's narrow path functions - fopen,
 * open, stat, opendir, every one of them - interpret their argument as UTF-8.
 * Measured: fopen OK, stat OK, on bytes that failed a line earlier. The whole
 * open/stat/readdir surface is fixed without a single call site changing, which
 * is the entire reason this is one line instead of a wide-character port.
 *
 * LC_CTYPE AND NOT LC_ALL, and the difference is not tidiness. LC_ALL would
 * take LC_NUMERIC with it, and on a machine whose locale uses a decimal comma
 * every "%.1f" in every report would change what it prints and every strtod
 * would change what it reads. Character classification is the only part of the
 * locale this needs.
 *
 * GetACP() is deliberately left alone - it still reports 1252 here afterwards.
 * Nothing else in the process changes behaviour; only the CRT's idea of what
 * its own narrow strings are encoded in.
 *
 * Then argv is rebuilt from the command line Windows actually gave, which is
 * the only copy that still has the name in it.
 */
static inline void kof_utf8_restore_cp(void);

static UINT kof_saved_out_cp;

static inline void kof_utf8_restore_cp(void)
{
	if (kof_saved_out_cp)
		SetConsoleOutputCP(kof_saved_out_cp);
}

static inline void kof_utf8_init(int *argc, char ***argv)
{
	wchar_t **wv;
	char **nv;
	int wc = 0, i;

	setlocale(LC_CTYPE, ".UTF8");

	/*
	 * So the bytes this now prints are the characters a reader sees. The
	 * previous code page is put back at exit: it is console state that
	 * outlives the process, and a tool that leaves a shell in a mode it
	 * did not ask for has broken something it does not own.
	 */
	kof_saved_out_cp = GetConsoleOutputCP();
	if (kof_saved_out_cp && kof_saved_out_cp != CP_UTF8) {
		if (SetConsoleOutputCP(CP_UTF8))
			atexit(kof_utf8_restore_cp);
		else
			kof_saved_out_cp = 0;
	} else {
		kof_saved_out_cp = 0;
	}

	if (!argc || !argv)
		return;

	wv = CommandLineToArgvW(GetCommandLineW(), &wc);
	if (!wv || wc <= 0)
		return;              /* keep the lossy argv: it is all there is */

	nv = calloc((size_t)wc + 1u, sizeof *nv);
	if (!nv) {
		LocalFree(wv);
		return;
	}
	for (i = 0; i < wc; i++) {
		int n = WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, NULL, 0,
					    NULL, NULL);

		if (n <= 0)
			goto give_up;
		nv[i] = malloc((size_t)n);
		if (!nv[i])
			goto give_up;
		if (WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, nv[i], n,
					NULL, NULL) <= 0)
			goto give_up;
	}
	nv[wc] = NULL;
	LocalFree(wv);
	/*
	 * NOT FREED, and that is deliberate rather than overlooked: this is
	 * argv, it is read for the whole life of the process, and the process
	 * is about to exit when it stops being read. Freeing it would need a
	 * teardown hook in every tool for memory the OS reclaims anyway.
	 */
	*argc = wc;
	*argv = nv;
	return;

give_up:
	/*
	 * A PARTIAL argv IS WORSE THAN A LOSSY ONE. Half-converted arguments
	 * would have a tool scanning one path and skipping another with no
	 * indication, so the original is kept whole.
	 */
	for (i = 0; i < wc; i++)
		free(nv[i]);
	free(nv);
	LocalFree(wv);
}

/* See the header comment: not a verified equivalent, only the closest
 * available primitive until reparse-point behaviour is checked for real. */
static inline int kof_lstat(const char *path, struct stat *st)
{
	return stat(path, st);
}

/* mingw-w64's mkdir takes no mode - NTFS permissions are not POSIX mode bits,
 * and nothing here has ever depended on the mode surviving. */
static inline int kof_mkdir(const char *path, int mode)
{
	(void)mode;
	return mkdir(path);
}

static inline uint64_t kof_page_size(void)
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	return (uint64_t)si.dwPageSize;
}

/* Read only view of an already open file descriptor, `len` bytes from the start.
 * The mapping object is closed as soon as the view exists: the view keeps the
 * mapping alive on its own, same reason the caller closes its fd right after this
 * returns. */
static inline void *kof_map_file_ro(int fd, uint64_t len)
{
	HANDLE fh, mh;
	void *view;

	fh = (HANDLE)_get_osfhandle(fd);
	if (fh == INVALID_HANDLE_VALUE)
		return NULL;
	mh = CreateFileMappingA(fh, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!mh)
		return NULL;
	view = MapViewOfFile(mh, FILE_MAP_READ, 0, 0, (SIZE_T)len);
	CloseHandle(mh);
	return view;
}

static inline void kof_unmap_file(void *p, uint64_t len)
{
	(void)len;
	if (p)
		UnmapViewOfFile(p);
}

/* Anonymous, read-write, for the code arena before anything is copied into it. */
static inline void *kof_map_anon_rw(uint64_t len)
{
	return VirtualAlloc(NULL, (SIZE_T)len, MEM_COMMIT | MEM_RESERVE,
			     PAGE_READWRITE);
}

/* Flip the arena from writable to executable. Same 0-success/-1-failure shape as
 * mprotect, so the call site's "!= 0" check is unchanged either way. */
static inline int kof_mprotect_rx(void *p, uint64_t len)
{
	DWORD old;
	return VirtualProtect(p, (SIZE_T)len, PAGE_EXECUTE_READ, &old) ? 0 : -1;
}

static inline void kof_unmap_anon(void *p, uint64_t len)
{
	(void)len;
	if (p)
		VirtualFree(p, 0, MEM_RELEASE);
}

/*
 * Knuth-Morris-Pratt, worst case O(hlen + nlen), needle bytes matched at most
 * twice each (once forward, at most once again via the failure link) - the
 * property that makes this immune to the O(hlen*nlen) blowup a memchr-anchored
 * scan hits on a haystack that repeats the anchor byte, which is exactly the
 * case this function exists to close off.
 *
 * The failure table is a fixed stack array rather than a VLA or a malloc: this
 * function's only caller (kofmatch.c) never passes a needle past KOF_STR_MAX_LEN
 * (512), so 1024 is generous headroom, and a fixed array means no allocation can
 * fail mid-search. A needle that somehow exceeds it is still answered correctly,
 * by the loop below the table - just without the O(n) guarantee, since there is
 * no bound here to size a table to and this is not the place to malloc one.
 */
#define KOF_MEMMEM_FAIL_MAX 1024

/*
 * Consecutive memchr calls that skipped nothing before the search stops
 * calling it. Small because the evidence is unambiguous - a skip of zero
 * means the byte was already there - and because the cost of being wrong for
 * this many bytes is nothing next to being wrong for a whole haystack.
 */
#define KOF_MEMMEM_GIVE_UP 16u

static inline const void *kof_memmem(const void *hay_, size_t hlen,
				      const void *needle_, size_t nlen)
{
	const uint8_t *hay = (const uint8_t *)hay_;
	const uint8_t *needle = (const uint8_t *)needle_;
	uint32_t fail[KOF_MEMMEM_FAIL_MAX];
	unsigned barren = 0;
	int anchored = 1;
	size_t i, k;

	if (nlen == 0)
		return hay;
	if (nlen > hlen)
		return NULL;

	if (nlen > KOF_MEMMEM_FAIL_MAX) {
		size_t s;
		for (s = 0; s + nlen <= hlen; s++)
			if (memcmp(hay + s, needle, nlen) == 0)
				return hay + s;
		return NULL;
	}

	fail[0] = 0;
	k = 0;
	for (i = 1; i < nlen; i++) {
		while (k > 0 && needle[i] != needle[k])
			k = fail[k - 1];
		if (needle[i] == needle[k])
			k++;
		fail[i] = (uint32_t)k;
	}

	/*
	 * SKIPPING TO THE NEXT BYTE THAT COULD START A MATCH, while keeping
	 * the automaton that makes the worst case linear.
	 *
	 * While k is zero nothing is half-matched, so every byte that is not
	 * the needle's first cannot begin one and memchr may run over them at
	 * whatever width the C library uses. The KMP state is not restarted by
	 * this - memchr only ever skips bytes the loop below would have
	 * rejected one at a time - so the O(hlen + nlen) bound is the same
	 * bound as before.
	 *
	 * `anchored` is the retreat, and it is why this is safe to do at all.
	 * On a haystack whose every byte is the needle's first, memchr skips
	 * nothing and its call overhead is pure loss - which is exactly the
	 * shape this function was given a KMP to survive. So the skips are
	 * watched, and enough consecutive ones that gained no ground turns the
	 * anchor off for the rest of the call. One way, so there is no
	 * oscillating between the two.
	 *
	 * Measured on this machine, 32MB haystacks, MB/s, x86_64 then AArch64:
	 *
	 *              before        after
	 *   sparse     1455  533     21333  21333
	 *   dense       372  332       674    800
	 *   hostile     901 1280      1049   2000
	 *
	 * The AArch64 column is why this was looked at: the plain loop carries
	 * the needle index through a load whose address depends on it, so each
	 * iteration waits a load latency, and the same C on x86_64 happens to
	 * break that chain. Skipping the bytes entirely helps both and does
	 * not depend on either compiler continuing to do what it does today.
	 */
	k = 0;
	i = 0;
	while (i < hlen) {
		uint8_t c;

		if (k == 0 && anchored) {
			const uint8_t *hit = (const uint8_t *)
				memchr(hay + i, needle[0], hlen - i);

			if (!hit)
				return NULL;
			if (hit == hay + i) {
				if (++barren >= KOF_MEMMEM_GIVE_UP)
					anchored = 0;
			} else {
				barren = 0;
			}
			i = (size_t)(hit - hay);
			k = 1;
			if (nlen == 1)
				return hay + i;
			i++;
			continue;
		}
		c = hay[i];
		while (k > 0 && c != needle[k])
			k = fail[k - 1];
		if (c == needle[k])
			k++;
		if (k == nlen)
			return hay + (i + 1 - nlen);
		i++;
	}
	return NULL;
}

#else /* POSIX */

#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>           /* open, O_RDONLY - kof_map_file_ro below */
#include <string.h>

/* The real one - see the header comment on why this side just calls it. Needs
 * _GNU_SOURCE (or an equivalent *_SOURCE macro) defined before the including
 * file's first system header, same as any other POSIX/GNU extension; this
 * header does not define it, because a feature test macro belongs to the
 * translation unit that needs it, not to a header included partway through
 * one. */
static inline const void *kof_memmem(const void *hay, size_t hlen,
				      const void *needle, size_t nlen)
{
	return memmem(hay, hlen, needle, nlen);
}

static inline int kof_mkdir(const char *path, int mode)
{
	return mkdir(path, (mode_t)mode);
}

/*
 * NOTHING TO DO, and the reason is worth one line rather than a bare no-op.
 *
 * A POSIX path is a byte string. The kernel neither knows nor cares what
 * encoding those bytes are in, argv carries them through untouched, and open()
 * hands them back exactly as given - so a name in UTF-8, in Shift-JIS, or in
 * no encoding at all opens either way. There is no conversion here to get
 * wrong, which is precisely why the Windows half of this file needs two calls
 * to reach the same place.
 */
static inline void kof_utf8_init(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
}

static inline int kof_lstat(const char *path, struct stat *st)
{
	return lstat(path, st);
}

static inline uint64_t kof_page_size(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	return ps > 0 ? (uint64_t)ps : 4096;
}

static inline void *kof_map_file_ro(int fd, uint64_t len)
{
	void *p = mmap(NULL, (size_t)len, PROT_READ, MAP_PRIVATE, fd, 0);
	return p == MAP_FAILED ? NULL : p;
}

static inline void kof_unmap_file(void *p, uint64_t len)
{
	if (p)
		munmap(p, (size_t)len);
}

static inline void *kof_map_anon_rw(uint64_t len)
{
	void *p = mmap(NULL, (size_t)len, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	return p == MAP_FAILED ? NULL : p;
}

static inline int kof_mprotect_rx(void *p, uint64_t len)
{
	return mprotect(p, (size_t)len, PROT_READ | PROT_EXEC);
}

static inline void kof_unmap_anon(void *p, uint64_t len)
{
	if (p)
		munmap(p, (size_t)len);
}

#endif

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

static inline const char *kof_tmpdir(void)
{
	const char *p = getenv("TMPDIR");

	if (p && p[0])
		return p;
#ifdef _WIN32
	p = getenv("TMP");
	if (p && p[0])
		return p;
	p = getenv("TEMP");
	if (p && p[0])
		return p;
	return ".";
#else
	return "/tmp";
#endif
}

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

#endif /* KOFENG_KOFPLATFORM_H */
