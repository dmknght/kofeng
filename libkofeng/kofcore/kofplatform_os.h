/*
 * kofplatform_os.h - the OS calls that differ per platform: mmap and its Windows
 * equivalent, lstat, memmem, alternate streams, UTF-8 argv, page size, W^X. *
 * A part of <kofplatform.h>, which includes it: include kofplatform.h, not this. Split
 * from it by purpose; the text is unchanged.
 */

#ifndef KOFENG_KOFPLATFORM_OS_H
#define KOFENG_KOFPLATFORM_OS_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32

#include <windows.h>
#include <shlobj.h>
#include <io.h>
/* _O_CREAT, _O_EXCL, _O_TRUNC, _O_RDWR, _O_BINARY - used by the openers below.
 * This header compiled without it only because every translation unit that
 * includes it happened to include <fcntl.h> first; a header that needs a
 * constant should ask for it itself. */
#include <fcntl.h>
#include <sys/stat.h>     /* _S_IREAD, _S_IWRITE */

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

/*
 * ---- THE OTHER STREAMS OF A FILE ----------------------------------------
 *
 * WHAT THIS IS FOR. On NTFS a file is not one run of bytes: it is a set of
 * named streams, of which the one every tool shows is called ::$DATA and has
 * no name. Anything can be put in another one. Measured on this machine: a
 * 218KB PE written to `host.txt:hidden.exe` leaves host.txt reporting 29
 * bytes, and a directory walk that reads what readdir returns scans those 29
 * bytes and calls the file clean.
 *
 * The engine could already read it - naming the stream explicitly parsed it
 * as a PE, correctly. What was missing was anyone ever naming it.
 *
 * THE ITERATOR IS HERE AND NOT IN THE SCANNER, for the reason everything else
 * in this header is here: the walk is one loop on both platforms and must not
 * grow an #ifdef. On POSIX a file has one stream, so open() answers no and the
 * loop does not run - which is not a stub, it is the correct answer.
 *
 * WHAT IT YIELDS is the SUFFIX, not a whole path: ":hidden.exe:$DATA", ready
 * to be appended to the file's own path. That is what FindFirstStreamW hands
 * back and it is what CreateFile accepts, so nothing has to be taken apart and
 * put together again.
 *
 * ::$DATA IS NOT YIELDED. It is the file itself, the caller has just scanned
 * it, and handing it over again would double every file on the machine.
 */
struct kof_stream_walk {
	void *h;              /* HANDLE, or INVALID_HANDLE_VALUE */
	int   pending;        /* the find already holds an unreported entry */
	char  name[544];      /* the suffix, UTF-8 */
};

static inline int kof_streams_next(struct kof_stream_walk *w);

static inline int kof_streams_open(struct kof_stream_walk *w, const char *path)
{
	wchar_t wp[1024];
	WIN32_FIND_STREAM_DATA fd;
	HANDLE h;

	w->h = INVALID_HANDLE_VALUE;
	w->pending = 0;
	w->name[0] = '\0';
	if (!path || !path[0])
		return 0;
	if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wp,
				 (int)(sizeof wp / sizeof wp[0])))
		return 0;
	h = FindFirstStreamW(wp, FindStreamInfoStandard, &fd, 0);
	if (h == INVALID_HANDLE_VALUE)
		return 0;
	w->h = h;
	/*
	 * The first entry is already in hand and is normally ::$DATA. It is
	 * kept rather than dropped because a file CAN have no unnamed stream,
	 * and deciding which it is belongs in one place - kof_streams_next.
	 */
	if (!WideCharToMultiByte(CP_UTF8, 0, fd.cStreamName, -1, w->name,
				 (int)sizeof w->name, NULL, NULL))
		w->name[0] = '\0';
	w->pending = 1;
	return 1;
}

static inline int kof_streams_next(struct kof_stream_walk *w)
{
	WIN32_FIND_STREAM_DATA fd;

	if (!w || w->h == INVALID_HANDLE_VALUE)
		return 0;
	for (;;) {
		if (w->pending) {
			w->pending = 0;
		} else {
			if (!FindNextStreamW((HANDLE)w->h, &fd))
				return 0;
			if (!WideCharToMultiByte(CP_UTF8, 0, fd.cStreamName, -1,
						 w->name, (int)sizeof w->name,
						 NULL, NULL))
				continue;   /* a name this cannot spell */
		}
		if (w->name[0] != ':')
			continue;       /* not a suffix; nothing to append */
		if (strcmp(w->name, "::$DATA") == 0)
			continue;       /* the file itself */
		return 1;
	}
}

static inline void kof_streams_close(struct kof_stream_walk *w)
{
	if (w && w->h != INVALID_HANDLE_VALUE) {
		FindClose((HANDLE)w->h);
		w->h = INVALID_HANDLE_VALUE;
	}
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

/*
 * Read `n` bytes at byte offset `off` of an open descriptor WITHOUT touching its file
 * position, so threads share one descriptor. Returns the bytes read: fewer than `n`
 * only at the end of the file (a file shorter than it was when it was measured) or on an
 * error, and the caller treats either as a failed read - this is what the database index
 * uses instead of a mapping, because a truncated file makes a read come back short
 * where a mapping raises a signal. 0 on error, never negative.
 */
static inline size_t kof_pread(int fd, void *buf, size_t n, uint64_t off)
{
	HANDLE fh = (HANDLE)_get_osfhandle(fd);
	size_t got = 0;

	if (fh == INVALID_HANDLE_VALUE)
		return 0;
	while (got < n) {
		OVERLAPPED ov;
		DWORD r = 0, ask = (n - got) > 0x40000000u ? 0x40000000u : (DWORD)(n - got);

		memset(&ov, 0, sizeof ov);
		ov.Offset = (DWORD)((off + got) & 0xffffffffu);
		ov.OffsetHigh = (DWORD)((off + got) >> 32);
		if (!ReadFile(fh, (char *)buf + got, ask, &r, &ov) || r == 0)
			break;
		got += r;
	}
	return got;
}

/*
 * Ask the system to read [off, off + len) of an open file into its cache, in the background, so a
 * later pread of it does not wait for the disk. A HINT: nothing waits on it, nothing depends on it
 * being taken, and it has no result. Windows has no advice call for a descriptor opened without
 * overlapped I/O (PrefetchVirtualMemory wants a mapping, which the engine does not make of these
 * parts), so there it does nothing and the first reads page the data in.
 */
static inline void kof_prefetch(int fd, uint64_t off, uint64_t len)
{
	(void)fd;
	(void)off;
	(void)len;
}

static inline void kof_unmap_file(void *p, uint64_t len)
{
	(void)len;
	if (p)
		UnmapViewOfFile(p);
}

/* Tell the system the pages of a read-only file mapping are not needed now: it may take them
 * back and they come from the file again on the next touch. No effect on what the mapping
 * says, only on what it holds resident. Windows has no equivalent that keeps the view, so this
 * does nothing there. */
static inline void kof_map_drop(void *p, uint64_t len)
{
	(void)p;
	(void)len;
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
#include <pwd.h>
#include <fcntl.h>           /* open, O_RDONLY - kof_map_file_ro below */
#include <errno.h>           /* EINTR - kof_pread */
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
 * A POSIX FILE HAS ONE STREAM, so the walk opens nothing and yields nothing.
 *
 * NOT A STUB. "There are no other streams" is the true answer here, not a
 * feature this platform is missing: a regular file is one run of bytes and
 * there is no second one to have overlooked. The Windows half is where the
 * question has an answer worth asking - see it for what an alternate data
 * stream costs a scanner that does not look.
 *
 * Extended attributes are NOT this. They are metadata with a size limit,
 * xattr has its own call, and nothing here has ever scanned one - calling
 * them streams to make this symmetrical would be inventing a feature to fill
 * a shape.
 */
struct kof_stream_walk {
	void *h;
	int   pending;
	char  name[544];
};

static inline int kof_streams_open(struct kof_stream_walk *w, const char *path)
{
	(void)path;
	if (w) {
		w->h = NULL;
		w->pending = 0;
		w->name[0] = '\0';
	}
	return 0;
}

static inline int kof_streams_next(struct kof_stream_walk *w)
{
	(void)w;
	return 0;
}

static inline void kof_streams_close(struct kof_stream_walk *w)
{
	(void)w;
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

/* See the Windows spelling above for what this promises. pread does not move the file
 * position and retries a short read until the end of the file. */
static inline size_t kof_pread(int fd, void *buf, size_t n, uint64_t off)
{
	size_t got = 0;

	while (got < n) {
		ssize_t r = pread(fd, (char *)buf + got, n - got, (off_t)(off + got));

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
		got += (size_t)r;
	}
	return got;
}

/* See the Windows spelling above for what this promises. posix_fadvise(WILLNEED) queues the read
 * and returns; where the call does not exist (macOS) it does nothing. */
static inline void kof_prefetch(int fd, uint64_t off, uint64_t len)
{
#ifdef POSIX_FADV_WILLNEED
	(void)posix_fadvise(fd, (off_t)off, (off_t)len, POSIX_FADV_WILLNEED);
#else
	(void)fd;
	(void)off;
	(void)len;
#endif
}

static inline void kof_unmap_file(void *p, uint64_t len)
{
	if (p)
		munmap(p, (size_t)len);
}

static inline void kof_map_drop(void *p, uint64_t len)
{
	if (p && len)
		(void)madvise(p, (size_t)len, MADV_DONTNEED);
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
 * Hand the C library's free heap back to the OS, where the library has a call for it.
 *
 * glibc keeps what a large free released (its mmap threshold rises to 32 MiB after the
 * first big free, so later buffers of that size come from the brk heap and stay): a
 * process that scanned one 31 MB object keeps that much resident for ever. malloc_trim
 * is the call that returns it. Nowhere else this builds for has one that does the same, and
 * there the call does nothing. Answers 1 when it asked the library, 0 when there was
 * nothing to ask. Never called by the engine on its own account: a host asks for it
 * (kscan_trim), because whether a long-lived process wants the CPU cost (measured +2.6%
 * when done after every scan) is its decision, and the engine must not change process-wide
 * allocator policy behind the host's back.
 */
#if defined(__GLIBC__) && !defined(_WIN32)
#include <malloc.h>
static inline int kof_heap_trim(void)
{
	malloc_trim(0);
	return 1;
}
#else
static inline int kof_heap_trim(void)
{
	return 0;
}
#endif

/*
 * Bytes the C library says are allocated right now, or 0 where it cannot say. Read twice
 * around a single-threaded step to learn what the step kept (keng_open: the database).
 */
#if defined(__GLIBC__) && !defined(_WIN32) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 33)
static inline uint64_t kof_heap_in_use(void)
{
	struct mallinfo2 m = mallinfo2();

	return (uint64_t)m.uordblks + (uint64_t)m.hblkhd;
}
#else
static inline uint64_t kof_heap_in_use(void) { return 0; }
#endif
#else
static inline uint64_t kof_heap_in_use(void)
{
	return 0;
}
#endif

#endif /* KOFENG_KOFPLATFORM_OS_H */
