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
#include <sys/stat.h>

#ifdef _WIN32

#include <windows.h>
#include <io.h>
#include <string.h>

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

static inline const void *kof_memmem(const void *hay_, size_t hlen,
				      const void *needle_, size_t nlen)
{
	const uint8_t *hay = (const uint8_t *)hay_;
	const uint8_t *needle = (const uint8_t *)needle_;
	uint32_t fail[KOF_MEMMEM_FAIL_MAX];
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

	k = 0;
	for (i = 0; i < hlen; i++) {
		while (k > 0 && hay[i] != needle[k])
			k = fail[k - 1];
		if (hay[i] == needle[k])
			k++;
		if (k == nlen)
			return hay + (i + 1 - nlen);
	}
	return NULL;
}

#else /* POSIX */

#include <sys/mman.h>
#include <unistd.h>
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

#endif /* KOFENG_KOFPLATFORM_H */
