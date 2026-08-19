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

#else /* POSIX */

#include <sys/mman.h>
#include <unistd.h>

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
