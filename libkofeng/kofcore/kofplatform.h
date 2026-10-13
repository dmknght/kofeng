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
 *
 * The text is in two parts by purpose, included below: kofplatform_os.h (mapping,
 * stat, memmem, streams, argv) and kofplatform_file.h (paths and files).
 */

#ifndef KOFENG_KOFPLATFORM_H
#define KOFENG_KOFPLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "kofplatform_os.h"
#include "kofplatform_file.h"

#endif /* KOFENG_KOFPLATFORM_H */
