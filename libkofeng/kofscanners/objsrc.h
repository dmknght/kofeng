/*
 * objsrc.h - where an object's bytes come from, and how long they live.
 *
 * A scan used to be one file at a time: map it, scan it, unmap it. Once an object
 * can yield children that is no longer enough, because a child is not always a
 * copy. The cheapest child - an overlay, a stored archive entry, anything already
 * contiguous in the parent - is a WINDOW into the parent's mapping, and it costs
 * nothing at all as long as the parent's mapping is still there when the child is
 * scanned. It is not: by then the parent has been scanned and would have been
 * unmapped.
 *
 * So the bytes get a lifetime of their own, separate from whatever produced them,
 * and it is counted rather than scoped. Three kinds, one struct:
 *
 *   file      an mmap of a regular file
 *   window    a range inside another source; holds a reference to it
 *   produced  bytes the engine made - a heap buffer, or an unnamed temporary
 *             file mapped back in when it got too large to keep in memory
 *
 * A caller cannot tell them apart and does not need to. kof_src_buf() hands back
 * bytes either way, so the scan path, the parsers and the matcher are unchanged.
 *
 *
 * WHY A TEMPORARY FILE IS NOT A SECURITY PROBLEM HERE
 *
 * Writing decompressed output to disk is where a long line of scanner
 * vulnerabilities came from: attacker-controlled entry names, path traversal,
 * symlink races, and cleanup that did not run. Every one of those needs the file to
 * have a NAME.
 *
 * These have none. O_TMPFILE creates an inode with no directory entry at all - it
 * exists only as a descriptor and is reclaimed by the kernel when the descriptor
 * closes, including on SIGKILL, OOM and a crash. There is nothing to traverse to,
 * nothing to race, and no cleanup step that can be skipped. The fallback for a
 * filesystem without O_TMPFILE creates a name and unlinks it immediately, which
 * gets the same property one syscall later.
 *
 * The entry name from the archive is never used for anything but reporting.
 */

#ifndef KOFENG_OBJSRC_H
#define KOFENG_OBJSRC_H

#include <stdint.h>
#include <stddef.h>

#include "../core/kofcore.h"

struct kof_objsrc;

/*
 * Map a regular file. NULL on failure, and *err is a KOF_ERR_*.
 *
 * A zero length file succeeds and yields no bytes: it is a legitimate object that
 * every module will decline, not an error, and mmap cannot represent it.
 */
struct kof_objsrc *kof_src_file(const char *path, int *err);

/*
 * A range of another source, without copying. The parent is referenced and stays
 * alive until this is released; the range is clipped to what the parent has.
 *
 * NULL if the range is empty after clipping - there is no object there.
 */
struct kof_objsrc *kof_src_window(struct kof_objsrc *parent, uint64_t off,
				  uint64_t len);

/* Take ownership of a malloc'd buffer. */
struct kof_objsrc *kof_src_heap(uint8_t *bytes, uint64_t len);

/*
 * Map an open descriptor and take ownership of it. Used for output that outgrew
 * memory: the bytes are already written, this turns them back into an object that
 * behaves exactly like a mapped file - only the pages a scan touches become
 * resident.
 */
struct kof_objsrc *kof_src_fd(int fd, uint64_t len);

struct kof_objsrc *kof_src_ref(struct kof_objsrc *);
void               kof_src_unref(struct kof_objsrc *);

kof_buf kof_src_buf(const struct kof_objsrc *);

/*
 * How many bytes this source cost to produce, or zero for a file or a window.
 *
 * The scanner charges this against its memory ceiling and gives it back when the
 * object is finished with. A window is free by construction - it is the parent's
 * mapping at a different offset - so accounting for it would double-count memory
 * that was never allocated.
 */
uint64_t kof_src_produced(const struct kof_objsrc *);

/*
 * An unnamed temporary file to write produced bytes into, or -1.
 *
 * Here rather than in the sink that uses it because the reason it is unnamed is the
 * same reason this header exists at all: the lifetime is the descriptor's, not a
 * directory entry's.
 */
int kof_src_tmpfile(void);

#endif /* KOFENG_OBJSRC_H */
