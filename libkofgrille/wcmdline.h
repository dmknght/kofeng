/*
 * wcmdline.h - reading a new process's command line out of its own memory.
 *
 * The one thing this collector FETCHES rather than receives, because
 * Kernel-Process does not carry it. See wcmdline.c for why that is worth doing
 * anyway, and for why every field read is validated rather than trusted.
 *
 * Consumer side only. It opens a handle and reads another process's memory,
 * neither of which may happen anywhere near the ETW callback.
 */

#ifndef KOFGRILLE_WCMDLINE_H
#define KOFGRILLE_WCMDLINE_H

#include <stdint.h>
#include <stddef.h>

#define KOFW_CMDLINE_FAIL 0   /* gone, refused, or the layout did not check out */
#define KOFW_CMDLINE_OK   1
#define KOFW_CMDLINE_CUT  2   /* read, and longer than `cap` */

/*
 * Fill `out` with the command line of `pid`, as sanitised UTF-8.
 *
 * Returns one of the three above. `out` is always NUL-terminated, including on
 * failure - a caller that ignores the return value gets an empty string rather
 * than a stale one, though ignoring it is exactly the mistake
 * KOFW_EF_CMDLINE_RACED exists to make visible.
 */
int kofw_cmdline_of(uint32_t pid, char *out, size_t cap);

#endif /* KOFGRILLE_WCMDLINE_H */
