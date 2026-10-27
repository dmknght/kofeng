/*
 * orbit_fx.h - what the adapters of the orbit stage share: the fake OS (tests/lib/orbit_sys.h), a scratch directory, a
 * memfd for "a file of these bytes", and the checks every record reader must hold.
 */
#ifndef KOF_FUZZ_ORBIT_FX_H
#define KOF_FUZZ_ORBIT_FX_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../lib/fuzz_drv.h"
#include "../../lib/orbit_sys.h"
#include "kofevt.h"

char *ofx_dir(void);
int ofx_memfd(const uint8_t *p, size_t n, char *path, size_t cap);

/* A record whose every string is a string: a NUL at the end of the arena, which is the guarantee kofevt_log_read gives and the
 * channel does not (WP12-10, a unit-test row). With it, a record from any source is safe to render; without it, none is. */
static inline void ofx_seal(struct kof_evt *e) { e->text[sizeof e->text - 1u] = '\0'; }

/* What a record that came out of a collector must satisfy, whatever bytes it was made from. */
static inline int ofx_evt_ok(const struct kof_evt *e)
{
	if (e->verb >= KOF_EVT_TYPE_COUNT)
		return 0;
	if (e->text_len > sizeof e->text)
		return 0;
	if (e->off_image != KOF_TEXT_NONE && e->off_image >= sizeof e->text)
		return 0;
	if (e->off_object != KOF_TEXT_NONE && e->off_object >= sizeof e->text)
		return 0;
	if (e->off_cmdline != KOF_TEXT_NONE && e->off_cmdline >= sizeof e->text)
		return 0;
	return 1;
}

#endif
