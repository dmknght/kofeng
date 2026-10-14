/*
 * objctx_spill.c - where a produced object too big for a comfortable heap goes, and what
 * happens when that place is not there.
 *
 * THE FLOW, for an object past SINK_SPILL (1 MiB) that is being emitted:
 *
 *   1. Probe, ONCE per scanner and scratch directory. Make an anonymous file (the host's
 *      scratch_dir first, then the platform's list) - failing that, STATE 2 / UNAVAILABLE
 *      (EACCES, EROFS, ENOENT, a quota). Ask the filesystem for its free space and whether
 *      it is RAM (tmpfs/ramfs; this host's /tmp is). A RAM place the host did not name
 *      saves nothing - the bytes are memory either way and the ledger counts them - so
 *      it is STATE 2 / RAM and the object is kept in heap. Free space must allow half of
 *      the largest object the cap lets through (obj_cap), else STATE 2 / SMALL.
 *   2. State 2: nothing is written to a file. The object stays in memory, bounded by the
 *      SAME ceilings as always - obj_cap, the resident allowance of this scanner's share
 *      and the produced-bytes budget, all of which scale with the caller's allowance. Hitting
 *      one is the existing cut (what is in hand is closed as a child, flagged KOF_BROKEN_LIMIT,
 *      limit_hits moves) and spill_ceiling counts it when a file was the alternative that
 *      was not available.
 *   3. State 1: bytes go to the file, and the free space is looked at again every
 *      SPILL_REFRESH bytes written (it can be consumed by others); below twice what the
 *      object may still add, or on any failed write (ENOSPC, EIO), the object is DROPPED
 *      - not closed as a prefix: its sink is discarded, the file with it - the ledger
 *      is given back, the object is marked KOF_BROKEN_LIMIT and spill_full counts it.
 *
 * CLEANUP CONTRACT: a spill file never has a name on disk. O_TMPFILE where the kernel has it,
 * else mkstemp + unlink in the same breath (Windows: _O_TEMPORARY). Every exit path - a failed
 * write, an early stop, scanner free, a child made from it - ends with the descriptor closed
 * or owned by the child, and the kernel reclaims the file. A killed process leaves nothing to
 * remove. Names, where they exist for a moment, are kofXXXXXX in the chosen directory.
 */

#define _GNU_SOURCE

#include "objctx_int.h"
#include "objsrc.h"
#include "../kofcore/kofplatform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <sys/statfs.h>
#include <sys/statvfs.h>
#endif

/* How much is written between looks at the free space. */
#define SPILL_REFRESH (16ull << 20)

static int real_open(void *user, const char *first)
{
	(void)user;
	return kof_src_tmpfile_at(first);
}

static int real_write(void *user, int fd, const void *p, uint64_t n)
{
	(void)user;
	return kof_write_all(fd, p, n);
}

static int real_space(void *user, int fd, uint64_t *avail, int *ram)
{
	(void)user;
	*ram = 0;
#ifdef _WIN32
	(void)fd;
	(void)avail;
	return 0;
#else
	{
		struct statvfs v;
		struct statfs f;

		if (fstatvfs(fd, &v) != 0)
			return 0;
		*avail = (uint64_t)v.f_bavail * (uint64_t)v.f_frsize;
		if (fstatfs(fd, &f) == 0)
			*ram = (uint64_t)f.f_type == 0x01021994u ||      /* tmpfs  */
			       (uint64_t)f.f_type == 0x858458f6u;        /* ramfs  */
		return 1;
	}
#endif
}

static const struct kof_spill_io REAL = { real_open, real_write, real_space, NULL };

static const struct kof_spill_io *io_of(const struct kof_scanner *sc)
{
	return sc->spill.io ? sc->spill.io : &REAL;
}

/* A test's table in place of the real calls; NULL puts them back. */
void kof_scan_spill_hook(struct kof_scanner *sc, const struct kof_spill_io *io)
{
	sc->spill.io = io;
	sc->spill.state = 0;
}

static void probe(struct kof_scanner *sc)
{
	const struct kof_spill_io *io = io_of(sc);
	uint64_t avail = 0;
	int ram = 0, fd, known;

	sc->spill.probed_for = sc->scratch;
	sc->spill.state = 2;
	fd = io->open(io->user, sc->scratch);
	if (fd < 0) {
		sc->spill.why = KOF_SPILL_UNAVAILABLE;
		return;
	}
	known = io->space(io->user, fd, &avail, &ram);
	close(fd);
	if (ram && !sc->scratch) {
		sc->spill.why = KOF_SPILL_RAM;
		return;
	}
	if (known && avail / 2u < sc->ledger.obj_cap) {
		sc->spill.why = KOF_SPILL_SMALL;
		sc->spill.avail = avail;
		return;
	}
	sc->spill.state = 1;
	sc->spill.why = KOF_SPILL_NONE;
	sc->spill.avail = known ? avail : UINT64_MAX;
	sc->spill.since = 0;
}

/* Whether a file is an option, probing if need be, without counting a refusal. */
int oc_spill_peek(struct kof_scanner *sc)
{
	if (sc->spill.state == 0 || sc->spill.probed_for != sc->scratch)
		probe(sc);
	return sc->spill.state == 1;
}

/* May this object go to a file. Counts why not, once per question. */
int oc_spill_usable(struct kof_scanner *sc)
{
	if (sc->spill.state == 0 || sc->spill.probed_for != sc->scratch)
		probe(sc);
	if (sc->spill.state == 1)
		return 1;
	switch (sc->spill.why) {
	case KOF_SPILL_UNAVAILABLE: sc->st.spill_unavailable++; break;
	case KOF_SPILL_SMALL:       sc->st.spill_small++; break;
	case KOF_SPILL_RAM:         sc->st.spill_ram++; break;
	default: break;
	}
	return 0;
}

/* The file for the object in hand, or -1 (and why). */
int oc_spill_open(struct kof_scanner *sc)
{
	const struct kof_spill_io *io = io_of(sc);
	int fd = io->open(io->user, sc->scratch);

	if (fd < 0) {
		sc->spill.state = 2;
		sc->spill.why = KOF_SPILL_UNAVAILABLE;
		sc->st.spill_unavailable++;
	}
	sc->spill.since = 0;
	return fd;
}

/*
 * Write n bytes of the object; 1 when they are in the file. On failure the object is
 * dropped whole (see the flow, step 3): nothing half-written is left to become a child.
 */
int oc_spill_write(struct kof_scanner *sc, const void *p, uint64_t n)
{
	const struct kof_spill_io *io = io_of(sc);
	uint64_t left = sc->ledger.obj_cap > sc->sink.spilled ? sc->ledger.obj_cap - sc->sink.spilled : 0;
	int ok = 1;

	if (sc->spill.since >= SPILL_REFRESH) {
		uint64_t avail = 0;
		int ram = 0;

		if (io->space(io->user, sc->sink.fd, &avail, &ram)) {
			sc->spill.avail = avail;
			if (avail / 2u < left)
				ok = 0;
		}
		sc->spill.since = 0;
	}
	if (ok && !io->write(io->user, sc->sink.fd, p, n))
		ok = 0;
	if (!ok) {
		sc->st.spill_full++;
		sc->spill.state = 0;            /* look again at the next object */
		kof_scan_sink_discard(sc);
		oc_scan_broken(sc, KOF_BROKEN_LIMIT);
		oc_scan_limit(sc);
		return 0;
	}
	sc->spill.since += n;
	return 1;
}

/*
 * THE SAME FILE FOR A ROOT FILE TOO BIG FOR THE HEAP (objsrc.c, kof_src_file), through the same
 * probe, hook and counters but not through the sink: a file read from the input is not an
 * object being emitted, so nothing here touches sc->sink.
 *
 * `scanner` is a struct kof_scanner *, spelled void * so the two functions have the shape the
 * file reader takes. The open answers -1 when no file may be made (the reasons are counted by
 * oc_spill_usable: no directory, too little space, a RAM filesystem the host did not name);
 * the write answers 1 when all of `n` bytes are in the file and otherwise counts spill_full
 * and asks for a new look at the next object, as a failed sink write does.
 */
int oc_spill_file_open(void *scanner)
{
	struct kof_scanner *sc = scanner;

	return oc_spill_usable(sc) ? oc_spill_open(sc) : -1;
}

int oc_spill_file_write(void *scanner, int fd, const void *p, uint64_t n)
{
	struct kof_scanner *sc = scanner;
	const struct kof_spill_io *io = io_of(sc);

	if (io->write(io->user, fd, p, n))
		return 1;
	sc->st.spill_full++;
	sc->spill.state = 0;
	return 0;
}

