/* SPDX-License-Identifier: Apache-2.0 */
/* See kofproc.h. */

#include <string.h>

#include "kofproc.h"

/*
 * Append one NUL-terminated string and hand back its offset, or 0 when there
 * was nothing to write or no room. Zero doubles as "absent" because the head
 * occupies offset 0, so no real string can ever start there.
 */
static uint16_t put(char *buf, uint32_t cap, uint32_t *at, const char *s,
		    int *overflow)
{
	uint32_t n;

	if (!s || !*s)
		return 0;
	n = (uint32_t)strlen(s) + 1u;
	if (*at + n > cap || *at + n > 0xffffu) {
		/*
		 * A STRING THAT DID NOT FIT FAILS THE WHOLE RECORD.
		 *
		 * Returning 0 alone would leave a perfectly valid record that
		 * simply has no command line - and a rule would read that
		 * absence as a fact about the process rather than as a buffer
		 * that was too small. kofproc.h promises no truncation; this
		 * is where the promise is kept.
		 */
		*overflow = 1;
		return 0;
	}
	memcpy(buf + *at, s, n);
	{
		uint16_t off = (uint16_t)*at;

		*at += n;
		return off;
	}
}

/*
 * The same, for a block that is not one string: the environment, whose
 * assignments are separated by NUL.
 *
 * A terminating NUL is written after it as well, so every offset in the arena
 * still points at something a reader can treat as a C string - str_ok in the
 * parse looks for exactly that, and a block with no terminator would fail a
 * check that is there to catch a truncated record.
 */
static uint16_t put_n(char *buf, uint32_t cap, uint32_t *at, const char *s,
		      uint32_t len, int *overflow)
{
	if (!s || !len)
		return 0;
	if (*at + len + 1u > cap || *at + len + 1u > 0xffffu) {
		*overflow = 1;
		return 0;
	}
	memcpy(buf + *at, s, len);
	buf[*at + len] = '\0';
	{
		uint16_t off = (uint16_t)*at;

		*at += len + 1u;
		return off;
	}
}

uint32_t kof_proc_build_rec(const struct kof_proc_build *b, void *buf,
			    uint32_t cap)
{
	struct kof_proc_rec *r = (struct kof_proc_rec *)buf;
	char    *a = (char *)buf;
	uint32_t at;

	if (!b || !buf || cap < sizeof *r)
		return 0;

	memset(r, 0, sizeof *r);
	r->magic    = KOF_PROC_REC_MAGIC;
	r->version  = KOF_PROC_REC_VERSION;
	r->head_len = (uint16_t)sizeof *r;
	r->os       = b->os;

	r->pid        = b->pid;
	r->ppid       = b->ppid;
	r->start_time = b->start_time;

	r->n_fd         = b->n_fd;
	r->n_socket     = b->n_socket;
	r->n_like_stdin = b->n_like_stdin;
	r->flags        = b->flags;

	memcpy(&r->plat, &b->plat_a, sizeof b->plat_a);
	memcpy((uint8_t *)&r->plat + sizeof b->plat_a, &b->plat_b,
	       sizeof b->plat_b);

	/*
	 * THE ARENA, IN REGION ORDER, AND THE ORDER IS THE CONTRACT.
	 *
	 * META first (the identity), then CMDLINE, then FD. kofmod/proc.h
	 * partitions the record at off_cmdline and off_fd0, so writing them in
	 * any other order produces regions that overlap - which the region
	 * contract forbids and which a rule scoped to one of them would
	 * silently search the wrong bytes for.
	 */
	at = (uint32_t)sizeof *r;
	{
		int over = 0;

		r->off_exe     = put(a, cap, &at, b->exe, &over);
		r->off_comm    = put(a, cap, &at, b->comm, &over);
		r->off_cmdline = put(a, cap, &at, b->cmdline, &over);
		/* Between the command line and the descriptors, so the arena
		 * stays in region order - see the partition in proc_parse.c. */
		r->off_environ = put_n(a, cap, &at, b->environ,
				       b->environ_len, &over);
		r->off_net     = put(a, cap, &at, b->net, &over);
		r->off_fd0     = put(a, cap, &at, b->fd0, &over);
		r->off_fd1     = put(a, cap, &at, b->fd1, &over);
		r->off_fd2     = put(a, cap, &at, b->fd2, &over);
		if (over)
			return 0;
	}

	if (at > 0xffffu)
		return 0;
	r->total_len = (uint16_t)at;
	return at;
}
