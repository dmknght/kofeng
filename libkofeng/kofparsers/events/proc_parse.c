/* SPDX-License-Identifier: Apache-2.0 */
/* See proc_parse.h. */

#include <string.h>

#include "proc_parse.h"

const uint32_t kof_proc_regions[3] = {
	KOF_SCAN_PROC_META, KOF_SCAN_PROC_CMDLINE, KOF_SCAN_PROC_FD
};

/*
 * REFUSES EVERYTHING. A snapshot is declared, never recognised - see the
 * header. Returning 0 here is what keeps this row out of the way of every
 * object that is merely bytes.
 */
int kof_proc_sniff(kof_buf b)
{
	(void)b;
	return 0;
}

/* Is [off, off+n) inside the record, and does it hold a NUL-terminated string?
 * A string that runs to the end without one is refused rather than truncated:
 * truncating would hand a rule a name the process does not have. */
static int str_ok(kof_buf b, uint32_t off, uint32_t end)
{
	uint32_t i;

	if (!off || off >= end || end > b.n)
		return 0;
	for (i = off; i < end; i++)
		if (b.p[i] == '\0')
			return 1;
	return 0;
}

static int starts_socket(kof_buf b, uint32_t off)
{
	return off && off + 7u <= b.n && !memcmp(b.p + off, "socket:", 7);
}

static int same_str(kof_buf b, uint32_t a, uint32_t c)
{
	if (!a || !c)
		return 0;
	return strcmp((const char *)b.p + a, (const char *)b.p + c) == 0;
}

int kof_proc_parse(kof_buf b, void *view, struct kof_obj_ctx *ctx)
{
	struct kof_proc_info     *pi = (struct kof_proc_info *)view;
	const struct kof_proc_rec *r;
	uint32_t total;

	if (!pi || !ctx)
		return 0;
	memset(pi, 0, sizeof *pi);
	pi->version = KOF_PROC_INFO_VERSION;

	if (b.n < sizeof *r)
		return 0;
	r = (const struct kof_proc_rec *)b.p;

	if (r->magic != KOF_PROC_REC_MAGIC ||
	    r->version != KOF_PROC_REC_VERSION)
		return 0;

	/*
	 * THE HEAD MUST END WHERE THE RECORD SAYS AND THE ARENA MUST FIT.
	 *
	 * head_len is the producer's own statement of where its fixed part
	 * stops, and a build that appended a field writes a bigger one - so
	 * this accepts any head at least as large as the one it knows and
	 * refuses a smaller one, which is what append-only buys.
	 */
	total = r->total_len;
	if (r->head_len < sizeof *r || total < r->head_len || total > b.n)
		return 0;

	pi->pid          = r->pid;
	pi->ppid         = r->ppid;
	pi->start_time   = r->start_time;
	pi->uid          = r->uid;
	pi->gid          = r->gid;
	pi->n_fd         = r->n_fd;
	pi->n_socket     = r->n_socket;
	pi->n_like_stdin = r->n_like_stdin;
	pi->flags        = r->flags;

	pi->off_exe     = r->off_exe;
	pi->off_comm    = r->off_comm;
	pi->off_cmdline = r->off_cmdline;
	pi->off_fd0     = r->off_fd0;

	/*
	 * EVERY OFFSET IS CHECKED BEFORE ANYTHING READS THROUGH IT. The record
	 * came off a channel or out of a file and is exactly as trustworthy as
	 * whoever wrote it.
	 */
	if (!str_ok(b, r->off_exe, total))     pi->off_exe = 0;
	if (!str_ok(b, r->off_comm, total))    pi->off_comm = 0;
	if (!str_ok(b, r->off_cmdline, total)) pi->off_cmdline = 0;

	if (str_ok(b, r->off_fd0, total)) {
		pi->fd0_socket = (uint8_t)starts_socket(b, r->off_fd0);
		if (str_ok(b, r->off_fd1, total)) {
			pi->fd1_socket = (uint8_t)starts_socket(b, r->off_fd1);
			pi->fd_same_01 =
				(uint8_t)same_str(b, r->off_fd0, r->off_fd1);
		}
		if (str_ok(b, r->off_fd2, total)) {
			pi->fd2_socket = (uint8_t)starts_socket(b, r->off_fd2);
			pi->fd_same_tty =
				(uint8_t)(!starts_socket(b, r->off_fd0) &&
					  same_str(b, r->off_fd0, r->off_fd1) &&
					  same_str(b, r->off_fd1, r->off_fd2) &&
					  r->off_fd0 + 9u <= b.n &&
					  !memcmp(b.p + r->off_fd0,
						  "/dev/pts/", 9));
		}
	} else {
		pi->off_fd0 = 0;
	}

	if (pi->off_comm) {
		const char *c = (const char *)b.p + pi->off_comm;
		size_t      n = strlen(c);

		pi->comm_bracketed =
			(uint8_t)(n >= 3u && c[0] == '[' && c[n - 1] == ']');
	}

	/*
	 * THE THREE REGIONS, AND THEY PARTITION THE RECORD.
	 *
	 * The producer writes the arena in region order - identity, then the
	 * command line, then the descriptor links - so the boundaries are two
	 * offsets and every byte falls in exactly one. A record that does not
	 * follow that order loses the partition, so the boundaries are taken
	 * from the offsets rather than assumed, and a missing section simply
	 * gives its neighbour the bytes.
	 */
	{
		uint32_t cmd = pi->off_cmdline ? pi->off_cmdline : total;
		uint32_t fd  = pi->off_fd0 ? pi->off_fd0 : total;

		if (cmd > total) cmd = total;
		if (fd < cmd)    fd = cmd;
		if (fd > total)  fd = total;

		pi->len_meta    = cmd;
		pi->len_cmdline = fd - cmd;
		pi->len_fd      = total - fd;
	}

	pi->valid = 1;
	ctx->obj_size = total;
	return 1;
}

const char *kof_proc_region_name(uint32_t bit)
{
	switch (bit) {
	case KOF_SCAN_PROC_META:    return "meta";
	case KOF_SCAN_PROC_CMDLINE: return "cmdline";
	case KOF_SCAN_PROC_FD:      return "fd";
	default:                    return "?";
	}
}

const char *kof_proc_anomaly_name(unsigned index)
{
	(void)index;
	return "?";
}

uint64_t kof_proc_anomalies(const void *view)
{
	(void)view;
	return 0;
}
