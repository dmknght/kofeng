/* See proc_parse.h. */

#include <string.h>

#include "proc_parse.h"

/* One - see KOF_SCAN_PROC_CLAIMED for why the head and the descriptors are
 * facts on a panel rather than bytes to search. */
const uint32_t kof_proc_regions[3] = {
	KOF_SCAN_PROC_CMDLINE, KOF_SCAN_PROC_ENV, KOF_SCAN_PROC_NET
};

/*
 * REFUSES EVERYTHING. A snapshot is declared, never recognised - see the
 * header. Returning 0 here is what keeps this row out of the way of every
 * object that is merely bytes.
 */
/*
 * WHERE THE THREE REGIONS ARE, which the parse already worked out and used to
 * keep to itself.
 *
 * The lengths were computed below and stored on the view, and nothing ever
 * turned them into extents - ctx->resolve_scan was left NULL, so
 * kof_scan_resolve_range answered "no extents" for all three. The regions were
 * therefore DECLARED and NAMED and empty: a rule targeting the command line
 * had nowhere to search, and a viewer drew a process with no region rows at
 * all while every other format had them. amsi_parse.c, the other declared
 * format, has always set this.
 *
 * They PARTITION the record - see the note beside the lengths - so a mask of
 * several is several extents and every byte of the arena is in exactly one.
 */
static uint32_t proc_resolve_scan(const struct kof_obj_ctx *ctx,
				  uint32_t mask, struct kof_range *ext,
				  uint32_t cap)
{
	const struct kof_proc_info *pi = ctx->file_header;
	uint32_t n = 0;
	uint64_t at;

	if (!pi || !pi->valid)
		return 0;
	at = 0;
	if ((mask & KOF_SCAN_PROC_META) && pi->len_meta && n < cap) {
		ext[n].off = at;
		ext[n].len = pi->len_meta;
		n++;
	}
	at += pi->len_meta;
	if ((mask & KOF_SCAN_PROC_CMDLINE) && pi->len_cmdline && n < cap) {
		ext[n].off = at;
		ext[n].len = pi->len_cmdline;
		n++;
	}
	at += pi->len_cmdline;
	if ((mask & KOF_SCAN_PROC_ENV) && pi->len_env && n < cap) {
		ext[n].off = at;
		ext[n].len = pi->len_env;
		n++;
	}
	at += pi->len_env;
	if ((mask & KOF_SCAN_PROC_NET) && pi->len_net && n < cap) {
		ext[n].off = at;
		ext[n].len = pi->len_net;
		n++;
	}
	at += pi->len_net;
	if ((mask & KOF_SCAN_PROC_FD) && pi->len_fd && n < cap) {
		ext[n].off = at;
		ext[n].len = pi->len_fd;
		n++;
	}
	return n;
}

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
	pi->os           = r->os;
	pi->n_fd         = r->n_fd;
	pi->n_socket     = r->n_socket;
	pi->n_like_stdin = r->n_like_stdin;
	pi->flags        = r->flags;

	/* The tail is two words whatever the platform; which two they are is
	 * what `os` says. Copied rather than interpreted - a parser that knew
	 * what a Windows integrity level meant would be a parser that has to
	 * change when Windows adds one. */
	memcpy(&pi->plat_a, &r->plat, sizeof pi->plat_a);
	memcpy(&pi->plat_b, (const uint8_t *)&r->plat + sizeof pi->plat_a,
	       sizeof pi->plat_b);

	pi->off_exe     = r->off_exe;
	pi->off_comm    = r->off_comm;
	pi->off_cmdline = r->off_cmdline;
	pi->off_env     = r->off_environ;
	pi->off_net     = r->off_net;
	pi->off_fd0     = r->off_fd0;

	/*
	 * EVERY OFFSET IS CHECKED BEFORE ANYTHING READS THROUGH IT. The record
	 * came off a channel or out of a file and is exactly as trustworthy as
	 * whoever wrote it.
	 */
	if (!str_ok(b, r->off_exe, total))     pi->off_exe = 0;
	if (!str_ok(b, r->off_comm, total))    pi->off_comm = 0;
	if (!str_ok(b, r->off_cmdline, total)) pi->off_cmdline = 0;
	if (!str_ok(b, r->off_environ, total)) pi->off_env = 0;
	if (!str_ok(b, r->off_net, total)) pi->off_net = 0;

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
		/*
		 * AN ABSENT SECTION TAKES THE NEXT ONE'S OFFSET, NOT THE END.
		 *
		 * Read backwards for that reason. A boundary is "where the
		 * next section starts", and a process with no connections has
		 * no off_net - so taking `total` there gave the ENVIRONMENT
		 * every byte after it, the descriptor links included. That was
		 * invisible while the environment was one space-separated
		 * string and strlen ended it; the moment its pieces were
		 * NUL-separated and the extent had to say where it stopped,
		 * three descriptor paths showed up as three more variables.
		 */
		uint32_t fd  = pi->off_fd0 ? pi->off_fd0 : total;
		uint32_t net = pi->off_net ? pi->off_net : fd;
		uint32_t env = pi->off_env ? pi->off_env : net;
		uint32_t cmd = pi->off_cmdline ? pi->off_cmdline : env;

		/*
		 * FOUR SECTIONS NOW, AND THE ORDER IS STILL THE PRODUCER'S.
		 * Each boundary is clamped forward from the one before, so a
		 * record whose offsets are out of order loses the section
		 * rather than the partition: a missing piece gives its bytes
		 * to its neighbour and nothing overlaps.
		 */
		if (cmd > total) cmd = total;
		if (env < cmd)   env = cmd;
		if (env > total) env = total;
		if (net < env)   net = env;
		if (net > total) net = total;
		if (fd < net)    fd = net;
		if (fd > total)  fd = total;

		pi->len_meta    = cmd;
		pi->len_cmdline = env - cmd;
		pi->len_env     = net - env;
		pi->len_net     = fd - net;
		pi->len_fd      = total - fd;
	}

	pi->valid = 1;

	/*
	 * THE PARSE SETS THE FORMAT, and the declared path relies on it.
	 *
	 * scan.c deliberately does NOT set ctx->format for a format that has a
	 * parser: a declaration whose parse then refuses would otherwise leave
	 * the id set and file_header NULL, and the first module reached for
	 * that format would dereference nothing. So the id is the PARSER's to
	 * grant, and forgetting it here is not a crash - it is silence. Every
	 * rule targeting KOF_EVT_PROC simply never ran, and the object came
	 * back clean.
	 */
	ctx->format = KOF_EVT_PROC;
	/*
	 * AND THE PLATFORM AS THE SUBTYPE - see KOF_PROC_OS_LIST for why a
	 * command line is not one language. Straight from the record: the
	 * collector said which machine it read, and this axis exists so a rule
	 * can be dropped on that without being entered.
	 */
	ctx->subtype = r->os;
	ctx->obj_size = total;

	/*
	 * AND THE VIEW, which is what kof_proc(ctx) casts.
	 *
	 * Forgetting this is the same failure as forgetting the format and has
	 * the same symptom: every rule ran, every rule found a NULL view, and
	 * every rule returned without deciding. The scan reported two modules
	 * examined and nothing found, which reads exactly like a database that
	 * has nothing to say about this object.
	 */
	ctx->file_header = pi;
	/* After file_header, which the resolver reads. */
	ctx->resolve_scan = proc_resolve_scan;
	return 1;
}

/*
 * THE KOF_SCAN_* SPELLING, which is what this returns and is not a display
 * word. kofformat.h states the contract where it declares region_name and
 * kof_region_mask_of - "a source carries the spelling" - and every other
 * parser here meets it by stringifying the enumerator.
 *
 * IT USED TO RETURN "MEM_CMDLINE", and that was not a shorter label, it was a
 * different answer to a different question. The consequences were both on the
 * signature path and both silent:
 *
 *   the editor WRITES this word into KOF_TARGET_RANGE, so a rule drafted off
 *   a process command line was generated as KOF_TARGET_RANGE(x, MEM_CMDLINE)
 *   and ksigbuilder refused it with "unknown region";
 *
 *   the editor READS a rule back by searching the source for this word, so
 *   KOF_SCAN_PROC_CMDLINE in a hand-written module matched nothing and the
 *   range came back empty - which saves as a rule that searches everything.
 *
 * The display word is DERIVED, by kof_region_label, which takes what follows
 * KOF_SCAN_<FMT>_ - so the column reads CMDLINE, ENV, NET, exactly as it
 * reads CODE and DATA for an ELF. Nothing is lost by spelling the enumerator
 * here; the label was the only thing the short form bought.
 *
 * THREE, AND NOT FIVE. kof_proc_regions advertises CMDLINE, ENV and NET, and
 * KOF_SCAN_PROC_CLAIMED says why META and FD are not regions but fields. A
 * name for a bit no signature may target is a name that invites one to be
 * written, so those return NULL - the same answer every other parser gives for
 * a bit it does not have.
 */
#define X_CASE(b) case (b): return #b;
const char *kof_proc_region_name(uint32_t bit)
{
	switch (bit) {
	KOF_SCAN_PROC_LIST(X_CASE)
	default: return NULL;
	}
}
#undef X_CASE

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
