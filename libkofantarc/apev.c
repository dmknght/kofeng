/*
 * apev.c - the netlink process connector, turned into neutral records.
 *
 * See apev.h for why there is no unprivileged mode and why the session proves
 * its own subscription instead of trusting that nothing failed.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

#include "apev.h"

/*
 * One read holds many records, the way afan's does. The connector's own
 * records are tiny - a header and a union - so this is a lot of them.
 */
#define APEV_BUF      8192u
#define APEV_PROBE_MS 300u

/*
 * THE PROCESS TABLE, and it does three jobs that turned out to be one.
 *
 * libkofgrille keeps the same thing for the same reasons - see KOFW_PTAB_MAX
 * in wfilter.h - and this is its Linux twin. What lives in it:
 *
 *   THE PARENT, FROM THE KERNEL RATHER THAN FROM /proc. A FORK record carries
 *   parent_tgid and child_tgid, so the launcher of a process is known before
 *   the process has done anything. Reading it from /proc/<pid>/stat at EXEC
 *   time - which is what this did first - is a race the collector loses on
 *   exactly the processes worth catching: the short-lived ones.
 *
 *   THE IMAGE, so name_of can answer. Without a table it could only ever
 *   answer about the very last record, which is not a cache.
 *
 *   WHICH PIDS THIS SESSION CALLED STARTED. An EXIT arrives for every process,
 *   including one that forked and never exec'd, and a stop with no start is
 *   the shape that leaks entries out of whatever table the consumer keeps.
 *
 * Open addressed on the pid and DELIBERATELY NOT EXACT: pids are reused, a
 * machine can start more processes than any fixed table holds, and a
 * recycled entry costs a column or one unpaired record - never a verdict.
 * What it must not do is grow without bound inside a sensor running for weeks.
 */
#define APEV_PTAB     4096u

/*
 * HOW LONG AN EXEC IS STILL "THE PROCESS STARTING", in nanoseconds.
 *
 * A program's own binary is opened for execution at the instant it starts; the
 * libraries it needs are opened by the dynamic linker over the milliseconds
 * after. Two seconds is not a measured boundary - it is a deliberately loose
 * one, for the reason KOFW_LATE_LOAD_TICKS gives on the Windows side: a cold
 * cache or a loaded machine must not push an ordinary start past it, and
 * erring long costs at most one suppressed duplicate.
 */
#define APEV_OWN_NS   2000000000ull

struct apev_ent {
	uint32_t pid;          /* 0 when free */
	uint32_t ppid;
	uint64_t started;      /* the connector's own stamp for the exec */
	uint8_t  running;      /* a PROC_START was emitted for this pid */
	/*
	 * As wide as the path read_exe produces, so what the table remembers
	 * is what the record carried rather than a shortened copy of it -
	 * which would also make the duplicate test compare two different
	 * strings and never match.
	 */
	char     image[512];
};

struct kofa_pev {
	int      fd;
	int      trace_self;
	uint32_t self_pid;

	union {
		char buf[APEV_BUF];
		struct nlmsghdr align;
	} rb;
	ssize_t  have;
	char    *at;

	struct apev_ent tab[APEV_PTAB];
	uint64_t recycled;    /* entries thrown out to make room */

	uint64_t seq;
	uint64_t records;     /* connector records read */
	uint64_t produced;    /* kof_evt records emitted */
	uint64_t dropped;     /* ENOBUFS: the socket buffer overran */
	uint64_t no_proc;     /* events whose /proc entry was already gone */

	struct kof_mon_api api;
};

/* ------------------------------------------------------------ the table */

/*
 * The entry for a pid, or NULL. Linear probing over a short run: a table this
 * size is far from full on any machine, and a walk that ran the whole of it on
 * a miss would cost four thousand comparisons per event.
 */
#define APEV_PROBE 8u

static struct apev_ent *ent_find(struct kofa_pev *p, uint32_t pid)
{
	uint32_t i, h = pid % APEV_PTAB;

	for (i = 0; i < APEV_PROBE; i++) {
		struct apev_ent *e = &p->tab[(h + i) % APEV_PTAB];

		if (e->pid == pid)
			return e;
	}
	return NULL;
}

/*
 * An entry for a pid, making one if there is none.
 *
 * A FULL RUN IS RECYCLED RATHER THAN REFUSED. wfilter.h draws the distinction
 * this follows: as a name cache a forgotten entry costs a column, and that is
 * all this is. Recycling is counted so a reader can tell a busy machine from a
 * table that is too small.
 */
static struct apev_ent *ent_get(struct kofa_pev *p, uint32_t pid)
{
	uint32_t i, h = pid % APEV_PTAB;
	struct apev_ent *free_slot = NULL, *oldest = NULL;

	for (i = 0; i < APEV_PROBE; i++) {
		struct apev_ent *e = &p->tab[(h + i) % APEV_PTAB];

		if (e->pid == pid)
			return e;
		if (!e->pid && !free_slot)
			free_slot = e;
		if (!oldest || e->started < oldest->started)
			oldest = e;
	}
	if (!free_slot) {
		free_slot = oldest;
		p->recycled++;
	}
	memset(free_slot, 0, sizeof *free_slot);
	free_slot->pid = pid;
	return free_slot;
}

static void ent_drop(struct kofa_pev *p, uint32_t pid)
{
	struct apev_ent *e = ent_find(p, pid);

	if (e)
		memset(e, 0, sizeof *e);
}

/* ----------------------------------------------------------------- /proc */

/*
 * The image and the command line, read the moment the event arrives.
 *
 * A RACE THIS CANNOT WIN, and the point is that it says so. By the time an
 * EXEC event is read the process may already be gone, and then there is no
 * /proc entry to read: the record reports the field MISSING rather than
 * carrying an empty string, so a consumer can tell "nobody looked" from
 * "there was nothing there".
 */
static int read_exe(uint32_t pid, char *out, size_t cap)
{
	char link[64];
	ssize_t n;

	snprintf(link, sizeof link, "/proc/%u/exe", (unsigned)pid);
	n = readlink(link, out, cap - 1u);
	if (n <= 0)
		return 0;
	out[n] = '\0';
	return 1;
}

/*
 * cmdline is NUL-separated in /proc and a command line is one string
 * everywhere else, so the separators become spaces here rather than at every
 * place that prints one. The trailing NUL the kernel leaves is dropped.
 */
static int read_cmdline(uint32_t pid, char *out, size_t cap)
{
	char path[64];
	int fd;
	ssize_t n;
	size_t i;

	snprintf(path, sizeof path, "/proc/%u/cmdline", (unsigned)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, out, cap - 1u);
	close(fd);
	if (n <= 0)
		return 0;
	out[n] = '\0';
	for (i = 0; i + 1u < (size_t)n; i++)
		if (!out[i])
			out[i] = ' ';
	while (n > 0 && (out[n - 1] == ' ' || !out[n - 1]))
		out[--n] = '\0';
	return out[0] != '\0';
}

/* ------------------------------------------------------------ the record */

/*
 * WHAT AN UNTYPED CONNECTOR EVENT SAYS, in one line.
 *
 * Written into the record's text so the event carries its own meaning: a RAW
 * record is an id and a blob otherwise, and an id nobody has typed yet is
 * exactly the thing a reader is trying to understand - see KOF_EVT_RAW.
 */
static void raw_detail(const struct proc_event *ev, char *out, size_t cap)
{
	switch (ev->what) {
	case PROC_EVENT_PTRACE:
		snprintf(out, cap, "ptrace tracer=%d",
			 (int)ev->event_data.ptrace.tracer_tgid);
		break;
	case PROC_EVENT_UID:
		snprintf(out, cap, "uid ruid=%u euid=%u",
			 (unsigned)ev->event_data.id.r.ruid,
			 (unsigned)ev->event_data.id.e.euid);
		break;
	case PROC_EVENT_GID:
		snprintf(out, cap, "gid rgid=%u egid=%u",
			 (unsigned)ev->event_data.id.r.rgid,
			 (unsigned)ev->event_data.id.e.egid);
		break;
	case PROC_EVENT_SID:
		snprintf(out, cap, "setsid");
		break;
	case PROC_EVENT_COMM:
		snprintf(out, cap, "comm %.*s", (int)sizeof
			 ev->event_data.comm.comm, ev->event_data.comm.comm);
		break;
	case PROC_EVENT_COREDUMP:
		snprintf(out, cap, "coredump");
		break;
	default:
		snprintf(out, cap, "proc_event 0x%08x", (unsigned)ev->what);
		break;
	}
}

/*
 * THE SUBJECT OF A CONNECTOR RECORD, whichever member of the union it is in.
 *
 * Every one of them names the process it is about in the same two fields under
 * a different member name, and reading the right member per type is four lines
 * of switch that were otherwise going to be repeated in every caller.
 */
static uint32_t ev_pid(const struct proc_event *ev)
{
	switch (ev->what) {
	case PROC_EVENT_FORK:   return (uint32_t)ev->event_data.fork.child_tgid;
	case PROC_EVENT_EXEC:   return (uint32_t)ev->event_data.exec.process_tgid;
	case PROC_EVENT_EXIT:   return (uint32_t)ev->event_data.exit.process_tgid;
	case PROC_EVENT_UID:
	case PROC_EVENT_GID:    return (uint32_t)ev->event_data.id.process_tgid;
	case PROC_EVENT_SID:    return (uint32_t)ev->event_data.sid.process_tgid;
	case PROC_EVENT_PTRACE: return (uint32_t)ev->event_data.ptrace.process_tgid;
	case PROC_EVENT_COMM:   return (uint32_t)ev->event_data.comm.process_tgid;
	case PROC_EVENT_COREDUMP:
		return (uint32_t)ev->event_data.coredump.process_tgid;
	default:                return 0;
	}
}

static int to_evt(struct kofa_pev *p, const struct proc_event *ev,
		  struct kof_evt *out)
{
	uint32_t pid = ev_pid(ev);
	struct apev_ent *e;
	uint16_t verb;

	if (!pid)
		return 0;

	/*
	 * A FORK IS RECORDED AND NOT REPORTED.
	 *
	 * It is the same program in a second process - a shell's subshell, a
	 * server's worker - and it carries no new image, so what a rule is
	 * written against is the exec that may follow. Reporting both would
	 * double the volume of the highest-value stream and give the second
	 * record nothing the first did not have.
	 *
	 * BUT IT IS WHERE THE PARENT COMES FROM, and that is why it is
	 * subscribed to at all. The kernel names both ends here; by EXEC time
	 * /proc may already be gone.
	 */
	if (ev->what == PROC_EVENT_FORK) {
		e = ent_get(p, pid);
		if (e) {
			e->ppid    = (uint32_t)ev->event_data.fork.parent_tgid;
			e->started = ev->timestamp_ns;
		}
		return 0;
	}

	switch (ev->what) {
	case PROC_EVENT_EXEC: verb = KOF_EVT_PROC_START; break;
	case PROC_EVENT_EXIT: verb = KOF_EVT_PROC_STOP;  break;
	/*
	 * AND THE ONES WITH NO VERB OF THEIR OWN, kept rather than dropped.
	 *
	 * A tracer attaching to another process is T1055 evidence; a
	 * credential change is T1548; a process renaming itself is T1036. The
	 * neutral vocabulary has no verb for any of them - adding one is a
	 * decision about BOTH platforms, see the note at the top of
	 * kofantarc.h - so they arrive as RAW carrying the connector's own id,
	 * which is exactly what KOF_EVT_RAW exists for.
	 */
	case PROC_EVENT_PTRACE:
	case PROC_EVENT_UID:
	case PROC_EVENT_GID:
	case PROC_EVENT_SID:
	case PROC_EVENT_COMM:
	case PROC_EVENT_COREDUMP:
		verb = KOF_EVT_RAW;
		break;
	default:
		return 0;
	}

	if (verb == KOF_EVT_PROC_STOP) {
		/*
		 * Only for a process this session called started - see the
		 * note on the table. The entry goes either way: the process is
		 * gone and the pid is about to be somebody else's.
		 */
		e = ent_find(p, pid);
		if (!e || !e->running) {
			ent_drop(p, pid);
			return 0;
		}
	}

	/* This process's own children, unless asked for - see the option. */
	if (!p->trace_self && pid == p->self_pid)
		return 0;

	memset(out, 0, sizeof *out);
	out->stamp  = (uint64_t)time(NULL);
	out->seq    = p->seq++;
	out->verb   = verb;
	out->os     = KOF_OS_LINUX;
	out->source = KOF_SRC_PROCESS;
	out->pid    = pid;
	out->off_object  = KOF_TEXT_NONE;
	out->off_image   = KOF_TEXT_NONE;
	out->off_cmdline = KOF_TEXT_NONE;

	if (verb == KOF_EVT_RAW) {
		char det[160];

		/* The connector's own id, so a reader can look up what
		 * arrived - see kof_evt.raw_id. */
		out->raw_id = (uint16_t)(ev->what & 0xffffu);
		raw_detail(ev, det, sizeof det);
		out->off_object = kof_evt_text_put(out, det);
		/*
		 * THE TRACER IS THE ACTOR, and it is the whole point of the
		 * record: a ptrace event is ABOUT the process being attached
		 * to and is caused by the one attaching.
		 */
		if (ev->what == PROC_EVENT_PTRACE)
			out->actor_pid =
				(uint32_t)ev->event_data.ptrace.tracer_tgid;
		else
			out->actor_pid = pid;
		p->produced++;
		return 1;
	}

	if (verb == KOF_EVT_PROC_STOP) {
		/*
		 * A stop is its own actor, absent evidence to the contrary:
		 * the connector's EXIT record does not say who ended the
		 * process - a signal from elsewhere and a plain return look
		 * identical - and there is no KOF_F_ for an actor to be
		 * reported missing with.
		 */
		out->actor_pid = pid;
		e = ent_find(p, pid);
		if (e) {
			if (e->ppid)
				out->ppid = e->ppid;
			else
				out->miss |= KOF_F_PPID;
			if (e->image[0])
				out->off_image = kof_evt_text_put(out,
								  e->image);
			else
				out->miss |= KOF_F_IMAGE;
		}
		ent_drop(p, pid);
		p->produced++;
		return 1;
	}

	/* ---- a start ---- */
	{
		char exe[512], cmd[1024];

		e = ent_get(p, pid);
		if (!e)
			return 0;
		e->running = 1;
		e->started = ev->timestamp_ns;
		/*
		 * THE PARENT, FROM THE FORK THIS SESSION ALREADY SAW. Falling
		 * back to /proc is for a process that forked before the
		 * session opened, and it is the racy path - which is why it is
		 * the fallback rather than the rule.
		 */
		if (!e->ppid) {
			char path[64], st[512];
			int fd;

			snprintf(path, sizeof path, "/proc/%u/stat",
				 (unsigned)pid);
			fd = open(path, O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				ssize_t n = read(fd, st, sizeof st - 1u);

				close(fd);
				if (n > 0) {
					char *rp;

					st[n] = '\0';
					/* Past comm, which may hold anything
					 * including spaces and brackets - the
					 * LAST ')' ends it. */
					rp = strrchr(st, ')');
					if (rp && rp[1] && rp[2])
						e->ppid = (uint32_t)strtoul(
							rp + 4, NULL, 10);
				}
			}
		}
		if (e->ppid) {
			out->ppid = e->ppid;
			/*
			 * THE ACTOR OF A START IS WHOEVER LAUNCHED IT, not the
			 * process that just came into being - see
			 * kof_evt.actor_pid, and libkofgrille fills it from the
			 * ETW raiser for the same reason.
			 */
			out->actor_pid = e->ppid;
		} else {
			out->miss |= KOF_F_PPID;
		}

		if (read_exe(pid, exe, sizeof exe)) {
			out->off_image  = kof_evt_text_put(out, exe);
			out->off_object = out->off_image;
			out->loc = kof_classify(exe, &out->attack);
			snprintf(e->image, sizeof e->image, "%s", exe);
		} else {
			out->miss |= KOF_F_IMAGE;
			p->no_proc++;
		}
		if (read_cmdline(pid, cmd, sizeof cmd))
			out->off_cmdline = kof_evt_text_put(out, cmd);
		else
			out->miss |= KOF_F_CMDLINE;
	}
	p->produced++;
	return 1;
}

/*
 * IS THIS EXEC-OPEN THE BINARY OF A PROCESS THAT JUST STARTED?
 *
 * fanotify reports FAN_OPEN_EXEC for a file opened with intent to execute, and
 * the connector reports the exec that follows. Run together they say the same
 * thing twice about the program's own binary - once as an image load and once
 * as a process start - and a consumer counting either would count it twice.
 *
 * This is the half of the answer only the process collector has: which pid
 * started, with which image, and when. The caller asks before publishing an
 * image load, and only the caller knows whether both collectors are running -
 * see the sensor. Asked of a session that never saw the start, the answer is
 * no, which is the safe direction: a duplicate is noise and a dropped event
 * is a gap.
 */
int kofa_pev_is_own_image(struct kofa_pev *p, uint32_t pid, const char *path,
			  uint64_t now_ns)
{
	const struct apev_ent *e;

	if (!p || !pid || !path || !*path)
		return 0;
	e = ent_find(p, pid);
	if (!e || !e->running || !e->image[0])
		return 0;
	if (strcmp(e->image, path))
		return 0;
	/*
	 * AND RECENTLY. A long-running process re-opening its own binary -
	 * a re-exec, a self-update reading itself - is a real event and not
	 * the start this already reported. `now_ns` of 0 means the caller has
	 * no clock to offer, and then the image match alone stands.
	 */
	if (now_ns && e->started && now_ns > e->started &&
	    now_ns - e->started > APEV_OWN_NS)
		return 0;
	return 1;
}

/* ------------------------------------------------------------- the stream */

/* Ask the kernel to start or stop sending. */
static int mcast(int fd, enum proc_cn_mcast_op op)
{
	struct {
		struct nlmsghdr      nl;
		struct cn_msg        cn;
		enum proc_cn_mcast_op op;
	} m;

	memset(&m, 0, sizeof m);
	m.nl.nlmsg_len  = sizeof m;
	m.nl.nlmsg_pid  = (uint32_t)getpid();
	m.nl.nlmsg_type = NLMSG_DONE;
	m.cn.id.idx     = CN_IDX_PROC;
	m.cn.id.val     = CN_VAL_PROC;
	m.cn.len        = sizeof m.op;
	m.op            = op;
	return send(fd, &m, sizeof m, 0) == (ssize_t)sizeof m;
}

/*
 * One record out of the buffer, refilling it when it is spent.
 *
 * Returns the proc_event, or NULL when the wait expired. The walk is the same
 * shape afan's is, and for the same reason: one read serves many next() calls
 * without re-entering the kernel.
 */
static const struct proc_event *stream_next(struct kofa_pev *p,
					    uint32_t wait_ms)
{
	for (;;) {
		while (p->have > 0) {
			struct nlmsghdr *h = (struct nlmsghdr *)p->at;
			struct cn_msg *cn;
			const struct proc_event *ev;

			if (!NLMSG_OK(h, (size_t)p->have)) {
				p->have = 0;
				break;
			}
			cn = (struct cn_msg *)NLMSG_DATA(h);
			ev = (const struct proc_event *)cn->data;
			{
				size_t step = NLMSG_ALIGN(h->nlmsg_len);

				p->at   += step;
				p->have -= (ssize_t)step;
			}
			if (h->nlmsg_type != NLMSG_DONE)
				continue;
			if (cn->id.idx != CN_IDX_PROC)
				continue;
			p->records++;
			return ev;
		}
		{
			struct pollfd pf;
			ssize_t n;

			pf.fd = p->fd;
			pf.events = POLLIN;
			pf.revents = 0;
			if (poll(&pf, 1, (int)wait_ms) <= 0)
				return NULL;
			n = recv(p->fd, p->rb.buf, sizeof p->rb.buf, 0);
			if (n <= 0) {
				/*
				 * ENOBUFS is the socket saying it threw
				 * records away because this reader was behind.
				 * Counted and reported through health, never
				 * silently absorbed - see afan's FAN_Q_OVERFLOW.
				 */
				if (n < 0 && errno == ENOBUFS)
					p->dropped++;
				return NULL;
			}
			p->have = n;
			p->at   = p->rb.buf;
		}
	}
}

/* ---------------------------------------------------------------- the api */

static int pev_next(void *self, struct kof_evt *out, uint32_t wait_ms)
{
	struct kofa_pev *p = (struct kofa_pev *)self;

	if (!p || !out)
		return 0;
	for (;;) {
		const struct proc_event *ev = stream_next(p, wait_ms);

		if (!ev)
			return 0;
		if (to_evt(p, ev, out))
			return 1;
		/*
		 * A record this build does not file. The wait is not restarted
		 * - the caller asked for at most wait_ms and a stream of forks
		 * would otherwise hold it for as long as the machine is busy.
		 */
		wait_ms = 0;
	}
}

static void pev_health(void *self, struct kof_evt_health *out)
{
	struct kofa_pev *p = (struct kofa_pev *)self;

	if (!p || !out)
		return;
	memset(out, 0, sizeof *out);
	out->produced = p->produced;
	out->dropped  = p->dropped;
}

/*
 * THE NAME BEHIND A PID, out of the table.
 *
 * It answered only about the very last record before the table existed, which
 * is not a cache: a consumer printing a line about a pid it saw a moment ago
 * got nothing. Borrowed and valid until the process exits, which is the
 * contract kof_mon_api.name_of states.
 */
static const char *pev_name_of(void *self, uint32_t pid, uint64_t start_time)
{
	struct kofa_pev *p = (struct kofa_pev *)self;
	const struct apev_ent *e;

	(void)start_time;
	if (!p)
		return NULL;
	e = ent_find(p, pid);
	return (e && e->image[0]) ? e->image : NULL;
}

static void pev_print_extra(void *self, FILE *out)
{
	struct kofa_pev *p = (struct kofa_pev *)self;

	if (!p || !out)
		return;
	fprintf(out, "  process connector: %llu record(s) read, %llu emitted\n",
		(unsigned long long)p->records,
		(unsigned long long)p->produced);
	/*
	 * THE RACE, AS A NUMBER. A process that exited before its own EXEC
	 * event was read has no /proc entry left, and the record then carries
	 * no path. It is the one loss here that is nobody's bug, so it is
	 * reported rather than buried.
	 */
	if (p->no_proc)
		fprintf(out, "  %llu exec(s) were gone before /proc "
			"could be read\n", (unsigned long long)p->no_proc);
	if (p->dropped)
		fprintf(out, "  %llu socket overrun(s)\n",
			(unsigned long long)p->dropped);
	/* A table too small for the machine, which costs a name or an unpaired
	 * record rather than a verdict - see APEV_PTAB. */
	if (p->recycled)
		fprintf(out, "  %llu process table entry(ies) recycled\n",
			(unsigned long long)p->recycled);
}

static void pev_close(void *self)
{
	kofa_pev_close((struct kofa_pev *)self);
}

/* --------------------------------------------------------------- opening */

/*
 * DOES THIS SOCKET ACTUALLY DELIVER - asked by causing an event and waiting
 * for it. See apev.h: the kernel refuses an unprivileged listener without
 * saying so, so there is nothing else to test.
 */
static int probe(struct kofa_pev *p, uint32_t ms)
{
	pid_t kid = fork();
	long end;
	struct timespec t;

	if (kid == 0)
		_exit(0);
	if (kid < 0)
		return 0;
	clock_gettime(CLOCK_MONOTONIC, &t);
	end = t.tv_sec * 1000L + t.tv_nsec / 1000000L + (long)ms;
	for (;;) {
		const struct proc_event *ev = stream_next(p, 20u);
		long now;

		if (ev && (ev->what == PROC_EVENT_FORK ||
			   ev->what == PROC_EVENT_EXIT ||
			   ev->what == PROC_EVENT_EXEC)) {
			waitpid(kid, NULL, 0);
			return 1;
		}
		clock_gettime(CLOCK_MONOTONIC, &t);
		now = t.tv_sec * 1000L + t.tv_nsec / 1000000L;
		if (now >= end)
			break;
	}
	waitpid(kid, NULL, 0);
	return 0;
}

struct kofa_pev *kofa_pev_open(const struct kofa_pev_option *opt, int *err)
{
	struct kofa_pev *p;
	struct kofa_pev_option o;
	struct sockaddr_nl sa;

	memset(&o, 0, sizeof o);
	if (opt)
		o = *opt;
	if (!o.probe_ms)
		o.probe_ms = APEV_PROBE_MS;
	if (err)
		*err = KOFA_OK;

	p = calloc(1, sizeof *p);
	if (!p) {
		if (err) *err = KOFA_ERR_NOMEM;
		return NULL;
	}
	p->fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC,
		       NETLINK_CONNECTOR);
	if (p->fd < 0) {
		/* No connector compiled in. Distinct from refused: one is
		 * fixed by privilege and the other is not fixed. */
		if (err)
			*err = (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			       ? KOFA_ERR_UNSUPPORTED : KOFA_ERR_OS;
		free(p);
		return NULL;
	}
	memset(&sa, 0, sizeof sa);
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = CN_IDX_PROC;
	sa.nl_pid    = 0;      /* the kernel picks, so two sessions can coexist */
	if (bind(p->fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
		if (err) *err = (errno == EPERM) ? KOFA_ERR_DENIED
						 : KOFA_ERR_OS;
		close(p->fd);
		free(p);
		return NULL;
	}
	p->self_pid   = (uint32_t)getpid();
	p->trace_self = o.trace_self;

	if (!mcast(p->fd, PROC_CN_MCAST_LISTEN)) {
		if (err) *err = (errno == EPERM) ? KOFA_ERR_DENIED
						 : KOFA_ERR_OS;
		close(p->fd);
		free(p);
		return NULL;
	}
	/*
	 * AND NOW PROVE IT. Everything above reported success on a kernel that
	 * then sent nothing at all - see apev.h for the measurement.
	 */
	if (!probe(p, o.probe_ms)) {
		if (err) *err = KOFA_ERR_DENIED;
		mcast(p->fd, PROC_CN_MCAST_IGNORE);
		close(p->fd);
		free(p);
		return NULL;
	}
	/* The probe's own records are not the caller's. */
	p->have = 0;
	p->seq = p->records = p->produced = 0;
	memset(p->tab, 0, sizeof p->tab);

	p->api.self        = p;
	p->api.next        = pev_next;
	p->api.health      = pev_health;
	p->api.name_of     = pev_name_of;
	p->api.print_extra = pev_print_extra;
	p->api.close       = pev_close;
	return p;
}

const struct kof_mon_api *kofa_pev_api(struct kofa_pev *p)
{
	return p ? &p->api : NULL;
}

void kofa_pev_close(struct kofa_pev *p)
{
	if (!p)
		return;
	if (p->fd >= 0) {
		mcast(p->fd, PROC_CN_MCAST_IGNORE);
		close(p->fd);
	}
	free(p);
}
