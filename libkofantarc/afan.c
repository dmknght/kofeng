/* SPDX-License-Identifier: Apache-2.0 */
/* See afan.h, which carries the measurements this file is built on. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/fanotify.h>
#include <sys/stat.h>

#include "afan.h"

/* How many watch paths a session keeps. A sensor watching more than this is
 * really asking for a filesystem mark, which is one entry. */
#define AFAN_MAX_WATCH 32u

/* One read of the fanotify fd. Events are small - 64 bytes for a dirent event
 * with a name - so this drains a burst in one syscall without being a page a
 * caller has to think about. */
#define AFAN_BUF 8192u

struct kofa_fan {
	int fd;
	int mode;
	int trace_self;
	uint32_t self_pid;

	char     watch[AFAN_MAX_WATCH][256];
	int      watch_fd[AFAN_MAX_WATCH];
	uint32_t n_watch;

	/* The current read buffer and where the walk is inside it, so one
	 * read can serve many next() calls without re-entering the kernel. */
	char     buf[AFAN_BUF];
	ssize_t  have;
	char    *at;

	/* What is left of the event being emitted - see verb_take. */
	uint64_t cur_mask;
	int      cur_open;

	uint64_t seq;
	uint64_t dropped;     /* FAN_Q_OVERFLOW records */
	uint64_t records;     /* fanotify records read */
	uint64_t produced;    /* kof_evt records emitted - see the counter */

	char path[1024];      /* assembled for the record being built */

	struct kof_mon_api api;
};

const char *kofa_fan_mode_name(int mode)
{
	switch (mode) {
	case KOFA_FAN_FULL:     return "full";
	case KOFA_FAN_DEGRADED: return "degraded";
	default:                return "?";
	}
}

/* ------------------------------------------------------------ the record */

/*
 * ONE VERB OFF A MASK, and the mask is what makes this a loop rather than a
 * lookup.
 *
 * FANOTIFY MERGES EVENTS FOR THE SAME OBJECT. Measured, from one create then
 * rename then delete of one file:
 *
 *     mask=0x100   FAN_CREATE
 *     mask=0x140   FAN_CREATE | FAN_MOVED_FROM
 *     mask=0x280   FAN_DELETE | FAN_MOVED_TO
 *
 * Three records carrying five events. The first version of this function
 * picked the most specific bit and returned it, which is a defensible reading
 * of "what is this event" and is wrong: the file's CREATION and its DELETION
 * both vanished, because each shared a record with a rename. A rule asking
 * "was this file created" would have been silent about a file that was, for
 * the sole reason that something renamed it afterwards.
 *
 * So the caller takes bits off until there are none, and emits a record for
 * each. The ORDER is the order they can only have happened in - a thing is
 * created before it is written, written before it is moved, and moved before
 * it is deleted - so a consumer reading the stream in order reads the file's
 * history in order.
 */
static uint16_t verb_take(uint64_t *mask)
{
	static const struct { uint64_t bit; uint16_t verb; } order[] = {
		{ FAN_CREATE,                     KOF_EVT_FILE_NEW },
		{ FAN_OPEN_EXEC,                  KOF_EVT_IMAGE_LOAD },
		{ FAN_MODIFY | FAN_CLOSE_WRITE,   KOF_EVT_FILE_WRITE },
		{ FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MOVE_SELF,
						  KOF_EVT_FILE_RENAME },
		{ FAN_DELETE | FAN_DELETE_SELF,   KOF_EVT_FILE_DELETE }
	};
	unsigned i;

	for (i = 0; i < sizeof order / sizeof order[0]; i++)
		if (*mask & order[i].bit) {
			*mask &= ~order[i].bit;
			return order[i].verb;
		}
	*mask = 0;
	return KOF_EVT_NONE;
}

/*
 * Put a NUL-terminated string in the record's arena and return its offset, or
 * KOF_TEXT_NONE. Bounded by the arena, and a string that does not fit is
 * refused rather than cut - a truncated path still looks like a path, and a
 * rule would match it and be wrong without knowing why.
 */
static uint16_t text_put(struct kof_evt *e, const char *s)
{
	size_t n, room = sizeof e->text;

	if (!s || !*s)
		return KOF_TEXT_NONE;
	n = strlen(s) + 1u;
	if ((size_t)e->text_len + n > room) {
		e->flags |= KOF_EF_TRUNCATED;
		return KOF_TEXT_NONE;
	}
	memcpy(e->text + e->text_len, s, n);
	{
		uint16_t off = e->text_len;

		e->text_len = (uint16_t)(e->text_len + n);
		return off;
	}
}

/*
 * The path an event names.
 *
 * DFID_NAME gives the directory's handle and the entry's name. Resolving the
 * handle needs open_by_handle_at, which needs CAP_DAC_READ_SEARCH - so in the
 * degraded mode there is nothing to resolve it WITH, and the directory is
 * instead the one this session marked. That works because an unprivileged
 * session only has directory marks in the first place: the event came from a
 * directory we named, so we know what it is called.
 *
 * With a filesystem mark the directory can be anywhere, and then the handle is
 * the only answer. Both paths end in the same buffer and the caller cannot
 * tell which produced it, which is the point.
 */
static const char *event_path(struct kofa_fan *f,
			      const struct fanotify_event_metadata *m,
			      const char *name, struct file_handle *fh,
			      int mount_fd)
{
	f->path[0] = '\0';

	if (fh && mount_fd >= 0) {
		int dfd = open_by_handle_at(mount_fd, fh, O_PATH | O_NOFOLLOW);

		if (dfd >= 0) {
			char link[64];
			char dir[768];
			ssize_t n;

			snprintf(link, sizeof link, "/proc/self/fd/%d", dfd);
			n = readlink(link, dir, sizeof dir - 1);
			close(dfd);
			if (n > 0) {
				dir[n] = '\0';
				if (name && *name)
					snprintf(f->path, sizeof f->path,
						 "%s/%s", dir, name);
				else
					snprintf(f->path, sizeof f->path,
						 "%s", dir);
				return f->path;
			}
		}
	}

	/*
	 * No handle to resolve: the directory is one we marked. With more than
	 * one watch this cannot say WHICH, so it names the first - and that is
	 * a real limit of the degraded mode rather than something to hide. A
	 * session that needs the answer runs privileged and gets the handle.
	 */
	if (f->n_watch && name && *name)
		snprintf(f->path, sizeof f->path, "%s/%s", f->watch[0], name);
	else if (name && *name)
		snprintf(f->path, sizeof f->path, "%s", name);

	(void)m;
	return f->path;
}

/*
 * Turn one fanotify event into the neutral record.
 *
 * Returns 0 for an event this build does not file - a mask with no verb, or a
 * queue overflow, which is counted rather than reported as an event.
 */
static int to_evt(struct kofa_fan *f,
		  const struct fanotify_event_metadata *m,
		  uint16_t verb, struct kof_evt *out)
{
	const char *name = NULL;
	struct file_handle *fh = NULL;
	const struct fanotify_event_info_header *h;
	const char *end = (const char *)m + m->event_len;

	if (!verb)
		return 0;

	h = (const void *)((const char *)m + sizeof *m);
	while ((const char *)h + sizeof *h <= end && h->len >= sizeof *h) {
		if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
		    h->info_type == FAN_EVENT_INFO_TYPE_DFID ||
		    h->info_type == FAN_EVENT_INFO_TYPE_FID) {
			const struct fanotify_event_info_fid *fi =
				(const void *)h;

			fh = (struct file_handle *)(uintptr_t)
			     (const void *)fi->handle;
			if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME)
				name = (const char *)fh->f_handle +
				       fh->handle_bytes;
		}
		h = (const void *)((const char *)h + h->len);
	}

	memset(out, 0, sizeof *out);
	out->stamp = (uint64_t)time(NULL);
	out->seq   = f->seq++;
	out->verb  = verb;
	out->os    = KOF_OS_LINUX;
	out->source = KOF_SRC_FILE;

	/*
	 * THE PID, AND WHEN THERE IS NOT ONE.
	 *
	 * Unprivileged, the kernel fills this only for events this process
	 * raised and zeroes it for everything else - see afan.h. Zero is a
	 * legal pid, so it is never written as one: the record says the field
	 * is MISSING and a consumer that branches on it has to handle that.
	 */
	if (m->pid > 0) {
		out->pid = (uint32_t)m->pid;
		out->actor_pid = (uint32_t)m->pid;
	} else {
		out->miss |= KOF_F_PID;
	}

	{
		const char *p = event_path(f, m, name,
					   (f->mode == KOFA_FAN_FULL) ? fh
								      : NULL,
					   f->n_watch ? f->watch_fd[0] : -1);

		out->off_object = text_put(out, p);
		out->off_image  = KOF_TEXT_NONE;
		out->off_cmdline = KOF_TEXT_NONE;
		out->loc = kof_classify(p, &out->attack);
	}
	return 1;
}

/* ---------------------------------------------------------------- the api */

static int fan_next(void *self, struct kof_evt *out, uint32_t wait_ms)
{
	struct kofa_fan *f = (struct kofa_fan *)self;

	if (!f || !out)
		return 0;

	for (;;) {
		/* Anything left in the buffer from the last read. */
		/*
		 * `have` IS the bytes left, because it is decremented as `at`
		 * advances - so it is what FAN_EVENT_OK must be asked about.
		 * Passing the original read length here instead would let the
		 * walk step past the end of the last event.
		 */
		while (f->at && f->have > 0) {
			const struct fanotify_event_metadata *m =
				(const void *)f->at;
			uint16_t verb;

			if (!FAN_EVENT_OK(m, f->have))
				break;

			/*
			 * A RECORD IS OPENED ONCE AND MAY OWE SEVERAL EVENTS.
			 * fanotify merges verbs for one object into one
			 * record - see verb_take - so the walk only advances
			 * when the mask is exhausted.
			 */
			if (!f->cur_open) {
				int self_ev = (m->pid > 0 &&
					       (uint32_t)m->pid == f->self_pid);

				f->records++;
				if (m->mask & FAN_Q_OVERFLOW) {
					/*
					 * The kernel's queue filled and it
					 * dropped records. Counted, never
					 * reported as an event: a consumer
					 * seeing it as one would have an event
					 * with no file, no actor and no verb.
					 */
					f->dropped++;
					f->at += m->event_len;
					f->have -= m->event_len;
					continue;
				}
				/* The feedback loop - see afan.h on why this
				 * is a trap in the degraded mode. */
				if (self_ev && !f->trace_self) {
					f->at += m->event_len;
					f->have -= m->event_len;
					continue;
				}
				f->cur_mask = m->mask;
				f->cur_open = 1;
			}

			verb = verb_take(&f->cur_mask);
			if (!verb) {
				f->cur_open = 0;
				f->at += m->event_len;
				f->have -= m->event_len;
				continue;
			}
			if (to_evt(f, m, verb, out)) {
				/*
				 * COUNTED WHERE IT IS EMITTED, not where the
				 * fanotify record was read.
				 *
				 * They are different numbers because one
				 * record carries several verbs - measured,
				 * 4000 records came out as 8000 events - and
				 * `produced` has one job: to be the number a
				 * consumer can check its own `seq` against. A
				 * count of records would have made every
				 * consumer conclude it had lost half the
				 * stream.
				 */
				f->produced++;
				return 1;
			}
		}

		f->have = 0;
		f->at = NULL;

		{
			struct pollfd pf;
			int rc;

			/*
			 * ONE poll FOR THE WHOLE WAIT, AND NOT A SLICED ONE.
			 *
			 * This was written as a loop of 50ms polls, copied
			 * from the channel - where slicing is right, because
			 * there the publisher signals only on an
			 * empty-to-nonempty edge and a missed edge must cost
			 * latency rather than a hang.
			 *
			 * A fanotify descriptor has no such problem. It is a
			 * real pollable fd: data arriving wakes the poll, and
			 * there is no edge to miss. So the slicing bought
			 * nothing and cost a wakeup every 50ms forever.
			 *
			 * MEASURED, idle, with nothing happening at all:
			 *
			 *     sliced   16.8 voluntary context switches/second
			 *     single    0.0 (one per call, and the caller
			 *                    chooses how long a call waits)
			 *
			 * CPU time was unmeasurable in both - the work per
			 * wakeup is nothing. WAKEUPS ARE THE COST, not cycles:
			 * a process that wakes seventeen times a second keeps
			 * the CPU out of its deep sleep states, which is what
			 * a laptop battery actually pays for, and it is
			 * exactly what powertop exists to name.
			 *
			 * So the wait is now the CALLER'S power knob and means
			 * what it says: a sensor that passes 5000 wakes at
			 * most once every five seconds while the machine is
			 * quiet, and instantly when it is not.
			 */
			pf.fd = f->fd;
			pf.events = POLLIN;
			pf.revents = 0;
			rc = poll(&pf, 1, (int)wait_ms);
			if (rc > 0) {
				ssize_t n = read(f->fd, f->buf, sizeof f->buf);

				if (n > 0) {
					f->have = n;
					f->at = f->buf;
					continue;
				}
			}
			return 0;
		}
	}
}

static void fan_health(void *self, struct kof_evt_health *out)
{
	struct kofa_fan *f = (struct kofa_fan *)self;

	if (!out)
		return;
	memset(out, 0, sizeof *out);
	if (!f)
		return;
	out->produced = f->produced;
	out->dropped  = f->dropped;
}

static void fan_print_extra(void *self, FILE *out)
{
	struct kofa_fan *f = (struct kofa_fan *)self;
	uint32_t i;

	if (!f || !out)
		return;
	fprintf(out, "  fanotify: %s mode, %u path(s) watched\n",
		kofa_fan_mode_name(f->mode), f->n_watch);
	fprintf(out, "    %llu kernel record(s) -> %llu event(s)\n",
		(unsigned long long)f->records,
		(unsigned long long)f->produced);
	for (i = 0; i < f->n_watch; i++)
		fprintf(out, "    %s\n", f->watch[i]);
	if (f->mode == KOFA_FAN_DEGRADED)
		fprintf(out,
			"  DEGRADED: no privilege, so dirent events only and\n"
			"            no actor on anything this process did not\n"
			"            do itself - every record says so in miss.\n");
}

static void fan_close_api(void *self)
{
	kofa_fan_close((struct kofa_fan *)self);
}

/* --------------------------------------------------------------- opening */

static int add_watch(struct kofa_fan *f, const char *dir, uint64_t mask)
{
	int fd;

	if (f->n_watch >= AFAN_MAX_WATCH)
		return 0;
	if (fanotify_mark(f->fd, FAN_MARK_ADD, mask, AT_FDCWD, dir) != 0)
		return 0;

	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	snprintf(f->watch[f->n_watch], sizeof f->watch[0], "%s", dir);
	f->watch_fd[f->n_watch] = fd;
	f->n_watch++;
	return 1;
}

struct kofa_fan *kofa_fan_open(const struct kofa_fan_option *opt, int *err)
{
	struct kofa_fan *f;
	struct kofa_fan_option o;
	uint64_t full_mask = FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF |
			     FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MOVE_SELF |
			     FAN_CLOSE_WRITE | FAN_OPEN_EXEC | FAN_ONDIR;
	uint64_t dirent_mask = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM |
			       FAN_MOVED_TO | FAN_ONDIR;
	uint32_t i;

	memset(&o, 0, sizeof o);
	if (opt)
		o = *opt;

	f = calloc(1, sizeof *f);
	if (!f) {
		if (err) *err = KOFA_ERR_NOMEM;
		return NULL;
	}
	f->fd = -1;
	f->trace_self = o.trace_self;
	f->self_pid = (uint32_t)getpid();

	/*
	 * DFID_NAME AND FID TOGETHER. The first is what gives an entry's name
	 * without an fd; the second is what makes the per-file events
	 * resolvable when a filesystem mark delivers them. Measured: both are
	 * accepted unprivileged, while FAN_REPORT_PIDFD and a bare
	 * FAN_CLASS_NOTIF are not.
	 */
	f->fd = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME |
			      FAN_REPORT_FID, O_RDONLY | O_CLOEXEC);
	if (f->fd < 0) {
		int e = (errno == ENOSYS) ? KOFA_ERR_UNSUPPORTED
					  : KOFA_ERR_DENIED;
		free(f);
		if (err) *err = e;
		return NULL;
	}

	/*
	 * THE WHOLE FILESYSTEM FIRST, because a list of directories is a list
	 * a dropper can step outside of. It needs CAP_SYS_ADMIN; when it is
	 * refused the session is DEGRADED and says so rather than pretending
	 * the directories it can watch are the same answer.
	 */
	if (!o.dirs &&
	    fanotify_mark(f->fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
			  full_mask, AT_FDCWD, "/") == 0) {
		f->mode = KOFA_FAN_FULL;
		snprintf(f->watch[0], sizeof f->watch[0], "/");
		f->watch_fd[0] = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		f->n_watch = 1;
	} else {
		f->mode = KOFA_FAN_DEGRADED;
		if (o.dirs) {
			for (i = 0; o.dirs[i]; i++)
				(void)add_watch(f, o.dirs[i], dirent_mask);
		}
		if (!f->n_watch) {
			const char *t = getenv("TMPDIR");

			(void)add_watch(f, t && *t ? t : "/tmp", dirent_mask);
		}
		if (!f->n_watch) {
			close(f->fd);
			free(f);
			if (err) *err = KOFA_ERR_DENIED;
			return NULL;
		}
	}

	f->api.self        = f;
	f->api.next        = fan_next;
	f->api.health      = fan_health;
	f->api.name_of     = NULL;   /* fanotify names files, not processes */
	f->api.print_extra = fan_print_extra;
	f->api.close       = fan_close_api;

	if (err) *err = KOFA_OK;
	return f;
}

int kofa_fan_mode(const struct kofa_fan *f) { return f ? f->mode : -1; }

uint32_t kofa_fan_watch_count(const struct kofa_fan *f)
{
	return f ? f->n_watch : 0u;
}

const char *kofa_fan_watch_at(const struct kofa_fan *f, uint32_t i)
{
	return (f && i < f->n_watch) ? f->watch[i] : NULL;
}

const struct kof_mon_api *kofa_fan_api(struct kofa_fan *f)
{
	return f ? &f->api : NULL;
}

void kofa_fan_close(struct kofa_fan *f)
{
	uint32_t i;

	if (!f)
		return;
	for (i = 0; i < f->n_watch; i++)
		if (f->watch_fd[i] >= 0)
			close(f->watch_fd[i]);
	if (f->fd >= 0)
		close(f->fd);
	free(f);
}
