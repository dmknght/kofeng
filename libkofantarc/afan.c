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
	/* Whether watch[i] names a FILE rather than a directory - the two are
	 * different marks and the path is assembled differently for each. */
	uint8_t  watch_is_file[AFAN_MAX_WATCH];
	/* Named but not watched: too long for watch[], or the mark was
	 * refused. Reported, because a watch nobody took is a question the
	 * operator asked and did not get. */
	uint32_t n_refused;
	/*
	 * AND THE KERNEL'S OWN NAME FOR EACH ONE, taken when it was marked.
	 *
	 * This is what lets the degraded mode say WHICH directory an event
	 * came from. The event carries a handle for its parent directory and
	 * nothing else usable - resolving that handle to a path needs
	 * CAP_DAC_READ_SEARCH, which is the whole reason the mode is degraded.
	 * But it does not have to be RESOLVED to be RECOGNISED: name_to_handle_at
	 * needs no privilege, so a handle taken here can be compared byte for
	 * byte against the one the event reports.
	 *
	 * Measured on this kernel, unprivileged: two temporary directories
	 * marked, a file created in each, and the handle of each event matched
	 * the handle of the directory it was actually made in.
	 *
	 * `ok` rather than assuming it worked: a filesystem that does not
	 * support handles - and some do not - returns EOPNOTSUPP here, and a
	 * zero-length handle would compare equal to every other failed one.
	 */
	struct {
		struct file_handle h;
		unsigned char      space[MAX_HANDLE_SZ];
	} watch_h[AFAN_MAX_WATCH];
	uint8_t  watch_h_ok[AFAN_MAX_WATCH];
	uint32_t n_watch;

	/*
	 * The current read buffer and where the walk is inside it, so one
	 * read can serve many next() calls without re-entering the kernel.
	 *
	 * ALIGNED, because the kernel writes structs into it and the walk
	 * reads them in place. It was a plain char array, which C aligns for
	 * characters and nothing more: placed after the watch table it landed
	 * on a four-byte boundary, and every record read out of it was a
	 * misaligned access to a type that requires eight. Undefined behaviour
	 * that x86 happens to tolerate and several architectures do not - found
	 * by UBSAN the moment this test could be built at all:
	 *
	 *   afan.c:292: member access within misaligned address ... for type
	 *   'const struct fanotify_event_metadata', which requires 8 byte
	 *   alignment
	 *
	 * The union names the type that sets the requirement rather than
	 * hard-coding a number, so it stays right if the kernel's record grows
	 * a wider member.
	 */
	union {
		char buf[AFAN_BUF];
		struct fanotify_event_metadata align;
	} rb;
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
		{ FAN_DELETE | FAN_DELETE_SELF,   KOF_EVT_FILE_DELETE },
		/*
		 * LAST, because the order of this table is the order a thing
		 * can only have happened in - see the note above - and
		 * metadata is set on a file that already exists.
		 */
		{ FAN_ATTRIB,                     KOF_EVT_FILE_ATTRIB }
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
			      int mount_fd, const struct file_handle *dfh)
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
	 * THE HANDLE COULD NOT BE RESOLVED, SO IT IS RECOGNISED INSTEAD.
	 *
	 * The directory is one this session marked, and the event says which
	 * by carrying its handle - see kofa_fan.watch_h. Comparing that
	 * against the handles taken at mark time costs no privilege and gives
	 * the right parent.
	 *
	 * It used to name watch[0] whatever the event said, which with more
	 * than one watch was not a reduced answer but a WRONG one: half the
	 * records carried a path the file was never at, and kof_classify then
	 * classified a directory nothing had happened in. A missing path is a
	 * gap somebody can see; an invented one is a lie the pipeline cannot
	 * tell from a fact.
	 */
	if (name && *name) {
		uint32_t i, hit = f->n_watch;

		if (dfh && dfh->handle_bytes)
			for (i = 0; i < f->n_watch; i++)
				if (f->watch_h_ok[i] &&
				    f->watch_h[i].h.handle_bytes ==
					    dfh->handle_bytes &&
				    !memcmp(f->watch_h[i].h.f_handle,
					    dfh->f_handle,
					    dfh->handle_bytes)) {
					hit = i;
					break;
				}
		/*
		 * NOTHING MATCHED. One watch means there is only one answer it
		 * could be; several means there is no answer, and the name
		 * alone is reported rather than a path under a guess.
		 */
		if (hit >= f->n_watch && f->n_watch == 1u)
			hit = 0;
		if (hit < f->n_watch && f->watch_is_file[hit])
			/*
			 * A FILE WATCH IS ALREADY THE WHOLE PATH.
			 *
			 * The name in the record is the file's own - the info
			 * record carries the PARENT's handle and the entry's
			 * name - so joining it to a watch that is itself the
			 * file produced "/some/file.txt/file.txt". Measured the
			 * first time --watch was pointed at a file.
			 */
			snprintf(f->path, sizeof f->path, "%s",
				 f->watch[hit]);
		else if (hit < f->n_watch)
			snprintf(f->path, sizeof f->path, "%s/%s",
				 f->watch[hit], name);
		else
			snprintf(f->path, sizeof f->path, "%s", name);
	}

	(void)m;
	return f->path;
}

/*
 * Turn one fanotify event into the neutral record.
 *
 * Returns 0 for an event this build does not file - a mask with no verb, or a
 * queue overflow, which is counted rather than reported as an event.
 */
/*
 * `raw` AND `m`, WHICH ARE THE SAME BYTES READ TWO WAYS.
 *
 * struct fanotify_event_metadata carries an __aligned_u64 and therefore wants
 * 8 byte alignment, and the records in the read buffer do not all start on one:
 * measured on this host, a FAN_REPORT_FID event comes back with event_len 76,
 * so the record after it begins four bytes off. Casting the cursor to the
 * struct was undefined there, which UBSan says out loud and a strict-alignment
 * target would say with a fault.
 *
 * So the caller copies the fixed header into an aligned local and hands it
 * over as `m`, while `raw` stays the address the record really has - the info
 * records that follow it need only four byte alignment and are read in place.
 */
static int to_evt(struct kofa_fan *f, const char *raw,
		  const struct fanotify_event_metadata *m,
		  uint16_t verb, struct kof_evt *out)
{
	const char *name = NULL;
	struct file_handle *fh = NULL;
	const struct fanotify_event_info_header *h;
	const char *end = raw + m->event_len;

	if (!verb)
		return 0;

	/*
	 * EVERY STEP INSIDE THE RECORD, and the record's own end is the only
	 * number trusted here.
	 *
	 * This walk used to check that the info HEADER fitted and that h->len
	 * was at least a header - and then follow h->len wherever it pointed.
	 * Two things came out of the record unchecked after that:
	 *
	 *   fh   goes to open_by_handle_at, which copies handle_bytes from
	 *        this address - so a handle_bytes past the record hands the
	 *        kernel a length into memory that is not the event;
	 *   name goes to snprintf("%s"), which reads until it finds a zero -
	 *        so a name pointer past the record reads until one turns up.
	 *
	 * The bytes come from the kernel and a kernel sends whole records, so
	 * this is not a hole somebody walks through. It is the same framing
	 * discipline the OUTER walk already keeps with FAN_EVENT_OK, applied
	 * to the nested one, and it costs three comparisons per info record.
	 */
	h = (const void *)(raw + sizeof *m);
	while ((const char *)h + sizeof *h <= end && h->len >= sizeof *h &&
	       (const char *)h + h->len <= end) {
		const char *h_end = (const char *)h + h->len;

		if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME ||
		    h->info_type == FAN_EVENT_INFO_TYPE_DFID ||
		    h->info_type == FAN_EVENT_INFO_TYPE_FID) {
			const struct fanotify_event_info_fid *fi =
				(const void *)h;
			const char *hp = (const char *)fi->handle;
			struct file_handle *cand = (struct file_handle *)
						   (uintptr_t)(const void *)hp;

			/* The handle's own header, then the bytes it claims. */
			if (hp + sizeof *cand > h_end)
				break;
			if ((uint64_t)cand->handle_bytes >
			    (uint64_t)(h_end - (hp + sizeof *cand)))
				break;
			fh = cand;
			if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
				const char *nm = (const char *)fh->f_handle +
						 fh->handle_bytes;

				/* And a name snprintf can stop reading. */
				if (nm < h_end &&
				    memchr(nm, '\0', (size_t)(h_end - nm)))
					name = nm;
			}
		}
		h = (const void *)((const char *)h + h->len);
	}

	memset(out, 0, sizeof *out);
	/*
	 * IN THE UNIT THE FIELD IS DEFINED IN, which is not seconds.
	 *
	 * This was time(NULL) - whole seconds - against a field whose unit is
	 * KOF_TICKS_PER_SEC, ten million ticks to the second. Every elapsed
	 * time computed from a Linux record was therefore out by that factor,
	 * and a live line printed 0.000 for everything because every stamp
	 * taken inside one second was the same number. kof_evt_now is the one
	 * clock all of this is meant to take - see the note beside it.
	 */
	out->stamp = kof_evt_now();
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
		/*
		 * `fh` is passed twice on purpose, and they are two different
		 * questions. As the fourth argument it is a handle to RESOLVE,
		 * which only a privileged session can do; as the fifth it is a
		 * handle to RECOGNISE against the ones taken at mark time,
		 * which anybody can - see kofa_fan.watch_h.
		 */
		const char *p = event_path(f, m, name,
					   (f->mode == KOFA_FAN_FULL) ? fh
								      : NULL,
					   f->n_watch ? f->watch_fd[0] : -1,
					   fh);

		out->off_object = kof_evt_text_put(out, p);
		out->off_image  = KOF_TEXT_NONE;
		out->off_cmdline = KOF_TEXT_NONE;
		out->loc = kof_classify(p, &out->attack);
		/*
		 * WHAT THE METADATA EVENT DOES NOT SAY IS WHICH FIELD MOVED.
		 *
		 * FAN_ATTRIB reports that something about the inode changed -
		 * mode, owner, link count, an extended attribute - and never
		 * which. The one that matters for the chain this verb exists
		 * for is the execute bit, so the mode is read back and written
		 * into the record where a rule can see it.
		 *
		 * IT IS A RACE AND IT SAYS SO. By the time the event is read
		 * the file may be gone, and then the record carries the path
		 * and no mode rather than a mode somebody made up.
		 */
		if (verb == KOF_EVT_FILE_ATTRIB) {
			struct stat st;
			char mode[32];

			if (p && *p && stat(p, &st) == 0) {
				snprintf(mode, sizeof mode, "mode=%04o%s",
					 (unsigned)(st.st_mode & 07777),
					 (st.st_mode & 0111) ? " +x" : "");
				out->off_image = kof_evt_text_put(out, mode);
			} else {
				out->miss |= KOF_F_OBJECT;
			}
		}
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
			/*
			 * COPIED, NOT POINTED AT - see the note on to_evt.
			 * FAN_EVENT_OK dereferences the header too, so the
			 * copy has to come first, and it needs its own length
			 * check because that is what FAN_EVENT_OK would have
			 * made.
			 */
			struct fanotify_event_metadata md;
			const struct fanotify_event_metadata *m = &md;
			uint16_t verb;

			if (f->have < (ssize_t)sizeof md)
				break;
			memcpy(&md, f->at, sizeof md);
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
			if (to_evt(f, f->at, m, verb, out)) {
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
				ssize_t n = read(f->fd, f->rb.buf, sizeof f->rb.buf);

				if (n > 0) {
					f->have = n;
					f->at = f->rb.buf;
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
	/* Said out loud. A path the caller named and this did not take is a
	 * watch they think they have - see watch_fits. */
	if (f->n_refused)
		fprintf(out,
			"    %u path(s) NAMED BUT NOT WATCHED - too long for\n"
			"      this build's 256 byte limit, or the mark was\n"
			"      refused by the kernel\n", f->n_refused);
	if (f->mode == KOFA_FAN_DEGRADED)
		fprintf(out,
			"  DEGRADED: no privilege, so dirent events only and\n"
			"            no actor on anything this process did not\n"
			"            do itself - every record says so in miss.\n");
}

/* The session's own descriptor - see kof_mon_api.pollfd. */
static int fan_pollfd(void *self)
{
	struct kofa_fan *f = (struct kofa_fan *)self;

	return f ? f->fd : -1;
}

static void fan_close_api(void *self)
{
	kofa_fan_close((struct kofa_fan *)self);
}

/* --------------------------------------------------------------- opening */

/*
 * A PATH THAT DOES NOT FIT IS REFUSED, NOT STORED SHORT.
 *
 * watch[] is 256 bytes a row and PATH_MAX is 4096, so an ordinary deep path
 * does not fit - and snprintf would truncate it without a word. What is stored
 * here is what gets REPORTED: for a directory watch the record is assembled as
 * "<watch>/<name>", and for a file watch the watch IS the reported object. A
 * truncated one therefore names a path the event never happened at, which is
 * the failure the note in event_path is about - a missing path is a gap
 * somebody can see, an invented one is a lie.
 */
static int watch_fits(const char *p)
{
	size_t n = 0;

	while (p[n])
		n++;
	return n > 0 && n < 256u;   /* sizeof kofa_fan.watch[0] */
}

static int add_watch(struct kofa_fan *f, const char *dir, uint64_t mask)
{
	int fd;

	if (f->n_watch >= AFAN_MAX_WATCH || !watch_fits(dir))
		return 0;
	if (fanotify_mark(f->fd, FAN_MARK_ADD, mask, AT_FDCWD, dir) != 0)
		return 0;

	fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	snprintf(f->watch[f->n_watch], sizeof f->watch[0], "%s", dir);
	f->watch_fd[f->n_watch] = fd;
	{
		int mnt = 0;

		f->watch_h[f->n_watch].h.handle_bytes = MAX_HANDLE_SZ;
		f->watch_h_ok[f->n_watch] =
			name_to_handle_at(AT_FDCWD, dir,
					  &f->watch_h[f->n_watch].h,
					  &mnt, 0) == 0;
	}
	f->n_watch++;
	return 1;
}

/*
 * A MARK ON ONE FILE, which is a different watch from a mark on its directory.
 *
 * add_watch above opens the path O_DIRECTORY, so it cannot take a file at all;
 * and the mask it is given for a directory is the dirent set, which never
 * carries a write. This takes the inode and asks for the writes - measured
 * unprivileged on this kernel: the mark is accepted and another process's
 * write arrives with FAN_MODIFY | FAN_CLOSE_WRITE.
 *
 * No descriptor is kept: watch_fd is the mount fd open_by_handle_at needs, and
 * that is a FULL session's path. Here the handle taken below is what lets a
 * record be recognised as this watch.
 */
static int add_watch_file(struct kofa_fan *f, const char *path)
{
	if (f->n_watch >= AFAN_MAX_WATCH || !watch_fits(path))
		return 0;
	if (fanotify_mark(f->fd, FAN_MARK_ADD,
			  FAN_MODIFY | FAN_CLOSE_WRITE | FAN_ATTRIB,
			  AT_FDCWD, path) != 0)
		return 0;

	snprintf(f->watch[f->n_watch], sizeof f->watch[0], "%s", path);
	f->watch_fd[f->n_watch] = -1;
	f->watch_is_file[f->n_watch] = 1;
	{
		int mnt = 0;

		f->watch_h[f->n_watch].h.handle_bytes = MAX_HANDLE_SZ;
		f->watch_h_ok[f->n_watch] =
			name_to_handle_at(AT_FDCWD, path,
					  &f->watch_h[f->n_watch].h,
					  &mnt, 0) == 0;
	}
	f->n_watch++;
	return 1;
}

struct kofa_fan *kofa_fan_open(const struct kofa_fan_option *opt, int *err)
{
	struct kofa_fan *f;
	struct kofa_fan_option o;
	/*
	 * AND FAN_ATTRIB, which closes the middle of the dropper chain: write
	 * the payload, make it executable, run it. The first and the third
	 * were reported and the second was not - see KOF_EVT_FILE_ATTRIB.
	 *
	 * ITS VOLUME IS NOT MEASURED HERE. FAN_ATTRIB needs a mount or
	 * filesystem mark to arrive at all, which needs CAP_SYS_ADMIN, so an
	 * unprivileged run - the only kind a CI or this sandbox can do -
	 * cannot see one. A link count changing raises it too, and how often
	 * that happens on a working machine is the number nobody has yet.
	 * Whoever runs this privileged should read the tally before trusting
	 * it in a rule.
	 */
	uint64_t full_mask = FAN_CREATE | FAN_DELETE | FAN_DELETE_SELF |
			     FAN_MOVED_FROM | FAN_MOVED_TO | FAN_MOVE_SELF |
			     FAN_CLOSE_WRITE | FAN_OPEN_EXEC | FAN_ATTRIB |
			     FAN_ONDIR;
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
	/* A caller that NAMED something wants that and not the whole machine -
	 * the filesystem mark would answer a question nobody asked and would
	 * need a privilege they may not have. */
	if (!o.dirs && !o.files &&
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
		if (o.files) {
			for (i = 0; o.files[i]; i++)
				if (!add_watch_file(f, o.files[i]))
					f->n_refused++;
		}
		if (!f->n_watch) {
			/*
			 * A LITERAL, NOT $TMPDIR. What a sensor watches is not
			 * a thing the environment gets to choose: a parent
			 * that set TMPDIR would be deciding where the machine
			 * is watched, and the degraded mode this falls back to
			 * is a test surface where "somewhere writable" is the
			 * whole requirement. A caller that wants elsewhere
			 * says so in kofa_fan_option.dirs.
			 */
			(void)add_watch(f, "/tmp", dirent_mask);
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
	f->api.pollfd      = fan_pollfd;
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
