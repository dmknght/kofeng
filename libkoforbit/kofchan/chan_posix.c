/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chan_posix.c - the POSIX backend of the channel. See kofchan.h for the
 * contract, which is the same one chan_win.c implements.
 *
 * THE RING LOGIC IS NOT REPEATED HERE BY ACCIDENT - it is repeated because it
 * is the part that must be identical, and the two files are short enough that
 * a reader can hold both. What differs is three things and only three:
 *
 *   the mapping   shm_open + ftruncate + mmap, twice, instead of
 *                 CreateFileMapping + MapViewOfFile.
 *   the wake      a named POSIX semaphore instead of an auto-reset event.
 *                 sem_post on the empty-to-nonempty edge, sem_timedwait with
 *                 the same capped slice, for the same reason: a missed edge
 *                 must cost latency and never a hang.
 *   the namespace /<name>-d and /<name>-c, created 0600. Windows uses Local\,
 *                 which scopes to the logon session; this scopes to the owning
 *                 user. Neither is a per-session ring - see kofchan.h.
 *
 * SHM OBJECTS OUTLIVE THE PROCESS THAT MADE THEM, which Windows sections do
 * not, and that difference is the whole of the extra work in here.
 *
 * A sensor that was killed leaves its objects behind, so a later start has to
 * tell "somebody else is publishing" from "the last run died". The first
 * version unlinked before creating, to clear the second case - and that made
 * the first case impossible to detect at all: the O_EXCL that was supposed to
 * refuse a second publisher could never fail, because the unlink had just
 * removed what it would have collided with. A test that started two publishers
 * found the second one SUCCEEDED, silently took the channel, and left the
 * first writing into an orphaned mapping that no subscriber could ever see.
 *
 * So: create with O_EXCL and, only when that collides, look at what is there.
 * A header with a live publisher's pid is a refusal; a zeroed magic or a pid
 * nobody owns any more is wreckage, and wreckage is unlinked and the create
 * retried once.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>

#include "kofchan.h"
#include "kofevtlog.h"

struct kof_chan_pub {
	int   fd_data, fd_cur;
	sem_t *wake;
	char  n_data[64], n_cur[64], n_wake[64];

	struct kof_chan_hdr    *hdr;
	unsigned char          *rec;
	struct kof_chan_cursor *cur;
	uint64_t data_bytes;
	uint32_t capacity, rec_size;
};

struct kof_chan_sub {
	int   fd_data, fd_cur;
	sem_t *wake;

	const struct kof_chan_hdr *hdr;
	const unsigned char       *rec;
	struct kof_chan_cursor    *cur;

	/* The same mapping as `hdr`, kept non-const for munmap - see the note
	 * on the Windows side's hdr_raw for why this is a field and not a cast
	 * at the teardown sites. */
	void    *hdr_raw;
	uint64_t data_bytes;
};

static uint32_t round_pow2(uint32_t v)
{
	uint32_t p = 1u;

	while (p < v && p < (1u << 30))
		p <<= 1;
	return p;
}

/*
 * The three object names. A POSIX shm name is one leading slash and no other,
 * so the base is taken as a stem and anything that would make a second path
 * component is refused rather than rewritten - a name that silently became a
 * different name is a channel two ends disagree about.
 */
static int chan_names(const char *base, char *d, char *c, char *w, size_t cap)
{
	const char *b = (base && *base) ? base : KOF_CHAN_NAME;
	size_t i;

	for (i = 0; b[i]; i++)
		if (b[i] == '/' || b[i] == '\\')
			return 0;
	if (i == 0 || i + 8u >= cap)
		return 0;

	snprintf(d, cap, "/%s-d", b);
	snprintf(c, cap, "/%s-c", b);
	snprintf(w, cap, "/%s-w", b);
	return 1;
}

/*
 * IS AN EXISTING CHANNEL WRECKAGE RATHER THAN A LIVE ONE.
 *
 * Zero magic means a publisher tore it down and is gone. A pid nobody owns
 * means one died without tearing anything down. Anything else is somebody
 * publishing right now and must be refused - see the note at the top.
 *
 * Deliberately conservative: anything this cannot read, it calls LIVE. A
 * mistake in that direction costs a refused start with a clear reason; the
 * other direction silently steals a running sensor's channel.
 */
static int stale_channel(const char *nd)
{
	struct kof_chan_hdr h;
	int fd = shm_open(nd, O_RDONLY, 0);
	void *m;
	int stale;

	if (fd < 0)
		return 0;

	m = mmap(NULL, sizeof h, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		close(fd);
		return 0;
	}
	memcpy(&h, m, sizeof h);
	munmap(m, sizeof h);
	close(fd);

	if (h.magic != KOF_CHAN_MAGIC)
		return 1;
	if (h.pid == 0u)
		return 1;

	/* ESRCH: no such process. EPERM means it exists and is somebody
	 * else's, which is still alive. */
	stale = (kill((pid_t)h.pid, 0) != 0 && errno == ESRCH);
	return stale;
}

static void *map_rw(int fd, uint64_t bytes)
{
	void *p = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);

	return (p == MAP_FAILED) ? NULL : p;
}

/* --------------------------------------------------------------- publisher */

/*
 * LET ONE GROUP SUBSCRIBE. 0 on success, -1 with errno set.
 *
 * WHY THIS IS A CALL AND NOT THE DEFAULT. The channel is created 0600, so a
 * sensor running as root publishes a channel only root can read - which is the
 * right default and the wrong outcome when the consumer is a CLI somebody runs
 * as themselves. Widening it is a DECISION with two costs, and an operator
 * naming a group is how they take both:
 *
 *   THE DATA SECTION BECOMES READABLE by that group, and it carries a path for
 *   every file event on the machine. That is a map of what everyone is doing.
 *
 *   THE CURSOR BECOMES WRITABLE by that group, because a subscriber has to
 *   record what it consumed. A member can therefore move the cursor and make
 *   the sensor believe records were taken that nobody read. It cannot forge a
 *   record - the data section stays read-only to it, which is the property
 *   kofchan.h is built around - so the worst it buys is silence, not a lie.
 *
 * Those are not the same risk and both are real, which is why this asks for a
 * group rather than taking 0666 and saying nothing.
 *
 * LINUX-SHAPED IN ONE PLACE: the semaphore has no descriptor to fchmod, so it
 * is reached through /dev/shm/sem.<name>, which is where glibc puts it. A
 * failure there is not fatal - the subscriber falls back to sleeping.
 */
/*
 * The two chowns and the two chmods, once the gid is settled.
 *
 * ERRNO IS SET EXPLICITLY ON EVERY FAILURE PATH, and that is not belt and
 * braces. Measured in a container: fchown on a shm descriptor returned -1
 * WITHOUT setting errno, and the caller then printed whatever errno happened
 * to hold - "Invalid argument", from a call that had succeeded. A diagnostic
 * that invents a cause is worse than one that says it does not know.
 */
static int grant_uid(struct kof_chan_pub *p, uid_t uid, gid_t gid)
{
	char        sem_path[320];
	const char *bare;

	/*
	 * THE DATA SECTION IS READ-ONLY TO THEM AND THE CURSOR IS NOT, which
	 * is the asymmetry the whole design rests on - see kofchan.h. A
	 * subscriber cannot write a record because it does not hold the access
	 * to, and that survives being handed ownership: the mode is what the
	 * PUBLISHER sets, and it sets r-- on the data.
	 *
	 * 0400 and 0600 rather than 0640 and 0660: with the object handed to
	 * the person by NAME there is nothing for a group bit to add, and a
	 * group bit on a distro that puts every account in `users` would hand
	 * the machine's file activity to all of them.
	 */
	errno = 0;
	if (fchown(p->fd_data, uid, gid) != 0 ||
	    fchmod(p->fd_data, 0400) != 0) {
		if (!errno) errno = EPERM;
		return -1;
	}
	errno = 0;
	if (fchown(p->fd_cur, uid, gid) != 0 ||
	    fchmod(p->fd_cur, 0600) != 0) {
		if (!errno) errno = EPERM;
		return -1;
	}

	bare = p->n_wake[0] == '/' ? p->n_wake + 1 : p->n_wake;
	snprintf(sem_path, sizeof sem_path, "/dev/shm/sem.%s", bare);
	(void)chown(sem_path, uid, gid);
	(void)chmod(sem_path, 0600);

	/*
	 * PROVE IT RATHER THAN ASSUME IT. Everything above can report success
	 * and leave the mode unchanged - a filesystem that ignores it, a
	 * sandbox that stubs it out. The whole point of the call is that a
	 * second account can open these, so the last thing it does is look.
	 */
	{
		struct stat sd, sc;

		if (fstat(p->fd_data, &sd) != 0 ||
		    fstat(p->fd_cur, &sc) != 0) {
			if (!errno) errno = EPERM;
			return -1;
		}
		if (sd.st_uid != uid || sc.st_uid != uid ||
		    !(sd.st_mode & S_IRUSR) || !(sc.st_mode & S_IWUSR)) {
			errno = EPERM;
			return -1;
		}
	}
	return 0;
}

/* The group form, for --channel-group: ownership stays with the publisher and
 * the group is what is widened, so a whole team can subscribe. */
static int grant_group(struct kof_chan_pub *p, gid_t gid)
{
	char        sem_path[320];
	const char *bare;
	struct stat sd, sc;

	errno = 0;
	if (fchown(p->fd_data, (uid_t)-1, gid) != 0 ||
	    fchmod(p->fd_data, 0640) != 0) {
		if (!errno) errno = EPERM;
		return -1;
	}
	errno = 0;
	if (fchown(p->fd_cur, (uid_t)-1, gid) != 0 ||
	    fchmod(p->fd_cur, 0660) != 0) {
		if (!errno) errno = EPERM;
		return -1;
	}
	bare = p->n_wake[0] == '/' ? p->n_wake + 1 : p->n_wake;
	snprintf(sem_path, sizeof sem_path, "/dev/shm/sem.%s", bare);
	(void)chown(sem_path, (uid_t)-1, gid);
	(void)chmod(sem_path, 0660);

	if (fstat(p->fd_data, &sd) != 0 || fstat(p->fd_cur, &sc) != 0) {
		if (!errno) errno = EPERM;
		return -1;
	}
	if (sd.st_gid != gid || sc.st_gid != gid ||
	    !(sd.st_mode & S_IRGRP) || !(sc.st_mode & S_IWGRP)) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * WHO IS THE PERSON BEHIND THIS PROCESS, or (uid_t)-1 when nothing says.
 *
 * /proc/self/loginuid IS THE ANSWER AND IT IS NOT A GUESS. The kernel's audit
 * subsystem records the uid that authenticated at login, PAM sets it once per
 * session, and it is INHERITED ACROSS setuid - so a process running as root
 * under sudo still reports the human who typed the password. It is kernel
 * state: a program cannot set it without CAP_AUDIT_CONTROL, and unlike
 * SUDO_UID it is not something the party being authorised can write.
 *
 * That is the whole reason this is the first source tried. The controlling
 * terminal is the fallback, and it is a weaker answer: a terminal can be owned
 * by root in a root shell, and a container hands out /dev/tty owned by nobody -
 * measured, in this tree's own sandbox, where it reads uid 65534.
 *
 * (uid_t)-1 when the audit uid is unset, which is what a kernel built without
 * CONFIG_AUDIT and what a process outside any login session both report.
 */
static uid_t human_behind(void)
{
	FILE *f = fopen("/proc/self/loginuid", "r");
	unsigned long v;

	if (f) {
		int got = fscanf(f, "%lu", &v);

		fclose(f);
		/* 4294967295 is "unset" - the audit uid has never been
		 * assigned, so it names nobody rather than naming root. */
		if (got == 1 && v != 0xffffffffUL && v != 0)
			return (uid_t)v;
	}
	{
		struct stat st;
		int fd = open("/dev/tty", O_RDONLY | O_CLOEXEC);

		if (fd >= 0) {
			int ok = fstat(fd, &st) == 0;

			close(fd);
			if (ok && st.st_uid != 0)
				return st.st_uid;
		}
	}
	return (uid_t)-1;
}

/*
 * GRANT TO THE PERSON BEHIND THIS PROCESS. 0 on success, -1 with errno;
 * ENOTTY when nothing identifies them and EPERM when it is root anyway, and
 * neither is a failure worth stopping for.
 *
 * WHY THIS EXISTS. `sudo kofwatchtower` from somebody's shell and then
 * `kofwatchman` as themselves is not an exotic deployment, it is THE
 * deployment, and it does not work: the channel belongs to root. Requiring a
 * flag for the only way anybody runs it is a flag that is always passed, which
 * is a default wearing a disguise.
 *
 * /dev/tty AND NOT FILE DESCRIPTOR 0, and the difference is the whole security
 * of it. Descriptor 0 is whatever the caller redirected it to - including a
 * file an attacker owns, which would name an attacker's group. The
 * CONTROLLING TERMINAL is kernel state, set at session leader time, and a
 * redirect cannot change it.
 *
 * AND NOT SUDO_UID EITHER, which is the obvious answer and is an environment
 * variable: readable and writable by whoever arranged the invocation, which is
 * exactly the party this decision must not be delegated to.
 */
int kof_chan_publish_grant_console(struct kof_chan_pub *p, char *who,
				   size_t who_cap)
{
	struct passwd  pw, *res = NULL;
	char           buf[4096];
	uid_t          uid;

	if (who && who_cap)
		who[0] = '\0';
	if (!p) {
		errno = EINVAL;
		return -1;
	}
	uid = human_behind();
	if (uid == (uid_t)-1) {
		errno = ENOTTY;
		return -1;
	}
	if (getpwuid_r(uid, &pw, buf, sizeof buf, &res) != 0 || !res) {
		errno = ENOENT;
		return -1;
	}
	if (who && who_cap)
		snprintf(who, who_cap, "%s", pw.pw_name);

	/*
	 * THE USER AND THEN THE GROUP, in that order and both.
	 *
	 * Group alone was not enough: it makes the objects readable by every
	 * member of that group, which on a distro giving each user a group of
	 * their own is exactly one person - and on a distro that puts everyone
	 * in `users` is everyone. Handing OWNERSHIP to the person named makes
	 * the answer the same on both, and it is what lets the mode below drop
	 * group and world entirely.
	 */
	return grant_uid(p, uid, pw.pw_gid);
}

int kof_chan_publish_grant(struct kof_chan_pub *p, const char *group)
{
	struct group  gr, *res = NULL;
	char          buf[4096];

	if (!p || !group || !*group) {
		errno = EINVAL;
		return -1;
	}
	if (getgrnam_r(group, &gr, buf, sizeof buf, &res) != 0 || !res) {
		errno = ENOENT;
		return -1;
	}
	return grant_group(p, gr.gr_gid);
}

struct kof_chan_pub *kof_chan_publish_open(const char *name, uint32_t capacity)
{
	struct kof_chan_pub *p;
	uint32_t cap = round_pow2(capacity ? capacity : 8192u);
	char nd[64], nc[64], nw[64];

	if (!chan_names(name, nd, nc, nw, sizeof nd))
		return NULL;

	p = calloc(1, sizeof *p);
	if (!p)
		return NULL;
	p->fd_data = p->fd_cur = -1;
	p->wake = SEM_FAILED;
	p->capacity = cap;
	p->rec_size = (uint32_t)sizeof(struct kof_evt);
	p->data_bytes = sizeof(struct kof_chan_hdr) +
			(uint64_t)cap * p->rec_size;
	snprintf(p->n_data, sizeof p->n_data, "%s", nd);
	snprintf(p->n_cur,  sizeof p->n_cur,  "%s", nc);
	snprintf(p->n_wake, sizeof p->n_wake, "%s", nw);

	/*
	 * O_EXCL, so two live publishers cannot share one ring: their records
	 * would interleave and the stream that came out would belong to
	 * neither. It is also what stops something squatting the name first
	 * and having the sensor write every event into a mapping it controls.
	 */
	p->fd_data = shm_open(nd, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (p->fd_data < 0 && errno == EEXIST && stale_channel(nd)) {
		shm_unlink(nd);
		shm_unlink(nc);
		sem_unlink(nw);
		p->fd_data = shm_open(nd, O_CREAT | O_EXCL | O_RDWR, 0600);
	}
	if (p->fd_data < 0)
		goto fail;
	p->fd_cur = shm_open(nc, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (p->fd_cur < 0)
		goto fail;

	if (ftruncate(p->fd_data, (off_t)p->data_bytes) != 0 ||
	    ftruncate(p->fd_cur, (off_t)sizeof(struct kof_chan_cursor)) != 0)
		goto fail;

	p->wake = sem_open(nw, O_CREAT | O_EXCL, 0600, 0);
	if (p->wake == SEM_FAILED)
		goto fail;

	p->hdr = map_rw(p->fd_data, p->data_bytes);
	p->cur = map_rw(p->fd_cur, sizeof(struct kof_chan_cursor));
	if (!p->hdr || !p->cur)
		goto fail;

	p->rec = (unsigned char *)p->hdr + sizeof *p->hdr;

	memset(p->hdr, 0, sizeof *p->hdr);
	p->hdr->rec_size  = p->rec_size;
	p->hdr->head_size = (uint32_t)KOF_EVT_HEAD;
	p->hdr->len_off   = (uint32_t)offsetof(struct kof_evt, text_len);
	p->hdr->rec_kind  = KOFEVT_REC_KOF;
	p->hdr->capacity  = cap;
	p->hdr->pid       = (uint32_t)getpid();
	p->hdr->version   = KOF_CHAN_VERSION;

	/* The magic LAST, with a release, so a subscriber that sees it sees
	 * every field above it - written first, it could attach to a header
	 * whose capacity was still zero and index a ring of no slots. */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic,
			      KOF_CHAN_MAGIC, memory_order_release);
	return p;

fail:
	if (p->hdr) munmap(p->hdr, (size_t)p->data_bytes);
	if (p->cur) munmap(p->cur, sizeof(struct kof_chan_cursor));
	if (p->wake != SEM_FAILED) { sem_close(p->wake); sem_unlink(nw); }
	if (p->fd_cur >= 0)  { close(p->fd_cur);  shm_unlink(nc); }
	if (p->fd_data >= 0) { close(p->fd_data); shm_unlink(nd); }
	free(p);
	return NULL;
}

int kof_chan_publish(struct kof_chan_pub *p, const struct kof_evt *e)
{
	uint32_t h, t, depth;

	if (!p || !e)
		return -1;

	h = p->hdr->head;

	/*
	 * THE TAIL IS NOT TRUSTED. It is written by the subscriber, which is
	 * the lower-privilege half and may be compromised or merely wrong, so
	 * it is clamped to a ring's worth and nothing else is assumed about
	 * it. A bogus tail costs that subscriber its own events and nothing
	 * else.
	 */
	t = atomic_load_explicit((_Atomic uint32_t *)&p->cur->tail,
				 memory_order_acquire);
	depth = h - t;
	if (depth > p->capacity)
		depth = p->capacity;

	if (depth >= p->capacity) {
		p->hdr->dropped++;
		return 1;
	}

	memcpy(p->rec + (uint64_t)(h & (p->capacity - 1u)) * p->rec_size,
	       e, p->rec_size);
	p->hdr->produced++;

	/* RELEASE: publishes the record above, so a subscriber that acquires
	 * this head sees a complete one rather than a half-written one. */
	atomic_store_explicit((_Atomic uint32_t *)&p->hdr->head, h + 1u,
			      memory_order_release);

	/* On the empty-to-nonempty edge only, so a burst costs one syscall
	 * rather than one per record. */
	if (depth == 0 && p->wake != SEM_FAILED)
		(void)sem_post(p->wake);
	return 0;
}

void kof_chan_publish_close(struct kof_chan_pub *p)
{
	if (!p)
		return;

	/* Zero the magic first: a subscriber attaching during teardown must
	 * not find a header that describes a mapping about to go away. */
	if (p->hdr)
		atomic_store_explicit((_Atomic uint32_t *)&p->hdr->magic, 0u,
				      memory_order_release);

	if (p->hdr) munmap(p->hdr, (size_t)p->data_bytes);
	if (p->cur) munmap(p->cur, sizeof(struct kof_chan_cursor));
	if (p->wake != SEM_FAILED) { sem_close(p->wake); sem_unlink(p->n_wake); }
	if (p->fd_cur >= 0)  { close(p->fd_cur);  shm_unlink(p->n_cur); }
	if (p->fd_data >= 0) { close(p->fd_data); shm_unlink(p->n_data); }
	free(p);
}

/* -------------------------------------------------------------- subscriber */

struct kof_chan_sub *kof_chan_sub_open(const char *name, const char **why,
				       int *reason)
{
	struct kof_chan_sub *s;
	char nd[64], nc[64], nw[64];
	struct stat st;

	if (why) *why = "";
	if (reason) *reason = KOF_CHAN_WHY_BROKEN;
	if (!chan_names(name, nd, nc, nw, sizeof nd)) {
		if (why) *why = "the channel name is not usable";
		return NULL;
	}

	s = calloc(1, sizeof *s);
	if (!s)
		return NULL;
	s->fd_data = s->fd_cur = -1;
	s->wake = SEM_FAILED;

	/*
	 * READ-ONLY ON THE DATA AND READ-WRITE ON THE CURSOR, which is the
	 * security of the whole design - see kofchan.h. Opened that way as
	 * well as mapped that way, so a subscriber cannot re-map the data
	 * section writable from the descriptor it was given.
	 */
	s->fd_data = shm_open(nd, O_RDONLY, 0);
	if (s->fd_data < 0) {
		/*
		 * EACCES IS NOT "NOTHING IS THERE", and telling them apart is
		 * the difference between starting a sensor and being told who
		 * may read the one already running. A root sensor's channel is
		 * created 0600 and owned by root, so an unprivileged
		 * subscriber gets refused by a channel that is working
		 * perfectly - and the old message sent them off to start a
		 * second one.
		 */
		if (errno == EACCES || errno == EPERM) {
			if (why)
				*why = "a sensor is publishing but this "
				       "account may not read its channel";
			if (reason) *reason = KOF_CHAN_WHY_DENIED;
		} else {
			if (why) *why = "no sensor is publishing";
			if (reason) *reason = KOF_CHAN_WHY_ABSENT;
		}
		goto fail;
	}
	s->fd_cur = shm_open(nc, O_RDWR, 0);
	if (s->fd_cur < 0) {
		if (errno == EACCES || errno == EPERM) {
			if (why)
				*why = "a sensor is publishing but this "
				       "account may not write its cursor";
			if (reason) *reason = KOF_CHAN_WHY_DENIED;
		} else {
			if (why) *why = "the channel has no cursor section";
		}
		goto fail;
	}
	if (fstat(s->fd_data, &st) != 0 ||
	    (uint64_t)st.st_size < sizeof(struct kof_chan_hdr)) {
		if (why) *why = "the channel is too small to hold a header";
		goto fail;
	}
	s->data_bytes = (uint64_t)st.st_size;

	s->hdr_raw = mmap(NULL, (size_t)s->data_bytes, PROT_READ, MAP_SHARED,
			  s->fd_data, 0);
	if (s->hdr_raw == MAP_FAILED) { s->hdr_raw = NULL; goto fail; }
	s->hdr = (const struct kof_chan_hdr *)s->hdr_raw;

	s->cur = map_rw(s->fd_cur, sizeof(struct kof_chan_cursor));
	if (!s->cur)
		goto fail;

	/* Absent is not fatal: the wait falls back to sleeping, which costs
	 * latency and never correctness. */
	s->wake = sem_open(nw, 0);

	if (atomic_load_explicit((_Atomic uint32_t *)s->hdr_raw,
				 memory_order_acquire) != KOF_CHAN_MAGIC) {
		if (why) *why = "no sensor is publishing";
		if (reason) *reason = KOF_CHAN_WHY_ABSENT;
		goto fail;
	}
	if (s->hdr->version != KOF_CHAN_VERSION) {
		if (why) *why = "the sensor publishes a different version";
		goto fail;
	}
	if (s->hdr->rec_size != (uint32_t)sizeof(struct kof_evt)) {
		if (why) *why = "the sensor publishes a different record size";
		goto fail;
	}
	if (s->hdr->rec_kind != KOFEVT_REC_KOF) {
		if (why) *why = "the sensor publishes a different record";
		goto fail;
	}
	if (s->hdr->capacity == 0u ||
	    (s->hdr->capacity & (s->hdr->capacity - 1u)) != 0u) {
		if (why) *why = "the channel capacity is not a power of two";
		goto fail;
	}

	s->rec = (const unsigned char *)s->hdr + sizeof *s->hdr;
	return s;

fail:
	if (s->hdr_raw) munmap(s->hdr_raw, (size_t)s->data_bytes);
	if (s->cur) munmap(s->cur, sizeof(struct kof_chan_cursor));
	if (s->wake != SEM_FAILED) sem_close(s->wake);
	if (s->fd_cur >= 0)  close(s->fd_cur);
	if (s->fd_data >= 0) close(s->fd_data);
	free(s);
	return NULL;
}

const struct kof_chan_hdr *kof_chan_sub_header(const struct kof_chan_sub *s)
{
	return s ? s->hdr : NULL;
}

int kof_chan_next(struct kof_chan_sub *s, struct kof_evt *out, uint32_t wait_ms)
{
	uint32_t left = wait_ms;

	if (!s || !out)
		return 0;

	for (;;) {
		uint32_t t = s->cur->tail;
		uint32_t h = atomic_load_explicit(
			(_Atomic uint32_t *)((unsigned char *)s->hdr_raw +
				offsetof(struct kof_chan_hdr, head)),
			memory_order_acquire);

		if (h != t) {
			/*
			 * A PUBLISHER THAT LAPPED US. If more than a ring's
			 * worth arrived since the last read, the oldest slots
			 * have been overwritten and reading from `tail` would
			 * hand back a record that is half old and half new.
			 * The loss already happened and is counted in the
			 * header; what must not happen is reporting a spliced
			 * record as an event.
			 */
			if (h - t > s->hdr->capacity)
				t = h - s->hdr->capacity;

			memcpy(out, s->rec +
				    (uint64_t)(t & (s->hdr->capacity - 1u)) *
				    s->hdr->rec_size,
			       sizeof *out);

			/* RELEASE, so the publisher cannot begin overwriting
			 * the slot until the copy above has happened. */
			atomic_store_explicit(
				(_Atomic uint32_t *)&s->cur->tail, t + 1u,
				memory_order_release);
			return 1;
		}

		if (left == 0)
			return 0;
		{
			uint32_t slice = left < 50u ? left : 50u;

			/*
			 * CAPPED, for the reason the Windows side caps it: the
			 * publisher signals only on the empty-to-nonempty edge
			 * and decides that from a tail it may have read a
			 * moment stale, so a missed wakeup must cost latency
			 * and not a hang.
			 */
			if (s->wake != SEM_FAILED) {
				struct timespec ts;

				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_nsec += (long)(slice % 1000u) * 1000000L;
				ts.tv_sec  += (time_t)(slice / 1000u) +
					      ts.tv_nsec / 1000000000L;
				ts.tv_nsec %= 1000000000L;
				(void)sem_timedwait(s->wake, &ts);
			} else {
				struct timespec ts;

				ts.tv_sec  = slice / 1000u;
				ts.tv_nsec = (long)(slice % 1000u) * 1000000L;
				(void)nanosleep(&ts, NULL);
			}
			left -= slice;
		}
	}
}

void kof_chan_sub_close(struct kof_chan_sub *s)
{
	if (!s)
		return;
	if (s->hdr_raw) munmap(s->hdr_raw, (size_t)s->data_bytes);
	if (s->cur) munmap(s->cur, sizeof(struct kof_chan_cursor));
	if (s->wake != SEM_FAILED) sem_close(s->wake);
	if (s->fd_cur >= 0)  close(s->fd_cur);
	if (s->fd_data >= 0) close(s->fd_data);
	free(s);
}
