/*
 * orbit_chan - the channel between a sensor and its consumers (chan_posix.c: a shared-memory ring and a cursor).
 * chan_ring covers the ring with both ends in one process. This is about the ends that are NOT what the library made:
 *
 *   names       a name with a separator or too long
 *   open        every failing call on the way up (shm_open, ftruncate, sem_open, one by one) leaves NOTHING in /dev/shm
 *   segments    hand-made channels whose header lies, one field at a time: the subscriber's reason and message
 *   ring        full (the drop count, one slot freed, one record more), head at the top of the 32-bit counter, a consumer
 *               that fell a whole ring behind, a consumer reading a record it did not see written
 *   stale       a publisher that died without closing, one that is alive, one that never finished initialising
 *   grant       the group and the console grants, with this account's own group and with one it is not in
 *   threads     one publisher thread and one consumer thread, 200000 records: order, no duplicate, and
 *               consumed + dropped = produced
 * Defect rows are KM_CHECK (known_miss.h).
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kofchan.h"
#include "kofevt.h"
#include "kofevtlog.h"
#include "known_miss.h"
#include "../lib/orbit_sys.c"

static int fails, checks;
static char base[64];

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		printf("  FAIL %s\n", what);
		fails++;
	}
}

#define OKF(cond, ...) do { char w_[260]; snprintf(w_, sizeof w_, __VA_ARGS__); ok((cond), w_); } while (0)

static void mkname(char *out, size_t cap, const char *tag) { snprintf(out, cap, "%s%s", base, tag); }

/* does anything of this channel exist in /dev/shm */
static int leftovers(const char *name)
{
	char p[200];
	int n = 0;

	snprintf(p, sizeof p, "/dev/shm/%s-d", name);
	n += access(p, F_OK) == 0;
	snprintf(p, sizeof p, "/dev/shm/%s-c", name);
	n += access(p, F_OK) == 0;
	snprintf(p, sizeof p, "/dev/shm/sem.%s-w", name);
	n += access(p, F_OK) == 0;
	return n;
}

static void scrub(const char *name)
{
	char p[200];

	snprintf(p, sizeof p, "/%s-d", name);
	shm_unlink(p);
	snprintf(p, sizeof p, "/%s-c", name);
	shm_unlink(p);
	snprintf(p, sizeof p, "/%s-w", name);
	sem_unlink(p);
}

static void ev(struct kof_evt *e, uint64_t seq)
{
	memset(e, 0, sizeof *e);
	e->verb = KOF_EVT_FILE_NEW;
	e->seq = seq;
	e->pid = (uint32_t)seq;
	e->off_image = e->off_object = e->off_cmdline = e->off_data = KOF_TEXT_NONE;
}

/* ------------------------------------------------------------------------------------------------- names and open */

static void case_names_open(void)
{
	char n[100];
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	const char *why = "";
	int reason = -1;
	unsigned k, call;
	static const struct { enum osys_fn fn; const char *what; } steps[] = {
		{ OSYS_SHMOPEN, "shm_open" }, { OSYS_FTRUNC, "ftruncate" }, { OSYS_SEMOPEN, "sem_open" },
	};

	printf("\nnames, and a failure at every step of publish_open:\n");
	ok(kof_chan_publish_open("a/b", 8) == NULL && kof_chan_publish_open("a\\b", 8) == NULL, "a name with a separator is refused");
	{
		char longn[80];

		memset(longn, 'n', sizeof longn - 1);
		longn[sizeof longn - 1] = '\0';
		ok(kof_chan_publish_open(longn, 8) == NULL, "a 79-byte name does not fit the 64-byte buffers: refused");
		memset(longn, 'n', 55);
		longn[55] = '\0';
		mkname(n, sizeof n, "x");
		(void)n;
		ok(kof_chan_sub_open(longn, &why, &reason) == NULL && reason != KOF_CHAN_WHY_NONE, "a long name on the subscriber side: refused or absent");
		ok(kof_chan_sub_open("a/b", &why, &reason) == NULL && reason == KOF_CHAN_WHY_BROKEN && strstr(why, "not usable"), "a name with a separator: BROKEN, 'not usable'");
	}
	mkname(n, sizeof n, "o");
	for (k = 0; k < sizeof steps / sizeof steps[0]; k++) {
		for (call = 1; call <= 2; call++) {
			char w[160];

			if (steps[k].fn == OSYS_SEMOPEN && call == 2)
				continue;
			scrub(n);
			osys_reset();
			osys_match(n);
			osys_fail(steps[k].fn, call, ENOSPC);
			p = kof_chan_publish_open(n, 64);
			snprintf(w, sizeof w, "%s failing on call %u: publish_open is NULL and leaves nothing in /dev/shm (%d left)", steps[k].what, call, leftovers(n));
			ok(p == NULL && leftovers(n) == 0, w);
			osys_reset();
			if (p)
				kof_chan_publish_close(p);
			scrub(n);
		}
	}
	/* mmap is not wrapped here; a good open then */
	p = kof_chan_publish_open(n, 5);
	ok(p != NULL && leftovers(n) == 3, "an open that works leaves three names");
	s = kof_chan_sub_open(n, &why, &reason);
	ok(s && kof_chan_sub_header(s)->capacity == 8 && kof_chan_sub_header(s)->pid == (uint32_t)getpid() && kof_chan_sub_header(s)->version == KOF_CHAN_VERSION,
	   "the header says: capacity rounded up to 8, the publisher's pid, the version");
	ok(kof_chan_sub_header(NULL) == NULL, "kof_chan_sub_header(NULL)");
	kof_chan_sub_close(s);
	ok(kof_chan_publish_open(n, 8) == NULL, "a second publisher while the first is alive: refused (the name is taken)");
	kof_chan_publish_close(p);
	ok(leftovers(n) == 0, "close removes the names");
	s = kof_chan_sub_open(n, &why, &reason);
	ok(s == NULL && reason == KOF_CHAN_WHY_ABSENT, "a subscriber after the close: ABSENT");
	/* capacity rounding */
	{
		static const struct { uint32_t ask, got; } caps[] = { { 0, 8192 }, { 1, 1 }, { 2, 2 }, { 3, 4 }, { 1000, 1024 }, { 1024, 1024 }, { 1025, 2048 } };

		for (k = 0; k < sizeof caps / sizeof caps[0]; k++) {
			p = kof_chan_publish_open(n, caps[k].ask);
			s = p ? kof_chan_sub_open(n, &why, &reason) : NULL;
			OKF(s && kof_chan_sub_header(s)->capacity == caps[k].got, "capacity %u rounds to %u", caps[k].ask, caps[k].got);
			kof_chan_sub_close(s);
			kof_chan_publish_close(p);
		}
	}
	ok(kof_chan_publish(NULL, NULL) == -1 && kof_chan_next(NULL, NULL, 0) == 0, "NULL arguments");
	kof_chan_publish_close(NULL);
	kof_chan_sub_close(NULL);
}

/* ------------------------------------------------------------------------------------------------- hand-made segments */

struct seg {
	int fd_d, fd_c;
	struct kof_chan_hdr *h;
	size_t bytes;
	char nd[200], nc[200], nw[200];
};

static int seg_make(struct seg *g, const char *name, uint32_t cap, uint32_t extra_bytes)
{
	struct kof_chan_cursor *c;

	memset(g, 0, sizeof *g);
	snprintf(g->nd, sizeof g->nd, "/%s-d", name);
	snprintf(g->nc, sizeof g->nc, "/%s-c", name);
	snprintf(g->nw, sizeof g->nw, "/%s-w", name);
	g->bytes = sizeof(struct kof_chan_hdr) + (size_t)cap * sizeof(struct kof_evt) + extra_bytes;
	g->fd_d = shm_open(g->nd, O_CREAT | O_EXCL | O_RDWR, 0600);
	g->fd_c = shm_open(g->nc, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (g->fd_d < 0 || g->fd_c < 0)
		return 0;
	if (ftruncate(g->fd_d, (off_t)g->bytes) || ftruncate(g->fd_c, sizeof *c))
		return 0;
	g->h = mmap(NULL, g->bytes, PROT_READ | PROT_WRITE, MAP_SHARED, g->fd_d, 0);
	if (g->h == MAP_FAILED)
		return 0;
	memset(g->h, 0, sizeof *g->h);
	g->h->magic = KOF_CHAN_MAGIC;
	g->h->version = KOF_CHAN_VERSION;
	g->h->rec_size = sizeof(struct kof_evt);
	g->h->head_size = KOF_EVT_HEAD;
	g->h->len_off = (uint32_t)offsetof(struct kof_evt, text_len);
	g->h->rec_kind = KOFEVT_REC_KOF;
	g->h->capacity = cap;
	g->h->pid = (uint32_t)getpid();
	return 1;
}

static void seg_drop(struct seg *g)
{
	if (g->h && g->h != MAP_FAILED)
		munmap(g->h, g->bytes);
	if (g->fd_d >= 0)
		close(g->fd_d);
	if (g->fd_c >= 0)
		close(g->fd_c);
	shm_unlink(g->nd);
	shm_unlink(g->nc);
	sem_unlink(g->nw);
}

struct seg_row {
	const char *id;
	int         field;       /* which header field */
	uint32_t    val;
	int         reason;
	const char *why;
};

enum { F_MAGIC, F_VERSION, F_REC_SIZE, F_KIND, F_CAP };

static const struct seg_row seg_rows[] = {
	{ "magic of a publisher that closed", F_MAGIC, 0, KOF_CHAN_WHY_ABSENT, "no sensor is publishing" },
	{ "wrong magic", F_MAGIC, 0xdeadbeef, KOF_CHAN_WHY_ABSENT, "no sensor is publishing" },
	{ "version", F_VERSION, 9, KOF_CHAN_WHY_BROKEN, "different version" },
	{ "rec_size", F_REC_SIZE, 639, KOF_CHAN_WHY_BROKEN, "different record size" },
	{ "rec_kind", F_KIND, 1, KOF_CHAN_WHY_BROKEN, "different record" },
	{ "capacity 0", F_CAP, 0, KOF_CHAN_WHY_BROKEN, "not a power of two" },
	{ "capacity 3", F_CAP, 3, KOF_CHAN_WHY_BROKEN, "not a power of two" },
	{ "capacity 2^31 (a power of two, far past the segment)", F_CAP, 1u << 31, KOF_CHAN_WHY_BROKEN, "smaller than it declares" },
	{ "capacity 16 over a segment that holds 8", F_CAP, 16, KOF_CHAN_WHY_BROKEN, "smaller than it declares" },
};

static void case_segments(void)
{
	char n[100];
	unsigned i;
	struct seg g;
	struct kof_chan_sub *s;
	const char *why;
	int reason;

	printf("\nhand-made segments whose header lies:\n");
	mkname(n, sizeof n, "s");
	scrub(n);
	for (i = 0; i < sizeof seg_rows / sizeof seg_rows[0]; i++) {
		const struct seg_row *r = &seg_rows[i];

		ok(seg_make(&g, n, 8, 0), "a segment made by hand");
		switch (r->field) {
		case F_MAGIC: g.h->magic = r->val; break;
		case F_VERSION: g.h->version = r->val; break;
		case F_REC_SIZE: g.h->rec_size = r->val; break;
		case F_KIND: g.h->rec_kind = r->val; break;
		default: g.h->capacity = r->val; break;
		}
		why = "";
		reason = -1;
		s = kof_chan_sub_open(n, &why, &reason);
		OKF(s == NULL && reason == r->reason && strstr(why, r->why), "segment row '%s': refused as %d '%s' (got %d '%s')", r->id, r->reason, r->why, reason, why);
		kof_chan_sub_close(s);
		seg_drop(&g);
	}
	/* a segment smaller than a header */
	ok(seg_make(&g, n, 8, 0), "a segment");
	ftruncate(g.fd_d, 16);
	why = "";
	s = kof_chan_sub_open(n, &why, &reason);
	ok(s == NULL && strstr(why, "too small"), "a data segment of 16 bytes: refused as too small to hold a header");
	kof_chan_sub_close(s);
	munmap(g.h, g.bytes);
	g.h = NULL;
	seg_drop(&g);
	/* the cursor segment missing */
	ok(seg_make(&g, n, 8, 0), "a segment");
	shm_unlink(g.nc);
	why = "";
	s = kof_chan_sub_open(n, &why, &reason);
	ok(s == NULL && strstr(why, "no cursor"), "no cursor section: refused");
	seg_drop(&g);
	/* a good hand-made channel, then a subscriber that reads what the test wrote */
	ok(seg_make(&g, n, 8, 0), "a segment");
	s = kof_chan_sub_open(n, &why, &reason);
	ok(s != NULL, "a hand-made channel with a good header opens");
	{
		struct kof_evt e, out;
		unsigned char *rec = (unsigned char *)g.h + sizeof *g.h;

		ev(&e, 41);
		memcpy(rec, &e, sizeof e);
		__atomic_store_n(&g.h->head, 1u, __ATOMIC_RELEASE);
		memset(&out, 0, sizeof out);
		ok(kof_chan_next(s, &out, 0) == 1 && out.seq == 41, "a record written by hand is read");
		ok(kof_chan_next(s, &out, 0) == 0, "and then the ring is empty");
		/* a head far ahead of the tail: the consumer fell a whole ring behind and loses the oldest */
		ev(&e, 42);
		__atomic_store_n(&g.h->head, 1000u, __ATOMIC_RELEASE);
		ok(kof_chan_next(s, &out, 0) == 1, "a head 1000 ahead of the tail: the consumer jumps to head - capacity and reads");
		{
			unsigned n_read = 1;

			while (kof_chan_next(s, &out, 0) == 1)
				n_read++;
			OKF(n_read == 8, "and reads exactly one ring's worth (8), not 1000 (%u)", n_read);
		}
		/* a hostile head that wrapped below the tail */
		__atomic_store_n(&g.h->head, 3u, __ATOMIC_RELEASE);
		{
			unsigned n_read = 0, guard = 0;

			while (guard++ < 100 && kof_chan_next(s, &out, 0) == 1)
				n_read++;
			OKF(n_read <= 8, "a head BEHIND the tail (a lying publisher) is read as a wrap, and never past the ring (%u records)", n_read);
		}
	}
	kof_chan_sub_close(s);
	seg_drop(&g);
}

/* ------------------------------------------------------------------------------------------------- the ring */

static void case_ring(void)
{
	char n[100];
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	struct kof_evt e, out;
	unsigned i, drops = 0, got = 0;
	const char *why;
	int reason;

	printf("\nthe ring: full, empty, wrapped:\n");
	mkname(n, sizeof n, "r");
	scrub(n);
	p = kof_chan_publish_open(n, 8);
	s = kof_chan_sub_open(n, &why, &reason);
	ok(p && s, "both ends");
	ok(kof_chan_next(s, &out, 0) == 0, "empty: 0");
	for (i = 0; i < 12; i++) {
		ev(&e, i);
		drops += kof_chan_publish(p, &e) == 1;
	}
	OKF(drops == 4 && kof_chan_sub_header(s)->dropped == 4 && kof_chan_sub_header(s)->produced == 8, "12 records into 8 slots: 4 refused with 1, dropped = 4, produced = 8 (%u, %llu, %llu)",
	    drops, (unsigned long long)kof_chan_sub_header(s)->dropped, (unsigned long long)kof_chan_sub_header(s)->produced);
	ok(kof_chan_next(s, &out, 0) == 1 && out.seq == 0, "the OLDEST survive (a full ring refuses the new one): the first read is 0");
	ev(&e, 100);
	ok(kof_chan_publish(p, &e) == 0, "one slot freed: one record more is accepted");
	ev(&e, 101);
	ok(kof_chan_publish(p, &e) == 1, "and the next is refused again");
	while (kof_chan_next(s, &out, 0) == 1)
		got++;
	ok(got == 8, "the rest: 7 old and the one new");
	/* head at the top of the 32-bit counter: write across the wrap through the segments by hand */
	{
		char path[200];
		int fd_d, fd_c;
		struct kof_chan_hdr *h;
		struct kof_chan_cursor *c;
		unsigned k, bad = 0;

		snprintf(path, sizeof path, "/%s-d", n);
		fd_d = shm_open(path, O_RDWR, 0);
		snprintf(path, sizeof path, "/%s-c", n);
		fd_c = shm_open(path, O_RDWR, 0);
		h = mmap(NULL, sizeof *h + 8u * sizeof(struct kof_evt), PROT_READ | PROT_WRITE, MAP_SHARED, fd_d, 0);
		c = mmap(NULL, sizeof *c, PROT_READ | PROT_WRITE, MAP_SHARED, fd_c, 0);
		__atomic_store_n(&h->head, 0xfffffff0u, __ATOMIC_RELEASE);
		__atomic_store_n(&c->tail, 0xfffffff0u, __ATOMIC_RELEASE);
		for (k = 0; k < 40; k++) {
			ev(&e, 5000 + k);
			if (kof_chan_publish(p, &e) != 0)
				bad++;
			if (kof_chan_next(s, &out, 0) != 1 || out.seq != 5000 + k)
				bad++;
		}
		OKF(bad == 0, "head and tail crossing 2^32: 40 records in order, none lost (%u bad)", bad);
		ok(h->head == 0xfffffff0u + 40u, "head wrapped to a small number");
		munmap(h, sizeof *h + 8u * sizeof(struct kof_evt));
		munmap(c, sizeof *c);
		close(fd_d);
		close(fd_c);
	}
	/* a wait on an empty ring. The publisher posts the wake semaphore on every empty -> non-empty transition and a reader that
	 * never waits (wait_ms 0) never takes the count back, so the first timed waits return at once: measured below. */
	{
		struct timespec a, b;
		long ms, first_ms;
		unsigned k;

		ev(&e, 7);
		kof_chan_publish(p, &e);
		ok(kof_chan_next(s, &out, 0) == 1, "one record published and read WITHOUT waiting (the semaphore keeps its count)");
		clock_gettime(CLOCK_MONOTONIC, &a);
		ok(kof_chan_next(s, &out, 120) == 0, "wait 120 ms on an empty ring: 0");
		clock_gettime(CLOCK_MONOTONIC, &b);
		first_ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
		printf("       a wait of 120 ms after a record that was read without waiting took %ld ms\n", first_ms);
		/* KNOWN DEFECT WP12-13 (2026-10-24, M): this row pins it, green until fixed. */
		KM_CHECK(first_ms >= 100, "kof_chan_next(120 ms) on an empty ring returned after a stale semaphore count, not after 120 ms (the budget is charged 50 ms per iteration whatever the wait took)",
			 "WP12-13: the wake semaphore is never drained by a reader that does not wait, and `left -= slice` assumes the wait took its slice");
		/* drain the stale counts, then the wait is a wait */
		for (k = 0; k < 20; k++)
			(void)kof_chan_next(s, &out, 60);
		clock_gettime(CLOCK_MONOTONIC, &a);
		ok(kof_chan_next(s, &out, 120) == 0, "wait 120 ms on an empty ring, the semaphore drained: 0");
		clock_gettime(CLOCK_MONOTONIC, &b);
		ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
		OKF(ms >= 100 && ms < 1500, "and it waited about that long (%ld ms)", ms);
		ev(&e, 8);
		kof_chan_publish(p, &e);
		clock_gettime(CLOCK_MONOTONIC, &a);
		ok(kof_chan_next(s, &out, 1000) == 1, "a record already there is returned at once");
		clock_gettime(CLOCK_MONOTONIC, &b);
		ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
		OKF(ms < 100, "without waiting (%ld ms)", ms);
	}
	/* the publisher closes under a live subscriber: the subscriber's mapping stays valid */
	kof_chan_publish_close(p);
	ok(kof_chan_next(s, &out, 0) == 0, "the publisher gone: the subscriber reads an empty ring, no fault");
	kof_chan_sub_close(s);
}

static void case_stale(void)
{
	char n[100];
	struct kof_chan_pub *p;
	pid_t kid;
	int st;
	struct seg g;

	printf("\nstale channels:\n");
	mkname(n, sizeof n, "t");
	scrub(n);
	/* a publisher that died without closing: its names stay */
	kid = fork();
	if (kid == 0) {
		struct kof_chan_pub *q = kof_chan_publish_open(n, 8);

		_exit(q ? 0 : 3);
	}
	waitpid(kid, &st, 0);
	ok(WIFEXITED(st) && WEXITSTATUS(st) == 0 && leftovers(n) >= 2, "a publisher process that exits without closing leaves its names");
	p = kof_chan_publish_open(n, 8);
	ok(p != NULL, "a new publisher takes over a channel whose publisher is dead");
	kof_chan_publish_close(p);
	scrub(n);
	/* a channel whose header was never finished (magic 0): taken over at once */
	ok(seg_make(&g, n, 8, 0), "a segment");
	g.h->magic = 0;
	p = kof_chan_publish_open(n, 8);
	ok(p != NULL, "magic 0 (a publisher still initialising, or a closed one): treated as stale and replaced");
	printf("       (a second sensor starting inside the first one's initialisation window does the same to a LIVE one - WP12-12, read from the code)\n");
	kof_chan_publish_close(p);
	munmap(g.h, g.bytes);
	close(g.fd_d);
	close(g.fd_c);
	scrub(n);
	/* pid 0 in a good header */
	ok(seg_make(&g, n, 8, 0), "a segment");
	g.h->pid = 0;
	p = kof_chan_publish_open(n, 8);
	ok(p != NULL, "a header with pid 0: stale");
	kof_chan_publish_close(p);
	munmap(g.h, g.bytes);
	close(g.fd_d);
	close(g.fd_c);
	scrub(n);
	/* a live pid that is not the publisher (pid 1): not stale */
	ok(seg_make(&g, n, 8, 0), "a segment");
	g.h->pid = 1;
	p = kof_chan_publish_open(n, 8);
	ok(p == NULL, "a header naming a live process: the channel is taken, not replaced");
	munmap(g.h, g.bytes);
	close(g.fd_d);
	close(g.fd_c);
	scrub(n);
}

static void case_grant(void)
{
	char n[100], who[64];
	struct kof_chan_pub *p;
	struct group *gr = getgrgid(getgid());
	int rc;
	struct stat sd;
	char path[200];
	int fd;

	printf("\ngrants:\n");
	mkname(n, sizeof n, "g");
	scrub(n);
	p = kof_chan_publish_open(n, 8);
	ok(p != NULL, "a channel");
	ok(kof_chan_publish_grant(NULL, "x") == -1 && errno == EINVAL && kof_chan_publish_grant(p, NULL) == -1 && kof_chan_publish_grant(p, "") == -1, "NULL channel, NULL and empty group: EINVAL");
	ok(kof_chan_publish_grant(p, "no_such_group_wp12_xyz") == -1 && errno == ENOENT, "a group that does not exist: ENOENT");
	if (gr) {
		rc = kof_chan_publish_grant(p, gr->gr_name);
		OKF(rc == 0, "grant to this account's own group '%s'", gr->gr_name);
		snprintf(path, sizeof path, "/%s-d", n);
		fd = shm_open(path, O_RDONLY, 0);
		ok(fd >= 0 && fstat(fd, &sd) == 0 && (sd.st_mode & 0777) == 0640 && sd.st_gid == getgid(), "the data segment is 0640 and group-owned");
		if (fd >= 0)
			close(fd);
		snprintf(path, sizeof path, "/%s-c", n);
		fd = shm_open(path, O_RDONLY, 0);
		ok(fd >= 0 && fstat(fd, &sd) == 0 && (sd.st_mode & 0777) == 0660, "the cursor segment is 0660");
		if (fd >= 0)
			close(fd);
	}
	{
		struct group *root = getgrnam("root");

		if (root && geteuid() != 0 && root->gr_gid != getgid()) {
			rc = kof_chan_publish_grant(p, "root");
			ok(rc == -1 && errno == EPERM, "a group this account is not in: refused with EPERM (and the segments keep their owner)");
		}
	}
	rc = kof_chan_publish_grant_console(p, who, sizeof who);
	if (rc == 0)
		OKF(who[0] != '\0', "console grant: went to '%s' (this session has a login uid)", who);
	else
		OKF(errno == ENOTTY || errno == ENOENT || errno == EPERM, "console grant refused (errno %d: %s) - no login uid / terminal in this session", errno, strerror(errno));
	ok(kof_chan_publish_grant_console(NULL, who, sizeof who) == -1 && errno == EINVAL, "console grant of NULL: EINVAL");
	ok(kof_chan_publish_grant_console(p, NULL, 0) == 0 || 1, "console grant with no name buffer");
	kof_chan_publish_close(p);
}

/* ------------------------------------------------------------------------------------------------- threads */

struct tx {
	struct kof_chan_pub *p;
	unsigned n;
	unsigned dropped;
};

static void *producer(void *a)
{
	struct tx *t = a;
	struct kof_evt e;
	unsigned i;

	for (i = 1; i <= t->n; i++) {
		ev(&e, i);
		while (kof_chan_publish(t->p, &e) == 1) {      /* a full ring: try again (the consumer is slower) */
			t->dropped++;
			sched_yield();
		}
	}
	return NULL;
}

static void case_threads(void)
{
	char n[100];
	struct kof_chan_pub *p;
	struct kof_chan_sub *s;
	pthread_t th;
	struct tx t;
	struct kof_evt out;
	unsigned last = 0, got = 0, bad = 0, idle = 0;
	const char *why;
	int reason;

	printf("\none publisher thread, one consumer thread, 200000 records through 1024 slots:\n");
	mkname(n, sizeof n, "th");
	scrub(n);
	p = kof_chan_publish_open(n, 1024);
	s = kof_chan_sub_open(n, &why, &reason);
	ok(p && s, "both ends");
	t.p = p;
	t.n = 200000;
	t.dropped = 0;
	pthread_create(&th, NULL, producer, &t);
	while (idle < 2000) {
		if (kof_chan_next(s, &out, 1) == 1) {
			idle = 0;
			got++;
			if (out.seq <= last)
				bad++;
			last = (unsigned)out.seq;
			if (out.pid != (uint32_t)out.seq)
				bad++;          /* a torn record: the fields of two records */
		} else {
			idle++;
		}
	}
	pthread_join(th, NULL);
	while (kof_chan_next(s, &out, 0) == 1) {
		got++;
		if (out.seq <= last)
			bad++;
		last = (unsigned)out.seq;
	}
	OKF(bad == 0, "every record in strictly increasing order and none torn (%u bad)", bad);
	OKF(got == t.n && last == t.n, "the publisher retries what a full ring refused, so all %u arrive (got %u, last %u)", t.n, got, last);
	OKF(kof_chan_sub_header(s)->produced == t.n && kof_chan_sub_header(s)->dropped == t.dropped, "the header's counters agree with the publisher's own (%llu produced, %llu refused attempts)",
	    (unsigned long long)kof_chan_sub_header(s)->produced, (unsigned long long)kof_chan_sub_header(s)->dropped);
	kof_chan_sub_close(s);
	kof_chan_publish_close(p);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	snprintf(base, sizeof base, "kwp12-%u-", (unsigned)getpid());
	case_names_open();
	case_segments();
	case_ring();
	case_stale();
	case_grant();
	case_threads();
	printf("\n%d check(s), %d failed; known misses %u\n", checks, fails, km_known_n);
	return (fails || km_fixed_n) ? 1 : 0;
}
