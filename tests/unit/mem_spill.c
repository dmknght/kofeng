/*
 * mem_spill - an object too big for the heap goes to a file only when a file is a safe place,
 * and when it is not, the engine says what it did instead and never loses an object quietly.
 *
 * The seam is the spill layer's own I/O table (struct kof_spill_io, objctx_spill.c), the
 * one the engine calls in every build; the hostile places are simulated through it: no
 * directory, no permission, no space, a disk that fills mid-object, a RAM filesystem. The
 * object is a zip whose one entry inflates to 1.5 MiB, so the sink is past its 1 MiB spill point.
 *
 *   directory unusable (open fails)       findings equal to the no-hook run; spill_unavailable counts
 *   too little free space                 same, spill_small
 *   a RAM filesystem, directory not named same, spill_ram; named by the host: it IS used
 *   ENOSPC part-way                       the object is dropped, not cut: broken = LIMIT,
 *                                         spill_full counts, no descriptor is left open, the next
 *                                         object (the disk freed) scans whole on the same scanner
 *   no file and a small allowance         the memory ceiling refuses the entry: broken, limit_hits,
 *                                         spill_ceiling; at 64 MiB the same object is whole
 *   1000 spilled children                 all findings equal, descriptors back where they were
 *   four threads spilling at once         own scanners, distinct files, equal findings; the real
 *                                         directory holds no leftover name afterwards
 */

#define _GNU_SOURCE
#include "caps_fix.h"
#include "caps_e2e.h"
#include "mem_fix.h"
#include "../../libkofeng/scanners/objctx_int.h"
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

static uint8_t zipb[(3u << 19) + (1u << 16)], data[(3u << 19)];
static uint64_t zlen;

struct sim {
	int      open_fails;            /* errno-style: the open answers -1 */
	uint64_t avail;                 /* what space() reports; 0 = unknown */
	int      ram;
	int64_t  fail_after;            /* bytes accepted before every write fails; <0 = never */
	uint64_t written, opens, writes;
	int      scratch_seen;          /* open was handed a directory */
};

static int s_open(void *u, const char *first)
{
	struct sim *s = u;

	__atomic_add_fetch(&s->opens, 1, __ATOMIC_RELAXED);
	if (first)
		s->scratch_seen = 1;
	if (s->open_fails)
		return -1;
	return memfd_create("kofspill", 0);             /* anonymous: no name, nothing to collide */
}

static int s_write(void *u, int fd, const void *p, uint64_t n)
{
	struct sim *s = u;

	__atomic_add_fetch(&s->writes, 1, __ATOMIC_RELAXED);
	if (s->fail_after >= 0 && s->written + n > (uint64_t)s->fail_after) {
		errno = ENOSPC;
		return 0;
	}
	s->written += n;
	return write(fd, p, (size_t)n) == (ssize_t)n;
}

static int s_space(void *u, int fd, uint64_t *avail, int *ram)
{
	struct sim *s = u;

	(void)fd;
	*ram = s->ram;
	if (!s->avail)
		return 0;
	*avail = s->avail;
	return 1;
}

static struct sim sim0(void)
{
	struct sim s;

	memset(&s, 0, sizeof s);
	s.avail = 1ull << 40;
	s.fail_after = -1;
	return s;
}

static int count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n++;
	closedir(d);
	return n;
}

static struct e2e scan(kof_scanner *sc, uint64_t resident, const char *scratch)
{
	struct kof_scan_option opt;
	struct e2e r;

	memset(&r, 0, sizeof r);
	memset(&opt, 0, sizeof opt);
	opt.max_produced_bytes = 1ull << 40;
	opt.max_resident_bytes = resident;
	opt.max_object_bytes = 64u << 20;
	opt.scratch_dir = scratch;
	(void)kscan_bytes(sc, zipb, zlen, "zip", &opt, e2e_on_object, &r);
	return r;
}

static struct mf_sig sig(const struct e2e *r)
{
	struct mf_sig s;

	mf_sig_of(r, &s);
	return s;
}

static void unusable_places(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct e2e r0 = scan(sc, 256u << 20, NULL);
	struct mf_sig ref = sig(&r0), s;
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct sim sm;
	struct e2e r;

	CK(ref.n_obj >= 2 && ref.incomplete == 0);

	/* a directory that does not exist / cannot be written */
	sm = sim0(); sm.open_fails = 1; io.user = &sm;
	kof_scan_spill_hook(sc, &io);
	r = scan(sc, 256u << 20, "no/such/dir");
	s = sig(&r);
	CK(s.h == ref.h && s.incomplete == 0);
	CK(kscan_stats(sc)->spill_unavailable >= 1 && sm.writes == 0);

	/* too little free space for an object of the size the cap allows */
	sm = sim0(); sm.avail = 1u << 20;
	kof_scan_spill_hook(sc, &io);
	r = scan(sc, 256u << 20, NULL);
	s = sig(&r);
	CK(s.h == ref.h && s.incomplete == 0);
	CK(kscan_stats(sc)->spill_small >= 1 && sm.writes == 0);

	/* a RAM filesystem the host did not name: kept in heap, said */
	sm = sim0(); sm.ram = 1;
	kof_scan_spill_hook(sc, &io);
	r = scan(sc, 256u << 20, NULL);
	s = sig(&r);
	CK(s.h == ref.h && s.incomplete == 0);
	CK(kscan_stats(sc)->spill_ram >= 1 && sm.writes == 0);
	/* ... and one the host named is used */
	sm = sim0(); sm.ram = 1;
	kof_scan_spill_hook(sc, &io);
	r = scan(sc, 256u << 20, "named");
	s = sig(&r);
	CK(s.h == ref.h && s.incomplete == 0);
	CK(sm.writes > 0 && sm.scratch_seen);

	/* an unusable place is looked at again when the host names another */
	sm = sim0(); sm.open_fails = 1;
	kof_scan_spill_hook(sc, &io);
	(void)scan(sc, 256u << 20, "a");
	sm.open_fails = 0;
	(void)scan(sc, 256u << 20, "b");
	CK(sm.writes > 0);
	kof_scan_spill_hook(sc, NULL);
	kscan_free(sc);
}

static void disk_fills(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct sim sm = sim0();
	struct e2e r0, r;
	struct mf_sig ref, s;
	int fds;
	unsigned i;

	io.user = &sm;
	kof_scan_spill_hook(sc, &io);
	r0 = scan(sc, 256u << 20, "named");
	ref = sig(&r0);
	CK(ref.incomplete == 0 && sm.writes > 0);
	fds = count_fds();
	for (i = 0; i < 3u; i++) {
		sm = sim0();
		sm.fail_after = 300000 * (int64_t)(i + 1u);     /* part-way through the entry */
		kof_scan_spill_hook(sc, &io);
		r = scan(sc, 256u << 20, "named");
		s = sig(&r);
		CK(s.incomplete > 0);                           /* said: broken, not clean */
		CK(r.o[r.n - 1u].broken == KOF_BROKEN_LIMIT || r.o[0].broken == KOF_BROKEN_LIMIT);
		CK(kscan_stats(sc)->spill_full >= i + 1u);
		/* the half-written object is not a child that was scanned as if whole */
		CK(r.n < ref.n_obj || s.h != ref.h);
		CK(sc->sink.fd < 0 && sc->sink.spilled == 0 && sc->sink.len == 0);
	}
	CK(count_fds() == fds);                                 /* nothing left open */
	sm = sim0();
	kof_scan_spill_hook(sc, &io);
	r = scan(sc, 256u << 20, "named");
	s = sig(&r);
	CK(s.h == ref.h && s.incomplete == 0);                  /* the disk freed: whole again */
	kof_scan_spill_hook(sc, NULL);
	kscan_free(sc);
}

static void memory_ceiling(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct sim sm = sim0();
	struct e2e r;
	struct mf_sig s;

	sm.open_fails = 1;
	io.user = &sm;
	kof_scan_spill_hook(sc, &io);
	/* an allowance whose per-object cap is a little over 1 MiB (half of it, less a child's record
	 * - the 16 KiB over 2 MiB keeps the cap at or above the 1 MiB where the sink would go to a
	 * file): the 1.5 MiB entry cannot stay in heap, there is no file, so it is refused - said,
	 * and counted */
	r = scan(sc, (2u << 20) + (16u << 10), NULL);
	s = sig(&r);
	CK(s.incomplete > 0);
	CK(kscan_stats(sc)->spill_ceiling >= 1 && kscan_stats(sc)->limit_hits >= 1);
	/* the ceiling scales with the allowance: the same object, 64 MiB, is whole */
	r = scan(sc, 64u << 20, NULL);
	s = sig(&r);
	CK(s.incomplete == 0 && s.n_obj >= 2);
	kof_scan_spill_hook(sc, NULL);
	kscan_free(sc);
}

static void many(void)
{
	kof_scanner *sc = kscan_new(e2e_eng);
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct sim sm = sim0();
	struct e2e r0 = { 0 }, r;
	struct mf_sig ref, s;
	int fds;
	unsigned i, bad = 0;

	io.user = &sm;
	kof_scan_spill_hook(sc, &io);
	r0 = scan(sc, 256u << 20, "named");
	ref = sig(&r0);
	fds = count_fds();
	for (i = 0; i < 1000u; i++) {
		r = scan(sc, 256u << 20, "named");
		s = sig(&r);
		bad += s.h != ref.h || s.incomplete;
	}
	CK(bad == 0);
	CK(sm.opens >= 1000u);                                  /* each one spilled */
	CK(count_fds() == fds);                                 /* each one cleaned */
	kof_scan_spill_hook(sc, NULL);
	kscan_free(sc);
}

struct th { kof_scanner *sc; struct mf_sig ref; int ok; };

static void *th_main(void *p)
{
	struct th *t = p;
	unsigned i;

	for (i = 0; i < 40u; i++) {
		struct e2e r = scan(t->sc, 256u << 20, "build/test");
		struct mf_sig s = sig(&r);

		if (s.h != t->ref.h || s.incomplete)
			t->ok = 0;
	}
	return NULL;
}

static unsigned leftovers(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	unsigned n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)))
		n += strncmp(e->d_name, "kof", 3) == 0 && strlen(e->d_name) == 9u &&
		     strncmp(e->d_name, "kofscratch", 10) != 0;
	closedir(d);
	return n;
}

static void threads(void)
{
	struct th t[4];
	pthread_t id[4];
	unsigned k, before = leftovers("build/test");

	/* the REAL calls, in a real directory that is not RAM: four scanners, one process */
	for (k = 0; k < 4u; k++) {
		struct e2e r;

		t[k].sc = kscan_new(e2e_eng);
		t[k].ok = 1;
		r = scan(t[k].sc, 256u << 20, "build/test");
		t[k].ref = sig(&r);
		CK(t[k].ref.incomplete == 0);
	}
	for (k = 0; k < 4u; k++)
		pthread_create(&id[k], NULL, th_main, &t[k]);
	for (k = 0; k < 4u; k++) {
		pthread_join(id[k], NULL);
		CK(t[k].ok);
		CK(t[k].ref.h == t[0].ref.h);
		kscan_free(t[k].sc);
	}
	CK(leftovers("build/test") == before);
}

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : "build/release/databases")) {
		printf("mem spill: no database\n");
		return 1;
	}
	memset(zipb, 0, sizeof zipb);
	zlen = mf_zip(zipb, data, sizeof data);
	unusable_places();
	disk_fills();
	memory_ceiling();
	many();
	threads();
	printf("mem spill: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
