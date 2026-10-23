/*
 * kit/seams - the kit's fault seams and process limits, driven as good adapters (the kit tests itself):
 *   seam_read   fz_read_fn over a memfd: short reads and EIO after N bytes follow the plan to the byte
 *   seam_spill  fz_wr_fn / fz_wr_open: ENOSPC after N bytes, "no file may be made", an O_TMPFILE that leaves nothing
 *   limits      fz_isolate with RLIMIT_FSIZE, _NOFILE, _NPROC, _AS, _CPU and the RSS poll: each limit is felt by the child
 */
#include "../../lib/fuzz_drv.h"

static void seeds(struct fz_corpus *c)
{
	uint8_t b[300];
	size_t i;

	for (i = 0; i < sizeof b; i++)
		b[i] = (uint8_t)(i ^ (i >> 3));
	fz_corpus_add(c, "300", b, sizeof b);
	fz_corpus_add(c, "17", b, 17);
	fz_corpus_add(c, "0", b, 0);
}

static int mem_fd(const uint8_t *in, size_t n)
{
	int fd = memfd_create("fzseam", 0);

	if (fd < 0)
		return -1;
	if (n && write(fd, in, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	(void)lseek(fd, 0, SEEK_SET);
	return fd;
}

static int seam_read(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static const uint32_t shorts[] = { 0, 1, 7, 4096 };
	struct fz_read_plan p;
	uint8_t buf[4097];                    /* one byte of room past the longest payload, so the end of file is read */
	uint64_t got = 0;
	int64_t r = 0;
	int fd;
	int last_err = 0;

	if (n > sizeof buf - 1u)
		n = sizeof buf - 1u;
	fd = mem_fd(in, n);
	if (fd < 0)
		return 0;
	memset(&p, 0, sizeof p);
	p.short_max = shorts[fz_below(c->rng, 4)];
	p.fail_after = fz_below(c->rng, 2) ? 1u + fz_below(c->rng, n + 8u) : 0u;
	while (got < sizeof buf) {
		r = fz_read_fn(&p, fd, buf + got, sizeof buf - got);
		if (r <= 0) {
			last_err = errno;
			break;
		}
		got += (uint64_t)r;
		FZ_CHECK(c, !p.short_max || r <= (int64_t)p.short_max, "a read longer than short_max");
	}
	if (p.fail_after && p.fail_after <= n) {
		FZ_CHECK(c, got == p.fail_after, "the failing read did not stop at fail_after");
		FZ_CHECK(c, r == -1 && last_err == EIO, "the failing read did not answer -1 with EIO");
	} else {
		FZ_CHECK(c, got == n, "a clean read returned another length");
		FZ_CHECK(c, r == 0, "a clean read did not end with 0");
	}
	FZ_CHECK(c, got == 0 || !memcmp(buf, in, (size_t)got), "a read returned other bytes");
	fz_digest(c, got ^ (uint64_t)p.short_max << 32);
	close(fd);
	return 0;
}
FZ_ADAPTER(seam_read, .name = "kit/seam_read", .shape = FZ_REQ, .seeds = seeds, .run = seam_read);

static int seam_spill(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct fz_wr_plan p;
	int fd = mem_fd(in, 0), ok = 1;
	size_t at = 0;

	if (fd < 0)
		return 0;
	memset(&p, 0, sizeof p);
	p.fail_after = fz_below(c->rng, 2) ? 1u + fz_below(c->rng, n + 8u) : 0u;
	while (at < n && ok) {
		size_t l = n - at < 32 ? n - at : 32;

		ok = fz_wr_fn(&p, fd, in + at, l);
		if (ok)
			at += l;
	}
	FZ_CHECK(c, !p.fail_after || p.bytes <= p.fail_after, "wrote past the plan's room");
	FZ_CHECK(c, ok == (!p.fail_after || n <= p.fail_after) || (p.fail_after && ok), "a write answered against the plan");
	FZ_CHECK(c, p.bytes == at, "bytes counted differ from bytes accepted");
	close(fd);
	memset(&p, 0, sizeof p);
	p.no_file = 1;
	FZ_CHECK(c, fz_wr_open(&p, ".") == -1 && p.opens == 1, "a plan with no file made a file");
	p.no_file = 0;
	fd = fz_wr_open(&p, ".");
	if (fd >= 0)
		close(fd);
	fz_digest(c, at);
	return 0;
}
FZ_ADAPTER(seam_spill, .name = "kit/seam_spill", .shape = FZ_REQ, .seeds = seeds, .run = seam_spill);

static int lim_fsize(void *u)
{
	uint8_t b[8192] = {0};
	int fd = open(".", O_RDWR | O_TMPFILE, 0600);   /* a real file system: a memfd is not limited by RLIMIT_FSIZE */

	(void)u;
	if (fd < 0)
		return 0;                                 /* no O_TMPFILE here: nothing to measure */
	{
		ssize_t w, total = 0;

		while ((w = write(fd, b, sizeof b)) > 0)      /* the first write is cut at the limit, the next one fails */
			total += w;
		close(fd);
		return w < 0 && errno == EFBIG && total <= 4096 ? 0 : 1;
	}
}

static int lim_nofile(void *u)
{
	int fds[64];
	int n = 0;

	(void)u;
	while (n < 64) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0)
			return errno == EMFILE && n <= 16 ? 0 : 1;
		fds[n++] = fd;
	}
	fz_fds_free(fds, n);
	return 1;
}

static int lim_nproc(void *u)
{
	pid_t p = fork();

	(void)u;
	if (p == 0)
		_exit(0);
	if (p > 0) {
		(void)waitpid(p, NULL, 0);
		return 1;
	}
	return errno == EAGAIN ? 0 : 1;
}

static int lim_as(void *u)
{
	void *p = mmap(NULL, (size_t)1 << 30, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	(void)u;
	return p == MAP_FAILED ? 0 : 1;
}

static int lim_spin(void *u)
{
	volatile uint64_t x = 0;

	(void)u;
	for (;;)
		if (++x == UINT64_MAX - 3u)
			break;
	return 0;
}

static int lim_rss(void *u)
{
	size_t n = (size_t)200 << 20, i;
	uint8_t *p;

	(void)u;
	fz_alloc_disarm(NULL);
	p = (uint8_t *)mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 2;
	for (i = 0; i < n; i += 4096)
		p[i] = 1;
	sleep(10);
	return 0;
}

static void one_limit(struct fz_ctx *c, const char *what, int (*fn)(void *), const struct fz_lim *lim, enum fz_kind kind, int code)
{
	struct fz_iso r;

	if (fz_isolate(fn, NULL, 20, lim, &r) < 0 || r.kind != kind || (kind == FZ_EXITED && r.code != code)) {
		printf("  limit %s: kind %d code %d sig %d\n", what, (int)r.kind, r.code, r.sig);
		FZ_CHECK(c, 0, "a process limit was not felt by the child");
	}
}

static int limits(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct fz_lim l;

	(void)in; (void)n;
	if (c->iter != 0 || c->failk)
		return 0;
	memset(&l, 0, sizeof l);
	l.fsize = 4096;
	one_limit(c, "fsize", lim_fsize, &l, FZ_EXITED, 0);
	memset(&l, 0, sizeof l);
	l.nofile = 16;
	one_limit(c, "nofile", lim_nofile, &l, FZ_EXITED, 0);
	if (geteuid() != 0) {
		memset(&l, 0, sizeof l);
		l.nproc = 1;
		one_limit(c, "nproc", lim_nproc, &l, FZ_EXITED, 0);
	}
	if (!FZ_ASAN) {
		memset(&l, 0, sizeof l);
		l.as = (uint64_t)256 << 20;
		one_limit(c, "as", lim_as, &l, FZ_EXITED, 0);
	}
	memset(&l, 0, sizeof l);
	l.rss_mb = 64;
	one_limit(c, "rss", lim_rss, &l, FZ_RSS_KILL, 0);
	memset(&l, 0, sizeof l);
	l.cpu_s = 1;
	one_limit(c, "cpu", lim_spin, &l, FZ_TIMEOUT, 0);
	return 0;
}
FZ_ADAPTER(limits, .name = "kit/limits", .shape = FZ_REQ, .flags = FZ_NONDET | FZ_NO_FAILK | FZ_MAY_HIT_CAP, .seeds = seeds, .run = limits);

/* "Fail the k-th allocation": five allocations of five kinds. A clean call gets all of them; a call with fail_k set loses exactly
 * the k-th (or none, when k is past the end), whichever function made it. */
static int failk_probe(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	void *v[5] = {0};
	void *m;
	unsigned nulls = 0, i;

	(void)in;
	v[0] = malloc(n + 1u);
	v[1] = calloc(n + 1u, 2);
	v[2] = realloc(NULL, n + 1u);
	if (posix_memalign(&m, 64, n + 1u) == 0)
		v[3] = m;
	m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m != MAP_FAILED)
		v[4] = m;
	for (i = 0; i < 5; i++)
		nulls += v[i] == NULL;
	FZ_CHECK(c, c->failk ? nulls <= 1 : nulls == 0, "the k-th allocation failed more than once, or a clean call lost one");
	for (i = 0; i < 4; i++)
		free(v[i]);
	if (v[4])
		munmap(v[4], 4096);
	fz_digest(c, n);
	return 0;
}
FZ_ADAPTER(failk_probe, .name = "kit/failk_probe", .shape = FZ_REQ, .seeds = seeds, .run = failk_probe);
