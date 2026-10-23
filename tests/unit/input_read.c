/*
 * input_read - a file the engine is handed is READ into memory it owns (objsrc.c, kof_src_file), so
 * the engine takes no signal from the input and installs no signal handler to survive one.
 *
 * The owner's rules for a file that changes under a scan, each one a group below:
 *
 *   NO HANDLER     sigaction(SIGBUS) and sigaction(SIGSEGV) are the same before and after a scanner
 *                  is made, scans (serial and parallel, a big file, a file that shrinks) and is
 *                  freed - and a host's own handler, installed first, is still the one in place and
 *                  was never called. Nothing is installed, so nothing is chained and nothing swallowed.
 *   NOT SWALLOWED  after all of that, a real SIGSEGV and a real SIGBUS raised in the same process
 *                  still kill it (a forked child, checked by the signal that ended it).
 *   STAGES         the file is cut, grown, replaced or fails to read at every stage of the read, through
 *                  the seam the read goes through (kof_scan_read_hook): before the open, before the
 *                  first read, in the middle of many, before the last, after the read (during the
 *                  scan). Cut short or EIO: the object is KOF_BROKEN_DAMAGED and the bytes it holds are
 *                  the file's own prefix. Grown: the scan is whole, over the size fstat reported.
 *                  After the read: whole and consistent. Never a crash, never a clean answer for a
 *                  file that was not all read.
 *   REPLACED       renamed over by a shorter file (the descriptor is on the old inode: whole) and
 *                  rewritten shorter in place (damaged).
 *   BUDGET         the bytes are charged to the engine's ceiling while the source lives and given
 *                  back; a file past what the share allows is read as far as it goes and reported
 *                  LIMIT; with a spill file offered, it is copied there whole, and the copy that
 *                  ends early is DAMAGED, one the disk refuses is LIMIT.
 *   PARALLEL       a thread truncates and regrows the files of a tree while four scanners walk it.
 *
 * The seam is the engine's own, the one every build calls (NULL is read(2)).
 */

#define _GNU_SOURCE
#include "hostile_engine.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/syscall.h>

#include "../../libkofeng/scanners/objctx_int.h"
#include "../../libkofeng/scanners/objsrc.h"
#include "../../libkofeng/kofcore/kofbudget.h"
#include "../../libkofeng/databases/pack/dbtables.h"

#define DB_SIGS "build/test/databases-sigs"
#define MARK    "GCC: (GNU)"

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define UNDER_ASAN 1
#else
#define UNDER_ASAN 0
#endif

static char tmp[300];

static void tp(char *out, size_t cap, const char *leaf)
{
	snprintf(out, cap, "%s/%s", tmp, leaf);
}

static int put(const char *path, const void *p, size_t n)
{
	FILE *f = fopen(path, "wb");

	if (!f)
		return 0;
	if (n)
		fwrite(p, 1, n, f);
	fclose(f);
	return 1;
}

/* 'A's with the marker a test signature finds at byte 10: any prefix of 10+len bytes still holds it. */
static void marked(uint8_t *b, size_t n)
{
	memset(b, 'A', n);
	memcpy(b + 10, MARK, strlen(MARK));
}

struct env {
	kof_engine  *e;
	kof_scanner *sc;
};

static int env_open(struct env *v, const char *db)
{
	v->e = keng_open(db);
	v->sc = v->e ? kscan_new(v->e) : NULL;
	notes_watch(v->sc);
	return v->sc != NULL;
}

static void env_close(struct env *v)
{
	kscan_free(v->sc);
	keng_close(v->e);
}

/* ---- the read seam -------------------------------------------------------------------------- */

enum act { A_NONE, A_TRUNC, A_GROW, A_EIO, A_EOF, A_EINTR, A_OVER, A_RENAME, A_REWRITE };

struct rd {
	enum act     act;
	uint64_t     at;          /* the read call the action happens at (1 = the first) */
	uint64_t     chunk;       /* a read call returns at most this much (0 = as asked) */
	uint64_t     cut_to;      /* A_TRUNC, A_REWRITE: the new size */
	const char  *path, *alt;
	uint64_t     calls;
	/* the same action, taken from the should_stop hook instead: before the open (1) or during the scan (2) */
	uint64_t     stop_at, stops;
	int          after_read;  /* act in should_stop, not in a read */
};

static void do_act(struct rd *r)
{
	switch (r->act) {
	case A_TRUNC:
		(void)truncate(r->path, (off_t)r->cut_to);
		break;
	case A_GROW: {
		FILE *f = fopen(r->path, "ab");
		static const char junk[4096] = { 1 };
		unsigned k;

		if (f) {
			for (k = 0; k < 256; k++)
				fwrite(junk, 1, sizeof junk, f);
			fclose(f);
		}
		break;
	}
	case A_RENAME:
		(void)rename(r->alt, r->path);
		break;
	case A_REWRITE: {
		static uint8_t b[1u << 16];
		FILE *f;

		memset(b, 'B', sizeof b);
		f = fopen(r->path, "wb");
		if (f) {
			fwrite(b, 1, r->cut_to < sizeof b ? r->cut_to : sizeof b, f);
			fclose(f);
		}
		break;
	}
	default:
		break;
	}
}

static int64_t hook_read(void *u, int fd, void *buf, uint64_t n)
{
	struct rd *r = u;
	uint64_t call = ++r->calls, asked = n;

	if (r->chunk && n > r->chunk)
		n = r->chunk;
	if (!r->after_read && call == r->at) {
		switch (r->act) {
		case A_EIO:
			errno = EIO;
			return -1;
		case A_EOF:
			return 0;
		case A_EINTR:
			errno = EINTR;
			return -1;
		case A_OVER:
			return (int64_t)asked + 1;  /* a hook claiming more than it was asked: a bug, not data */
		default:
			do_act(r);
			break;
		}
	}
	return (int64_t)read(fd, buf, (size_t)n);
}

static int stop_cb(void *u)
{
	struct rd *r = u;

	if (r->after_read && ++r->stops == r->stop_at)
		do_act(r);
	return 0;
}

/* What the root object was, as the callback saw it. */
struct seen {
	uint64_t        root_len, objects, findings;
	uint32_t        root_broken;
	int             have_root, consistent;
	const uint8_t  *expect;       /* the bytes the root must be a prefix of; NULL = not checked */
	uint64_t        expect_len;
	unsigned        keep_calls;   /* cache_keep calls: a file read in full and clean is offered once */
};

static int seen_cb(const char *name, const void *b, uint64_t len, const struct kof_result *res, void *u)
{
	struct seen *s = u;

	s->objects++;
	{
		struct note_list got;

		notes_here(&got);
		s->findings += res ? got.n : 0u;
	}
	if (kobj_depth(name) == 0 && !s->have_root) {
		s->have_root = 1;
		s->root_len = len;
		s->root_broken = res ? res->broken : 0u;
		s->consistent = 1;
		if (s->expect && (len > s->expect_len || (len && memcmp(b, s->expect, (size_t)len) != 0)))
			s->consistent = 0;
	}
	return 0;
}

static void keep_cb(void *u, const char *path)
{
	(void)path;
	((struct seen *)u)->keep_calls++;
}

static int keep_seen_cb(void *u, const char *path)
{
	(void)u;
	(void)path;
	return 0;
}

static struct kof_scan_option base_opt(struct rd *r, struct seen *s)
{
	struct kof_scan_option o = he_opt();

	o.should_stop = stop_cb;
	o.stop_user = r;
	o.cache_seen = keep_seen_cb;
	o.cache_keep = keep_cb;
	o.cache_user = s;
	return o;
}

/* One file, one scanner, one hook. -1 when the environment could not be made. */
static int scan_with(const char *path, struct rd *r, struct seen *s)
{
	struct env v;
	struct kof_src_read_io io = { hook_read, r };
	struct kof_scan_option o;
	int rc;

	if (!env_open(&v, DB_SIGS))
		return -1;
	o = base_opt(r, s);
	kof_scan_read_hook(v.sc, &io);
	rc = kscan_path(v.sc, path, &o, seen_cb, s);
	kof_scan_read_hook(v.sc, NULL);
	env_close(&v);
	return rc;
}

#define BIG (4u << 20)

static uint8_t orig[BIG];

static void fresh(const char *path)
{
	marked(orig, BIG);
	put(path, orig, BIG);
}

/* ---- NO HANDLER, and the signals still kill ---------------------------------------------------- */

static unsigned host_hits;

static void host_handler(int sig)
{
	(void)sig;
	host_hits++;
}

/* The mask is compared by membership: glibc leaves the bytes of sigset_t past the kernel's 8 unwritten. */
static int same_action(const struct sigaction *a, const struct sigaction *b)
{
	int sig;

	for (sig = 1; sig < 65; sig++)
		if (sigismember(&a->sa_mask, sig) != sigismember(&b->sa_mask, sig))
			return 0;
	return a->sa_flags == b->sa_flags &&
	       ((a->sa_flags & SA_SIGINFO) ? a->sa_sigaction == b->sa_sigaction : a->sa_handler == b->sa_handler);
}

static int c_nohandler(void)
{
	static const int sigs[] = { SIGBUS, SIGSEGV };
	struct sigaction before[2], after[2], host;

	struct env v;
	struct rd r;
	struct seen s;
	char p[600], d[600];
	kof_scanner *sc[4];
	struct kof_scan_option o = he_opt();
	unsigned i;
	int bad = 0, pass;

	tp(p, sizeof p, "nh.bin");
	tp(d, sizeof d, "nhdir");
	fresh(p);
	mkdir(d, 0700);
	for (i = 0; i < 12; i++) {
		char q[700];

		snprintf(q, sizeof q, "%s/f%u.bin", d, i);
		put(q, orig, 300000u + i * 50000u);
	}
	/* Twice: the engine's own state (none installed) first, then a host's handler in place. */
	for (pass = 0; pass < 2; pass++) {
		for (i = 0; i < 2; i++) {
			if (pass == 1) {
				memset(&host, 0, sizeof host);
				host.sa_handler = host_handler;
				sigemptyset(&host.sa_mask);
				sigaction(sigs[i], &host, NULL);
			}
			memset(&before[i], 0, sizeof before[i]);    /* glibc fills 8 of sa_mask's 128 bytes */
			sigaction(sigs[i], NULL, &before[i]);
		}
		memset(&r, 0, sizeof r);
		memset(&s, 0, sizeof s);
		CK(env_open(&v, DB_SIGS), "engine opened");
		/* the same, but a file shrinks during its own read: the case the old handler existed for */
		r.act = A_TRUNC;
		r.at = 2;
		r.chunk = 65536;
		r.path = p;
		r.cut_to = BIG / 2;
		{
			struct kof_src_read_io io = { hook_read, &r };

			kof_scan_read_hook(v.sc, &io);
			CK(kscan_path(v.sc, p, &o, seen_cb, &s) >= 1, "a shrinking file is scanned");
			kof_scan_read_hook(v.sc, NULL);
		}
		fresh(p);
		for (i = 0; i < 4; i++) {
			sc[i] = kscan_new(v.e);
			notes_watch(sc[i]);
		}
		CK(kscan_path_mt(sc, 4, d, &o, seen_cb, &s) >= 12, "the parallel walk scans the tree");
		for (i = 0; i < 4; i++)
			kscan_free(sc[i]);
		env_close(&v);
		for (i = 0; i < 2; i++) {
			memset(&after[i], 0, sizeof after[i]);
			sigaction(sigs[i], NULL, &after[i]);
			CK(same_action(&before[i], &after[i]), "signal %d: the disposition is what it was (pass %d)", sigs[i], pass);
			if (!same_action(&before[i], &after[i]))
				bad = 1;
			if (pass == 1)
				CK(after[i].sa_handler == host_handler && !(after[i].sa_flags & SA_SIGINFO),
				   "signal %d: the host's own handler is still the one installed", sigs[i]);
		}
		CK(host_hits == 0, "the host's handler was never called by a scan");
		for (i = 0; i < 2; i++) {
			struct sigaction dfl;

			memset(&dfl, 0, sizeof dfl);
			dfl.sa_handler = SIG_DFL;
			sigaction(sigs[i], &dfl, NULL);
		}
	}
	return bad || he_fails != 0;
}

static void scan_a_bit(void)
{
	struct env v;
	struct seen s;
	struct rd r;
	char p[600];
	struct kof_scan_option o = he_opt();

	tp(p, sizeof p, "sg.bin");
	fresh(p);
	memset(&s, 0, sizeof s);
	memset(&r, 0, sizeof r);
	if (env_open(&v, DB_SIGS)) {
		(void)kscan_path(v.sc, p, &o, seen_cb, &s);
		env_close(&v);
	}
}

/* Reaching the next line means the signal was swallowed. */
static int c_segv_kills(void)
{
	scan_a_bit();
	{
		volatile int *volatile z = NULL;

		*z = 1;
	}
	return 0;
}

static int c_bus_kills(void)
{
	char p[600];
	int fd;
	volatile uint8_t *m;

	scan_a_bit();
	tp(p, sizeof p, "bus.bin");
	put(p, orig, 8192);
	fd = open(p, O_RDONLY);
	m = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
	truncate(p, 0);
	(void)m[4096];
	return 0;
}

/* ---- STAGES ---------------------------------------------------------------------------------- */

struct stage {
	const char *what;
	enum act    act;
	uint64_t    at, chunk, cut_to;
	int         after_read;
	/* expectation */
	int         damaged;      /* the root is KOF_BROKEN_DAMAGED */
	int64_t     len;          /* the bytes it holds; -1 = at most BIG */
	int         whole;        /* the root is all BIG bytes */
};

static const struct stage stages[] = {
	/* before the open: the file is already short, the size fstat reports is the new one - whole */
	{ "cut to 0 before the open",           A_TRUNC, 1, 0, 0,        1, 0, 0, 0 },
	{ "cut to half before the open",        A_TRUNC, 1, 0, BIG / 2,  1, 0, BIG / 2, 0 },
	/* before the first read */
	{ "cut to 0 before the first read",     A_TRUNC, 1, 0, 0,        0, 1, 0, 0 },
	{ "cut to half before the first read",  A_TRUNC, 1, 0, BIG / 2,  0, 1, BIG / 2, 0 },
	/* in the middle of 64 reads */
	{ "cut to 0 after 2 of 64 reads",       A_TRUNC, 3, 65536, 0,    0, 1, 2 * 65536, 0 },
	{ "cut to a quarter after 31 reads",    A_TRUNC, 32, 65536, BIG / 4, 0, 1, 31 * 65536, 0 },
	{ "cut to half before the last read",   A_TRUNC, 64, 65536, BIG / 2, 0, 1, 63 * 65536, 0 },
	/* after the read, during the scan: the engine's own copy is whole and consistent */
	{ "cut to 0 during the scan",           A_TRUNC, 2, 0, 0,        1, 0, BIG, 1 },
	{ "cut to half during the scan",        A_TRUNC, 3, 0, BIG / 2,  1, 0, BIG, 1 },
	/* grown: the bytes are the size fstat reported, one consistent prefix */
	{ "grown before the first read",        A_GROW, 1, 0, 0,         0, 0, BIG, 1 },
	{ "grown in the middle of 64 reads",    A_GROW, 32, 65536, 0,    0, 0, BIG, 1 },
	{ "grown during the scan",              A_GROW, 2, 0, 0,         1, 0, BIG, 1 },
	/* the read itself fails or ends */
	{ "EIO on the first read",              A_EIO, 1, 0, 0,          0, 1, 0, 0 },
	{ "EIO on the 33rd of 64 reads",        A_EIO, 33, 65536, 0,     0, 1, 32 * 65536, 0 },
	{ "EIO on the last read",               A_EIO, 64, 65536, 0,     0, 1, 63 * 65536, 0 },
	{ "end of file on the first read",      A_EOF, 1, 0, 0,          0, 1, 0, 0 },
	{ "end of file on the 40th read",       A_EOF, 40, 65536, 0,     0, 1, 39 * 65536, 0 },
	{ "an interrupted read is retried",     A_EINTR, 5, 65536, 0,    0, 0, BIG, 1 },
	{ "a read that claims more than asked", A_OVER, 3, 65536, 0,     0, 1, 2 * 65536, 0 },
};

static int c_stages(void)
{
	unsigned i;
	char p[600];
	int bad = 0;

	tp(p, sizeof p, "stage.bin");
	for (i = 0; i < sizeof stages / sizeof stages[0]; i++) {
		const struct stage *st = &stages[i];
		struct rd r;
		struct seen s;
		int rc;

		fresh(p);
		memset(&r, 0, sizeof r);
		memset(&s, 0, sizeof s);
		r.act = st->act;
		r.at = st->after_read ? 0 : st->at;
		r.stop_at = st->after_read ? st->at : 0;
		r.after_read = st->after_read;
		r.chunk = st->chunk;
		r.cut_to = st->cut_to;
		r.path = p;
		s.expect = orig;
		s.expect_len = BIG;
		rc = scan_with(p, &r, &s);
		printf("  %-38s rc %d root %llu bytes broken %u keep %u\n", st->what, rc,
		       (unsigned long long)s.root_len, s.root_broken, s.keep_calls);
		CK(rc >= 1 && s.have_root, "%s: the scan completed and reported the file", st->what);
		CK(s.consistent, "%s: the bytes the root holds are the file's own prefix", st->what);
		if (st->damaged) {
			CK(s.root_broken == KOF_BROKEN_DAMAGED, "%s: reported damaged (%u)", st->what, s.root_broken);
			CK(s.keep_calls == 0, "%s: a file not read whole is never offered to the clean cache", st->what);
		} else if (st->whole) {
			CK(s.root_broken == KOF_BROKEN_NONE, "%s: whole, not damaged (%u)", st->what, s.root_broken);
		}
		if (st->len >= 0 && st->damaged)
			CK(s.root_len == (uint64_t)st->len, "%s: holds %llu bytes, expected %lld", st->what,
			   (unsigned long long)s.root_len, (long long)st->len);
		if (st->whole)
			CK(s.root_len == BIG && s.findings >= 1, "%s: all %u bytes and the marker found", st->what, BIG);
		if (!st->damaged && !st->whole)
			CK(s.root_len == (uint64_t)st->len, "%s: %llu bytes (the size fstat reported)", st->what,
			   (unsigned long long)s.root_len);
		if (he_fails)
			bad = 1;
	}
	return bad || he_fails != 0;
}

/* ---- REPLACED -------------------------------------------------------------------------------- */

static int c_replaced(void)
{
	char p[600], alt[600];
	struct rd r;
	struct seen s;
	uint8_t shorter[100];

	tp(p, sizeof p, "rep.bin");
	tp(alt, sizeof alt, "rep_alt.bin");
	/* renamed over by a shorter file: the open descriptor is on the old inode - the old file, whole */
	fresh(p);
	marked(shorter, sizeof shorter);
	put(alt, shorter, sizeof shorter);
	memset(&r, 0, sizeof r);
	memset(&s, 0, sizeof s);
	r.act = A_RENAME;
	r.at = 2;
	r.chunk = 65536;
	r.path = p;
	r.alt = alt;
	s.expect = orig;
	s.expect_len = BIG;
	CK(scan_with(p, &r, &s) >= 1 && s.have_root, "renamed over: scanned");
	CK(s.root_len == BIG && s.root_broken == KOF_BROKEN_NONE && s.consistent,
	   "renamed over by a shorter file: the old file, whole (%llu bytes, broken %u)", (unsigned long long)s.root_len,
	   s.root_broken);
	/* rewritten shorter in place: the file the descriptor names IS the short one - damaged */
	fresh(p);
	memset(&r, 0, sizeof r);
	memset(&s, 0, sizeof s);
	r.act = A_REWRITE;
	r.at = 2;
	r.chunk = 65536;
	r.path = p;
	r.cut_to = 100;
	CK(scan_with(p, &r, &s) >= 1 && s.have_root, "rewritten: scanned");
	CK(s.root_broken == KOF_BROKEN_DAMAGED, "rewritten shorter in place: damaged (%u)", s.root_broken);
	CK(s.root_len == 65536u && s.consistent, "and holds what was read before the rewrite (%llu bytes)", (unsigned long long)s.root_len);
	return he_fails != 0;
}

/* ---- BUDGET, LIMIT, SPILL -------------------------------------------------------------------- */

static kof_engine *eng;
static uint64_t used_now(void)
{
	return atomic_load(&eng->budget->used);
}

struct snap {
	uint64_t used_in_root, root_len;
	uint32_t root_broken;
};

static struct snap snap_g;

static int snap_cb(const char *name, const void *b, uint64_t len, const struct kof_result *res, void *u)
{
	(void)b;
	(void)u;
	if (kobj_depth(name) == 0) {
		snap_g.used_in_root = used_now();
		snap_g.root_len = len;
		snap_g.root_broken = res ? res->broken : 0u;
	}
	return 0;
}

static int c_budget(void)
{
	kof_scanner *sc = kscan_new(eng);
	struct kof_scan_option o = he_opt();
	char p[600];
	uint64_t base;

	tp(p, sizeof p, "bud.bin");
	fresh(p);
	base = used_now();
	memset(&snap_g, 0, sizeof snap_g);
	CK(kscan_path(sc, p, &o, snap_cb, NULL) >= 1, "scanned");
	CK(snap_g.used_in_root >= base + BIG, "while the root is scanned its %u bytes are held by the engine", BIG);
	CK(snap_g.root_len == BIG && snap_g.root_broken == KOF_BROKEN_NONE, "whole and clean");
	CK(used_now() == base, "and given back when the file is done (%llu before, %llu after)", (unsigned long long)base,
	   (unsigned long long)used_now());
	kscan_free(sc);
	return he_fails != 0;
}

/* kof_src_file by itself: exactly what it charges, holds, and says. */
static int c_src(void)
{
	struct kof_budget b;
	struct kof_src_file_req rq;
	struct kof_objsrc *src;
	char p[600], d[600], l[600];
	int err;
	kof_buf buf;

	tp(p, sizeof p, "src.bin");
	tp(d, sizeof d, "src_dir");
	tp(l, sizeof l, "src_link");
	fresh(p);
	mkdir(d, 0700);
	(void)symlink(p, l);
	memset(&rq, 0, sizeof rq);
	rq.path = p;
	rq.budget = &b;
	rq.room = rq.limit = 2u * BIG;

	kof_budget_init(&b, 64u << 20);
	src = kof_src_file(&rq, &err);
	CK(src && err == 0, "a file is read");
	buf = kof_src_buf(src);
	CK(buf.n == BIG && memcmp(buf.p, orig, BIG) == 0, "all of it, byte for byte");
	CK(kof_src_cut(src) == 0 && kof_src_charged(src) == BIG, "whole, and charged exactly its size");
	CK(atomic_load(&b.used) == BIG, "the budget holds %u", BIG);
	kof_src_unref(src);
	CK(atomic_load(&b.used) == 0, "and none when the source is gone");

	rq.limit = rq.room = BIG / 4;
	src = kof_src_file(&rq, &err);
	CK(src && kof_src_buf(src).n == BIG / 4 && kof_src_cut(src) == KOF_BROKEN_LIMIT, "past the limit: the head, marked LIMIT");
	CK(memcmp(kof_src_buf(src).p, orig, BIG / 4) == 0, "and it is the file's own head");
	CK(atomic_load(&b.used) == BIG / 4, "charged for what was held");
	kof_src_unref(src);
	CK(atomic_load(&b.used) == 0, "given back");

	rq.limit = rq.room = 2u * BIG;
	kof_budget_init(&b, BIG / 2);
	src = kof_src_file(&rq, &err);
	CK(src && kof_src_buf(src).n == BIG / 2 && kof_src_cut(src) == KOF_BROKEN_LIMIT,
	   "the budget has less than the room: what it has, marked LIMIT");
	kof_src_unref(src);
	kof_budget_init(&b, 64u << 20);
	(void)kof_budget_charge(&b, 64u << 20);
	src = kof_src_file(&rq, &err);
	CK(src && kof_src_buf(src).n == 0 && kof_src_cut(src) == KOF_BROKEN_LIMIT, "a spent budget: an empty object, marked LIMIT");
	kof_src_unref(src);

	rq.budget = NULL;
	src = kof_src_file(&rq, &err);
	CK(src && kof_src_buf(src).n == BIG && kof_src_cut(src) == 0 && kof_src_charged(src) == 0, "no budget: read, nothing charged");
	kof_src_unref(src);

	put(p, orig, 0);
	src = kof_src_file(&rq, &err);
	CK(src && err == 0 && kof_src_buf(src).n == 0 && kof_src_cut(src) == 0, "an empty file is an object with no bytes");
	kof_src_unref(src);

	rq.path = d;
	CK(kof_src_file(&rq, &err) == NULL && err == KOF_ERR_OPEN, "a directory is refused");
	rq.path = l;
	CK(kof_src_file(&rq, &err) == NULL && err == KOF_ERR_OPEN, "a symlink is refused");
	rq.path = "build/test/no-such-file-for-input-read";
	CK(kof_src_file(&rq, &err) == NULL && err == KOF_ERR_OPEN, "a missing file is refused");
	CK(kof_src_cut(NULL) == 0 && kof_src_charged(NULL) == 0, "NULL answers 0");
	return he_fails != 0;
}

#define HUGE_FILE (40u << 20)

static int c_limit(void)
{
	kof_scanner *sc;
	struct kof_scan_option o = he_opt();
	char p[600];
	uint8_t *b = malloc(HUGE_FILE);
	uint64_t db = keng_memory_db(eng), base, lim;
	uint64_t cap_before = keng_memory_cap(eng);
	uint64_t hits;

	if (!b)
		return 9;
	marked(b, HUGE_FILE);
	tp(p, sizeof p, "huge.bin");
	put(p, b, HUGE_FILE);
	free(b);
	/* a ceiling too small for this file's share: 40 MiB cannot be held under 32 MiB */
	CK(keng_set_memory_cap(eng, 32u << 20), "a 32 MiB ceiling is allowed");
	sc = kscan_new(eng);
	CK(sc != NULL, "a scanner is made under it");
	if (!sc)
		return 1;
	base = used_now();
	hits = kscan_stats(sc)->limit_hits;
	memset(&snap_g, 0, sizeof snap_g);
	CK(kscan_path(sc, p, &o, snap_cb, NULL) >= 1, "scanned");
	lim = snap_g.root_len;
	printf("  40 MiB file under a 32 MiB ceiling (database %llu): %llu bytes held, broken %u\n",
	       (unsigned long long)db, (unsigned long long)lim, snap_g.root_broken);
	CK(lim < HUGE_FILE, "only the part the share allows is held (%llu of %u)", (unsigned long long)lim, HUGE_FILE);
	CK(snap_g.root_broken == KOF_BROKEN_LIMIT, "and it is SAID: Limit reached (%u)", snap_g.root_broken);
	CK(kscan_stats(sc)->limit_hits > hits, "limit_hits moved");
	CK(snap_g.used_in_root <= keng_memory_cap(eng), "the engine never held more than its ceiling");
	CK(used_now() == base, "and the charge came back");
	kscan_free(sc);
	CK(keng_set_memory_cap(eng, cap_before), "the ceiling is restored");
	return he_fails != 0;
}

/* The spill file, simulated through the engine's own seam as mem_spill does: a memfd, anonymous. */
struct sim {
	int      open_fails, ram;
	int64_t  fail_after;
	uint64_t written, opens, writes;
};

static int s_open(void *u, const char *first)
{
	struct sim *s = u;

	(void)first;
	__atomic_add_fetch(&s->opens, 1, __ATOMIC_RELAXED);
	return s->open_fails ? -1 : (int)syscall(SYS_memfd_create, "kofspill", 0);
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
	*avail = 1ull << 40;
	return 1;
}

static int c_spill(void)
{
	kof_scanner *sc;
	struct kof_scan_option o = he_opt();
	struct sim sm;
	struct kof_spill_io io = { s_open, s_write, s_space, NULL };
	struct rd r;
	struct kof_src_read_io rio = { hook_read, &r };
	char p[600];
	uint8_t *b = malloc(HUGE_FILE);
	uint64_t cap_before = keng_memory_cap(eng), base;
	uint64_t damaged_len;

	if (!b)
		return 9;
	marked(b, HUGE_FILE);
	tp(p, sizeof p, "spill.bin");
	put(p, b, HUGE_FILE);
	free(b);
	CK(keng_set_memory_cap(eng, 32u << 20), "a 32 MiB ceiling is allowed");
	sc = kscan_new(eng);
	if (!sc)
		return 1;
	base = used_now();
	io.user = &sm;
	o.scratch_dir = "named";

	/* a spill file may be made: the file is copied there whole, nothing is charged for it */
	memset(&sm, 0, sizeof sm);
	sm.fail_after = -1;
	kof_scan_spill_hook(sc, &io);
	memset(&snap_g, 0, sizeof snap_g);
	CK(kscan_path(sc, p, &o, snap_cb, NULL) >= 1, "spill: scanned");
	CK(snap_g.root_len == HUGE_FILE && snap_g.root_broken == KOF_BROKEN_NONE,
	   "spill: all %u bytes, whole (%llu, broken %u)", HUGE_FILE, (unsigned long long)snap_g.root_len, snap_g.root_broken);
	CK(sm.writes >= HUGE_FILE / (1u << 20) && sm.written == HUGE_FILE, "spill: the file went through the spill file (%llu bytes)",
	   (unsigned long long)sm.written);
	CK(used_now() == base, "spill: nothing left charged");

	/* the disk fills part-way: what was written is held, and it is a LIMIT */
	memset(&sm, 0, sizeof sm);
	sm.fail_after = 20u << 20;
	kof_scan_spill_hook(sc, &io);
	memset(&snap_g, 0, sizeof snap_g);
	CK(kscan_path(sc, p, &o, snap_cb, NULL) >= 1, "full disk: scanned");
	CK(snap_g.root_len == (20u << 20) && snap_g.root_broken == KOF_BROKEN_LIMIT,
	   "full disk: the 20 MiB written, Limit reached (%llu, %u)", (unsigned long long)snap_g.root_len, snap_g.root_broken);
	CK(kscan_stats(sc)->spill_full >= 1, "full disk: spill_full counts");

	/* the file is cut while it is copied: damaged, with the part copied */
	memset(&sm, 0, sizeof sm);
	sm.fail_after = -1;
	kof_scan_spill_hook(sc, &io);
	memset(&r, 0, sizeof r);
	r.act = A_TRUNC;
	r.at = 5;
	r.cut_to = 10u << 20;
	r.path = p;
	kof_scan_read_hook(sc, &rio);
	memset(&snap_g, 0, sizeof snap_g);
	CK(kscan_path(sc, p, &o, snap_cb, NULL) >= 1, "cut during the copy: scanned");
	kof_scan_read_hook(sc, NULL);
	damaged_len = snap_g.root_len;
	CK(snap_g.root_broken == KOF_BROKEN_DAMAGED && damaged_len >= (4u << 20) && damaged_len <= (10u << 20),
	   "cut during the copy: damaged with the part copied (%llu, %u)", (unsigned long long)damaged_len, snap_g.root_broken);

	/* no file may be made (a RAM filesystem the host did not name): held in memory up to the limit, said */
	{
		struct kof_scan_option o2 = he_opt();

		{
			uint8_t *b2 = malloc(HUGE_FILE);

			if (!b2)
				return 9;
			marked(b2, HUGE_FILE);
			put(p, b2, HUGE_FILE);
			free(b2);
		}
		memset(&sm, 0, sizeof sm);
		sm.fail_after = -1;
		sm.ram = 1;
		kof_scan_spill_hook(sc, &io);
		memset(&snap_g, 0, sizeof snap_g);
		CK(kscan_path(sc, p, &o2, snap_cb, NULL) >= 1, "RAM scratch: scanned");
		CK(sm.writes == 0 && snap_g.root_len < HUGE_FILE && snap_g.root_broken == KOF_BROKEN_LIMIT,
		   "RAM scratch: no spill, the head is held and it is said (%llu, %u)", (unsigned long long)snap_g.root_len,
		   snap_g.root_broken);
		CK(kscan_stats(sc)->spill_ram >= 1, "RAM scratch: spill_ram counts");
	}
	kof_scan_spill_hook(sc, NULL);
	CK(used_now() == base, "nothing left charged");
	kscan_free(sc);
	CK(keng_set_memory_cap(eng, cap_before), "the ceiling is restored");
	return he_fails != 0;
}

/* ---- PARALLEL -------------------------------------------------------------------------------- */

static atomic_int stop_thr;
static char thr_dir[600];

static void *meddler(void *arg)
{
	unsigned n = 0;

	(void)arg;
	while (!atomic_load(&stop_thr)) {
		char q[700];
		unsigned i = n++ % 24u;

		snprintf(q, sizeof q, "%s/m%u.bin", thr_dir, i);
		switch ((n / 24u) % 3u) {
		case 0:
			(void)truncate(q, (off_t)(((n * 7919u) % 500u) * 1024u));
			break;
		case 1: {
			FILE *f = fopen(q, "ab");

			if (f) {
				static const char junk[8192] = { 2 };

				fwrite(junk, 1, sizeof junk, f);
				fclose(f);
			}
			break;
		}
		default:
			(void)truncate(q, 0);
			break;
		}
	}
	return NULL;
}

static int c_parallel(void)
{
	struct env v;
	kof_scanner *sc[4];
	struct kof_scan_option o = he_opt();
	struct seen s;
	pthread_t th;
	unsigned i, round;
	int rc = 0;

	tp(thr_dir, sizeof thr_dir, "meddle");
	mkdir(thr_dir, 0700);
	marked(orig, BIG);
	for (i = 0; i < 24; i++) {
		char q[700];

		snprintf(q, sizeof q, "%s/m%u.bin", thr_dir, i);
		put(q, orig, 1u << 20);
	}
	if (!env_open(&v, DB_SIGS))
		return 9;
	for (i = 0; i < 4; i++) {
		sc[i] = kscan_new(v.e);
		notes_watch(sc[i]);
	}
	memset(&s, 0, sizeof s);
	atomic_store(&stop_thr, 0);
	pthread_create(&th, NULL, meddler, NULL);
	for (round = 0; round < 8; round++) {
		rc = kscan_path_mt(sc, 4, thr_dir, &o, seen_cb, &s);
		CK(rc >= 0, "round %u: the parallel walk of files that change returns a count (%d)", round, rc);
	}
	atomic_store(&stop_thr, 1);
	pthread_join(th, NULL);
	for (i = 0; i < 4; i++)
		kscan_free(sc[i]);
	env_close(&v);
	CK(s.objects > 0, "objects were scanned");
	return he_fails != 0;
}

/* ---- the runner ------------------------------------------------------------------------------ */

struct kase {
	const char *name;
	int       (*body)(void);
	unsigned    secs;
	int         sig;      /* the signal the case MUST end in, 0 for a normal exit */
};

static int run_kase(void *arg)
{
	/* a child's tally is its own: the parent's failures so far are not the case's */
	he_fails = 0;
	he_checks = 0;
	return ((const struct kase *)arg)->body();
}

static const struct kase cases[] = {
	{ "no signal handler installed or replaced by a scan", c_nohandler, 60, 0 },
	{ "a real SIGSEGV still kills the process after a scan", c_segv_kills, 30, SIGSEGV },
	{ "a real SIGBUS still kills the process after a scan", c_bus_kills, 30, SIGBUS },
	{ "a file cut, grown or failing at every stage of the read", c_stages, 120, 0 },
	{ "a file replaced by a shorter one", c_replaced, 30, 0 },
	{ "the file's bytes are charged and given back", c_budget, 30, 0 },
	{ "kof_src_file: what it charges, holds and says", c_src, 30, 0 },
	{ "a file past the share is cut and said", c_limit, 60, 0 },
	{ "a file past the share goes to the spill file", c_spill, 120, 0 },
	{ "parallel walk of files that change", c_parallel, 120, 0 },
};

int main(void)
{
	unsigned i;
	struct stat sb;

	if (stat(DB_SIGS, &sb) != 0) {
		printf("input_read: databases missing - nothing tested\n");
		return 0;
	}
	snprintf(tmp, sizeof tmp, "build/test/input_read_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("input_read: no build/test directory - nothing tested\n");
		return 0;
	}
	/* the budget cases share one engine of their own; the rest each make theirs in their child */
	eng = keng_open(DB_SIGS);
	CK(eng != NULL, "an engine for the budget cases");
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		const struct kase *k = &cases[i];
		struct he_status st;
		int ok;

		st = he_child(run_kase, (void *)(uintptr_t)k, k->secs);
		if (k->sig) {
			/* under a sanitiser the report is SIGABRT or its own exit code (abort_on_error is the
			 * make target's to set): the process still died of the fault, which is the point */
			ok = (!st.exited && (st.sig == k->sig || st.sig == SIGABRT)) ||
			     (UNDER_ASAN && st.exited && st.code != 0);
			printf("%s: %s%s\n", k->name, he_how(st), ok ? " (killed, as it must be)" : "");
			CK(ok, "%s: expected to die of signal %d, got %s", k->name, k->sig, he_how(st));
		} else {
			printf("%s: %s\n", k->name, he_how(st));
			CK(he_ok(st), "%s: %s", k->name, he_how(st));
		}
	}
	keng_close(eng);
	he_rmtree(tmp);
	printf("input_read: %u checks, %u failed\n", he_checks, he_fails);
	return he_fails != 0;
}
