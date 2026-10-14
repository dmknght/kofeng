/*
 * hostile_engine_scan.c - kscan_path / kscan_path_mt / kscan_bytes handed what
 * an attacker, or the file system, can hand them: paths that are not files,
 * files that change while they are scanned, trees that loop or are deeper than
 * any limit, callbacks that misbehave, scanners that are used in the wrong order.
 *
 * Each case runs in a forked child with an alarm. The ones that END in a signal
 * are the point: a scanner that blocks on a pipe or faults when a file shrinks is
 * a scanner an attacker can stall or crash by choosing a path or racing a write,
 * and that is reported as a result of the case, with the cause beside it.
 *
 *   PATHS         a FIFO, a socket, devices, procfs files, a path of 5000 bytes,
 *                 an unreadable file and directory, odd bytes in a file name
 *   TREES         symlinks that are never followed (whatever follow_symlinks says),
 *                 a directory 400 and 2100 levels deep, five thousand entries,
 *                 max_depth exactly honoured
 *   CHANGING      a file truncated / grown / unlinked / replaced by a symlink in
 *                 the middle of its own scan (the should_stop hook is called
 *                 between modules, which is the one place a test can act while
 *                 the file is being scanned; the cut DURING the read is
 *                 input_read.c's)
 *   CALLBACKS     one that aborts, one that scans again from inside (another
 *                 scanner, then the same one), one that returns garbage
 *   PARALLEL      kscan_path_mt over a tree must agree with the serial walk
 *   EXHAUSTION    an address space too small for the scanner's tables
 */

#include "hostile_engine.h"
#include "known_miss.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include <kofmod/kofsig.h>

#define DB_SIGS "build/test/databases-sigs"
#define DB_REL  "build/release/databases"
#define MARK    "GCC: (GNU)"

#if defined(__SANITIZE_ADDRESS__) || (defined(__has_feature) && __has_feature(address_sanitizer))
#define UNDER_ASAN 1
#else
#define UNDER_ASAN 0
#endif

static char tmp[300];
#define KM_BIT 0x10

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

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
	return v->sc != NULL;
}

static void env_close(struct env *v)
{
	kscan_free(v->sc);
	keng_close(v->e);
}

static int count_cb(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	return he_on_object(name, b, n, r, u);
}

/* ---- paths that are not files ---------------------------------------------------------- */

static int c_fifo(void)
{
	struct env v;
	char p[600];
	struct kof_scan_option o;
	int rc;

	tp(p, sizeof p, "fifo");
	if (mkfifo(p, 0600) != 0 || !env_open(&v, DB_SIGS))
		return 9;
	memset(&o, 0, sizeof o);
	/* Alarm in the harness; reaching the next line means the open did not block. */
	rc = kscan_path(v.sc, p, &o, NULL, NULL);
	env_close(&v);
	return rc == KOF_ERR_OPEN ? 0 : 1;
}

static int c_devices(void)
{
	struct env v;
	struct kof_scan_option o;
	static const char *paths[] = { "/dev/zero", "/dev/urandom", "/dev/null", "/dev/full", "/dev/tty",
				       "/proc/self/maps", "/proc/self/status", "/proc/self/environ",
				       "/sys/kernel/mm", "/proc/self/fd" };
	unsigned i;
	int bad = 0;

	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&o, 0, sizeof o);
	o.recurse_dirs = 0;
	for (i = 0; i < sizeof paths / sizeof paths[0]; i++) {
		struct he_tally t;
		int rc;

		memset(&t, 0, sizeof t);
		rc = kscan_path(v.sc, paths[i], &o, he_on_object, &t);
		/* a result or a refusal; never a hang (the alarm) or a crash */
		printf("  %-22s rc %3d objects %llu bytes %llu\n", paths[i], rc, (unsigned long long)t.objects,
		       (unsigned long long)t.bytes);
		if (!strncmp(paths[i], "/dev/", 5) && strcmp(paths[i], "/dev/tty") != 0 && rc > 0) {
			printf("  FAIL: a device %s was scanned as an object\n", paths[i]);
			bad = 1;
		}
		if (t.bytes > (64ull << 20)) {
			printf("  FAIL: %s produced an object of %llu bytes\n", paths[i], (unsigned long long)t.bytes);
			bad = 1;
		}
	}
	env_close(&v);
	return bad;
}

static int c_socket(void)
{
	struct env v;
	struct sockaddr_un sa;
	char p[600];
	int s, rc;
	struct kof_scan_option o;

	tp(p, sizeof p, "sock");
	if (strlen(p) >= sizeof sa.sun_path)
		return 0;
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, p);
	if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof sa) != 0)
		return 9;
	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&o, 0, sizeof o);
	rc = kscan_path(v.sc, p, &o, NULL, NULL);
	env_close(&v);
	close(s);
	return rc == KOF_ERR_OPEN ? 0 : 1;
}

static int c_long_paths(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char *big = malloc(70000);
	size_t lens[] = { 4094, 4095, 4096, 4097, 5000, 65535 };
	unsigned i;
	int bad = 0;

	if (!big || !env_open(&v, DB_SIGS))
		return 9;
	for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
		int rc;

		memset(big, 'a', lens[i]);
		big[lens[i]] = 0;
		rc = kscan_path(v.sc, big, &o, NULL, NULL);
		if (rc != KOF_ERR_OPEN) {
			printf("  FAIL: a path of %zu bytes answered %d\n", lens[i], rc);
			bad = 1;
		}
	}
	{
		/* a directory named through a thousand redundant separators: the same objects as by its plain name */
		char abs[PATH_MAX], plain[PATH_MAX];
		size_t n = 0, k;
		struct he_tally t1, t2;
		int r1, r2;

		o.recurse_dirs = 1;
		if (realpath(tmp, abs)) {
			snprintf(plain, sizeof plain, "%s", abs);
			big[0] = 0;
			for (k = 0; k < 1000 && n + strlen(abs) + 2u < 4000u; k++)
				big[n++] = '/';
			memcpy(big + n, abs, strlen(abs) + 1u);
			memset(&t1, 0, sizeof t1);
			memset(&t2, 0, sizeof t2);
			r1 = kscan_path(v.sc, plain, &o, he_on_object, &t1);
			r2 = kscan_path(v.sc, big, &o, he_on_object, &t2);
			if (r1 != r2 || t1.objects != t2.objects) {
				printf("  FAIL: the same directory by two spellings: %d objects against %d\n", r1, r2);
				bad = 1;
			}
		}
	}
	free(big);
	env_close(&v);
	return bad;
}

static int c_unreadable(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char f[600], d[600], inner[700];
	uint64_t u0;
	int rc;

	tp(f, sizeof f, "noread.bin");
	tp(d, sizeof d, "nodir");
	put(f, "xxxxxxxx", 8);
	mkdir(d, 0700);
	snprintf(inner, sizeof inner, "%s/in.bin", d);
	put(inner, "yyyy", 4);
	chmod(f, 0);
	chmod(d, 0);
	if (!env_open(&v, DB_SIGS))
		return 9;
	if (geteuid() == 0) {
		env_close(&v);
		return 0;
	}
	u0 = kscan_stats(v.sc)->unreadable;
	rc = kscan_path(v.sc, f, &o, NULL, NULL);
	if (rc != KOF_ERR_OPEN || kscan_stats(v.sc)->unreadable != u0 + 1) {
		printf("  FAIL: unreadable file: rc %d unreadable %llu\n", rc,
		       (unsigned long long)kscan_stats(v.sc)->unreadable);
		return 1;
	}
	u0 = kscan_stats(v.sc)->unreadable;
	rc = kscan_path(v.sc, tmp, &o, NULL, NULL);
	chmod(f, 0600);
	chmod(d, 0700);
	if (kscan_stats(v.sc)->unreadable < u0 + 2) {
		printf("  FAIL: the unreadable file and directory inside the tree are not both counted (%llu)\n",
		       (unsigned long long)(kscan_stats(v.sc)->unreadable - u0));
		return 1;
	}
	env_close(&v);
	return 0;
}

static int c_odd_names(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	static uint8_t buf[100];
	static const char *names[] = { "a\nb.bin", "tab\there", "\xff\xfe.bin", "sp ace", "-dash", "~tilde",
				       "semi;colon", "dollar$x", "quote\"q", "back\\slash", "colon:name", "star*" };
	char d[600], p[700];
	unsigned i, created = 0;
	struct he_tally t;
	int rc;

	tp(d, sizeof d, "odd");
	mkdir(d, 0700);
	marked(buf, sizeof buf);
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		snprintf(p, sizeof p, "%s/%s", d, names[i]);
		created += (unsigned)put(p, buf, sizeof buf);
	}
	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, d, &o, count_cb, &t);
	env_close(&v);
	if (rc != (int)created || t.findings != created) {
		printf("  FAIL: %u files with odd names: %d objects, %llu findings\n", created, rc,
		       (unsigned long long)t.findings);
		return 1;
	}
	return 0;
}

/* ---- trees ------------------------------------------------------------------------------ */

/* One link to an ancestor. The engine never follows links - the owner's decision, a
 * symlink-attack defence - so the tree is the one real file whether or not the
 * (ignored) follow_symlinks option is set. */
static int c_symlink_one(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char d[600], l[700], f[700];
	static uint8_t buf[100];
	struct he_tally t;
	int rc;

	marked(buf, sizeof buf);
	tp(d, sizeof d, "loop1");
	mkdir(d, 0700);
	snprintf(f, sizeof f, "%s/f.bin", d);
	put(f, buf, sizeof buf);
	snprintf(l, sizeof l, "%s/up", d);
	if (symlink("..", l) != 0)
		return 9;
	if (!env_open(&v, DB_SIGS))
		return 9;
	o.follow_symlinks = 0;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, d, &o, count_cb, &t);
	if (rc != 1) {
		printf("  FAIL: links not followed: %d objects\n", rc);
		return 1;
	}
	/* The option is deprecated and ignored: the engine never follows a link. */
	o.follow_symlinks = 1;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, d, &o, count_cb, &t);
	printf("  one loop, follow_symlinks set: %d objects\n", rc);
	env_close(&v);
	if (rc != 1) {
		printf("  FAIL: follow_symlinks changed what the walk reads: %d objects\n", rc);
		return 1;
	}
	return 0;
}

/* Two links in one directory, both loops: followed, every level doubled (the kernel's 40
 * link limit ended it, after minutes). Not followed, it is one file. */
static int c_symlink_two(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char d[600], l[700], f[700];
	static uint8_t buf[100];
	struct he_tally t;
	int rc;

	marked(buf, sizeof buf);
	tp(d, sizeof d, "loop2");
	mkdir(d, 0700);
	snprintf(f, sizeof f, "%s/f.bin", d);
	put(f, buf, sizeof buf);
	snprintf(l, sizeof l, "%s/up", d);
	if (symlink("..", l) != 0)
		return 9;
	snprintf(l, sizeof l, "%s/self", d);
	if (symlink(".", l) != 0)
		return 9;
	if (!env_open(&v, DB_SIGS))
		return 9;
	o.follow_symlinks = 1;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, d, &o, count_cb, &t);
	printf("  two loops, follow_symlinks set: %d objects\n", rc);
	env_close(&v);
	return rc == 1 ? 0 : 1;
}

/* A link to a file, a link to a directory, a link to a missing name and a dangling loop,
 * next to one real file; and a link named AS the scan path. None is read, with the
 * option clear or set, and a link given as the path is refused and counted. */
static int c_symlink_never(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char d[600], l[700], f[700], sub[700];
	static uint8_t buf[100];
	struct he_tally t;
	int rc, flag, bad = 0;

	marked(buf, sizeof buf);
	tp(d, sizeof d, "linknever");
	mkdir(d, 0700);
	snprintf(f, sizeof f, "%s/real.bin", d);
	put(f, buf, sizeof buf);
	snprintf(sub, sizeof sub, "%s/dir", d);
	mkdir(sub, 0700);
	snprintf(l, sizeof l, "%s/dir/inner.bin", d);
	put(l, buf, sizeof buf);
	snprintf(l, sizeof l, "%s/tofile", d);
	if (symlink("real.bin", l) != 0)
		return 9;
	snprintf(l, sizeof l, "%s/todir", d);
	if (symlink("dir", l) != 0)
		return 9;
	snprintf(l, sizeof l, "%s/dangling", d);
	if (symlink("nowhere", l) != 0)
		return 9;
	if (!env_open(&v, DB_SIGS))
		return 9;
	for (flag = 0; flag < 2; flag++) {
		o.follow_symlinks = flag;
		memset(&t, 0, sizeof t);
		rc = kscan_path(v.sc, d, &o, count_cb, &t);
		/* real.bin and dir/inner.bin; the three links are neither. */
		if (rc != 2 || t.objects != 2) {
			printf("  FAIL: follow_symlinks %d: %d objects (%llu callbacks), want the two real files\n", flag, rc,
			       (unsigned long long)t.objects);
			bad = 1;
		}
	}
	/* A link as the scan path itself: a link to a FILE is not opened (O_NOFOLLOW)... */
	snprintf(l, sizeof l, "%s/tofile", d);
	for (flag = 0; flag < 2; flag++) {
		o.follow_symlinks = flag;
		memset(&t, 0, sizeof t);
		rc = kscan_path(v.sc, l, &o, count_cb, &t);
		if (rc > 0 || t.objects != 0) {
			printf("  FAIL: a symlink named as the path was read (follow_symlinks %d, rc %d)\n", flag, rc);
			bad = 1;
		}
	}
	/* ...and a link to a DIRECTORY is not walked. */
	snprintf(l, sizeof l, "%s/todir", d);
	o.follow_symlinks = 1;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, l, &o, count_cb, &t);
	if (rc > 0 || t.objects != 0) {
		printf("  FAIL: a symlink to a directory named as the path was walked (rc %d)\n", rc);
		bad = 1;
	}
	env_close(&v);
	return bad;
}

static int c_deep_tree(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char path[3000], leaf[3100];
	static uint8_t buf[100];
	struct he_tally t;
	unsigned i;
	int rc;

	marked(buf, sizeof buf);
	snprintf(path, sizeof path, "%s/deep", tmp);
	mkdir(path, 0700);
	for (i = 0; i < 400; i++) {
		size_t n = strlen(path);

		if (n + 3 >= sizeof path)
			break;
		strcpy(path + n, "/d");
		mkdir(path, 0700);
	}
	snprintf(leaf, sizeof leaf, "%s/bottom.bin", path);
	put(leaf, buf, sizeof buf);
	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&t, 0, sizeof t);
	snprintf(path, sizeof path, "%s/deep", tmp);
	rc = kscan_path(v.sc, path, &o, count_cb, &t);
	printf("  400 levels deep: %d objects (depth %u made)\n", rc, i);
	env_close(&v);
	return rc == 1 ? 0 : 1;
}

/*
 * 2100 levels, built by chdir because no path to the bottom fits PATH_MAX. max_depth is 0,
 * which is "no limit of the engine's own"; the walk ends where the kernel refuses the
 * path (about 2000 levels), and the directory it could not open is COUNTED, not skipped
 * quietly - that is what makes an unbounded setting honest.
 */
static int c_deeper_tree(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char top[3000], here[3000];
	static uint8_t buf[100];
	struct he_tally t;
	unsigned i, made = 0;
	int rc, bad = 0;

	marked(buf, sizeof buf);
	snprintf(top, sizeof top, "%s/deeper", tmp);
	mkdir(top, 0700);
	if (!getcwd(here, sizeof here))
		return 9;
	if (chdir(top) != 0)
		return 9;
	for (i = 0; i < 2100; i++) {
		if (mkdir("d", 0700) != 0 || chdir("d") != 0)
			break;
		made++;
		if (i == 5)
			put("near.bin", buf, sizeof buf);
	}
	if (chdir(here) != 0)
		return 9;
	if (made < 2100)
		return 9;
	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&t, 0, sizeof t);
	/* The tree's root is absolute: `tmp` is relative to the cwd the test started in. */
	if (top[0] != '/') {
		char abs[3000];

		snprintf(abs, sizeof abs, "%s/%s", here, top);
		snprintf(top, sizeof top, "%s", abs);
	}
	rc = kscan_path(v.sc, top, &o, count_cb, &t);
	printf("  2100 levels: %d objects, unreadable %llu\n", rc, (unsigned long long)kscan_stats(v.sc)->unreadable);
	if (rc != 1)
		bad = 1;
	if (kscan_stats(v.sc)->unreadable == 0) {
		printf("  FAIL: the directory the kernel refused was not counted\n");
		bad = 1;
	}
	env_close(&v);
	return bad;
}

static int c_wide_tree(void)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	char d[600], p[700];
	static uint8_t buf[100];
	struct he_tally t;
	unsigned i;
	int rc;

	marked(buf, sizeof buf);
	tp(d, sizeof d, "wide");
	mkdir(d, 0700);
	for (i = 0; i < 5000; i++) {
		snprintf(p, sizeof p, "%s/f%u.bin", d, i);
		put(p, buf, i % 7 ? sizeof buf : 10);
	}
	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, d, &o, count_cb, &t);
	env_close(&v);
	if (rc != 5000 || t.objects != 5000) {
		printf("  FAIL: 5000 files gave %d objects (%llu callbacks)\n", rc, (unsigned long long)t.objects);
		return 1;
	}
	return 0;
}

/* ---- files that change while they are scanned ---------------------------------------------- */

struct chg {
	char     path[600];
	char     alt[600];
	unsigned calls, act_at;
	int      mode;   /* 0 truncate, 1 grow, 2 unlink, 3 replace by symlink, 4 truncate to half */
};

static int act(void *u)
{
	struct chg *c = (struct chg *)u;

	if (++c->calls == c->act_at) {
		switch (c->mode) {
		case 0:
			(void)truncate(c->path, 0);
			break;
		case 1: {
			FILE *f = fopen(c->path, "ab");

			if (f) {
				static const char junk[4096] = { 1 };
				unsigned k;

				for (k = 0; k < 64; k++)
					fwrite(junk, 1, sizeof junk, f);
				fclose(f);
			}
			break;
		}
		case 2:
			unlink(c->path);
			break;
		case 3:
			unlink(c->path);
			(void)symlink(c->alt, c->path);
			break;
		default:
			(void)truncate(c->path, 1u << 19);
			break;
		}
	}
	return 0;
}

static int c_change(int mode)
{
	struct env v;
	struct kof_scan_option o = he_opt();
	struct chg c;
	uint8_t *b = malloc(4u << 20);
	struct he_tally t;
	int rc;

	if (!b)
		return 9;
	if (mode == 4)
		memset(b, 'A', 4u << 20);
	else
		marked(b, 4u << 20);
	memset(&c, 0, sizeof c);
	snprintf(c.path, sizeof c.path, "%s/changing%d.bin", tmp, mode);
	snprintf(c.alt, sizeof c.alt, "%s/alt.bin", tmp);
	c.mode = mode;
	c.act_at = 2;      /* the first call is before the file is opened */
	put(c.path, b, 4u << 20);
	put(c.alt, b, 128);
	free(b);
	if (!env_open(&v, DB_SIGS))
		return 9;
	o.should_stop = act;
	o.stop_user = &c;
	memset(&t, 0, sizeof t);
	rc = kscan_path(v.sc, c.path, &o, count_cb, &t);
	printf("  mode %d: rc %d, hook calls %u, broken %llu\n", mode, rc, c.calls, (unsigned long long)t.broken);
	env_close(&v);
	/*
	 * A FILE CUT SHORT (modes 0 and 4) AFTER THE ENGINE READ IT: the bytes are the engine's own copy
	 * (objsrc.c, kof_src_file), so the scan is whole and consistent - nothing is mapped, nothing
	 * faults, and no signal handler exists to survive one. Reaching this line at all is the first
	 * half (the process used to die of SIGBUS); the object being scanned whole and not reported
	 * damaged is the second - the file was complete when it was read. A cut that lands DURING the
	 * read is the engine's to report as damaged, and tests/unit/input_read.c cuts at every stage.
	 */
	if ((mode == 0 || mode == 4) && (rc < 1 || t.broken != 0)) {
		printf("  FAIL: truncated after the read: rc %d, %llu broken objects\n", rc, (unsigned long long)t.broken);
		return 1;
	}
	return 0;
}

static int c_trunc0(void) { return c_change(0); }
static int c_trunc_half(void) { return c_change(4); }
static int c_grow(void) { return c_change(1); }
static int c_unlink(void) { return c_change(2); }
static int c_symrep(void) { return c_change(3); }

/* ---- callbacks --------------------------------------------------------------------------------- */

struct cbstate {
	kof_scanner *other;
	kof_scanner *same;
	unsigned calls;
	int      inner_rc;
	int      mode;
	int      ret;
};

static int cb_reenter(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	struct cbstate *s = (struct cbstate *)u;
	static uint8_t inner[100];

	(void)name; (void)b; (void)n; (void)r;
	s->calls++;
	if (s->calls == 1) {
		marked(inner, sizeof inner);
		if (s->mode == 1)
			s->inner_rc = kscan_bytes(s->other, inner, sizeof inner, "inner", NULL, NULL, NULL);
		else if (s->mode == 2)
			s->inner_rc = kscan_bytes(s->same, inner, sizeof inner, "inner", NULL, NULL, NULL);
	}
	return s->ret;
}

static int c_reenter_other(void)
{
	struct env v;
	kof_scanner *other;
	static uint8_t buf[300];
	struct cbstate s;
	int rc;

	if (!env_open(&v, DB_SIGS))
		return 9;
	other = kscan_new(v.e);
	memset(&s, 0, sizeof s);
	s.other = other;
	s.mode = 1;
	marked(buf, sizeof buf);
	rc = kscan_bytes(v.sc, buf, sizeof buf, "outer", NULL, cb_reenter, &s);
	kscan_free(other);
	env_close(&v);
	return rc == 1 && s.inner_rc == 1 ? 0 : 1;
}

static int c_reenter_same(void)
{
	struct env v;
	static uint8_t buf[300];
	struct cbstate s;
	int rc, rc2;
	struct he_tally t;

	if (!env_open(&v, DB_SIGS))
		return 9;
	memset(&s, 0, sizeof s);
	s.same = v.sc;
	s.mode = 2;
	marked(buf, sizeof buf);
	rc = kscan_bytes(v.sc, buf, sizeof buf, "outer", NULL, cb_reenter, &s);
	/* whatever the nested call did, the scanner still answers afterwards */
	rc2 = he_scan(v.sc, buf, sizeof buf, "after", NULL, &t);
	printf("  nested scan on the same scanner: outer %d inner %d after %d findings %llu\n", rc, s.inner_rc,
	       rc2, (unsigned long long)t.findings);
	env_close(&v);
	return rc2 == 1 && t.findings == 1 ? 0 : 1;
}

static int c_cb_garbage(void)
{
	struct env v;
	static uint8_t buf[300];
	struct cbstate s;
	static const int rets[] = { 1, -1, 0x7fffffff, (int)0x80000000 };
	unsigned i;
	int bad = 0;

	if (!env_open(&v, DB_REL))
		return 9;
	marked(buf, sizeof buf);
	for (i = 0; i < sizeof rets / sizeof rets[0]; i++) {
		struct he_w z = { 0 };
		struct he_member m[3] = { { "a", buf, 100 }, { "b", buf, 100 }, { "c", buf, 100 } };
		struct kof_scan_option o = he_opt();

		he_zip(&z, m, 3);
		memset(&s, 0, sizeof s);
		s.ret = rets[i];
		kscan_bytes(v.sc, z.p, z.n, "z.zip", &o, cb_reenter, &s);
		if (s.calls != 1) {
			printf("  FAIL: a callback returning %d was called %u times\n", rets[i], s.calls);
			bad = 1;
		}
		he_free(&z);
	}
	env_close(&v);
	return bad;
}

/* ---- parallel ----------------------------------------------------------------------------------- */

struct bag {
	char     name[512][160];
	uint32_t finds[512];
	uint64_t len[512];
	unsigned n;
};

static int bag_cb(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	struct bag *g = (struct bag *)u;

	(void)b;
	if (g->n < 512) {
		snprintf(g->name[g->n], sizeof g->name[0], "%s", name);
		g->finds[g->n] = r->n;
		g->len[g->n] = n;
	}
	g->n++;
	return 0;
}

static int bag_cmp(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

/* Sort a bag by name through an index array, then compare two bags. */
static int bag_same(struct bag *a, struct bag *b)
{
	unsigned i, j;
	int same = a->n == b->n;

	if (!same)
		return 0;
	for (i = 0; i < a->n && same; i++) {
		int found = 0;

		for (j = 0; j < b->n; j++)
			if (!strcmp(a->name[i], b->name[j])) {
				found = a->finds[i] == b->finds[j] && a->len[i] == b->len[j];
				break;
			}
		same = found;
	}
	(void)bag_cmp;
	return same;
}

static int c_parallel(void)
{
	kof_engine *e = keng_open(DB_SIGS);
	kof_scanner *sc[8];
	struct kof_scan_option o = he_opt();
	static struct bag serial, par;
	char d[600], p[700];
	static uint8_t buf[200];
	unsigned i, k;
	int bad = 0, rc1, rc2;
	uint64_t objs = 0;
	unsigned f0 = he_fails;

	if (!e)
		return 9;
	tp(d, sizeof d, "par");
	mkdir(d, 0700);
	for (i = 0; i < 8; i++) {
		snprintf(p, sizeof p, "%s/s%u", d, i);
		mkdir(p, 0700);
	}
	for (i = 0; i < 400; i++) {
		snprintf(p, sizeof p, "%s/s%u/f%u.bin", d, i % 8, i);
		marked(buf, sizeof buf);
		put(p, buf, i % 3 ? sizeof buf : 20 + i % 50);
	}
	for (i = 0; i < 8; i++)
		sc[i] = kscan_new(e);
	rc1 = kscan_path_mt(sc, 1, d, &o, bag_cb, &serial);
	for (k = 2; k <= 8; k += 2) {
		uint64_t before[8];

		memset(&par, 0, sizeof par);
		for (i = 0; i < 8; i++)
			before[i] = kscan_stats(sc[i])->objects;
		rc2 = kscan_path_mt(sc, k, d, &o, bag_cb, &par);
		for (i = 0; i < 8; i++)
			objs += kscan_stats(sc[i])->objects - before[i];
		if (rc1 != rc2 || !bag_same(&serial, &par)) {
			printf("  FAIL: %u scanners: %d objects against %d serial, same set %d\n", k, rc2, rc1,
			       bag_same(&serial, &par));
			bad = 1;
		}
		if (objs != (uint64_t)rc2) {
			printf("  FAIL: %u scanners: per-scanner stats add to %llu, the walk says %d\n", k,
			       (unsigned long long)objs, rc2);
			bad = 1;
		}
		objs = 0;
	}
	CK(kscan_path_mt(NULL, 2, d, &o, NULL, NULL) == KOF_ERR_ARG, "NULL scanner array");
	CK(kscan_path_mt(sc, 0, d, &o, NULL, NULL) == KOF_ERR_ARG, "zero scanners");
	CK(kscan_path_mt(sc, 2, NULL, &o, NULL, NULL) == KOF_ERR_ARG, "NULL path");
	{
		kof_scanner *nul[2] = { NULL, sc[1] };

		CK(kscan_path_mt(nul, 2, d, &o, NULL, NULL) == KOF_ERR_ARG, "a NULL first scanner");
	}
	CK(kscan_path_mt(sc, 4, "build/test/definitely-missing", &o, NULL, NULL) == KOF_ERR_OPEN, "missing path");
	{
		struct kof_scan_option z;

		memset(&z, 0, sizeof z);
		CK(kscan_path_mt(sc, 4, d, &z, NULL, NULL) == KOF_ERR_OPEN, "a directory without recurse_dirs");
		CK(kscan_path_mt(sc, 4, d, NULL, NULL, NULL) == KOF_ERR_OPEN, "NULL option");
	}
	for (i = 0; i < 8; i++)
		kscan_free(sc[i]);
	keng_close(e);
	return bad || he_fails != f0 ? 1 : 0;
}

struct stopper {
	unsigned n;
};

static int stop_after_five(const char *name, const void *b, uint64_t n, const struct kof_result *r, void *u)
{
	struct stopper *s = (struct stopper *)u;

	(void)name; (void)b; (void)n; (void)r;
	return ++s->n >= 5;
}

static int c_parallel_abort(void)
{
	kof_engine *e = keng_open(DB_SIGS);
	kof_scanner *sc[4];
	struct kof_scan_option o = he_opt();
	struct stopper s = { 0 };
	char d[600];
	unsigned i;
	int rc;
	double t0, t1;
	struct timespec ts;

	if (!e)
		return 9;
	tp(d, sizeof d, "par");
	for (i = 0; i < 4; i++)
		sc[i] = kscan_new(e);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	t0 = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
	rc = kscan_path_mt(sc, 4, d, &o, stop_after_five, &s);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	t1 = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
	printf("  abort after 5: rc %d, %u callbacks, %.2fs\n", rc, s.n, t1 - t0);
	for (i = 0; i < 4; i++)
		kscan_free(sc[i]);
	keng_close(e);
	return rc >= 5 && rc < 400 ? 0 : 1;
}

/* ---- exhaustion ---------------------------------------------------------------------------------- */

static int c_no_memory(void)
{
#if UNDER_ASAN
	return 0;
#else
	struct env v;
	struct rlimit rl;
	kof_scanner *sc;
	static uint8_t buf[300];
	struct kof_scan_option o = he_opt();
	struct he_tally t;
	unsigned i;

	v.e = keng_open(DB_SIGS);
	if (!v.e)
		return 9;
	getrlimit(RLIMIT_AS, &rl);
	{
		/* leave room for what is mapped already and almost nothing else */
		FILE *f = fopen("/proc/self/statm", "r");
		unsigned long pages = 0;

		if (f) {
			if (fscanf(f, "%lu", &pages) != 1)
				pages = 0;
			fclose(f);
		}
		rl.rlim_cur = (rlim_t)pages * 4096u + (6u << 20);
	}
	setrlimit(RLIMIT_AS, &rl);
	marked(buf, sizeof buf);
	for (i = 0; i < 20; i++) {
		sc = kscan_new(v.e);
		if (!sc)
			continue;
		he_scan(sc, buf, sizeof buf, "x", &o, &t);
		kscan_free(sc);
	}
	keng_close(v.e);
	return 0;
#endif
}

/* ---- options at their extremes ------------------------------------------------------------------- */

static int c_options(void)
{
	struct env v;
	static const uint32_t u32s[] = { 0, 1, 2, 3, 0x7fffffffu, 0x80000000u, 0xffffffffu };
	static const uint64_t u64s[] = { 0, 1, 4096, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xffffffffffffffffull };
	struct he_w z = { 0 };
	struct he_member m[2];
	static uint8_t body[300];
	unsigned a, b, n = 0;
	int bad = 0;

	if (!env_open(&v, DB_REL))
		return 9;
	marked(body, sizeof body);
	m[0].name = "a";
	m[0].data = body;
	m[0].len = sizeof body;
	m[1].name = "b";
	m[1].data = body;
	m[1].len = 100;
	he_zip(&z, m, 2);
	for (a = 0; a < sizeof u32s / sizeof u32s[0]; a++)
		for (b = 0; b < sizeof u64s / sizeof u64s[0]; b++) {
			struct kof_scan_option o;
			struct he_tally t;
			int rc;

			memset(&o, 0, sizeof o);
			o.heur_level = u32s[a];
			o.heur_off = u32s[(a + 1u) % 7u];
			o.emu_use = u32s[(a + 2u) % 7u];
			o.emu_forbidden = u32s[(a + 3u) % 7u];
			o.max_depth = u32s[(a + 4u) % 7u];
			o.max_object_depth = u32s[a];
			o.max_children = u32s[(a + 5u) % 7u];
			o.max_resident_bytes = u64s[b];
			o.max_produced_bytes = u64s[(b + 1u) % 6u];
			o.max_object_bytes = u64s[(b + 2u) % 6u];
			o.all_matches = (int)u32s[(a + 6u) % 7u];
			o.report_diag = (int)u32s[a];
			o.recurse_dirs = (int)u32s[b % 7u];
			memset(&t, 0, sizeof t);
			rc = kscan_bytes(v.sc, z.p, z.n, "opts.zip", &o, he_on_object, &t);
			if (rc < 0 || (uint64_t)rc != t.objects) {
				printf("  FAIL: option set %u/%u: rc %d, %llu callbacks\n", a, b, rc, (unsigned long long)t.objects);
				bad = 1;
			}
			n++;
		}
	printf("  %u option combinations scanned\n", n);
	he_free(&z);
	env_close(&v);
	return bad;
}

/* ---- the caller declares what the bytes are --------------------------------------------------------- */

/*
 * Sizes are multiples of 8 so that the buffer, which ends on a page, also begins 8 aligned.
 * proc_parse.c:118 reads the record as `const struct kof_proc_rec` (8 byte alignment) straight
 * from the caller's bytes: with a buffer that starts at an odd address that is a misaligned
 * member access (UBSAN reports it; x86 does not mind). A host's buffers are not always aligned
 * either; the finding is in the report, not in a case that would make this binary
 * unrunnable under -fsanitize=undefined.
 */
static int c_as_format(void)
{
	struct env v;
	static const uint32_t lens[] = { 0, 1, 7, 8, 16, 64, 1000, 4096 };
	unsigned f, l, rounds = 0;
	int bad = 0;
	static uint8_t blob[8192];

	if (!env_open(&v, DB_REL))
		return 9;
	he_seed(99);
	for (f = 0; f < 256u; f++)
		for (l = 0; l < sizeof lens / sizeof lens[0]; l++) {
			struct kof_scan_option o = he_opt();
			struct he_guard gv, go;

			if (f == KOF_FMT_DOCZIP)
				continue;   /* its own case: c_as_doczip */
			unsigned i, nlen = (1u + he_below(300u) + 7u) & ~7u;   /* 8 aligned: see below */
			struct he_tally t;
			int rc;

			for (i = 0; i < sizeof blob; i++)
				blob[i] = (uint8_t)he_next();
			if (!he_guard_make(&go, blob, nlen) ||
			    !he_guard_make(&gv, blob, lens[l]))
				return 9;
			o.as_format = (uint8_t)f;
			o.as_view = lens[l] ? gv.p : NULL;
			o.as_view_len = lens[l];
			memset(&t, 0, sizeof t);
			rc = kscan_bytes(v.sc, go.p, go.n, "as", &o, he_on_object, &t);
			if (rc < 0) {
				printf("  FAIL: as_format %u as_view_len %u: rc %d\n", f, lens[l], rc);
				bad = 1;
			}
			he_guard_free(&go);
			he_guard_free(&gv);
			rounds++;
		}
	printf("  %u declared-format scans\n", rounds);
	env_close(&v);
	return bad;
}

/*
 * A declared format with no parser. scan_facts.c answers a declaration by looking the format up in
 * the parser table; for a format with no row it used to set ctx->format and nothing else, so
 * modules written for that format were offered an object whose view pointer is NULL.
 * KOF_FMT_DOCZIP is the one the shipped database has a module for: bases/decomp/zip.c targets
 * ZIP | DOCZIP and begins `z = kof_zip(ctx); if (!z->valid)`. Now the object is left
 * unidentified, as a failed sniff leaves it.
 */
static int c_as_doczip(void)
{
	struct env v;
	uint8_t blob[300];
	struct kof_scan_option o = he_opt();
	struct he_tally t;
	unsigned i;

	if (!env_open(&v, DB_REL))
		return 9;
	for (i = 0; i < sizeof blob; i++)
		blob[i] = (uint8_t)(i * 7u);
	o.as_format = KOF_FMT_DOCZIP;
	memset(&t, 0, sizeof t);
	kscan_bytes(v.sc, blob, sizeof blob, "doczip", &o, he_on_object, &t);
	env_close(&v);
	return 0;
}

/* ---- the memory allowance ----------------------------------------------------------------------------- */

static int c_allowance(void)
{
	struct env v;
	struct he_w z = { 0 };
	struct he_member m[8];
	static uint8_t big[1u << 20];
	unsigned i;
	struct kof_scan_option o = he_opt();
	struct he_tally t;
	int bad = 0;

	if (!env_open(&v, DB_REL))
		return 9;
	for (i = 0; i < sizeof big; i++)
		big[i] = (uint8_t)(i * 2654435761u >> 24);
	for (i = 0; i < 8; i++) {
		m[i].name = "m";
		m[i].data = big;
		m[i].len = sizeof big;
	}
	he_zip(&z, m, 8);
	o.max_resident_bytes = 1u << 20;
	o.max_produced_bytes = 0;
	o.max_object_bytes = 0;
	memset(&t, 0, sizeof t);
	kscan_bytes(v.sc, z.p, z.n, "allow.zip", &o, he_on_object, &t);
	printf("  1MB allowance over eight 1MB members: %llu objects, %llu broken, peak %llu\n", (unsigned long long)t.objects,
	       (unsigned long long)t.broken, (unsigned long long)kscan_stats(v.sc)->peak_resident);
	if (kscan_stats(v.sc)->peak_resident > (3u << 20)) {
		printf("  FAIL: the ceiling was 1MB and %llu bytes were resident\n", (unsigned long long)kscan_stats(v.sc)->peak_resident);
		bad = 1;
	}
	/* Members are windows into the stored zip: nothing is produced, so nothing is resident; the
	 * allowance bites only on what is decoded. All eight must still be opened. */
	if (t.objects != 9 && t.broken == 0) {
		printf("  FAIL: %llu of 9 objects and nothing says the rest were refused\n", (unsigned long long)t.objects);
		bad = 1;
	}
	he_free(&z);
	env_close(&v);
	return bad;
}

/* ---- the runner ---- ---------------------------------------------------------------------- */

struct kase {
	const char *name;
	int (*body)(void);
	unsigned secs;
	const char *km_what, *km_cap;
	int km_sig;       /* the signal that IS the known defect */
	int km_hang;      /* or: a hang is the known defect */
};

static int run_kase(void *arg)
{
	return ((const struct kase *)arg)->body();
}

static const struct kase cases[] = {
	{ "fifo given as the path", c_fifo, 5, NULL, NULL, 0, 0 },
	{ "socket as the path", c_socket, 10, NULL, NULL, 0, 0 },
	{ "devices and procfs", c_devices, 10, NULL, NULL, 0, 0 },
	{ "very long paths", c_long_paths, 20, NULL, NULL, 0, 0 },
	{ "unreadable file and directory", c_unreadable, 10, NULL, NULL, 0, 0 },
	{ "odd bytes in file names", c_odd_names, 10, NULL, NULL, 0, 0 },
	{ "one symlink loop, follow_symlinks set", c_symlink_one, 20, NULL, NULL, 0, 0 },
	{ "two symlink loops, follow_symlinks set", c_symlink_two, 5, NULL, NULL, 0, 0 },
	{ "symlinks to files and directories are never followed", c_symlink_never, 20, NULL, NULL, 0, 0 },
	{ "directory 400 levels deep", c_deep_tree, 20, NULL, NULL, 0, 0 },
	{ "directory 2100 levels deep (past PATH_MAX)", c_deeper_tree, 30, NULL, NULL, 0, 0 },
	{ "5000 files in one directory", c_wide_tree, 30, NULL, NULL, 0, 0 },
	{ "file truncated to 0 during its scan", c_trunc0, 30, NULL, NULL, 0, 0 },
	{ "file truncated to half during its scan", c_trunc_half, 30, NULL, NULL, 0, 0 },
	{ "file grown during its scan", c_grow, 30, NULL, NULL, 0, 0 },
	{ "file unlinked during its scan", c_unlink, 30, NULL, NULL, 0, 0 },
	{ "file replaced by a symlink during its scan", c_symrep, 30, NULL, NULL, 0, 0 },
	{ "callback scans with another scanner", c_reenter_other, 20, NULL, NULL, 0, 0 },
	{ "callback scans with the same scanner", c_reenter_same, 20, NULL, NULL, 0, 0 },
	{ "callback returns odd values", c_cb_garbage, 20, NULL, NULL, 0, 0 },
	{ "parallel walk equals serial", c_parallel, 60, NULL, NULL, 0, 0 },
	{ "parallel walk aborted by the callback", c_parallel_abort, 30, NULL, NULL, 0, 0 },
	{ "options at their extremes", c_options, 40, NULL, NULL, 0, 0 },
	{ "a declared format and view of any size", c_as_format, 60, NULL, NULL, 0, 0 },
	{ "a declared format that has no parser (DocZip)", c_as_doczip, 20, NULL, NULL, 0, 0 },
	{ "the resident ceiling over stored members", c_allowance, 30, NULL, NULL, 0, 0 },
	{ "address space too small for a scanner", c_no_memory, 30, NULL, NULL, 0, 0 }
};

int main(void)
{
	unsigned i;
	struct stat sb;

	if (stat(DB_REL, &sb) != 0 || stat(DB_SIGS, &sb) != 0) {
		printf("hostile_engine_scan: databases missing - nothing tested\n");
		return 0;
	}
	snprintf(tmp, sizeof tmp, "build/test/hostile_engine_scan_%d", (int)getpid());
	if (mkdir(tmp, 0700) != 0) {
		printf("hostile_engine_scan: no build/test directory - nothing tested\n");
		return 0;
	}
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		const struct kase *k = &cases[i];
		double t0 = now_s();
		struct he_status st = he_child(run_kase, (void *)(uintptr_t)k, k->secs);
		int is_km = k->km_what != NULL;
		int defect = 0;

		printf("%s: %s (%.2fs)\n", k->name, he_how(st), now_s() - t0);
		if (is_km) {
			/* a hang is the alarm; a crash is any other signal (a sanitiser's report is SIGABRT) */
			defect = (k->km_hang && !st.exited && st.sig == SIGALRM) ||
				 (k->km_sig && !st.exited && st.sig != SIGALRM && st.sig > 0);
			CK(defect || he_ok(st), "%s: %s", k->name, he_how(st));
			KM_CHECK(!defect, k->km_what, k->km_cap);
		} else {
			CK(he_ok(st), "%s: %s", k->name, he_how(st));
		}
	}
	he_rmtree(tmp);
	printf("hostile_engine_scan: %u checks, %u failed, %u known-miss\n", he_checks, he_fails, km_known());
	return he_fails != 0 || km_failed();
}
