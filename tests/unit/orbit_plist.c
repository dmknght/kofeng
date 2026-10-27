/*
 * orbit_plist - the Linux process list (kofa_plist_*, aproc.c) over a FAKE /proc: every file the walk reads is a real file
 * the test wrote under build/kof_orbit_plist_XXXXXX and tests/lib/orbit_sys.c sends "/proc/..." there (link-time wraps; the
 * library has no seam). That is the only way to hand the walk a /proc/<pid>/stat that no kernel would write, so the
 * suites below are about content the real /proc never shows but a process can still arrange:
 *
 *   stat      the fields, the comm trap at the last ')', every malformed shape, the numbers at 32 and 64 bits
 *   exe       readlink: the "(deleted)" suffix, memfd, a path longer than the buffer, a link that is not there
 *   cmdline   a run of NUL-terminated words: no NUL at all, all NULs, 10 MB of it, binary; and the environ twin
 *   fds       stdio by name, sockets counted, the 256-inode cap, names that are not numbers, 20000 descriptors
 *   net       the four /proc/<pid>/net tables joined on the inode: bad rows, short addresses, a line over the buffer
 *   errors    EMFILE / EACCES / EINTR on each open, opendir failure: what the walk calls them
 *   fd limit  RLIMIT_NOFILE exhausted on the REAL /proc (what a walk reports when it cannot open anything)
 *
 * Defects met are rows with KM_CHECK (known_miss.h): green while the library has them, red the day it stops.
 * Defect ids are WP12-n; the list is in the work package's final report.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "aproc.h"
#include "known_miss.h"
#include "../lib/orbit_sys.c"

static int fails, checks;
static char *R;

#define OKF(cond, ...) do { char w_[240]; snprintf(w_, sizeof w_, __VA_ARGS__); ok((cond), w_); } while (0)

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		printf("  FAIL %s\n", what);
		fails++;
	}
}

/* what a walk returned for one process: copies, because the walk's strings are borrowed */
struct seen {
	uint32_t pid, ppid, flags, n_fd, n_socket, n_like_stdin, environ_len, uid;
	uint64_t start;
	uint8_t  fds_read, exe_on_disk, is_kthread;
	char     comm[80], exe[4200], cmd[4200], env[8300], net[4200], fd0[300], fd1[300], fd2[300];
};

static struct seen got[64];
static unsigned n_got;

static int walk(const struct kofa_plist_option *o, int *err_out)
{
	struct kofa_plist *l;
	struct kofa_proc p;
	int err = -1;

	n_got = 0;
	l = kofa_plist_open(o, &err);
	if (err_out)
		*err_out = err;
	if (!l)
		return 0;
	while (n_got < 64 && kofa_plist_next(l, &p)) {
		struct seen *s = &got[n_got++];

		memset(s, 0, sizeof *s);
		s->pid = p.pid;
		s->ppid = p.ppid;
		s->flags = p.flags;
		s->n_fd = p.n_fd;
		s->n_socket = p.n_socket;
		s->n_like_stdin = p.n_like_stdin;
		s->environ_len = p.environ_len;
		s->uid = p.uid;
		s->start = p.start_time;
		s->fds_read = p.fds_read;
		s->exe_on_disk = p.exe_on_disk;
		s->is_kthread = p.is_kthread;
		snprintf(s->comm, sizeof s->comm, "%s", p.comm ? p.comm : "(null)");
		snprintf(s->exe, sizeof s->exe, "%s", p.exe ? p.exe : "(null)");
		snprintf(s->cmd, sizeof s->cmd, "%s", p.cmdline ? p.cmdline : "(null)");
		if (p.environ)
			memcpy(s->env, p.environ, p.environ_len < sizeof s->env - 1 ? p.environ_len : sizeof s->env - 1);
		snprintf(s->net, sizeof s->net, "%s", p.net ? p.net : "(null)");
		snprintf(s->fd0, sizeof s->fd0, "%s", p.fd_stdin ? p.fd_stdin : "(null)");
		snprintf(s->fd1, sizeof s->fd1, "%s", p.fd_stdout ? p.fd_stdout : "(null)");
		snprintf(s->fd2, sizeof s->fd2, "%s", p.fd_stderr ? p.fd_stderr : "(null)");
	}
	kofa_plist_close(l);
	return (int)n_got;
}

static struct seen *find(uint32_t pid)
{
	unsigned i;

	for (i = 0; i < n_got; i++)
		if (got[i].pid == pid)
			return &got[i];
	return NULL;
}

/* the entry for a pid, or an empty one: a missing process fails its own check and does not crash the next */
static struct seen *must(uint32_t pid)
{
	static struct seen none;
	struct seen *s = find(pid);

	return s ? s : &none;
}

static void fresh(void)
{
	osys_reset();
	osys_rmrf(R);
	mkdir(R, 0755);
	osys_proc_root(R);
}

static void put_s(uint32_t pid, const char *rel, const char *text) { (void)osys_put(R, pid, rel, text, strlen(text)); }

/* the 52 fields of a real stat line, with the ones the walk reads set */
static void mkstat(char *buf, size_t cap, uint32_t pid, const char *comm, unsigned long long ppid, unsigned flags,
		   unsigned long long start)
{
	int n = snprintf(buf, cap, "%u (%s) S %llu 1 1 0 -1 %u 0 0 0 0 0 0 0 0 20 0 1 0 %llu 4096 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n",
			 pid, comm, ppid, flags, start);
	(void)n;
}

static void put_stat(uint32_t pid, const char *comm, unsigned long long ppid, unsigned flags, unsigned long long start)
{
	char b[8192];

	mkstat(b, sizeof b, pid, comm, ppid, flags, start);
	put_s(pid, "stat", b);
	put_s(pid, "maps", "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n");
}

static struct kofa_plist_option opt_min(void)
{
	struct kofa_plist_option o;

	memset(&o, 0, sizeof o);
	o.no_net = 1;
	return o;
}

/* ------------------------------------------------------------------------------------------------- stat */

struct stat_row {
	const char *id;
	const char *raw;        /* the whole file */
	size_t      len;
	int         listed;     /* does the walk return the process */
	unsigned    ppid;
	unsigned long long start;
	const char *comm;
};

static const struct stat_row stat_rows[] = {
	{ "plain", "100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n", sizeof("100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n") - 1u, 1, 42, 777, "bash" },
	{ "comm with ') 1 2 3 ('", "100 () 1 2 3 () S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 888 1 1\n", sizeof("100 () 1 2 3 () S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 888 1 1\n") - 1u, 1, 42, 888, ") 1 2 3 (" },
	{ "empty comm", "100 () S 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1\n", sizeof("100 () S 7 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1\n") - 1u, 1, 7, 5, "" },
	{ "comm of spaces and parens", "100 ( ) ( ) S 9 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 6 1 1\n", sizeof("100 ( ) ( ) S 9 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 6 1 1\n") - 1u, 1, 9, 6, " ) ( " },
	{ "no ')' at all", "100 (bash S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n", sizeof("100 (bash S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n") - 1u, 0, 0, 0, "" },
	{ "no '(' but a ')'", "100 bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n", sizeof("100 bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 1 1\n") - 1u, 1, 42, 777, "" },
	{ "stops after the state", "100 (bash) S", sizeof("100 (bash) S") - 1u, 0, 0, 0, "" },
	{ "stops before starttime (19 fields)", "100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0", sizeof("100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0") - 1u, 0, 0, 0, "" },
	{ "starttime is the last field and has no newline", "100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 31337", sizeof("100 (bash) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 31337") - 1u, 1, 42, 31337, "bash" },
	{ "ppid is not a number", "100 (bash) S x 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n", sizeof("100 (bash) S x 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n") - 1u, 0, 0, 0, "" },
	{ "a field in the middle is not a number", "100 (bash) S 42 1 1 0 -1 abc 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n", sizeof("100 (bash) S 42 1 1 0 -1 abc 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n") - 1u, 0, 0, 0, "" },
	{ "negative ppid wraps (strtoull accepts '-')", "100 (bash) S -1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n", sizeof("100 (bash) S -1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n") - 1u, 1, 0xffffffffu, 1, "bash" },
	{ "ppid above 32 bits is cut to 32", "100 (bash) S 4294967297 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n", sizeof("100 (bash) S 4294967297 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n") - 1u, 1, 1, 1, "bash" },
	{ "starttime 2^64-1", "100 (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 18446744073709551615 1 1\n", sizeof("100 (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 18446744073709551615 1 1\n") - 1u, 1, 1, 18446744073709551615ull, "bash" },
	{ "starttime past 2^64 saturates", "100 (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999999999999999999999 1 1\n", sizeof("100 (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999999999999999999999 1 1\n") - 1u, 1, 1, 18446744073709551615ull, "bash" },
	{ "extra spaces between fields", "100 (bash)    S    42  1   1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0   9 1 1\n", sizeof("100 (bash)    S    42  1   1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0   9 1 1\n") - 1u, 1, 42, 9, "bash" },
	{ "empty file", "", sizeof("") - 1u, 0, 0, 0, "" },
	{ "only a newline", "\n", sizeof("\n") - 1u, 0, 0, 0, "" },
	{ "NUL inside comm (strrchr stops at it: no ')')", "100 (ba\0sh) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7 1 1\n", sizeof("100 (ba\0sh) S 42 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 7 1 1\n") - 1u, 0, 0, 0, "" },
};

static void case_stat_rows(void)
{
	unsigned i;

	printf("\nstat parsing (a table; each row is one fake /proc/100/stat):\n");
	for (i = 0; i < sizeof stat_rows / sizeof stat_rows[0]; i++) {
		const struct stat_row *r = &stat_rows[i];
		struct kofa_plist_option o = opt_min();
		struct seen *s;
		char w[200];

		fresh();
		(void)osys_put(R, 100, "stat", r->raw, r->len);
		put_s(100, "maps", "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n");
		walk(&o, NULL);
		s = find(100);
		snprintf(w, sizeof w, "stat row '%s': listed == %d", r->id, r->listed);
		ok((s != NULL) == r->listed, w);
		if (s && r->listed) {
			snprintf(w, sizeof w, "stat row '%s': ppid %u", r->id, r->ppid);
			ok(s->ppid == r->ppid, w);
			snprintf(w, sizeof w, "stat row '%s': starttime", r->id);
			ok(s->start == r->start, w);
			snprintf(w, sizeof w, "stat row '%s': comm '%s'", r->id, r->comm);
			ok(strcmp(s->comm, r->comm) == 0, w);
		}
	}
}

static void case_comm_cap(void)
{
	char comm[300], w[100];
	struct kofa_plist_option o = opt_min();
	struct seen *s;
	size_t i;

	printf("\ncomm longer than the 64-byte field:\n");
	for (i = 0; i < sizeof comm - 1; i++)
		comm[i] = (char)('a' + i % 26);
	comm[sizeof comm - 1] = '\0';
	fresh();
	put_stat(100, comm, 1, 0, 5);
	walk(&o, NULL);
	s = find(100);
	ok(s != NULL, "a 299-byte comm still lists the process");
	snprintf(w, sizeof w, "comm cut to 63 bytes + NUL (got %zu)", s ? strlen(s->comm) : 0);
	ok(s && strlen(s->comm) == 63 && !memcmp(s->comm, comm, 63), w);
}

static void case_stat_window(void)
{
	/* the walk reads at most 2047 bytes of stat: a ')' that only exists past that is "no ')'" */
	char *b = malloc(5000);
	struct kofa_plist_option o = opt_min();

	printf("\nstat longer than the read window:\n");
	fresh();
	memset(b, 'x', 5000);
	memcpy(b, "100 (", 5);
	memcpy(b + 3000, ") S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1\n", 49);
	(void)osys_put(R, 100, "stat", b, 3049);
	put_s(100, "maps", "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n");
	walk(&o, NULL);
	ok(find(100) == NULL, "a ')' past byte 2047 is not seen: the process is dropped, not mis-parsed");
	free(b);
}

static void case_pid_names(void)
{
	static const char *const names[] = { "abc", "0", "12x", "-5", "+7", " 9", "", "self", "thread-self", "1e3" };
	struct kofa_plist_option o = opt_min();
	unsigned i;
	char b[8192];

	printf("\ndirectory names that are not pids:\n");
	fresh();
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		char rel[64];

		if (!names[i][0])
			continue;
		mkstat(b, sizeof b, 1, "x", 1, 0, 1);
		snprintf(rel, sizeof rel, "../%s/stat", names[i]);
		/* put below the root through the flat writer */
		snprintf(rel, sizeof rel, "%s/stat", names[i]);
		(void)osys_put_flat(R, rel, b, strlen(b));
	}
	put_stat(321, "ok", 1, 0, 9);
	walk(&o, NULL);
	ok(n_got == 1 && got[0].pid == 321, "only the numeric directory is a process");
}

static void case_only_pid(void)
{
	struct kofa_plist_option o = opt_min();

	printf("\nonly_pid, kernel threads, refused:\n");
	fresh();
	put_stat(100, "a", 1, 0, 5);
	put_stat(200, "b", 1, 0, 6);
	put_stat(300, "kworker", 2, 0x00200000u, 7);
	o.only_pid = 200;
	walk(&o, NULL);
	ok(n_got == 1 && got[0].pid == 200, "only_pid selects one process");
	o.only_pid = 999;
	walk(&o, NULL);
	ok(n_got == 0, "only_pid of a pid that is not there lists nothing");
	o.only_pid = 0;
	walk(&o, NULL);
	ok(n_got == 2 && !find(300), "a kernel thread is left out by default");
	o.want_kernel = 1;
	walk(&o, NULL);
	ok(n_got == 3 && find(300) && (must(300)->flags & KOFA_PF_KERNEL) && must(300)->is_kthread,
	   "want_kernel lists it with KOFA_PF_KERNEL and is_kthread");
	ok(find(300) && !must(300)->exe[0] && !must(300)->cmd[0] && !must(300)->fds_read,
	   "and reads no exe, cmdline or descriptors for it");
	/* unreadable maps = refused */
	{
		char p[300];

		snprintf(p, sizeof p, "%s/200/maps", R);
		unlink(p);
	}
	o.want_kernel = 0;
	o.want_refused = 1;
	walk(&o, NULL);
	ok(find(200) && (must(200)->flags & KOFA_PF_REFUSED), "a process whose maps cannot be read is REFUSED");
	o.want_refused = 0;
	{
		struct kofa_plist *l;
		struct kofa_proc p;
		unsigned n = 0, refused = 0;
		int e = 0;

		/* the library's own default (NULL options) lists refused; an explicit struct with want_refused = 0 drops them */
		l = kofa_plist_open(&o, &e);
		while (l && kofa_plist_next(l, &p)) {
			n++;
			refused += (p.flags & KOFA_PF_REFUSED) != 0;
		}
		kofa_plist_close(l);
		ok(refused == 0 && n == 1, "want_refused = 0 drops the refused process");
		l = kofa_plist_open(NULL, &e);
		n = refused = 0;
		while (l && kofa_plist_next(l, &p)) {
			n++;
			refused += (p.flags & KOFA_PF_REFUSED) != 0;
		}
		kofa_plist_close(l);
		ok(n == 2 && refused == 1, "NULL options list refused processes too (want_refused defaults on)");
	}
}

/* ------------------------------------------------------------------------------------------------- exe */

static void case_exe(void)
{
	char target[600], real[512];
	struct kofa_plist_option o = opt_min();
	struct seen *s;
	char longp[4096];

	printf("\nexe link:\n");
	fresh();
	snprintf(real, sizeof real, "%s/realfile", R);
	(void)osys_put_flat(R, "realfile", "x", 1);
	put_stat(100, "a", 1, 0, 1);
	(void)osys_link(R, 100, "exe", real);
	put_stat(101, "b", 1, 0, 2);
	snprintf(target, sizeof target, "%.*s (deleted)", 500, real);
	(void)osys_link(R, 101, "exe", target);
	put_stat(102, "c", 1, 0, 3);
	(void)osys_link(R, 102, "exe", "/memfd:payload (deleted)");
	put_stat(103, "d", 1, 0, 4);                                  /* no exe link at all */
	put_stat(104, "e", 1, 0, 5);
	(void)osys_link(R, 104, "exe", " (deleted)");                 /* exactly the suffix: n == 10, not > 10 */
	put_stat(105, "f", 1, 0, 6);
	(void)osys_link(R, 105, "exe", "/x (deleted)");
	put_stat(106, "g", 1, 0, 7);
	memset(longp, 'p', sizeof longp - 1);
	longp[0] = '/';
	longp[sizeof longp - 1] = '\0';
	(void)osys_link(R, 106, "exe", longp);
	put_stat(107, "h", 1, 0, 8);
	(void)osys_link(R, 107, "exe", "/memfd:x");
	walk(&o, NULL);
	s = find(100);
	ok(s && !strcmp(s->exe, real) && s->exe_on_disk && !(s->flags & KOFA_PF_EXE_GONE), "an exe on disk: path, exe_on_disk, no GONE");
	s = find(101);
	ok(s && !strcmp(s->exe, real) && (s->flags & KOFA_PF_EXE_GONE), "'(deleted)' is stripped and flagged GONE");
	ok(s && s->exe_on_disk, "and exe_on_disk is a separate fact (the stripped path still exists here)");
	s = find(102);
	ok(s && !strcmp(s->exe, "/memfd:payload") && (s->flags & KOFA_PF_EXE_MEMFD) && (s->flags & KOFA_PF_EXE_GONE),
	   "memfd: suffix stripped, MEMFD and GONE both set (the library keeps the two facts separate)");
	ok(s && !s->exe_on_disk, "a memfd path is not on disk");
	s = find(103);
	ok(s && !s->exe[0] && !s->exe_on_disk, "no exe link: empty, not on disk");
	s = find(104);
	ok(s && !strcmp(s->exe, " (deleted)") && !(s->flags & KOFA_PF_EXE_GONE), "a link that IS the suffix (10 bytes) is left alone");
	s = find(105);
	ok(s && !strcmp(s->exe, "/x") && (s->flags & KOFA_PF_EXE_GONE) && !s->exe_on_disk, "'/x (deleted)': stripped, GONE, not on disk");
	s = find(106);
	ok(s && strlen(s->exe) == 4095, "a 4095-byte link (the longest the kernel allows) fits the 4096-byte buffer whole");
	s = find(107);
	ok(s && (s->flags & KOFA_PF_EXE_MEMFD) && !(s->flags & KOFA_PF_EXE_GONE), "memfd without the suffix: MEMFD only");
}

/* ------------------------------------------------------------------------------------------------- cmdline / environ */

static void case_cmdline(void)
{
	struct kofa_plist_option o = opt_min();
	struct seen *s;
	char *big;
	static const char words[] = "/bin/sh\0-c\0echo hi\0";
	static const char binary[] = "a\0\xff\x01\xfe\0\0\0b\0";
	char path[300];
	int fd;

	printf("\ncmdline and environ:\n");
	fresh();
	put_stat(100, "a", 1, 0, 1);
	(void)osys_put(R, 100, "cmdline", words, sizeof words - 1u);
	put_stat(101, "b", 1, 0, 2);
	put_s(101, "cmdline", "no-nul-at-all");
	put_stat(102, "c", 1, 0, 3);
	(void)osys_put(R, 102, "cmdline", "\0\0\0\0\0\0\0\0", 8);
	put_stat(103, "d", 1, 0, 4);
	(void)osys_put(R, 103, "cmdline", binary, sizeof binary - 1u);
	put_stat(104, "e", 1, 0, 5);                                   /* 10 MB, sparse */
	snprintf(path, sizeof path, "%s/104/cmdline", R);
	mkdir(R, 0755);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	big = malloc(1u << 20);
	memset(big, 'A', 1u << 20);
	ok(fd >= 0 && write(fd, big, 1u << 20) == (1 << 20), "wrote 1 MiB of 'A'");
	ftruncate(fd, 10 << 20);
	close(fd);
	free(big);
	put_stat(105, "f", 1, 0, 6);
	put_s(105, "cmdline", "");
	put_stat(106, "g", 1, 0, 7);                                    /* cmdline is a directory */
	{
		char d[300];

		snprintf(d, sizeof d, "%s/106/cmdline", R);
		mkdir(d, 0755);
	}
	put_stat(107, "h", 1, 0, 8);
	(void)osys_put(R, 107, "environ", "A=1\0B=two words\0C=\0", 19);
	put_stat(108, "i", 1, 0, 9);
	(void)osys_put(R, 108, "environ", "X=1\0\0\0\0", 7);
	{
		char env[9000];

		memset(env, 'e', sizeof env);
		put_stat(109, "j", 1, 0, 10);
		(void)osys_put(R, 109, "environ", env, sizeof env);
	}
	walk(&o, NULL);
	s = find(100);
	ok(s && !strcmp(s->cmd, "/bin/sh -c echo hi"), "NULs between words become spaces, the trailing NUL is dropped");
	s = find(101);
	ok(s && !strcmp(s->cmd, "no-nul-at-all"), "a cmdline with no NUL at all comes back whole");
	s = find(102);
	ok(s && !strcmp(s->cmd, ""), "all NULs: empty");
	s = find(103);
	ok(s && !strcmp(s->cmd, "a \xff\x01\xfe   b"), "binary bytes pass through; inner NULs are spaces");
	s = find(104);
	ok(s && strlen(s->cmd) == 4095, "a 10 MB cmdline is read to the 4096-byte buffer and no further");
	s = find(105);
	ok(s && !strcmp(s->cmd, ""), "an empty cmdline file is the empty string");
	s = find(106);
	ok(s && !strcmp(s->cmd, ""), "a cmdline that is a directory (read fails) is the empty string");
	s = find(107);
	ok(s && s->environ_len == 18 && !memcmp(s->env, "A=1\0B=two words\0C=", 18), "environ keeps its NULs and carries the length (trailing NUL dropped)");
	s = find(108);
	ok(s && s->environ_len == 3, "environ: a run of trailing NULs is dropped whole");
	s = find(109);
	ok(s && s->environ_len == 8191, "environ is cut at its 8192-byte buffer");
	o.no_cmdline = 1;
	o.no_environ = 1;
	walk(&o, NULL);
	s = find(100);
	ok(s && !s->cmd[0] && s->environ_len == 0, "no_cmdline / no_environ skip both reads");
}

/* ------------------------------------------------------------------------------------------------- fds and net */

static void put_fd(uint32_t pid, const char *name, const char *target)
{
	char rel[64];

	snprintf(rel, sizeof rel, "fd/%s", name);
	(void)osys_link(R, pid, rel, target);
}

static void case_fds(void)
{
	struct kofa_plist_option o = opt_min();
	struct seen *s;
	unsigned i;
	char nm[32], tg[64];

	printf("\ndescriptors:\n");
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_fd(100, "0", "/dev/null");
	put_fd(100, "1", "pipe:[55]");
	put_fd(100, "2", "/dev/null");
	put_fd(100, "3", "socket:[1001]");
	put_fd(100, "4", "socket:[1002]");
	put_fd(100, "5", "/dev/null");
	put_fd(100, "x", "/dev/null");                  /* not a number: not counted */
	put_fd(100, "7y", "/dev/null");                 /* starts with a digit: counted (isdigit on the first byte) */
	put_stat(101, "b", 1, 0, 2);                    /* no fd directory at all */
	put_stat(102, "c", 1, 0, 3);                    /* 300 sockets: the inode list is capped at 256 */
	for (i = 0; i < 300; i++) {
		snprintf(nm, sizeof nm, "%u", 3 + i);
		snprintf(tg, sizeof tg, "socket:[%u]", 5000 + i);
		put_fd(102, nm, tg);
	}
	put_stat(103, "d", 1, 0, 4);                    /* a link target longer than the 256-byte slot */
	{
		char longt[600];

		memset(longt, 't', sizeof longt - 1);
		longt[sizeof longt - 1] = '\0';
		longt[0] = '/';
		put_fd(103, "0", longt);
		put_fd(103, "1", "socket:[bad]");
		put_fd(103, "2", "socket:[]");
	}
	walk(&o, NULL);
	s = find(100);
	ok(s && s->fds_read && !strcmp(s->fd0, "/dev/null") && !strcmp(s->fd1, "pipe:[55]") && !strcmp(s->fd2, "/dev/null"),
	   "stdio is read by name");
	ok(s && s->n_fd == 7 && s->n_socket == 2, "7 numeric names counted (including '7y'), 2 sockets");
	ok(s && s->n_like_stdin == 4, "descriptors whose link text equals fd 0's: 0, 2, 5 and '7y' (fd 0 counts itself)");
	s = find(101);
	ok(s && !s->fds_read && s->n_fd == 0 && !s->fd0[0], "no fd directory: fds_read is 0, counts zero");
	s = find(102);
	ok(s && s->n_fd == 300 && s->n_socket == 300, "300 sockets are all COUNTED (the cap is on the join list only)");
	s = find(103);
	ok(s && strlen(s->fd0) == 255, "a 599-byte link target is cut to the 256-byte slot (255 + NUL)");
	ok(s && s->n_socket == 2, "'socket:[bad]' and 'socket:[]' still count as sockets (prefix match)");
	o.no_fds = 1;
	walk(&o, NULL);
	s = find(100);
	ok(s && !s->fds_read && s->n_fd == 0, "no_fds skips the walk");
}

static void case_fds_many(void)
{
	struct kofa_plist_option o = opt_min();
	struct seen *s;
	unsigned i;
	char nm[32];

	printf("\n20000 descriptors in one process:\n");
	fresh();
	put_stat(100, "a", 1, 0, 1);
	for (i = 0; i < 20000; i++) {
		snprintf(nm, sizeof nm, "%u", i);
		put_fd(100, nm, "/dev/null");
	}
	walk(&o, NULL);
	s = find(100);
	ok(s && s->n_fd == 20000 && s->n_like_stdin == 20000, "all 20000 counted, every one is like stdin");
}

static void put_net(uint32_t pid, const char *table, const char *text) { char rel[64]; snprintf(rel, sizeof rel, "net/%s", table); put_s(pid, rel, text); }

static void case_net(void)
{
	static const char hdr[] = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
	struct kofa_plist_option o;
	struct seen *s;
	char big[20000];
	unsigned i;
	size_t at;

	printf("\n/proc/<pid>/net joined on the inode:\n");
	memset(&o, 0, sizeof o);
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_fd(100, "3", "socket:[1001]");
	put_fd(100, "4", "socket:[1002]");
	put_fd(100, "5", "socket:[1003]");
	put_fd(100, "6", "socket:[1004]");
	{
		char t[2048];

		snprintf(t, sizeof t, "%s"
			 "   0: 0100007F:1F90 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0000000000000000 100 0 0 10 0\n"
			 "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0\n"
			 "   2: garbage line that is not a socket row\n"
			 "   3: 0100007F:1F91 0200A8C0:01BC 0B 00000000:00000000 00:00000000 00000000  1000        0 0 1 0000000000000000 100 0 0 10 0\n"
			 "   4: 0100007F:1F92 0200A8C0:01BD 0C 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 100 0 0 10 0\n",
			 hdr);
		put_net(100, "tcp", t);
		snprintf(t, sizeof t, "%s"
			 "   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1003 2 0000000000000000 0\n", hdr);
		put_net(100, "udp", t);
		snprintf(t, sizeof t, "%s"
			 "   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1004 1 0000000000000000 100 0 0 10 0\n", hdr);
		put_net(100, "tcp6", t);
	}
	walk(&o, NULL);
	s = find(100);
	ok(s && strstr(s->net, "TCP 127.0.0.1:8080 -> 192.168.0.2:443 ESTABLISHED\n"), "a tcp row whose inode is one of the process's sockets is listed with its state");
	ok(s && !strstr(s->net, ":22 "), "a row of another process's socket (inode 9999) is not");
	ok(s && strstr(s->net, "TCP 127.0.0.1:8082 -> 192.168.0.2:445 ?\n"), "a state number outside the table is '?'");
	ok(s && strstr(s->net, "UDP 127.0.0.1:53 -> 0.0.0.0:0 \n"), "a udp row has an empty state");
	ok(s && strstr(s->net, "TCP6 0000:0000:0000:0000:0000:0000:0000:0001:80 -> ") != NULL,
	   "a tcp6 row is listed with eight 16-bit groups, each 32-bit word little-endian");
	ok(s && !strstr(s->net, "8081"), "a row with inode 0 is skipped");
	/* a huge, hostile table: more rows than the 4096-byte output holds */
	fresh();
	put_stat(100, "a", 1, 0, 1);
	for (i = 0; i < 256; i++) {
		char nm[16], tg[32];

		snprintf(nm, sizeof nm, "%u", 3 + i);
		snprintf(tg, sizeof tg, "socket:[%u]", 70000 + i);
		put_fd(100, nm, tg);
	}
	at = (size_t)snprintf(big, sizeof big, "%s", hdr);
	for (i = 0; i < 256 && at + 200 < sizeof big; i++)
		at += (size_t)snprintf(big + at, sizeof big - at,
				       "%4u: 0100007F:%04X 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 %u 1 0000000000000000 100 0 0 10 0\n",
				       i, 1000 + i, 70000 + i);
	put_net(100, "tcp", big);
	walk(&o, NULL);
	s = find(100);
	ok(s && strlen(s->net) < 4096 && strlen(s->net) > 3000, "256 matching rows fill the 4096-byte buffer and stop at a whole line");
	ok(s && s->net[strlen(s->net) - 1] == '\n', "the last line kept is whole");
	/* lines over the 512-byte fgets window */
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_fd(100, "3", "socket:[1001]");
	{
		char l[1500];
		int n = snprintf(l, sizeof l, "%s   0: 0100007F:1F90 0200A8C0:01BB 01 ", hdr);

		memset(l + n, ' ', 900);
		n += 900;
		n += snprintf(l + n, sizeof l - (size_t)n, "0 1001\n");
		put_net(100, "tcp", l);
	}
	walk(&o, NULL);
	s = find(100);
	ok(s != NULL, "a row longer than the read window does not break the walk (it is split into fragments)");
	/* net table that is a directory / missing */
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_fd(100, "3", "socket:[1001]");
	walk(&o, NULL);
	s = find(100);
	ok(s && !s->net[0], "no net tables: an empty string, not NULL");
	/* short addresses on the v6 path: the library reads 32 hex digits whatever the row says */
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_fd(100, "3", "socket:[1001]");
	put_net(100, "tcp6", "hdr\n   0: 0100:1F90 0200:01BB 0A 00000000:00000000 00:00000000 00000000  1000        0 1001 1 0\n");
	walk(&o, NULL);
	s = find(100);
	ok(s != NULL, "a tcp6 row with 4-digit addresses is accepted without a crash (WP12-2: it is formatted from stack bytes past the digits)");
}

/* ------------------------------------------------------------------------------------------------- errors */

static void case_errors(void)
{
	struct kofa_plist_option o = opt_min();
	struct kofa_plist *l;
	int err = 0;
	static const int errs[] = { EMFILE, ENFILE, EINTR, ENOMEM, EIO };
	unsigned i;

	printf("\nfailing calls: what the walk makes of them:\n");
	fresh();
	put_stat(100, "a", 1, 0, 1);
	put_stat(200, "b", 1, 0, 2);
	osys_fail(OSYS_OPENDIR, 1, EMFILE);
	l = kofa_plist_open(&o, &err);
	ok(l == NULL && err == KOFA_ERR_OS, "opendir(/proc) failing is KOFA_ERR_OS and no list");
	osys_reset();
	osys_proc_root(R);
	for (i = 0; i < sizeof errs / sizeof errs[0]; i++) {
		char w[160];
		unsigned long total;

		osys_match("/stat");
		osys_fail(OSYS_OPEN, 1, errs[i]);
		walk(&o, NULL);
		total = n_got;
		snprintf(w, sizeof w, "a transient open() failure (%s) on one stat: both processes are still listed, the failed one as REFUSED (WP12-1)", strerror(errs[i]));
		ok(total == 2, w);
		{
			unsigned refused = 0, k;

			for (k = 0; k < n_got; k++)
				refused += (got[k].flags & KOFA_PF_REFUSED) != 0;
			snprintf(w, sizeof w, "open() failure (%s) on one stat: exactly one process carries KOFA_PF_REFUSED (it was not looked at), %u do", strerror(errs[i]), refused);
			ok(refused == 1, w);
		}
		/* the status itself: a resource error is KOFA_ERR_OS, never GONE */
		osys_reset();
		osys_proc_root(R);
		osys_match("/stat");
		osys_fail(OSYS_OPEN, 1, errs[i]);
		{
			int perr = -1;
			struct kofa_pmem *pm = kofa_pmem_open(100, 0, NULL, &perr);

			snprintf(w, sizeof w, "kofa_pmem_open with open() of stat failing (%s) is KOFA_ERR_OS, not GONE (got %s)", strerror(errs[i]), kofa_err_name(perr));
			ok(pm == NULL && perr == KOFA_ERR_OS, w);
			kofa_pmem_close(pm);
		}
		osys_reset();
		osys_proc_root(R);
	}
	/* the control: a process that really left (ENOENT, ESRCH) stays GONE and is dropped without a trace */
	{
		static const int left[] = { ENOENT, ESRCH };

		for (i = 0; i < 2; i++) {
			int perr = -1;
			struct kofa_pmem *pm;

			osys_match("/stat");
			osys_fail(OSYS_OPEN, 1, left[i]);
			walk(&o, NULL);
			OKF(n_got == 1 && !((got[0].flags) & KOFA_PF_REFUSED), "open() of stat failing with %s: the process is gone and dropped (%lu listed)", strerror(left[i]), (unsigned long)n_got);
			osys_reset();
			osys_proc_root(R);
			osys_match("/stat");
			osys_fail(OSYS_OPEN, 1, left[i]);
			pm = kofa_pmem_open(100, 0, NULL, &perr);
			OKF(pm == NULL && perr == KOFA_ERR_GONE, "kofa_pmem_open with stat failing with %s is KOFA_ERR_GONE (got %s)", strerror(left[i]), kofa_err_name(perr));
			kofa_pmem_close(pm);
			osys_reset();
			osys_proc_root(R);
		}
	}
	/* EACCES on stat: refused when asked */
	o.want_refused = 1;
	osys_match("/stat");
	osys_fail(OSYS_OPEN, 1, EACCES);
	walk(&o, NULL);
	ok(n_got == 2 && ((got[0].flags | got[1].flags) & KOFA_PF_REFUSED), "EACCES on stat: the process is listed as REFUSED");
	osys_reset();
	osys_proc_root(R);
	osys_match("/stat");
	osys_fail(OSYS_OPEN, 1, EACCES);
	o.want_refused = 0;
	walk(&o, NULL);
	ok(n_got == 1, "EACCES on stat with want_refused = 0: dropped");
	osys_reset();
	/* NULL arguments */
	ok(kofa_plist_next(NULL, NULL) == 0, "kofa_plist_next(NULL, NULL) is 0");
	kofa_plist_close(NULL);
	ok(strcmp(kofa_err_name(KOFA_OK), "ok") == 0 && strcmp(kofa_err_name(KOFA_ERR_GONE), "gone") == 0 &&
	   strcmp(kofa_err_name(KOFA_ERR_DENIED), "denied") == 0 && strcmp(kofa_err_name(KOFA_ERR_NOMEM), "nomem") == 0 &&
	   strcmp(kofa_err_name(KOFA_ERR_UNSUPPORTED), "unsupported") == 0 && strcmp(kofa_err_name(KOFA_ERR_OS), "os") == 0 &&
	   strcmp(kofa_err_name(-1), "?") == 0 && strcmp(kofa_err_name(99), "?") == 0, "kofa_err_name names every code and answers '?' otherwise");
}

/* ------------------------------------------------------------------------------------------------- process exits mid-walk */

static void case_race(void)
{
	/* The directory is listed, then a process's files go away before the walk reads them: every file of the three
	 * read stages is removed in turn, one process each. The walk must list the others and never crash. */
	static const char *const gone[] = { "stat", "maps", "exe", "cmdline", "environ", "fd/0" };
	struct kofa_plist_option o = opt_min();
	unsigned i;

	o.want_refused = 1;
	printf("\na process that exits between readdir and the reads:\n");
	for (i = 0; i < sizeof gone / sizeof gone[0]; i++) {
		char p[400], w[120];
		uint32_t pid = 100 + i;

		fresh();
		put_stat(500, "stay", 1, 0, 1);
		put_stat(pid, "go", 1, 0, 2);
		(void)osys_link(R, pid, "exe", "/bin/true");
		put_s(pid, "cmdline", "x");
		put_s(pid, "environ", "A=1");
		put_fd(pid, "0", "/dev/null");
		snprintf(p, sizeof p, "%s/%u/%s", R, (unsigned)pid, gone[i]);
		(void)unlink(p);
		walk(&o, NULL);
		snprintf(w, sizeof w, "'%s' removed: the other process is still listed", gone[i]);
		ok(find(500) != NULL, w);
		snprintf(w, sizeof w, "'%s' removed: the half-gone process is %s", gone[i],
		       i == 0 ? "dropped (no stat)" : i == 1 ? "listed as REFUSED (maps unreadable)" : "listed with the rest empty");
		if (i == 0)
			ok(find(pid) == NULL, w);
		else if (i == 1)
			ok(find(pid) && (must(pid)->flags & KOFA_PF_REFUSED), w);
		else
			ok(find(pid) != NULL, w);
	}
	/* the whole directory removed after being opened */
	fresh();
	put_stat(100, "a", 1, 0, 1);
	{
		struct kofa_plist *l = kofa_plist_open(&o, NULL);
		struct kofa_proc p;

		osys_rmrf(R);
		ok(l && kofa_plist_next(l, &p) == 0, "the /proc directory removed after open: the next call ends the walk");
		kofa_plist_close(l);
	}
}

/* ------------------------------------------------------------------------------------------------- 10^5 pids */

static void case_many_pids(void)
{
	/* 20000 process directories: the walk is streaming (one process per call) and must not grow with the count. */
	struct kofa_plist_option o = opt_min();
	struct kofa_plist *l;
	struct kofa_proc p;
	unsigned i, n = 0;
	char b[8192], rel[64];

	printf("\n20000 processes:\n");
	fresh();
	o.no_fds = 1;
	o.no_cmdline = 1;
	o.no_environ = 1;
	mkstat(b, sizeof b, 1, "x", 1, 0, 1);
	for (i = 1; i <= 20000; i++) {
		snprintf(rel, sizeof rel, "%u/stat", i);
		(void)osys_put_flat(R, rel, b, strlen(b));
	}
	l = kofa_plist_open(&o, NULL);
	while (l && kofa_plist_next(l, &p))
		n++;
	kofa_plist_close(l);
	/* maps is absent for all of them: want_refused (the struct has it 0) drops them; with the default list they are all there */
	ok(n == 0, "20000 directories without maps: all refused, and want_refused = 0 drops them");
	o.want_refused = 1;
	l = kofa_plist_open(&o, NULL);
	n = 0;
	while (l && kofa_plist_next(l, &p))
		n++;
	kofa_plist_close(l);
	ok(n == 20000, "with want_refused = 1 all 20000 are listed, once each");
}

/* ------------------------------------------------------------------------------------------------- concurrent walkers */

#include <pthread.h>

struct wk {
	uint64_t digest;
	unsigned n;
};

static void *walker(void *a)
{
	struct wk *w = a;
	struct kofa_plist_option o = opt_min();
	struct kofa_plist *l;
	struct kofa_proc p;
	unsigned rep;

	w->digest = 0;
	w->n = 0;
	o.want_refused = 1;
	for (rep = 0; rep < 20; rep++) {
		l = kofa_plist_open(&o, NULL);
		while (l && kofa_plist_next(l, &p)) {
			w->digest += ((uint64_t)p.pid * 1000003u) ^ ((uint64_t)p.ppid << 20) ^ p.start_time ^ ((uint64_t)strlen(p.cmdline) << 40) ^ ((uint64_t)p.n_fd << 50);
			w->n++;
		}
		kofa_plist_close(l);
	}
	return NULL;
}

static void case_threads(void)
{
	enum { T = 8 };
	pthread_t th[T];
	struct wk w[T];
	unsigned i;
	char b[8192], cmd[40];

	printf("\n%d walkers at once over 300 fake processes (20 walks each): one answer:\n", T);
	fresh();
	for (i = 1; i <= 300; i++) {
		snprintf(cmd, sizeof cmd, "prog-%u", i);
		mkstat(b, sizeof b, i, "p", i % 7u, 0, 1000u + i);
		put_s(i, "stat", b);
		put_s(i, "maps", "00400000-00401000 r-xp 00000000 08:01 7 /bin/x\n");
		(void)osys_put(R, i, "cmdline", cmd, strlen(cmd) + 1u);
		put_fd(i, "0", "/dev/null");
	}
	for (i = 0; i < T; i++)
		pthread_create(&th[i], NULL, walker, &w[i]);
	for (i = 0; i < T; i++)
		pthread_join(th[i], NULL);
	{
		unsigned same = 0;

		for (i = 0; i < T; i++)
			same += w[i].digest == w[0].digest && w[i].n == w[0].n;
		OKF(same == T && w[0].n == 20u * 300u, "all %d walkers listed 20 x 300 processes and agree on every field (%u agree, %u listed)", T, same, w[0].n);
	}
}

/* ------------------------------------------------------------------------------------------------- fd exhaustion on the real /proc */

static void case_fd_limit(void)
{
	pid_t kid;
	int st = 0, pp[2];

	printf("\nRLIMIT_NOFILE exhausted, REAL /proc (child process):\n");
	osys_reset();
	if (pipe(pp))
		return;
	kid = fork();
	if (kid == 0) {
		struct rlimit rl;
		struct kofa_plist_option o = opt_min();
		struct kofa_plist *l;
		struct kofa_proc p;
		unsigned n_ok = 0, n_total = 0;
		int e = 0, fd, lowest = 0;
		char buf[96];
		int n;

		close(pp[0]);
		l = kofa_plist_open(&o, &e);               /* the baseline: an unconstrained walk */
		while (l && kofa_plist_next(l, &p))
			n_total++;
		kofa_plist_close(l);
		for (fd = 0; fd < 1024; fd++)               /* leave exactly one descriptor: opendir(/proc) takes it, every open() after is EMFILE */
			if (fcntl(fd, F_GETFD) < 0) {
				lowest = fd;
				break;
			}
		getrlimit(RLIMIT_NOFILE, &rl);
		rl.rlim_cur = (rlim_t)lowest + 1;
		setrlimit(RLIMIT_NOFILE, &rl);
		l = kofa_plist_open(&o, &e);
		if (l) {
			while (kofa_plist_next(l, &p))
				n_ok++;
			kofa_plist_close(l);
		}
		n = snprintf(buf, sizeof buf, "%u %u %d\n", n_total, n_ok, e);
		(void)write(pp[1], buf, (size_t)n);
		_exit(0);
	}
	close(pp[1]);
	{
		char buf[96] = "";
		unsigned tot = 0, okn = 0;
		int e = 0;
		ssize_t r = read(pp[0], buf, sizeof buf - 1);

		waitpid(kid, &st, 0);
		if (r > 0 && sscanf(buf, "%u %u %d", &tot, &okn, &e) == 3) {
			char w[200];

			printf("       baseline %u processes; with no descriptor left %u are listed (open error %d)\n", tot, okn, e);
			snprintf(w, sizeof w, "no free descriptor: the walk still lists the processes it could not read (%u of %u listed)", okn, tot);
			ok(okn >= tot / 2 || tot < 4, w);
		} else
			ok(0, "the fd-limit child reported");
	}
	close(pp[0]);
}

int main(void)
{
	R = osys_tmpdir("orbit_plist");
	if (!R) {
		printf("cannot make the scratch directory\n");
		return 1;
	}
	case_stat_rows();
	case_comm_cap();
	case_stat_window();
	case_pid_names();
	case_only_pid();
	case_exe();
	case_cmdline();
	case_fds();
	case_fds_many();
	case_net();
	case_errors();
	case_race();
	case_many_pids();
	case_threads();
	osys_proc_root(NULL);
	case_fd_limit();
	osys_reset();
	osys_rmrf(R);
	free(R);
	printf("\n%d check(s), %d failed; known misses %u\n", checks, fails, km_known_n);
	return (fails || km_fixed_n) ? 1 : 0;
}
