/* SPDX-License-Identifier: Apache-2.0 */
/* See aproc.h. */

#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "aproc.h"
#include "apagemap.h"

#define APATH_MAX 4096

/* PF_KTHREAD, from the kernel's sched.h. Field 9 of /proc/<pid>/stat. */
#define A_PF_KTHREAD 0x00200000u

/*
 * How many runs a region's pagemap scan records before it stops recording and
 * only counts. 256 covers every region measured on a real desktop - the worst
 * observed was 30 runs in a 64 MB V8 mapping - and costs 4 KB in the handle.
 */
#define A_RUNS_CACHED 256

/* Pagemap entries read per pread. 4096 entries is 32 KB and covers 16 MB of
 * address space per syscall, so a 512 MB region costs 32 reads rather than one
 * 1 MB allocation. */
#define A_PM_BATCH 4096

/* Defaults for kofa_pmem_option, all reasoned in aproc.h. */
#define A_DEF_MAX_REGION      (1ULL << 31)   /* 2 GB  */
#define A_DEF_MAX_HEAP_REGION (1ULL << 20)   /* 1 MB  */
#define A_DEF_MAX_BYTES       (256ULL << 20) /* 256 MB per process */

/*
 * The largest piece handed over at once. A resident run can be hundreds of
 * megabytes; 1 MB is large enough that the per-chunk overhead disappears
 * against the copy and small enough that the handle's buffer is not a thing a
 * caller has to think about.
 */
#define A_DEF_CHUNK_MAX       (1ULL << 20)
/*
 * BELOW THIS, READ BLIND. Measured rather than reasoned, which it was not
 * before: the value here was 1 MB on the argument that "one pread costs more
 * than reading the region", with no number behind it.
 *
 * The measurement is the WORST CASE for pagemap - a fully resident region,
 * where it saves nothing and is pure overhead - so the crossing point it finds
 * is the safe one. Times are per call, averaged over 200:
 *
 *      region     blind      guided    guided/blind
 *        4 KB     2.4 us      4.6 us      0.52x   blind wins
 *       16 KB     4.5 us      7.7 us      0.59x   blind wins
 *       64 KB    15.6 us     18.8 us      0.83x   blind wins
 *      256 KB    63.7 us     48.8 us      1.30x   pagemap wins
 *        1 MB    63.7 us     51.1 us      1.25x   pagemap wins
 *        4 MB   161.0 us    157.0 us      1.03x   even
 *       16 MB   1314 us     1326 us       0.99x   even
 *
 * So the crossing is between 64 KB and 256 KB, and 1 MB was turning pagemap
 * OFF across a range where it already paid - while a SPARSE region of that
 * size is exactly where it pays most: the same walk over real V8 mappings
 * measured 37x to 887x, because there the guided read skips almost everything.
 *
 * 64 KB, then: the last size at which reading blind is measurably cheaper even
 * when pagemap can save nothing at all.
 */
#define A_DEF_PAGEMAP_MIN     (64ULL << 10)   /* 64 KB */

/* ------------------------------------------------------------------ names */

const char *kofa_err_name(int err)
{
	switch (err) {
	case KOFA_OK:              return "ok";
	case KOFA_ERR_GONE:        return "gone";
	case KOFA_ERR_DENIED:      return "denied";
	case KOFA_ERR_NOMEM:       return "nomem";
	case KOFA_ERR_UNSUPPORTED: return "unsupported";
	case KOFA_ERR_OS:          return "os";
	default:                   return "?";
	}
}

const char *kofa_rgn_use_name(uint8_t use)
{
	switch (use) {
	case KOFA_USE_IMAGE: return "image";
	case KOFA_USE_CODE:  return "code";
	case KOFA_USE_HEAP:  return "heap";
	case KOFA_USE_STACK: return "stack";
	case KOFA_USE_DATA:  return "data";
	default:             return "?";
	}
}

size_t kofa_region_describe(const struct kofa_region *r, char *buf, size_t cap)
{
	char prot[5];
	int n;

	if (!buf || !cap)
		return 0;
	if (!r) {
		buf[0] = '\0';
		return 0;
	}

	prot[0] = (r->flags & KOFA_RGF_READ)  ? 'r' : '-';
	prot[1] = (r->flags & KOFA_RGF_WRITE) ? 'w' : '-';
	prot[2] = (r->flags & KOFA_RGF_EXEC)  ? 'x' : '-';
	prot[3] = 'p';
	prot[4] = '\0';

	n = snprintf(buf, cap, "%016llx %8lluK res %7lluK%s %s %-5s%s%s%s%s%s%s%s%s%s",
		     (unsigned long long)r->base,
		     (unsigned long long)(r->size >> 10),
		     (unsigned long long)(r->rss >> 10),
		     (r->flags & KOFA_RGF_RSS_MEASURED) ? " " : "?",
		     prot, kofa_rgn_use_name(r->use),
		     (r->flags & KOFA_RGF_UNBACKED)   ? " unbacked" : "",
		     (r->flags & KOFA_RGF_DELETED)    ? " deleted"  : "",
		     (r->flags & KOFA_RGF_MEMFD)      ? " memfd"    : "",
		     (r->flags & KOFA_RGF_WX)         ? " wx"       : "",
		     (r->flags & KOFA_RGF_UNEXAMINED) ? " skipped"  : "",
		     (r->flags & KOFA_RGF_ZERO_HEAVY) ? " zeroes"   : "",
		     (r->flags & KOFA_RGF_DIRTY_CODE) ? " DIRTY"    : "",
		     (r->path && r->path[0]) ? " " : "",
		     (r->path && r->path[0]) ? r->path : "");

	if (n < 0)
		return 0;
	return ((size_t)n >= cap) ? cap - 1 : (size_t)n;
}

/* -------------------------------------------------------------- /proc/stat */

/*
 * Parse the fields this library wants out of /proc/<pid>/stat.
 *
 * THE COMM FIELD IS WHY THIS IS NOT A scanf. It is the executable's name in
 * parentheses, it is not escaped, and it may contain both spaces and
 * parentheses - a process can be called "foo) 1 2 3 (bar". Every parser that
 * splits on whitespace gets a wrong ppid for those, and only for those, which
 * is the kind of bug that survives for years. The only correct split is at the
 * LAST ')' in the line.
 */
struct a_stat {
	uint32_t ppid;
	uint32_t flags;
	uint64_t start_time;
	char     comm[64];
};

static int a_read_stat(uint32_t pid, struct a_stat *out)
{
	char path[64], buf[2048], *close_paren, *p;
	int fd;
	ssize_t got;
	int field;

	snprintf(path, sizeof path, "/proc/%u/stat", (unsigned)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno == EACCES) ? KOFA_ERR_DENIED : KOFA_ERR_GONE;

	got = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (got <= 0)
		return KOFA_ERR_GONE;
	buf[got] = '\0';

	close_paren = strrchr(buf, ')');
	if (!close_paren)
		return KOFA_ERR_OS;

	/* comm, between the first '(' and that last ')'. */
	p = strchr(buf, '(');
	if (p && p < close_paren) {
		size_t n = (size_t)(close_paren - p - 1);

		if (n >= sizeof out->comm)
			n = sizeof out->comm - 1;
		memcpy(out->comm, p + 1, n);
		out->comm[n] = '\0';
	} else {
		out->comm[0] = '\0';
	}

	/*
	 * After the ')' the fields are, numbered as procfs numbers them:
	 * 3 state, 4 ppid, ... 9 flags, ... 22 starttime. So counting tokens
	 * from zero after the paren, ppid is 1, flags is 6 and starttime is 19.
	 */
	out->ppid = 0;
	out->flags = 0;
	out->start_time = 0;

	p = close_paren + 1;
	for (field = 0; field <= 19; field++) {
		char *end;
		unsigned long long v;

		while (*p == ' ')
			p++;
		if (!*p)
			return KOFA_ERR_OS;

		if (field == 0) {   /* state, not a number */
			while (*p && *p != ' ')
				p++;
			continue;
		}

		v = strtoull(p, &end, 10);
		if (end == p)
			return KOFA_ERR_OS;
		p = end;

		if (field == 1)
			out->ppid = (uint32_t)v;
		else if (field == 6)
			out->flags = (uint32_t)v;
		else if (field == 19)
			out->start_time = (uint64_t)v;
	}

	return KOFA_OK;
}

/*
 * readlink /proc/<pid>/exe into `buf`, stripping a " (deleted)" suffix and
 * reporting what it meant in *flags.
 *
 * The suffix is stripped HERE, once, because a path ending in " (deleted)" is
 * not a path anything can open, and a caller that has to notice a magic suffix
 * before using a string is a caller that will one day forget. A memfd path is
 * left alone: it is not a filesystem path at all and there is nothing to
 * recover by trimming it.
 */
static void a_read_exe(uint32_t pid, char *buf, size_t cap, uint32_t *flags)
{
	char path[64];
	ssize_t n;

	buf[0] = '\0';
	snprintf(path, sizeof path, "/proc/%u/exe", (unsigned)pid);

	n = readlink(path, buf, cap - 1);
	if (n <= 0) {
		buf[0] = '\0';
		return;
	}
	buf[n] = '\0';

	if (n > 10 && !strcmp(buf + n - 10, " (deleted)")) {
		buf[n - 10] = '\0';
		*flags |= KOFA_PF_EXE_GONE;
	}
	if (!strncmp(buf, "/memfd:", 7))
		*flags |= KOFA_PF_EXE_MEMFD;
}

/*
 * /proc/<pid>/cmdline into `buf`, NULs turned into spaces.
 *
 * The file is a run of NUL-terminated arguments with a trailing NUL, and it is
 * EMPTY for a kernel thread and for a zombie - which is a fact about the
 * process, not a failure, so "" is the honest answer and not an error.
 */
/*
 * /proc/<pid>/<what> into `buf`, NULs turned into spaces.
 *
 * ONE READER FOR cmdline AND environ, because the two files have exactly the
 * same shape - a run of NUL-terminated strings with a trailing NUL - the same
 * permission, and the same "" for a kernel thread or a zombie, which is a fact
 * about the process and not a failure. Two copies of this walk would be two
 * chances to disagree about the trailing NUL.
 */
static void a_read_nul_list(uint32_t pid, const char *what, char *buf,
			    size_t cap)
{
	char path[64];
	int fd;
	ssize_t got;
	size_t i;

	buf[0] = '\0';
	snprintf(path, sizeof path, "/proc/%u/%s", (unsigned)pid, what);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;

	got = read(fd, buf, cap - 1);
	close(fd);
	if (got <= 0) {
		buf[0] = '\0';
		return;
	}

	/*
	 * The trailing NUL is a terminator and not a separator, so turning it
	 * into a space too leaves every command line ending in one - which
	 * then shows up in every comparison a caller writes.
	 */
	while (got > 0 && buf[got - 1] == '\0')
		got--;

	for (i = 0; i < (size_t)got; i++)
		if (buf[i] == '\0')
			buf[i] = ' ';
	buf[got] = '\0';
}

static void a_read_cmdline(uint32_t pid, char *buf, size_t cap)
{
	a_read_nul_list(pid, "cmdline", buf, cap);
}

static void a_read_environ(uint32_t pid, char *buf, size_t cap)
{
	a_read_nul_list(pid, "environ", buf, cap);
}

/*
 * Count the process's file descriptors and record what its stdio points at.
 *
 * DECIDES NOTHING. It reads the three links that carry meaning, counts the
 * table, and counts how many entries name the same object as fd 0 - that last
 * one only because nothing outside this walk can see fd 7 or fd 255, so a rule
 * could not compute it for itself.
 *
 * stdin, stdout and stderr are read by NAME rather than picked out of the
 * directory walk, because a process with four thousand descriptors would
 * otherwise decide how long this takes before the three that matter are even
 * looked at.
 */
/* How many socket inodes one process's connection list may join on. A process
 * with more sockets than this has more rows than anybody reads, and the count
 * in n_socket still tells the truth about how many there were. */
#define A_NET_MAX_SOCK 256u

/*
 * THE PROCESS'S OWN CONNECTIONS, as text, one per line:
 *
 *     TCP 10.0.0.5:54321 -> 93.184.216.34:443 ESTABLISHED
 *
 * READ FROM /proc/<pid>/net AND NOT FROM /proc/net, and that is correctness
 * rather than tidiness: those tables are per NETWORK NAMESPACE, so a process
 * in a container joined against the host's table matches nothing, or worse
 * matches an unrelated socket that happens to share an inode number. The
 * per-pid path is the same file seen through that process's namespace.
 *
 * ONE PASS PER TABLE, JOINED ON THE INODE. The descriptor walk has already
 * collected this process's socket inodes - it was counting them anyway - so
 * the cost here is four sequential reads and a linear probe per row, not a
 * read per socket. A read per socket is the quadratic version and is the one
 * mistake worth naming.
 */
static int a_sock_known(const uint64_t *ino, uint32_t n, uint64_t want)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (ino[i] == want)
			return 1;
	return 0;
}

/* "0100007F:1F90" - the address is hex, in the byte order the kernel writes
 * it, which for v4 is one little-endian word. */
static void a_net_addr(const char *hex, char *out, size_t cap, int v6)
{
	unsigned b[16];
	unsigned i, n = v6 ? 16u : 4u;

	for (i = 0; i < n; i++) {
		unsigned hi, lo;
		char c;

		c = hex[i * 2u];
		hi = (unsigned)(c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
		c = hex[i * 2u + 1u];
		lo = (unsigned)(c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
		b[i] = (hi << 4) | lo;
	}
	if (!v6) {
		snprintf(out, cap, "%u.%u.%u.%u", b[3], b[2], b[1], b[0]);
		return;
	}
	/* Each 32-bit word is little-endian, the words in order. */
	snprintf(out, cap,
		 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		 "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		 b[3], b[2], b[1], b[0], b[7], b[6], b[5], b[4],
		 b[11], b[10], b[9], b[8], b[15], b[14], b[13], b[12]);
}

static const char *a_tcp_state(unsigned st)
{
	switch (st) {
	case 1:  return "ESTABLISHED";
	case 2:  return "SYN_SENT";
	case 3:  return "SYN_RECV";
	case 4:  return "FIN_WAIT1";
	case 5:  return "FIN_WAIT2";
	case 6:  return "TIME_WAIT";
	case 7:  return "CLOSE";
	case 8:  return "CLOSE_WAIT";
	case 9:  return "LAST_ACK";
	case 10: return "LISTEN";
	case 11: return "CLOSING";
	default: return "?";
	}
}

static void a_net_table(uint32_t pid, const char *what, const char *proto,
			int v6, const uint64_t *ino, uint32_t n_ino,
			char *buf, size_t cap, size_t *at)
{
	char path[64], line[512];
	FILE *f;

	snprintf(path, sizeof path, "/proc/%u/net/%s", (unsigned)pid, what);
	f = fopen(path, "r");
	if (!f)
		return;
	/* The header row. */
	if (!fgets(line, sizeof line, f)) {
		fclose(f);
		return;
	}
	while (fgets(line, sizeof line, f)) {
		char lh[48], rh[48], ls[64], rs[64];
		unsigned lp, rp, st;
		unsigned long long inode = 0;
		int w;

		/* sl local:port rem:port st ... then seven fields to inode. */
		if (sscanf(line,
			   " %*u: %47[0-9A-Fa-f]:%x %47[0-9A-Fa-f]:%x %x "
			   "%*x:%*x %*x:%*x %*x %*u %*u %llu",
			   lh, &lp, rh, &rp, &st, &inode) != 6)
			continue;
		if (!inode || !a_sock_known(ino, n_ino, (uint64_t)inode))
			continue;
		a_net_addr(lh, ls, sizeof ls, v6);
		a_net_addr(rh, rs, sizeof rs, v6);
		w = snprintf(buf + *at, cap - *at, "%s %s:%u -> %s:%u %s\n",
			     proto, ls, lp, rs, rp,
			     proto[0] == 'T' ? a_tcp_state(st) : "");
		if (w < 0 || (size_t)w >= cap - *at)
			break;
		*at += (size_t)w;
	}
	fclose(f);
}

static void a_read_net(uint32_t pid, const uint64_t *ino, uint32_t n_ino,
		       char *buf, size_t cap)
{
	size_t at = 0;

	buf[0] = '\0';
	if (!n_ino)
		return;
	a_net_table(pid, "tcp",  "TCP",  0, ino, n_ino, buf, cap, &at);
	a_net_table(pid, "tcp6", "TCP6", 1, ino, n_ino, buf, cap, &at);
	a_net_table(pid, "udp",  "UDP",  0, ino, n_ino, buf, cap, &at);
	a_net_table(pid, "udp6", "UDP6", 1, ino, n_ino, buf, cap, &at);
	buf[at] = '\0';
}

static void a_read_fds(uint32_t pid, struct kofa_proc *out,
		       char std[3][KOFA_FDLINK_MAX],
		       uint64_t *ino, uint32_t *n_ino)
{
	char path[64], link[KOFA_FDLINK_MAX];
	DIR *d;
	struct dirent *de;
	int i;

	out->n_fd = 0;
	out->n_socket = 0;
	out->n_like_stdin = 0;
	out->fds_read = 0;
	std[0][0] = std[1][0] = std[2][0] = '\0';

	for (i = 0; i < 3; i++) {
		ssize_t n;

		snprintf(path, sizeof path, "/proc/%u/fd/%d", (unsigned)pid, i);
		n = readlink(path, link, sizeof link - 1);
		if (n <= 0)
			continue;
		link[n] = '\0';
		memcpy(std[i], link, (size_t)n + 1u);
	}

	snprintf(path, sizeof path, "/proc/%u/fd", (unsigned)pid);
	d = opendir(path);
	if (!d)
		return;

	/*
	 * readlinkat against the open directory rather than a path built per
	 * entry: a d_name is up to 255 bytes and the path buffer is 64, so the
	 * built form was a truncation the compiler was right to complain
	 * about. It is also one fewer path walk per descriptor, on the loop
	 * that runs thousands of times for a busy daemon.
	 */
	while ((de = readdir(d)) != NULL) {
		ssize_t n;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		out->n_fd++;

		n = readlinkat(dirfd(d), de->d_name, link, sizeof link - 1);
		if (n <= 0)
			continue;
		link[n] = '\0';
		if (!strncmp(link, "socket:", 7)) {
			out->n_socket++;
			/* Collected HERE because this walk is already
			 * readlinking every descriptor to count them; a second
			 * pass to find the same inodes would double the one
			 * loop that scales with a busy daemon's fd table. */
			if (ino && n_ino && *n_ino < A_NET_MAX_SOCK) {
				unsigned long long v = 0;

				if (sscanf(link, "socket:[%llu]", &v) == 1)
					ino[(*n_ino)++] = (uint64_t)v;
			}
		}
		if (std[0][0] && !strcmp(link, std[0]))
			out->n_like_stdin++;
	}
	closedir(d);
	out->fds_read = 1;
}


/* -------------------------------------------------------------- the plist */

struct kofa_plist {
	DIR *d;
	struct kofa_plist_option o;
	char comm[64];
	char exe[APATH_MAX];
	char cmdline[4096];
	/* Bigger than the command line because an environment routinely is -
	 * a desktop session hands a child forty variables. Truncated rather
	 * than grown: what is past this is not worth a second allocation on a
	 * path that runs once per process. */
	char environ[8192];
	/* One line per connection; a process with more than this many rows has
	 * more than anybody reads, and n_socket still says how many there
	 * were. */
	char net[4096];
	char std[3][KOFA_FDLINK_MAX];
};

struct kofa_plist *kofa_plist_open(const struct kofa_plist_option *opt,
				   int *err)
{
	struct kofa_plist *l = calloc(1, sizeof *l);

	if (!l) {
		if (err)
			*err = KOFA_ERR_NOMEM;
		return NULL;
	}

	if (opt) {
		l->o = *opt;
	} else {
		l->o.want_kernel = 0;
		l->o.want_refused = 1;
	}
	/* no_cmdline and no_fds are negative by design - a zeroed option
	 * struct asks for everything. See kofa_plist_option. */

	l->d = opendir("/proc");
	if (!l->d) {
		free(l);
		if (err)
			*err = KOFA_ERR_OS;
		return NULL;
	}

	if (err)
		*err = KOFA_OK;
	return l;
}

int kofa_plist_next(struct kofa_plist *l, struct kofa_proc *out)
{
	struct dirent *de;

	if (!l || !out)
		return 0;

	while ((de = readdir(l->d)) != NULL) {
		struct a_stat st;
		struct stat sb;
		char path[64];
		unsigned long pid;
		char *end;
		int rc;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		pid = strtoul(de->d_name, &end, 10);
		if (*end || !pid)
			continue;
		/*
		 * ONE PID, WHEN ONE WAS ASKED FOR - see
		 * kofa_plist_option.only_pid. Filtered here rather than by the
		 * caller so everything below it still runs: the cmdline, the
		 * descriptors and the ownership are read by THIS loop, and a
		 * caller that filtered afterwards would have had to reach them
		 * some other way.
		 */
		if (l->o.only_pid && (uint32_t)pid != l->o.only_pid)
			continue;

		memset(out, 0, sizeof *out);
		out->pid = (uint32_t)pid;

		rc = a_read_stat(out->pid, &st);
		if (rc == KOFA_ERR_GONE)
			continue;          /* exited while we walked. Normal. */
		if (rc == KOFA_ERR_DENIED) {
			if (!l->o.want_refused)
				continue;
			out->flags |= KOFA_PF_REFUSED;
			l->comm[0] = '\0';
			l->exe[0] = '\0';
			l->cmdline[0] = '\0';
			l->std[0][0] = l->std[1][0] = l->std[2][0] = '\0';
			out->comm = l->comm;
			out->exe = l->exe;
			out->cmdline = l->cmdline;
			out->fd_stdin = l->std[0];
			out->fd_stdout = l->std[1];
			out->fd_stderr = l->std[2];
			return 1;
		}
		if (rc != KOFA_OK)
			continue;

		if (st.flags & A_PF_KTHREAD) {
			if (!l->o.want_kernel)
				continue;
			out->flags |= KOFA_PF_KERNEL;
		}

		out->ppid = st.ppid;
		out->start_time = st.start_time;

		memcpy(l->comm, st.comm, sizeof l->comm);
		l->comm[sizeof l->comm - 1] = '\0';

		l->exe[0] = '\0';
		if (!(out->flags & KOFA_PF_KERNEL))
			a_read_exe(out->pid, l->exe, sizeof l->exe,
				   &out->flags);

		snprintf(path, sizeof path, "/proc/%u", (unsigned)out->pid);
		if (stat(path, &sb) == 0) {
			out->uid = sb.st_uid;
			out->gid = sb.st_gid;
		}

		/*
		 * Refused is decided by whether the ADDRESS SPACE can be read,
		 * not by whether /proc/<pid>/stat could - stat is world
		 * readable and maps is not, so a walk that judged from stat
		 * would call every other user's process readable and only find
		 * out later, per region.
		 */
		snprintf(path, sizeof path, "/proc/%u/maps", (unsigned)out->pid);
		if (!(out->flags & KOFA_PF_KERNEL) &&
		    access(path, R_OK) != 0) {
			if (!l->o.want_refused)
				continue;
			out->flags |= KOFA_PF_REFUSED;
		}

		/*
		 * TWO FACTS ABOUT THE EXECUTABLE, REPORTED APART.
		 *
		 * The link said "(deleted)" - KOFA_PF_EXE_GONE, read where the
		 * link was read. Whether the path resolves NOW is this. A
		 * package upgrade produces the first without the second; a
		 * program that unlinked itself produces both. Which of those
		 * happened is a question for a rule, and joining them here
		 * would answer it in the one place nobody can disagree with.
		 *
		 * Likewise the kernel's own PF_KTHREAD, copied out as a field:
		 * comparing it against a name that looks like "[kworker/0:2]"
		 * is a join, and the join belongs to a rule.
		 */
		out->is_kthread  = (out->flags & KOFA_PF_KERNEL) ? 1u : 0u;
		out->exe_on_disk = (l->exe[0] == '/' &&
				    access(l->exe, F_OK) == 0) ? 1u : 0u;

		l->cmdline[0] = '\0';
		if (!l->o.no_cmdline && !(out->flags & KOFA_PF_KERNEL))
			a_read_cmdline(out->pid, l->cmdline,
				       sizeof l->cmdline);

		/* Same reader as the command line: the file has the same shape
		 * - NUL separated, trailing NUL - and the same permission. */
		l->environ[0] = '\0';
		if (!l->o.no_environ && !(out->flags & KOFA_PF_KERNEL))
			a_read_environ(out->pid, l->environ,
				       sizeof l->environ);
		out->environ = l->environ;

		l->std[0][0] = l->std[1][0] = l->std[2][0] = '\0';
		if (!l->o.no_fds && !(out->flags & KOFA_PF_KERNEL))
		{
			uint64_t ino[A_NET_MAX_SOCK];
			uint32_t n_ino = 0;

			a_read_fds(out->pid, out, l->std, ino, &n_ino);
			l->net[0] = '\0';
			if (!l->o.no_net)
				a_read_net(out->pid, ino, n_ino, l->net,
					   sizeof l->net);
			out->net = l->net;
		}

		out->comm = l->comm;
		out->exe = l->exe;
		out->cmdline = l->cmdline;
		out->fd_stdin = l->std[0];
		out->fd_stdout = l->std[1];
		out->fd_stderr = l->std[2];
		return 1;
	}

	return 0;
}

void kofa_plist_close(struct kofa_plist *l)
{
	if (!l)
		return;
	if (l->d)
		closedir(l->d);
	free(l);
}

/* --------------------------------------------------------------- the pmem */

struct kofa_pmem {
	struct kofa_pmem_option o;
	struct kofa_proc proc;
	char comm[64];
	char exe[APATH_MAX];

	FILE *maps;
	int use_smaps;
	int pmfd;

	/*
	 * ONE REGION OF LOOKAHEAD, which reading smaps forces.
	 *
	 * smaps gives a maps line followed by a block of counters belonging to
	 * it, so a region is only complete when the NEXT region's header
	 * arrives (or the file ends). maps needs no lookahead at all - hence
	 * the flag, rather than two walks.
	 */
	int pending_valid;
	struct kofa_region pending;
	char pending_path[APATH_MAX];

	uint64_t *pm_scratch;
	struct kofa_run runs[A_RUNS_CACHED];

	/* Which region self->runs currently describes, so kofa_pmem_runs does
	 * not read the pagemap a second time for the region the caller just
	 * received. Zero size means "nothing cached". */
	uint64_t cached_base, cached_size;
	int cached_runs, cached_more;

	char line[APATH_MAX + 256];
	char path[APATH_MAX];

	/* Grouping state - see kofa_region.group_id. */
	uint64_t prev_end, prev_inode, group_id;
	int have_prev, prev_anon;

	uint64_t budget_used;
	struct kofa_pmem_stat st;

	/* ---- the chunk walk, per region ---- */

	/*
	 * The region kofa_pmem_next_chunk is part way through, and where it
	 * has got to. `chunk_base` is zero when no walk is open, which is why
	 * a region at address zero could not be walked - and there is no such
	 * region, because the kernel does not map one.
	 */
	uint64_t chunk_base, chunk_size;
	int      chunk_run;        /* index into runs[] */
	uint64_t chunk_off;        /* bytes into that run */
	struct kofa_run chunk_runs[A_RUNS_CACHED];
	int      chunk_nruns;

	/*
	 * THE BUFFER AND WHAT IS STILL IN IT.
	 *
	 * A read fills chunk_buf with up to chunk_max bytes; one call may
	 * hand back only the first span of it, so the rest STAYS and the next
	 * call resumes inside the buffer. Rewinding the run offset and
	 * reading again was the first version and it moved the tail of every
	 * read twice - measured on a six-page region: 45 KB pulled out of the
	 * process for 24 KB of region.
	 */
	unsigned char *chunk_buf;  /* chunk_max bytes, allocated on first use */
	uint64_t chunk_have;       /* valid bytes in it */
	uint64_t chunk_pos;        /* how far this call has got through them */
	uint64_t chunk_addr;       /* process address of chunk_buf[0] */
};

static uint64_t a_opt_or(uint64_t v, uint64_t def) { return v ? v : def; }

struct kofa_pmem *kofa_pmem_open(uint32_t pid, uint64_t start_time,
				 const struct kofa_pmem_option *opt, int *err)
{
	struct kofa_pmem *m;
	struct a_stat st;
	char path[64];
	int rc;

	rc = a_read_stat(pid, &st);
	if (rc != KOFA_OK) {
		if (err)
			*err = rc;
		return NULL;
	}

	/*
	 * THE PID HAS BEEN REUSED CHECK, and it is the reason every entry
	 * point here takes a pair. A pid names a slot, not a process.
	 */
	if (start_time && st.start_time != start_time) {
		if (err)
			*err = KOFA_ERR_GONE;
		return NULL;
	}

	m = calloc(1, sizeof *m);
	if (!m) {
		if (err)
			*err = KOFA_ERR_NOMEM;
		return NULL;
	}

	if (opt)
		m->o = *opt;
	m->o.want = m->o.want ? m->o.want : KOFA_MW_DEFAULT;
	m->o.max_region = a_opt_or(m->o.max_region, A_DEF_MAX_REGION);
	m->o.max_heap_region =
		a_opt_or(m->o.max_heap_region, A_DEF_MAX_HEAP_REGION);
	m->o.max_bytes = a_opt_or(m->o.max_bytes, A_DEF_MAX_BYTES);
	m->o.pagemap_min = a_opt_or(m->o.pagemap_min, A_DEF_PAGEMAP_MIN);
	m->o.chunk_max = a_opt_or(m->o.chunk_max, A_DEF_CHUNK_MAX);

	m->pmfd = -1;
	m->proc.pid = pid;
	m->proc.ppid = st.ppid;
	m->proc.start_time = st.start_time;
	memcpy(m->comm, st.comm, sizeof m->comm);
	m->comm[sizeof m->comm - 1] = '\0';
	a_read_exe(pid, m->exe, sizeof m->exe, &m->proc.flags);
	m->proc.comm = m->comm;
	m->proc.exe = m->exe;

	m->use_smaps = (m->o.want & KOFA_MW_SMAPS) != 0;
	snprintf(path, sizeof path, "/proc/%u/%s", (unsigned)pid,
		 m->use_smaps ? "smaps" : "maps");
	m->maps = fopen(path, "re");
	if (!m->maps && m->use_smaps) {
		/* smaps needs CONFIG_PROC_PAGE_MONITOR too. Falling back keeps
		 * the walk working on a kernel without it, with rss coming
		 * from pagemap and reading looser. */
		m->use_smaps = 0;
		snprintf(path, sizeof path, "/proc/%u/maps", (unsigned)pid);
		m->maps = fopen(path, "re");
	}
	if (!m->maps) {
		int e = (errno == EACCES || errno == EPERM) ? KOFA_ERR_DENIED
							    : KOFA_ERR_GONE;
		free(m);
		if (err)
			*err = e;
		return NULL;
	}

	if (m->o.want & KOFA_MW_PAGEMAP) {
		int pe = KOFA_OK;

		m->pmfd = kofa_pm_open(pid, &pe);
		if (m->pmfd >= 0) {
			m->pm_scratch = malloc((size_t)A_PM_BATCH * 8);
			if (!m->pm_scratch) {
				close(m->pmfd);
				m->pmfd = -1;
			}
		}
		/*
		 * A missing pagemap is NOT a failure to open the process. The
		 * walk still works, every region comes back flagged
		 * KOFA_RGF_NO_PAGEMAP, and reads are blind - slower, and
		 * honestly labelled.
		 */
	}

	if (err)
		*err = KOFA_OK;
	return m;
}

const struct kofa_proc *kofa_pmem_proc(const struct kofa_pmem *m)
{
	return m ? &m->proc : NULL;
}

/*
 * Decide what a region is, from the maps line alone. No bytes are read here.
 *
 * THE ORDER OF THESE TESTS IS THE WHOLE FUNCTION. [vdso] and [vsyscall] are
 * anonymous and executable, so a classifier that asks "executable with no file"
 * first files the vDSO of every process on the machine as unbacked code -
 * measured: 34 of them on this desktop, one per process, every one a false
 * positive that no amount of later filtering can undo because the fact was
 * recorded wrong.
 */
static void a_classify(struct kofa_region *r, const char *name)
{
	int exec = (r->flags & KOFA_RGF_EXEC) != 0;
	int write = (r->flags & KOFA_RGF_WRITE) != 0;
	int read = (r->flags & KOFA_RGF_READ) != 0;
	int anon = (r->inode == 0);

	/*
	 * NO ACCESS AT ALL, FIRST, because these are enormous and because
	 * everything below would give one of them a confident wrong answer.
	 * Chromium reserves seven of them at roughly 1.3 TB each. They hold
	 * nothing and cannot be read; see aproc.h.
	 */
	if (!read && !write && !exec) {
		r->use = KOFA_USE_UNKNOWN;
		return;
	}

	/* The kernel's own mappings, named in brackets. None of them is
	 * interesting and two of them are executable. */
	if (name[0] == '[') {
		/*
		 * The kernel's own mappings. Flagged as well as classified,
		 * because [vdso] is executable with no file and a consumer
		 * that only looked at those two facts would call it shellcode.
		 */
		r->flags |= KOFA_RGF_KERNEL_MAPPED;
		if (!strcmp(name, "[stack]")) {
			r->use = KOFA_USE_STACK;
			return;
		}
		if (!strcmp(name, "[heap]")) {
			r->use = KOFA_USE_HEAP;
			return;
		}
		/* [vdso] [vvar] [vsyscall] [vvar_vclock] and anything else the
		 * kernel adds later. Data, whatever its protection says. */
		r->use = KOFA_USE_DATA;
		return;
	}

	if (exec) {
		if (anon) {
			r->use = KOFA_USE_CODE;
			r->flags |= KOFA_RGF_UNBACKED;
		} else {
			r->use = KOFA_USE_IMAGE;
			/* A file that has been unlinked, or was never a file:
			 * the bytes are here and nothing on disk holds them,
			 * so this is code a file scanner cannot reach. */
			if (r->flags & (KOFA_RGF_DELETED | KOFA_RGF_MEMFD))
				r->flags |= KOFA_RGF_UNBACKED;
		}
		return;
	}

	if (anon && write) {
		r->use = KOFA_USE_HEAP;
		return;
	}

	r->use = KOFA_USE_DATA;
}

/*
 * Parse one line of /proc/<pid>/maps.
 *
 * The pathname is the rest of the line after five whitespace-separated fields,
 * and it MAY CONTAIN SPACES - " (deleted)" is itself a space and a word glued
 * onto a path by the kernel. So the split is by field count, never by the last
 * token.
 */
static int a_parse_maps(char *line, struct kofa_region *r, char *pathbuf,
			size_t pathcap)
{
	unsigned long long lo, hi, off, ino;
	unsigned maj, min;
	char perms[8];
	char *p = line;
	int n = 0;
	size_t len;

	memset(r, 0, sizeof *r);
	pathbuf[0] = '\0';

	if (sscanf(line, "%llx-%llx %7s %llx %x:%x %llu%n",
		   &lo, &hi, perms, &off, &maj, &min, &ino, &n) < 7)
		return 0;
	if (hi <= lo)
		return 0;

	r->base = lo;
	r->size = hi - lo;
	r->file_off = off;
	r->inode = ino;
	r->dev = ((uint64_t)maj << 8) | min;

	if (perms[0] == 'r') r->flags |= KOFA_RGF_READ;
	if (perms[1] == 'w') r->flags |= KOFA_RGF_WRITE;
	if (perms[2] == 'x') r->flags |= KOFA_RGF_EXEC;
	if ((r->flags & KOFA_RGF_WRITE) && (r->flags & KOFA_RGF_EXEC))
		r->flags |= KOFA_RGF_WX;

	p = line + n;
	while (*p == ' ' || *p == '\t')
		p++;

	len = strlen(p);
	while (len && (p[len - 1] == '\n' || p[len - 1] == '\r'))
		p[--len] = '\0';

	if (!len)
		return 1;

	if (len >= pathcap)
		len = pathcap - 1;
	memcpy(pathbuf, p, len);
	pathbuf[len] = '\0';

	if (len > 10 && !strcmp(pathbuf + len - 10, " (deleted)")) {
		pathbuf[len - 10] = '\0';
		len -= 10;
		r->flags |= KOFA_RGF_DELETED;
	}

	if (!strncmp(pathbuf, "/memfd:", 7)) {
		r->flags |= KOFA_RGF_MEMFD;
		/*
		 * A memfd never had a file, so the "deleted" the kernel
		 * appends to it does not mean what it means anywhere else.
		 * Withdrawn here so a caller counting unlinked files does not
		 * count these twice under two different stories.
		 */
		r->flags &= ~(uint32_t)KOFA_RGF_DELETED;
	} else if (!strncmp(pathbuf, "/dev/shm/", 9) ||
		   !strncmp(pathbuf, "/run/", 5)) {
		r->flags |= KOFA_RGF_VOLATILE;
	}

	return 1;
}

/* Is this a maps/smaps region header rather than one of smaps' counter
 * lines? A header starts with a hex address and has a '-' before its first
 * space; a counter line starts with a capital letter. */
static int a_is_header(const char *line)
{
	const char *p = line;

	if (!isxdigit((unsigned char)*p))
		return 0;
	while (*p && *p != ' ') {
		if (*p == '-')
			return 1;
		p++;
	}
	return 0;
}

/* "Rss:                 360 kB" -> bytes. */
static uint64_t a_kb_line(const char *line)
{
	const char *p = strchr(line, ':');

	if (!p)
		return 0;
	return (uint64_t)strtoull(p + 1, NULL, 10) * 1024u;
}

/*
 * The next region as the kernel describes it, with smaps' Rss folded in when
 * this walk is reading smaps. No filtering, no pagemap, no budgets - those
 * belong to the caller below, which needs to see EVERY region to group them
 * even when it will report only some.
 */
static int a_next_raw(struct kofa_pmem *m, struct kofa_region *r)
{
	if (!m->use_smaps) {
		while (fgets(m->line, (int)sizeof m->line, m->maps))
			if (a_parse_maps(m->line, r, m->path, sizeof m->path))
				return 1;
		return 0;
	}

	for (;;) {
		if (!fgets(m->line, (int)sizeof m->line, m->maps)) {
			if (!m->pending_valid)
				return 0;
			*r = m->pending;
			memcpy(m->path, m->pending_path, sizeof m->path);
			m->pending_valid = 0;
			return 1;
		}

		if (a_is_header(m->line)) {
			struct kofa_region nr;
			char np[APATH_MAX];

			if (!a_parse_maps(m->line, &nr, np, sizeof np))
				continue;

			if (m->pending_valid) {
				*r = m->pending;
				memcpy(m->path, m->pending_path,
				       sizeof m->path);
				m->pending = nr;
				memcpy(m->pending_path, np, sizeof np);
				return 1;
			}
			m->pending = nr;
			memcpy(m->pending_path, np, sizeof np);
			m->pending_valid = 1;
			continue;
		}

		/*
		 * Rss is the one counter this walk wants, and it is the one
		 * pagemap cannot give: it EXCLUDES the shared zero page. See
		 * KOFA_MW_SMAPS.
		 */
		if (m->pending_valid && !strncmp(m->line, "Rss:", 4)) {
			m->pending.rss = a_kb_line(m->line);
			m->pending.flags |= KOFA_RGF_RSS_MEASURED;
			continue;
		}

		/*
		 * Private_Dirty on an executable file-backed region is code
		 * somebody wrote to - see KOFA_RGF_DIRTY_CODE. Free, because
		 * smaps is already open for Rss.
		 */
		if (m->pending_valid &&
		    !strncmp(m->line, "Private_Dirty:", 14) &&
		    (m->pending.flags & KOFA_RGF_EXEC) &&
		    m->pending.inode != 0 &&
		    a_kb_line(m->line) > 0)
			m->pending.flags |= KOFA_RGF_DIRTY_CODE;
	}
}

int kofa_pmem_next_region(struct kofa_pmem *m, struct kofa_region *out)
{
	struct kofa_region r_scratch;

	if (!m || !out || !m->maps)
		return 0;

	while (a_next_raw(m, &r_scratch)) {
		struct kofa_region r = r_scratch;
		int anon, want_it, have_smaps;
		uint64_t smaps_rss;

		a_classify(&r, m->path);
		r.loc = kof_classify_path(m->path);
		r.path = m->path;

		/*
		 * GROUPING RUNS FIRST, AND BEFORE FILTERING.
		 *
		 * One mapped shared object is three or four VMAs split where
		 * the protection changes. They are grouped by being adjacent
		 * and sharing a backing inode - or by being adjacent and both
		 * anonymous.
		 *
		 * It must happen before the filter, because adjacency is a
		 * property of the WHOLE map. A caller asking for executable
		 * regions only still needs its r-xp region grouped with the
		 * r--p header it follows, and that header is a line the filter
		 * is about to discard.
		 */
		anon = (r.inode == 0);
		if (m->have_prev && r.base == m->prev_end &&
		    ((anon && m->prev_anon) ||
		     (!anon && !m->prev_anon && r.inode == m->prev_inode))) {
			r.group_id = m->group_id;
		} else {
			m->group_id = r.base;
			r.group_id = r.base;
		}
		m->have_prev = 1;
		m->prev_end = r.base + r.size;
		m->prev_inode = r.inode;
		m->prev_anon = anon;

		/* ------------------------------------------- the filter */

		want_it = 1;
		if (r.use == KOFA_USE_UNKNOWN &&
		    !(m->o.want & KOFA_MW_RESERVED))
			want_it = 0;
		if ((m->o.want & KOFA_MW_EXEC_ONLY) &&
		    !(r.flags & KOFA_RGF_EXEC))
			want_it = 0;
		if (r.use == KOFA_USE_HEAP && !(m->o.want & KOFA_MW_HEAP))
			want_it = 0;

		if (!want_it) {
			m->st.regions_filtered++;
			continue;
		}

		/* ------------------------------------ how much is really there */

		/*
		 * TWO SOURCES ANSWERING TWO QUESTIONS.
		 *
		 * smaps' Rss, already folded in by a_next_raw, says HOW MUCH
		 * of this region is real - it is the only one of the two that
		 * excludes the shared zero page. pagemap says WHERE, which
		 * smaps cannot say at all. When only pagemap is available its
		 * count stands in for both, and is a looser bound.
		 */
		smaps_rss = (r.flags & KOFA_RGF_RSS_MEASURED) ? r.rss : 0;
		have_smaps = (r.flags & KOFA_RGF_RSS_MEASURED) != 0;

		if (!have_smaps)
			r.rss = r.size;
		m->cached_base = 0;
		m->cached_size = 0;
		m->cached_runs = 0;
		m->cached_more = 0;

		if (m->pmfd < 0) {
			if (m->o.want & KOFA_MW_PAGEMAP)
				r.flags |= KOFA_RGF_NO_PAGEMAP;
		} else if (r.size < m->o.pagemap_min) {
			/* Deliberately not consulted: one pread of the map
			 * costs more than reading the region. Not flagged
			 * NO_PAGEMAP, which means "could not", not "chose
			 * not". */
		} else if (r.size > m->o.max_region) {
			/* Not examined at all, and the pagemap read is itself
			 * proportional to the size we are refusing. */
			r.flags |= KOFA_RGF_UNEXAMINED;
			m->st.regions_skipped++;
		} else {
			struct kofa_pm_result pr;
			int rc = kofa_pm_scan(m->pmfd, r.base, r.size,
					      m->pm_scratch, A_PM_BATCH,
					      m->runs, A_RUNS_CACHED, &pr);

			m->st.pagemap_reads++;
			if (rc != KOFA_OK) {
				m->st.pagemap_failed++;
				r.flags |= KOFA_RGF_NO_PAGEMAP;
			} else {
				if (!have_smaps) {
					r.rss = pr.resident;
					r.flags |= KOFA_RGF_RSS_MEASURED;
				}
				m->cached_base = r.base;
				m->cached_size = r.size;
				m->cached_runs = pr.runs;
				m->cached_more = pr.more;

				/*
				 * pagemap points at far more than smaps
				 * charges: the excess is shared zero pages,
				 * so the runs are mostly 4096 zeroes each.
				 * The margin is deliberately generous - THP
				 * already makes pagemap overshoot by up to
				 * 2 MB per touch, and that is not this.
				 */
				if (have_smaps &&
				    pr.resident > smaps_rss * 2 + (1u << 20))
					r.flags |= KOFA_RGF_ZERO_HEAVY;

				if (r.rss * 10 < r.size)
					r.flags |= KOFA_RGF_SPARSE;
			}
		}

		/* ------------------------------------------- the budgets */

		if (r.use == KOFA_USE_HEAP && r.rss > m->o.max_heap_region) {
			r.flags |= KOFA_RGF_UNEXAMINED;
			m->st.regions_skipped++;
		}

		m->st.regions_seen++;
		m->st.bytes_virtual += r.size;

		/*
		 * MEASURED AND ASSUMED GO IN DIFFERENT COLUMNS. Adding an
		 * upper bound to a measurement produces a number that is
		 * neither, and reports it with the authority of the one it is
		 * not - see KOFA_RGF_RSS_MEASURED.
		 */
		if (r.flags & KOFA_RGF_RSS_MEASURED) {
			m->st.bytes_resident += r.rss;
			m->st.regions_measured++;
		} else {
			m->st.bytes_unmeasured += r.size;
		}

		*out = r;
		out->path = m->path;
		return 1;
	}

	return 0;
}

int kofa_pmem_runs(struct kofa_pmem *m, const struct kofa_region *r,
		   struct kofa_run *out, int max, int *more)
{
	struct kofa_pm_result pr;
	int rc, n;

	if (more)
		*more = 0;
	if (!m || !r || !out || max < 1)
		return 0;

	/*
	 * The region the caller just received is already described, because
	 * next_region had to read its pagemap to learn rss. Serving it from
	 * there is not a cache in the hopeful sense - it is the same answer,
	 * and reading it again would be a second pass over the same map in the
	 * overwhelmingly common call pattern of "walk, then read what was
	 * interesting".
	 */
	if (m->cached_size && r->base == m->cached_base &&
	    r->size == m->cached_size) {
		n = m->cached_runs < max ? m->cached_runs : max;
		memcpy(out, m->runs, (size_t)n * sizeof *out);
		if (more)
			*more = m->cached_more || n < m->cached_runs;
		return n;
	}

	if (m->pmfd < 0 || !m->pm_scratch)
		return 0;

	rc = kofa_pm_scan(m->pmfd, r->base, r->size, m->pm_scratch,
			  A_PM_BATCH, out, max, &pr);
	m->st.pagemap_reads++;
	if (rc != KOFA_OK) {
		m->st.pagemap_failed++;
		return 0;
	}
	if (more)
		*more = pr.more;
	return pr.runs;
}

/*
 * Is this page nothing but zeroes?
 *
 * Word at a time rather than byte at a time - measured at 3.67 GB/s over
 * 1132 MB, which is what makes the filter cheap enough to always run. A plain
 * byte loop is the obvious version and is several times slower on the only
 * path that matters, which is the one where the page IS zero and every byte
 * has to be looked at.
 */
static int page_is_zero(const unsigned char *p, size_t n)
{
	size_t i = 0;

	while (i + sizeof(uint64_t) <= n) {
		uint64_t w;

		memcpy(&w, p + i, sizeof w);
		if (w)
			return 0;
		i += sizeof w;
	}
	for (; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

/*
 * Take the budgets off `want` and say how much may actually be read. Returns 0
 * when nothing may, and records the refusal - see kofa_sweep.
 */
static uint64_t budget_allow(struct kofa_pmem *m, uint64_t want)
{
	uint64_t left;

	if (m->budget_used >= m->o.max_bytes)
		return 0;
	left = m->o.max_bytes - m->budget_used;
	if (want > left)
		want = left;

	if (m->o.sweep && m->o.sweep->max_bytes) {
		struct kofa_sweep *sw = m->o.sweep;

		if (sw->used >= sw->max_bytes) {
			sw->refused += want;
			return 0;
		}
		left = sw->max_bytes - sw->used;
		if (want > left) {
			sw->refused += want - left;
			want = left;
		}
	}
	return want;
}

int kofa_pmem_next_chunk(struct kofa_pmem *m, const struct kofa_region *r,
			 struct kofa_chunk *out)
{
	if (!m || !r || !out)
		return 0;

	/* A new region ends whatever walk was open. */
	if (m->chunk_base != r->base || m->chunk_size != r->size) {
		int more = 0;

		m->chunk_base = r->base;
		m->chunk_size = r->size;
		m->chunk_off  = 0;
		m->chunk_run  = 0;
		m->chunk_nruns = 0;
		m->chunk_have = 0;
		m->chunk_pos  = 0;

		if (r->flags & KOFA_RGF_UNEXAMINED)
			return 0;

		/*
		 * NOTHING IS CHARGED TO THIS REGION, SO THERE IS NOTHING IN IT.
		 *
		 * smaps' Rss counts pages charged to the process, and the
		 * shared zero page is charged to nobody - so a region whose
		 * pages pagemap calls present and whose Rss is zero holds the
		 * zero page and nothing else.
		 *
		 * THE ONLY PART OF THIS IDEA THAT SURVIVED MEASUREMENT. The
		 * obvious extension - stop once as many non-zero bytes as Rss
		 * have been handed over, since Rss must bound the content -
		 * is WRONG, and transparent huge pages are why. A child that
		 * wrote 256 KB into a 64 MB mapping and read the rest came
		 * back with Rss 2.00 MB: THP promoted the write to one 2 MB
		 * page and charged all of it, zeroes included. So Rss is not a
		 * bound on content; the budget never emptied, and the walk
		 * read all 64.00 MB with the bound on exactly as it did with
		 * it off. It was removed rather than left in place not firing.
		 *
		 * Rss EXACTLY ZERO is still sound: nothing is charged at all,
		 * so there is no huge page to have inflated it.
		 */
		if ((r->flags & KOFA_RGF_RSS_MEASURED) && r->rss == 0)
			return 0;

		m->chunk_nruns = kofa_pmem_runs(m, r, m->chunk_runs,
						A_RUNS_CACHED, &more);
		/*
		 * NO RUNS AND NO PAGEMAP ARE DIFFERENT ANSWERS. Without
		 * pagemap there is nothing to guide a read, so the region is
		 * taken whole - one run covering it. With pagemap and no runs,
		 * nothing is resident and there is nothing to hand over.
		 */
		if (!m->chunk_nruns && (r->flags & KOFA_RGF_NO_PAGEMAP)) {
			m->chunk_runs[0].addr = r->base;
			m->chunk_runs[0].len  = r->size;
			m->chunk_nruns = 1;
		}
	}

	if (!m->chunk_buf) {
		m->chunk_buf = malloc((size_t)m->o.chunk_max);
		if (!m->chunk_buf)
			return 0;
	}

	for (;;) {
		const struct kofa_run *run;
		uint64_t left, want, got;

		/*
		 * ANYTHING LEFT IN THE BUFFER FIRST. A read can hold several
		 * spans separated by zero pages, and each is its own chunk -
		 * see the note on chunk_have for why they are not re-read.
		 */
		while (m->chunk_pos < m->chunk_have) {
			uint64_t keep_off = 0, keep_len = 0, i;

			for (i = m->chunk_pos; i < m->chunk_have;
			     i += KOFA_PAGE_SIZE) {
				size_t pn = (size_t)
					((m->chunk_have - i < KOFA_PAGE_SIZE)
					 ? m->chunk_have - i : KOFA_PAGE_SIZE);

				if (page_is_zero(m->chunk_buf + i, pn)) {
					if (keep_len)
						break;   /* the span ended */
					m->st.bytes_zero += pn;
					continue;
				}
				if (!keep_len)
					keep_off = i;
				keep_len += pn;
			}

			if (!keep_len) {
				m->chunk_pos = m->chunk_have;
				break;
			}

			m->chunk_pos = keep_off + keep_len;
			out->addr = m->chunk_addr + keep_off;
			out->p    = m->chunk_buf + keep_off;
			out->len  = keep_len;
			m->st.chunks++;
			return 1;
		}

		/* The buffer is spent; fill it from the run being walked. */
		if (m->chunk_run >= m->chunk_nruns)
			return 0;


		run = &m->chunk_runs[m->chunk_run];
		left = run->len - m->chunk_off;
		if (!left) {
			m->chunk_run++;
			m->chunk_off = 0;
			continue;
		}

		want = left < m->o.chunk_max ? left : m->o.chunk_max;
		want = budget_allow(m, want);
		if (!want) {
			/*
			 * The budget ran out mid region. Said rather than
			 * left as a short walk: a caller has to be able to
			 * tell "there was no more" from "we stopped".
			 */
			m->st.regions_skipped++;
			if (m->o.sweep)
				m->o.sweep->regions_refused++;
			m->chunk_run = m->chunk_nruns;
			return 0;
		}

		got = kofa_pmem_read(m, run->addr + m->chunk_off,
				     m->chunk_buf, (size_t)want);
		if (!got) {
			/* The region went away under us, which is ordinary. */
			m->chunk_run++;
			m->chunk_off = 0;
			continue;
		}
		m->chunk_addr = run->addr + m->chunk_off;
		m->chunk_off += got;
		m->chunk_have = got;
		m->chunk_pos = 0;
	}
	return 0;
}

size_t kofa_pmem_read(struct kofa_pmem *m, uint64_t addr, void *buf, size_t n)
{
	struct iovec local, remote;
	ssize_t got;

	if (!m || !buf || !n)
		return 0;

	if (m->budget_used >= m->o.max_bytes)
		return 0;
	if (n > m->o.max_bytes - m->budget_used)
		n = (size_t)(m->o.max_bytes - m->budget_used);

	local.iov_base = buf;
	local.iov_len = n;
	remote.iov_base = (void *)(uintptr_t)addr;
	remote.iov_len = n;

	/* pid_t is signed and a pid never is. The cast is explicit so the
	 * tree's -Wsign-conversion does not have to guess whether it was
	 * meant. */
	got = process_vm_readv((pid_t)m->proc.pid, &local, 1, &remote, 1, 0);
	if (got <= 0)
		return 0;

	m->budget_used += (uint64_t)got;
	m->st.bytes_read += (uint64_t)got;
	if (m->o.sweep)
		m->o.sweep->used += (uint64_t)got;
	return (size_t)got;
}

void kofa_pmem_stats(const struct kofa_pmem *m, struct kofa_pmem_stat *out)
{
	if (!out)
		return;
	if (!m) {
		memset(out, 0, sizeof *out);
		return;
	}
	*out = m->st;
}

void kofa_pmem_close(struct kofa_pmem *m)
{
	if (!m)
		return;
	if (m->maps)
		fclose(m->maps);
	if (m->pmfd >= 0)
		close(m->pmfd);
	free(m->pm_scratch);
	free(m->chunk_buf);
	free(m);
}
