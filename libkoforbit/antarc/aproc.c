/* See aproc.h. aproc_pmem.c is the other half. */

#define _GNU_SOURCE

#include "aproc_int.h"

/* PF_KTHREAD, from the kernel's sched.h. Field 9 of /proc/<pid>/stat. */
#define A_PF_KTHREAD 0x00200000u

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

/* "image", "code", "heap", "stack", "data", or "?". Never NULL. */
static const char *kofa_rgn_use_name(uint8_t use)
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



int kofa_proc_errno_status(int e)
{
	if (e == ENOENT || e == ESRCH)
		return KOFA_ERR_GONE;
	if (e == EACCES || e == EPERM)
		return KOFA_ERR_DENIED;
	return KOFA_ERR_OS;
}

int kofa_read_stat(uint32_t pid, struct a_stat *out)
{
	char path[64], buf[2048], *close_paren, *p;
	int fd, e = 0;
	ssize_t got;
	int field;

	out->io_err = 0;
	snprintf(path, sizeof path, "/proc/%u/stat", (unsigned)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		out->io_err = 1;
		return kofa_proc_errno_status(errno);
	}

	got = read(fd, buf, sizeof buf - 1);
	if (got < 0)
		e = errno;          /* close() may overwrite it */
	close(fd);
	if (got < 0) {
		out->io_err = 1;
		return kofa_proc_errno_status(e);
	}
	if (got == 0)
		return KOFA_ERR_GONE;   /* an empty stat: the entry is going away */
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
void kofa_read_exe(uint32_t pid, char *buf, size_t cap, uint32_t *flags)
{
	char path[64];
	ssize_t n;

	/*
	 * `cap` IS USED AS `cap - 1`, so a zero has to be refused before the
	 * subtraction and not after: it wraps to SIZE_MAX and the kernel is
	 * then asked to fill that many bytes. No caller passes zero today -
	 * every one passes a sizeof - and a_fmt_region two hundred lines up
	 * already opens `if (!buf || !cap)`. This is the same guard on the
	 * three that did not have it.
	 */
	if (!buf || !cap)
		return;
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
/*
 * `sep` is what the NULs between the pieces become, and 0 means LEAVE THEM.
 *
 * A command line wants spaces: it is read as one sentence, and the argv
 * boundaries inside it are not what anybody compares against. AN ENVIRONMENT
 * DOES NOT. Its pieces are NAME=value assignments and a value may contain a
 * space - a packager's DEBFULLNAME, a browser's argument list, anything a
 * shell exported with quotes - so a space separator loses the boundary it was
 * meant to mark, and a reader splitting on it gets one variable shown as two,
 * the second with no name. There is no character that cannot appear in a
 * value, which is why the answer is to keep the NUL and carry the length.
 *
 * Returns the bytes written, not counting the terminator.
 */
static size_t a_read_nul_list(uint32_t pid, const char *what, char *buf,
			      size_t cap, char sep)
{
	char path[64];
	int fd;
	ssize_t got;
	size_t i;

	/* Same as kofa_read_exe: `cap - 1` goes to read(). */
	if (!buf || !cap)
		return 0;
	buf[0] = '\0';
	snprintf(path, sizeof path, "/proc/%u/%s", (unsigned)pid, what);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;

	got = read(fd, buf, cap - 1);
	close(fd);
	if (got <= 0) {
		buf[0] = '\0';
		return 0;
	}

	/*
	 * The trailing NUL is a terminator and not a separator, so turning it
	 * into a space too leaves every command line ending in one - which
	 * then shows up in every comparison a caller writes. Dropped for the
	 * NUL-separated form as well, so the length names the last piece's
	 * end rather than an empty piece after it.
	 */
	while (got > 0 && buf[got - 1] == '\0')
		got--;

	if (sep)
		for (i = 0; i < (size_t)got; i++)
			if (buf[i] == '\0')
				buf[i] = sep;
	buf[got] = '\0';
	return (size_t)got;
}

static void a_read_cmdline(uint32_t pid, char *buf, size_t cap)
{
	(void)a_read_nul_list(pid, "cmdline", buf, cap, ' ');
}

static size_t a_read_environ(uint32_t pid, char *buf, size_t cap)
{
	return a_read_nul_list(pid, "environ", buf, cap, 0);
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
/* KNOWN DEFECT WP12-2 (2026-10-24, M) [sev M]: a_net_addr reads hex[0..31] of the
 * 48-byte lh/rh buffer a_net_table fills. Trigger: a tcp6 row whose address has
 * fewer than 32 hex digits. Effect: uninitialised stack bytes are read (lh[48]
 * is not cleared). Reproducer: orbit_plist.c case_net (no crash only); fuzz
 * orbit/proc_text digests differ. Fix: memset lh/rh or check strlen(hex) >= 2 *
 * n before the loop. */
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

/* One of the /proc/<pid>/net tables: its file, its label and its family. */
struct a_net_kind {
	const char *what;
	const char *proto;
	int         v6;
};

/* Where the lines go: the caller's buffer, its size and how much is used. */
struct a_net_out {
	char   *buf;
	size_t  cap;
	size_t  at;
};

static void a_net_table(uint32_t pid, const struct a_net_kind *kind,
			const uint64_t *ino, uint32_t n_ino,
			struct a_net_out *o)
{
	const char *proto = kind->proto;
	int v6 = kind->v6;
	char *buf = o->buf;
	size_t cap = o->cap;
	size_t *at = &o->at;
	char path[64], line[512];
	FILE *f;

	snprintf(path, sizeof path, "/proc/%u/net/%s", (unsigned)pid,
		 kind->what);
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
	static const struct a_net_kind kinds[] = {
		{ "tcp",  "TCP",  0 },
		{ "tcp6", "TCP6", 1 },
		{ "udp",  "UDP",  0 },
		{ "udp6", "UDP6", 1 },
	};
	struct a_net_out o = { buf, cap, 0 };
	size_t k;

	buf[0] = '\0';
	if (!n_ino)
		return;
	for (k = 0; k < sizeof kinds / sizeof kinds[0]; k++)
		a_net_table(pid, &kinds[k], ino, n_ino, &o);
	buf[o.at] = '\0';
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

		rc = kofa_read_stat(out->pid, &st);
		if (rc == KOFA_ERR_GONE)
			continue;          /* exited while we walked. Normal. */
		/*
		 * A stat that could not be opened or read for a reason that is not
		 * the process's - no descriptor left, no memory, an I/O error - is
		 * "never looked at", the same state as a refusal, and is listed as
		 * one whatever want_refused says: that option filters the
		 * processes the system refused us, not the ones the walk failed to
		 * read. Dropping them was a walk under RLIMIT_NOFILE listing 0 of 29
		 * processes. A malformed stat text (io_err clear) is still skipped.
		 */
		if (rc == KOFA_ERR_DENIED || (rc == KOFA_ERR_OS && st.io_err)) {
			if (rc == KOFA_ERR_DENIED && !l->o.want_refused)
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
			kofa_read_exe(out->pid, l->exe, sizeof l->exe,
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
		out->environ_len = 0;
		if (!l->o.no_environ && !(out->flags & KOFA_PF_KERNEL))
			out->environ_len =
				(uint32_t)a_read_environ(out->pid, l->environ,
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
