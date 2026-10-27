/*
 * orbit_sys.c - the wraps behind tests/lib/orbit_sys.h. Include this file in ONE translation unit of a binary linked with
 * ORBIT_SYS_WRAP. Global state here is the TEST's (a fake OS is one by nature); the library under test has none.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <pwd.h>
#include <semaphore.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "orbit_sys.h"

int __real_open(const char *path, int flags, ...);
FILE *__real_fopen(const char *path, const char *mode);
DIR *__real_opendir(const char *path);
ssize_t __real_readlink(const char *path, char *buf, size_t n);
int __real_access(const char *path, int mode);
int __real_stat(const char *path, struct stat *st);
int __real_lstat(const char *path, struct stat *st);
ssize_t __real_pread(int fd, void *buf, size_t n, off_t off);
ssize_t __real_process_vm_readv(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
				unsigned long rn, unsigned long flags);
int __real_socket(int domain, int type, int protocol);
int __real_bind(int fd, const struct sockaddr *sa, socklen_t len);
ssize_t __real_recv(int fd, void *buf, size_t n, int flags);
int __real_poll(struct pollfd *fds, nfds_t n, int timeout);
int __real_mkdir(const char *path, mode_t mode);
int __real_rename(const char *from, const char *to);
int __real_fanotify_init(unsigned flags, unsigned event_f_flags);
int __real_fanotify_mark(int fd, unsigned flags, uint64_t mask, int dirfd, const char *path);
int __real_open_by_handle_at(int mount_fd, struct file_handle *h, int flags);
pid_t __real_fork(void);
int __real_shm_open(const char *name, int oflag, mode_t mode);
int __real_ftruncate(int fd, off_t len);
sem_t *__real_sem_open(const char *name, int oflag, ...);
int __real_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);

#define OSYS_VMS 8

static struct {
	char root[512];
	int  proc_on;
	char match[128];
	struct { unsigned nth; unsigned cur; int err; int from; } inj[OSYS_N];
	unsigned long calls[OSYS_N];
	char enospc[128];
	int  nl_on, nl_deny, nl_fd, nl_peer;
	int  fan_on, fan_full, fan_fd, fan_peer;
	char fan_refuse[128];
	char obh[512];
	char home[512];
	int  fake_fork;
	unsigned char nl_pre[8][256];
	size_t nl_pre_n[8];
	unsigned n_pre;
	struct { uint32_t pid; uint64_t base; const unsigned char *p; size_t n; } vm[OSYS_VMS];
} osys = { .fan_full = 1 };

/* bounded copies: a fixture path longer than the field is cut, never overflows */
static void cp(char *to, size_t cap, const char *from)
{
	size_t n = from ? strlen(from) : 0;

	if (n >= cap)
		n = cap - 1;
	if (n)
		memcpy(to, from, n);
	to[n] = '\0';
}

void osys_reset(void)
{
	/* the test's ends only: the library closes its own, and closing a number twice would hit whatever reused it */
	if (osys.nl_peer > 0)
		close(osys.nl_peer);
	if (osys.fan_peer > 0)
		close(osys.fan_peer);
	memset(&osys, 0, sizeof osys);
	osys.fan_full = 1;
}

void osys_proc_root(const char *dir)
{
	if (!dir) {
		osys.proc_on = 0;
		return;
	}
	cp(osys.root, sizeof osys.root, dir);
	osys.proc_on = 1;
}

void osys_match(const char *text) { cp(osys.match, sizeof osys.match, text); }

void osys_fail(enum osys_fn fn, unsigned nth, int err)
{
	osys.inj[fn].nth = nth;
	osys.inj[fn].cur = 0;
	osys.inj[fn].err = err;
	osys.inj[fn].from = 0;
}

void osys_fail_from(enum osys_fn fn, unsigned nth, int err)
{
	osys_fail(fn, nth, err);
	osys.inj[fn].from = 1;
}

unsigned long osys_calls(enum osys_fn fn) { return osys.calls[fn]; }
void osys_enospc(const char *text) { cp(osys.enospc, sizeof osys.enospc, text); }
void osys_nl(int on) { osys.nl_on = on; }
void osys_nl_deny(int err) { osys.nl_deny = err; }
int  osys_nl_peer(void) { return osys.nl_peer; }

void osys_nl_preload(const void *d, size_t n)
{
	if (osys.n_pre < 8 && n <= 256) {
		memcpy(osys.nl_pre[osys.n_pre], d, n);
		osys.nl_pre_n[osys.n_pre++] = n;
	}
}
void osys_fan(int on) { osys.fan_on = on; }
void osys_fan_full(int allowed) { osys.fan_full = allowed; }
void osys_fan_refuse(const char *t) { cp(osys.fan_refuse, sizeof osys.fan_refuse, t); }
int  osys_fan_peer(void) { return osys.fan_peer; }

void osys_fork(int fake) { osys.fake_fork = fake; }
void osys_home(const char *dir) { cp(osys.home, sizeof osys.home, dir); }
void osys_obh_dir(const char *dir) { cp(osys.obh, sizeof osys.obh, dir); }

void osys_vm_set(uint32_t pid, uint64_t base, const void *bytes, size_t n)
{
	int i;

	for (i = 0; i < OSYS_VMS; i++)
		if (!osys.vm[i].pid || (osys.vm[i].pid == pid && osys.vm[i].base == base)) {
			osys.vm[i].pid = pid;
			osys.vm[i].base = base;
			osys.vm[i].p = bytes;
			osys.vm[i].n = n;
			return;
		}
}

/* Count this call and say whether it fails; sets errno when it does. `path` may be NULL (an fd-based call). */
static int osys_hit(enum osys_fn fn, const char *path)
{
	if (path && osys.match[0] && !strstr(path, osys.match))
		return 0;
	osys.calls[fn]++;
	if (!osys.inj[fn].nth)
		return 0;
	osys.inj[fn].cur++;
	if (osys.inj[fn].cur == osys.inj[fn].nth || (osys.inj[fn].from && osys.inj[fn].cur > osys.inj[fn].nth)) {
		errno = osys.inj[fn].err;
		return 1;
	}
	return 0;
}

/* "/proc" itself and "/proc/<digits>..." go to the fixture root while it is on ("/proc/self", "/proc/net" stay real: the
 * library resolves its own descriptors through /proc/self/fd). */
static const char *osys_rd(const char *p, char *buf, size_t cap)
{
	if (!osys.proc_on || !p || strncmp(p, "/proc", 5) || (p[5] && p[5] != '/') || (p[5] == '/' && p[6] && (p[6] < '0' || p[6] > '9')))
		return p;
	snprintf(buf, cap, "%s%s", osys.root, p + 5);
	return buf;
}

static int osys_wr_flags(int flags) { return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0; }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

int __wrap_open(const char *path, int flags, ...)
{
	char b[1024];
	mode_t mode = 0;
	const char *p = osys_rd(path, b, sizeof b);

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;

		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (osys_hit(OSYS_OPEN, path))
		return -1;
	if (osys.enospc[0] && path && strstr(path, osys.enospc) && osys_wr_flags(flags))
		return __real_open("/dev/full", O_WRONLY | (flags & O_CLOEXEC));
	return __real_open(p, flags, mode);
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_FOPEN, path))
		return NULL;
	if (osys.enospc[0] && path && strstr(path, osys.enospc) && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')))
		return __real_fopen("/dev/full", "w");
	return __real_fopen(p, mode);
}

DIR *__wrap_opendir(const char *path)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_OPENDIR, path))
		return NULL;
	return __real_opendir(p);
}

ssize_t __wrap_readlink(const char *path, char *buf, size_t n)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_READLINK, path))
		return -1;
	return __real_readlink(p, buf, n);
}

int __wrap_access(const char *path, int mode)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_ACCESS, path))
		return -1;
	return __real_access(p, mode);
}

int __wrap_stat(const char *path, struct stat *st)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_STAT, path))
		return -1;
	return __real_stat(p, st);
}

int __wrap_lstat(const char *path, struct stat *st)
{
	char b[1024];
	const char *p = osys_rd(path, b, sizeof b);

	if (osys_hit(OSYS_LSTAT, path))
		return -1;
	return __real_lstat(p, st);
}

ssize_t __wrap_pread(int fd, void *buf, size_t n, off_t off)
{
	if (osys_hit(OSYS_PREAD, NULL))
		return -1;
	return __real_pread(fd, buf, n, off);
}

ssize_t __wrap_process_vm_readv(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
				unsigned long rn, unsigned long flags)
{
	int i;

	if (osys_hit(OSYS_VM, NULL))
		return -1;
	{
		int known = 0;

		for (i = 0; i < OSYS_VMS; i++)
			if (osys.vm[i].pid && osys.vm[i].pid == (uint32_t)pid && ln == 1 && rn == 1) {
				uint64_t a = (uint64_t)(uintptr_t)r[0].iov_base;
				size_t n = r[0].iov_len;

				known = 1;
				if (a < osys.vm[i].base || a - osys.vm[i].base >= osys.vm[i].n)
					continue;              /* another range of the same process may hold it */
				if (n > osys.vm[i].n - (a - osys.vm[i].base))      /* a short copy, as the kernel does at the end of a mapping */
					n = osys.vm[i].n - (size_t)(a - osys.vm[i].base);
				if (n > l[0].iov_len)
					n = l[0].iov_len;
				memcpy(l[0].iov_base, osys.vm[i].p + (a - osys.vm[i].base), n);
				return (ssize_t)n;
			}
		if (known) {
			errno = EFAULT;
			return -1;
		}
	}
	return __real_process_vm_readv(pid, l, ln, r, rn, flags);
}

int __wrap_socket(int domain, int type, int protocol)
{
	if (osys_hit(OSYS_SOCKET, NULL))
		return -1;
	if (domain == AF_NETLINK && osys.nl_deny) {
		errno = osys.nl_deny;
		return -1;
	}
	if (domain == AF_NETLINK && osys.nl_on) {
		int sv[2];

		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv))
			return -1;
		osys.nl_fd = sv[0];
		osys.nl_peer = sv[1];
		{
			unsigned i;

			for (i = 0; i < osys.n_pre; i++)
				(void)write(sv[1], osys.nl_pre[i], osys.nl_pre_n[i]);
		}
		return sv[0];
	}
	return __real_socket(domain, type, protocol);
}

int __wrap_bind(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (osys_hit(OSYS_BIND, NULL))
		return -1;
	if (osys.nl_on && fd == osys.nl_fd)
		return 0;
	return __real_bind(fd, sa, len);
}

ssize_t __wrap_recv(int fd, void *buf, size_t n, int flags)
{
	if (osys_hit(OSYS_RECV, NULL))
		return -1;
	return __real_recv(fd, buf, n, flags);
}

int __wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	if (osys_hit(OSYS_POLL, NULL))
		return -1;
	return __real_poll(fds, n, timeout);
}

int __wrap_mkdir(const char *path, mode_t mode)
{
	if (osys_hit(OSYS_MKDIR, path))
		return -1;
	return __real_mkdir(path, mode);
}

int __wrap_rename(const char *from, const char *to)
{
	if (osys_hit(OSYS_RENAME, to))
		return -1;
	return __real_rename(from, to);
}

int __wrap_fanotify_init(unsigned flags, unsigned event_f_flags)
{
	int sv[2];

	if (osys_hit(OSYS_FANINIT, NULL))
		return -1;
	if (!osys.fan_on)
		return __real_fanotify_init(flags, event_f_flags);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv))
		return -1;
	osys.fan_fd = sv[0];
	osys.fan_peer = sv[1];
	return sv[0];
}

int __wrap_fanotify_mark(int fd, unsigned flags, uint64_t mask, int dirfd, const char *path)
{
	if (osys_hit(OSYS_FANMARK, NULL))
		return -1;
	if (osys.fan_on && fd == osys.fan_fd) {
		if (!osys.fan_full && path && !strcmp(path, "/")) {
			errno = EPERM;
			return -1;
		}
		if (osys.fan_refuse[0] && path && strstr(path, osys.fan_refuse)) {
			errno = EPERM;
			return -1;
		}
		return 0;
	}
	return __real_fanotify_mark(fd, flags, mask, dirfd, path);
}

pid_t __wrap_fork(void)
{
	return osys.fake_fork ? (pid_t)2000000000 : __real_fork();
}

int __wrap_shm_open(const char *name, int oflag, mode_t mode)
{
	if (osys_hit(OSYS_SHMOPEN, name))
		return -1;
	return __real_shm_open(name, oflag, mode);
}

int __wrap_ftruncate(int fd, off_t len)
{
	if (osys_hit(OSYS_FTRUNC, NULL))
		return -1;
	return __real_ftruncate(fd, len);
}

sem_t *__wrap_sem_open(const char *name, int oflag, ...)
{
	mode_t mode = 0;
	unsigned value = 0;

	if (osys_hit(OSYS_SEMOPEN, name))
		return SEM_FAILED;
	if (oflag & O_CREAT) {
		va_list ap;

		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		value = va_arg(ap, unsigned);
		va_end(ap);
		return __real_sem_open(name, oflag, mode, value);
	}
	return __real_sem_open(name, oflag);
}

int __wrap_getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
	int rc = __real_getpwuid_r(uid, pwd, buf, buflen, result);

	/* the home directory only: the name, the uid and the gid stay the real ones. The string lives in the caller's buffer. */
	if (rc == 0 && *result && osys.home[0] && uid == getuid() && strlen(osys.home) + 1 <= buflen) {
		size_t used = strlen(pwd->pw_name) + strlen(pwd->pw_passwd) + strlen(pwd->pw_gecos) + strlen(pwd->pw_shell) + 5u;

		if (used + strlen(osys.home) + 1 <= buflen) {
			char *at = buf + buflen - strlen(osys.home) - 1u;

			memcpy(at, osys.home, strlen(osys.home) + 1);
			pwd->pw_dir = at;
		}
	}
	return rc;
}

int __wrap_open_by_handle_at(int mount_fd, struct file_handle *h, int flags)
{
	if (osys_hit(OSYS_OBH, NULL))
		return -1;
	if (osys.obh[0])
		return __real_open(osys.obh, O_PATH | O_DIRECTORY | O_CLOEXEC);
	return __real_open_by_handle_at(mount_fd, h, flags);
}

#pragma GCC diagnostic pop

/* ---- fixtures ---------------------------------------------------------------------------------------------- */

char *osys_tmpdir(const char *name)
{
	char t[512], cwd[256], *r;

	if (!getcwd(cwd, sizeof cwd))
		return NULL;
	snprintf(t, sizeof t, "%s/build/kof_%s_XXXXXX", cwd, name);
	if (!mkdtemp(t))
		return NULL;
	r = strdup(t);
	return r;
}

static int rm_cb(const char *p, const struct stat *sb, int type, struct FTW *f)
{
	(void)sb;
	(void)type;
	(void)f;
	return remove(p);
}

void osys_rmrf(const char *dir)
{
	if (dir && dir[0])
		(void)nftw(dir, rm_cb, 32, FTW_DEPTH | FTW_PHYS);
}

static void mkparents(const char *path)
{
	char b[1024], *s;

	snprintf(b, sizeof b, "%s", path);
	for (s = b + 1; *s; s++)
		if (*s == '/') {
			*s = '\0';
			(void)__real_mkdir(b, 0755);
			*s = '/';
		}
}

int osys_put_flat(const char *dir, const char *rel, const void *data, size_t n)
{
	char p[1024];
	int fd;

	snprintf(p, sizeof p, "%s/%s", dir, rel);
	mkparents(p);
	fd = __real_open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;
	if (n && write(fd, data, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	return close(fd);
}

int osys_put(const char *root, uint32_t pid, const char *rel, const void *data, size_t n)
{
	char r[512];

	snprintf(r, sizeof r, "%u/%s", (unsigned)pid, rel);
	return osys_put_flat(root, r, data, n);
}

int osys_link(const char *root, uint32_t pid, const char *rel, const char *target)
{
	char p[1024];

	snprintf(p, sizeof p, "%s/%u/%s", root, (unsigned)pid, rel);
	mkparents(p);
	(void)unlink(p);
	return symlink(target, p);
}
