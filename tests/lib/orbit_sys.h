/*
 * orbit_sys.h - a fake operating system for the libkoforbit collectors, by LINK-TIME WRAPS.
 *
 * aproc.c, aproc_pmem.c, apagemap.c, apev.c and afan.c name /proc/<pid>/..., the process connector and fanotify in their
 * own source, with no root to inject. The library has no seam for that and none is added (owner, 2026-10-23): the test
 * binary is linked with -Wl,--wrap=open,fopen,... (ORBIT_SYS_WRAP below) and tests/lib/orbit_sys.c answers instead.
 * Include that .c file in ONE translation unit of a binary (a unit test, or tests/fuzz/orbit/sys.c) and pass the flags.
 *
 *   /proc          osys_proc_root(dir) sends "/proc" and "/proc/..." to dir/... : the fixture is real files, links,
 *                  FIFOs and sparse files that the test makes with osys_put / osys_link; opendir("/proc") lists dir.
 *                  NULL turns the redirect off (the real /proc again).
 *   failure        osys_fail(fn, nth, err): the nth call of fn from now (1 = the next) fails with errno err and the call
 *                  after it works; osys_fail_from(fn, nth, err): every call from the nth on. A path filter
 *                  (osys_match) limits counting and failing to paths that contain the text, so the test's own calls to the
 *                  same function are not hit. fn is one of the OSYS_* ids.
 *   disk full      osys_enospc(text): open / fopen of a path containing text for writing is answered with /dev/full:
 *                  the kernel's own ENOSPC on the first write, with the stdio error state and the short count a real
 *                  full disk gives.
 *   netlink        osys_nl(1): socket(PF_NETLINK, ..., NETLINK_CONNECTOR) returns one end of a datagram socketpair and
 *                  bind succeeds on it; osys_nl_peer() is the other end, where the test writes what "the kernel" sends
 *                  (and reads what the library sent); osys_nl_preload queues a datagram at creation, which is how the
 *                  open's probe (a fork the library makes itself) gets the record it waits for. osys_nl_deny(err): the
 *                  socket call fails with err.
 *   fanotify       osys_fan(1): fanotify_init returns one end of a SEQPACKET socketpair (a read returns one record, as
 *                  fanotify's does), fanotify_mark succeeds; osys_fan_full(0) refuses the filesystem-wide mark with
 *                  EPERM (the unprivileged case, degraded mode); osys_fan_peer() is the test's end.
 *   handles        osys_obh_dir(dir): open_by_handle_at (a privileged call) returns a descriptor on dir, so the
 *                  handle-to-path cache of afan.c runs unprivileged.
 *   fork           osys_fork(1): the open probe of apev.c forks a child only to make the kernel send a record; with the fake
 *                  connector the record is already queued, so the fork is answered without making a process.
 *   home           osys_home(dir): the passwd entry of this user says its home is dir (the cache path is built from it).
 *   other process  osys_vm_set(pid, base, bytes, n): process_vm_readv for that pid is served from the test's buffer.
 */
#ifndef KOF_TESTS_ORBIT_SYS_H
#define KOF_TESTS_ORBIT_SYS_H

#include <stddef.h>
#include <stdint.h>

enum osys_fn {
	OSYS_OPEN = 0, OSYS_FOPEN, OSYS_OPENDIR, OSYS_READLINK, OSYS_ACCESS, OSYS_STAT, OSYS_LSTAT, OSYS_PREAD,
	OSYS_VM, OSYS_SOCKET, OSYS_BIND, OSYS_RECV, OSYS_POLL, OSYS_MKDIR, OSYS_RENAME, OSYS_FANINIT, OSYS_FANMARK, OSYS_OBH, OSYS_SHMOPEN, OSYS_FTRUNC, OSYS_SEMOPEN,
	OSYS_N
};

#define ORBIT_SYS_WRAP \
	"-Wl,--wrap=open -Wl,--wrap=fopen -Wl,--wrap=opendir -Wl,--wrap=readlink -Wl,--wrap=access -Wl,--wrap=stat " \
	"-Wl,--wrap=lstat -Wl,--wrap=pread -Wl,--wrap=process_vm_readv -Wl,--wrap=socket -Wl,--wrap=bind " \
	"-Wl,--wrap=recv -Wl,--wrap=poll -Wl,--wrap=mkdir -Wl,--wrap=rename -Wl,--wrap=fanotify_init " \
	"-Wl,--wrap=fanotify_mark -Wl,--wrap=open_by_handle_at -Wl,--wrap=getpwuid_r -Wl,--wrap=shm_open -Wl,--wrap=ftruncate -Wl,--wrap=sem_open -Wl,--wrap=fork"

void osys_reset(void);                                      /* everything off, counters zero */
void osys_proc_root(const char *dir);
void osys_match(const char *text);                          /* NULL or "" = every path */
void osys_fail(enum osys_fn fn, unsigned nth, int err);
void osys_fail_from(enum osys_fn fn, unsigned nth, int err);
unsigned long osys_calls(enum osys_fn fn);                  /* calls counted since the last reset (all paths) */
void osys_enospc(const char *text);
void osys_nl(int on);
void osys_nl_deny(int err);
int  osys_nl_peer(void);
void osys_nl_preload(const void *datagram, size_t n);        /* written to the peer end the moment the socket is made (up to 8) */
void osys_fan(int on);
void osys_fan_full(int allowed);
void osys_fan_refuse(const char *path_text);                /* fanotify_mark of a path containing this fails EPERM */
int  osys_fan_peer(void);
void osys_fork(int fake);                                    /* fork() answers a pid that is nobody's and makes no child (the connector's open probe forks) */
void osys_home(const char *dir);                            /* getpwuid_r answers pw_dir = dir for the current uid (NULL: the real passwd) */
void osys_obh_dir(const char *dir);                         /* open_by_handle_at answers an O_PATH fd on this directory (NULL: the real call) */
void osys_vm_set(uint32_t pid, uint64_t base, const void *bytes, size_t n);

/* ---- fixture helpers (real files under a scratch root; no fake in them) ---- */
char *osys_tmpdir(const char *name);                        /* "build/kof_<name>_XXXXXX", made; malloc'd */
void  osys_rmrf(const char *dir);
int   osys_put(const char *root, uint32_t pid, const char *rel, const void *data, size_t n);   /* root/pid/rel, parents made */
int   osys_link(const char *root, uint32_t pid, const char *rel, const char *target);
int   osys_put_flat(const char *dir, const char *rel, const void *data, size_t n);            /* dir/rel */

#endif
