/*
 * orbit/sys - the fake operating system (tests/lib/orbit_sys.c) is linked into this binary through this one translation unit;
 * the adapters see it through orbit_fx.h. Nothing is registered here.
 */
#include "orbit_fx.h"
#include "../../lib/orbit_sys.c"

#include <sys/stat.h>

/* The scratch directory of the process, made on first use under build/ (never /tmp) and shared by the adapters. */
char *ofx_dir(void)
{
	static char *d;

	if (!d)
		d = osys_tmpdir("fuzz_orbit");
	return d;
}

/* A memfd holding the bytes, and the path that names it ("/proc/self/fd/N" is not redirected by the fake). */
int ofx_memfd(const uint8_t *p, size_t n, char *path, size_t cap)
{
	int fd = memfd_create("orbit", MFD_CLOEXEC);

	if (fd < 0)
		return -1;
	if (n && write(fd, p, n) != (ssize_t)n) {
		close(fd);
		return -1;
	}
	snprintf(path, cap, "/proc/self/fd/%d", fd);
	return fd;
}
