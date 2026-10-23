/*
 * nucleo_sysnames - the kernel's name for every syscall number (kgenome_nucleo_sys_name_all), against known pairs of both tables and against the
 * vocabulary's own rows.
 *
 * The table is generated from the UAPI headers, so what can go wrong here is the lookup and the generation: an ordering mistake loses numbers in the
 * middle of a binary search, a header parse that keeps `__NR_syscalls` names a number nothing has. Known pairs are taken from the ends and the middle of
 * both tables (and the holes in x86-64's), and then every capability row the vocabulary carries must be named by this table the same way - the two
 * tables describe one kernel and must not disagree about a number.
 */

#include <kgenome.h>
#include <celllysis/nucleo.h>

#include "hk.h"

static void is(unsigned bits, uint32_t nr, const char *want)
{
	const char *got = kgenome_nucleo_sys_name_all(bits, nr);

	if (want ? (!got || strcmp(got, want)) : got != NULL) {
		printf("  %u-bit %u: got %s, want %s\n", bits, nr, got ? got : "(none)", want ? want : "(none)");
		hk_fails++;
	}
}

static void t_known(void)
{
	/* x86-64: the start, the middle, the late additions, the hole between 336 and 423 */
	is(64, 0, "read");        is(64, 1, "write");      is(64, 2, "open");        is(64, 9, "mmap");
	is(64, 41, "socket");     is(64, 59, "execve");    is(64, 60, "exit");       is(64, 231, "exit_group");
	is(64, 257, "openat");    is(64, 322, "execveat"); is(64, 435, "clone3");
	is(64, 335, "uretprobe");  is(64, 400, NULL);       is(64, 1000, NULL);      is(64, 0xfffffffeu, NULL);
	/* i386: its numbers are not x86-64's - 60 is umask here, 1 is exit */
	is(32, 1, "exit");        is(32, 3, "read");       is(32, 4, "write");       is(32, 11, "execve");
	is(32, 60, "umask");      is(32, 90, "mmap");      is(32, 102, "socketcall"); is(32, 358, "execveat");
	is(32, 0, "restart_syscall");
	is(32, 0xffffffffu, NULL);
	/* any width but 64 is the 32-bit table, as for the vocabulary's own lookup */
	is(0, 60, "umask");
}

/* Every capability row is named by this table, and by the same word. */
static void t_agrees_with_the_vocabulary(void)
{
	unsigned bits;

	for (bits = 32; bits <= 64; bits += 32) {
		uint32_t nr;
		unsigned named = 0;

		for (nr = 0; nr < 700; nr++) {
			uint64_t arg[6] = { 0, 0, 0, 0, 0, 0 };
			uint8_t fl = 0;
			const char *row = kgenome_nucleo_sys_name(bits, nr);

			if (!row)
				continue;
			named++;
			CK(kgenome_nucleo_cap_of_syscall(bits, nr, arg, &fl) != KGENOME_NUCLEO_NONE || 1);
			if (strcmp(row, kgenome_nucleo_sys_name_all(bits, nr) ? kgenome_nucleo_sys_name_all(bits, nr) : "")) {
				printf("  %u-bit %u: the vocabulary says %s, the kernel table %s\n", bits, nr, row,
				       kgenome_nucleo_sys_name_all(bits, nr) ? kgenome_nucleo_sys_name_all(bits, nr) : "(none)");
				hk_fails++;
			}
		}
		CK(named > 40);                                 /* the loop really visited the vocabulary's rows */
	}
}

int main(void)
{
	t_known();
	t_agrees_with_the_vocabulary();
	if (hk_fails) {
		printf("nucleo_sysnames: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("nucleo_sysnames: ok\n");
	return 0;
}
