/* See nucleo.h. The syscall half: the numbering of each ABI and what a number means. */

#include "nucleo_private.h"

#include <string.h>

/*
 * WHAT A SYSCALL NUMBER MEANS, per ABI.
 *
 * Two tables and not one: i386 and x86-64 Linux do not share a numbering, and
 * a table that pretended they did would report `read` for `write` on half the
 * samples. Only the numbers a stager uses are here - this is a capability
 * reader, not a strace.
 */
/*
 * The roles are nucleo.h's - see KGENOME_NUCLEO_ROLE_NONE. Naming them in the
 * table rather than re-listing the numbers in the pass that needs them is
 * what keeps "4183 is socket" written down exactly once.
 */
/*
 * ONE ROW PER SYSCALL THE VOCABULARY HAS A WORD FOR.
 *
 * AND THE NAME IS HERE, not in whatever is displaying the result. A chain
 * step read from a syscall used to carry only the NUMBER, so a page showed
 * `syscall_9` and a reader had to know that 9 is mmap on x86-64 and link on
 * i386. The number means nothing without the table that resolved it, and
 * this is that table - so the name travels with the answer and the same
 * word comes out wherever it is read.
 */

/* A table and its length: the length is the table's own, so no second number
 * can drift from it. */
#define SYSTAB_N(t) ((uint32_t)(sizeof kgenome_nucleo_##t / sizeof kgenome_nucleo_##t[0]))

/* Linux x86-64. */
/*
 * NOTES THAT STOOD BETWEEN THE ROWS OF THE TABLE BELOW, kept whole. It is in
 * number order now, which no group of rows survives, so they are not beside the
 * rows they were about.
 *
 *
 * THE REST OF THE READ AND WRITE FAMILY, which was simply absent.
 *
 * A table holding read and write and not readv or pread describes a
 * program nobody writes: the vectored and positional forms are what a
 * runtime actually emits, and a stager that uses one was invisible -
 * not misclassified, invisible. They take a descriptor like read does
 * and say no more about it than read does, so they take the same word.
 *
 * sendfile and splice move bytes between TWO descriptors without the
 * program seeing them. Read as mem-read because that is what is known;
 * the second descriptor is an argument, and an argument is where that
 * belongs rather than in a word.
 *
 * AND THE REST OF WHAT A PROGRAM CAN ASK FOR. Numbers read out of
 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this machine
 * rather than remembered, because a wrong one here is not a missed
 * detection - it is a confident wrong name on whatever syscall does
 * hold the number.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys64[] = {
	{     0, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{     1, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{     2, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{   9, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see prot_cap */
	{  10, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{    17, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "pread64"  },
	{    18, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "pwrite64"  },
	{    19, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "readv"  },
	{    20, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "writev"  },
	{  22, KGENOME_NUCLEO_PIPE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "pipe"  },
	{  33, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup2"  },
	{   35, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{    40, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "sendfile"  },
	{  41, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{   42, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{   43, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{   44, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{   45, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{    46, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendmsg"  },
	{    47, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvmsg"  },
	{  53, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_NONE, "socketpair"  },
	{  56, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{   57, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{   58, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "vfork"  },
	{   59, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{  82, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "rename"  },
	{  87, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlink"  },
	{  90, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "chmod"  },
	{  91, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmod"  },
	{ 101, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{ 105, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setuid"  },
	{ 106, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setgid"  },
	{ 113, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setreuid"  },
	{ 117, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setresuid"  },
	{ 132, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utime"  },
	{ 155, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "pivot_root"  },
	{ 161, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "chroot"  },
	{ 175, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "init_module"  },
	{ 176, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "delete_module"  },
	{ 235, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimes"  },
	{ 257, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{ 261, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "futimesat"  },
	{ 263, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlinkat"  },
	{ 264, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat"  },
	{ 268, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmodat"  },
	{ 272, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "unshare"  },
	{   275, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "splice"  },
	{ 280, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimensat"  },
	{ 292, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup3"  },
	{   295, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "preadv"  },
	{   296, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "pwritev"  },
	{ 308, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "setns"  },
	{ 310, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_readv"  },
	{ 311, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_writev"  },
	{ 313, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "finit_module"  },
	{ 316, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat2"  },
	{ 319, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  },
	{ 321, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "bpf"  },
	{ 322, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execveat"  },
	{   327, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "preadv2"  },
	{   328, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "pwritev2"  }
};

/* Linux i386. */
/*
 * NOTES THAT STOOD BETWEEN THE ROWS OF THE TABLE BELOW, kept whole. It is in
 * number order now, which no group of rows survives, so they are not beside the
 * rows they were about.
 *
 * The same list on i386, from asm/unistd_32.h and NOT by subtracting
 * anything from the table above - the two numberings are unrelated. 
 *
 * The same family on i386 - see the note in the amd64 table. 
 *
 */
static const struct kgenome_sysrow kgenome_nucleo_sys32[] = {
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{  10, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlink"  },
	{   11, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{  15, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "chmod"  },
	{  23, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setuid"  },
	{  26, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{  30, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utime"  },
	{  38, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "rename"  },
	{  42, KGENOME_NUCLEO_PIPE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "pipe"  },
	{  46, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setgid"  },
	{  61, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "chroot"  },
	{  63, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup2"  },
	{  70, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setreuid"  },
	{  90, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },
	{  94, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmod"  },
	{ 102, KGENOME_NUCLEO_NONE, KGENOME_NUCLEO_ROLE_NONE, "socketcall"  },         /* socketcall - the sub-call is in ebx */
	{ 120, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{ 125, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },
	{ 128, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "init_module"  },
	{ 129, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "delete_module"  },
	{   145, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "readv"  },
	{   146, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "writev"  },
	{ 162, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{ 164, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setresuid"  },
	{   180, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "pread64"  },
	{   181, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "pwrite64"  },
	{   187, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "sendfile"  },
	{ 192, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap2"  },
	{ 217, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "pivot_root"  },
	{   239, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "sendfile64"  },
	{ 271, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimes"  },
	{ 295, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{ 299, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "futimesat"  },
	{ 301, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlinkat"  },
	{ 302, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat"  },
	{ 306, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmodat"  },
	{ 310, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "unshare"  },
	{   313, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "splice"  },
	{ 320, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimensat"  },
	{ 330, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup3"  },
	{   333, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "preadv"  },
	{   334, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "pwritev"  },
	{ 346, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "setns"  },
	{ 347, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_readv"  },
	{ 348, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_writev"  },
	{ 350, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "finit_module"  },
	{ 353, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat2"  },
	{ 356, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  },
	{ 357, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "bpf"  },
	{ 358, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execveat"  }
};

/* i386 multiplexes every socket operation through socketcall, with the
 * operation in ebx. Left as its own table rather than folded into the one
 * above, because it is a different axis and merging them would need a second
 * key nothing else uses. */
static const struct kgenome_sysrow kgenome_nucleo_sockcall[] = {
	{  1, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket" },
	{  2, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind" },
	{  3, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect" },
	{  4, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen" },
	{  5, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept" },
	{  9, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "send" },
	{ 10, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recv" },
	{ 11, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto" },
	{ 12, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom" }
};


/* The row of `t` for syscall `nr`, or NULL. One search; a caller reads the field
 * it wants (cap, name, role) from the row, so there is no per-field twin.
 *
 * EVERY TABLE BELOW IS IN ASCENDING NUMBER ORDER AND HOLDS EACH NUMBER ONCE, and
 * that is what lets this be a binary search: it was a scan from the top, 482000
 * times in a 5 MB static binary (the wrapper walk asks per call of a wrapper),
 * 9% of its instructions. kgenome_nucleo_sys_ordered says it, and a test holds it. */
static const struct kgenome_sysrow *kgenome_nucleo_sys_row(const struct kgenome_sysrow *t,
					     uint32_t n, uint32_t nr)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (t[mid].nr < nr)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < n && t[lo].nr == nr ? &t[lo] : NULL;
}


/*
 * The syscall half of the vocabulary, for a caller that has a RUN rather
 * than code. Exported rather than copied for the reason at the head of
 * nucleo.h: a second table is a second thing to keep right.
 */
/*
 * fcntl(fd, F_SETFL, ... | O_NONBLOCK) and setsockopt(fd, IPPROTO_IP,
 * IP_HDRINCL, ..): the two option calls whose arguments are a claim.
 * O_NONBLOCK is 04000 on Linux for x86 and x86-64 alike; F_SETFL is 4;
 * IPPROTO_IP is 0 and IP_HDRINCL is 3. The number of the call is the only
 * thing that differs between the two machines: x86-64 fcntl 72 and setsockopt
 * 54; i386 fcntl 55, fcntl64 221 and, on kernels that have it, a direct
 * setsockopt 366 (older ones go through socketcall, whose arguments are in
 * memory and are not read here).
 */
#define FLOW_F_SETFL      4u
#define FLOW_O_NONBLOCK   0x800u
#define FLOW_IPPROTO_IP   0u
#define FLOW_IP_HDRINCL   3u

/*
 * AN ARGUMENT THAT IS A SET OF FLAGS, where knowing that one bit is SET is the
 * whole claim: F_SETFL's third argument is `flags | O_NONBLOCK`, and the
 * `flags` half is what F_GETFL returned, which no static walk knows. A caller
 * that tracks "these bits are set, the rest unknown" may hand that value to
 * kgenome_nucleo_cap_of_syscall for these arguments and no others: for a length or a
 * protection a partly-known number is a wrong number.
 */
int kgenome_nucleo_arg_is_flags(unsigned bits, uint32_t nr, unsigned idx)
{
	int is_fcntl = bits == 32 ? (nr == 55u || nr == 221u) : nr == 72u;

	return is_fcntl && idx == 2u;
}

/*
 * A SOCKET THAT IS MADE NON-BLOCKING IN THE CALL THAT MAKES IT: the type
 * argument carries SOCK_NONBLOCK (04000, the same bit as O_NONBLOCK). It says
 * the same thing as an fcntl afterwards, and a program that uses it never calls
 * fcntl, so the vocabulary cannot ask only for the fcntl - MEASURED, 50 of 400
 * x86 and 73 of 388 x86-64 Bazaar files had a connect and a non-blocking socket
 * and no fcntl node to say so. The caller makes a second node for it.
 */
int kgenome_nucleo_sock_nonblock(unsigned bits, uint32_t nr, const uint64_t *arg,
			   unsigned have)
{
	int is_socket = bits == 32 ? nr == 359u : nr == 41u;

	return is_socket && (have & 2u) && (arg[1] & FLOW_O_NONBLOCK);
}

int kgenome_nucleo_sockcall_nonblock(uint32_t sub, const uint64_t *arg, unsigned have)
{
	return sub == 1u && (have & 2u) && (arg[1] & FLOW_O_NONBLOCK);
}

static uint16_t flow_opt_cap(unsigned bits, uint32_t nr, const uint64_t *arg)
{
	int is_fcntl = bits == 32 ? (nr == 55u || nr == 221u) : nr == 72u;
	int is_setsockopt = bits == 32 ? nr == 366u : nr == 54u;

	if (is_fcntl && (arg[1] & 0xffffffffu) == FLOW_F_SETFL &&
	    (arg[2] & FLOW_O_NONBLOCK))
		return KGENOME_NUCLEO_FD_NONBLOCK;
	if (is_setsockopt && (arg[1] & 0xffffffffu) == FLOW_IPPROTO_IP &&
	    (arg[2] & 0xffffffffu) == FLOW_IP_HDRINCL)
		return KGENOME_NUCLEO_NET_HDRINCL;
	return KGENOME_NUCLEO_NONE;
}

/*
 * THE CAPABILITY OF ONE OPERATION OF i386's socketcall, with the arguments that
 * were found in the array its second argument points at. `have` says which of
 * them were: a socket whose domain and type were not read is a socket of an
 * unknown kind and must not be refined from zeros.
 */
uint16_t kgenome_nucleo_cap_of_sockcall(uint32_t sub, const uint64_t *arg,
				  unsigned have, uint8_t *flags)
{
	const struct kgenome_sysrow *row = kgenome_nucleo_sys_row(kgenome_nucleo_sockcall,
							   SYSTAB_N(sockcall), sub);
	uint16_t cap = row ? row->cap : KGENOME_NUCLEO_NONE;

	if (flags)
		*flags = 0;
	if (cap == KGENOME_NUCLEO_NET_OPEN && sub == 1u && arg && (have & 3u) == 3u)
		return kgenome_nucleo_sock_kind(arg, flags);
	/* setsockopt(fd, level, optname, ...): the operation whose arguments are a
	 * claim - see flow_opt_cap for the numbers. */
	if (sub == 14u && arg && (have & 6u) == 6u &&
	    (arg[1] & 0xffffffffu) == FLOW_IPPROTO_IP &&
	    (arg[2] & 0xffffffffu) == FLOW_IP_HDRINCL)
		return KGENOME_NUCLEO_NET_HDRINCL;
	return cap;
}

uint16_t kgenome_nucleo_cap_of_syscall(unsigned bits, uint32_t nr,
				const uint64_t *arg, uint8_t *flags)
{
	const struct kgenome_sysrow *row;
	uint16_t cap;

	if (flags)
		*flags = 0;
	if (bits == 32) {
		/* socketcall multiplexes; the operation is the first argument
		 * and without it the number says only "something network". */
		if (nr == 102u) {
			if (!arg)
				return KGENOME_NUCLEO_NONE;
			row = kgenome_nucleo_sys_row(kgenome_nucleo_sockcall,
					      SYSTAB_N(sockcall),
					      (uint32_t)arg[0]);
			return row ? row->cap : KGENOME_NUCLEO_NONE;
		}
		row = kgenome_nucleo_sys_row(kgenome_nucleo_sys32, SYSTAB_N(sys32), nr);
	} else {
		row = kgenome_nucleo_sys_row(kgenome_nucleo_sys64, SYSTAB_N(sys64), nr);
	}
	cap = row ? row->cap : KGENOME_NUCLEO_NONE;
	/*
	 * PROT_EXEC, WHICH IS THE WHOLE DIFFERENCE between a buffer and a
	 * payload. Unlike the Windows side there is no guessing to do: mmap
	 * and mprotect both carry prot in the third argument, and i386's
	 * mmap2 and old_mmap do too.
	 */
	/* The same two refinements the sweep makes, from the arguments a run
	 * recorded instead of from a constant map. One rule, two readers. */
	if (arg && cap == KGENOME_NUCLEO_SPAWN &&
	    (bits == 32 ? nr == 120u : nr == 56u))
		return (arg[0] & KGENOME_NUCLEO_CLONE_THREAD) ? KGENOME_NUCLEO_THREAD
						    : KGENOME_NUCLEO_SPAWN;
	if (arg && cap == KGENOME_NUCLEO_NET_OPEN && bits != 32 && nr == 41u)
		return kgenome_nucleo_sock_kind(arg, flags);
	/*
	 * fcntl AND setsockopt ARE NOT WORDS HERE, only the two things they can
	 * say that a rule is entitled to build on - and only when the arguments
	 * that say it were read. A call whose cmd or level was not followed is
	 * not a node at all, which is the honest state: a node reading as
	 * "something with a descriptor" would be matched by nothing and mean
	 * nothing.
	 */
	if (arg && cap == KGENOME_NUCLEO_NONE)
		return flow_opt_cap(bits, nr, arg);
	if (cap == KGENOME_NUCLEO_ALLOC && arg) {
		int is_map = bits == 32 ? (nr == 90u || nr == 125u || nr == 192u)
					: (nr == 9u || nr == 10u);

		if (is_map && (arg[2] & 4u)) {         /* PROT_EXEC */
			/*
			 * W+X IS A DIFFERENT FACT FROM EXECUTABLE, and the
			 * note on KGENOME_NUCLEO_F_WX is the whole reason: a JIT
			 * asks for RW and flips to RX, so it is never both
			 * at once; a loader asks for RWX in one call. Both
			 * are ALLOC_EXEC and only the second is W+X.
			 */
			if (flags && (arg[2] & 2u))    /* PROT_WRITE too */
				*flags = KGENOME_NUCLEO_F_WX;
			return KGENOME_NUCLEO_ALLOC_EXEC;
		}
	}
	return cap;
}

const char *kgenome_nucleo_sys_name(unsigned bits, uint32_t nr)
{
	const struct kgenome_sysrow *row = bits == 64
		? kgenome_nucleo_sys_row(kgenome_nucleo_sys64, SYSTAB_N(sys64), nr)
		: kgenome_nucleo_sys_row(kgenome_nucleo_sys32, SYSTAB_N(sys32), nr);

	return row ? row->name : NULL;
}

/*
 * THE SAME TWO QUESTIONS FOR A PORT THAT HAS ITS OWN TABLE.
 *
 * kgenome_nucleo_cap_of_syscall above is x86's: `bits` picks between two tables and
 * the refinements test x86 numbers. A fixed-width port is described by its
 * kgenome_nucleo_abi instead - table, and which argument holds prot - and the refinements
 * are keyed by the ROW's role, which is what the role column is for: a row
 * that says it is mmap is asked about PROT_EXEC whatever number it has.
 *
 * Only the rows the port's table has. A number with no row is NONE, which the
 * caller records as a syscall the vocabulary has no word for.
 */
static uint16_t fx_look(const struct kgenome_nucleo_abi *fx, uint32_t nr, uint8_t *role,
			const char **name)
{
	const struct kgenome_sysrow *row;

	if (!fx) {                              /* no ABI described: no row, as for a number it lacks */
		*role = KGENOME_NUCLEO_ROLE_NONE;
		*name = NULL;
		return KGENOME_NUCLEO_NONE;
	}
	row = kgenome_nucleo_sys_row(fx->tab, fx->n_tab, nr);
	if (!row)
		row = kgenome_nucleo_sys_row(fx->tab2, fx->n_tab2, nr);
	if (!row) {
		*role = KGENOME_NUCLEO_ROLE_NONE;
		*name = NULL;
		return KGENOME_NUCLEO_NONE;
	}
	*role = row->role;
	*name = row->name;
	return row->cap;
}

uint16_t kgenome_nucleo_cap_of_syscall_abi(const struct kgenome_nucleo_abi *fx, uint32_t nr,
				     const uint64_t *arg, uint8_t *flags)
{
	const char *nm;
	uint8_t role;
	uint16_t cap = fx_look(fx, nr, &role, &nm);

	if (flags)
		*flags = 0;
	if (arg && cap == KGENOME_NUCLEO_SPAWN && role == KGENOME_NUCLEO_ROLE_CLONE)
		return (arg[0] & KGENOME_NUCLEO_CLONE_THREAD) ? KGENOME_NUCLEO_THREAD
						    : KGENOME_NUCLEO_SPAWN;
	if (arg && cap == KGENOME_NUCLEO_NET_OPEN && role == KGENOME_NUCLEO_ROLE_SOCK)
		return kgenome_nucleo_sock_kind(arg, flags);
	if (arg && cap == KGENOME_NUCLEO_ALLOC && role == KGENOME_NUCLEO_ROLE_MMAP &&
	    (arg[fx->prot_arg] & 4u)) {         /* PROT_EXEC */
		if (flags && (arg[fx->prot_arg] & 2u))
			*flags = KGENOME_NUCLEO_F_WX;
		return KGENOME_NUCLEO_ALLOC_EXEC;
	}
	return cap;
}

const char *kgenome_nucleo_sys_name_abi(const struct kgenome_nucleo_abi *fx, uint32_t nr)
{
	const char *nm;
	uint8_t role;

	fx_look(fx, nr, &role, &nm);
	return nm;
}

/* The syscall tables, one per ABI. Only the numbers the vocabulary names. */

/*
 * AArch64 and anything else on asm-generic. VERIFIED against
 * /usr/include/asm-generic/unistd.h; mmap is __NR3264_mmap, which is 222.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_a64[] = {
	{   56, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{   63, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{   64, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{ 101, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{ 117, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{ 198, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 200, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 201, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 202, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 203, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 206, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 207, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{ 220, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{ 221, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{ 222, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see fixed_prot */
	{ 226, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{ 279, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  }
};

/*
 * ARM EABI. The low numbers are i386's, which ARM inherited - so these agree
 * with kgenome_nucleo_sys32 above and are not a second claim about them. The socket calls
 * are ARM's own, past where the shared range ends: i386 multiplexes them
 * through socketcall and ARM does not.
 *
 * NOT FROM A HEADER - this host has none for ARM. Corroborated on the corpus
 * instead, and the shape of the agreement is the evidence: across 1771 ARM
 * objects, 281, 283 and 289 each appear in 97 files, 291 and 290 in 96.
 * A program that opens a socket connects and sends on it, so a table that
 * had any of these wrong would not produce counts that track each other.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_arm[] = {
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{   11, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{   26, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{ 120, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{ 125, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },
	{ 162, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{ 190, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "vfork"  },
	{ 192, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap2"  },
	{ 281, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 282, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 283, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 284, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 285, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 289, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "send"  },
	{ 290, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 291, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recv"  },
	{ 292, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{ 322, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{ 385, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  }
};

/*
 * MIPS o32, which bases its numbering at 4000.
 *
 * NOT FROM A HEADER either, and corroborated the same way: over 478 MIPS
 * objects 4183, 4170 and 4178 each appear in 123 files and 4175 in 121,
 * while the server-side three - 4169, 4174, 4168 - trail at 78, 72 and 65.
 * That is the profile of a corpus of clients with some listeners in it, and
 * it is not a profile a mis-numbered table produces.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_mips[] = {
	{ 4002, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{ 4003, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{ 4004, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{ 4005, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{ 4011, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{ 4026, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{ 4090, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },
	{ 4120, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{ 4125, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },
	{ 4166, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{ 4168, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 4169, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 4170, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 4174, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 4175, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recv"  },
	{ 4176, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{ 4178, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "send"  },
	{ 4180, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 4183, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 4288, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{ 4354, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  }
};

/*
 * POWERPC, AND IT INHERITED i386's NUMBERS.
 *
 * NOT FROM A HEADER - there is none for any of these on this host - and
 * corroborated the way kgenome_nucleo_sys_arm and kgenome_nucleo_sys_mips were, from what the corpus
 * actually contains. Over 260 PPC objects the numbers that appear are
 * 1, 2, 3, 4, 5, 6, 20, 37, 45, 54, 66, 85, 91, 102, 173, 202, 204: that is
 * i386's low range and nothing else, which is what the port did.
 *
 * WHAT IT ADDED IS THE SOCKET BLOCK. i386 multiplexes through socketcall and
 * PowerPC kept that - 102 appears in 68% of the 32-bit objects - but it ALSO
 * has the calls directly, at 326 and up, and the 64-bit objects use those:
 * 326 appears in 79.7% of them and 339 with it. Both are here because the
 * corpus contains both.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_ppc[] = {
	{ 326, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 327, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 328, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 329, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 330, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 334, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "send"  },
	{ 335, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 336, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recv"  },
	{ 337, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  }
};

/*
 * SPARC, WHICH KEPT ITS OWN NUMBERING and is the one port here that did.
 *
 * Corroborated the same way, over 256 objects: 206 appears in 94.5% of them
 * and 102, 103, 155, 44, 53, 69, 70 move with it. That is SPARC's socket at
 * 206, not i386's at anything - and the agreement of the group is the
 * evidence, because a mis-numbered table does not produce counts that track.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_sparc[] = {
	{     1, KGENOME_NUCLEO_NONE, KGENOME_NUCLEO_ROLE_NONE, "exit"  },
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{   26, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{   59, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{   71, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },
	{   74, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },
	{ 206, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 207, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 232, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 233, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{ 234, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 235, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 240, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 284, KGENOME_NUCLEO_THREAD, KGENOME_NUCLEO_ROLE_NONE, "clone"  }
};



/*
 * MIPS n64, which bases its numbering at 5000.
 *
 * FROM A HEADER THIS TIME, and the header is named because the o32 table
 * beside it was not: /run/host/usr/lib/linux/uapi/mips/asm/unistd_n64.h on
 * this machine. Corroborated against the corpus anyway - see
 * KGENOME_NUCLEO_A_MIPS64 - because a header read wrongly is as quiet as a number
 * remembered wrongly.
 *
 * NOT AN OFFSET FROM THE o32 TABLE. 4003 is read on o32 and 5003 is close on
 * n64; the lists diverge immediately and anything derived by adding 1000
 * would be confidently wrong.
 */
static const struct kgenome_sysrow kgenome_nucleo_sys_mips64[] = {
	{ 5000, KGENOME_NUCLEO_MEM_READ, KGENOME_NUCLEO_ROLE_NONE, "read"  },
	{ 5001, KGENOME_NUCLEO_MEM_WRITE, KGENOME_NUCLEO_ROLE_NONE, "write"  },
	{ 5002, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "open"  },
	{ 5009, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mmap"  },
	{ 5010, KGENOME_NUCLEO_ALLOC, KGENOME_NUCLEO_ROLE_MMAP, "mprotect"  },
	{ 5032, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup2"  },
	{ 5034, KGENOME_NUCLEO_SLEEP, KGENOME_NUCLEO_ROLE_NONE, "nanosleep"  },
	{ 5040, KGENOME_NUCLEO_NET_OPEN, KGENOME_NUCLEO_ROLE_SOCK, "socket"  },
	{ 5041, KGENOME_NUCLEO_NET_CONNECT, KGENOME_NUCLEO_ROLE_NONE, "connect"  },
	{ 5042, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept"  },
	{ 5043, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendto"  },
	{ 5044, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvfrom"  },
	{ 5045, KGENOME_NUCLEO_NET_WRITE, KGENOME_NUCLEO_ROLE_NONE, "sendmsg"  },
	{ 5046, KGENOME_NUCLEO_NET_READ, KGENOME_NUCLEO_ROLE_NONE, "recvmsg"  },
	{ 5048, KGENOME_NUCLEO_NET_BIND, KGENOME_NUCLEO_ROLE_NONE, "bind"  },
	{ 5049, KGENOME_NUCLEO_NET_LISTEN, KGENOME_NUCLEO_ROLE_NONE, "listen"  },
	{ 5055, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_CLONE, "clone"  },
	{ 5056, KGENOME_NUCLEO_SPAWN, KGENOME_NUCLEO_ROLE_NONE, "fork"  },
	{ 5057, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execve"  },
	{ 5080, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "rename"  },
	{ 5085, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlink"  },
	{ 5088, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "chmod"  },
	{ 5089, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmod"  },
	{ 5099, KGENOME_NUCLEO_PTRACE, KGENOME_NUCLEO_ROLE_NONE, "ptrace"  },
	{ 5103, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setuid"  },
	{ 5104, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setgid"  },
	{ 5111, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setreuid"  },
	{ 5115, KGENOME_NUCLEO_CRED_SET, KGENOME_NUCLEO_ROLE_NONE, "setresuid"  },
	{ 5130, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utime"  },
	{ 5151, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "pivot_root"  },
	{ 5156, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "chroot"  },
	{ 5168, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "init_module"  },
	{ 5169, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "delete_module"  },
	{ 5226, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimes"  },
	{ 5247, KGENOME_NUCLEO_FILE_OPEN, KGENOME_NUCLEO_ROLE_NONE, "openat"  },
	{ 5251, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "futimesat"  },
	{ 5253, KGENOME_NUCLEO_FILE_DELETE, KGENOME_NUCLEO_ROLE_NONE, "unlinkat"  },
	{ 5254, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat"  },
	{ 5258, KGENOME_NUCLEO_PERM_SET, KGENOME_NUCLEO_ROLE_NONE, "fchmodat"  },
	{ 5262, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "unshare"  },
	{ 5275, KGENOME_NUCLEO_TIMESTOMP, KGENOME_NUCLEO_ROLE_NONE, "utimensat"  },
	{ 5286, KGENOME_NUCLEO_FD_REDIR, KGENOME_NUCLEO_ROLE_NONE, "dup3"  },
	{ 5293, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_NUCLEO_ROLE_NONE, "accept4"  },
	{ 5303, KGENOME_NUCLEO_JAIL, KGENOME_NUCLEO_ROLE_NONE, "setns"  },
	{ 5304, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_readv"  },
	{ 5305, KGENOME_NUCLEO_PROC_MEM, KGENOME_NUCLEO_ROLE_NONE, "process_vm_writev"  },
	{ 5307, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "finit_module"  },
	{ 5311, KGENOME_NUCLEO_FILE_RENAME, KGENOME_NUCLEO_ROLE_NONE, "renameat2"  },
	{ 5314, KGENOME_NUCLEO_MEMFD, KGENOME_NUCLEO_ROLE_NONE, "memfd_create"  },
	{ 5315, KGENOME_NUCLEO_MOD_LOAD, KGENOME_NUCLEO_ROLE_NONE, "bpf"  },
	{ 5316, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_NUCLEO_ROLE_NONE, "execveat"  }
};


/* Whether every table above is strictly ascending in number: what the search in
 * kgenome_nucleo_sys_row relies on. Tests only. */
static int sys_tab_ordered(const struct kgenome_sysrow *t, uint32_t n)
{
	uint32_t i;

	for (i = 1; i < n; i++)
		if (t[i - 1u].nr >= t[i].nr)
			return 0;
	return 1;
}

int kgenome_nucleo_sys_ordered(void)
{
	return sys_tab_ordered(kgenome_nucleo_sys64, SYSTAB_N(sys64)) &&
	       sys_tab_ordered(kgenome_nucleo_sys32, SYSTAB_N(sys32)) &&
	       sys_tab_ordered(kgenome_nucleo_sockcall, SYSTAB_N(sockcall)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_a64, SYSTAB_N(sys_a64)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_arm, SYSTAB_N(sys_arm)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_mips, SYSTAB_N(sys_mips)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_ppc, SYSTAB_N(sys_ppc)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_sparc, SYSTAB_N(sys_sparc)) &&
	       sys_tab_ordered(kgenome_nucleo_sys_mips64, SYSTAB_N(sys_mips64));
}

#define FXN(t) kgenome_nucleo_##t, SYSTAB_N(t)

static const struct kgenome_nucleo_abi FX_MIPS = {
	FXN(sys_mips), NULL, 0, 0, 2, 2, 4, 4, 2
};
/* Same registers and the same `syscall`; only the table differs. */
static const struct kgenome_nucleo_abi FX_MIPS64 = {
	FXN(sys_mips64), NULL, 0, 0, 2, 2, 4, 4, 2
};
static const struct kgenome_nucleo_abi FX_ARM = {
	FXN(sys_arm),  NULL, 0, 0, 7, 0, 0, 6, 2
};
static const struct kgenome_nucleo_abi FX_A64 = {
	FXN(sys_a64),  NULL, 0, 0, 8, 0, 0, 6, 2
};
/*
 * PowerPC: r0 carries the number, r3 the result and the first argument -
 * the same register, which is why the provenance note in sweep_fixed applies
 * here exactly as it does to ARM.
 */
static const struct kgenome_nucleo_abi FX_PPC = {
	FXN(sys_ppc), FXN(sys32), 102, 0, 3, 3, 6, 2
};
/* SPARC: %g1 is register 1, %o0 is register 8 and is both the result and the
 * first argument. */
static const struct kgenome_nucleo_abi FX_SPARC = {
	FXN(sys_sparc), NULL, 0, 0, 1, 8, 8, 6, 2
};
/*
 * RISC-V, AND IT NEEDS NO TABLE OF ITS OWN. The port took the generic
 * numbering, which is AArch64's - corroborated over 45 objects, where 93,
 * 94, 56, 57, 198, 214, 215, 220 and 222 are what appears, every one of them
 * a row of kgenome_nucleo_sys_a64. a7 is x17 and a0 is x10.
 */
static const struct kgenome_nucleo_abi FX_RISCV = {
	FXN(sys_a64), NULL, 0, 0, 17, 10, 10, 6, 2
};
/* SuperH: r3 the number, r0 the result, r4 the first argument. */
static const struct kgenome_nucleo_abi FX_SH = {
	FXN(sys32), NULL, 0, 102, 3, 0, 4, 4, 2
};
/* m68k: d0 the number AND the result, d1 the first argument. */
static const struct kgenome_nucleo_abi FX_M68K = {
	FXN(sys32), NULL, 0, 102, 0, 0, 1, 5, 2
};


const struct kgenome_nucleo_abi *kgenome_nucleo_abi_of(unsigned arch)
{
	switch (arch) {
	case KGENOME_NUCLEO_A_MIPS32:  return &FX_MIPS;
	case KGENOME_NUCLEO_A_MIPS64:  return &FX_MIPS64;
	case KGENOME_NUCLEO_A_ARM32:   return &FX_ARM;
	case KGENOME_NUCLEO_A_PPC32:
	case KGENOME_NUCLEO_A_PPC64:   return &FX_PPC;
	case KGENOME_NUCLEO_A_SPARC32: return &FX_SPARC;
	case KGENOME_NUCLEO_A_RISCV:   return &FX_RISCV;
	case KGENOME_NUCLEO_A_SH:      return &FX_SH;
	case KGENOME_NUCLEO_A_M68K:    return &FX_M68K;
	default:                 return &FX_A64;
	}
}
