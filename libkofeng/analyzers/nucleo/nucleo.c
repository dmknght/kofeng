/* See nucleo.h. */

#include "nucleo.h"

#include <stdio.h>
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
 * The roles are nucleo.h's - see KOF_FLOW_ROLE_NONE. Naming them in the
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

/* Linux x86-64. */
const struct sysrow kof_sys64[] = {
	{     0, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     1, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	/*
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
	 */
	{    17, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "pread64"  },
	{    18, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "pwrite64"  },
	{    19, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "readv"  },
	{    20, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "writev"  },
	{    40, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "sendfile"  },
	{   275, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "splice"  },
	{   295, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "preadv"  },
	{   296, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "pwritev"  },
	{   327, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "preadv2"  },
	{   328, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "pwritev2"  },
	{    46, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendmsg"  },
	{    47, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvmsg"  },
	{     2, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   9, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see prot_cap */
	{  10, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{   35, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{  41, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{   42, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{   43, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{   44, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{   45, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{  56, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{   57, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{   58, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "vfork"  },
	{   59, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 257, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 319, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 322, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	/*
	 * AND THE REST OF WHAT A PROGRAM CAN ASK FOR. Numbers read out of
	 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this machine
	 * rather than remembered, because a wrong one here is not a missed
	 * detection - it is a confident wrong name on whatever syscall does
	 * hold the number.
	 */
	{  82, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "rename"  },
	{  87, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{ 263, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 264, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 316, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{  90, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{  91, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 268, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{ 105, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{ 106, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{ 113, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 117, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 310, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 311, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 175, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 176, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 313, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 321, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{ 161, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 155, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 308, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 272, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{ 101, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{  22, KOF_NUCLEO_PIPE_OPEN, KOF_FLOW_ROLE_NONE, "pipe"  },
	{  33, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{  53, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_NONE, "socketpair"  },
	{ 292, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{ 132, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 235, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 261, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 280, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
};

/* Linux i386. */
const struct sysrow kof_sys32[] = {
	{     2, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	/* The same family on i386 - see the note in the amd64 table. */
	{   180, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "pread64"  },
	{   181, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "pwrite64"  },
	{   145, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "readv"  },
	{   146, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "writev"  },
	{   187, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "sendfile"  },
	{   239, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "sendfile64"  },
	{   313, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "splice"  },
	{   333, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "preadv"  },
	{   334, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "pwritev"  },
	{     4, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   11, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{  90, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 102, KOF_NUCLEO_NONE, KOF_FLOW_ROLE_NONE, "socketcall"  },         /* socketcall - the sub-call is in ebx */
	{ 120, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 192, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap2"  },
	{ 295, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 356, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 358, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	/* The same list on i386, from asm/unistd_32.h and NOT by subtracting
	 * anything from the table above - the two numberings are unrelated. */
	{  10, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{  38, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "rename"  },
	{ 301, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 302, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 353, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{  15, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{  94, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 306, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{  23, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{  46, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{  70, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 164, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 347, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 348, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 128, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 129, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 350, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 357, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{  61, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 217, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 346, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 310, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{  26, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{  42, KOF_NUCLEO_PIPE_OPEN, KOF_FLOW_ROLE_NONE, "pipe"  },
	{  63, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{ 330, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{  30, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 271, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 299, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 320, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
};

/* i386 multiplexes every socket operation through socketcall, with the
 * operation in ebx. Left as its own table rather than folded into the one
 * above, because it is a different axis and merging them would need a second
 * key nothing else uses. */
const struct sysrow kof_sockcall[] = {
	{  1, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket" },
	{  2, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind" },
	{  3, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect" },
	{  4, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen" },
	{  5, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept" },
	{  9, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "send" },
	{ 10, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recv" },
	{ 11, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto" },
	{ 12, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom" }
};


uint16_t kof_sys_look(const struct sysrow *t, uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return t[i].cap;
	return KOF_NUCLEO_NONE;
}

/* The kernel's own name for the call, or NULL - see the note on sysrow. */
const char *kof_sys_look_name(const struct sysrow *t, uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return t[i].name;
	return 0;
}

uint8_t kof_sys_look_role(const struct sysrow *t, uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return t[i].role;
	return KOF_FLOW_ROLE_NONE;
}

/*
 * WHAT AN IMPORTED NAME IS, in the same vocabulary.
 *
 * Longest-sensible match and no prefix guessing: "recv" and "recvfrom" are
 * both here rather than matched by a prefix, because "recvmmsg" and "recvmsg"
 * would fall out of a prefix test and so would anything a future libc adds.
 *
 * WINDOWS NAMES SIT BESIDE POSIX ONES on purpose. VirtualAlloc and mmap are
 * the same fact about a program, and a rule written over these words is the
 * one thing that can be shared between the two platforms - see the note on
 * enum kof_flow_cap.
 */
static const struct { const char *name; uint16_t cap; uint8_t role; }
names[] = {
	/* POSIX */
	{ "mmap",           KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "mmap64",         KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "mprotect",       KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	/* Not a finding on its own - see KOF_NUCLEO_HEAP - and here so that a
	 * buffer two transfers share has a name. posix_memalign is left
	 * out: it hands the pointer back THROUGH one, and until
	 * kof_flow_out_arg carries it the step would make something
	 * nothing could hold. */
	{ "malloc",         KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "calloc",         KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "realloc",        KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "reallocarray",   KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "aligned_alloc",  KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "memalign",       KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "_Znwm",          KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },  /* new    */
	{ "_Znam",          KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },  /* new[]  */
	{ "socket",         KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "socketpair",     KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_NONE },
	/* Not a finding on its own - see KOF_NUCLEO_PIPE_OPEN - and here so
	 * the step has a name and so a dynamically linked object calling
	 * pipe@plt reaches the same word as a static one. */
	{ "pipe",           KOF_NUCLEO_PIPE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "pipe2",          KOF_NUCLEO_PIPE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "connect",        KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "accept",         KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "accept4",        KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "bind",           KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE },
	{ "listen",         KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE },
	{ "recv",           KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "recvfrom",       KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "recvmsg",        KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "read",           KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE },
	{ "send",           KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "sendto",         KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "sendmsg",        KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "write",          KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE },
	{ "open",           KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "open64",         KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "openat",         KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "fopen",          KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "memfd_create",   KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE },
	{ "execve",         KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execv",          KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execl",          KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execlp",         KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execvp",         KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "system",         KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "popen",          KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "fork",           KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE },
	{ "vfork",          KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE },
	/* The libc wrapper, whose flags are its THIRD argument rather than its
	 * first - a different convention from the syscall, and past what is
	 * refined here. It stays the weaker claim. */
	{ "clone",          KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE },
	/* No flags to read and no ambiguity: the name IS the claim. */
	{ "pthread_create", KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	{ "daemon",         KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE },
	{ "sleep",          KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "usleep",         KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "nanosleep",      KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "ptrace",         KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE },
	/* Windows, for the same words */
	{ "VirtualAlloc",   KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "VirtualAllocEx", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "VirtualProtect", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "HeapAlloc",      KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "HeapReAlloc",    KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "RtlAllocateHeap", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "LocalAlloc",     KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "GlobalAlloc",    KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "CoTaskMemAlloc", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "WSASocketA",     KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "WSASocketW",     KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "InternetOpenA",  KOF_NUCLEO_HTTP_OPEN, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenW",  KOF_NUCLEO_HTTP_OPEN, KOF_FLOW_ROLE_NONE },
	{ "WSAConnect",     KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetConnectA", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetConnectW", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "CreateFileA",    KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "CreateFileW",    KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "WriteFile",      KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE },
	{ "ReadFile",       KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessA", KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessW", KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "WinExec",        KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteA",  KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteW",  KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateThread",   KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	/*
	 * THE REST OF THE WINDOWS SURFACE, and it was not a short list.
	 *
	 * Measured over the PE objects in MalwareLab that produced no chain:
	 * 220 of 453 held a name the vocabulary could have said something
	 * about and this table did not carry. The commonest were the plain
	 * Berkeley names - ws2_32 exports `socket`, `connect`, `send` under
	 * those spellings and not only as WSA* - then the loader pair, then
	 * the three steps of process injection.
	 */
	/* ws2_32 exports these under their POSIX spellings, which the rows
	 * above already carry; what is listed here is only what it adds. */
	{ "WSARecv",        KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "WSASend",        KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "WSAAccept",      KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "closesocket",    KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenUrlA", KOF_NUCLEO_HTTP_SEND, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenUrlW", KOF_NUCLEO_HTTP_SEND, KOF_FLOW_ROLE_NONE },
	{ "InternetReadFile", KOF_NUCLEO_HTTP_RECV, KOF_FLOW_ROLE_NONE },
	{ "HttpSendRequestA", KOF_NUCLEO_HTTP_SEND, KOF_FLOW_ROLE_NONE },
	{ "HttpSendRequestW", KOF_NUCLEO_HTTP_SEND, KOF_FLOW_ROLE_NONE },
	{ "HttpOpenRequestA", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "HttpOpenRequestW", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "URLDownloadToFileA", KOF_NUCLEO_HTTP_FETCH, KOF_FLOW_ROLE_NONE },
	{ "URLDownloadToFileW", KOF_NUCLEO_HTTP_FETCH, KOF_FLOW_ROLE_NONE },
	/*
	 * THE WINDOWS SPELLING OF A REDIRECTED SHELL, which the table had
	 * only the POSIX half of.
	 *
	 * `pipe` then `dup2` then `execve` is the shape KOF_NUCLEO_PIPE_OPEN
	 * exists for; on Windows it is `CreatePipe` then `SetStdHandle` or
	 * a STARTUPINFO, then `CreateProcess` - and CreateProcess was the
	 * only one of the three in this table. The producer and the
	 * redirect are what make it a sentence rather than three words.
	 */
	{ "CreatePipe",     KOF_NUCLEO_PIPE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "SetStdHandle",   KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "DuplicateHandle", KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "WinHttpOpen",    KOF_NUCLEO_HTTP_OPEN, KOF_FLOW_ROLE_NONE },
	{ "WinHttpConnect", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "WinHttpOpenRequest", KOF_NUCLEO_HTTP_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "WinHttpSendRequest", KOF_NUCLEO_HTTP_SEND, KOF_FLOW_ROLE_NONE },
	{ "WinHttpReadData", KOF_NUCLEO_HTTP_RECV, KOF_FLOW_ROLE_NONE },
	/* A mapping is a mapping, whichever name asks for it. */
	{ "VirtualProtectEx", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtAllocateVirtualMemory", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtProtectVirtualMemory", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "ZwAllocateVirtualMemory", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "ZwProtectVirtualMemory", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "CreateFileMappingA", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "CreateFileMappingW", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "MapViewOfFile",  KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "MapViewOfFileEx", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	/* The handle, the memory and the execution - see the note on the
	 * three capabilities in kofmod/kofcap.h. */
	{ "OpenProcess",    KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "DebugActiveProcess", KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE },
	/* A thread handle is the same kind of hold on another execution
	 * context, and it is what SetThreadContext and ResumeThread are
	 * handed - they were modelled and the handle they take was not. */
	{ "OpenThread",     KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "WriteProcessMemory", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "ReadProcessMemory", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "NtWriteVirtualMemory", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	/* Reading another thread's registers, and emptying another image
	 * out of its address space: the two legs of hollowing whose other
	 * halves - SetThreadContext and WriteProcessMemory - were already
	 * here. */
	{ "GetThreadContext", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "NtUnmapViewOfSection", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "ZwUnmapViewOfSection", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "CreateRemoteThread", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "CreateRemoteThreadEx", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "NtQueueApcThread", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "QueueUserAPC",   KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "SetThreadContext", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "NtResumeThread", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "SuspendThread",  KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "NtSuspendThread", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "ResumeThread",   KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	/* The loader pair, which is what a program has INSTEAD of an import
	 * table entry - see KOF_NUCLEO_RESOLVE. */
	{ "LoadLibraryA",   KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryW",   KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryExA", KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryExW", KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "GetProcAddress", KOF_NUCLEO_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "LdrLoadDll",     KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LdrGetProcedureAddress", KOF_NUCLEO_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "dlopen",         KOF_NUCLEO_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "dlsym",          KOF_NUCLEO_RESOLVE, KOF_FLOW_ROLE_NONE },
	/* Writes only; a program reading its own configuration is every
	 * program - see KOF_NUCLEO_REG_SET. */
	/* And where the handle they are given comes from - see
	 * KOF_NUCLEO_REG_OPEN. Not a finding; the head of a link. */
	/* Windows' spelling of rename - the word already existed for the
	 * POSIX one, see KOF_NUCLEO_FILE_RENAME, and only the name was
	 * missing. 16 of the 128 measured PE import MoveFileW. */
	{ "MoveFileA",      KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "MoveFileW",      KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "MoveFileExA",    KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "MoveFileExW",    KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "MoveFileWithProgressW", KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "RegOpenKeyExA",  KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "RegOpenKeyExW",  KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "RegOpenKeyA",    KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "RegOpenKeyW",    KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "NtOpenKey",      KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "NtOpenKeyEx",    KOF_NUCLEO_REG_OPEN, KOF_FLOW_ROLE_NONE },
	{ "RegSetValueExA", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegSetValueExW", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegCreateKeyExA", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegCreateKeyExW", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteValueA", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteValueW", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "NtSetValueKey",  KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "Sleep",          KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE },

	/*
	 * THE ROWS THE RANKING CHOSE. Measured over the whole corpus here -
	 * 1772 ELF malware objects against 20347 Linux binaries - and kept
	 * because of what the numbers said, not because they sounded right.
	 * See KOF_NUCLEO_NET_ADDR for the rates and for what the ranking
	 * rejected.
	 */
	{ "htons",          KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "htonl",          KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "ntohs",          KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "ntohl",          KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_addr",      KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_aton",      KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_pton",      KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_ntoa",      KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_network",   KOF_NUCLEO_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "gethostbyname",  KOF_NUCLEO_DNS, KOF_FLOW_ROLE_NONE },
	{ "getaddrinfo",    KOF_NUCLEO_DNS, KOF_FLOW_ROLE_NONE },
	{ "prctl",          KOF_NUCLEO_SELF_HIDE, KOF_FLOW_ROLE_NONE },
	{ "setsid",         KOF_NUCLEO_BACKGROUND, KOF_FLOW_ROLE_NONE },

	/*
	 * THE KERNEL, which is the same kind of table and a different side of
	 * the same machine.
	 *
	 * A loadable module makes no syscalls - it answers them - so the whole
	 * vocabulary above is silent on one. What it has instead is a list of
	 * UNDEFINED symbols, which is the same declaration a PE import table
	 * is: the names it was compiled against, fixed, and not the module's
	 * to choose. See KOF_NUCLEO_CRED_SET for the measurement that picked
	 * these.
	 *
	 * THE LINUX ONES HAVE NO PREFIX AND THAT IS A HAZARD worth stating:
	 * `kernel_read` and `filp_open` are kernel names, but nothing stops a
	 * userspace program exporting a function of the same name, and this
	 * table is consulted for both. Each row below is a name a userspace
	 * libc does not have, which is the only thing keeping the two apart.
	 *
	 * MEASURED, because a hazard without a number is a guess: across 1038
	 * objects from a frozen copy of /usr/bin, ZERO declare any of
	 * prepare_creds, commit_creds, prepare_kernel_cred, register_kprobe,
	 * kallsyms_lookup_name, kernel_read, kernel_write, filp_open,
	 * vfs_read, vfs_write, list_del, text_poke or sock_create. The hazard
	 * is real and it does not bite on real userspace - which is a fact
	 * about today's libraries, not a property of the design, so the rule
	 * for a new row stands: add a name only if userspace does not have it.
	 */
	/* Credentials BUILT, then credentials INSTALLED - "give me root" is
	 * the value passing from the first to the second, so the two halves
	 * have separate words. See KOF_NUCLEO_CRED_PREPARE. */
	{ "prepare_creds",  KOF_NUCLEO_CRED_PREPARE, KOF_FLOW_ROLE_NONE },
	{ "prepare_kernel_cred", KOF_NUCLEO_CRED_PREPARE, KOF_FLOW_ROLE_NONE },
	/*
	 * ---- THE KERNEL'S ALLOCATORS ---------------------------------------
	 *
	 * Missing, and the gap showed up as a chain resting on nothing. A
	 * hooked getdents is
	 *
	 *     kdirent = kzalloc(n);  copy_from_user(kdirent, dirent, n);
	 *     <edit kdirent>;        copy_to_user(dirent, kdirent, n);
	 *
	 * and kdirent is the object the whole hook turns on. With no word for
	 * the allocation it was an anonymous stand-in - good enough to carry
	 * the link between the two copies, and unable to BE one end of it.
	 * The buffer that the listing is edited in should be a node.
	 *
	 * COMMON, as an allocator is: __kmalloc_noprof is in 177 of 900 clean
	 * kernel modules on this machine and kfree in 428. A term, never a
	 * verdict - what is said is not that a module allocates but what it
	 * then does with what it allocated.
	 *
	 * BOTH SPELLINGS of the kernel's recent renames, for the reason the
	 * list-surgery row gives: a table that knows only the old name is a
	 * table about one kernel version.
	 */
	{ "__kmalloc",      KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "__kmalloc_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kmalloc",        KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kmalloc_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kmalloc_trace",  KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kvmalloc_node",  KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kvmalloc_node_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "krealloc",       KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "krealloc_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kmem_cache_alloc", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "kmem_cache_alloc_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "vmalloc",        KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "vmalloc_noprof", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "__vmalloc",      KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "__vmalloc_node_range", KOF_NUCLEO_HEAP, KOF_FLOW_ROLE_NONE },
	{ "commit_creds",   KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "set_current_groups", KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	/*
	 * A KPROBE PUT ON AND A KPROBE TAKEN OFF - two words, and neither of
	 * them is "hook". See KOF_NUCLEO_KPROBE_REG for why this row has now
	 * been wrong twice. The pair is the IDIOM: put a probe on a name,
	 * read kp.addr, take the probe away again, all in one function - and
	 * an idiom made of two calls needs two words to be written down.
	 * Measured at 0 of 900 clean modules on each side.
	 */
	{ "register_kprobe", KOF_NUCLEO_KPROBE_REG, KOF_FLOW_ROLE_NONE },
	{ "register_kprobes", KOF_NUCLEO_KPROBE_REG, KOF_FLOW_ROLE_NONE },
	{ "unregister_kprobe", KOF_NUCLEO_KPROBE_UNREG, KOF_FLOW_ROLE_NONE },
	{ "unregister_kprobes", KOF_NUCLEO_KPROBE_UNREG, KOF_FLOW_ROLE_NONE },
	/* A RETURN probe cannot read an address and leave; it exists to run
	 * code on somebody else's return, so it stays hooking. */
	{ "register_kretprobe", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "unregister_kretprobe", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	/* Code of one's own put in the path of somebody else's. */
	{ "unregister_ftrace_function", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	/*
	 * ---- write_cr0 / write_cr4 / mov_cr0 ARE OFF, ON PURPOSE --------
	 *
	 * The word is KOF_NUCLEO_PROT_OFF - "the module took write access to
	 * memory the kernel protects" - and these three are the only members
	 * it has. All three are x86, and two of them are the instruction
	 * rather than the behaviour, which is the one thing a nucleo word
	 * must never be: arm64 has no CR0 at all, and reaches the same end
	 * through update_mapping_prot, set_memory_rw or
	 * aarch64_insn_patch_text. A word that covers one architecture's
	 * mechanism makes rules that stop working on the next port, and
	 * leaving it half-populated is worse than leaving it empty, because
	 * a rule written against it would read as architecture-neutral.
	 *
	 * There is no LKM sample for any other architecture on this machine,
	 * so the membership cannot be measured yet. The value stays declared
	 * and nothing produces it until it can be.
	 */
	/* { "write_cr0",   KOF_NUCLEO_PROT_OFF, KOF_FLOW_ROLE_NONE }, */
	/* { "write_cr4",   KOF_NUCLEO_PROT_OFF, KOF_FLOW_ROLE_NONE }, */
	/*
	 * AND THE INSTRUCTION ITSELF, AS A NAME.
	 *
	 * `mov cr0, reg` has no symbol anywhere - it is inline assembly - so
	 * the node that reads it has nothing to put beside its capability and
	 * a reader sees "prot-off" with a dash. This row gives it a label.
	 *
	 * The underscore spelling is not a symbol anybody exports, so nothing
	 * can match this row by accident; it is reachable only by the sweep
	 * naming it directly.
	 */
	{ "peb_ldr",        KOF_NUCLEO_SELF_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "name_hash",      KOF_NUCLEO_NAME_HASH, KOF_FLOW_ROLE_NONE },
	/* off with the other two - see the note above them */
	/* { "mov_cr0",     KOF_NUCLEO_PROT_OFF, KOF_FLOW_ROLE_NONE }, */
	{ "register_ftrace_function", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "ftrace_set_filter_ip", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "register_ftrace_direct", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "text_poke",      KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "text_poke_kgdb", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "set_memory_rw",  KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "set_memory_x",   KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	/*
	 * An entry taken out of a kernel list, or put into one. EVERY
	 * SPELLING, because the kernel renamed the check twice and a table
	 * that knows two of the three eras is still a table about kernel
	 * versions - see KOF_NUCLEO_LIST_HIDE, where the 17% that makes this
	 * a term and not a verdict is measured.
	 *
	 *   __list_del_entry              before the validator, pre-4.x
	 *   __list_del_entry_valid        4.x
	 *   __list_del_entry_valid_or_report  6.x
	 *
	 * MEASURED: the bare one was missing and hcrootkit - built for a 3.x
	 * kernel - produced no list node at all, so a diagnose about module
	 * self-removal matched Diamorphine and missed it, for no reason to do
	 * with what either of them does.
	 */
	{ "__list_del_entry", KOF_NUCLEO_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "__list_del_entry_valid", KOF_NUCLEO_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "__list_del_entry_valid_or_report", KOF_NUCLEO_LIST_HIDE,
	  KOF_FLOW_ROLE_NONE },
	{ "__list_add_valid", KOF_NUCLEO_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "__list_add_valid_or_report", KOF_NUCLEO_LIST_HIDE,
	  KOF_FLOW_ROLE_NONE },
	{ "list_del",       KOF_NUCLEO_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "list_add",       KOF_NUCLEO_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE WORDS THE KERNEL NEEDS OF ITS OWN.
	 *
	 * kallsyms_lookup_name was called dlsym with a different name. It is
	 * not: dlsym returns what a library exported, this returns ANY symbol
	 * the kernel knows - and the one a rootkit wants, sys_call_table, is
	 * exported to nobody. See KOF_NUCLEO_KSYM_LOOKUP.
	 */
	/*
	 * ---- A CALL THROUGH A POINTER, WHICH IS AN IMPORT ON A RETPOLINE
	 * KERNEL ------------------------------------------------------------
	 *
	 * WHY THIS IS HERE AT ALL. A module that resolves a symbol at runtime
	 * does not call it by name - it stores the address in a variable and
	 * calls through that. Diamorphine's kallsyms_lookup_name_ is
	 * `uint64_t kallsyms_lookup_name_ = 0x0` in .bss, filled from kp.addr
	 * and then called. There is no symbol for that call, and the single
	 * most important call in the module was invisible.
	 *
	 * EXCEPT THAT ON A RETPOLINE BUILD THERE IS. The compiler does not
	 * emit `call *%rax`; it emits `call __x86_indirect_thunk_rax`, an
	 * UNDEFINED SYMBOL, which the relocation table lists like any other -
	 * and whose name states the register the target was in. So the site,
	 * the fact that it is indirect, and which register held the pointer
	 * all arrive without decoding anything.
	 *
	 * COMMON, AND THAT IS THE POINT OF SAYING SO: 359 of 900 clean kernel
	 * modules from this machine import one. It is a term and never a
	 * verdict - what matters is not that a module calls through a pointer
	 * but WHERE the pointer came from, which is a link.
	 *
	 * The register spellings are written out rather than matched by
	 * prefix: a prefix match would also take __x86_return_thunk, which is
	 * a return and not a call.
	 */
	{ "__x86_indirect_thunk_rax", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rbx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rcx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rdx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rsi", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rdi", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_rbp", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r8", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r9", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r10", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r11", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r12", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r13", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r14", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_r15", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_eax", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_ebx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_ecx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_edx", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_esi", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_edi", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "__x86_indirect_thunk_ebp", KOF_NUCLEO_CALL_REG, KOF_FLOW_ROLE_NONE },
	{ "kallsyms_lookup_name", KOF_NUCLEO_KSYM_LOOKUP, KOF_FLOW_ROLE_NONE },
	{ "kallsyms_lookup_name_t", KOF_NUCLEO_KSYM_LOOKUP, KOF_FLOW_ROLE_NONE },
	{ "__symbol_get",   KOF_NUCLEO_SYMBOL_GET, KOF_FLOW_ROLE_NONE },
	/* ACROSS THE USER/KERNEL BOUNDARY, which is not a file - see
	 * KOF_NUCLEO_COPY_FROM_USER. The rows under this one take a struct file
	 * and really are file I/O. */
	{ "_copy_from_user", KOF_NUCLEO_COPY_FROM_USER, KOF_FLOW_ROLE_NONE },
	{ "copy_from_user", KOF_NUCLEO_COPY_FROM_USER, KOF_FLOW_ROLE_NONE },
	{ "__copy_from_user", KOF_NUCLEO_COPY_FROM_USER, KOF_FLOW_ROLE_NONE },
	{ "_copy_to_user",  KOF_NUCLEO_COPY_TO_USER, KOF_FLOW_ROLE_NONE },
	{ "copy_to_user",   KOF_NUCLEO_COPY_TO_USER, KOF_FLOW_ROLE_NONE },
	{ "__copy_to_user", KOF_NUCLEO_COPY_TO_USER, KOF_FLOW_ROLE_NONE },
	{ "kernel_read",    KOF_NUCLEO_READ,  KOF_FLOW_ROLE_NONE },
	{ "kernel_write",   KOF_NUCLEO_WRITE, KOF_FLOW_ROLE_NONE },
	{ "vfs_read",       KOF_NUCLEO_READ,  KOF_FLOW_ROLE_NONE },
	{ "vfs_write",      KOF_NUCLEO_WRITE, KOF_FLOW_ROLE_NONE },
	{ "filp_open",      KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "filp_close",     KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "call_usermodehelper", KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "call_usermodehelper_exec", KOF_NUCLEO_EXEC_IMAGE,
	  KOF_FLOW_ROLE_NONE },
	{ "kthread_create_on_node", KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	{ "kthread_run",    KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	{ "wake_up_process", KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	{ "sock_create",    KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "sock_create_kern", KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "kernel_connect", KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "kernel_accept",  KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "kernel_sendmsg", KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "kernel_recvmsg", KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE WINDOWS KERNEL, which reaches this table the way every other
	 * PE import does - the mechanism needs nothing new, only the words.
	 */
	{ "ZwCreateFile",   KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "ZwOpenFile",     KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "ZwReadFile",     KOF_NUCLEO_MEM_READ,  KOF_FLOW_ROLE_NONE },
	{ "ZwWriteFile",    KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE },
	{ "MmGetSystemRoutineAddress", KOF_NUCLEO_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "MmMapLockedPagesSpecifyCache", KOF_NUCLEO_PROC_MEM,
	  KOF_FLOW_ROLE_NONE },
	{ "MmMapLockedPages", KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "PsLookupProcessByProcessId", KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "PsSetCreateProcessNotifyRoutine", KOF_NUCLEO_HOOK,
	  KOF_FLOW_ROLE_NONE },
	{ "PsSetCreateProcessNotifyRoutineEx", KOF_NUCLEO_HOOK,
	  KOF_FLOW_ROLE_NONE },
	{ "PsSetLoadImageNotifyRoutine", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "ObRegisterCallbacks", KOF_NUCLEO_HOOK, KOF_FLOW_ROLE_NONE },
	{ "PsCreateSystemThread", KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE },
	{ "ZwTerminateProcess", KOF_NUCLEO_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	/*
	 * ===== THE WORDS ADDED WITH THE NINE CAPABILITIES AT THE END OF
	 * enum kof_flow_cap. Each entry point here exists to do ONE thing;
	 * that is the bar, and the names that did not clear it are listed in
	 * kofcap.h beside the capabilities rather than here.
	 */
	/* Encryption. Windows has two generations of the same API and both are
	 * still shipped, so both are here. */
	{ "CryptEncrypt",   KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptDecrypt",   KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptAcquireContextA", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptAcquireContextW", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptGenKey",    KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptDeriveKey", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptImportKey", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptEncrypt",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptDecrypt",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptGenerateSymmetricKey", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptImportKeyPair", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	/* And the Linux side, which is OpenSSL in practice. The EVP names are
	 * the ones a program links; the AES_ ones are the older direct calls
	 * that statically linked malware still carries. */
	{ "EVP_EncryptInit_ex", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_EncryptUpdate",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_DecryptInit_ex", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_DecryptUpdate",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_CipherInit_ex",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_set_encrypt_key", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_cbc_encrypt",     KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_encrypt",         KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "RSA_public_encrypt",  KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "RSA_private_decrypt", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "crypto_secretbox_easy", KOF_NUCLEO_CRYPTO, KOF_FLOW_ROLE_NONE },
	/* Taking what the user is doing. */
	{ "SetWindowsHookExA", KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "SetWindowsHookExW", KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetAsyncKeyState",  KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetKeyboardState",  KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetRawInputData",   KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "RegisterRawInputDevices", KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetClipboardData",  KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "SetClipboardData",  KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "XQueryKeymap",      KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "XGrabKeyboard",     KOF_NUCLEO_CAPTURE, KOF_FLOW_ROLE_NONE },
	/* Installing itself as a service. */
	{ "OpenSCManagerA",  KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "OpenSCManagerW",  KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "CreateServiceA",  KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "CreateServiceW",  KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "StartServiceA",   KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "StartServiceW",   KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "ChangeServiceConfigA", KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "ChangeServiceConfigW", KOF_NUCLEO_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	/* Code into the kernel. */
	{ "init_module",    KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "finit_module",   KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "delete_module",  KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf",            KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_load_program", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_prog_load",  KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE NAMES libbpf ACTUALLY EXPORTS, which are not the syscall's.
	 *
	 * The three above were written from the syscall and measured nothing:
	 * boopkit, an eBPF rootkit sitting in the corpus, reported no
	 * module-load at all. Nothing links `bpf` - a program built the
	 * normal way compiles its eBPF object into a SKELETON and calls
	 * bpf_object__load_skeleton and bpf_object__attach_skeleton, and
	 * libbpf makes the syscall from inside a shared library this engine
	 * never reads.
	 *
	 * Loading and attaching only. bpf_map_update_elem and the map
	 * accessors are how a loaded program is talked to afterwards and
	 * every eBPF program uses them, so they say nothing about whether
	 * this process put code in the kernel.
	 */
	{ "bpf_object__load", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_object__load_skeleton", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_object__attach_skeleton", KOF_NUCLEO_MOD_LOAD,
	  KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_kprobe", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_uprobe", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_tracepoint", KOF_NUCLEO_MOD_LOAD,
	  KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_xdp", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_prog_attach", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_set_link_xdp_fd", KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_tc_attach",  KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "NtLoadDriver",   KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "ZwLoadDriver",   KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	/* A named pipe, and only a named one. */
	{ "CreateNamedPipeA", KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CreateNamedPipeW", KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "ConnectNamedPipe", KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CallNamedPipeA",   KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CallNamedPipeW",   KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "mkfifo",           KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	{ "mkfifoat",         KOF_NUCLEO_PIPE, KOF_FLOW_ROLE_NONE },
	/* Removing a file. */
	{ "DeleteFileA",    KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "DeleteFileW",    KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	/* MoveFileEx* used to be here as a DELETE. When KOF_NUCLEO_FILE_RENAME
	 * was split out of KOF_NUCLEO_FILE_DELETE the POSIX `rename` moved and
	 * these two did not, so the page went on saying `file-delete` with
	 * MoveFileExW beside it - the exact contradiction that split was
	 * made to end. They are with the other MoveFile rows now. */
	{ "unlink",         KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "unlinkat",       KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "remove",         KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "rename",         KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	{ "renameat",       KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE },
	/* Making a dropped file runnable. */
	{ "chmod",          KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "fchmod",         KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "fchmodat",       KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "SetFileAttributesA", KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "SetFileAttributesW", KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE },
	/* Asking whether it is watched. */
	{ "IsDebuggerPresent", KOF_NUCLEO_ANTI_DEBUG, KOF_FLOW_ROLE_NONE },
	{ "CheckRemoteDebuggerPresent", KOF_NUCLEO_ANTI_DEBUG,
	  KOF_FLOW_ROLE_NONE },
	{ "NtSetInformationThread", KOF_NUCLEO_ANTI_DEBUG, KOF_FLOW_ROLE_NONE },
	/* Moving the boundary of what it can see. */
	{ "chroot",         KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE },
	{ "pivot_root",     KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE },
	{ "setns",          KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE },
	{ "unshare",        KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE },
	/*
	 * AND WORDS FOR CAPABILITIES THAT ALREADY EXISTED, where only the
	 * spelling was missing. Changing one's own privileges is CRED_SET
	 * whether a kernel module calls commit_creds or a program calls
	 * setuid; reaching into another process is PROC_MEM whether it is
	 * WriteProcessMemory or process_vm_writev.
	 */
	{ "setuid",         KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setgid",         KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "seteuid",        KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setreuid",       KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setresuid",      KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "AdjustTokenPrivileges", KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "OpenProcessToken",      KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "DuplicateTokenEx",      KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "ImpersonateLoggedOnUser", KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "SetThreadToken",        KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "process_vm_readv",      KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "process_vm_writev",     KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "posix_spawn",           KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessAsUserA",  KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessAsUserW",  KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessWithTokenW", KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessWithLogonW", KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteExA",       KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteExW",       KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	/* The three measured ones. */
	{ "dup2",           KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "dup3",           KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "utime",          KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "utimes",         KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "utimensat",      KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "futimens",       KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "SetFileTime",    KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "CreateToolhelp32Snapshot", KOF_NUCLEO_PROC_LIST,
	  KOF_FLOW_ROLE_NONE },
	{ "Process32First", KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32FirstW", KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32Next",  KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32NextW", KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Module32First",  KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Module32Next",   KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Thread32First",  KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Thread32Next",   KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "EnumProcesses",  KOF_NUCLEO_PROC_LIST, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE GAPS THE SAME MEASUREMENT FOUND IN WORDS THAT ALREADY
	 * EXISTED - each one a spelling nobody had written down.
	 */
	{ "BCryptOpenAlgorithmProvider", KOF_NUCLEO_CRYPTO,
	  KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyA",  KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyW",  KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyExA", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyExW", KOF_NUCLEO_REG_SET, KOF_FLOW_ROLE_NONE },
	/* An allocation, and incidentally one that fails in some sandboxes -
	 * which is why a loader picks it. The capability is the allocation. */
	{ "VirtualAllocExNuma", KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtQueryInformationProcess", KOF_NUCLEO_ANTI_DEBUG,
	  KOF_FLOW_ROLE_NONE }
};

/*
 * The syscall half of the vocabulary, for a caller that has a RUN rather
 * than code. Exported rather than copied for the reason at the head of
 * nucleo.h: a second table is a second thing to keep right.
 */
/*
 * WHAT KIND OF SOCKET `socket(domain, type, ...)` MADE, from the first two
 * arguments. One statement of it, read by the syscall and by the named call
 * (kof_flow_cap_of_call): the Windows socket()/WSASocket* take the same two
 * values in the same order, and AF_UNIX and SOCK_RAW are the same numbers.
 */
static uint16_t sock_kind(const uint64_t *arg, uint8_t *flags)
{
	if ((arg[0] & 0xffu) == FLOW_AF_UNIX && flags)
		*flags |= KOF_FLOWF_LOCAL;
	if ((arg[1] & 0xfu) == FLOW_SOCK_RAW)
		return KOF_NUCLEO_NET_RAW;
	if ((arg[1] & 0xfu) == FLOW_SOCK_DGRAM && flags)
		*flags |= KOF_FLOWF_DGRAM;
	return KOF_NUCLEO_NET_OPEN;
}

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
 * kof_flow_cap_of_syscall for these arguments and no others: for a length or a
 * protection a partly-known number is a wrong number.
 */
int kof_flow_arg_is_flags(unsigned bits, uint32_t nr, unsigned idx)
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
int kof_flow_sock_nonblock(unsigned bits, uint32_t nr, const uint64_t *arg,
			   unsigned have)
{
	int is_socket = bits == 32 ? nr == 359u : nr == 41u;

	return is_socket && (have & 2u) && (arg[1] & FLOW_O_NONBLOCK);
}

int kof_flow_sockcall_nonblock(uint32_t sub, const uint64_t *arg, unsigned have)
{
	return sub == 1u && (have & 2u) && (arg[1] & FLOW_O_NONBLOCK);
}

static uint16_t flow_opt_cap(unsigned bits, uint32_t nr, const uint64_t *arg)
{
	int is_fcntl = bits == 32 ? (nr == 55u || nr == 221u) : nr == 72u;
	int is_setsockopt = bits == 32 ? nr == 366u : nr == 54u;

	if (is_fcntl && (arg[1] & 0xffffffffu) == FLOW_F_SETFL &&
	    (arg[2] & FLOW_O_NONBLOCK))
		return KOF_NUCLEO_FD_NONBLOCK;
	if (is_setsockopt && (arg[1] & 0xffffffffu) == FLOW_IPPROTO_IP &&
	    (arg[2] & 0xffffffffu) == FLOW_IP_HDRINCL)
		return KOF_NUCLEO_NET_HDRINCL;
	return KOF_NUCLEO_NONE;
}

/*
 * A NAMED CALL, REFINED BY THE ARGUMENTS IT WAS MADE WITH - the same job
 * kof_flow_cap_of_syscall does for a system call, for code that reached an API
 * by name or was observed calling one.
 *
 * VirtualAlloc and VirtualProtect become an executable allocation when the
 * protection asks for execute (PAGE_EXECUTE 0x10, _READ 0x20, _READWRITE 0x40,
 * _WRITECOPY 0x80), and W+X when it also asks for write: the Windows words for
 * what mmap and mprotect say with PROT_EXEC. Measured, the Metasploit stager
 * asks for 0x40.
 *
 * `arg` holds the first four arguments, which is what is carried; a call whose
 * protection is a later argument is left as it was named rather than guessed.
 */
uint16_t kof_flow_cap_of_call(const char *name, const uint64_t *arg,
			      uint8_t *flags)
{
	uint16_t cap = kof_flow_cap_of_name(name);

	if (flags)
		*flags = 0;
	if (!arg || cap == KOF_NUCLEO_NONE)
		return cap;
	if (cap == KOF_NUCLEO_ALLOC) {
		uint64_t prot = 0;
		int have = 0;

		if (!strcmp(name, "VirtualAlloc")) {
			prot = arg[3];
			have = 1;
		} else if (!strcmp(name, "VirtualProtect")) {
			prot = arg[2];
			have = 1;
		}
		if (have && (prot & 0xf0u)) {
			if (flags && (prot & 0xc0u))    /* ..._READWRITE, ..._WRITECOPY */
				*flags = KOF_FLOWF_WX;
			return KOF_NUCLEO_ALLOC_EXEC;
		}
		return cap;
	}
	if (cap == KOF_NUCLEO_NET_OPEN &&
	    (!strcmp(name, "socket") || !strcmp(name, "WSASocketA") ||
	     !strcmp(name, "WSASocketW")))
		return sock_kind(arg, flags);
	return cap;
}

/*
 * THE CAPABILITY OF ONE OPERATION OF i386's socketcall, with the arguments that
 * were found in the array its second argument points at. `have` says which of
 * them were: a socket whose domain and type were not read is a socket of an
 * unknown kind and must not be refined from zeros.
 */
uint16_t kof_flow_cap_of_sockcall(uint32_t sub, const uint64_t *arg,
				  unsigned have, uint8_t *flags)
{
	uint16_t cap = kof_sys_look(kof_sockcall, kof_sockcall_n, sub);

	if (flags)
		*flags = 0;
	if (cap == KOF_NUCLEO_NET_OPEN && sub == 1u && arg && (have & 3u) == 3u)
		return sock_kind(arg, flags);
	/* setsockopt(fd, level, optname, ...): the operation whose arguments are a
	 * claim - see flow_opt_cap for the numbers. */
	if (sub == 14u && arg && (have & 6u) == 6u &&
	    (arg[1] & 0xffffffffu) == FLOW_IPPROTO_IP &&
	    (arg[2] & 0xffffffffu) == FLOW_IP_HDRINCL)
		return KOF_NUCLEO_NET_HDRINCL;
	return cap;
}

uint16_t kof_flow_cap_of_syscall(unsigned bits, uint32_t nr,
				const uint64_t *arg, uint8_t *flags)
{
	uint16_t cap;

	if (flags)
		*flags = 0;
	if (bits == 32) {
		/* socketcall multiplexes; the operation is the first argument
		 * and without it the number says only "something network". */
		if (nr == 102u) {
			if (!arg)
				return KOF_NUCLEO_NONE;
			return kof_sys_look(kof_sockcall,
				    kof_sockcall_n,
				    (uint32_t)arg[0]);
		}
		cap = kof_sys_look(kof_sys32, kof_sys32_n, nr);
	} else {
		cap = kof_sys_look(kof_sys64, kof_sys64_n, nr);
	}
	/*
	 * PROT_EXEC, WHICH IS THE WHOLE DIFFERENCE between a buffer and a
	 * payload. Unlike the Windows side there is no guessing to do: mmap
	 * and mprotect both carry prot in the third argument, and i386's
	 * mmap2 and old_mmap do too.
	 */
	/* The same two refinements the sweep makes, from the arguments a run
	 * recorded instead of from a constant map. One rule, two readers. */
	if (arg && cap == KOF_NUCLEO_SPAWN &&
	    (bits == 32 ? nr == 120u : nr == 56u))
		return (arg[0] & FLOW_CLONE_THREAD) ? KOF_NUCLEO_THREAD
						    : KOF_NUCLEO_SPAWN;
	if (arg && cap == KOF_NUCLEO_NET_OPEN && bits != 32 && nr == 41u)
		return sock_kind(arg, flags);
	/*
	 * fcntl AND setsockopt ARE NOT WORDS HERE, only the two things they can
	 * say that a rule is entitled to build on - and only when the arguments
	 * that say it were read. A call whose cmd or level was not followed is
	 * not a node at all, which is the honest state: a node reading as
	 * "something with a descriptor" would be matched by nothing and mean
	 * nothing.
	 */
	if (arg && cap == KOF_NUCLEO_NONE)
		return flow_opt_cap(bits, nr, arg);
	if (cap == KOF_NUCLEO_ALLOC && arg) {
		int is_map = bits == 32 ? (nr == 90u || nr == 125u || nr == 192u)
					: (nr == 9u || nr == 10u);

		if (is_map && (arg[2] & 4u)) {         /* PROT_EXEC */
			/*
			 * W+X IS A DIFFERENT FACT FROM EXECUTABLE, and the
			 * note on KOF_FLOWF_WX is the whole reason: a JIT
			 * asks for RW and flips to RX, so it is never both
			 * at once; a loader asks for RWX in one call. Both
			 * are ALLOC_EXEC and only the second is W+X.
			 */
			if (flags && (arg[2] & 2u))    /* PROT_WRITE too */
				*flags = KOF_FLOWF_WX;
			return KOF_NUCLEO_ALLOC_EXEC;
		}
	}
	return cap;
}

const char *kof_sys_name(unsigned bits, uint32_t nr)
{
	return bits == 64 ? kof_sys_look_name(kof_sys64, kof_sys64_n, nr)
			  : kof_sys_look_name(kof_sys32, kof_sys32_n, nr);
}

/*
 * THE SAME TWO QUESTIONS FOR A PORT THAT HAS ITS OWN TABLE.
 *
 * kof_flow_cap_of_syscall above is x86's: `bits` picks between two tables and
 * the refinements test x86 numbers. A fixed-width port is described by its
 * fxabi instead - table, and which argument holds prot - and the refinements
 * are keyed by the ROW's role, which is what the role column is for: a row
 * that says it is mmap is asked about PROT_EXEC whatever number it has.
 *
 * Only the rows the port's table has. A number with no row is NONE, which the
 * caller records as a syscall the vocabulary has no word for.
 */
static uint16_t fx_look(const struct fxabi *fx, uint32_t nr, uint8_t *role,
			const char **name)
{
	uint32_t i;

	for (i = 0; i < fx->n_tab; i++) {
		if (fx->tab[i].nr != nr)
			continue;
		*role = fx->tab[i].role;
		*name = fx->tab[i].name;
		return fx->tab[i].cap;
	}
	for (i = 0; i < fx->n_tab2; i++) {
		if (fx->tab2[i].nr != nr)
			continue;
		*role = fx->tab2[i].role;
		*name = fx->tab2[i].name;
		return fx->tab2[i].cap;
	}
	*role = KOF_FLOW_ROLE_NONE;
	*name = NULL;
	return KOF_NUCLEO_NONE;
}

uint16_t kof_flow_cap_of_syscall_abi(const struct fxabi *fx, uint32_t nr,
				     const uint64_t *arg, uint8_t *flags)
{
	const char *nm;
	uint8_t role;
	uint16_t cap = fx_look(fx, nr, &role, &nm);

	if (flags)
		*flags = 0;
	if (arg && cap == KOF_NUCLEO_SPAWN && role == KOF_FLOW_ROLE_CLONE)
		return (arg[0] & FLOW_CLONE_THREAD) ? KOF_NUCLEO_THREAD
						    : KOF_NUCLEO_SPAWN;
	if (arg && cap == KOF_NUCLEO_NET_OPEN && role == KOF_FLOW_ROLE_SOCK)
		return sock_kind(arg, flags);
	if (arg && cap == KOF_NUCLEO_ALLOC && role == KOF_FLOW_ROLE_MMAP &&
	    (arg[fx->prot_arg] & 4u)) {         /* PROT_EXEC */
		if (flags && (arg[fx->prot_arg] & 2u))
			*flags = KOF_FLOWF_WX;
		return KOF_NUCLEO_ALLOC_EXEC;
	}
	return cap;
}

const char *kof_sys_name_abi(const struct fxabi *fx, uint32_t nr)
{
	const char *nm;
	uint8_t role;

	fx_look(fx, nr, &role, &nm);
	return nm;
}

uint16_t kof_flow_cap_of_name(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return KOF_NUCLEO_NONE;
	/* An ELF import may carry a version suffix - "open64@@GLIBC_2.2.5" is
	 * the same function as "open64", and the caller should not have to
	 * know that this file cares. */
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return names[i].cap;
	}
	return KOF_NUCLEO_NONE;
}

uint8_t kof_flow_role_of_name(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return KOF_FLOW_ROLE_NONE;
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return names[i].role;
	}
	return KOF_FLOW_ROLE_NONE;
}

uint16_t kof_flow_name_id(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return 0;
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return (uint16_t)(i + 1u);
	}
	return 0;
}

const char *kof_flow_name_of(uint16_t id)
{
	if (!id || id > sizeof names / sizeof names[0])
		return NULL;
	return names[id - 1u].name;
}

/*
 * DOES THIS STEP MAKE SOMETHING A LATER STEP CAN HOLD.
 *
 * A link is a VARIABLE: one step produces a value and another uses it.
 * `socket` makes a descriptor, `mmap` makes a mapping, `LoadLibrary` makes a
 * module handle - each of those is the head of a link and every later step
 * that takes it is the tail.
 *
 * MOST CALLS MAKE NOTHING OF THE KIND. `fork` answers with a process id,
 * `write` with a byte count, `Process32First` with a boolean - nobody passes
 * those to anything as a resource. A link whose head is one of them is an
 * artefact of following a register, and MEASURED over 609 objects it was a
 * fifth of all the links kept: 86 `spawn -> spawn`, 55 `file-open ->
 * file-open` where the second argument is a PATH, 35 `process-list ->
 * process-list`, 22 `file-write -> file-write`.
 *
 * So the vocabulary says which words make a thing, and a link with any other
 * head is not stored. It is the same question kof_flow_role_of_name answers
 * for sockets, asked of every word.
 */
int kof_flow_cap_makes(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_ALLOC:        /* a mapping                        */
	case KOF_NUCLEO_ALLOC_EXEC:
	case KOF_NUCLEO_NET_OPEN:     /* a descriptor                     */
	case KOF_NUCLEO_NET_RAW:
	case KOF_NUCLEO_NET_ACCEPT:
	case KOF_NUCLEO_FILE_OPEN:
	case KOF_NUCLEO_MEMFD:
	case KOF_NUCLEO_PIPE_OPEN:
	case KOF_NUCLEO_PIPE:
	case KOF_NUCLEO_HEAP:        /* a buffer - see KOF_NUCLEO_HEAP   */
	case KOF_NUCLEO_REG_OPEN:    /* a key handle                  */
	case KOF_NUCLEO_LIB_OPEN:     /* a module handle                  */
	case KOF_NUCLEO_RESOLVE:      /* an address - see lib-resolve     */
	case KOF_NUCLEO_PTRACE:       /* a handle on another process      */
	case KOF_NUCLEO_SELF_RESOLVE:
	case KOF_NUCLEO_PROC_LIST:    /* a snapshot handle to walk        */
	case KOF_NUCLEO_NET_ADDR:     /* an address built for a connect   */
	case KOF_NUCLEO_DNS:
	/*
	 * AND A TRANSFER MAKES THE BYTES IT WROTE.
	 *
	 * What `read` produces is not a handle - it is the CONTENT of the
	 * place it was given, and that place is nameable: see
	 * kof_flow_out_arg, which says which argument it writes through.
	 * The two tables have to agree, and they did not: the out-argument
	 * table named the place while this one said the step made nothing,
	 * so `exec-memory` joined to the `read` that filled it was built,
	 * carried, and then dropped by the one pass that asks this
	 * question. A stager is exactly that edge.
	 */
	case KOF_NUCLEO_READ:
	case KOF_NUCLEO_NET_READ:
		return 1;
	default:
		return 0;
	}
}

/*
 * WHAT TO CALL THE THING A STEP MADE, when a later step is handed it.
 *
 * A link is a variable, and a variable wants a name that says WHAT it is.
 * The renderer used to number them in order of appearance - `link_1`,
 * `link_2` - which puts a different thing behind the same name in every
 * chain of the same file: `link_1` was a socket in one and a file handle
 * in the next, and nothing on the page said which. The number carried no
 * information and the collision it was meant to avoid is rare.
 *
 * So the noun comes from the capability, which is the one thing about the
 * value that does not move. Two mappings in one chain are `mem` and
 * `mem2`; a mapping and an executable mapping are `mem` and `mem_x` and
 * need no counter at all, which is the case where telling them apart
 * matters - `exec-memory(mem_x)` says which of the two was entered.
 *
 * Only producers have one - see kof_flow_cap_makes. NULL for the rest.
 */
/*
 * WHICH ARGUMENT OF THIS STEP IS A STRING, as index plus one, or 0.
 *
 * A path and a program name are the two things a reader most wants off
 * this page and the two it could least get: the value is an ADDRESS, so
 * the row said `open(0x4a8c84)` and the reader went to a hex editor. The
 * bytes are in the object; this says WHICH argument to go and read.
 *
 * BY THE NAME AND NOT ONLY THE WORD, because `openat` puts the path
 * second - the directory handle is first - and `open` puts it first. One
 * word, two shapes, and guessing either way is wrong half the time.
 */
uint8_t kof_flow_text_arg(uint16_t cap, uint16_t name)
{
	const char *nm = kof_flow_name_of(name);

	switch (cap) {
	case KOF_NUCLEO_FILE_OPEN:
		if (nm && (!strcmp(nm, "openat") || !strcmp(nm, "openat2")))
			return 2u;
		return 1u;
	case KOF_NUCLEO_EXEC_IMAGE:
		return 1u;
	default:
		return 0u;
	}
}

/*
 * WHICH ARGUMENT THIS STEP WRITES ITS RESULT THROUGH - index plus one,
 * or 0 when it hands everything back in the return register.
 *
 * `pipe(fds)` puts two descriptors in the caller's array and `read(fd,
 * buf, n)` puts the bytes in the caller's buffer. The place is the only
 * thing a later step can be joined to, and without this table it has no
 * name: MEASURED on an msfvenom stager, `read` filled a stack buffer and
 * the `jmp *%ecx` two instructions later - the second stage starting -
 * had nothing to point at.
 *
 * The TRANSFERS and not the queries: `stat` fills a buffer too, and what
 * comes back is a description of a file rather than a thing the program
 * then uses.
 */
uint8_t kof_flow_out_arg(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_PIPE_OPEN:  return 1u;   /* the pair of descriptors */
	case KOF_NUCLEO_READ:
	case KOF_NUCLEO_NET_READ:   return 2u;   /* the bytes */
	default:                 return 0u;
	}
}

const char *kof_flow_cap_noun(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_ALLOC:        return "mem";
	case KOF_NUCLEO_ALLOC_EXEC:   return "mem_x";
	case KOF_NUCLEO_NET_OPEN:     return "sock";
	case KOF_NUCLEO_NET_RAW:      return "sock_raw";
	case KOF_NUCLEO_NET_ACCEPT:   return "conn";
	case KOF_NUCLEO_FILE_OPEN:    return "file";
	case KOF_NUCLEO_MEMFD:        return "memfd";
	case KOF_NUCLEO_PIPE:         return "pipe";
	case KOF_NUCLEO_PIPE_OPEN:    return "pipe";
	case KOF_NUCLEO_HEAP:         return "buf";
	case KOF_NUCLEO_REG_OPEN:     return "key";
	/*
	 * AND A TRANSFER MAKES BYTES, which this table said it did not.
	 *
	 * kof_flow_cap_makes names READ and NET_READ - see the note there -
	 * and the header says the two tables are the same set. They were
	 * not: a `read` was a producer with nothing to call what it
	 * produced. Checked by walking both tables over every word, which
	 * found these two and nothing else.
	 */
	case KOF_NUCLEO_READ:
	case KOF_NUCLEO_NET_READ:     return "bytes";
	case KOF_NUCLEO_LIB_OPEN:     return "lib";
	case KOF_NUCLEO_RESOLVE:      return "sym";
	case KOF_NUCLEO_SELF_RESOLVE: return "sym";
	case KOF_NUCLEO_PTRACE:       return "proc";
	case KOF_NUCLEO_PROC_LIST:    return "snap";
	case KOF_NUCLEO_NET_ADDR:     return "addr";
	case KOF_NUCLEO_DNS:          return "addr";
	default:                   return NULL;
	}
}

/*
 * THE WORD THIS ONE IS A SPECIAL CASE OF, or KOF_NUCLEO_NONE.
 *
 * WHY A VOCABULARY NEEDS THIS AT ALL. Some capabilities are the same act
 * with a fact added:
 *
 *     net-recv, file-read   are mem-read with the descriptor identified
 *     net-send, file-write  are mem-write, likewise
 *     mem-alloc-exec        is mem-alloc with PROT_EXEC in its argument
 *
 * A rule names the level it MEANS. "A region was allocated writable and
 * executable" has to say mem-alloc-exec, because mem-alloc would match every
 * malloc on the machine. "Something filled it" has to say mem-read, because
 * the diagnose is true whether the bytes came off a socket or out of a file -
 * and MEASURED, naming the specific word instead is how rwx_exec stopped
 * matching the moment the engine learned to tell a socket read from a file
 * read. The rule had not changed and the program had not changed; only the
 * precision of the word had.
 *
 * SO THE MATCHER ASKS "IS THIS THAT, OR A KIND OF THAT", and the relation
 * lives here with the names rather than in the matcher, because it is a fact
 * about the vocabulary. One level is enough today; the walk is written as a
 * loop so a second does not need a second mechanism.
 *
 * IT IS NOT A GROUP. net-recv is in KOF_CG_NET and mem-read in KOF_CG_IO,
 * which is right - they answer different questions - so the encoding cannot
 * carry this and a table must.
 */
uint16_t kof_flow_cap_generic(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_NET_READ:
	case KOF_NUCLEO_READ:         return KOF_NUCLEO_MEM_READ;
	case KOF_NUCLEO_NET_WRITE:
	case KOF_NUCLEO_WRITE:        return KOF_NUCLEO_MEM_WRITE;
	case KOF_NUCLEO_ALLOC_EXEC:   return KOF_NUCLEO_ALLOC;
	default:                   return KOF_NUCLEO_NONE;
	}
}

const char *kof_flow_cap_name(uint16_t cap)
{
	switch (cap) {
	case KOF_NUCLEO_ALLOC:        return "mem-alloc";
	case KOF_NUCLEO_ALLOC_EXEC:   return "mem-alloc-exec";
	case KOF_NUCLEO_HEAP:         return "mem-alloc-heap";
	case KOF_NUCLEO_FIELD_READ:   return "mem-field-read";
	case KOF_NUCLEO_FIELD_WRITE:  return "mem-field-write";
	case KOF_NUCLEO_REG_OPEN:     return "reg-open";
	/* "exec-memory" and not "exec-register": the register is how the
	 * branch was spelled, the memory is what was entered. */
	case KOF_NUCLEO_EXEC_REG:     return "exec-memory";
	case KOF_NUCLEO_SELF_RESOLVE: return "lib-peb-walk";
	case KOF_NUCLEO_NAME_HASH:    return "lib-name-hash";
	/*
	 * "lib-call-indirect", AND IT USED TO BE "call-register".
	 *
	 * Two things were wrong with the old spelling. It was the only word
	 * in KOF_CG_LIB without the group's prefix - lib-api-resolve,
	 * lib-peb-walk, lib-name-hash - so a reader could not tell what
	 * family it belonged to. And it named the register, which is the way
	 * the instruction was WRITTEN, after the line directly above it had
	 * just refused to do that for exec-memory on the ground that the
	 * spelling is not the fact.
	 *
	 * What the fact is: a call whose target is not named at the call. The
	 * target was decided earlier, wherever the pointer was stored, and
	 * that is the whole difficulty - see the note on retpoline thunks in
	 * the table above.
	 */
	case KOF_NUCLEO_CALL_REG:     return "lib-call-indirect";
	case KOF_NUCLEO_CRYPTO:       return "crypto";
	case KOF_NUCLEO_CAPTURE:      return "input-capture";
	case KOF_NUCLEO_SVC_INSTALL:  return "service-install";
	case KOF_NUCLEO_MOD_LOAD:     return "kmodule-load";
	case KOF_NUCLEO_PIPE:         return "pipe-named-create";
	case KOF_NUCLEO_PIPE_OPEN:    return "pipe-create";
	case KOF_NUCLEO_FILE_DELETE:  return "file-delete";
	case KOF_NUCLEO_FILE_RENAME:  return "file-rename";
	case KOF_NUCLEO_PERM_SET:     return "file-perm-set";
	case KOF_NUCLEO_ANTI_DEBUG:   return "anti-debug";
	case KOF_NUCLEO_JAIL:         return "namespace-change";
	case KOF_NUCLEO_FD_REDIR:     return "fd-redirect";
	case KOF_NUCLEO_TIMESTOMP:    return "file-timestamp-set";
	case KOF_NUCLEO_PROC_LIST:    return "proc-enum";
	case KOF_NUCLEO_NET_READ:     return "net-recv";
	case KOF_NUCLEO_NET_WRITE:    return "net-send";
	case KOF_NUCLEO_FD_NONBLOCK:  return "fd-nonblock";
	case KOF_NUCLEO_NET_HDRINCL:  return "net-hdrincl";
	case KOF_NUCLEO_HTTP_OPEN:    return "http-open";
	case KOF_NUCLEO_HTTP_CONNECT: return "http-connect";
	case KOF_NUCLEO_HTTP_SEND:    return "http-send";
	case KOF_NUCLEO_HTTP_RECV:    return "http-recv";
	case KOF_NUCLEO_HTTP_FETCH:   return "http-fetch";
	case KOF_NUCLEO_NET_OPEN:     return "net-open";
	case KOF_NUCLEO_NET_CONNECT:  return "net-connect";
	case KOF_NUCLEO_NET_ACCEPT:   return "net-accept";
	case KOF_NUCLEO_NET_BIND:     return "net-bind";
	case KOF_NUCLEO_NET_LISTEN:   return "net-listen";
	case KOF_NUCLEO_MEM_READ:      return "mem-read";
	case KOF_NUCLEO_MEM_WRITE:     return "mem-write";
	case KOF_NUCLEO_READ:         return "file-read";
	case KOF_NUCLEO_WRITE:        return "file-write";
	case KOF_NUCLEO_FILE_OPEN:    return "file-open";
	case KOF_NUCLEO_MEMFD:        return "memfd-create";
	case KOF_NUCLEO_EXEC_IMAGE:   return "proc-start";
	case KOF_NUCLEO_SPAWN:        return "proc-fork";
	case KOF_NUCLEO_THREAD:       return "thread-create";
	case KOF_NUCLEO_NET_RAW:      return "net-raw";
	case KOF_NUCLEO_SLEEP:        return "sleep";
	case KOF_NUCLEO_PTRACE:       return "proc-open";
	case KOF_NUCLEO_PROC_MEM:     return "proc-mem-access";
	case KOF_NUCLEO_PROC_EXEC:    return "proc-control";
	case KOF_NUCLEO_RESOLVE:      return "lib-api-resolve";
	case KOF_NUCLEO_LIB_OPEN:     return "lib-load";
	case KOF_NUCLEO_DNS:          return "net-getaddr";
	case KOF_NUCLEO_REG_SET:      return "reg-set";
	case KOF_NUCLEO_CRED_SET:     return "cred-modify";
	case KOF_NUCLEO_HOOK:         return "kmodule-hook";
	case KOF_NUCLEO_KPROBE_REG:   return "kmodule-kprobe-register";
	case KOF_NUCLEO_KPROBE_UNREG: return "kmodule-kprobe-unregister";
	case KOF_NUCLEO_COPY_FROM_USER: return "kmodule-copy-from-user";
	case KOF_NUCLEO_COPY_TO_USER: return "kmodule-copy-to-user";
	case KOF_NUCLEO_KSYM_LOOKUP:  return "kmodule-ksym-lookup";
	case KOF_NUCLEO_SYMBOL_GET:   return "kmodule-symbol-get";
	case KOF_NUCLEO_CRED_PREPARE: return "cred-prepare";
	case KOF_NUCLEO_LIST_HIDE:    return "kmodule-list-edit";
	/* Named for the x86 instruction, which is the fault that took the
	 * word out of service - see the note in the import table. */
	case KOF_NUCLEO_PROT_OFF:     return "kmodule-write-protect-off";
	case KOF_NUCLEO_NET_ADDR:     return "net-addr";
	case KOF_NUCLEO_SELF_HIDE:    return "self-hide";
	case KOF_NUCLEO_BACKGROUND:   return "proc-background";
	default:                   return "?";
	}
}

/* See the note in nucleo.h. */
unsigned kof_flow_name_arg(uint16_t cap, unsigned *arg)
{
	if (arg)
		*arg = 0u;
	switch (cap) {
	/* A resolver is handed the word it is to find. */
	case KOF_NUCLEO_KSYM_LOOKUP:
	case KOF_NUCLEO_SYMBOL_GET:
		return KOF_NAME_DIRECT;
	/*
	 * A probe is handed an OBJECT, and the name it is to be placed on is
	 * one of the pointers in it - see the note in nucleo.h for why this
	 * does not say which.
	 */
	case KOF_NUCLEO_KPROBE_REG:
		return KOF_NAME_OBJECT;
	default:
		return 0u;
	}
}

/* See the note in nucleo.h - this is the vocabulary's own answer, and the
 * only one. */
int kof_flow_hands_on(uint16_t cap, const char *nm)
{
	switch (cap) {
	case KOF_NUCLEO_ALLOC:
	case KOF_NUCLEO_ALLOC_EXEC:
	case KOF_NUCLEO_HEAP:
		/*
		 * mprotect shares the word with mmap and is not a
		 * constructor: it is handed a mapping and returns a status.
		 */
		return !(nm && (!strcmp(nm, "mprotect") ||
				!strcmp(nm, "mprotect64")));
	case KOF_NUCLEO_NET_OPEN:
	case KOF_NUCLEO_NET_RAW:
	case KOF_NUCLEO_NET_ACCEPT:
	case KOF_NUCLEO_FILE_OPEN:
	case KOF_NUCLEO_MEMFD:
	case KOF_NUCLEO_PIPE_OPEN:
	/* The kernel side: a credential to edit and commit, and the address
	 * of whatever was looked up. */
	case KOF_NUCLEO_CRED_PREPARE:
	case KOF_NUCLEO_KSYM_LOOKUP:
	case KOF_NUCLEO_SYMBOL_GET:
		return 1;
	default:
		return 0;
	}
}

/* The syscall tables, one per ABI. Only the numbers the vocabulary names. */

/*
 * AArch64 and anything else on asm-generic. VERIFIED against
 * /usr/include/asm-generic/unistd.h; mmap is __NR3264_mmap, which is 222.
 */
const struct sysrow kof_sys_a64[] = {
	{   56, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{   63, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{   64, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 101, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 117, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 198, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 200, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 201, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 202, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 203, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 206, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 207, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 220, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 221, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 222, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see fixed_prot */
	{ 226, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{ 279, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
};

/*
 * ARM EABI. The low numbers are i386's, which ARM inherited - so these agree
 * with kof_sys32 above and are not a second claim about them. The socket calls
 * are ARM's own, past where the shared range ends: i386 multiplexes them
 * through socketcall and ARM does not.
 *
 * NOT FROM A HEADER - this host has none for ARM. Corroborated on the corpus
 * instead, and the shape of the agreement is the evidence: across 1771 ARM
 * objects, 281, 283 and 289 each appear in 97 files, 291 and 290 in 96.
 * A program that opens a socket connects and sends on it, so a table that
 * had any of these wrong would not produce counts that track each other.
 */
const struct sysrow kof_sys_arm[] = {
	{     2, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     4, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   11, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{   26, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 120, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 190, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "vfork"  },
	{ 192, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap2"  },
	{ 281, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 282, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 283, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 284, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 285, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 289, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 290, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 291, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 292, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 322, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 385, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
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
const struct sysrow kof_sys_mips[] = {
	{ 4002, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{ 4003, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{ 4004, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 4005, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{ 4011, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 4026, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 4090, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 4120, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 4125, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 4166, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 4168, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 4169, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 4170, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 4174, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 4175, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 4176, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 4178, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 4180, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 4183, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 4288, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 4354, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
};

/*
 * POWERPC, AND IT INHERITED i386's NUMBERS.
 *
 * NOT FROM A HEADER - there is none for any of these on this host - and
 * corroborated the way kof_sys_arm and kof_sys_mips were, from what the corpus
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
const struct sysrow kof_sys_ppc[] = {
	{ 326, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 327, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 328, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 329, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 330, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 334, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 335, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 336, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 337, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  }
};

/*
 * SPARC, WHICH KEPT ITS OWN NUMBERING and is the one port here that did.
 *
 * Corroborated the same way, over 256 objects: 206 appears in 94.5% of them
 * and 102, 103, 155, 44, 53, 69, 70 move with it. That is SPARC's socket at
 * 206, not i386's at anything - and the agreement of the group is the
 * evidence, because a mis-numbered table does not produce counts that track.
 */
const struct sysrow kof_sys_sparc[] = {
	{     1, KOF_NUCLEO_NONE, KOF_FLOW_ROLE_NONE, "exit"  },
	{     2, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     4, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   26, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{   59, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{   71, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{   74, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 206, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 207, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 232, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 233, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 234, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 235, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 240, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 284, KOF_NUCLEO_THREAD, KOF_FLOW_ROLE_NONE, "clone"  }
};



/*
 * MIPS n64, which bases its numbering at 5000.
 *
 * FROM A HEADER THIS TIME, and the header is named because the o32 table
 * beside it was not: /run/host/usr/lib/linux/uapi/mips/asm/unistd_n64.h on
 * this machine. Corroborated against the corpus anyway - see
 * KOF_FLOW_A_MIPS64 - because a header read wrongly is as quiet as a number
 * remembered wrongly.
 *
 * NOT AN OFFSET FROM THE o32 TABLE. 4003 is read on o32 and 5003 is close on
 * n64; the lists diverge immediately and anything derived by adding 1000
 * would be confidently wrong.
 */
const struct sysrow kof_sys_mips64[] = {
	{ 5000, KOF_NUCLEO_MEM_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{ 5001, KOF_NUCLEO_MEM_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 5002, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{ 5247, KOF_NUCLEO_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 5009, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 5010, KOF_NUCLEO_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 5055, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 5056, KOF_NUCLEO_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{ 5057, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 5316, KOF_NUCLEO_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	{ 5040, KOF_NUCLEO_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 5041, KOF_NUCLEO_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 5042, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 5293, KOF_NUCLEO_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept4"  },
	{ 5048, KOF_NUCLEO_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 5049, KOF_NUCLEO_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 5043, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 5044, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 5045, KOF_NUCLEO_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendmsg"  },
	{ 5046, KOF_NUCLEO_NET_READ, KOF_FLOW_ROLE_NONE, "recvmsg"  },
	{ 5034, KOF_NUCLEO_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 5099, KOF_NUCLEO_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 5314, KOF_NUCLEO_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 5085, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{ 5253, KOF_NUCLEO_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 5080, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "rename"  },
	{ 5254, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 5311, KOF_NUCLEO_FILE_RENAME, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{ 5088, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{ 5089, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 5258, KOF_NUCLEO_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{ 5103, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{ 5104, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{ 5111, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 5115, KOF_NUCLEO_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 5304, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 5305, KOF_NUCLEO_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 5168, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 5169, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 5307, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 5315, KOF_NUCLEO_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{ 5156, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 5151, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 5303, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 5262, KOF_NUCLEO_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{ 5032, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{ 5286, KOF_NUCLEO_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{ 5130, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 5226, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 5251, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 5275, KOF_NUCLEO_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
};

/* `v` against a table of single bits, joined with '|'. Returns how much was
 * written, 0 when no bit matched. */
static uint32_t bits_join(uint64_t v, const char *const *nm,
			  const uint64_t *bit, uint32_t n, char *out,
			  uint32_t cap)
{
	uint32_t i, at = 0;

	for (i = 0; i < n && at + 16u < cap; i++)
		if ((v & bit[i]) == bit[i] && bit[i])
			at += (uint32_t)snprintf(out + at, cap - at, "%s%s",
						 at ? "|" : "", nm[i]);
	return at;
}

const char *kof_flow_arg_name(uint16_t name, uint16_t cap, uint32_t idx,
			      uint64_t v, char *out, uint32_t n)
{
	static uint16_t id_socket, id_mmap, id_mprotect, id_open, id_openat;
	static uint16_t id_clone, id_pthread, id_createthread;
	static int once;

	if (!out || n < 24u)
		return 0;
	if (!once) {
		once = 1;
		id_socket = kof_flow_name_id("socket");
		id_mmap = kof_flow_name_id("mmap");
		id_mprotect = kof_flow_name_id("mprotect");
		id_open = kof_flow_name_id("open");
		id_openat = kof_flow_name_id("openat");
		id_clone = kof_flow_name_id("clone");
		id_pthread = kof_flow_name_id("pthread_create");
		id_createthread = kof_flow_name_id("CreateThread");
	}

	/* socket(domain, type, protocol) - the two that decide what the
	 * socket IS. The numbers are Linux's; Windows agrees on both. */
	if (name && name == id_socket) {
		if (idx == 0u) {
			switch (v) {
			case 1:  return snprintf(out, n, "AF_UNIX"), out;
			case 2:  return snprintf(out, n, "AF_INET"), out;
			case 10: return snprintf(out, n, "AF_INET6"), out;
			case 17: return snprintf(out, n, "AF_PACKET"), out;
			default: return 0;
			}
		}
		if (idx == 1u) {
			switch (v & 0xffu) {
			case 1: return snprintf(out, n, "SOCK_STREAM"), out;
			case 2: return snprintf(out, n, "SOCK_DGRAM"), out;
			case 3: return snprintf(out, n, "SOCK_RAW"), out;
			default: return 0;
			}
		}
		/*
		 * AND THE PROTOCOL, which was not decoded at all.
		 *
		 * Usually 0 - "the default for this domain and type" - and
		 * that is worth saying in words rather than as `0x0`, which
		 * a reader cannot tell from a value the sweep failed to
		 * resolve. It stops being a formality with SOCK_RAW, where
		 * the protocol IS the behaviour: 1 is the ICMP flooder and
		 * 255 is a sender writing its own IP headers.
		 */
		if (idx == 2u) {
			switch (v) {
			case 0:   return snprintf(out, n, "IPPROTO_IP"), out;
			case 1:   return snprintf(out, n, "IPPROTO_ICMP"), out;
			case 6:   return snprintf(out, n, "IPPROTO_TCP"), out;
			case 17:  return snprintf(out, n, "IPPROTO_UDP"), out;
			case 132: return snprintf(out, n, "IPPROTO_SCTP"), out;
			case 255: return snprintf(out, n, "IPPROTO_RAW"), out;
			default:  break;
			}
		}
		return 0;
	}

	/* mmap(addr, len, prot, flags) and mprotect(addr, len, prot). The
	 * protection is the whole of what separates a buffer from a payload,
	 * and `rwx` says it in three characters. */
	if (name && (name == id_mmap || name == id_mprotect)) {
		/* Without the PROT_/MAP_ prefix: the argument's position says
		 * which family it is, and the line has to fit a terminal. */
		static const char *const pn[] = { "READ", "WRITE", "EXEC" };
		static const uint64_t pb[] = { 1, 2, 4 };
		static const char *const fn[] = { "SHARED", "PRIVATE",
						  "FIXED", "ANON" };
		static const uint64_t fb[] = { 1, 2, 0x10, 0x20 };

		if (idx == 2u) {
			if (!v)
				return snprintf(out, n, "NONE"), out;
			return bits_join(v, pn, pb, 3, out, n) ? out : 0;
		}
		if (idx == 3u && name == id_mmap)
			return bits_join(v, fn, fb, 4, out, n) ? out : 0;
		return 0;
	}

	/* clone(flags, ...) and the two library spellings beside it. Only the
	 * bits that change WHAT IS CREATED are named; the rest are the
	 * caller's bookkeeping. */
	if (name && (name == id_clone || name == id_pthread ||
		     name == id_createthread) && idx == 0u) {
		static const char *const cn[] = { "VM", "FS", "FILES",
						  "THREAD", "NEWNS" };
		static const uint64_t cb[] = { 0x100, 0x200, 0x400,
					       0x10000, 0x20000 };

		return bits_join(v, cn, cb, 5, out, n) ? out : 0;
	}

	/* open(path, flags, mode) - the access mode is the low two bits and
	 * is a VALUE, not a flag, so it is switched rather than joined. */
	if (name && (name == id_open || name == id_openat) &&
	    idx == (name == id_openat ? 2u : 1u)) {
		static const char *const on[] = { "O_CREAT", "O_TRUNC",
						  "O_APPEND" };
		static const uint64_t ob[] = { 0x40, 0x200, 0x400 };
		const char *acc = (v & 3u) == 0u ? "O_RDONLY"
				: (v & 3u) == 1u ? "O_WRONLY" : "O_RDWR";
		uint32_t at = (uint32_t)snprintf(out, n, "%s", acc);

		if (at + 16u < n && bits_join(v, on, ob, 3, out + at + 1u,
					      n - at - 1u)) {
			out[at] = '|';
		}
		return out;
	}
	(void)cap;
	return 0;
}

const uint32_t kof_sys64_n = (uint32_t)(sizeof kof_sys64 / sizeof kof_sys64[0]);
const uint32_t kof_sys32_n = (uint32_t)(sizeof kof_sys32 / sizeof kof_sys32[0]);
const uint32_t kof_sockcall_n = (uint32_t)(sizeof kof_sockcall / sizeof kof_sockcall[0]);
const uint32_t kof_sys_a64_n = (uint32_t)(sizeof kof_sys_a64 / sizeof kof_sys_a64[0]);
const uint32_t kof_sys_arm_n = (uint32_t)(sizeof kof_sys_arm / sizeof kof_sys_arm[0]);
const uint32_t kof_sys_mips_n = (uint32_t)(sizeof kof_sys_mips / sizeof kof_sys_mips[0]);
const uint32_t kof_sys_mips64_n = (uint32_t)(sizeof kof_sys_mips64 / sizeof kof_sys_mips64[0]);
const uint32_t kof_sys_ppc_n = (uint32_t)(sizeof kof_sys_ppc / sizeof kof_sys_ppc[0]);
const uint32_t kof_sys_sparc_n = (uint32_t)(sizeof kof_sys_sparc / sizeof kof_sys_sparc[0]);

#define FXN(t) kof_##t, kof_##t##_n

static const struct fxabi FX_MIPS = {
	FXN(sys_mips), NULL, 0, 0, 2, 2, 4, 4, 2
};
/* Same registers and the same `syscall`; only the table differs. */
static const struct fxabi FX_MIPS64 = {
	FXN(sys_mips64), NULL, 0, 0, 2, 2, 4, 4, 2
};
static const struct fxabi FX_ARM = {
	FXN(sys_arm),  NULL, 0, 0, 7, 0, 0, 6, 2
};
static const struct fxabi FX_A64 = {
	FXN(sys_a64),  NULL, 0, 0, 8, 0, 0, 6, 2
};
/*
 * PowerPC: r0 carries the number, r3 the result and the first argument -
 * the same register, which is why the provenance note in sweep_fixed applies
 * here exactly as it does to ARM.
 */
static const struct fxabi FX_PPC = {
	FXN(sys_ppc), FXN(sys32), 102, 0, 3, 3, 6, 2
};
/* SPARC: %g1 is register 1, %o0 is register 8 and is both the result and the
 * first argument. */
static const struct fxabi FX_SPARC = {
	FXN(sys_sparc), NULL, 0, 0, 1, 8, 8, 6, 2
};
/*
 * RISC-V, AND IT NEEDS NO TABLE OF ITS OWN. The port took the generic
 * numbering, which is AArch64's - corroborated over 45 objects, where 93,
 * 94, 56, 57, 198, 214, 215, 220 and 222 are what appears, every one of them
 * a row of kof_sys_a64. a7 is x17 and a0 is x10.
 */
static const struct fxabi FX_RISCV = {
	FXN(sys_a64), NULL, 0, 0, 17, 10, 10, 6, 2
};
/* SuperH: r3 the number, r0 the result, r4 the first argument. */
static const struct fxabi FX_SH = {
	FXN(sys32), NULL, 0, 102, 3, 0, 4, 4, 2
};
/* m68k: d0 the number AND the result, d1 the first argument. */
static const struct fxabi FX_M68K = {
	FXN(sys32), NULL, 0, 102, 0, 0, 1, 5, 2
};


const struct fxabi *kof_fx_abi_of(unsigned arch)
{
	switch (arch) {
	case KOF_FLOW_A_MIPS32:  return &FX_MIPS;
	case KOF_FLOW_A_MIPS64:  return &FX_MIPS64;
	case KOF_FLOW_A_ARM32:   return &FX_ARM;
	case KOF_FLOW_A_PPC32:
	case KOF_FLOW_A_PPC64:   return &FX_PPC;
	case KOF_FLOW_A_SPARC32: return &FX_SPARC;
	case KOF_FLOW_A_RISCV:   return &FX_RISCV;
	case KOF_FLOW_A_SH:      return &FX_SH;
	case KOF_FLOW_A_M68K:    return &FX_M68K;
	default:                 return &FX_A64;
	}
}

/*
 * The names whose success value is zero. Short and explicit rather than
 * derived: "returns 0 on success" is a per-call fact in the manual page, and
 * a rule that tried to infer it from the capability would get `socket` and
 * `bind` wrong in opposite directions.
 *
 * `execve` is deliberately absent: on success it does not return at all, so
 * there is no value to claim.
 */
int kof_sys_zero_on_success(const char *name)
{
	static const char *const z[] = {
		"connect", "bind", "listen", "shutdown", "close",
		"mprotect", "munmap", "chmod", "fchmod", "fchmodat",
		"chdir", "chroot", "setuid", "setgid", "setreuid",
		"setresuid", "unlink", "unlinkat", "rename", "renameat",
		"utime", "utimes", "utimensat", "init_module",
		"finit_module", "delete_module", "setns", "unshare",
		"pivot_root"
	};
	uint32_t i;

	if (!name)
		return 0;
	for (i = 0; i < sizeof z / sizeof z[0]; i++)
		if (!strcmp(name, z[i]))
			return 1;
	return 0;
}

/*
 * HOW MANY ARGUMENTS THE CALL ACTUALLY TAKES, or 0 for "not written down".
 *
 * The sweep reads the ABI's argument registers, and there are always four of
 * them whether or not the call uses four. What was in the fourth before
 * belongs to whatever ran last: on msfvenom's x86-64 stager, `socket` - which
 * takes THREE - was displayed as `socket(0x2, 0x1, _, 0x22)`, and 0x22 is
 * the flags word the `mmap` two instructions earlier had left in r10.
 *
 * That is the engine presenting something it does not know as something it
 * does, which is worse than presenting nothing. Only the calls whose arity is
 * written here are trimmed; 0 means "nobody wrote it down yet" and the old
 * behaviour stands, so this list can grow one line at a time without the
 * absence of a line being a wrong answer.
 */
uint8_t kof_sys_argc(const char *name)
{
	static const struct { const char *n; uint8_t c; } a[] = {
		{ "socket", 3 },      { "socketpair", 4 },
		{ "pipe", 1 },        { "pipe2", 2 },
		{ "connect", 3 },     { "bind", 3 },
		{ "listen", 2 },      { "accept", 3 },
		{ "accept4", 4 },     { "shutdown", 2 },
		{ "read", 3 },        { "write", 3 },
		{ "recv", 4 },        { "send", 4 },
		{ "recvfrom", 6 },    { "sendto", 6 },
		{ "open", 3 },        { "openat", 4 },
		{ "close", 1 },       { "mmap", 6 },
		{ "mmap2", 6 },       { "mprotect", 3 },
		{ "munmap", 2 },      { "memfd_create", 2 },
		{ "execve", 3 },      { "execveat", 5 },
		{ "fork", 0 },        { "vfork", 0 },
		{ "clone", 5 },       { "nanosleep", 2 },
		{ "ptrace", 4 },      { "dup2", 2 },
		{ "dup3", 3 },        { "chmod", 2 },
		{ "fchmod", 2 },      { "unlink", 1 },
		{ "rename", 2 },      { "chroot", 1 },
		{ "setuid", 1 },      { "setgid", 1 },
		{ "kill", 2 },        { "pipe", 1 },
		{ "init_module", 3 }, { "finit_module", 3 },
		{ "delete_module", 2 }, { "bpf", 3 },
		{ "setns", 2 },       { "unshare", 1 },
		{ "process_vm_readv", 6 },
		{ "process_vm_writev", 6 }
	};
	uint32_t i;

	if (!name)
		return 0;
	for (i = 0; i < sizeof a / sizeof a[0]; i++)
		if (!strcmp(name, a[i].n))
			return a[i].c;
	return 0;
}

/*
 * DOES THIS SYSCALL EVER COME BACK.
 *
 * `exit` and `exit_group` do not, and a sweep that reads code in address
 * order has no other way to know. The instruction after one of them is
 * reached by a JUMP from somewhere else, not by falling through, so
 * everything the sweep believes at that point belongs to a path that ended.
 *
 * Measured on msfvenom's x86-64 stager: the error path sets rdi to 1 and
 * exits; the success path jumps past it. Treating the exit as falling
 * through handed the block after it rdi = 1, and the `read` there lost its
 * link back to the socket - the one edge that says the bytes executed came
 * off the network.
 *
 * `execve` is NOT here. It does not return WHEN IT SUCCEEDS, and a stager
 * that calls it in a loop is relying on it failing.
 */
int kof_sys_noreturn(unsigned bits, uint32_t nr)
{
	/*
	 * BY NUMBER, because these have no capability and so no row in the
	 * tables above - those hold "one row per syscall the vocabulary has
	 * a word for", and "the program stopped" is not a capability. The
	 * numbers are from the same headers as the rest.
	 *
	 * x86 and x86-64 only. The fixed-width ABIs each have their own
	 * numbering and none of them has been checked, so they answer no -
	 * which is what the sweep did before this existed.
	 */
	if (bits == 32)
		return nr == 1u || nr == 252u;      /* exit, exit_group */
	return nr == 60u || nr == 231u;
}
