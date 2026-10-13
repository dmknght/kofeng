/* See nucleo.h. */

#include "nucleo.h"

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
 * The roles are nucleo.h's - see KGENOME_FLOW_ROLE_NONE. Naming them in the
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
const struct kgenome_sysrow kgenome_sys64[] = {
	{     0, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{     1, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
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
	{    17, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "pread64"  },
	{    18, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "pwrite64"  },
	{    19, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "readv"  },
	{    20, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "writev"  },
	{    40, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "sendfile"  },
	{   275, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "splice"  },
	{   295, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "preadv"  },
	{   296, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "pwritev"  },
	{   327, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "preadv2"  },
	{   328, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "pwritev2"  },
	{    46, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendmsg"  },
	{    47, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvmsg"  },
	{     2, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{   9, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see prot_cap */
	{  10, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{   35, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{  41, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{   42, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{   43, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{   44, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{   45, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{  56, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{   57, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{   58, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "vfork"  },
	{   59, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{ 257, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{ 319, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  },
	{ 322, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execveat"  },
	/*
	 * AND THE REST OF WHAT A PROGRAM CAN ASK FOR. Numbers read out of
	 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this machine
	 * rather than remembered, because a wrong one here is not a missed
	 * detection - it is a confident wrong name on whatever syscall does
	 * hold the number.
	 */
	{  82, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "rename"  },
	{  87, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlink"  },
	{ 263, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlinkat"  },
	{ 264, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat"  },
	{ 316, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat2"  },
	{  90, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "chmod"  },
	{  91, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmod"  },
	{ 268, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmodat"  },
	{ 105, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setuid"  },
	{ 106, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setgid"  },
	{ 113, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setreuid"  },
	{ 117, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setresuid"  },
	{ 310, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 311, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 175, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "init_module"  },
	{ 176, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "delete_module"  },
	{ 313, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "finit_module"  },
	{ 321, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "bpf"  },
	{ 161, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "chroot"  },
	{ 155, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "pivot_root"  },
	{ 308, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "setns"  },
	{ 272, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "unshare"  },
	{ 101, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{  22, KGENOME_NUCLEO_PIPE_OPEN, KGENOME_FLOW_ROLE_NONE, "pipe"  },
	{  33, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup2"  },
	{  53, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_NONE, "socketpair"  },
	{ 292, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup3"  },
	{ 132, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utime"  },
	{ 235, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimes"  },
	{ 261, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "futimesat"  },
	{ 280, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimensat"  }
};

/* Linux i386. */
const struct kgenome_sysrow kgenome_sys32[] = {
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	/* The same family on i386 - see the note in the amd64 table. */
	{   180, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "pread64"  },
	{   181, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "pwrite64"  },
	{   145, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "readv"  },
	{   146, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "writev"  },
	{   187, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "sendfile"  },
	{   239, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "sendfile64"  },
	{   313, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "splice"  },
	{   333, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "preadv"  },
	{   334, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "pwritev"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{   11, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{  90, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },
	{ 102, KGENOME_NUCLEO_NONE, KGENOME_FLOW_ROLE_NONE, "socketcall"  },         /* socketcall - the sub-call is in ebx */
	{ 120, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{ 192, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap2"  },
	{ 295, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{ 356, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  },
	{ 358, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execveat"  },
	/* The same list on i386, from asm/unistd_32.h and NOT by subtracting
	 * anything from the table above - the two numberings are unrelated. */
	{  10, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlink"  },
	{  38, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "rename"  },
	{ 301, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlinkat"  },
	{ 302, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat"  },
	{ 353, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat2"  },
	{  15, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "chmod"  },
	{  94, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmod"  },
	{ 306, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmodat"  },
	{  23, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setuid"  },
	{  46, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setgid"  },
	{  70, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setreuid"  },
	{ 164, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setresuid"  },
	{ 347, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 348, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 128, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "init_module"  },
	{ 129, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "delete_module"  },
	{ 350, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "finit_module"  },
	{ 357, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "bpf"  },
	{  61, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "chroot"  },
	{ 217, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "pivot_root"  },
	{ 346, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "setns"  },
	{ 310, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "unshare"  },
	{  26, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{  42, KGENOME_NUCLEO_PIPE_OPEN, KGENOME_FLOW_ROLE_NONE, "pipe"  },
	{  63, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup2"  },
	{ 330, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup3"  },
	{  30, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utime"  },
	{ 271, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimes"  },
	{ 299, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "futimesat"  },
	{ 320, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimensat"  }
};

/* i386 multiplexes every socket operation through socketcall, with the
 * operation in ebx. Left as its own table rather than folded into the one
 * above, because it is a different axis and merging them would need a second
 * key nothing else uses. */
const struct kgenome_sysrow kgenome_sockcall[] = {
	{  1, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket" },
	{  2, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind" },
	{  3, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect" },
	{  4, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen" },
	{  5, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept" },
	{  9, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "send" },
	{ 10, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recv" },
	{ 11, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto" },
	{ 12, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom" }
};


/* The row of `t` for syscall `nr`, or NULL. One loop; a caller reads the field
 * it wants (cap, name, role) from the row, so there is no per-field twin. */
const struct kgenome_sysrow *kgenome_sys_row(const struct kgenome_sysrow *t,
					     uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return &t[i];
	return NULL;
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
 * enum kgenome_flow_cap.
 */
static const struct { const char *name; uint16_t cap; }
names[] = {
	/* POSIX */
	{ "mmap",           KGENOME_NUCLEO_ALLOC },
	{ "mmap64",         KGENOME_NUCLEO_ALLOC },
	{ "mprotect",       KGENOME_NUCLEO_ALLOC },
	/* Not a finding on its own - see KGENOME_NUCLEO_HEAP - and here so that a
	 * buffer two transfers share has a name. posix_memalign is left
	 * out: it hands the pointer back THROUGH one, and nothing here
	 * carries an output argument, so the step would make something
	 * nothing could hold. */
	{ "malloc",         KGENOME_NUCLEO_HEAP },
	{ "calloc",         KGENOME_NUCLEO_HEAP },
	{ "realloc",        KGENOME_NUCLEO_HEAP },
	{ "reallocarray",   KGENOME_NUCLEO_HEAP },
	{ "aligned_alloc",  KGENOME_NUCLEO_HEAP },
	{ "memalign",       KGENOME_NUCLEO_HEAP },
	{ "_Znwm",          KGENOME_NUCLEO_HEAP },  /* new    */
	{ "_Znam",          KGENOME_NUCLEO_HEAP },  /* new[]  */
	{ "socket",         KGENOME_NUCLEO_NET_OPEN },
	{ "socketpair",     KGENOME_NUCLEO_NET_OPEN },
	/* Not a finding on its own - see KGENOME_NUCLEO_PIPE_OPEN - and here so
	 * the step has a name and so a dynamically linked object calling
	 * pipe@plt reaches the same word as a static one. */
	{ "pipe",           KGENOME_NUCLEO_PIPE_OPEN },
	{ "pipe2",          KGENOME_NUCLEO_PIPE_OPEN },
	{ "connect",        KGENOME_NUCLEO_NET_CONNECT },
	{ "accept",         KGENOME_NUCLEO_NET_ACCEPT },
	{ "accept4",        KGENOME_NUCLEO_NET_ACCEPT },
	{ "bind",           KGENOME_NUCLEO_NET_BIND },
	{ "listen",         KGENOME_NUCLEO_NET_LISTEN },
	{ "recv",           KGENOME_NUCLEO_NET_READ },
	{ "recvfrom",       KGENOME_NUCLEO_NET_READ },
	{ "recvmsg",        KGENOME_NUCLEO_NET_READ },
	{ "read",           KGENOME_NUCLEO_MEM_READ },
	{ "send",           KGENOME_NUCLEO_NET_WRITE },
	{ "sendto",         KGENOME_NUCLEO_NET_WRITE },
	{ "sendmsg",        KGENOME_NUCLEO_NET_WRITE },
	{ "write",          KGENOME_NUCLEO_MEM_WRITE },
	{ "open",           KGENOME_NUCLEO_FILE_OPEN },
	{ "open64",         KGENOME_NUCLEO_FILE_OPEN },
	{ "openat",         KGENOME_NUCLEO_FILE_OPEN },
	{ "fopen",          KGENOME_NUCLEO_FILE_OPEN },
	{ "memfd_create",   KGENOME_NUCLEO_MEMFD },
	{ "execve",         KGENOME_NUCLEO_EXEC_IMAGE },
	{ "execv",          KGENOME_NUCLEO_EXEC_IMAGE },
	{ "execl",          KGENOME_NUCLEO_EXEC_IMAGE },
	{ "execlp",         KGENOME_NUCLEO_EXEC_IMAGE },
	{ "execvp",         KGENOME_NUCLEO_EXEC_IMAGE },
	{ "system",         KGENOME_NUCLEO_EXEC_IMAGE },
	{ "popen",          KGENOME_NUCLEO_EXEC_IMAGE },
	{ "fork",           KGENOME_NUCLEO_SPAWN },
	{ "vfork",          KGENOME_NUCLEO_SPAWN },
	/* The libc wrapper, whose flags are its THIRD argument rather than its
	 * first - a different convention from the syscall, and past what is
	 * refined here. It stays the weaker claim. */
	{ "clone",          KGENOME_NUCLEO_SPAWN },
	/* No flags to read and no ambiguity: the name IS the claim. */
	{ "pthread_create", KGENOME_NUCLEO_THREAD },
	{ "daemon",         KGENOME_NUCLEO_SPAWN },
	{ "sleep",          KGENOME_NUCLEO_SLEEP },
	{ "usleep",         KGENOME_NUCLEO_SLEEP },
	{ "nanosleep",      KGENOME_NUCLEO_SLEEP },
	{ "ptrace",         KGENOME_NUCLEO_PTRACE },
	/* Windows, for the same words */
	{ "VirtualAlloc",   KGENOME_NUCLEO_ALLOC },
	{ "VirtualAllocEx", KGENOME_NUCLEO_ALLOC },
	{ "VirtualProtect", KGENOME_NUCLEO_ALLOC },
	{ "HeapAlloc",      KGENOME_NUCLEO_HEAP },
	{ "HeapReAlloc",    KGENOME_NUCLEO_HEAP },
	{ "RtlAllocateHeap", KGENOME_NUCLEO_HEAP },
	{ "LocalAlloc",     KGENOME_NUCLEO_HEAP },
	{ "GlobalAlloc",    KGENOME_NUCLEO_HEAP },
	{ "CoTaskMemAlloc", KGENOME_NUCLEO_HEAP },
	{ "WSASocketA",     KGENOME_NUCLEO_NET_OPEN },
	{ "WSASocketW",     KGENOME_NUCLEO_NET_OPEN },
	{ "InternetOpenA",  KGENOME_NUCLEO_HTTP_OPEN },
	{ "InternetOpenW",  KGENOME_NUCLEO_HTTP_OPEN },
	{ "WSAConnect",     KGENOME_NUCLEO_NET_CONNECT },
	{ "InternetConnectA", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "InternetConnectW", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "CreateFileA",    KGENOME_NUCLEO_FILE_OPEN },
	{ "CreateFileW",    KGENOME_NUCLEO_FILE_OPEN },
	{ "WriteFile",      KGENOME_NUCLEO_MEM_WRITE },
	{ "ReadFile",       KGENOME_NUCLEO_MEM_READ },
	{ "CreateProcessA", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateProcessW", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "WinExec",        KGENOME_NUCLEO_EXEC_IMAGE },
	{ "ShellExecuteA",  KGENOME_NUCLEO_EXEC_IMAGE },
	{ "ShellExecuteW",  KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateThread",   KGENOME_NUCLEO_THREAD },
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
	{ "WSARecv",        KGENOME_NUCLEO_NET_READ },
	{ "WSASend",        KGENOME_NUCLEO_NET_WRITE },
	{ "WSAAccept",      KGENOME_NUCLEO_NET_ACCEPT },
	{ "closesocket",    KGENOME_NUCLEO_NET_OPEN },
	{ "InternetOpenUrlA", KGENOME_NUCLEO_HTTP_SEND },
	{ "InternetOpenUrlW", KGENOME_NUCLEO_HTTP_SEND },
	{ "InternetReadFile", KGENOME_NUCLEO_HTTP_RECV },
	{ "HttpSendRequestA", KGENOME_NUCLEO_HTTP_SEND },
	{ "HttpSendRequestW", KGENOME_NUCLEO_HTTP_SEND },
	{ "HttpOpenRequestA", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "HttpOpenRequestW", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "URLDownloadToFileA", KGENOME_NUCLEO_HTTP_FETCH },
	{ "URLDownloadToFileW", KGENOME_NUCLEO_HTTP_FETCH },
	/*
	 * THE WINDOWS SPELLING OF A REDIRECTED SHELL, which the table had
	 * only the POSIX half of.
	 *
	 * `pipe` then `dup2` then `execve` is the shape KGENOME_NUCLEO_PIPE_OPEN
	 * exists for; on Windows it is `CreatePipe` then `SetStdHandle` or
	 * a STARTUPINFO, then `CreateProcess` - and CreateProcess was the
	 * only one of the three in this table. The producer and the
	 * redirect are what make it a sentence rather than three words.
	 */
	{ "CreatePipe",     KGENOME_NUCLEO_PIPE_OPEN },
	{ "SetStdHandle",   KGENOME_NUCLEO_FD_REDIR },
	{ "DuplicateHandle", KGENOME_NUCLEO_FD_REDIR },
	{ "WinHttpOpen",    KGENOME_NUCLEO_HTTP_OPEN },
	{ "WinHttpConnect", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "WinHttpOpenRequest", KGENOME_NUCLEO_HTTP_CONNECT },
	{ "WinHttpSendRequest", KGENOME_NUCLEO_HTTP_SEND },
	{ "WinHttpReadData", KGENOME_NUCLEO_HTTP_RECV },
	/* A mapping is a mapping, whichever name asks for it. */
	{ "VirtualProtectEx", KGENOME_NUCLEO_ALLOC },
	{ "NtAllocateVirtualMemory", KGENOME_NUCLEO_ALLOC },
	{ "NtProtectVirtualMemory", KGENOME_NUCLEO_ALLOC },
	{ "ZwAllocateVirtualMemory", KGENOME_NUCLEO_ALLOC },
	{ "ZwProtectVirtualMemory", KGENOME_NUCLEO_ALLOC },
	{ "CreateFileMappingA", KGENOME_NUCLEO_ALLOC },
	{ "CreateFileMappingW", KGENOME_NUCLEO_ALLOC },
	{ "MapViewOfFile",  KGENOME_NUCLEO_ALLOC },
	{ "MapViewOfFileEx", KGENOME_NUCLEO_ALLOC },
	/* The handle, the memory and the execution - see the note on the
	 * three capabilities in kofmod/kofcap.h. */
	{ "OpenProcess",    KGENOME_NUCLEO_PTRACE },
	{ "DebugActiveProcess", KGENOME_NUCLEO_PTRACE },
	/* A thread handle is the same kind of hold on another execution
	 * context, and it is what SetThreadContext and ResumeThread are
	 * handed - they were modelled and the handle they take was not. */
	{ "OpenThread",     KGENOME_NUCLEO_PTRACE },
	{ "WriteProcessMemory", KGENOME_NUCLEO_PROC_MEM },
	{ "ReadProcessMemory", KGENOME_NUCLEO_PROC_MEM },
	{ "NtWriteVirtualMemory", KGENOME_NUCLEO_PROC_MEM },
	/* Reading another thread's registers, and emptying another image
	 * out of its address space: the two legs of hollowing whose other
	 * halves - SetThreadContext and WriteProcessMemory - were already
	 * here. */
	{ "GetThreadContext", KGENOME_NUCLEO_PROC_MEM },
	{ "NtUnmapViewOfSection", KGENOME_NUCLEO_PROC_MEM },
	{ "ZwUnmapViewOfSection", KGENOME_NUCLEO_PROC_MEM },
	{ "CreateRemoteThread", KGENOME_NUCLEO_PROC_EXEC },
	{ "CreateRemoteThreadEx", KGENOME_NUCLEO_PROC_EXEC },
	{ "NtQueueApcThread", KGENOME_NUCLEO_PROC_EXEC },
	{ "QueueUserAPC",   KGENOME_NUCLEO_PROC_EXEC },
	{ "SetThreadContext", KGENOME_NUCLEO_PROC_EXEC },
	{ "NtResumeThread", KGENOME_NUCLEO_PROC_EXEC },
	{ "SuspendThread",  KGENOME_NUCLEO_PROC_EXEC },
	{ "NtSuspendThread", KGENOME_NUCLEO_PROC_EXEC },
	{ "ResumeThread",   KGENOME_NUCLEO_PROC_EXEC },
	/* The loader pair, which is what a program has INSTEAD of an import
	 * table entry - see KGENOME_NUCLEO_RESOLVE. */
	{ "LoadLibraryA",   KGENOME_NUCLEO_LIB_OPEN },
	{ "LoadLibraryW",   KGENOME_NUCLEO_LIB_OPEN },
	{ "LoadLibraryExA", KGENOME_NUCLEO_LIB_OPEN },
	{ "LoadLibraryExW", KGENOME_NUCLEO_LIB_OPEN },
	{ "GetProcAddress", KGENOME_NUCLEO_RESOLVE },
	{ "LdrLoadDll",     KGENOME_NUCLEO_LIB_OPEN },
	{ "LdrGetProcedureAddress", KGENOME_NUCLEO_RESOLVE },
	{ "dlopen",         KGENOME_NUCLEO_LIB_OPEN },
	{ "dlsym",          KGENOME_NUCLEO_RESOLVE },
	/* Writes only; a program reading its own configuration is every
	 * program - see KGENOME_NUCLEO_REG_SET. */
	/* And where the handle they are given comes from - see
	 * KGENOME_NUCLEO_REG_OPEN. Not a finding; the head of a link. */
	/* Windows' spelling of rename - the word already existed for the
	 * POSIX one, see KGENOME_NUCLEO_FILE_RENAME, and only the name was
	 * missing. 16 of the 128 measured PE import MoveFileW. */
	{ "MoveFileA",      KGENOME_NUCLEO_FILE_RENAME },
	{ "MoveFileW",      KGENOME_NUCLEO_FILE_RENAME },
	{ "MoveFileExA",    KGENOME_NUCLEO_FILE_RENAME },
	{ "MoveFileExW",    KGENOME_NUCLEO_FILE_RENAME },
	{ "MoveFileWithProgressW", KGENOME_NUCLEO_FILE_RENAME },
	{ "RegOpenKeyExA",  KGENOME_NUCLEO_REG_OPEN },
	{ "RegOpenKeyExW",  KGENOME_NUCLEO_REG_OPEN },
	{ "RegOpenKeyA",    KGENOME_NUCLEO_REG_OPEN },
	{ "RegOpenKeyW",    KGENOME_NUCLEO_REG_OPEN },
	{ "NtOpenKey",      KGENOME_NUCLEO_REG_OPEN },
	{ "NtOpenKeyEx",    KGENOME_NUCLEO_REG_OPEN },
	{ "RegSetValueExA", KGENOME_NUCLEO_REG_SET },
	{ "RegSetValueExW", KGENOME_NUCLEO_REG_SET },
	{ "RegCreateKeyExA", KGENOME_NUCLEO_REG_SET },
	{ "RegCreateKeyExW", KGENOME_NUCLEO_REG_SET },
	{ "RegDeleteValueA", KGENOME_NUCLEO_REG_SET },
	{ "RegDeleteValueW", KGENOME_NUCLEO_REG_SET },
	{ "NtSetValueKey",  KGENOME_NUCLEO_REG_SET },
	{ "Sleep",          KGENOME_NUCLEO_SLEEP },

	/*
	 * THE ROWS THE RANKING CHOSE. Measured over the whole corpus here -
	 * 1772 ELF malware objects against 20347 Linux binaries - and kept
	 * because of what the numbers said, not because they sounded right.
	 * See KGENOME_NUCLEO_NET_ADDR for the rates and for what the ranking
	 * rejected.
	 */
	{ "htons",          KGENOME_NUCLEO_NET_ADDR },
	{ "htonl",          KGENOME_NUCLEO_NET_ADDR },
	{ "ntohs",          KGENOME_NUCLEO_NET_ADDR },
	{ "ntohl",          KGENOME_NUCLEO_NET_ADDR },
	{ "inet_addr",      KGENOME_NUCLEO_NET_ADDR },
	{ "inet_aton",      KGENOME_NUCLEO_NET_ADDR },
	{ "inet_pton",      KGENOME_NUCLEO_NET_ADDR },
	{ "inet_ntoa",      KGENOME_NUCLEO_NET_ADDR },
	{ "inet_network",   KGENOME_NUCLEO_NET_ADDR },
	{ "gethostbyname",  KGENOME_NUCLEO_DNS },
	{ "getaddrinfo",    KGENOME_NUCLEO_DNS },
	{ "prctl",          KGENOME_NUCLEO_SELF_HIDE },
	{ "setsid",         KGENOME_NUCLEO_BACKGROUND },

	/*
	 * THE KERNEL, which is the same kind of table and a different side of
	 * the same machine.
	 *
	 * A loadable module makes no syscalls - it answers them - so the whole
	 * vocabulary above is silent on one. What it has instead is a list of
	 * UNDEFINED symbols, which is the same declaration a PE import table
	 * is: the names it was compiled against, fixed, and not the module's
	 * to choose. See KGENOME_NUCLEO_CRED_SET for the measurement that picked
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
	 * have separate words. See KGENOME_NUCLEO_CRED_PREPARE. */
	{ "prepare_creds",  KGENOME_NUCLEO_CRED_PREPARE },
	{ "prepare_kernel_cred", KGENOME_NUCLEO_CRED_PREPARE },
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
	{ "__kmalloc",      KGENOME_NUCLEO_HEAP },
	{ "__kmalloc_noprof", KGENOME_NUCLEO_HEAP },
	{ "kmalloc",        KGENOME_NUCLEO_HEAP },
	{ "kmalloc_noprof", KGENOME_NUCLEO_HEAP },
	{ "kmalloc_trace",  KGENOME_NUCLEO_HEAP },
	{ "kvmalloc_node",  KGENOME_NUCLEO_HEAP },
	{ "kvmalloc_node_noprof", KGENOME_NUCLEO_HEAP },
	{ "krealloc",       KGENOME_NUCLEO_HEAP },
	{ "krealloc_noprof", KGENOME_NUCLEO_HEAP },
	{ "kmem_cache_alloc", KGENOME_NUCLEO_HEAP },
	{ "kmem_cache_alloc_noprof", KGENOME_NUCLEO_HEAP },
	{ "vmalloc",        KGENOME_NUCLEO_HEAP },
	{ "vmalloc_noprof", KGENOME_NUCLEO_HEAP },
	{ "__vmalloc",      KGENOME_NUCLEO_HEAP },
	{ "__vmalloc_node_range", KGENOME_NUCLEO_HEAP },
	{ "commit_creds",   KGENOME_NUCLEO_CRED_SET },
	{ "set_current_groups", KGENOME_NUCLEO_CRED_SET },
	/*
	 * A KPROBE PUT ON AND A KPROBE TAKEN OFF - two words, and neither of
	 * them is "hook". See KGENOME_NUCLEO_KPROBE_REG for why this row has now
	 * been wrong twice. The pair is the IDIOM: put a probe on a name,
	 * read kp.addr, take the probe away again, all in one function - and
	 * an idiom made of two calls needs two words to be written down.
	 * Measured at 0 of 900 clean modules on each side.
	 */
	{ "register_kprobe", KGENOME_NUCLEO_KPROBE_REG },
	{ "register_kprobes", KGENOME_NUCLEO_KPROBE_REG },
	{ "unregister_kprobe", KGENOME_NUCLEO_KPROBE_UNREG },
	{ "unregister_kprobes", KGENOME_NUCLEO_KPROBE_UNREG },
	/* A RETURN probe cannot read an address and leave; it exists to run
	 * code on somebody else's return, so it stays hooking. */
	{ "register_kretprobe", KGENOME_NUCLEO_HOOK },
	{ "unregister_kretprobe", KGENOME_NUCLEO_HOOK },
	/* Code of one's own put in the path of somebody else's. */
	{ "unregister_ftrace_function", KGENOME_NUCLEO_HOOK },
	/*
	 * ---- write_cr0 / write_cr4 / mov_cr0 ARE OFF, ON PURPOSE --------
	 *
	 * The word is KGENOME_NUCLEO_PROT_OFF - "the module took write access to
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
	/* { "write_cr0",   KGENOME_NUCLEO_PROT_OFF }, */
	/* { "write_cr4",   KGENOME_NUCLEO_PROT_OFF }, */
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
	{ "peb_ldr",        KGENOME_NUCLEO_SELF_RESOLVE },
	{ "name_hash",      KGENOME_NUCLEO_NAME_HASH },
	/* off with the other two - see the note above them */
	/* { "mov_cr0",     KGENOME_NUCLEO_PROT_OFF }, */
	{ "register_ftrace_function", KGENOME_NUCLEO_HOOK },
	{ "ftrace_set_filter_ip", KGENOME_NUCLEO_HOOK },
	{ "register_ftrace_direct", KGENOME_NUCLEO_HOOK },
	{ "text_poke",      KGENOME_NUCLEO_HOOK },
	{ "text_poke_kgdb", KGENOME_NUCLEO_HOOK },
	{ "set_memory_rw",  KGENOME_NUCLEO_HOOK },
	{ "set_memory_x",   KGENOME_NUCLEO_HOOK },
	/*
	 * An entry taken out of a kernel list, or put into one. EVERY
	 * SPELLING, because the kernel renamed the check twice and a table
	 * that knows two of the three eras is still a table about kernel
	 * versions - see KGENOME_NUCLEO_LIST_HIDE, where the 17% that makes this
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
	{ "__list_del_entry", KGENOME_NUCLEO_LIST_HIDE },
	{ "__list_del_entry_valid", KGENOME_NUCLEO_LIST_HIDE },
	{ "__list_del_entry_valid_or_report", KGENOME_NUCLEO_LIST_HIDE },
	{ "__list_add_valid", KGENOME_NUCLEO_LIST_HIDE },
	{ "__list_add_valid_or_report", KGENOME_NUCLEO_LIST_HIDE },
	{ "list_del",       KGENOME_NUCLEO_LIST_HIDE },
	{ "list_add",       KGENOME_NUCLEO_LIST_HIDE },
	/*
	 * AND THE WORDS THE KERNEL NEEDS OF ITS OWN.
	 *
	 * kallsyms_lookup_name was called dlsym with a different name. It is
	 * not: dlsym returns what a library exported, this returns ANY symbol
	 * the kernel knows - and the one a rootkit wants, sys_call_table, is
	 * exported to nobody. See KGENOME_NUCLEO_KSYM_LOOKUP.
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
	{ "__x86_indirect_thunk_rax", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rbx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rcx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rdx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rsi", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rdi", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_rbp", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r8", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r9", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r10", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r11", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r12", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r13", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r14", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_r15", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_eax", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_ebx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_ecx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_edx", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_esi", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_edi", KGENOME_NUCLEO_CALL_REG },
	{ "__x86_indirect_thunk_ebp", KGENOME_NUCLEO_CALL_REG },
	{ "kallsyms_lookup_name", KGENOME_NUCLEO_KSYM_LOOKUP },
	{ "kallsyms_lookup_name_t", KGENOME_NUCLEO_KSYM_LOOKUP },
	{ "__symbol_get",   KGENOME_NUCLEO_SYMBOL_GET },
	/* ACROSS THE USER/KERNEL BOUNDARY, which is not a file - see
	 * KGENOME_NUCLEO_COPY_FROM_USER. The rows under this one take a struct file
	 * and really are file I/O. */
	{ "_copy_from_user", KGENOME_NUCLEO_COPY_FROM_USER },
	{ "copy_from_user", KGENOME_NUCLEO_COPY_FROM_USER },
	{ "__copy_from_user", KGENOME_NUCLEO_COPY_FROM_USER },
	{ "_copy_to_user",  KGENOME_NUCLEO_COPY_TO_USER },
	{ "copy_to_user",   KGENOME_NUCLEO_COPY_TO_USER },
	{ "__copy_to_user", KGENOME_NUCLEO_COPY_TO_USER },
	{ "kernel_read",    KGENOME_NUCLEO_READ },
	{ "kernel_write",   KGENOME_NUCLEO_WRITE },
	{ "vfs_read",       KGENOME_NUCLEO_READ },
	{ "vfs_write",      KGENOME_NUCLEO_WRITE },
	{ "filp_open",      KGENOME_NUCLEO_FILE_OPEN },
	{ "filp_close",     KGENOME_NUCLEO_FILE_OPEN },
	{ "call_usermodehelper", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "call_usermodehelper_exec", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "kthread_create_on_node", KGENOME_NUCLEO_THREAD },
	{ "kthread_run",    KGENOME_NUCLEO_THREAD },
	{ "wake_up_process", KGENOME_NUCLEO_THREAD },
	{ "sock_create",    KGENOME_NUCLEO_NET_OPEN },
	{ "sock_create_kern", KGENOME_NUCLEO_NET_OPEN },
	{ "kernel_connect", KGENOME_NUCLEO_NET_CONNECT },
	{ "kernel_accept",  KGENOME_NUCLEO_NET_ACCEPT },
	{ "kernel_sendmsg", KGENOME_NUCLEO_NET_WRITE },
	{ "kernel_recvmsg", KGENOME_NUCLEO_NET_READ },
	/*
	 * AND THE WINDOWS KERNEL, which reaches this table the way every other
	 * PE import does - the mechanism needs nothing new, only the words.
	 */
	{ "ZwCreateFile",   KGENOME_NUCLEO_FILE_OPEN },
	{ "ZwOpenFile",     KGENOME_NUCLEO_FILE_OPEN },
	{ "ZwReadFile",     KGENOME_NUCLEO_MEM_READ },
	{ "ZwWriteFile",    KGENOME_NUCLEO_MEM_WRITE },
	{ "MmGetSystemRoutineAddress", KGENOME_NUCLEO_RESOLVE },
	{ "MmMapLockedPagesSpecifyCache", KGENOME_NUCLEO_PROC_MEM },
	{ "MmMapLockedPages", KGENOME_NUCLEO_PROC_MEM },
	{ "PsLookupProcessByProcessId", KGENOME_NUCLEO_PTRACE },
	{ "PsSetCreateProcessNotifyRoutine", KGENOME_NUCLEO_HOOK },
	{ "PsSetCreateProcessNotifyRoutineEx", KGENOME_NUCLEO_HOOK },
	{ "PsSetLoadImageNotifyRoutine", KGENOME_NUCLEO_HOOK },
	{ "ObRegisterCallbacks", KGENOME_NUCLEO_HOOK },
	{ "PsCreateSystemThread", KGENOME_NUCLEO_THREAD },
	{ "ZwTerminateProcess", KGENOME_NUCLEO_PROC_EXEC },
	/*
	 * ===== THE WORDS ADDED WITH THE NINE CAPABILITIES AT THE END OF
	 * enum kgenome_flow_cap. Each entry point here exists to do ONE thing;
	 * that is the bar, and the names that did not clear it are listed in
	 * kofcap.h beside the capabilities rather than here.
	 */
	/* Encryption. Windows has two generations of the same API and both are
	 * still shipped, so both are here. */
	{ "CryptEncrypt",   KGENOME_NUCLEO_CRYPTO },
	{ "CryptDecrypt",   KGENOME_NUCLEO_CRYPTO },
	{ "CryptAcquireContextA", KGENOME_NUCLEO_CRYPTO },
	{ "CryptAcquireContextW", KGENOME_NUCLEO_CRYPTO },
	{ "CryptGenKey",    KGENOME_NUCLEO_CRYPTO },
	{ "CryptDeriveKey", KGENOME_NUCLEO_CRYPTO },
	{ "CryptImportKey", KGENOME_NUCLEO_CRYPTO },
	{ "BCryptEncrypt",  KGENOME_NUCLEO_CRYPTO },
	{ "BCryptDecrypt",  KGENOME_NUCLEO_CRYPTO },
	{ "BCryptGenerateSymmetricKey", KGENOME_NUCLEO_CRYPTO },
	{ "BCryptImportKeyPair", KGENOME_NUCLEO_CRYPTO },
	/* And the Linux side, which is OpenSSL in practice. The EVP names are
	 * the ones a program links; the AES_ ones are the older direct calls
	 * that statically linked malware still carries. */
	{ "EVP_EncryptInit_ex", KGENOME_NUCLEO_CRYPTO },
	{ "EVP_EncryptUpdate",  KGENOME_NUCLEO_CRYPTO },
	{ "EVP_DecryptInit_ex", KGENOME_NUCLEO_CRYPTO },
	{ "EVP_DecryptUpdate",  KGENOME_NUCLEO_CRYPTO },
	{ "EVP_CipherInit_ex",  KGENOME_NUCLEO_CRYPTO },
	{ "AES_set_encrypt_key", KGENOME_NUCLEO_CRYPTO },
	{ "AES_cbc_encrypt",     KGENOME_NUCLEO_CRYPTO },
	{ "AES_encrypt",         KGENOME_NUCLEO_CRYPTO },
	{ "RSA_public_encrypt",  KGENOME_NUCLEO_CRYPTO },
	{ "RSA_private_decrypt", KGENOME_NUCLEO_CRYPTO },
	{ "crypto_secretbox_easy", KGENOME_NUCLEO_CRYPTO },
	/* Taking what the user is doing. */
	{ "SetWindowsHookExA", KGENOME_NUCLEO_CAPTURE },
	{ "SetWindowsHookExW", KGENOME_NUCLEO_CAPTURE },
	{ "GetAsyncKeyState",  KGENOME_NUCLEO_CAPTURE },
	{ "GetKeyboardState",  KGENOME_NUCLEO_CAPTURE },
	{ "GetRawInputData",   KGENOME_NUCLEO_CAPTURE },
	{ "RegisterRawInputDevices", KGENOME_NUCLEO_CAPTURE },
	{ "GetClipboardData",  KGENOME_NUCLEO_CAPTURE },
	{ "SetClipboardData",  KGENOME_NUCLEO_CAPTURE },
	{ "XQueryKeymap",      KGENOME_NUCLEO_CAPTURE },
	{ "XGrabKeyboard",     KGENOME_NUCLEO_CAPTURE },
	/* Installing itself as a service. */
	{ "OpenSCManagerA",  KGENOME_NUCLEO_SVC_INSTALL },
	{ "OpenSCManagerW",  KGENOME_NUCLEO_SVC_INSTALL },
	{ "CreateServiceA",  KGENOME_NUCLEO_SVC_INSTALL },
	{ "CreateServiceW",  KGENOME_NUCLEO_SVC_INSTALL },
	{ "StartServiceA",   KGENOME_NUCLEO_SVC_INSTALL },
	{ "StartServiceW",   KGENOME_NUCLEO_SVC_INSTALL },
	{ "ChangeServiceConfigA", KGENOME_NUCLEO_SVC_INSTALL },
	{ "ChangeServiceConfigW", KGENOME_NUCLEO_SVC_INSTALL },
	/* Code into the kernel. */
	{ "init_module",    KGENOME_NUCLEO_MOD_LOAD },
	{ "finit_module",   KGENOME_NUCLEO_MOD_LOAD },
	{ "delete_module",  KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf",            KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_load_program", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_prog_load",  KGENOME_NUCLEO_MOD_LOAD },
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
	{ "bpf_object__load", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_object__load_skeleton", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_object__attach_skeleton", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_program__attach", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_program__attach_kprobe", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_program__attach_uprobe", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_program__attach_tracepoint", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_program__attach_xdp", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_prog_attach", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_set_link_xdp_fd", KGENOME_NUCLEO_MOD_LOAD },
	{ "bpf_tc_attach",  KGENOME_NUCLEO_MOD_LOAD },
	{ "NtLoadDriver",   KGENOME_NUCLEO_MOD_LOAD },
	{ "ZwLoadDriver",   KGENOME_NUCLEO_MOD_LOAD },
	/* A named pipe, and only a named one. */
	{ "CreateNamedPipeA", KGENOME_NUCLEO_PIPE },
	{ "CreateNamedPipeW", KGENOME_NUCLEO_PIPE },
	{ "ConnectNamedPipe", KGENOME_NUCLEO_PIPE },
	{ "CallNamedPipeA",   KGENOME_NUCLEO_PIPE },
	{ "CallNamedPipeW",   KGENOME_NUCLEO_PIPE },
	{ "mkfifo",           KGENOME_NUCLEO_PIPE },
	{ "mkfifoat",         KGENOME_NUCLEO_PIPE },
	/* Removing a file. */
	{ "DeleteFileA",    KGENOME_NUCLEO_FILE_DELETE },
	{ "DeleteFileW",    KGENOME_NUCLEO_FILE_DELETE },
	/* MoveFileEx* used to be here as a DELETE. When KGENOME_NUCLEO_FILE_RENAME
	 * was split out of KGENOME_NUCLEO_FILE_DELETE the POSIX `rename` moved and
	 * these two did not, so the page went on saying `file-delete` with
	 * MoveFileExW beside it - the exact contradiction that split was
	 * made to end. They are with the other MoveFile rows now. */
	{ "unlink",         KGENOME_NUCLEO_FILE_DELETE },
	{ "unlinkat",       KGENOME_NUCLEO_FILE_DELETE },
	{ "remove",         KGENOME_NUCLEO_FILE_DELETE },
	{ "rename",         KGENOME_NUCLEO_FILE_RENAME },
	{ "renameat",       KGENOME_NUCLEO_FILE_RENAME },
	/* Making a dropped file runnable. */
	{ "chmod",          KGENOME_NUCLEO_PERM_SET },
	{ "fchmod",         KGENOME_NUCLEO_PERM_SET },
	{ "fchmodat",       KGENOME_NUCLEO_PERM_SET },
	{ "SetFileAttributesA", KGENOME_NUCLEO_PERM_SET },
	{ "SetFileAttributesW", KGENOME_NUCLEO_PERM_SET },
	/* Asking whether it is watched. */
	{ "IsDebuggerPresent", KGENOME_NUCLEO_ANTI_DEBUG },
	{ "CheckRemoteDebuggerPresent", KGENOME_NUCLEO_ANTI_DEBUG },
	{ "NtSetInformationThread", KGENOME_NUCLEO_ANTI_DEBUG },
	/* Moving the boundary of what it can see. */
	{ "chroot",         KGENOME_NUCLEO_JAIL },
	{ "pivot_root",     KGENOME_NUCLEO_JAIL },
	{ "setns",          KGENOME_NUCLEO_JAIL },
	{ "unshare",        KGENOME_NUCLEO_JAIL },
	/*
	 * AND WORDS FOR CAPABILITIES THAT ALREADY EXISTED, where only the
	 * spelling was missing. Changing one's own privileges is CRED_SET
	 * whether a kernel module calls commit_creds or a program calls
	 * setuid; reaching into another process is PROC_MEM whether it is
	 * WriteProcessMemory or process_vm_writev.
	 */
	{ "setuid",         KGENOME_NUCLEO_CRED_SET },
	{ "setgid",         KGENOME_NUCLEO_CRED_SET },
	{ "seteuid",        KGENOME_NUCLEO_CRED_SET },
	{ "setreuid",       KGENOME_NUCLEO_CRED_SET },
	{ "setresuid",      KGENOME_NUCLEO_CRED_SET },
	{ "AdjustTokenPrivileges", KGENOME_NUCLEO_CRED_SET },
	{ "OpenProcessToken",      KGENOME_NUCLEO_CRED_SET },
	{ "DuplicateTokenEx",      KGENOME_NUCLEO_CRED_SET },
	{ "ImpersonateLoggedOnUser", KGENOME_NUCLEO_CRED_SET },
	{ "SetThreadToken",        KGENOME_NUCLEO_CRED_SET },
	{ "process_vm_readv",      KGENOME_NUCLEO_PROC_MEM },
	{ "process_vm_writev",     KGENOME_NUCLEO_PROC_MEM },
	{ "posix_spawn",           KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateProcessAsUserA",  KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateProcessAsUserW",  KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateProcessWithTokenW", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "CreateProcessWithLogonW", KGENOME_NUCLEO_EXEC_IMAGE },
	{ "ShellExecuteExA",       KGENOME_NUCLEO_EXEC_IMAGE },
	{ "ShellExecuteExW",       KGENOME_NUCLEO_EXEC_IMAGE },
	/* The three measured ones. */
	{ "dup2",           KGENOME_NUCLEO_FD_REDIR },
	{ "dup3",           KGENOME_NUCLEO_FD_REDIR },
	{ "utime",          KGENOME_NUCLEO_TIMESTOMP },
	{ "utimes",         KGENOME_NUCLEO_TIMESTOMP },
	{ "utimensat",      KGENOME_NUCLEO_TIMESTOMP },
	{ "futimens",       KGENOME_NUCLEO_TIMESTOMP },
	{ "SetFileTime",    KGENOME_NUCLEO_TIMESTOMP },
	{ "CreateToolhelp32Snapshot", KGENOME_NUCLEO_PROC_LIST },
	{ "Process32First", KGENOME_NUCLEO_PROC_LIST },
	{ "Process32FirstW", KGENOME_NUCLEO_PROC_LIST },
	{ "Process32Next",  KGENOME_NUCLEO_PROC_LIST },
	{ "Process32NextW", KGENOME_NUCLEO_PROC_LIST },
	{ "Module32First",  KGENOME_NUCLEO_PROC_LIST },
	{ "Module32Next",   KGENOME_NUCLEO_PROC_LIST },
	{ "Thread32First",  KGENOME_NUCLEO_PROC_LIST },
	{ "Thread32Next",   KGENOME_NUCLEO_PROC_LIST },
	{ "EnumProcesses",  KGENOME_NUCLEO_PROC_LIST },
	/*
	 * AND THE GAPS THE SAME MEASUREMENT FOUND IN WORDS THAT ALREADY
	 * EXISTED - each one a spelling nobody had written down.
	 */
	{ "BCryptOpenAlgorithmProvider", KGENOME_NUCLEO_CRYPTO },
	{ "RegDeleteKeyA",  KGENOME_NUCLEO_REG_SET },
	{ "RegDeleteKeyW",  KGENOME_NUCLEO_REG_SET },
	{ "RegDeleteKeyExA", KGENOME_NUCLEO_REG_SET },
	{ "RegDeleteKeyExW", KGENOME_NUCLEO_REG_SET },
	/* An allocation, and incidentally one that fails in some sandboxes -
	 * which is why a loader picks it. The capability is the allocation. */
	{ "VirtualAllocExNuma", KGENOME_NUCLEO_ALLOC },
	{ "NtQueryInformationProcess", KGENOME_NUCLEO_ANTI_DEBUG }
};

/*
 * The syscall half of the vocabulary, for a caller that has a RUN rather
 * than code. Exported rather than copied for the reason at the head of
 * nucleo.h: a second table is a second thing to keep right.
 */
/*
 * WHAT KIND OF SOCKET `socket(domain, type, ...)` MADE, from the first two
 * arguments. One statement of it, read by the syscall and by the named call
 * (kgenome_flow_cap_of_call): the Windows socket()/WSASocket* take the same two
 * values in the same order, and AF_UNIX and SOCK_RAW are the same numbers.
 */
static uint16_t sock_kind(const uint64_t *arg, uint8_t *flags)
{
	if ((arg[0] & 0xffu) == KGENOME_FLOW_AF_UNIX && flags)
		*flags |= KGENOME_FLOWF_LOCAL;
	if ((arg[1] & 0xfu) == KGENOME_FLOW_SOCK_RAW)
		return KGENOME_NUCLEO_NET_RAW;
	if ((arg[1] & 0xfu) == KGENOME_FLOW_SOCK_DGRAM && flags)
		*flags |= KGENOME_FLOWF_DGRAM;
	return KGENOME_NUCLEO_NET_OPEN;
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
 * kgenome_flow_cap_of_syscall for these arguments and no others: for a length or a
 * protection a partly-known number is a wrong number.
 */
int kgenome_flow_arg_is_flags(unsigned bits, uint32_t nr, unsigned idx)
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
int kgenome_flow_sock_nonblock(unsigned bits, uint32_t nr, const uint64_t *arg,
			   unsigned have)
{
	int is_socket = bits == 32 ? nr == 359u : nr == 41u;

	return is_socket && (have & 2u) && (arg[1] & FLOW_O_NONBLOCK);
}

int kgenome_flow_sockcall_nonblock(uint32_t sub, const uint64_t *arg, unsigned have)
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
 * A NAMED CALL, REFINED BY THE ARGUMENTS IT WAS MADE WITH - the same job
 * kgenome_flow_cap_of_syscall does for a system call, for code that reached an API
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
uint16_t kgenome_flow_cap_of_call(const char *name, const uint64_t *arg,
			      uint8_t *flags)
{
	uint16_t cap = kgenome_flow_cap_of_name(name);

	if (flags)
		*flags = 0;
	if (!arg || cap == KGENOME_NUCLEO_NONE)
		return cap;
	if (cap == KGENOME_NUCLEO_ALLOC) {
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
				*flags = KGENOME_FLOWF_WX;
			return KGENOME_NUCLEO_ALLOC_EXEC;
		}
		return cap;
	}
	if (cap == KGENOME_NUCLEO_NET_OPEN &&
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
uint16_t kgenome_flow_cap_of_sockcall(uint32_t sub, const uint64_t *arg,
				  unsigned have, uint8_t *flags)
{
	const struct kgenome_sysrow *row = kgenome_sys_row(kgenome_sockcall,
							   kgenome_sockcall_n, sub);
	uint16_t cap = row ? row->cap : KGENOME_NUCLEO_NONE;

	if (flags)
		*flags = 0;
	if (cap == KGENOME_NUCLEO_NET_OPEN && sub == 1u && arg && (have & 3u) == 3u)
		return sock_kind(arg, flags);
	/* setsockopt(fd, level, optname, ...): the operation whose arguments are a
	 * claim - see flow_opt_cap for the numbers. */
	if (sub == 14u && arg && (have & 6u) == 6u &&
	    (arg[1] & 0xffffffffu) == FLOW_IPPROTO_IP &&
	    (arg[2] & 0xffffffffu) == FLOW_IP_HDRINCL)
		return KGENOME_NUCLEO_NET_HDRINCL;
	return cap;
}

uint16_t kgenome_flow_cap_of_syscall(unsigned bits, uint32_t nr,
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
			row = kgenome_sys_row(kgenome_sockcall,
					      kgenome_sockcall_n,
					      (uint32_t)arg[0]);
			return row ? row->cap : KGENOME_NUCLEO_NONE;
		}
		row = kgenome_sys_row(kgenome_sys32, kgenome_sys32_n, nr);
	} else {
		row = kgenome_sys_row(kgenome_sys64, kgenome_sys64_n, nr);
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
		return (arg[0] & KGENOME_FLOW_CLONE_THREAD) ? KGENOME_NUCLEO_THREAD
						    : KGENOME_NUCLEO_SPAWN;
	if (arg && cap == KGENOME_NUCLEO_NET_OPEN && bits != 32 && nr == 41u)
		return sock_kind(arg, flags);
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
			 * note on KGENOME_FLOWF_WX is the whole reason: a JIT
			 * asks for RW and flips to RX, so it is never both
			 * at once; a loader asks for RWX in one call. Both
			 * are ALLOC_EXEC and only the second is W+X.
			 */
			if (flags && (arg[2] & 2u))    /* PROT_WRITE too */
				*flags = KGENOME_FLOWF_WX;
			return KGENOME_NUCLEO_ALLOC_EXEC;
		}
	}
	return cap;
}

const char *kgenome_sys_name(unsigned bits, uint32_t nr)
{
	const struct kgenome_sysrow *row = bits == 64
		? kgenome_sys_row(kgenome_sys64, kgenome_sys64_n, nr)
		: kgenome_sys_row(kgenome_sys32, kgenome_sys32_n, nr);

	return row ? row->name : NULL;
}

/*
 * THE SAME TWO QUESTIONS FOR A PORT THAT HAS ITS OWN TABLE.
 *
 * kgenome_flow_cap_of_syscall above is x86's: `bits` picks between two tables and
 * the refinements test x86 numbers. A fixed-width port is described by its
 * kgenome_fxabi instead - table, and which argument holds prot - and the refinements
 * are keyed by the ROW's role, which is what the role column is for: a row
 * that says it is mmap is asked about PROT_EXEC whatever number it has.
 *
 * Only the rows the port's table has. A number with no row is NONE, which the
 * caller records as a syscall the vocabulary has no word for.
 */
static uint16_t fx_look(const struct kgenome_fxabi *fx, uint32_t nr, uint8_t *role,
			const char **name)
{
	const struct kgenome_sysrow *row = kgenome_sys_row(fx->tab, fx->n_tab, nr);

	if (!row)
		row = kgenome_sys_row(fx->tab2, fx->n_tab2, nr);
	if (!row) {
		*role = KGENOME_FLOW_ROLE_NONE;
		*name = NULL;
		return KGENOME_NUCLEO_NONE;
	}
	*role = row->role;
	*name = row->name;
	return row->cap;
}

uint16_t kgenome_flow_cap_of_syscall_abi(const struct kgenome_fxabi *fx, uint32_t nr,
				     const uint64_t *arg, uint8_t *flags)
{
	const char *nm;
	uint8_t role;
	uint16_t cap = fx_look(fx, nr, &role, &nm);

	if (flags)
		*flags = 0;
	if (arg && cap == KGENOME_NUCLEO_SPAWN && role == KGENOME_FLOW_ROLE_CLONE)
		return (arg[0] & KGENOME_FLOW_CLONE_THREAD) ? KGENOME_NUCLEO_THREAD
						    : KGENOME_NUCLEO_SPAWN;
	if (arg && cap == KGENOME_NUCLEO_NET_OPEN && role == KGENOME_FLOW_ROLE_SOCK)
		return sock_kind(arg, flags);
	if (arg && cap == KGENOME_NUCLEO_ALLOC && role == KGENOME_FLOW_ROLE_MMAP &&
	    (arg[fx->prot_arg] & 4u)) {         /* PROT_EXEC */
		if (flags && (arg[fx->prot_arg] & 2u))
			*flags = KGENOME_FLOWF_WX;
		return KGENOME_NUCLEO_ALLOC_EXEC;
	}
	return cap;
}

const char *kgenome_sys_name_abi(const struct kgenome_fxabi *fx, uint32_t nr)
{
	const char *nm;
	uint8_t role;

	fx_look(fx, nr, &role, &nm);
	return nm;
}

/* The row of `names` that `sym` is, or -1. An ELF import may carry a version
 * suffix - "open64@@GLIBC_2.2.5" is the same function as "open64", and the
 * caller should not have to know that this file cares. */
static long names_find(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return -1;
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return (long)i;
	}
	return -1;
}

uint16_t kgenome_flow_cap_of_name(const char *sym)
{
	long i = names_find(sym);

	return i < 0 ? KGENOME_NUCLEO_NONE : names[i].cap;
}

int kgenome_flow_cap_named(uint16_t cap)
{
	size_t i;

	if (cap == KGENOME_NUCLEO_NONE)
		return 0;
	for (i = 0; i < sizeof names / sizeof names[0]; i++)
		if (names[i].cap == cap || kgenome_flow_cap_generic(names[i].cap) == cap)
			return 1;
	return 0;
}

uint16_t kgenome_flow_name_id(const char *sym)
{
	long i = names_find(sym);

	return i < 0 ? 0 : (uint16_t)(i + 1);
}

const char *kgenome_flow_name_of(uint16_t id)
{
	if (!id || id > sizeof names / sizeof names[0])
		return NULL;
	return names[id - 1u].name;
}

/*
 * THE WORD THIS ONE IS A SPECIAL CASE OF, or KGENOME_NUCLEO_NONE.
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
 * IT IS NOT A GROUP. net-recv is in KGENOME_CG_NET and mem-read in KGENOME_CG_IO,
 * which is right - they answer different questions - so the encoding cannot
 * carry this and a table must.
 */
uint16_t kgenome_flow_cap_generic(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_NET_READ:
	case KGENOME_NUCLEO_READ:         return KGENOME_NUCLEO_MEM_READ;
	case KGENOME_NUCLEO_NET_WRITE:
	case KGENOME_NUCLEO_WRITE:        return KGENOME_NUCLEO_MEM_WRITE;
	case KGENOME_NUCLEO_ALLOC_EXEC:   return KGENOME_NUCLEO_ALLOC;
	default:                   return KGENOME_NUCLEO_NONE;
	}
}

const char *kgenome_flow_cap_name(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_ALLOC:        return "mem-alloc";
	case KGENOME_NUCLEO_ALLOC_EXEC:   return "mem-alloc-exec";
	case KGENOME_NUCLEO_HEAP:         return "mem-alloc-heap";
	case KGENOME_NUCLEO_ACTION_READ:   return "mem-action-read";
	case KGENOME_NUCLEO_ACTION_WRITE:  return "mem-action-write";
	case KGENOME_NUCLEO_REG_OPEN:     return "reg-open";
	/* "exec-memory" and not "exec-register": the register is how the
	 * branch was spelled, the memory is what was entered. */
	case KGENOME_NUCLEO_EXEC_REG:     return "exec-memory";
	case KGENOME_NUCLEO_SELF_RESOLVE: return "lib-peb-walk";
	case KGENOME_NUCLEO_NAME_HASH:    return "lib-name-hash";
	/*
	 * "lib-call-indirect", AND IT USED TO BE "call-register".
	 *
	 * Two things were wrong with the old spelling. It was the only word
	 * in KGENOME_CG_LIB without the group's prefix - lib-api-resolve,
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
	case KGENOME_NUCLEO_CALL_REG:     return "lib-call-indirect";
	case KGENOME_NUCLEO_CRYPTO:       return "crypto";
	case KGENOME_NUCLEO_CAPTURE:      return "input-capture";
	case KGENOME_NUCLEO_SVC_INSTALL:  return "service-install";
	case KGENOME_NUCLEO_MOD_LOAD:     return "kmodule-load";
	case KGENOME_NUCLEO_PIPE:         return "pipe-named-create";
	case KGENOME_NUCLEO_PIPE_OPEN:    return "pipe-create";
	case KGENOME_NUCLEO_FILE_DELETE:  return "file-delete";
	case KGENOME_NUCLEO_FILE_RENAME:  return "file-rename";
	case KGENOME_NUCLEO_PERM_SET:     return "file-perm-set";
	case KGENOME_NUCLEO_ANTI_DEBUG:   return "anti-debug";
	case KGENOME_NUCLEO_JAIL:         return "namespace-change";
	case KGENOME_NUCLEO_FD_REDIR:     return "fd-redirect";
	case KGENOME_NUCLEO_TIMESTOMP:    return "file-timestamp-set";
	case KGENOME_NUCLEO_PROC_LIST:    return "proc-enum";
	case KGENOME_NUCLEO_NET_READ:     return "net-recv";
	case KGENOME_NUCLEO_NET_WRITE:    return "net-send";
	case KGENOME_NUCLEO_FD_NONBLOCK:  return "fd-nonblock";
	case KGENOME_NUCLEO_NET_HDRINCL:  return "net-hdrincl";
	case KGENOME_NUCLEO_HTTP_OPEN:    return "http-open";
	case KGENOME_NUCLEO_HTTP_CONNECT: return "http-connect";
	case KGENOME_NUCLEO_HTTP_SEND:    return "http-send";
	case KGENOME_NUCLEO_HTTP_RECV:    return "http-recv";
	case KGENOME_NUCLEO_HTTP_FETCH:   return "http-fetch";
	case KGENOME_NUCLEO_NET_OPEN:     return "net-open";
	case KGENOME_NUCLEO_NET_CONNECT:  return "net-connect";
	case KGENOME_NUCLEO_NET_ACCEPT:   return "net-accept";
	case KGENOME_NUCLEO_NET_BIND:     return "net-bind";
	case KGENOME_NUCLEO_NET_LISTEN:   return "net-listen";
	case KGENOME_NUCLEO_MEM_READ:      return "mem-read";
	case KGENOME_NUCLEO_MEM_WRITE:     return "mem-write";
	case KGENOME_NUCLEO_READ:         return "file-read";
	case KGENOME_NUCLEO_WRITE:        return "file-write";
	case KGENOME_NUCLEO_FILE_OPEN:    return "file-open";
	case KGENOME_NUCLEO_MEMFD:        return "memfd-create";
	case KGENOME_NUCLEO_EXEC_IMAGE:   return "proc-start";
	case KGENOME_NUCLEO_SPAWN:        return "proc-fork";
	case KGENOME_NUCLEO_THREAD:       return "thread-create";
	case KGENOME_NUCLEO_NET_RAW:      return "net-raw";
	case KGENOME_NUCLEO_SLEEP:        return "sleep";
	case KGENOME_NUCLEO_PTRACE:       return "proc-open";
	case KGENOME_NUCLEO_PROC_MEM:     return "proc-mem-access";
	case KGENOME_NUCLEO_PROC_EXEC:    return "proc-control";
	case KGENOME_NUCLEO_RESOLVE:      return "lib-api-resolve";
	case KGENOME_NUCLEO_LIB_OPEN:     return "lib-load";
	case KGENOME_NUCLEO_DNS:          return "net-getaddr";
	case KGENOME_NUCLEO_REG_SET:      return "reg-set";
	case KGENOME_NUCLEO_CRED_SET:     return "cred-modify";
	case KGENOME_NUCLEO_HOOK:         return "kmodule-hook";
	case KGENOME_NUCLEO_KPROBE_REG:   return "kmodule-kprobe-register";
	case KGENOME_NUCLEO_KPROBE_UNREG: return "kmodule-kprobe-unregister";
	case KGENOME_NUCLEO_COPY_FROM_USER: return "kmodule-copy-from-user";
	case KGENOME_NUCLEO_COPY_TO_USER: return "kmodule-copy-to-user";
	case KGENOME_NUCLEO_KSYM_LOOKUP:  return "kmodule-ksym-lookup";
	case KGENOME_NUCLEO_SYMBOL_GET:   return "kmodule-symbol-get";
	case KGENOME_NUCLEO_CRED_PREPARE: return "cred-prepare";
	case KGENOME_NUCLEO_LIST_HIDE:    return "kmodule-list-edit";
	/* Named for the x86 instruction, which is the fault that took the
	 * word out of service - see the note in the import table. */
	case KGENOME_NUCLEO_PROT_OFF:     return "kmodule-write-protect-off";
	case KGENOME_NUCLEO_NET_ADDR:     return "net-addr";
	case KGENOME_NUCLEO_SELF_HIDE:    return "self-hide";
	case KGENOME_NUCLEO_BACKGROUND:   return "proc-background";
	default:                   return "?";
	}
}

/* See the note in nucleo.h. */
unsigned kgenome_flow_name_arg(uint16_t cap, unsigned *arg)
{
	if (arg)
		*arg = 0u;
	switch (cap) {
	/* A resolver is handed the word it is to find. */
	case KGENOME_NUCLEO_KSYM_LOOKUP:
	case KGENOME_NUCLEO_SYMBOL_GET:
		return KGENOME_NAME_DIRECT;
	/*
	 * A probe is handed an OBJECT, and the name it is to be placed on is
	 * one of the pointers in it - see the note in nucleo.h for why this
	 * does not say which.
	 */
	case KGENOME_NUCLEO_KPROBE_REG:
		return KGENOME_NAME_OBJECT;
	default:
		return 0u;
	}
}

/* See the note in nucleo.h - this is the vocabulary's own answer, and the
 * only one. */
int kgenome_flow_hands_on(uint16_t cap, const char *nm)
{
	switch (cap) {
	case KGENOME_NUCLEO_ALLOC:
	case KGENOME_NUCLEO_ALLOC_EXEC:
	case KGENOME_NUCLEO_HEAP:
		/*
		 * mprotect shares the word with mmap and is not a
		 * constructor: it is handed a mapping and returns a status.
		 */
		return !(nm && (!strcmp(nm, "mprotect") ||
				!strcmp(nm, "mprotect64")));
	case KGENOME_NUCLEO_NET_OPEN:
	case KGENOME_NUCLEO_NET_RAW:
	case KGENOME_NUCLEO_NET_ACCEPT:
	case KGENOME_NUCLEO_FILE_OPEN:
	case KGENOME_NUCLEO_MEMFD:
	case KGENOME_NUCLEO_PIPE_OPEN:
	/* The kernel side: a credential to edit and commit, and the address
	 * of whatever was looked up. */
	case KGENOME_NUCLEO_CRED_PREPARE:
	case KGENOME_NUCLEO_KSYM_LOOKUP:
	case KGENOME_NUCLEO_SYMBOL_GET:
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
const struct kgenome_sysrow kgenome_sys_a64[] = {
	{   56, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{   63, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{   64, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{ 101, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{ 117, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{ 198, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 200, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 201, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 202, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 203, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 206, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 207, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{ 220, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{ 221, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{ 222, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see fixed_prot */
	{ 226, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{ 279, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  }
};

/*
 * ARM EABI. The low numbers are i386's, which ARM inherited - so these agree
 * with kgenome_sys32 above and are not a second claim about them. The socket calls
 * are ARM's own, past where the shared range ends: i386 multiplexes them
 * through socketcall and ARM does not.
 *
 * NOT FROM A HEADER - this host has none for ARM. Corroborated on the corpus
 * instead, and the shape of the agreement is the evidence: across 1771 ARM
 * objects, 281, 283 and 289 each appear in 97 files, 291 and 290 in 96.
 * A program that opens a socket connects and sends on it, so a table that
 * had any of these wrong would not produce counts that track each other.
 */
const struct kgenome_sysrow kgenome_sys_arm[] = {
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{   11, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{   26, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{ 120, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{ 190, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "vfork"  },
	{ 192, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap2"  },
	{ 281, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 282, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 283, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 284, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 285, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 289, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "send"  },
	{ 290, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 291, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recv"  },
	{ 292, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{ 322, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{ 385, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  }
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
const struct kgenome_sysrow kgenome_sys_mips[] = {
	{ 4002, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{ 4003, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{ 4004, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{ 4005, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{ 4011, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{ 4026, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{ 4090, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },
	{ 4120, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{ 4125, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },
	{ 4166, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{ 4168, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 4169, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 4170, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 4174, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 4175, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recv"  },
	{ 4176, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{ 4178, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "send"  },
	{ 4180, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 4183, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 4288, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{ 4354, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  }
};

/*
 * POWERPC, AND IT INHERITED i386's NUMBERS.
 *
 * NOT FROM A HEADER - there is none for any of these on this host - and
 * corroborated the way kgenome_sys_arm and kgenome_sys_mips were, from what the corpus
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
const struct kgenome_sysrow kgenome_sys_ppc[] = {
	{ 326, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 327, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 328, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 329, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 330, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 334, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "send"  },
	{ 335, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 336, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recv"  },
	{ 337, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  }
};

/*
 * SPARC, WHICH KEPT ITS OWN NUMBERING and is the one port here that did.
 *
 * Corroborated the same way, over 256 objects: 206 appears in 94.5% of them
 * and 102, 103, 155, 44, 53, 69, 70 move with it. That is SPARC's socket at
 * 206, not i386's at anything - and the agreement of the group is the
 * evidence, because a mis-numbered table does not produce counts that track.
 */
const struct kgenome_sysrow kgenome_sys_sparc[] = {
	{     1, KGENOME_NUCLEO_NONE, KGENOME_FLOW_ROLE_NONE, "exit"  },
	{     2, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{     3, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{     4, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{     5, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{   26, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{   59, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{   71, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },
	{   74, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },
	{ 206, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 207, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 232, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 233, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{ 234, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 235, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 240, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 284, KGENOME_NUCLEO_THREAD, KGENOME_FLOW_ROLE_NONE, "clone"  }
};



/*
 * MIPS n64, which bases its numbering at 5000.
 *
 * FROM A HEADER THIS TIME, and the header is named because the o32 table
 * beside it was not: /run/host/usr/lib/linux/uapi/mips/asm/unistd_n64.h on
 * this machine. Corroborated against the corpus anyway - see
 * KGENOME_FLOW_A_MIPS64 - because a header read wrongly is as quiet as a number
 * remembered wrongly.
 *
 * NOT AN OFFSET FROM THE o32 TABLE. 4003 is read on o32 and 5003 is close on
 * n64; the lists diverge immediately and anything derived by adding 1000
 * would be confidently wrong.
 */
const struct kgenome_sysrow kgenome_sys_mips64[] = {
	{ 5000, KGENOME_NUCLEO_MEM_READ, KGENOME_FLOW_ROLE_NONE, "read"  },
	{ 5001, KGENOME_NUCLEO_MEM_WRITE, KGENOME_FLOW_ROLE_NONE, "write"  },
	{ 5002, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "open"  },
	{ 5247, KGENOME_NUCLEO_FILE_OPEN, KGENOME_FLOW_ROLE_NONE, "openat"  },
	{ 5009, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mmap"  },
	{ 5010, KGENOME_NUCLEO_ALLOC, KGENOME_FLOW_ROLE_MMAP, "mprotect"  },
	{ 5055, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_CLONE, "clone"  },
	{ 5056, KGENOME_NUCLEO_SPAWN, KGENOME_FLOW_ROLE_NONE, "fork"  },
	{ 5057, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execve"  },
	{ 5316, KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_FLOW_ROLE_NONE, "execveat"  },
	{ 5040, KGENOME_NUCLEO_NET_OPEN, KGENOME_FLOW_ROLE_SOCK, "socket"  },
	{ 5041, KGENOME_NUCLEO_NET_CONNECT, KGENOME_FLOW_ROLE_NONE, "connect"  },
	{ 5042, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept"  },
	{ 5293, KGENOME_NUCLEO_NET_ACCEPT, KGENOME_FLOW_ROLE_NONE, "accept4"  },
	{ 5048, KGENOME_NUCLEO_NET_BIND, KGENOME_FLOW_ROLE_NONE, "bind"  },
	{ 5049, KGENOME_NUCLEO_NET_LISTEN, KGENOME_FLOW_ROLE_NONE, "listen"  },
	{ 5043, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendto"  },
	{ 5044, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvfrom"  },
	{ 5045, KGENOME_NUCLEO_NET_WRITE, KGENOME_FLOW_ROLE_NONE, "sendmsg"  },
	{ 5046, KGENOME_NUCLEO_NET_READ, KGENOME_FLOW_ROLE_NONE, "recvmsg"  },
	{ 5034, KGENOME_NUCLEO_SLEEP, KGENOME_FLOW_ROLE_NONE, "nanosleep"  },
	{ 5099, KGENOME_NUCLEO_PTRACE, KGENOME_FLOW_ROLE_NONE, "ptrace"  },
	{ 5314, KGENOME_NUCLEO_MEMFD, KGENOME_FLOW_ROLE_NONE, "memfd_create"  },
	{ 5085, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlink"  },
	{ 5253, KGENOME_NUCLEO_FILE_DELETE, KGENOME_FLOW_ROLE_NONE, "unlinkat"  },
	{ 5080, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "rename"  },
	{ 5254, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat"  },
	{ 5311, KGENOME_NUCLEO_FILE_RENAME, KGENOME_FLOW_ROLE_NONE, "renameat2"  },
	{ 5088, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "chmod"  },
	{ 5089, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmod"  },
	{ 5258, KGENOME_NUCLEO_PERM_SET, KGENOME_FLOW_ROLE_NONE, "fchmodat"  },
	{ 5103, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setuid"  },
	{ 5104, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setgid"  },
	{ 5111, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setreuid"  },
	{ 5115, KGENOME_NUCLEO_CRED_SET, KGENOME_FLOW_ROLE_NONE, "setresuid"  },
	{ 5304, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 5305, KGENOME_NUCLEO_PROC_MEM, KGENOME_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 5168, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "init_module"  },
	{ 5169, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "delete_module"  },
	{ 5307, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "finit_module"  },
	{ 5315, KGENOME_NUCLEO_MOD_LOAD, KGENOME_FLOW_ROLE_NONE, "bpf"  },
	{ 5156, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "chroot"  },
	{ 5151, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "pivot_root"  },
	{ 5303, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "setns"  },
	{ 5262, KGENOME_NUCLEO_JAIL, KGENOME_FLOW_ROLE_NONE, "unshare"  },
	{ 5032, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup2"  },
	{ 5286, KGENOME_NUCLEO_FD_REDIR, KGENOME_FLOW_ROLE_NONE, "dup3"  },
	{ 5130, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utime"  },
	{ 5226, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimes"  },
	{ 5251, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "futimesat"  },
	{ 5275, KGENOME_NUCLEO_TIMESTOMP, KGENOME_FLOW_ROLE_NONE, "utimensat"  }
};

const uint32_t kgenome_sys64_n = (uint32_t)(sizeof kgenome_sys64 / sizeof kgenome_sys64[0]);
const uint32_t kgenome_sys32_n = (uint32_t)(sizeof kgenome_sys32 / sizeof kgenome_sys32[0]);
const uint32_t kgenome_sockcall_n = (uint32_t)(sizeof kgenome_sockcall / sizeof kgenome_sockcall[0]);
const uint32_t kgenome_sys_a64_n = (uint32_t)(sizeof kgenome_sys_a64 / sizeof kgenome_sys_a64[0]);
const uint32_t kgenome_sys_arm_n = (uint32_t)(sizeof kgenome_sys_arm / sizeof kgenome_sys_arm[0]);
const uint32_t kgenome_sys_mips_n = (uint32_t)(sizeof kgenome_sys_mips / sizeof kgenome_sys_mips[0]);
const uint32_t kgenome_sys_mips64_n = (uint32_t)(sizeof kgenome_sys_mips64 / sizeof kgenome_sys_mips64[0]);
const uint32_t kgenome_sys_ppc_n = (uint32_t)(sizeof kgenome_sys_ppc / sizeof kgenome_sys_ppc[0]);
const uint32_t kgenome_sys_sparc_n = (uint32_t)(sizeof kgenome_sys_sparc / sizeof kgenome_sys_sparc[0]);

#define FXN(t) kgenome_##t, kgenome_##t##_n

static const struct kgenome_fxabi FX_MIPS = {
	FXN(sys_mips), NULL, 0, 0, 2, 2, 4, 4, 2
};
/* Same registers and the same `syscall`; only the table differs. */
static const struct kgenome_fxabi FX_MIPS64 = {
	FXN(sys_mips64), NULL, 0, 0, 2, 2, 4, 4, 2
};
static const struct kgenome_fxabi FX_ARM = {
	FXN(sys_arm),  NULL, 0, 0, 7, 0, 0, 6, 2
};
static const struct kgenome_fxabi FX_A64 = {
	FXN(sys_a64),  NULL, 0, 0, 8, 0, 0, 6, 2
};
/*
 * PowerPC: r0 carries the number, r3 the result and the first argument -
 * the same register, which is why the provenance note in sweep_fixed applies
 * here exactly as it does to ARM.
 */
static const struct kgenome_fxabi FX_PPC = {
	FXN(sys_ppc), FXN(sys32), 102, 0, 3, 3, 6, 2
};
/* SPARC: %g1 is register 1, %o0 is register 8 and is both the result and the
 * first argument. */
static const struct kgenome_fxabi FX_SPARC = {
	FXN(sys_sparc), NULL, 0, 0, 1, 8, 8, 6, 2
};
/*
 * RISC-V, AND IT NEEDS NO TABLE OF ITS OWN. The port took the generic
 * numbering, which is AArch64's - corroborated over 45 objects, where 93,
 * 94, 56, 57, 198, 214, 215, 220 and 222 are what appears, every one of them
 * a row of kgenome_sys_a64. a7 is x17 and a0 is x10.
 */
static const struct kgenome_fxabi FX_RISCV = {
	FXN(sys_a64), NULL, 0, 0, 17, 10, 10, 6, 2
};
/* SuperH: r3 the number, r0 the result, r4 the first argument. */
static const struct kgenome_fxabi FX_SH = {
	FXN(sys32), NULL, 0, 102, 3, 0, 4, 4, 2
};
/* m68k: d0 the number AND the result, d1 the first argument. */
static const struct kgenome_fxabi FX_M68K = {
	FXN(sys32), NULL, 0, 102, 0, 0, 1, 5, 2
};


const struct kgenome_fxabi *kgenome_fx_abi_of(unsigned arch)
{
	switch (arch) {
	case KGENOME_FLOW_A_MIPS32:  return &FX_MIPS;
	case KGENOME_FLOW_A_MIPS64:  return &FX_MIPS64;
	case KGENOME_FLOW_A_ARM32:   return &FX_ARM;
	case KGENOME_FLOW_A_PPC32:
	case KGENOME_FLOW_A_PPC64:   return &FX_PPC;
	case KGENOME_FLOW_A_SPARC32: return &FX_SPARC;
	case KGENOME_FLOW_A_RISCV:   return &FX_RISCV;
	case KGENOME_FLOW_A_SH:      return &FX_SH;
	case KGENOME_FLOW_A_M68K:    return &FX_M68K;
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
int kgenome_sys_zero_on_success(const char *name)
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

