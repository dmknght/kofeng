/* See vocab.h. */

#include "flow.h"   /* KOF_FLOW_A_*: which ABI a table belongs to */
#include "vocab.h"

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
 * The roles are flow.h's - see KOF_FLOW_ROLE_NONE. Naming them in the table
 * rather than re-listing the numbers in the pass that needs them is what
 * keeps "4183 is socket" written down exactly once.
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
	{     0, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     1, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     2, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   9, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see prot_cap */
	{  10, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{   35, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{  41, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{   42, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{   43, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{   44, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{   45, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{  56, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{   57, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{   58, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "vfork"  },
	{   59, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 257, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 319, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 322, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	/*
	 * AND THE REST OF WHAT A PROGRAM CAN ASK FOR. Numbers read out of
	 * /usr/include/x86_64-linux-gnu/asm/unistd_64.h on this machine
	 * rather than remembered, because a wrong one here is not a missed
	 * detection - it is a confident wrong name on whatever syscall does
	 * hold the number.
	 */
	{  82, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "rename"  },
	{  87, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{ 263, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 264, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 316, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{  90, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{  91, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 268, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{ 105, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{ 106, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{ 113, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 117, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 310, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 311, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 175, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 176, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 313, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 321, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{ 161, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 155, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 308, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 272, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{ 101, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{  33, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{ 292, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{ 132, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 235, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 261, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 280, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
};

/* Linux i386. */
const struct sysrow kof_sys32[] = {
	{     2, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     4, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   11, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{  90, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 102, KOF_CAP_NONE, KOF_FLOW_ROLE_NONE, "socketcall"  },         /* socketcall - the sub-call is in ebx */
	{ 120, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 192, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap2"  },
	{ 295, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 356, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 358, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	/* The same list on i386, from asm/unistd_32.h and NOT by subtracting
	 * anything from the table above - the two numberings are unrelated. */
	{  10, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{  38, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "rename"  },
	{ 301, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 302, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 353, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{  15, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{  94, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 306, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{  23, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{  46, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{  70, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 164, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 347, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 348, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 128, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 129, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 350, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 357, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{  61, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 217, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 346, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 310, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{  26, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{  63, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{ 330, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{  30, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 271, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 299, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 320, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
};

/* i386 multiplexes every socket operation through socketcall, with the
 * operation in ebx. Left as its own table rather than folded into the one
 * above, because it is a different axis and merging them would need a second
 * key nothing else uses. */
const struct sysrow kof_sockcall[] = {
	{  1, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket" },
	{  2, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind" },
	{  3, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect" },
	{  4, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen" },
	{  5, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept" },
	{  9, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "send" },
	{ 10, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recv" },
	{ 11, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto" },
	{ 12, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom" }
};


uint8_t kof_sys_look(const struct sysrow *t, uint32_t n, uint32_t nr)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (t[i].nr == nr)
			return t[i].cap;
	return KOF_CAP_NONE;
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
static const struct { const char *name; uint8_t cap; uint8_t role; }
names[] = {
	/* POSIX */
	{ "mmap",           KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "mmap64",         KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "mprotect",       KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "socket",         KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "socketpair",     KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "connect",        KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "accept",         KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "accept4",        KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "bind",           KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE },
	{ "listen",         KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE },
	{ "recv",           KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "recvfrom",       KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "recvmsg",        KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "read",           KOF_CAP_READ, KOF_FLOW_ROLE_NONE },
	{ "send",           KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "sendto",         KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "sendmsg",        KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "write",          KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "open",           KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "open64",         KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "openat",         KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "fopen",          KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "memfd_create",   KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE },
	{ "execve",         KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execv",          KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execl",          KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execlp",         KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "execvp",         KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "system",         KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "popen",          KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "fork",           KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE },
	{ "vfork",          KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE },
	/* The libc wrapper, whose flags are its THIRD argument rather than its
	 * first - a different convention from the syscall, and past what is
	 * refined here. It stays the weaker claim. */
	{ "clone",          KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE },
	/* No flags to read and no ambiguity: the name IS the claim. */
	{ "pthread_create", KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
	{ "daemon",         KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE },
	{ "sleep",          KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "usleep",         KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "nanosleep",      KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE },
	{ "ptrace",         KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE },
	/* Windows, for the same words */
	{ "VirtualAlloc",   KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "VirtualAllocEx", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "VirtualProtect", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "WSASocketA",     KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "WSASocketW",     KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK },
	{ "InternetOpenA",  KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenW",  KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "WSAConnect",     KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetConnectA", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetConnectW", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "CreateFileA",    KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "CreateFileW",    KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "WriteFile",      KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "ReadFile",       KOF_CAP_READ, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessA", KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessW", KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "WinExec",        KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteA",  KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteW",  KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateThread",   KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
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
	{ "WSARecv",        KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "WSASend",        KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE },
	{ "WSAAccept",      KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "closesocket",    KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenUrlA", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetOpenUrlW", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "InternetReadFile", KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	{ "HttpSendRequestA", KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "HttpSendRequestW", KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "HttpOpenRequestA", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "HttpOpenRequestW", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "URLDownloadToFileA", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "URLDownloadToFileW", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "WinHttpConnect", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "WinHttpOpenRequest", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "WinHttpSendRequest", KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "WinHttpReadData", KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE },
	/* A mapping is a mapping, whichever name asks for it. */
	{ "VirtualProtectEx", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtAllocateVirtualMemory", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtProtectVirtualMemory", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "ZwAllocateVirtualMemory", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "ZwProtectVirtualMemory", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "CreateFileMappingA", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "CreateFileMappingW", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "MapViewOfFile",  KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "MapViewOfFileEx", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	/* The handle, the memory and the execution - see the note on the
	 * three capabilities in flow.h. */
	{ "OpenProcess",    KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "DebugActiveProcess", KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "WriteProcessMemory", KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "ReadProcessMemory", KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "NtWriteVirtualMemory", KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "CreateRemoteThread", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "CreateRemoteThreadEx", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "NtQueueApcThread", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "QueueUserAPC",   KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "SetThreadContext", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "NtResumeThread", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	{ "ResumeThread",   KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	/* The loader pair, which is what a program has INSTEAD of an import
	 * table entry - see KOF_CAP_RESOLVE. */
	{ "LoadLibraryA",   KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryW",   KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryExA", KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LoadLibraryExW", KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "GetProcAddress", KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "LdrLoadDll",     KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "LdrGetProcedureAddress", KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "dlopen",         KOF_CAP_LIB_OPEN, KOF_FLOW_ROLE_NONE },
	{ "dlsym",          KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	/* Writes only; a program reading its own configuration is every
	 * program - see KOF_CAP_REG_SET. */
	{ "RegSetValueExA", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegSetValueExW", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegCreateKeyExA", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegCreateKeyExW", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteValueA", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteValueW", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "NtSetValueKey",  KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "Sleep",          KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE },

	/*
	 * THE ROWS THE RANKING CHOSE. Measured over the whole corpus here -
	 * 1772 ELF malware objects against 20347 Linux binaries - and kept
	 * because of what the numbers said, not because they sounded right.
	 * See KOF_CAP_NET_ADDR for the rates and for what the ranking
	 * rejected.
	 */
	{ "htons",          KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "htonl",          KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "ntohs",          KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "ntohl",          KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_addr",      KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_aton",      KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_pton",      KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_ntoa",      KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "inet_network",   KOF_CAP_NET_ADDR, KOF_FLOW_ROLE_NONE },
	{ "gethostbyname",  KOF_CAP_DNS, KOF_FLOW_ROLE_NONE },
	{ "getaddrinfo",    KOF_CAP_DNS, KOF_FLOW_ROLE_NONE },
	{ "prctl",          KOF_CAP_SELF_HIDE, KOF_FLOW_ROLE_NONE },
	{ "setsid",         KOF_CAP_BACKGROUND, KOF_FLOW_ROLE_NONE },

	/*
	 * THE KERNEL, which is the same kind of table and a different side of
	 * the same machine.
	 *
	 * A loadable module makes no syscalls - it answers them - so the whole
	 * vocabulary above is silent on one. What it has instead is a list of
	 * UNDEFINED symbols, which is the same declaration a PE import table
	 * is: the names it was compiled against, fixed, and not the module's
	 * to choose. See KOF_CAP_CRED_SET for the measurement that picked
	 * these.
	 *
	 * THE LINUX ONES HAVE NO PREFIX AND THAT IS A HAZARD worth stating:
	 * `kernel_read` and `filp_open` are kernel names, but nothing stops a
	 * userspace program exporting a function of the same name, and this
	 * table is consulted for both. Each row below is a name a userspace
	 * libc does not have, which is the only thing keeping the two apart.
	 */
	/* Credentials replaced - "give me root", compiled. */
	{ "commit_creds",   KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "prepare_creds",  KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "prepare_kernel_cred", KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "set_current_groups", KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	/* Code of one's own put in the path of somebody else's. */
	{ "register_kprobe", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "register_kprobes", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "register_kretprobe", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	/*
	 * THE UNREGISTER SIDE TOO, and it is not symmetry for its own sake:
	 * the modern way to find an unexported kernel symbol is to put a
	 * kprobe on it, read the address and take the probe away again - so
	 * the pair is the IDIOM, and a module that registers one and never
	 * removes it is doing something else. Measured at 5 of 6 rootkits and
	 * 0 of 898 clean modules, the same as the register side.
	 */
	{ "unregister_kprobe", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "unregister_kprobes", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "unregister_kretprobe", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "unregister_ftrace_function", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "write_cr0",      KOF_CAP_PROT_OFF, KOF_FLOW_ROLE_NONE },
	{ "write_cr4",      KOF_CAP_PROT_OFF, KOF_FLOW_ROLE_NONE },
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
	{ "peb_ldr",        KOF_CAP_SELF_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "name_hash",      KOF_CAP_NAME_HASH, KOF_FLOW_ROLE_NONE },
	{ "mov_cr0",        KOF_CAP_PROT_OFF, KOF_FLOW_ROLE_NONE },
	{ "register_ftrace_function", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "ftrace_set_filter_ip", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "register_ftrace_direct", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "text_poke",      KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "text_poke_kgdb", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "set_memory_rw",  KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "set_memory_x",   KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	/*
	 * An entry taken out of a kernel list. BOTH SPELLINGS, because the
	 * kernel renamed the check and a table that knew only the old one
	 * would be a table about one kernel version - see KOF_CAP_LIST_HIDE,
	 * where the 17% that makes this a term and not a verdict is measured.
	 */
	{ "__list_del_entry_valid", KOF_CAP_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "__list_del_entry_valid_or_report", KOF_CAP_LIST_HIDE,
	  KOF_FLOW_ROLE_NONE },
	{ "__list_add_valid", KOF_CAP_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	{ "__list_add_valid_or_report", KOF_CAP_LIST_HIDE,
	  KOF_FLOW_ROLE_NONE },
	{ "list_del",       KOF_CAP_LIST_HIDE, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE WORDS THE VOCABULARY ALREADY HAD, in the kernel's spelling.
	 * kallsyms_lookup_name is dlsym with a different name - it is how a
	 * module reaches a symbol the kernel did not export to it, and it
	 * needs no new word to say so.
	 */
	{ "kallsyms_lookup_name", KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "__symbol_get",   KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "_copy_from_user", KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	{ "copy_from_user", KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	{ "_copy_to_user",  KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "copy_to_user",   KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "kernel_read",    KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	{ "kernel_write",   KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "vfs_read",       KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	{ "vfs_write",      KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "filp_open",      KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "filp_close",     KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "call_usermodehelper", KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "call_usermodehelper_exec", KOF_CAP_EXEC_IMAGE,
	  KOF_FLOW_ROLE_NONE },
	{ "kthread_create_on_node", KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
	{ "kthread_run",    KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
	{ "wake_up_process", KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
	{ "sock_create",    KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "sock_create_kern", KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_NONE },
	{ "kernel_connect", KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE },
	{ "kernel_accept",  KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE },
	{ "kernel_sendmsg", KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "kernel_recvmsg", KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE WINDOWS KERNEL, which reaches this table the way every other
	 * PE import does - the mechanism needs nothing new, only the words.
	 */
	{ "ZwCreateFile",   KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "ZwOpenFile",     KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE },
	{ "ZwReadFile",     KOF_CAP_READ,  KOF_FLOW_ROLE_NONE },
	{ "ZwWriteFile",    KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE },
	{ "MmGetSystemRoutineAddress", KOF_CAP_RESOLVE, KOF_FLOW_ROLE_NONE },
	{ "MmMapLockedPagesSpecifyCache", KOF_CAP_PROC_MEM,
	  KOF_FLOW_ROLE_NONE },
	{ "MmMapLockedPages", KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "PsLookupProcessByProcessId", KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE },
	{ "PsSetCreateProcessNotifyRoutine", KOF_CAP_HOOK,
	  KOF_FLOW_ROLE_NONE },
	{ "PsSetCreateProcessNotifyRoutineEx", KOF_CAP_HOOK,
	  KOF_FLOW_ROLE_NONE },
	{ "PsSetLoadImageNotifyRoutine", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "ObRegisterCallbacks", KOF_CAP_HOOK, KOF_FLOW_ROLE_NONE },
	{ "PsCreateSystemThread", KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE },
	{ "ZwTerminateProcess", KOF_CAP_PROC_EXEC, KOF_FLOW_ROLE_NONE },
	/*
	 * ===== THE WORDS ADDED WITH THE NINE CAPABILITIES AT THE END OF
	 * enum kof_flow_cap. Each entry point here exists to do ONE thing;
	 * that is the bar, and the names that did not clear it are listed in
	 * kofpathogen.h beside the capabilities rather than here.
	 */
	/* Encryption. Windows has two generations of the same API and both are
	 * still shipped, so both are here. */
	{ "CryptEncrypt",   KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptDecrypt",   KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptAcquireContextA", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptAcquireContextW", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptGenKey",    KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptDeriveKey", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "CryptImportKey", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptEncrypt",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptDecrypt",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptGenerateSymmetricKey", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "BCryptImportKeyPair", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	/* And the Linux side, which is OpenSSL in practice. The EVP names are
	 * the ones a program links; the AES_ ones are the older direct calls
	 * that statically linked malware still carries. */
	{ "EVP_EncryptInit_ex", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_EncryptUpdate",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_DecryptInit_ex", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_DecryptUpdate",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "EVP_CipherInit_ex",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_set_encrypt_key", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_cbc_encrypt",     KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "AES_encrypt",         KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "RSA_public_encrypt",  KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "RSA_private_decrypt", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	{ "crypto_secretbox_easy", KOF_CAP_CRYPTO, KOF_FLOW_ROLE_NONE },
	/* Taking what the user is doing. */
	{ "SetWindowsHookExA", KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "SetWindowsHookExW", KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetAsyncKeyState",  KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetKeyboardState",  KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetRawInputData",   KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "RegisterRawInputDevices", KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "GetClipboardData",  KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "SetClipboardData",  KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "XQueryKeymap",      KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	{ "XGrabKeyboard",     KOF_CAP_CAPTURE, KOF_FLOW_ROLE_NONE },
	/* Installing itself as a service. */
	{ "OpenSCManagerA",  KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "OpenSCManagerW",  KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "CreateServiceA",  KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "CreateServiceW",  KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "StartServiceA",   KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "StartServiceW",   KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "ChangeServiceConfigA", KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	{ "ChangeServiceConfigW", KOF_CAP_SVC_INSTALL, KOF_FLOW_ROLE_NONE },
	/* Code into the kernel. */
	{ "init_module",    KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "finit_module",   KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "delete_module",  KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf",            KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_load_program", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_prog_load",  KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
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
	{ "bpf_object__load", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_object__load_skeleton", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_object__attach_skeleton", KOF_CAP_MOD_LOAD,
	  KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_kprobe", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_uprobe", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_tracepoint", KOF_CAP_MOD_LOAD,
	  KOF_FLOW_ROLE_NONE },
	{ "bpf_program__attach_xdp", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_prog_attach", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_set_link_xdp_fd", KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "bpf_tc_attach",  KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "NtLoadDriver",   KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	{ "ZwLoadDriver",   KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE },
	/* A named pipe, and only a named one. */
	{ "CreateNamedPipeA", KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CreateNamedPipeW", KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "ConnectNamedPipe", KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CallNamedPipeA",   KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "CallNamedPipeW",   KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "mkfifo",           KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	{ "mkfifoat",         KOF_CAP_PIPE, KOF_FLOW_ROLE_NONE },
	/* Removing a file. */
	{ "DeleteFileA",    KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "DeleteFileW",    KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "MoveFileExA",    KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "MoveFileExW",    KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "unlink",         KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "unlinkat",       KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "remove",         KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	{ "rename",         KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE },
	/* Making a dropped file runnable. */
	{ "chmod",          KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "fchmod",         KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "fchmodat",       KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "SetFileAttributesA", KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE },
	{ "SetFileAttributesW", KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE },
	/* Asking whether it is watched. */
	{ "IsDebuggerPresent", KOF_CAP_ANTI_DEBUG, KOF_FLOW_ROLE_NONE },
	{ "CheckRemoteDebuggerPresent", KOF_CAP_ANTI_DEBUG,
	  KOF_FLOW_ROLE_NONE },
	{ "NtSetInformationThread", KOF_CAP_ANTI_DEBUG, KOF_FLOW_ROLE_NONE },
	/* Moving the boundary of what it can see. */
	{ "chroot",         KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE },
	{ "pivot_root",     KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE },
	{ "setns",          KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE },
	{ "unshare",        KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE },
	/*
	 * AND WORDS FOR CAPABILITIES THAT ALREADY EXISTED, where only the
	 * spelling was missing. Changing one's own privileges is CRED_SET
	 * whether a kernel module calls commit_creds or a program calls
	 * setuid; reaching into another process is PROC_MEM whether it is
	 * WriteProcessMemory or process_vm_writev.
	 */
	{ "setuid",         KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setgid",         KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "seteuid",        KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setreuid",       KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "setresuid",      KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "AdjustTokenPrivileges", KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "OpenProcessToken",      KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "DuplicateTokenEx",      KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "ImpersonateLoggedOnUser", KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "SetThreadToken",        KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE },
	{ "process_vm_readv",      KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "process_vm_writev",     KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE },
	{ "posix_spawn",           KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessAsUserA",  KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessAsUserW",  KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessWithTokenW", KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "CreateProcessWithLogonW", KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteExA",       KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	{ "ShellExecuteExW",       KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE },
	/* The three measured ones. */
	{ "dup2",           KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "dup3",           KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE },
	{ "utime",          KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "utimes",         KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "utimensat",      KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "futimens",       KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "SetFileTime",    KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE },
	{ "CreateToolhelp32Snapshot", KOF_CAP_PROC_LIST,
	  KOF_FLOW_ROLE_NONE },
	{ "Process32First", KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32FirstW", KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32Next",  KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Process32NextW", KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Module32First",  KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Module32Next",   KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Thread32First",  KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "Thread32Next",   KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	{ "EnumProcesses",  KOF_CAP_PROC_LIST, KOF_FLOW_ROLE_NONE },
	/*
	 * AND THE GAPS THE SAME MEASUREMENT FOUND IN WORDS THAT ALREADY
	 * EXISTED - each one a spelling nobody had written down.
	 */
	{ "BCryptOpenAlgorithmProvider", KOF_CAP_CRYPTO,
	  KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyA",  KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyW",  KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyExA", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	{ "RegDeleteKeyExW", KOF_CAP_REG_SET, KOF_FLOW_ROLE_NONE },
	/* An allocation, and incidentally one that fails in some sandboxes -
	 * which is why a loader picks it. The capability is the allocation. */
	{ "VirtualAllocExNuma", KOF_CAP_ALLOC, KOF_FLOW_ROLE_NONE },
	{ "NtQueryInformationProcess", KOF_CAP_ANTI_DEBUG,
	  KOF_FLOW_ROLE_NONE }
};

/*
 * The syscall half of the vocabulary, for a caller that has a RUN rather than
 * code. See the note in flow.h for why this is exported instead of copied.
 */
uint8_t kof_flow_cap_of_syscall(unsigned bits, uint32_t nr,
				const uint64_t *arg, uint8_t *flags)
{
	uint8_t cap;

	if (flags)
		*flags = 0;
	if (bits == 32) {
		/* socketcall multiplexes; the operation is the first argument
		 * and without it the number says only "something network". */
		if (nr == 102u) {
			if (!arg)
				return KOF_CAP_NONE;
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
	if (arg && cap == KOF_CAP_SPAWN &&
	    (bits == 32 ? nr == 120u : nr == 56u))
		return (arg[0] & FLOW_CLONE_THREAD) ? KOF_CAP_THREAD
						    : KOF_CAP_SPAWN;
	if (arg && cap == KOF_CAP_NET_OPEN && bits != 32 && nr == 41u) {
		if ((arg[0] & 0xffu) == FLOW_AF_UNIX && flags)
			*flags |= KOF_FLOWF_LOCAL;
		if ((arg[1] & 0xfu) == FLOW_SOCK_RAW)
			return KOF_CAP_NET_RAW;
		if ((arg[1] & 0xfu) == FLOW_SOCK_DGRAM && flags)
			*flags |= KOF_FLOWF_DGRAM;
		return KOF_CAP_NET_OPEN;
	}
	if (cap == KOF_CAP_ALLOC && arg) {
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
			return KOF_CAP_ALLOC_EXEC;
		}
	}
	return cap;
}

uint8_t kof_flow_cap_of_name(const char *sym)
{
	size_t i;

	if (!sym || !*sym)
		return KOF_CAP_NONE;
	/* An ELF import may carry a version suffix - "open64@@GLIBC_2.2.5" is
	 * the same function as "open64", and the caller should not have to
	 * know that this file cares. */
	for (i = 0; i < sizeof names / sizeof names[0]; i++) {
		const char *a = names[i].name, *b = sym;

		while (*a && *a == *b) { a++; b++; }
		if (!*a && (!*b || *b == '@'))
			return names[i].cap;
	}
	return KOF_CAP_NONE;
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

const char *kof_flow_cap_name(uint8_t cap)
{
	switch (cap) {
	case KOF_CAP_ALLOC:        return "alloc";
	case KOF_CAP_ALLOC_EXEC:   return "alloc-exec";
	/* "exec-memory" and not "exec-register": the register is how the
	 * branch was spelled, the memory is what was entered. The sibling
	 * KOF_CAP_CALL_REG keeps `call-register`, because there the register
	 * IS the fact - it holds the program's own code. */
	case KOF_CAP_EXEC_REG:     return "exec-memory";
	case KOF_CAP_SELF_RESOLVE: return "self-resolve";
	case KOF_CAP_NAME_HASH:    return "name-hash";
	case KOF_CAP_CALL_REG:     return "call-register";
	case KOF_CAP_CRYPTO:       return "crypto";
	case KOF_CAP_CAPTURE:      return "capture";
	case KOF_CAP_SVC_INSTALL:  return "service-install";
	case KOF_CAP_MOD_LOAD:     return "module-load";
	case KOF_CAP_PIPE:         return "named-pipe";
	case KOF_CAP_FILE_DELETE:  return "file-delete";
	case KOF_CAP_PERM_SET:     return "perm-set";
	case KOF_CAP_ANTI_DEBUG:   return "anti-debug";
	case KOF_CAP_JAIL:         return "jail";
	case KOF_CAP_FD_REDIR:     return "fd-redirect";
	case KOF_CAP_TIMESTOMP:    return "timestomp";
	case KOF_CAP_PROC_LIST:    return "process-list";
	case KOF_CAP_NET_READ:     return "net-read";
	case KOF_CAP_NET_WRITE:    return "net-write";
	case KOF_CAP_NET_OPEN:     return "net-open";
	case KOF_CAP_NET_CONNECT:  return "net-connect";
	case KOF_CAP_NET_ACCEPT:   return "net-accept";
	case KOF_CAP_NET_BIND:     return "net-bind";
	case KOF_CAP_NET_LISTEN:   return "net-listen";
	case KOF_CAP_READ:         return "read";
	case KOF_CAP_WRITE:        return "write";
	case KOF_CAP_FILE_OPEN:    return "file-open";
	case KOF_CAP_MEMFD:        return "memfd";
	case KOF_CAP_EXEC_IMAGE:   return "exec-image";
	case KOF_CAP_SPAWN:        return "spawn";
	case KOF_CAP_THREAD:       return "thread";
	case KOF_CAP_NET_RAW:      return "net-raw";
	case KOF_CAP_SLEEP:        return "sleep";
	case KOF_CAP_PTRACE:       return "ptrace";
	case KOF_CAP_PROC_MEM:     return "proc-mem";
	case KOF_CAP_PROC_EXEC:    return "proc-exec";
	case KOF_CAP_RESOLVE:      return "lib-resolve";
	case KOF_CAP_LIB_OPEN:     return "lib-open";
	case KOF_CAP_DNS:          return "dns";
	case KOF_CAP_REG_SET:      return "reg-set";
	case KOF_CAP_CRED_SET:     return "cred-set";
	case KOF_CAP_HOOK:         return "hook";
	case KOF_CAP_LIST_HIDE:    return "list-hide";
	case KOF_CAP_PROT_OFF:     return "prot-off";
	case KOF_CAP_NET_ADDR:     return "net-addr";
	case KOF_CAP_SELF_HIDE:    return "self-hide";
	case KOF_CAP_BACKGROUND:   return "run-background";
	default:                   return "?";
	}
}

/* The syscall tables, one per ABI. Only the numbers the vocabulary names. */

/*
 * AArch64 and anything else on asm-generic. VERIFIED against
 * /usr/include/asm-generic/unistd.h; mmap is __NR3264_mmap, which is 222.
 */
const struct sysrow kof_sys_a64[] = {
	{   56, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{   63, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{   64, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 101, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 117, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 198, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 200, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 201, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 202, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 203, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 206, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 207, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 220, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 221, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 222, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },        /* mmap - prot decides, see fixed_prot */
	{ 226, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },        /* mprotect - same */
	{ 279, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
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
	{     2, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     4, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   11, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{   26, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 120, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 125, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 162, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 190, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "vfork"  },
	{ 192, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap2"  },
	{ 281, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 282, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 283, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 284, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 285, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 289, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 290, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 291, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 292, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 322, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 385, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
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
	{ 4002, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{ 4003, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{ 4004, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 4005, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{ 4011, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 4026, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 4090, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 4120, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 4125, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 4166, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 4168, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 4169, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 4170, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 4174, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 4175, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 4176, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 4178, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 4180, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 4183, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 4288, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 4354, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  }
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
	{ 326, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 327, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 328, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 329, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 330, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 334, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "send"  },
	{ 335, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 336, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recv"  },
	{ 337, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  }
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
	{     1, KOF_CAP_NONE, KOF_FLOW_ROLE_NONE, "exit"  },
	{     2, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{     3, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{     4, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{     5, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{   26, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{   59, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{   71, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{   74, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 206, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 207, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 232, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 233, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 234, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 235, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 240, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 284, KOF_CAP_THREAD, KOF_FLOW_ROLE_NONE, "clone"  }
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
	{ 5000, KOF_CAP_READ, KOF_FLOW_ROLE_NONE, "read"  },
	{ 5001, KOF_CAP_WRITE, KOF_FLOW_ROLE_NONE, "write"  },
	{ 5002, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "open"  },
	{ 5247, KOF_CAP_FILE_OPEN, KOF_FLOW_ROLE_NONE, "openat"  },
	{ 5009, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mmap"  },
	{ 5010, KOF_CAP_ALLOC, KOF_FLOW_ROLE_MMAP, "mprotect"  },
	{ 5055, KOF_CAP_SPAWN, KOF_FLOW_ROLE_CLONE, "clone"  },
	{ 5056, KOF_CAP_SPAWN, KOF_FLOW_ROLE_NONE, "fork"  },
	{ 5057, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execve"  },
	{ 5316, KOF_CAP_EXEC_IMAGE, KOF_FLOW_ROLE_NONE, "execveat"  },
	{ 5040, KOF_CAP_NET_OPEN, KOF_FLOW_ROLE_SOCK, "socket"  },
	{ 5041, KOF_CAP_NET_CONNECT, KOF_FLOW_ROLE_NONE, "connect"  },
	{ 5042, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept"  },
	{ 5293, KOF_CAP_NET_ACCEPT, KOF_FLOW_ROLE_NONE, "accept4"  },
	{ 5048, KOF_CAP_NET_BIND, KOF_FLOW_ROLE_NONE, "bind"  },
	{ 5049, KOF_CAP_NET_LISTEN, KOF_FLOW_ROLE_NONE, "listen"  },
	{ 5043, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendto"  },
	{ 5044, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvfrom"  },
	{ 5045, KOF_CAP_NET_WRITE, KOF_FLOW_ROLE_NONE, "sendmsg"  },
	{ 5046, KOF_CAP_NET_READ, KOF_FLOW_ROLE_NONE, "recvmsg"  },
	{ 5034, KOF_CAP_SLEEP, KOF_FLOW_ROLE_NONE, "nanosleep"  },
	{ 5099, KOF_CAP_PTRACE, KOF_FLOW_ROLE_NONE, "ptrace"  },
	{ 5314, KOF_CAP_MEMFD, KOF_FLOW_ROLE_NONE, "memfd_create"  },
	{ 5085, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlink"  },
	{ 5253, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "unlinkat"  },
	{ 5080, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "rename"  },
	{ 5254, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat"  },
	{ 5311, KOF_CAP_FILE_DELETE, KOF_FLOW_ROLE_NONE, "renameat2"  },
	{ 5088, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "chmod"  },
	{ 5089, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmod"  },
	{ 5258, KOF_CAP_PERM_SET, KOF_FLOW_ROLE_NONE, "fchmodat"  },
	{ 5103, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setuid"  },
	{ 5104, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setgid"  },
	{ 5111, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setreuid"  },
	{ 5115, KOF_CAP_CRED_SET, KOF_FLOW_ROLE_NONE, "setresuid"  },
	{ 5304, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_readv"  },
	{ 5305, KOF_CAP_PROC_MEM, KOF_FLOW_ROLE_NONE, "process_vm_writev"  },
	{ 5168, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "init_module"  },
	{ 5169, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "delete_module"  },
	{ 5307, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "finit_module"  },
	{ 5315, KOF_CAP_MOD_LOAD, KOF_FLOW_ROLE_NONE, "bpf"  },
	{ 5156, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "chroot"  },
	{ 5151, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "pivot_root"  },
	{ 5303, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "setns"  },
	{ 5262, KOF_CAP_JAIL, KOF_FLOW_ROLE_NONE, "unshare"  },
	{ 5032, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup2"  },
	{ 5286, KOF_CAP_FD_REDIR, KOF_FLOW_ROLE_NONE, "dup3"  },
	{ 5130, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utime"  },
	{ 5226, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimes"  },
	{ 5251, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "futimesat"  },
	{ 5275, KOF_CAP_TIMESTOMP, KOF_FLOW_ROLE_NONE, "utimensat"  }
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

const char *kof_flow_arg_name(uint16_t name, uint8_t cap, uint32_t idx,
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
	FXN(sys_arm),  NULL, 0, 0, 7, 0, 0, 7, 2
};
static const struct fxabi FX_A64 = {
	FXN(sys_a64),  NULL, 0, 0, 8, 0, 0, 8, 2
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
