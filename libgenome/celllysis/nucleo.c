/* See nucleo.h. The name half: what an imported name means, what a capability is called. */

#include "nucleo_private.h"

#include <string.h>

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
 * enum kgenome_nucleo_cap.
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
	 * enum kgenome_nucleo_cap. Each entry point here exists to do ONE thing;
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
 * A NAMED CALL, REFINED BY THE ARGUMENTS IT WAS MADE WITH - the same job
 * kgenome_nucleo_cap_of_syscall does for a system call, for code that reached an API
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
uint16_t kgenome_nucleo_cap_of_call(const char *name, const uint64_t *arg,
			      uint8_t *flags)
{
	uint16_t cap = kgenome_nucleo_cap_of_name(name);

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
				*flags = KGENOME_NUCLEO_F_WX;
			return KGENOME_NUCLEO_ALLOC_EXEC;
		}
		return cap;
	}
	if (cap == KGENOME_NUCLEO_NET_OPEN &&
	    (!strcmp(name, "socket") || !strcmp(name, "WSASocketA") ||
	     !strcmp(name, "WSASocketW")))
		return kgenome_nucleo_sock_kind(arg, flags);
	return cap;
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

uint16_t kgenome_nucleo_cap_of_name(const char *sym)
{
	long i = names_find(sym);

	return i < 0 ? KGENOME_NUCLEO_NONE : names[i].cap;
}

int kgenome_nucleo_cap_named(uint16_t cap)
{
	size_t i;

	if (cap == KGENOME_NUCLEO_NONE)
		return 0;
	for (i = 0; i < sizeof names / sizeof names[0]; i++)
		if (names[i].cap == cap || kgenome_nucleo_cap_generic(names[i].cap) == cap)
			return 1;
	return 0;
}

uint16_t kgenome_nucleo_name_id(const char *sym)
{
	long i = names_find(sym);

	return i < 0 ? 0 : (uint16_t)(i + 1);
}

const char *kgenome_nucleo_name_of(uint16_t id)
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
uint16_t kgenome_nucleo_cap_generic(uint16_t cap)
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

const char *kgenome_nucleo_cap_name(uint16_t cap)
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
unsigned kgenome_nucleo_name_arg(uint16_t cap, unsigned *arg)
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
int kgenome_nucleo_hands_on(uint16_t cap, const char *nm)
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

/*
 * The names whose success value is zero. Short and explicit rather than
 * derived: "returns 0 on success" is a per-call fact in the manual page, and
 * a rule that tried to infer it from the capability would get `socket` and
 * `bind` wrong in opposite directions.
 *
 * `execve` is deliberately absent: on success it does not return at all, so
 * there is no value to claim.
 */
int kgenome_nucleo_sys_zero_on_success(const char *name)
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
