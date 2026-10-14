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
/* WHICH ARGUMENT OF A NAMED CALL REFINES ITS CAPABILITY, by the table's own row - see
 * kgenome_nucleo_cap_of_call. It was three spellings of the same names in a second
 * function (strcmp against "VirtualAlloc", "VirtualProtect", "socket", "WSASocketA/W"),
 * so a name added here had to be added there too; one row now says both. */
enum { REFINE_NONE = 0, REFINE_PROT_ARG3, REFINE_PROT_ARG2, REFINE_SOCK };

static const struct { const char *name; uint16_t cap; uint8_t refine; }
names[] = {
	/* POSIX */
	{ .name = "mmap", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "mmap64", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "mprotect", .cap = KGENOME_NUCLEO_ALLOC },
	/* Not a finding on its own - see KGENOME_NUCLEO_HEAP - and here so that a
	 * buffer two transfers share has a name. posix_memalign is left
	 * out: it hands the pointer back THROUGH one, and nothing here
	 * carries an output argument, so the step would make something
	 * nothing could hold. */
	{ .name = "malloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "calloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "realloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "reallocarray", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "aligned_alloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "memalign", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "_Znwm", .cap = KGENOME_NUCLEO_HEAP },  /* new    */
	{ .name = "_Znam", .cap = KGENOME_NUCLEO_HEAP },  /* new[]  */
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = REFINE_SOCK },
	{ .name = "socketpair", .cap = KGENOME_NUCLEO_NET_OPEN },
	/* Not a finding on its own - see KGENOME_NUCLEO_PIPE_OPEN - and here so
	 * the step has a name and so a dynamically linked object calling
	 * pipe@plt reaches the same word as a static one. */
	{ .name = "pipe", .cap = KGENOME_NUCLEO_PIPE_OPEN },
	{ .name = "pipe2", .cap = KGENOME_NUCLEO_PIPE_OPEN },
	{ .name = "connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "accept4", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "recvfrom", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "recvmsg", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "read", .cap = KGENOME_NUCLEO_MEM_READ },
	{ .name = "send", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "sendto", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "sendmsg", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "write", .cap = KGENOME_NUCLEO_MEM_WRITE },
	{ .name = "open", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "open64", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "openat", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fopen", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "memfd_create", .cap = KGENOME_NUCLEO_MEMFD },
	{ .name = "execve", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execv", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execlp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execvp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "vfork", .cap = KGENOME_NUCLEO_SPAWN },
	/* The libc wrapper, whose flags are its THIRD argument rather than its
	 * first - a different convention from the syscall, and past what is
	 * refined here. It stays the weaker claim. */
	{ .name = "clone", .cap = KGENOME_NUCLEO_SPAWN },
	/* No flags to read and no ambiguity: the name IS the claim. */
	{ .name = "pthread_create", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "daemon", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "sleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "usleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "nanosleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "ptrace", .cap = KGENOME_NUCLEO_PTRACE },
	/* Windows, for the same words */
	{ .name = "VirtualAlloc", .cap = KGENOME_NUCLEO_ALLOC, .refine = REFINE_PROT_ARG3 },
	{ .name = "VirtualAllocEx", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "VirtualProtect", .cap = KGENOME_NUCLEO_ALLOC, .refine = REFINE_PROT_ARG2 },
	{ .name = "HeapAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "HeapReAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "RtlAllocateHeap", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "LocalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "GlobalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "CoTaskMemAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "WSASocketA", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = REFINE_SOCK },
	{ .name = "WSASocketW", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = REFINE_SOCK },
	{ .name = "InternetOpenA", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "InternetOpenW", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "WSAConnect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "InternetConnectA", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "InternetConnectW", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "CreateFileA", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "CreateFileW", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "WriteFile", .cap = KGENOME_NUCLEO_MEM_WRITE },
	{ .name = "ReadFile", .cap = KGENOME_NUCLEO_MEM_READ },
	{ .name = "CreateProcessA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "WinExec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateThread", .cap = KGENOME_NUCLEO_THREAD },
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
	{ .name = "WSARecv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "WSASend", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "WSAAccept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "closesocket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "InternetOpenUrlA", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "InternetOpenUrlW", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "InternetReadFile", .cap = KGENOME_NUCLEO_HTTP_RECV },
	{ .name = "HttpSendRequestA", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "HttpSendRequestW", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "HttpOpenRequestA", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "HttpOpenRequestW", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "URLDownloadToFileA", .cap = KGENOME_NUCLEO_HTTP_FETCH },
	{ .name = "URLDownloadToFileW", .cap = KGENOME_NUCLEO_HTTP_FETCH },
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
	{ .name = "CreatePipe", .cap = KGENOME_NUCLEO_PIPE_OPEN },
	{ .name = "SetStdHandle", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "DuplicateHandle", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "WinHttpOpen", .cap = KGENOME_NUCLEO_HTTP_OPEN },
	{ .name = "WinHttpConnect", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "WinHttpOpenRequest", .cap = KGENOME_NUCLEO_HTTP_CONNECT },
	{ .name = "WinHttpSendRequest", .cap = KGENOME_NUCLEO_HTTP_SEND },
	{ .name = "WinHttpReadData", .cap = KGENOME_NUCLEO_HTTP_RECV },
	/* A mapping is a mapping, whichever name asks for it. */
	{ .name = "VirtualProtectEx", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "NtAllocateVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "NtProtectVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "ZwAllocateVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "ZwProtectVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "CreateFileMappingA", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "CreateFileMappingW", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "MapViewOfFile", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "MapViewOfFileEx", .cap = KGENOME_NUCLEO_ALLOC },
	/* The handle, the memory and the execution - see the note on the
	 * three capabilities in kofmod/kofcap.h. */
	{ .name = "OpenProcess", .cap = KGENOME_NUCLEO_PTRACE },
	{ .name = "DebugActiveProcess", .cap = KGENOME_NUCLEO_PTRACE },
	/* A thread handle is the same kind of hold on another execution
	 * context, and it is what SetThreadContext and ResumeThread are
	 * handed - they were modelled and the handle they take was not. */
	{ .name = "OpenThread", .cap = KGENOME_NUCLEO_PTRACE },
	{ .name = "WriteProcessMemory", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "ReadProcessMemory", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "NtWriteVirtualMemory", .cap = KGENOME_NUCLEO_PROC_MEM },
	/* Reading another thread's registers, and emptying another image
	 * out of its address space: the two legs of hollowing whose other
	 * halves - SetThreadContext and WriteProcessMemory - were already
	 * here. */
	{ .name = "GetThreadContext", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "NtUnmapViewOfSection", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "ZwUnmapViewOfSection", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "CreateRemoteThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "CreateRemoteThreadEx", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "NtQueueApcThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "QueueUserAPC", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "SetThreadContext", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "NtResumeThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "SuspendThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "NtSuspendThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "ResumeThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	/* The loader pair, which is what a program has INSTEAD of an import
	 * table entry - see KGENOME_NUCLEO_RESOLVE. */
	{ .name = "LoadLibraryA", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "LoadLibraryW", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "LoadLibraryExA", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "LoadLibraryExW", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "GetProcAddress", .cap = KGENOME_NUCLEO_RESOLVE },
	{ .name = "LdrLoadDll", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "LdrGetProcedureAddress", .cap = KGENOME_NUCLEO_RESOLVE },
	{ .name = "dlopen", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "dlsym", .cap = KGENOME_NUCLEO_RESOLVE },
	/* Writes only; a program reading its own configuration is every
	 * program - see KGENOME_NUCLEO_REG_SET. */
	/* And where the handle they are given comes from - see
	 * KGENOME_NUCLEO_REG_OPEN. Not a finding; the head of a link. */
	/* Windows' spelling of rename - the word already existed for the
	 * POSIX one, see KGENOME_NUCLEO_FILE_RENAME, and only the name was
	 * missing. 16 of the 128 measured PE import MoveFileW. */
	{ .name = "MoveFileA", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "MoveFileW", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "MoveFileExA", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "MoveFileExW", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "MoveFileWithProgressW", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "RegOpenKeyExA", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "RegOpenKeyExW", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "RegOpenKeyA", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "RegOpenKeyW", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "NtOpenKey", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "NtOpenKeyEx", .cap = KGENOME_NUCLEO_REG_OPEN },
	{ .name = "RegSetValueExA", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegSetValueExW", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegCreateKeyExA", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegCreateKeyExW", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegDeleteValueA", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegDeleteValueW", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "NtSetValueKey", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "Sleep", .cap = KGENOME_NUCLEO_SLEEP },

	/*
	 * THE ROWS THE RANKING CHOSE. Measured over the whole corpus here -
	 * 1772 ELF malware objects against 20347 Linux binaries - and kept
	 * because of what the numbers said, not because they sounded right.
	 * See KGENOME_NUCLEO_NET_ADDR for the rates and for what the ranking
	 * rejected.
	 */
	{ .name = "htons", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "htonl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohs", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_addr", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_aton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_pton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_ntoa", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_network", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "getaddrinfo", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "prctl", .cap = KGENOME_NUCLEO_SELF_HIDE },
	{ .name = "setsid", .cap = KGENOME_NUCLEO_BACKGROUND },

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
	{ .name = "prepare_creds", .cap = KGENOME_NUCLEO_CRED_PREPARE },
	{ .name = "prepare_kernel_cred", .cap = KGENOME_NUCLEO_CRED_PREPARE },
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
	{ .name = "__kmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__kmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc_trace", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kvmalloc_node", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kvmalloc_node_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "krealloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "krealloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmem_cache_alloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmem_cache_alloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "vmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "vmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__vmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__vmalloc_node_range", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "commit_creds", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "set_current_groups", .cap = KGENOME_NUCLEO_CRED_SET },
	/*
	 * A KPROBE PUT ON AND A KPROBE TAKEN OFF - two words, and neither of
	 * them is "hook". See KGENOME_NUCLEO_KPROBE_REG for why this row has now
	 * been wrong twice. The pair is the IDIOM: put a probe on a name,
	 * read kp.addr, take the probe away again, all in one function - and
	 * an idiom made of two calls needs two words to be written down.
	 * Measured at 0 of 900 clean modules on each side.
	 */
	{ .name = "register_kprobe", .cap = KGENOME_NUCLEO_KPROBE_REG },
	{ .name = "register_kprobes", .cap = KGENOME_NUCLEO_KPROBE_REG },
	{ .name = "unregister_kprobe", .cap = KGENOME_NUCLEO_KPROBE_UNREG },
	{ .name = "unregister_kprobes", .cap = KGENOME_NUCLEO_KPROBE_UNREG },
	/* A RETURN probe cannot read an address and leave; it exists to run
	 * code on somebody else's return, so it stays hooking. */
	{ .name = "register_kretprobe", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "unregister_kretprobe", .cap = KGENOME_NUCLEO_HOOK },
	/* Code of one's own put in the path of somebody else's. */
	{ .name = "unregister_ftrace_function", .cap = KGENOME_NUCLEO_HOOK },
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
	/* { .name = "write_cr0", .cap = KGENOME_NUCLEO_PROT_OFF }, */
	/* { .name = "write_cr4", .cap = KGENOME_NUCLEO_PROT_OFF }, */
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
	{ .name = "peb_ldr", .cap = KGENOME_NUCLEO_SELF_RESOLVE },
	{ .name = "name_hash", .cap = KGENOME_NUCLEO_NAME_HASH },
	/* off with the other two - see the note above them */
	/* { .name = "mov_cr0", .cap = KGENOME_NUCLEO_PROT_OFF }, */
	{ .name = "register_ftrace_function", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "ftrace_set_filter_ip", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "register_ftrace_direct", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "text_poke", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "text_poke_kgdb", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "set_memory_rw", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "set_memory_x", .cap = KGENOME_NUCLEO_HOOK },
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
	{ .name = "__list_del_entry", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_del_entry_valid", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_del_entry_valid_or_report", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_add_valid", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_add_valid_or_report", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "list_del", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "list_add", .cap = KGENOME_NUCLEO_LIST_HIDE },
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
	{ .name = "__x86_indirect_thunk_rax", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rbx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rcx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rdx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rsi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rdi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rbp", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r8", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r9", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r10", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r11", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r12", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r13", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r14", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r15", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_eax", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ebx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ecx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_edx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_esi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_edi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ebp", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "kallsyms_lookup_name", .cap = KGENOME_NUCLEO_KSYM_LOOKUP },
	{ .name = "kallsyms_lookup_name_t", .cap = KGENOME_NUCLEO_KSYM_LOOKUP },
	{ .name = "__symbol_get", .cap = KGENOME_NUCLEO_SYMBOL_GET },
	/* ACROSS THE USER/KERNEL BOUNDARY, which is not a file - see
	 * KGENOME_NUCLEO_COPY_FROM_USER. The rows under this one take a struct file
	 * and really are file I/O. */
	{ .name = "_copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "__copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "_copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "__copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "kernel_read", .cap = KGENOME_NUCLEO_READ },
	{ .name = "kernel_write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "vfs_read", .cap = KGENOME_NUCLEO_READ },
	{ .name = "vfs_write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "filp_open", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "filp_close", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "call_usermodehelper", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "call_usermodehelper_exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "kthread_create_on_node", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "kthread_run", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "wake_up_process", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "sock_create", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "sock_create_kern", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "kernel_connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "kernel_accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "kernel_sendmsg", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "kernel_recvmsg", .cap = KGENOME_NUCLEO_NET_READ },
	/*
	 * AND THE WINDOWS KERNEL, which reaches this table the way every other
	 * PE import does - the mechanism needs nothing new, only the words.
	 */
	{ .name = "ZwCreateFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "ZwOpenFile", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "ZwReadFile", .cap = KGENOME_NUCLEO_MEM_READ },
	{ .name = "ZwWriteFile", .cap = KGENOME_NUCLEO_MEM_WRITE },
	{ .name = "MmGetSystemRoutineAddress", .cap = KGENOME_NUCLEO_RESOLVE },
	{ .name = "MmMapLockedPagesSpecifyCache", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "MmMapLockedPages", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "PsLookupProcessByProcessId", .cap = KGENOME_NUCLEO_PTRACE },
	{ .name = "PsSetCreateProcessNotifyRoutine", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "PsSetCreateProcessNotifyRoutineEx", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "PsSetLoadImageNotifyRoutine", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "ObRegisterCallbacks", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "PsCreateSystemThread", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "ZwTerminateProcess", .cap = KGENOME_NUCLEO_PROC_EXEC },
	/*
	 * ===== THE WORDS ADDED WITH THE NINE CAPABILITIES AT THE END OF
	 * enum kgenome_nucleo_cap. Each entry point here exists to do ONE thing;
	 * that is the bar, and the names that did not clear it are listed in
	 * kofcap.h beside the capabilities rather than here.
	 */
	/* Encryption. Windows has two generations of the same API and both are
	 * still shipped, so both are here. */
	{ .name = "CryptEncrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptDecrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptAcquireContextA", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptAcquireContextW", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptGenKey", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptDeriveKey", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "CryptImportKey", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "BCryptEncrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "BCryptDecrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "BCryptGenerateSymmetricKey", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "BCryptImportKeyPair", .cap = KGENOME_NUCLEO_CRYPTO },
	/* And the Linux side, which is OpenSSL in practice. The EVP names are
	 * the ones a program links; the AES_ ones are the older direct calls
	 * that statically linked malware still carries. */
	{ .name = "EVP_EncryptInit_ex", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "EVP_EncryptUpdate", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "EVP_DecryptInit_ex", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "EVP_DecryptUpdate", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "EVP_CipherInit_ex", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "AES_set_encrypt_key", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "AES_cbc_encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "AES_encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "RSA_public_encrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "RSA_private_decrypt", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "crypto_secretbox_easy", .cap = KGENOME_NUCLEO_CRYPTO },
	/* Taking what the user is doing. */
	{ .name = "SetWindowsHookExA", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "SetWindowsHookExW", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "GetAsyncKeyState", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "GetKeyboardState", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "GetRawInputData", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "RegisterRawInputDevices", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "GetClipboardData", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "SetClipboardData", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "XQueryKeymap", .cap = KGENOME_NUCLEO_CAPTURE },
	{ .name = "XGrabKeyboard", .cap = KGENOME_NUCLEO_CAPTURE },
	/* Installing itself as a service. */
	{ .name = "OpenSCManagerA", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "OpenSCManagerW", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "CreateServiceA", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "CreateServiceW", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "StartServiceA", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "StartServiceW", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "ChangeServiceConfigA", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	{ .name = "ChangeServiceConfigW", .cap = KGENOME_NUCLEO_SVC_INSTALL },
	/* Code into the kernel. */
	{ .name = "init_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "finit_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "delete_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_load_program", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_prog_load", .cap = KGENOME_NUCLEO_MOD_LOAD },
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
	{ .name = "bpf_object__load", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_object__load_skeleton", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_object__attach_skeleton", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_kprobe", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_uprobe", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_tracepoint", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_xdp", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_prog_attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_set_link_xdp_fd", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_tc_attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "NtLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "ZwLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD },
	/* A named pipe, and only a named one. */
	{ .name = "CreateNamedPipeA", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CreateNamedPipeW", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "ConnectNamedPipe", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CallNamedPipeA", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CallNamedPipeW", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "mkfifo", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "mkfifoat", .cap = KGENOME_NUCLEO_PIPE },
	/* Removing a file. */
	{ .name = "DeleteFileA", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "DeleteFileW", .cap = KGENOME_NUCLEO_FILE_DELETE },
	/* MoveFileEx* used to be here as a DELETE. When KGENOME_NUCLEO_FILE_RENAME
	 * was split out of KGENOME_NUCLEO_FILE_DELETE the POSIX `rename` moved and
	 * these two did not, so the page went on saying `file-delete` with
	 * MoveFileExW beside it - the exact contradiction that split was
	 * made to end. They are with the other MoveFile rows now. */
	{ .name = "unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "unlinkat", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "remove", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "renameat", .cap = KGENOME_NUCLEO_FILE_RENAME },
	/* Making a dropped file runnable. */
	{ .name = "chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fchmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fchmodat", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "SetFileAttributesA", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "SetFileAttributesW", .cap = KGENOME_NUCLEO_PERM_SET },
	/* Asking whether it is watched. */
	{ .name = "IsDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	{ .name = "CheckRemoteDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	{ .name = "NtSetInformationThread", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	/* Moving the boundary of what it can see. */
	{ .name = "chroot", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "pivot_root", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "setns", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "unshare", .cap = KGENOME_NUCLEO_JAIL },
	/*
	 * AND WORDS FOR CAPABILITIES THAT ALREADY EXISTED, where only the
	 * spelling was missing. Changing one's own privileges is CRED_SET
	 * whether a kernel module calls commit_creds or a program calls
	 * setuid; reaching into another process is PROC_MEM whether it is
	 * WriteProcessMemory or process_vm_writev.
	 */
	{ .name = "setuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setgid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "seteuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setreuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setresuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "AdjustTokenPrivileges", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "OpenProcessToken", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "DuplicateTokenEx", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "ImpersonateLoggedOnUser", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "SetThreadToken", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "process_vm_readv", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "process_vm_writev", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "posix_spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessAsUserA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessAsUserW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessWithTokenW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessWithLogonW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteExA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteExW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/* The three measured ones. */
	{ .name = "dup2", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "dup3", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "utime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "utimes", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "utimensat", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "futimens", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "SetFileTime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "CreateToolhelp32Snapshot", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Process32First", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Process32FirstW", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Process32Next", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Process32NextW", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Module32First", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Module32Next", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Thread32First", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "Thread32Next", .cap = KGENOME_NUCLEO_PROC_LIST },
	{ .name = "EnumProcesses", .cap = KGENOME_NUCLEO_PROC_LIST },
	/*
	 * AND THE GAPS THE SAME MEASUREMENT FOUND IN WORDS THAT ALREADY
	 * EXISTED - each one a spelling nobody had written down.
	 */
	{ .name = "BCryptOpenAlgorithmProvider", .cap = KGENOME_NUCLEO_CRYPTO },
	{ .name = "RegDeleteKeyA", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegDeleteKeyW", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegDeleteKeyExA", .cap = KGENOME_NUCLEO_REG_SET },
	{ .name = "RegDeleteKeyExW", .cap = KGENOME_NUCLEO_REG_SET },
	/* An allocation, and incidentally one that fails in some sandboxes -
	 * which is why a loader picks it. The capability is the allocation. */
	{ .name = "VirtualAllocExNuma", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "NtQueryInformationProcess", .cap = KGENOME_NUCLEO_ANTI_DEBUG }
};

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
	long row = names_find(name);
	uint16_t cap = row < 0 ? KGENOME_NUCLEO_NONE : names[row].cap;

	if (flags)
		*flags = 0;
	if (!arg || cap == KGENOME_NUCLEO_NONE)
		return cap;
	if (cap == KGENOME_NUCLEO_ALLOC) {
		uint64_t prot = 0;
		int have = 0;

		if (names[row].refine == REFINE_PROT_ARG3) {
			prot = arg[3];
			have = 1;
		} else if (names[row].refine == REFINE_PROT_ARG2) {
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
	if (cap == KGENOME_NUCLEO_NET_OPEN && names[row].refine == REFINE_SOCK)
		return kgenome_nucleo_sock_kind(arg, flags);
	return cap;
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
 * only one.
 *
 * `nm` IS NOT A NAME THE FILE CHOSE. A caller passes either the label of the syscall
 * NUMBER it decoded (kgenome_nucleo_sys_name: the kernel's own table, so a renamed or
 * stripped binary gives the same word) or an IMPORT name the loader resolves (the one
 * OS-defined spelling: change it and the program no longer links). A symbol name taken
 * from a program's own .symtab never reaches here - see kgenome_diag_sym's sites,
 * which come from undefined symbols only. Test: names_structural. */
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
 * The names whose success value is zero - the labels of the kernel's own syscall table
 * and the OS-defined import names, with the same provenance as kgenome_nucleo_hands_on's
 * `nm` (never a name the file spelled for itself). Short and explicit rather than
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
