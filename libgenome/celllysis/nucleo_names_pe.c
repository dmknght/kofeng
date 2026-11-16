/*
 * nucleo_names_pe.c - what an imported name means in a PE object: the Win32 and native API, and Winsock (whose names are lowercase and are Windows API all the same).
 *
 * One table of imported (or called) NAMES per target, each in the same capability vocabulary: what a program IS asked to do
 * is the one thing a rule can share between targets, and which API spells it is not. Looked up through
 * kgenome_nucleo_cap_of_name and its siblings (nucleo.c), which are told the target.
 */

#include "nucleo_private.h"

/*
 * EVERY SHAPE BELOW WAS CHECKED AGAINST THE API'S PAGE (2026-11-15): the parameter list of the Win32 or WDK reference on
 * learn.microsoft.com (OpenSSL: its manual and include/openssl/aes.h), transcribed by page and compared index by index. An A/W pair was
 * checked on one page: the reference documents the pair as one function. A row whose page could not be found keeps its capability and no
 * shape of its own (its capability's answer, which is what it had); each such row says TODO(verify) and why.
 */
static const struct kgenome_nucleo_namerow rows[] = {
	/* winsock2.h. connect's/bind's second argument is the address the call is handed (SOURCE: memory read). */
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "connect", .cap = KGENOME_NUCLEO_NET_CONNECT, KGENOME_SHAPE("fd0 src1 res=status0") },
	{ .name = "accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "bind", .cap = KGENOME_NUCLEO_NET_BIND, KGENOME_SHAPE("fd0 src1 res=status0") },
	{ .name = "listen", .cap = KGENOME_NUCLEO_NET_LISTEN, KGENOME_SHAPE("fd0 res=status0") },
	{ .name = "recv", .cap = KGENOME_NUCLEO_NET_READ, KGENOME_SHAPE("fd0 buf1 res=value") },
	{ .name = "recvfrom", .cap = KGENOME_NUCLEO_NET_READ, KGENOME_SHAPE("fd0 buf1 res=value") },
	{ .name = "send", .cap = KGENOME_NUCLEO_NET_WRITE, KGENOME_SHAPE("fd0 src1 res=value") },
	{ .name = "sendto", .cap = KGENOME_NUCLEO_NET_WRITE, KGENOME_SHAPE("fd0 src1 res=value") },
	/* Windows, for the same words */
	{ .name = "VirtualAlloc", .cap = KGENOME_NUCLEO_ALLOC, .refine = KGENOME_NUCLEO_REFINE_PROT_ARG3 },
	/*
	 * TODO(limit): VirtualAllocEx's and VirtualAllocExNuma's protection is argument 4, and a named call carries its first four
	 * (kgenome_diag_apicall.arg[4], diag_scan.h), so an executable remote allocation stays mem-alloc. The next step is a wider
	 * carried argument array; the static PE route reads no argument at all.
	 */
	{ .name = "VirtualAllocEx", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 res=pointer") },
	/* VirtualProtect returns a BOOL: the region is its first argument (it was handed on as the object, D2). */
	{ .name = "VirtualProtect", .cap = KGENOME_NUCLEO_ALLOC, .refine = KGENOME_NUCLEO_REFINE_PROT_ARG2, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "HeapAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "HeapReAlloc", .cap = KGENOME_NUCLEO_HEAP, KGENOME_SHAPE("fd2 res=pointer") },
	{ .name = "RtlAllocateHeap", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "LocalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "GlobalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "CoTaskMemAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "WSASocketA", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "WSASocketW", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "InternetOpenA", .cap = KGENOME_NUCLEO_HTTP_OPEN, KGENOME_SHAPE("val0 res=handle") },
	{ .name = "InternetOpenW", .cap = KGENOME_NUCLEO_HTTP_OPEN, KGENOME_SHAPE("val0 res=handle") },
	{ .name = "WSAConnect", .cap = KGENOME_NUCLEO_NET_CONNECT, KGENOME_SHAPE("fd0 src1 res=status0") },
	{ .name = "InternetConnectA", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path1 val2 res=handle") },
	{ .name = "InternetConnectW", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path1 val2 res=handle") },
	{ .name = "CreateFileA", .cap = KGENOME_NUCLEO_FILE_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "CreateFileW", .cap = KGENOME_NUCLEO_FILE_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "WriteFile", .cap = KGENOME_NUCLEO_MEM_WRITE },
	{ .name = "ReadFile", .cap = KGENOME_NUCLEO_MEM_READ },
	/*
	 * TODO(owner) Q2 - how an exec's inputs are worded. Default (this table): PATH is the image named (lpApplicationName, ShellExecute's
	 * lpFile), VALUE is the command line (lpCommandLine, WinExec's lpCmdLine, ShellExecute's lpParameters). Alternative: the command
	 * line is PATH in every spelling (WinExec as before) and lpApplicationName gets no role. No shipped diagnose names a role, so
	 * neither choice moves a shipped verdict; a diagnose that means "what ran" names PATH or VALUE under the default.
	 */
	{ .name = "CreateProcessA", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path0 val1 out9 res=status") },
	{ .name = "CreateProcessW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path0 val1 out9 res=status") },
	{ .name = "WinExec", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("val0 res=value") },
	{ .name = "ShellExecuteA", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path2 val3 res=value") },
	{ .name = "ShellExecuteW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path2 val3 res=value") },
	{ .name = "CreateThread", .cap = KGENOME_NUCLEO_THREAD, KGENOME_SHAPE("tgt2 val3 entry2 res=handle") },
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
	 * above already carry; what is listed here is only what it adds. The buffer of WSARecv/WSASend is WSABUF.buf, a field of
	 * the array argument 1 points at; the completion routine (argument 6) is code the system calls. */
	{ .name = "WSARecv", .cap = KGENOME_NUCLEO_NET_READ, KGENOME_SHAPE("fd0 buf1 field1 tgt6 entry6 res=status0") },
	{ .name = "WSASend", .cap = KGENOME_NUCLEO_NET_WRITE, KGENOME_SHAPE("fd0 src1 field1 tgt6 entry6 res=status0") },
	{ .name = "WSAAccept", .cap = KGENOME_NUCLEO_NET_ACCEPT, KGENOME_SHAPE("fd0 tgt3 entry3 res=handle") },
	/* Ends the socket it is handed and returns a status: it was handed on as a new socket (D1). The word stays the socket's - see
	 * TODO(owner) Q1 at VirtualFree. */
	{ .name = "closesocket", .cap = KGENOME_NUCLEO_NET_OPEN, KGENOME_SHAPE("fd0 rel0 res=status0") },
	{ .name = "InternetOpenUrlA", .cap = KGENOME_NUCLEO_HTTP_SEND, KGENOME_SHAPE("fd0 path1 src2 res=handle") },
	{ .name = "InternetOpenUrlW", .cap = KGENOME_NUCLEO_HTTP_SEND, KGENOME_SHAPE("fd0 path1 src2 res=handle") },
	{ .name = "InternetReadFile", .cap = KGENOME_NUCLEO_HTTP_RECV, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "HttpSendRequestA", .cap = KGENOME_NUCLEO_HTTP_SEND, KGENOME_SHAPE("fd0 val1 src3 res=status") },
	{ .name = "HttpSendRequestW", .cap = KGENOME_NUCLEO_HTTP_SEND, KGENOME_SHAPE("fd0 val1 src3 res=status") },
	{ .name = "HttpOpenRequestA", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path2 res=handle") },
	{ .name = "HttpOpenRequestW", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path2 res=handle") },
	/* The page documents URLDownloadToFile with both names; the local file (argument 2) is a second name in one call, and PATH is
	 * the URL's. */
	{ .name = "URLDownloadToFileA", .cap = KGENOME_NUCLEO_HTTP_FETCH, KGENOME_SHAPE("path1 res=status0") },
	{ .name = "URLDownloadToFileW", .cap = KGENOME_NUCLEO_HTTP_FETCH, KGENOME_SHAPE("path1 res=status0") },
	/*
	 * THE WINDOWS SPELLING OF A REDIRECTED SHELL, which the table had
	 * only the POSIX half of.
	 *
	 * `pipe` then `dup2` then `execve` is the shape KGENOME_NUCLEO_PIPE_OPEN
	 * exists for; on Windows it is `CreatePipe` then `SetStdHandle` or
	 * a STARTUPINFO, then `CreateProcess` - and CreateProcess was the
	 * only one of the three in this table. The producer and the
	 * redirect are what make it a sentence rather than three words.
	 *
	 * CreatePipe returns a BOOL and writes the two handles through arguments 0 and 1 (it was handed on as the pipe, D6).
	 * SetStdHandle's handle is argument 1 (0 is STD_*_HANDLE) and DuplicateHandle's source handle is argument 1 (0 is a process).
	 */
	{ .name = "CreatePipe", .cap = KGENOME_NUCLEO_PIPE_OPEN, KGENOME_SHAPE("out0 out1 res=status") },
	{ .name = "SetStdHandle", .cap = KGENOME_NUCLEO_FD_REDIR, KGENOME_SHAPE("fd1 res=status") },
	{ .name = "DuplicateHandle", .cap = KGENOME_NUCLEO_FD_REDIR, KGENOME_SHAPE("fd1 out3 res=status") },
	{ .name = "WinHttpOpen", .cap = KGENOME_NUCLEO_HTTP_OPEN, KGENOME_SHAPE("val0 res=handle") },
	{ .name = "WinHttpConnect", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path1 val2 res=handle") },
	{ .name = "WinHttpOpenRequest", .cap = KGENOME_NUCLEO_HTTP_CONNECT, KGENOME_SHAPE("fd0 path2 res=handle") },
	{ .name = "WinHttpSendRequest", .cap = KGENOME_NUCLEO_HTTP_SEND, KGENOME_SHAPE("fd0 val1 src3 res=status") },
	{ .name = "WinHttpReadData", .cap = KGENOME_NUCLEO_HTTP_RECV, KGENOME_SHAPE("fd0 buf1 res=status") },
	/* A mapping is a mapping, whichever name asks for it. VirtualProtectEx returns a BOOL; its protection is argument 3, which a
	 * named call carries (D5). Its first argument is the process: a second object where FD is the region's, so no role. */
	{ .name = "VirtualProtectEx", .cap = KGENOME_NUCLEO_ALLOC, .refine = KGENOME_NUCLEO_REFINE_PROT_ARG3, KGENOME_SHAPE("fd1 res=status") },
	/* The Zw page names the user-mode spelling Nt: one function. NTSTATUS, the region through argument 1 (D3). TODO(limit): the
	 * protection is argument 5, past the four a named call carries. */
	{ .name = "NtAllocateVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 out1 res=status0") },
	/* TODO(verify): no reference page for Nt/ZwProtectVirtualMemory (both URLs 404, the search finds none). The capability's answer
	 * (the result is handed on as a region) stays until its parameter list is checked; it is the D2 defect for these two names. */
	{ .name = "NtProtectVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "ZwAllocateVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 out1 res=status0") },
	{ .name = "ZwProtectVirtualMemory", .cap = KGENOME_NUCLEO_ALLOC },
	/* A section handle, not memory (D4: the kind; it is handed on either way). */
	{ .name = "CreateFileMappingA", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 path5 res=handle") },
	{ .name = "CreateFileMappingW", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 path5 res=handle") },
	{ .name = "MapViewOfFile", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 res=pointer") },
	{ .name = "MapViewOfFileEx", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 res=pointer") },
	/* The handle, the memory and the execution - see the note on the
	 * three capabilities in kofmod/kofcap.h. */
	{ .name = "OpenProcess", .cap = KGENOME_NUCLEO_PTRACE, KGENOME_SHAPE("val2 res=handle") },
	{ .name = "DebugActiveProcess", .cap = KGENOME_NUCLEO_PTRACE, KGENOME_SHAPE("val0 res=status") },
	/* A thread handle is the same kind of hold on another execution
	 * context, and it is what SetThreadContext and ResumeThread are
	 * handed - they were modelled and the handle they take was not. */
	{ .name = "OpenThread", .cap = KGENOME_NUCLEO_PTRACE, KGENOME_SHAPE("val2 res=handle") },
	{ .name = "WriteProcessMemory", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 buf1 src2 res=status") },
	{ .name = "ReadProcessMemory", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 src1 buf2 res=status") },
	/* TODO(verify): NtWriteVirtualMemory has no reference page; no shape until it is checked. */
	{ .name = "NtWriteVirtualMemory", .cap = KGENOME_NUCLEO_PROC_MEM },
	/* Reading another thread's registers, and emptying another image
	 * out of its address space: the two legs of hollowing whose other
	 * halves - SetThreadContext and WriteProcessMemory - were already
	 * here. */
	{ .name = "GetThreadContext", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 buf1 res=status") },
	/* The Zw page names the Nt spelling: one function. The base (argument 1) is a second object: no role. */
	{ .name = "NtUnmapViewOfSection", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 res=status0") },
	{ .name = "ZwUnmapViewOfSection", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 res=status0") },
	{ .name = "CreateRemoteThread", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 tgt3 val4 entry3 entry=remote res=handle") },
	{ .name = "CreateRemoteThreadEx", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 tgt3 val4 entry3 entry=remote res=handle") },
	/* TODO(verify): NtQueueApcThread, NtResumeThread and NtSuspendThread have no reference page; no shape until checked. */
	{ .name = "NtQueueApcThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "QueueUserAPC", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("tgt0 fd1 val2 entry0 res=value") },
	{ .name = "SetThreadContext", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 src1 res=status") },
	{ .name = "NtResumeThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "SuspendThread", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 res=value") },
	{ .name = "NtSuspendThread", .cap = KGENOME_NUCLEO_PROC_EXEC },
	{ .name = "ResumeThread", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 res=value") },
	/* The loader pair, which is what a program has INSTEAD of an import
	 * table entry - see KGENOME_NUCLEO_RESOLVE. The module handle is what GetProcAddress is handed (FD), the name it looks up its
	 * PATH (the name an object is looked up by), the result the address of code. */
	{ .name = "LoadLibraryA", .cap = KGENOME_NUCLEO_LIB_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "LoadLibraryW", .cap = KGENOME_NUCLEO_LIB_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "LoadLibraryExA", .cap = KGENOME_NUCLEO_LIB_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "LoadLibraryExW", .cap = KGENOME_NUCLEO_LIB_OPEN, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "GetProcAddress", .cap = KGENOME_NUCLEO_RESOLVE, KGENOME_SHAPE("fd0 path1 res=codeptr") },
	/* TODO(verify): LdrLoadDll and LdrGetProcedureAddress have no reference page; no shape until checked. */
	{ .name = "LdrLoadDll", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "LdrGetProcedureAddress", .cap = KGENOME_NUCLEO_RESOLVE },
	/* Writes only; a program reading its own configuration is every
	 * program - see KGENOME_NUCLEO_REG_SET. */
	/* And where the handle they are given comes from - see
	 * KGENOME_NUCLEO_REG_OPEN. Not a finding; the head of a link. The key comes back through a pointer (out). */
	/* Windows' spelling of rename - the word already existed for the
	 * POSIX one, see KGENOME_NUCLEO_FILE_RENAME, and only the name was
	 * missing. 16 of the 128 measured PE import MoveFileW. The new name (argument 1) is a second name in one call: no role. */
	{ .name = "MoveFileA", .cap = KGENOME_NUCLEO_FILE_RENAME, KGENOME_SHAPE("path0 res=status") },
	{ .name = "MoveFileW", .cap = KGENOME_NUCLEO_FILE_RENAME, KGENOME_SHAPE("path0 res=status") },
	{ .name = "MoveFileExA", .cap = KGENOME_NUCLEO_FILE_RENAME, KGENOME_SHAPE("path0 res=status") },
	{ .name = "MoveFileExW", .cap = KGENOME_NUCLEO_FILE_RENAME, KGENOME_SHAPE("path0 res=status") },
	{ .name = "MoveFileWithProgressW", .cap = KGENOME_NUCLEO_FILE_RENAME, KGENOME_SHAPE("path0 tgt2 entry2 res=status") },
	{ .name = "RegOpenKeyExA", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("fd0 path1 out4 res=status0") },
	{ .name = "RegOpenKeyExW", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("fd0 path1 out4 res=status0") },
	{ .name = "RegOpenKeyA", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("fd0 path1 out2 res=status0") },
	{ .name = "RegOpenKeyW", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("fd0 path1 out2 res=status0") },
	/* The Zw pages name the Nt spellings. The key's name is OBJECT_ATTRIBUTES.ObjectName, a field of argument 2. */
	{ .name = "NtOpenKey", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("path2 field2 out0 res=status0") },
	{ .name = "NtOpenKeyEx", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("path2 field2 out0 res=status0") },
	{ .name = "RegSetValueExA", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 src4 res=status0") },
	{ .name = "RegSetValueExW", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 src4 res=status0") },
	/* TODO(limit): the key comes back through argument 7, past the six argument slots the lineage stage reads. */
	{ .name = "RegCreateKeyExA", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 out7 res=status0") },
	{ .name = "RegCreateKeyExW", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 out7 res=status0") },
	{ .name = "RegDeleteValueA", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	{ .name = "RegDeleteValueW", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	{ .name = "NtSetValueKey", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 field1 src4 res=status0") },
	{ .name = "Sleep", .cap = KGENOME_NUCLEO_SLEEP, KGENOME_SHAPE("val0 res=void") },
	{ .name = "htons", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=value") },
	{ .name = "htonl", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=value") },
	{ .name = "ntohs", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=value") },
	{ .name = "ntohl", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=value") },
	{ .name = "inet_addr", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=value") },
	{ .name = "inet_pton", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val1 out2 res=value") },
	{ .name = "inet_ntoa", .cap = KGENOME_NUCLEO_NET_ADDR, KGENOME_SHAPE("val0 res=pointer") },
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS, KGENOME_SHAPE("path0 res=pointer") },
	{ .name = "getaddrinfo", .cap = KGENOME_NUCLEO_DNS, KGENOME_SHAPE("path0 val1 out3 res=status0") },
	/*
	 * AND THE WINDOWS KERNEL, which reaches this table the way every other
	 * PE import does - the mechanism needs nothing new, only the words. The file's name is OBJECT_ATTRIBUTES.ObjectName (argument 2);
	 * the handle comes back through argument 0 and the result is an NTSTATUS (it was handed on as the handle, D3). ZwReadFile's
	 * buffer is argument 5 (1 is the event, D-ARGIDX) and argument 2 is an APC routine the system calls.
	 */
	{ .name = "ZwCreateFile", .cap = KGENOME_NUCLEO_FILE_OPEN, KGENOME_SHAPE("path2 field2 out0 res=status0") },
	{ .name = "ZwOpenFile", .cap = KGENOME_NUCLEO_FILE_OPEN, KGENOME_SHAPE("path2 field2 out0 res=status0") },
	{ .name = "ZwReadFile", .cap = KGENOME_NUCLEO_MEM_READ, KGENOME_SHAPE("fd0 tgt2 buf5 entry2 res=status0") },
	{ .name = "ZwWriteFile", .cap = KGENOME_NUCLEO_MEM_WRITE, KGENOME_SHAPE("fd0 tgt2 src5 entry2 res=status0") },
	{ .name = "MmGetSystemRoutineAddress", .cap = KGENOME_NUCLEO_RESOLVE, KGENOME_SHAPE("path0 field0 res=codeptr") },
	{ .name = "MmMapLockedPagesSpecifyCache", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 res=pointer") },
	{ .name = "MmMapLockedPages", .cap = KGENOME_NUCLEO_PROC_MEM, KGENOME_SHAPE("fd0 res=pointer") },
	{ .name = "PsLookupProcessByProcessId", .cap = KGENOME_NUCLEO_PTRACE, KGENOME_SHAPE("val0 out1 res=status0") },
	{ .name = "PsSetCreateProcessNotifyRoutine", .cap = KGENOME_NUCLEO_HOOK, KGENOME_SHAPE("tgt0 entry0 res=status0") },
	{ .name = "PsSetCreateProcessNotifyRoutineEx", .cap = KGENOME_NUCLEO_HOOK, KGENOME_SHAPE("tgt0 entry0 res=status0") },
	{ .name = "PsSetLoadImageNotifyRoutine", .cap = KGENOME_NUCLEO_HOOK, KGENOME_SHAPE("tgt0 entry0 res=status0") },
	/* TODO(limit): the callbacks are fields of the OB_OPERATION_REGISTRATION array that a field of argument 0 points at - two
	 * levels; entry=field names the first. */
	{ .name = "ObRegisterCallbacks", .cap = KGENOME_NUCLEO_HOOK, KGENOME_SHAPE("tgt0 field0 entry0 entry=field out1 res=status0") },
	{ .name = "PsCreateSystemThread", .cap = KGENOME_NUCLEO_THREAD, KGENOME_SHAPE("fd3 tgt5 val6 out0 entry5 res=status0") },
	{ .name = "ZwTerminateProcess", .cap = KGENOME_NUCLEO_PROC_EXEC, KGENOME_SHAPE("fd0 res=status0") },
	/*
	 * ===== THE WORDS ADDED WITH THE NINE CAPABILITIES AT THE END OF
	 * enum kgenome_nucleo_cap. Each entry point here exists to do ONE thing;
	 * that is the bar, and the names that did not clear it are listed in
	 * kofcap.h beside the capabilities rather than here.
	 */
	/* Encryption. Windows has two generations of the same API and both are
	 * still shipped, so both are here. TODO(limit): BCryptEncrypt's output is argument 6, past the six slots the lineage stage reads. */
	{ .name = "CryptEncrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 buf4 res=status") },
	{ .name = "CryptDecrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 buf4 res=status") },
	{ .name = "CryptAcquireContextA", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("out0 res=status") },
	{ .name = "CryptAcquireContextW", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("out0 res=status") },
	{ .name = "CryptGenKey", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 out3 res=status") },
	{ .name = "CryptDeriveKey", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 out4 res=status") },
	{ .name = "CryptImportKey", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src1 out5 res=status") },
	{ .name = "BCryptEncrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src1 buf6 res=status0") },
	{ .name = "BCryptDecrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src1 buf6 res=status0") },
	{ .name = "BCryptGenerateSymmetricKey", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src4 out1 res=status0") },
	{ .name = "BCryptImportKeyPair", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src4 out3 res=status0") },
	/* OpenSSL (libcrypto), which a PE reaches by importing a libcrypto DLL. The EVP names are
	 * the ones a program links; the AES_ ones are the older direct calls
	 * that statically linked malware still carries. The ELF table holds the same rows, shape for shape (2026-11-15: an ELF
	 * importing them had no row); tests/lib/genome/nucleo_rows.c (openssl_elf) holds the two equal. */
	{ .name = "EVP_EncryptInit_ex", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src3 res=value") },
	{ .name = "EVP_EncryptUpdate", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 buf1 src3 res=value") },
	{ .name = "EVP_DecryptInit_ex", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src3 res=value") },
	{ .name = "EVP_DecryptUpdate", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 buf1 src3 res=value") },
	{ .name = "EVP_CipherInit_ex", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("fd0 src3 res=value") },
	{ .name = "AES_set_encrypt_key", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("src0 buf2 res=value") },
	{ .name = "AES_cbc_encrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("src0 buf1 res=void") },
	{ .name = "AES_encrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("src0 buf1 res=void") },
	{ .name = "RSA_public_encrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("src1 buf2 res=value") },
	{ .name = "RSA_private_decrypt", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("src1 buf2 res=value") },
	/* Taking what the user is doing. The hook procedure is code the system calls; the module it is in is the handle (FD). (The X11
	 * pair that stood here is in the ELF table.) */
	{ .name = "SetWindowsHookExA", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("tgt1 fd2 entry1 res=handle") },
	{ .name = "SetWindowsHookExW", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("tgt1 fd2 entry1 res=handle") },
	{ .name = "GetAsyncKeyState", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("res=value") },
	{ .name = "GetKeyboardState", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("buf0 res=status") },
	{ .name = "GetRawInputData", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("fd0 buf2 res=value") },
	{ .name = "RegisterRawInputDevices", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("src0 res=status") },
	{ .name = "GetClipboardData", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("res=handle") },
	{ .name = "SetClipboardData", .cap = KGENOME_NUCLEO_CAPTURE, KGENOME_SHAPE("fd1 res=handle") },
	/* Installing itself as a service. TODO(limit): CreateServiceA/W's binary path is argument 7, past the six slots the lineage
	 * stage reads. */
	{ .name = "OpenSCManagerA", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("res=handle") },
	{ .name = "OpenSCManagerW", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("res=handle") },
	{ .name = "CreateServiceA", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 path1 res=handle") },
	{ .name = "CreateServiceW", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 path1 res=handle") },
	{ .name = "StartServiceA", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "StartServiceW", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "ChangeServiceConfigA", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 path4 res=status") },
	{ .name = "ChangeServiceConfigW", .cap = KGENOME_NUCLEO_SVC_INSTALL, KGENOME_SHAPE("fd0 path4 res=status") },
	/* The Zw page names the Nt spelling. The driver's registry path is a UNICODE_STRING (field of argument 0). */
	{ .name = "NtLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD, KGENOME_SHAPE("path0 field0 res=status0") },
	{ .name = "ZwLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD, KGENOME_SHAPE("path0 field0 res=status0") },
	/* A named pipe, and only a named one. */
	{ .name = "CreateNamedPipeA", .cap = KGENOME_NUCLEO_PIPE, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "CreateNamedPipeW", .cap = KGENOME_NUCLEO_PIPE, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "ConnectNamedPipe", .cap = KGENOME_NUCLEO_PIPE, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "CallNamedPipeA", .cap = KGENOME_NUCLEO_PIPE, KGENOME_SHAPE("path0 src1 buf3 res=status") },
	{ .name = "CallNamedPipeW", .cap = KGENOME_NUCLEO_PIPE, KGENOME_SHAPE("path0 src1 buf3 res=status") },
	/* Removing a file. */
	{ .name = "DeleteFileA", .cap = KGENOME_NUCLEO_FILE_DELETE, KGENOME_SHAPE("path0 res=status") },
	{ .name = "DeleteFileW", .cap = KGENOME_NUCLEO_FILE_DELETE, KGENOME_SHAPE("path0 res=status") },
	{ .name = "SetFileAttributesA", .cap = KGENOME_NUCLEO_PERM_SET, KGENOME_SHAPE("path0 res=status") },
	{ .name = "SetFileAttributesW", .cap = KGENOME_NUCLEO_PERM_SET, KGENOME_SHAPE("path0 res=status") },
	/* Asking whether it is watched. The Zw page names NtSetInformationThread. */
	{ .name = "IsDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG, KGENOME_SHAPE("res=value") },
	{ .name = "CheckRemoteDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "NtSetInformationThread", .cap = KGENOME_NUCLEO_ANTI_DEBUG, KGENOME_SHAPE("fd0 res=status0") },
	/* The credential calls of Windows are handed a TOKEN or a process HANDLE, not the credential struct a Linux kernel builds
	 * (commit_creds: BUFFER, the capability's shape) - FD (D7). OpenProcessToken's token comes back through argument 2;
	 * SetThreadToken's token is argument 1 (0 is a pointer to the thread). */
	{ .name = "AdjustTokenPrivileges", .cap = KGENOME_NUCLEO_CRED_SET, KGENOME_SHAPE("fd0 src2 res=status") },
	{ .name = "OpenProcessToken", .cap = KGENOME_NUCLEO_CRED_SET, KGENOME_SHAPE("fd0 out2 res=status") },
	{ .name = "DuplicateTokenEx", .cap = KGENOME_NUCLEO_CRED_SET, KGENOME_SHAPE("fd0 out5 res=status") },
	{ .name = "ImpersonateLoggedOnUser", .cap = KGENOME_NUCLEO_CRED_SET, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "SetThreadToken", .cap = KGENOME_NUCLEO_CRED_SET, KGENOME_SHAPE("fd1 res=status") },
	{ .name = "CreateProcessAsUserA", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("fd0 path1 val2 out10 res=status") },
	{ .name = "CreateProcessAsUserW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("fd0 path1 val2 out10 res=status") },
	{ .name = "CreateProcessWithTokenW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("fd0 path2 val3 out8 res=status") },
	{ .name = "CreateProcessWithLogonW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path4 val5 out10 res=status") },
	/* SHELLEXECUTEINFO.lpFile is a field of argument 0 (lpParameters is another: TODO(limit), one field role per argument). */
	{ .name = "ShellExecuteExA", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path0 field0 res=status") },
	{ .name = "ShellExecuteExW", .cap = KGENOME_NUCLEO_EXEC_IMAGE, KGENOME_SHAPE("path0 field0 res=status") },
	{ .name = "SetFileTime", .cap = KGENOME_NUCLEO_TIMESTOMP, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "CreateToolhelp32Snapshot", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("res=handle") },
	{ .name = "Process32First", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Process32FirstW", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Process32Next", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Process32NextW", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Module32First", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Module32Next", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Thread32First", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "Thread32Next", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("fd0 buf1 res=status") },
	{ .name = "EnumProcesses", .cap = KGENOME_NUCLEO_PROC_LIST, KGENOME_SHAPE("buf0 res=status") },
	/*
	 * AND THE GAPS THE SAME MEASUREMENT FOUND IN WORDS THAT ALREADY
	 * EXISTED - each one a spelling nobody had written down.
	 */
	{ .name = "BCryptOpenAlgorithmProvider", .cap = KGENOME_NUCLEO_CRYPTO, KGENOME_SHAPE("val1 out0 res=status0") },
	{ .name = "RegDeleteKeyA", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	{ .name = "RegDeleteKeyW", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	{ .name = "RegDeleteKeyExA", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	{ .name = "RegDeleteKeyExW", .cap = KGENOME_NUCLEO_REG_SET, KGENOME_SHAPE("fd0 path1 res=status0") },
	/* An allocation, and incidentally one that fails in some sandboxes -
	 * which is why a loader picks it. The capability is the allocation. (Protection is argument 4: TODO(limit) at VirtualAllocEx.) */
	{ .name = "VirtualAllocExNuma", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 res=pointer") },
	{ .name = "NtQueryInformationProcess", .cap = KGENOME_NUCLEO_ANTI_DEBUG, KGENOME_SHAPE("fd0 buf2 res=status0") },
	/*
	 * ===== 2026-11-15: SPELLINGS OF WORDS THAT EXIST, AND THE ROWS WITH NO WORD =====
	 *
	 * Each added for the APT set of 2026-11-15 and the lineage audit (fix_aptgap): no new capability. A spelling of an existing word is
	 * a row like those above. A row WITHOUT a capability (KGENOME_NUCLEO_NONE) makes no node: it is here for what it says about the
	 * call - an indirect entry for the function partition (kgenome_nucleo_entry_arg), an object the call ends, an argument.
	 */
	{ .name = "SleepEx", .cap = KGENOME_NUCLEO_SLEEP, KGENOME_SHAPE("val0 res=value") },
	/* The C runtime's thread start, as a PE imports it from msvcrt/ucrtbase (a statically linked one is a LIB row: below). */
	{ .name = "_beginthreadex", .cap = KGENOME_NUCLEO_THREAD, KGENOME_SHAPE("tgt2 val3 entry2 res=handle") },
	{ .name = "_beginthread", .cap = KGENOME_NUCLEO_THREAD, KGENOME_SHAPE("tgt0 val2 entry0 res=handle") },
	/*
	 * TODO(owner) Q1 - what a call that ENDS an object is. Default (these rows, and closesocket above): the word of the object it
	 * ends, with rel<k> (a fact of the row; no pack carries it), so a VirtualFreeEx is mem-alloc and its region input links it to the
	 * allocation. Alternative: no capability (a fact-only row), so a release is no node and no evidence. A rule naming mem-alloc
	 * matches a free under the default only through a relation; "freeing" alone is no behaviour, which is why no new word is proposed.
	 */
	{ .name = "VirtualFree", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd0 rel0 res=status") },
	{ .name = "VirtualFreeEx", .cap = KGENOME_NUCLEO_ALLOC, KGENOME_SHAPE("fd1 rel1 res=status") },
	{ .name = "HeapFree", .cap = KGENOME_NUCLEO_HEAP, KGENOME_SHAPE("fd2 rel2 res=status") },
	{ .name = "freeaddrinfo", .cap = KGENOME_NUCLEO_DNS, KGENOME_SHAPE("fd0 rel0 res=void") },
	{ .name = "FreeLibrary", .cap = KGENOME_NUCLEO_LIB_OPEN, KGENOME_SHAPE("fd0 rel0 res=status") },
	{ .name = "RegCloseKey", .cap = KGENOME_NUCLEO_REG_OPEN, KGENOME_SHAPE("fd0 rel0 res=status0") },
	{ .name = "InternetCloseHandle", .cap = KGENOME_NUCLEO_HTTP_OPEN, KGENOME_SHAPE("fd0 rel0 res=status") },
	{ .name = "WinHttpCloseHandle", .cap = KGENOME_NUCLEO_HTTP_OPEN, KGENOME_SHAPE("fd0 rel0 res=status") },
	/*
	 * TODO(owner) Q4 - running as a Windows service. Default (these rows): KGENOME_NUCLEO_BACKGROUND, the word for a program that
	 * detaches to keep running ("what every daemon does"); the handler is code the service manager calls, and SetServiceStatus is
	 * handed the status handle the registration returned (FD). Alternative: a new word for "runs as a service" (SVC_INSTALL is
	 * installing, a different act). Cost of the default: diagnose.c's family() places BACKGROUND near fork, and these are no fork.
	 * The dispatcher's ServiceMain is SERVICE_TABLE_ENTRY.lpServiceProc, a field of the table argument 0 points at.
	 */
	{ .name = "RegisterServiceCtrlHandlerA", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("path0 tgt1 entry1 res=handle") },
	{ .name = "RegisterServiceCtrlHandlerW", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("path0 tgt1 entry1 res=handle") },
	{ .name = "RegisterServiceCtrlHandlerExA", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("path0 tgt1 val2 entry1 res=handle") },
	{ .name = "RegisterServiceCtrlHandlerExW", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("path0 tgt1 val2 entry1 res=handle") },
	{ .name = "SetServiceStatus", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("fd0 src1 res=status") },
	{ .name = "StartServiceCtrlDispatcherA", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("tgt0 field0 entry0 entry=field res=status") },
	{ .name = "StartServiceCtrlDispatcherW", .cap = KGENOME_NUCLEO_BACKGROUND, KGENOME_SHAPE("tgt0 field0 entry0 entry=field res=status") },
	/*
	 * TODO(owner) Q6 - the mutex. Default: no word - "single instance, CreateMutex - every desktop application" is on the list of
	 * rejected words (capability_ids.h); the row says only that its name is argument 2. Alternative: reopen the rejection, since the
	 * lineage now supplies what the rejection said was missing (the name's producer, e.g. a decrypted string).
	 * (OpenMutexA's page is the W page, which documents both names.)
	 */
	{ .name = "CreateMutexA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path2 res=handle") },
	{ .name = "CreateMutexW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path2 res=handle") },
	{ .name = "OpenMutexA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path2 res=handle") },
	{ .name = "OpenMutexW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path2 res=handle") },
	/*
	 * TODO(owner) Q5 - GetModuleHandle. Default: no word (it brings no code in, which is what lib-load means). Alternative: lib-load,
	 * because its handle heads the same GetProcAddress link LoadLibrary's does.
	 */
	{ .name = "GetModuleHandleA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path0 res=handle") },
	{ .name = "GetModuleHandleW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path0 res=handle") },
	/* Path building and a process's exit code: no word (the "file probing" class); an argument a later analysis of where a path's
	 * bytes came from reads. */
	{ .name = "GetTempPathA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("buf1 res=value") },
	{ .name = "GetTempPathW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("buf1 res=value") },
	{ .name = "GetTempFileNameA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path0 buf3 res=value") },
	{ .name = "GetTempFileNameW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("path0 buf3 res=value") },
	{ .name = "GetExitCodeProcess", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd0 res=status") },
	{ .name = "CertOpenStore", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=handle") },
	{ .name = "CloseHandle", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd0 rel0 res=status") },
	/* Code the system will call: the function partition's indirect entries (kgenome_nucleo_entry_arg). */
	{ .name = "CreateTimerQueueTimer", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd1 tgt2 val3 out0 entry2 res=status") },
	{ .name = "RegisterWaitForSingleObject", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd1 tgt2 val3 out0 entry2 res=status") },
	{ .name = "SetWaitableTimer", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd0 tgt3 val4 entry3 res=status") },
	{ .name = "SetTimer", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt3 entry3 res=value") },
	{ .name = "CreateThreadpoolWork", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 val1 entry0 res=pointer") },
	{ .name = "TrySubmitThreadpoolCallback", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 val1 entry0 res=status") },
	{ .name = "CreateThreadpoolTimer", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 val1 entry0 res=pointer") },
	{ .name = "CreateFiber", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt1 val2 entry1 res=pointer") },
	{ .name = "EnumWindows", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 val1 entry0 res=status") },
	{ .name = "EnumChildWindows", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd0 tgt1 val2 entry1 res=status") },
	{ .name = "EnumDesktopWindows", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("fd0 tgt1 val2 entry1 res=status") },
	{ .name = "EnumSystemLocalesA", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 entry0 res=status") },
	{ .name = "EnumSystemLocalesW", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 entry0 res=status") },
	{ .name = "SetUnhandledExceptionFilter", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 entry0 res=codeptr") },
	{ .name = "AddVectoredExceptionHandler", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt1 entry1 res=pointer") },
	{ .name = "SetConsoleCtrlHandler", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("tgt0 entry0 res=status") },
	/*
	 * NO CAPABILITY, A FACT: THE CALLS THAT DO NOT RETURN (res=noret; no node, the call ends its block - see the same rows of
	 * nucleo_names_elf.c). The Windows ones: TerminateProcess is NOT here, it returns when its target is another process. Then the C
	 * names: the one list these rows replace (noreturn_names[], diag_lineage_chain.c) answered the PE route for every name it held,
	 * so a PE import of `abort` or `longjmp` from its C runtime ended its block; they are kept for the PE route as they were.
	 * TODO(verify): which of these a Windows C runtime (msvcrt, ucrt, a MinGW import library) actually exports is not checked against
	 * any export table; a name no runtime exports costs nothing (no import, no row reached), a missing one would lose an end of block.
	 */
	{ .name = "ExitProcess", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "ExitThread", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "RtlExitUserProcess", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "RtlExitUserThread", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "FatalExit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_CxxThrowException", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_amsg_exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_invoke_watson", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_Exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "abort", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "quick_exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__stack_chk_fail", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__stack_chk_fail_local", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__assert_fail", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__assert", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__assert_perror_fail", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__chk_fail", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__fortify_fail", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__libc_fatal", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "longjmp", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_longjmp", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "siglongjmp", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__longjmp_chk", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "pthread_exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__cxa_throw", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__cxa_rethrow", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__cxa_bad_cast", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "__cxa_bad_typeid", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "_Unwind_Resume", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "err", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "errx", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "verr", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "verrx", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	{ .name = "thrd_exit", .cap = KGENOME_NUCLEO_NONE, KGENOME_SHAPE("res=noret") },
	/*
	 * NOT HERE, AND WHY:
	 *   TODO(verify) NtCreateThreadEx, RtlCreateUserThread - no reference page; and TODO(owner) Q7: they are spellings of
	 *     thread-create, to be added when counted in the corpus (default: count first; alternative: add now on the APT evidence).
	 *   TODO(verify) WSAIoctl - the refine that makes SIO_RCVALL a raw-socket word needs the code's value, which its page does not state.
	 *   TODO(owner) LIB rows - a statically linked library function (libcurl, zlib/minizip, Crypto++, the C runtime) is a row keyed
	 *     (library, function) and bound by the LIB identification step (partition step 2b, whose database location the owner decides),
	 *     never by a symbol the file chose (names_structural). Dormant until that step exists: no table, no row.
	 */
};

const struct kgenome_nucleo_names kgenome_nucleo_names_pe = {
	.target = KGENOME_NUCLEO_T_PE, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
