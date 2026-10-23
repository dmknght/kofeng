/*
 * nucleo_names_pe.c - what an imported name means in a PE object: the Win32 and native API, and Winsock (whose names are lowercase and are Windows API all the same).
 *
 * One table of imported (or called) NAMES per target, each in the same capability vocabulary: what a program IS asked to do
 * is the one thing a rule can share between targets, and which API spells it is not. Looked up through
 * kgenome_nucleo_cap_of_name and its siblings (nucleo.c), which are told the target.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "recvfrom", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "send", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "sendto", .cap = KGENOME_NUCLEO_NET_WRITE },
	/* Windows, for the same words */
	{ .name = "VirtualAlloc", .cap = KGENOME_NUCLEO_ALLOC, .refine = KGENOME_NUCLEO_REFINE_PROT_ARG3 },
	{ .name = "VirtualAllocEx", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "VirtualProtect", .cap = KGENOME_NUCLEO_ALLOC, .refine = KGENOME_NUCLEO_REFINE_PROT_ARG2 },
	{ .name = "HeapAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "HeapReAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "RtlAllocateHeap", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "LocalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "GlobalAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "CoTaskMemAlloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "WSASocketA", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "WSASocketW", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
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
	{ .name = "htons", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "htonl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohs", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_addr", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_pton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_ntoa", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "getaddrinfo", .cap = KGENOME_NUCLEO_DNS },
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
	{ .name = "NtLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "ZwLoadDriver", .cap = KGENOME_NUCLEO_MOD_LOAD },
	/* A named pipe, and only a named one. */
	{ .name = "CreateNamedPipeA", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CreateNamedPipeW", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "ConnectNamedPipe", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CallNamedPipeA", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "CallNamedPipeW", .cap = KGENOME_NUCLEO_PIPE },
	/* Removing a file. */
	{ .name = "DeleteFileA", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "DeleteFileW", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "SetFileAttributesA", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "SetFileAttributesW", .cap = KGENOME_NUCLEO_PERM_SET },
	/* Asking whether it is watched. */
	{ .name = "IsDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	{ .name = "CheckRemoteDebuggerPresent", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	{ .name = "NtSetInformationThread", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
	{ .name = "AdjustTokenPrivileges", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "OpenProcessToken", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "DuplicateTokenEx", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "ImpersonateLoggedOnUser", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "SetThreadToken", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "CreateProcessAsUserA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessAsUserW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessWithTokenW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "CreateProcessWithLogonW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteExA", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "ShellExecuteExW", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
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
	{ .name = "NtQueryInformationProcess", .cap = KGENOME_NUCLEO_ANTI_DEBUG },
};

const struct kgenome_nucleo_names kgenome_nucleo_names_pe = {
	.target = KGENOME_NUCLEO_T_PE, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
