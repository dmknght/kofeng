/*
 * nucleo_rows - the row table (step 1a, 2026-11-15): one row per API spelling says which argument is which input, what the result is,
 * and which argument is code the system will call; the per-capability questions answer from the same generated table.
 *
 * RED ON THE OLD CODE (each fails before the change, passes after; why the old tests missed it after the case):
 *   d1_closesocket       kgenome_nucleo_hands_on(NET_OPEN, "closesocket") was 1: a status handed on as a new socket. (b) the hand-on
 *                        tests asked mmap/mprotect/open/read only - no row whose word constructs while the call does not.
 *   d2_protect           VirtualProtect / VirtualProtectEx returned BOOL and were handed on as the region (only "mprotect" was exempt). (b)
 *   d3_ntstatus          ZwAllocateVirtualMemory, NtAllocateVirtualMemory, ZwCreateFile, ZwOpenFile: an NTSTATUS handed on as the object. (b)
 *   d5_protect_ex        cap_of_call(PE, "VirtualProtectEx", prot 0x40 in argument 3) stayed mem-alloc: the row had no refine. (b) the refine
 *                        tests named VirtualAlloc and VirtualProtect only.
 *   d6_createpipe        CreatePipe's BOOL handed on as the pipe. (b)
 *   hand_constructors    LoadLibraryA, GetProcAddress, CreateThread, OpenProcess, InternetOpenA, CreateNamedPipeA handed NOTHING on (LG-HAND).
 *                        (a) no test asked any of them.
 *   x11_rows             XQueryKeymap and XGrabKeyboard stood in the PE table: an ELF importing them had no node. (a)
 *   rows_elf_1           (2026-11-15) pipe, pipe2, socketpair, sock_create, sock_create_kern, filp_close: a status handed on as the object
 *                        (the capability's res=handle; ROWS-ELF-1, the ELF twin of d1/d3/d6). (b) cap_unchanged PINNED
 *                        hands_on(PIPE_OPEN, "pipe") == 1 - the wrong answer - and no test asked the out argument of an ELF row.
 *   openssl_elf          (2026-11-15) the OpenSSL rows stood in the PE table only: cap_of_name(ELF, "EVP_EncryptUpdate") was none.
 *                        (a) doc_oracle reads the PE table only.
 *   setid_value          (2026-11-15) setuid/setgid/seteuid/setreuid/setresuid took CRED_SET's BUFFER on a uid/gid argument (and
 *                        seteuid res=status). (b) no test asked an ELF row's role; doc_oracle is the PE table.
 *   elf_connect          (2026-11-15, fix_linrow) ROWS-ELF-CONNECT: the ELF row of connect was `fd0` where the PE row is `fd0 src1`, so the
 *                        address an ELF program connects to was never an input. (b) doc_oracle reads the PE table; no test compared a
 *                        name both tables hold.
 * PINNED (no old API to be red against):
 *   doc_oracle           every row checked against its reference page: the role at each index, the result, the entry - the table below is
 *                        the transcription of the pages (learn.microsoft.com / the OpenSSL manual), written apart from the rows, so a row
 *                        whose index drifts fails here (mutants: tools-free, see the report).
 *   cap_unchanged        the capability's answers (kgenome_diag_role_of_arg's old switch, hands_on with no name, name_arg, the old zero list)
 *                        are what they were: the routes that hold only a capability see no change.
 *   ordinals             ws2_32 / wsock32 ordinal names, the two tables differing at 10..12, case and ".dll" ignored, nothing else named.
 *   invariants           over every row of every table: no role twice in a shape, an entry is a TARGET argument, an out is never an input
 *                        of the same index; a fact-only row answers no capability and keeps its id.
 */
#include <stdio.h>
#include <string.h>

#include <kgenome.h>
#include <celllysis/nucleo.h>
#include <celllysis/capability_ids.h>
#include <phenotype/diag_vocab.h>
#include <phenotype/diag_private.h>

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

#define FD   KGENOME_DIAG_ROLE_FD
#define BUF  KGENOME_DIAG_ROLE_BUFFER
#define SRC  KGENOME_DIAG_ROLE_SOURCE
#define PTH  KGENOME_DIAG_ROLE_PATH
#define VAL  KGENOME_DIAG_ROLE_VALUE
#define TGT  KGENOME_DIAG_ROLE_TARGET
#define NO   KGENOME_NUCLEO_ARG_NONE

static void d1_closesocket(void)
{
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_NET_OPEN, "closesocket") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_NET_OPEN, "socket") == 1);       /* CONTROL: the constructor still is one */
}

static void d2_protect(void)
{
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "VirtualProtect") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC_EXEC, "VirtualProtect") == 0);   /* refined to exec: the same row */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "VirtualProtectEx") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "VirtualAlloc") == 1);          /* CONTROL */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC_EXEC, "VirtualAlloc") == 1);
}

static void d3_ntstatus(void)
{
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "ZwAllocateVirtualMemory") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "NtAllocateVirtualMemory") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "ZwCreateFile") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "ZwOpenFile") == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "CreateFileA") == 1);       /* CONTROL */
}

static void d5_protect_ex(void)
{
	uint64_t a[4] = { 0xffffffffffffffffull, 0x10000, 0x1000, 0x40 };
	uint8_t fl = 0;

	CK(kgenome_nucleo_cap_of_call(KGENOME_NUCLEO_T_PE, "VirtualProtectEx", a, &fl) == KGENOME_NUCLEO_ALLOC_EXEC && fl == KGENOME_NUCLEO_F_WX);
	a[3] = 0x04;    /* PAGE_READWRITE: no execute */
	CK(kgenome_nucleo_cap_of_call(KGENOME_NUCLEO_T_PE, "VirtualProtectEx", a, &fl) == KGENOME_NUCLEO_ALLOC && fl == 0);
}

static void d6_createpipe(void)
{
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_PIPE_OPEN, "CreatePipe") == 0);
	CK(kgenome_nucleo_row_out(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreatePipe"), 0) == 0);
	CK(kgenome_nucleo_row_out(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreatePipe"), 1) == 1);
}

static void hand_constructors(void)
{
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_LIB_OPEN, "LoadLibraryA") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_RESOLVE, "GetProcAddress") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_THREAD, "CreateThread") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_PTRACE, "OpenProcess") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_HTTP_OPEN, "InternetOpenA") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_PIPE, "CreateNamedPipeA") == 1);
	/* CONTROL: the capability with no name still answers as before */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_LIB_OPEN, NULL) == 0);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_THREAD, NULL) == 0);
}

static void rows_elf_1(void)
{
	static const struct { const char *name; uint16_t cap; unsigned out; } made[] = {
		{ "pipe", KGENOME_NUCLEO_PIPE_OPEN, 0 }, { "pipe2", KGENOME_NUCLEO_PIPE_OPEN, 0 },
		{ "socketpair", KGENOME_NUCLEO_NET_OPEN, 3 }, { "sock_create", KGENOME_NUCLEO_NET_OPEN, 3 },
		{ "sock_create_kern", KGENOME_NUCLEO_NET_OPEN, 4 },
	};
	unsigned i;
	uint16_t r;

	for (i = 0; i < sizeof made / sizeof made[0]; i++) {
		r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, made[i].name);
		CK(r != 0 && kgenome_nucleo_row_cap(r) == made[i].cap);
		CK(kgenome_nucleo_hands_on(made[i].cap, made[i].name) == 0);
		CK(kgenome_nucleo_row_res(r) == KGENOME_NUCLEO_RES_STATUS0 && kgenome_nucleo_sys_zero_on_success(made[i].name));
		CK(kgenome_nucleo_row_out(r, 0) == made[i].out && kgenome_nucleo_row_out(r, 1) == NO);
	}
	r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, "filp_close");
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "filp_close") == 0);
	CK(kgenome_nucleo_row_release(r) == 0 && kgenome_nucleo_row_role(r, 0) == FD && kgenome_nucleo_row_res(r) == KGENOME_NUCLEO_RES_STATUS0);
	/* CONTROL: the constructors of the same words still hand one on */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_NET_OPEN, "socket") == 1 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "filp_open") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "open") == 1 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_PIPE_OPEN, NULL) == 1);
}

/* connect(fd, addr, len) has one contract on both systems: the descriptor and the address it is handed (POSIX and Winsock). */
static void elf_connect(void)
{
	const uint16_t e = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, "connect"), w = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "connect");
	unsigned i;

	CK(e && w);
	CK(kgenome_nucleo_row_role(e, 0) == FD && kgenome_nucleo_row_role(e, 1) == SRC);
	for (i = 0; i < 8u; i++)
		CK(kgenome_nucleo_row_role(e, i) == kgenome_nucleo_row_role(w, i));
	CK(kgenome_nucleo_row_res(e) == kgenome_nucleo_row_res(w));
}

static void openssl_elf(void)
{
	static const char *const n[] = {
		"EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_CipherInit_ex",
		"AES_set_encrypt_key", "AES_cbc_encrypt", "AES_encrypt", "RSA_public_encrypt", "RSA_private_decrypt",
	};
	unsigned i, k;

	for (i = 0; i < sizeof n / sizeof n[0]; i++) {
		uint16_t e = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, n[i]), p = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, n[i]);
		int bad = !e || !p || e == p;

		CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, n[i]) == KGENOME_NUCLEO_CRYPTO);
		for (k = 0; k < 8u && !bad; k++)
			if (kgenome_nucleo_row_role(e, k) != kgenome_nucleo_row_role(p, k) || kgenome_nucleo_row_field(e, k) != kgenome_nucleo_row_field(p, k))
				bad = 1;
		if (!bad && (kgenome_nucleo_row_res(e) != kgenome_nucleo_row_res(p) || kgenome_nucleo_row_out(e, 0) != kgenome_nucleo_row_out(p, 0) ||
			     kgenome_nucleo_entry_arg(e, NULL) != kgenome_nucleo_entry_arg(p, NULL) || kgenome_nucleo_row_release(e) != kgenome_nucleo_row_release(p)))
			bad = 1;
		if (bad) {
			printf("  FAIL openssl_elf %s: ELF row %u, PE row %u\n", n[i], e, p);
			fails++;
		}
	}
	/* the PE spelling of one: the oracle's transcription, read through the ELF row */
	CK(kgenome_nucleo_row_role(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, "EVP_EncryptUpdate"), 1) == BUF);
	CK(kgenome_nucleo_row_role(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, "EVP_EncryptUpdate"), 3) == SRC);
}

static void setid_value(void)
{
	static const char *const n[] = { "setuid", "setgid", "seteuid", "setreuid", "setresuid" };
	unsigned i, k;

	for (i = 0; i < sizeof n / sizeof n[0]; i++) {
		uint16_t r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, n[i]);

		CK(r != 0 && kgenome_nucleo_row_cap(r) == KGENOME_NUCLEO_CRED_SET);
		CK(kgenome_nucleo_row_role(r, 0) == VAL && kgenome_nucleo_row_res(r) == KGENOME_NUCLEO_RES_STATUS0);
		for (k = 1; k < 8u; k++)
			CK(kgenome_nucleo_row_role(r, k) == 0);
		CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_CRED_SET, r, 0) == VAL);
	}
	/* CONTROL: commit_creds installs a credential that was built - the capability's BUFFER */
	CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_CRED_SET, kgenome_nucleo_row_of(KGENOME_NUCLEO_T_ELF, "commit_creds"), 0) == BUF);
	CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_CRED_SET, 0, 0) == BUF);
}

static void x11_rows(void)
{
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, "XQueryKeymap") == KGENOME_NUCLEO_CAPTURE);
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_ELF, "XGrabKeyboard") == KGENOME_NUCLEO_CAPTURE);
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, "XQueryKeymap") == KGENOME_NUCLEO_NONE);
}

/*
 * THE PAGES, TRANSCRIBED (2026-11-15). r[k] is the role of argument k as this table's grammar words it from the page's parameter
 * list; `res` the return type's kind, `entry` the parameter that is a callback.
 */
struct doc {
	const char *name;
	uint8_t r[8];
	unsigned res, entry;
};

#define S   KGENOME_NUCLEO_RES_STATUS
#define S0  KGENOME_NUCLEO_RES_STATUS0
#define V   KGENOME_NUCLEO_RES_VALUE
#define H   KGENOME_NUCLEO_RES_HANDLE
#define P   KGENOME_NUCLEO_RES_POINTER
#define CP  KGENOME_NUCLEO_RES_CODEPTR
#define VO  KGENOME_NUCLEO_RES_VOID

static const struct doc pe_docs[] = {
	{ "connect",            { FD, SRC },                          S0, NO },
	{ "bind",               { FD, SRC },                          S0, NO },
	{ "listen",             { FD },                               S0, NO },
	{ "recv",               { FD, BUF },                          V,  NO },
	{ "sendto",             { FD, SRC },                          V,  NO },
	{ "WSAConnect",         { FD, SRC },                          S0, NO },
	{ "WSARecv",            { FD, BUF, 0, 0, 0, 0, TGT },                          S0, 6 },
	{ "WSASend",            { FD, SRC, 0, 0, 0, 0, TGT },                          S0, 6 },
	{ "WSAAccept",          { FD, 0, 0, TGT },                               H,  3 },
	{ "closesocket",        { FD },                               S0, NO },
	{ "htons",              { VAL },                              V,  NO },
	{ "inet_pton",          { 0, VAL },                           V,  NO },
	{ "gethostbyname",      { PTH },                              P,  NO },
	{ "getaddrinfo",        { PTH, VAL },                         S0, NO },
	{ "freeaddrinfo",       { FD },                               VO, NO },
	{ "VirtualAllocEx",     { FD },                               P,  NO },
	{ "VirtualAllocExNuma", { FD },                               P,  NO },
	{ "VirtualProtect",     { FD },                               S,  NO },
	{ "VirtualProtectEx",   { 0, FD },                            S,  NO },
	{ "ZwAllocateVirtualMemory", { FD },                          S0, NO },
	{ "CreateFileMappingA", { FD, 0, 0, 0, 0, PTH },              H,  NO },
	{ "MapViewOfFile",      { FD },                               P,  NO },
	{ "HeapReAlloc",        { 0, 0, FD },                         P,  NO },
	{ "VirtualFree",        { FD },                               S,  NO },
	{ "VirtualFreeEx",      { 0, FD },                            S,  NO },
	{ "HeapFree",           { 0, 0, FD },                         S,  NO },
	{ "CreateFileA",        { PTH },                              H,  NO },
	{ "ReadFile",           { FD, BUF },                          S,  NO },
	{ "WriteFile",          { FD, SRC },                          S,  NO },
	{ "ZwCreateFile",       { 0, 0, PTH },                        S0, NO },
	{ "ZwOpenFile",         { 0, 0, PTH },                        S0, NO },
	{ "ZwReadFile",         { FD, 0, TGT, 0, 0, BUF },              S0, 2 },
	{ "ZwWriteFile",        { FD, 0, TGT, 0, 0, SRC },              S0, 2 },
	{ "DeleteFileA",        { PTH },                              S,  NO },
	{ "MoveFileExW",        { PTH },                              S,  NO },
	{ "MoveFileWithProgressW", { PTH, 0, TGT },                           S,  2 },
	{ "SetFileTime",        { FD },                               S,  NO },
	{ "CreatePipe",         { 0 },                                S,  NO },
	{ "CreateNamedPipeW",   { PTH },                              H,  NO },
	{ "CallNamedPipeA",     { PTH, SRC, 0, BUF },                 S,  NO },
	{ "GetTempFileNameA",   { PTH, 0, 0, BUF },                   V,  NO },
	{ "CreateProcessA",     { PTH, VAL },                         S,  NO },
	{ "CreateProcessW",     { PTH, VAL },                         S,  NO },
	{ "WinExec",            { VAL },                              V,  NO },
	{ "ShellExecuteA",      { 0, 0, PTH, VAL },                   V,  NO },
	{ "ShellExecuteW",      { 0, 0, PTH, VAL },                   V,  NO },
	{ "CreateProcessAsUserA", { FD, PTH, VAL },                   S,  NO },
	{ "CreateProcessWithTokenW", { FD, 0, PTH, VAL },             S,  NO },
	{ "CreateProcessWithLogonW", { 0, 0, 0, 0, PTH, VAL },        S,  NO },
	{ "CreateThread",       { 0, 0, TGT, VAL },                   H,  2 },
	{ "CreateRemoteThread", { FD, 0, 0, TGT, VAL },               H,  3 },
	{ "CreateRemoteThreadEx", { FD, 0, 0, TGT, VAL },             H,  3 },
	{ "QueueUserAPC",       { TGT, FD, VAL },                     V,  0 },
	{ "SetThreadContext",   { FD, SRC },                          S,  NO },
	{ "GetThreadContext",   { FD, BUF },                          S,  NO },
	{ "ResumeThread",       { FD },                               V,  NO },
	{ "ZwTerminateProcess", { FD },                               S0, NO },
	{ "OpenProcess",        { 0, 0, VAL },                        H,  NO },
	{ "OpenThread",         { 0, 0, VAL },                        H,  NO },
	{ "DebugActiveProcess", { VAL },                              S,  NO },
	{ "PsLookupProcessByProcessId", { VAL },                      S0, NO },
	{ "WriteProcessMemory", { FD, BUF, SRC },                     S,  NO },
	{ "ReadProcessMemory",  { FD, SRC, BUF },                     S,  NO },
	{ "ZwUnmapViewOfSection", { FD },                             S0, NO },
	{ "MmMapLockedPagesSpecifyCache", { FD },                     P,  NO },
	{ "SetStdHandle",       { 0, FD },                            S,  NO },
	{ "DuplicateHandle",    { 0, FD },                            S,  NO },
	{ "CreateToolhelp32Snapshot", { 0 },                          H,  NO },
	{ "Process32First",     { FD, BUF },                          S,  NO },
	{ "EnumProcesses",      { BUF },                              S,  NO },
	{ "PsCreateSystemThread", { 0, 0, 0, FD, 0, TGT, VAL },       S0, 5 },
	{ "_beginthreadex",     { 0, 0, TGT, VAL },                   H,  2 },
	{ "_beginthread",       { TGT, 0, VAL },                      H,  0 },
	{ "GetExitCodeProcess", { FD },                               S,  NO },
	{ "LoadLibraryA",       { PTH },                              H,  NO },
	{ "LoadLibraryExW",     { PTH },                              H,  NO },
	{ "GetProcAddress",     { FD, PTH },                          CP, NO },
	{ "MmGetSystemRoutineAddress", { PTH },                       CP, NO },
	{ "FreeLibrary",        { FD },                               S,  NO },
	{ "GetModuleHandleA",   { PTH },                              H,  NO },
	{ "RegOpenKeyExA",      { FD, PTH },                          S0, NO },
	{ "RegOpenKeyW",        { FD, PTH },                          S0, NO },
	{ "NtOpenKey",          { 0, 0, PTH },                        S0, NO },
	{ "RegSetValueExA",     { FD, PTH, 0, 0, SRC },               S0, NO },
	{ "RegCreateKeyExW",    { FD, PTH },                          S0, NO },
	{ "RegDeleteKeyExA",    { FD, PTH },                          S0, NO },
	{ "NtSetValueKey",      { FD, PTH, 0, 0, SRC },               S0, NO },
	{ "RegCloseKey",        { FD },                               S0, NO },
	{ "InternetOpenA",      { VAL },                              H,  NO },
	{ "InternetConnectA",   { FD, PTH, VAL },                     H,  NO },
	{ "InternetOpenUrlW",   { FD, PTH, SRC },                     H,  NO },
	{ "InternetReadFile",   { FD, BUF },                          S,  NO },
	{ "HttpOpenRequestA",   { FD, 0, PTH },                       H,  NO },
	{ "HttpSendRequestW",   { FD, VAL, 0, SRC },                  S,  NO },
	{ "URLDownloadToFileA", { 0, PTH },                           S0, NO },
	{ "WinHttpOpen",        { VAL },                              H,  NO },
	{ "WinHttpConnect",     { FD, PTH, VAL },                     H,  NO },
	{ "WinHttpOpenRequest", { FD, 0, PTH },                       H,  NO },
	{ "WinHttpSendRequest", { FD, VAL, 0, SRC },                  S,  NO },
	{ "WinHttpReadData",    { FD, BUF },                          S,  NO },
	{ "InternetCloseHandle", { FD },                              S,  NO },
	{ "OpenSCManagerW",     { 0 },                                H,  NO },
	{ "CreateServiceA",     { FD, PTH },                          H,  NO },
	{ "StartServiceW",      { FD },                               S,  NO },
	{ "ChangeServiceConfigA", { FD, 0, 0, 0, PTH },               S,  NO },
	{ "ZwLoadDriver",       { PTH },                              S0, NO },
	{ "RegisterServiceCtrlHandlerW", { PTH, TGT },                H,  1 },
	{ "RegisterServiceCtrlHandlerExA", { PTH, TGT, VAL },         H,  1 },
	{ "SetServiceStatus",   { FD, SRC },                          S,  NO },
	{ "StartServiceCtrlDispatcherW", { TGT },                     S,  0 },
	{ "OpenProcessToken",   { FD },                               S,  NO },
	{ "AdjustTokenPrivileges", { FD, 0, SRC },                    S,  NO },
	{ "DuplicateTokenEx",   { FD },                               S,  NO },
	{ "ImpersonateLoggedOnUser", { FD },                          S,  NO },
	{ "SetThreadToken",     { 0, FD },                            S,  NO },
	{ "CryptAcquireContextA", { 0 },                              S,  NO },
	{ "CryptGenKey",        { FD },                               S,  NO },
	{ "CryptDeriveKey",     { FD },                               S,  NO },
	{ "CryptImportKey",     { FD, SRC },                          S,  NO },
	{ "CryptEncrypt",       { FD, 0, 0, 0, BUF },                 S,  NO },
	{ "CryptDecrypt",       { FD, 0, 0, 0, BUF },                 S,  NO },
	{ "BCryptOpenAlgorithmProvider", { 0, VAL },                  S0, NO },
	{ "BCryptGenerateSymmetricKey", { FD, 0, 0, 0, SRC },         S0, NO },
	{ "BCryptImportKeyPair", { FD, 0, 0, 0, SRC },                S0, NO },
	{ "BCryptEncrypt",      { FD, SRC, 0, 0, 0, 0, BUF },         S0, NO },
	{ "BCryptDecrypt",      { FD, SRC, 0, 0, 0, 0, BUF },         S0, NO },
	{ "EVP_EncryptUpdate",  { FD, BUF, 0, SRC },                  V,  NO },
	{ "EVP_CipherInit_ex",  { FD, 0, 0, SRC },                    V,  NO },
	{ "AES_set_encrypt_key", { SRC, 0, BUF },                     V,  NO },
	{ "AES_cbc_encrypt",    { SRC, BUF },                         VO, NO },
	{ "RSA_private_decrypt", { 0, SRC, BUF },                     V,  NO },
	{ "SetWindowsHookExA",  { 0, TGT, FD },                       H,  1 },
	{ "GetKeyboardState",   { BUF },                              S,  NO },
	{ "GetRawInputData",    { FD, 0, BUF },                       V,  NO },
	{ "RegisterRawInputDevices", { SRC },                         S,  NO },
	{ "SetClipboardData",   { 0, FD },                            H,  NO },
	{ "CheckRemoteDebuggerPresent", { FD },                       S,  NO },
	{ "NtSetInformationThread", { FD },                           S0, NO },
	{ "NtQueryInformationProcess", { FD, 0, BUF },                S0, NO },
	{ "PsSetCreateProcessNotifyRoutineEx", { TGT },               S0, 0 },
	{ "PsSetLoadImageNotifyRoutine", { TGT },                     S0, 0 },
	{ "ObRegisterCallbacks", { TGT },                             S0, 0 },
	{ "Sleep",              { VAL },                              VO, NO },
	{ "SleepEx",            { VAL },                              V,  NO },
	{ "CreateMutexA",       { 0, 0, PTH },                        H,  NO },
	{ "OpenMutexW",         { 0, 0, PTH },                        H,  NO },
	{ "CloseHandle",        { FD },                               S,  NO },
	{ "CreateTimerQueueTimer", { 0, FD, TGT, VAL },               S,  2 },
	{ "RegisterWaitForSingleObject", { 0, FD, TGT, VAL },         S,  2 },
	{ "SetWaitableTimer",   { FD, 0, 0, TGT, VAL },               S,  3 },
	{ "SetTimer",           { 0, 0, 0, TGT },                     V,  3 },
	{ "CreateThreadpoolWork", { TGT, VAL },                       P,  0 },
	{ "TrySubmitThreadpoolCallback", { TGT, VAL },                S,  0 },
	{ "CreateFiber",        { 0, TGT, VAL },                      P,  1 },
	{ "EnumWindows",        { TGT, VAL },                         S,  0 },
	{ "EnumChildWindows",   { FD, TGT, VAL },                     S,  1 },
	{ "EnumSystemLocalesA", { TGT },                              S,  0 },
	{ "SetUnhandledExceptionFilter", { TGT },                     CP, 0 },
	{ "AddVectoredExceptionHandler", { 0, TGT },                  P,  1 },
	{ "SetConsoleCtrlHandler", { TGT },                           S,  0 },
};

static void doc_oracle(void)
{
	size_t d;
	unsigned k;

	for (d = 0; d < sizeof pe_docs / sizeof pe_docs[0]; d++) {
		const struct doc *x = &pe_docs[d];
		uint16_t row = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, x->name);
		int bad = !row;

		for (k = 0; k < 8u && row; k++)
			if (kgenome_nucleo_row_role(row, k) != x->r[k])
				bad = 1;
		if (row && (kgenome_nucleo_row_res(row) != x->res || kgenome_nucleo_entry_arg(row, NULL) != x->entry))
			bad = 1;
		if (bad) {
			printf("  FAIL doc_oracle %s (row %u): roles", x->name, row);
			for (k = 0; k < 8u; k++)
				printf(" %u/%u", kgenome_nucleo_row_role(row, k), x->r[k]);
			printf(" res %u/%u entry %u/%u\n", kgenome_nucleo_row_res(row), x->res, kgenome_nucleo_entry_arg(row, NULL), x->entry);
			fails++;
		}
	}
	/* the entry's how */
	{
		unsigned how = 0;

		CK(kgenome_nucleo_entry_arg(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateRemoteThread"), &how) == 3 && how == KGENOME_NUCLEO_ENTRY_REMOTE);
		CK(kgenome_nucleo_entry_arg(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "StartServiceCtrlDispatcherA"), &how) == 0 && how == KGENOME_NUCLEO_ENTRY_FIELD);
		CK(kgenome_nucleo_entry_arg(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateThread"), &how) == 2 && how == KGENOME_NUCLEO_ENTRY_DIRECT);
		CK(kgenome_nucleo_entry_arg(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "Sleep"), &how) == NO && how == 0);
		CK(kgenome_nucleo_entry_arg(0, &how) == NO && how == 0);
		CK(kgenome_nucleo_entry_arg(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateThread"), NULL) == 2);
	}
	/* fields, outs, releases */
	{
		uint16_t r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "WSARecv");

		CK(kgenome_nucleo_row_field(r, 1) && !kgenome_nucleo_row_field(r, 0) && !kgenome_nucleo_row_field(r, 9));
		r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "ZwCreateFile");
		CK(kgenome_nucleo_row_field(r, 2) && kgenome_nucleo_row_out(r, 0) == 0 && kgenome_nucleo_row_out(r, 1) == NO && kgenome_nucleo_row_out(r, 2) == NO);
		r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "VirtualFreeEx");
		CK(kgenome_nucleo_row_release(r) == 1);
		CK(kgenome_nucleo_row_release(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "VirtualAlloc")) == NO);
		CK(kgenome_nucleo_row_out(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateProcessA"), 0) == 9);
		CK(kgenome_nucleo_row_out(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "RegCreateKeyExA"), 0) == 7);
	}
	/* a fact-only row: found by row_of, no word, no id */
	{
		uint16_t r = kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateTimerQueueTimer"), id = 1;

		CK(r != 0 && kgenome_nucleo_row_cap(r) == KGENOME_NUCLEO_NONE);
		CK(kgenome_nucleo_name_lookup(KGENOME_NUCLEO_T_PE, "CreateTimerQueueTimer", &id) == KGENOME_NUCLEO_NONE && id == r);
		CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, "CloseHandle") == KGENOME_NUCLEO_NONE);
		CK(kgenome_nucleo_row_cap(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "SetServiceStatus")) == KGENOME_NUCLEO_BACKGROUND);
	}
	/* row 0 and past the end answer nothing */
	CK(kgenome_nucleo_row_role(0, 0) == 0 && kgenome_nucleo_row_res(0) == KGENOME_NUCLEO_RES_STATUS && !kgenome_nucleo_row_hands_on(0));
	CK(kgenome_nucleo_row_role(0xffffu, 0) == 0 && kgenome_nucleo_row_out(0xffffu, 0) == NO && kgenome_nucleo_row_release(0xffffu) == NO);
	CK(kgenome_nucleo_row_role(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "connect"), 8) == 0);
	CK(kgenome_nucleo_row_cap(0) == KGENOME_NUCLEO_NONE && kgenome_nucleo_row_cap(0xffffu) == KGENOME_NUCLEO_NONE);
	CK(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "ZwProtectVirtualMemory") != 0);      /* unverified: kept, the capability's shape */
	CK(kgenome_nucleo_row_hands_on(kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "ZwProtectVirtualMemory")) == 1);
	/* the call's answer: the row when there is one, the capability's otherwise */
	CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_EXEC_IMAGE, 0, 0) == PTH);
	CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_EXEC_IMAGE, kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateProcessA"), 1) == VAL);
	CK(kgenome_nucleo_call_role(KGENOME_NUCLEO_EXEC_IMAGE, kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "CreateProcessA"), 0) == PTH);
	CK(kgenome_nucleo_call_hands_on(KGENOME_NUCLEO_LIB_OPEN, 0) == 0);
	CK(kgenome_nucleo_call_hands_on(KGENOME_NUCLEO_LIB_OPEN, kgenome_nucleo_row_of(KGENOME_NUCLEO_T_PE, "LoadLibraryW")) == 1);
}

/* The old per-capability answers, written out as they were (diag_hit.c's switch, nucleo.c's hands_on list and name_arg). */
static uint8_t old_role(uint16_t cap, unsigned i)
{
	switch (cap) {
	case KGENOME_NUCLEO_MEM_READ: case KGENOME_NUCLEO_READ: case KGENOME_NUCLEO_NET_READ:
		return i == 1u ? BUF : i == 0u ? FD : 0;
	case KGENOME_NUCLEO_MEM_WRITE: case KGENOME_NUCLEO_WRITE: case KGENOME_NUCLEO_NET_WRITE:
		return i == 1u ? SRC : i == 0u ? FD : 0;
	case KGENOME_NUCLEO_COPY_FROM_USER: case KGENOME_NUCLEO_COPY_TO_USER:
		return i == 0u ? BUF : i == 1u ? SRC : 0;
	case KGENOME_NUCLEO_NET_CONNECT: case KGENOME_NUCLEO_NET_BIND: case KGENOME_NUCLEO_NET_LISTEN: case KGENOME_NUCLEO_NET_ACCEPT:
	case KGENOME_NUCLEO_FD_REDIR: case KGENOME_NUCLEO_FD_NONBLOCK: case KGENOME_NUCLEO_NET_HDRINCL:
		return i == 0u ? FD : 0;
	case KGENOME_NUCLEO_EXEC_IMAGE:
		return i == 0u ? PTH : 0;
	case KGENOME_NUCLEO_DECODE: case KGENOME_NUCLEO_EVAL: case KGENOME_NUCLEO_CREATE:
		return i == 0u ? VAL : 0;
	case KGENOME_NUCLEO_DYNCALL: case KGENOME_NUCLEO_DYNLOAD:
		return i == 0u ? TGT : 0;
	case KGENOME_NUCLEO_CRED_SET: case KGENOME_NUCLEO_KPROBE_REG: case KGENOME_NUCLEO_KPROBE_UNREG: case KGENOME_NUCLEO_LIST_HIDE:
		return i == 0u ? BUF : 0;
	default:
		return 0;
	}
}

static int old_hands(uint16_t cap)
{
	switch (cap) {
	case KGENOME_NUCLEO_ALLOC: case KGENOME_NUCLEO_ALLOC_EXEC: case KGENOME_NUCLEO_HEAP: case KGENOME_NUCLEO_NET_OPEN:
	case KGENOME_NUCLEO_NET_RAW: case KGENOME_NUCLEO_NET_ACCEPT: case KGENOME_NUCLEO_FILE_OPEN: case KGENOME_NUCLEO_MEMFD:
	case KGENOME_NUCLEO_PIPE_OPEN: case KGENOME_NUCLEO_CRED_PREPARE: case KGENOME_NUCLEO_KSYM_LOOKUP: case KGENOME_NUCLEO_SYMBOL_GET:
		return 1;
	default:
		return 0;
	}
}

static void cap_unchanged(void)
{
	static const char *const z[] = {
		"connect", "bind", "listen", "shutdown", "close", "mprotect", "munmap", "chmod", "fchmod", "fchmodat", "chdir", "chroot",
		"setuid", "setgid", "setreuid", "setresuid", "unlink", "unlinkat", "rename", "renameat", "utime", "utimes", "utimensat",
		"init_module", "finit_module", "delete_module", "setns", "unshare", "pivot_root"
	};
	uint32_t c;
	unsigned i, bad = 0;

	for (c = 0; c < 0x10000u; c++) {
		for (i = 0; i < 8u; i++)
			if (kgenome_diag_role_of_arg((uint16_t)c, i) != (i < 6u ? old_role((uint16_t)c, i) : 0u))
				bad++;
		if (kgenome_nucleo_hands_on((uint16_t)c, NULL) != old_hands((uint16_t)c))
			bad++;
	}
	CK(bad == 0);
	for (i = 0; i < sizeof z / sizeof z[0]; i++)
		if (!kgenome_nucleo_sys_zero_on_success(z[i])) {
			printf("  FAIL zero-on-success lost %s\n", z[i]);
			fails++;
		}
	CK(!kgenome_nucleo_sys_zero_on_success("socket") && !kgenome_nucleo_sys_zero_on_success("execve") && !kgenome_nucleo_sys_zero_on_success("mmap"));
	CK(!kgenome_nucleo_sys_zero_on_success(NULL) && !kgenome_nucleo_sys_zero_on_success("") && !kgenome_nucleo_sys_zero_on_success("connec"));
	CK(!kgenome_nucleo_sys_zero_on_success("CreatePipe"));       /* the ELF table's question: a PE name is not a syscall */
	{
		unsigned arg = 9;

		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_KSYM_LOOKUP, &arg) == KGENOME_NAME_DIRECT && arg == 0);
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_SYMBOL_GET, &arg) == KGENOME_NAME_DIRECT && arg == 0);
		arg = 9;
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_KPROBE_REG, &arg) == KGENOME_NAME_OBJECT && arg == 0);
		arg = 9;
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_ALLOC, &arg) == 0 && arg == 0);
		CK(kgenome_nucleo_name_arg(KGENOME_NUCLEO_KPROBE_UNREG, NULL) == 0);
	}
	/* the hand-on names of the ELF table that a route passes: unchanged except closesocket */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "mmap") == 1 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_ALLOC, "mprotect") == 0);
	/* pipe was pinned at 1 here (ROWS-ELF-1, the wrong answer): its row now says status0 - see rows_elf_1 */
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_PIPE_OPEN, "pipe") == 0 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_FILE_OPEN, "open") == 1);
	CK(kgenome_nucleo_hands_on(KGENOME_NUCLEO_MEM_READ, "read") == 0 && kgenome_nucleo_hands_on(KGENOME_NUCLEO_NET_OPEN, "socketcall_unknown") == 1);
}

static void ordinals(void)
{
	CK(!strcmp(kgenome_nucleo_ordinal_name("WS2_32.dll", 23), "socket"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32", 4), "connect"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("Ws2_32.DLL", 19), "send"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 16), "recv"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 1), "accept"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 151), "__WSAFDIsSet"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 115), "WSAStartup"));
	/* the two tables differ at 10..12 */
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 10), "ioctlsocket") && !strcmp(kgenome_nucleo_ordinal_name("wsock32.dll", 10), "inet_addr"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 11), "inet_addr") && !strcmp(kgenome_nucleo_ordinal_name("WSOCK32.DLL", 11), "inet_ntoa"));
	CK(!strcmp(kgenome_nucleo_ordinal_name("ws2_32.dll", 12), "inet_ntoa") && !strcmp(kgenome_nucleo_ordinal_name("wsock32", 12), "ioctlsocket"));
	/* nothing else */
	CK(!kgenome_nucleo_ordinal_name("ws2_32.dll", 0) && !kgenome_nucleo_ordinal_name("ws2_32.dll", 24) && !kgenome_nucleo_ordinal_name("ws2_32.dll", 500));
	CK(!kgenome_nucleo_ordinal_name("ws2_32.dll", 58) && !kgenome_nucleo_ordinal_name("ws2_32.dll", 0xffffffffu));
	CK(!kgenome_nucleo_ordinal_name("kernel32.dll", 23) && !kgenome_nucleo_ordinal_name(NULL, 23) && !kgenome_nucleo_ordinal_name("", 23));
	CK(!kgenome_nucleo_ordinal_name("ws2_32.dllx", 23) && !kgenome_nucleo_ordinal_name("ws2_32.", 23) && !kgenome_nucleo_ordinal_name("ws2_3", 23));
	CK(!kgenome_nucleo_ordinal_name("ws2_32x.dll", 23) && !kgenome_nucleo_ordinal_name("ws2_32.exe", 23) && !kgenome_nucleo_ordinal_name("ws2_32.dl", 23));
	/* every name an ordinal gives that is a socket call has a row of the PE table (or none, by intent): connect, recv, send, socket */
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, kgenome_nucleo_ordinal_name("ws2_32.dll", 23)) == KGENOME_NUCLEO_NET_OPEN);
	CK(kgenome_nucleo_cap_of_name(KGENOME_NUCLEO_T_PE, kgenome_nucleo_ordinal_name("wsock32.dll", 4)) == KGENOME_NUCLEO_NET_CONNECT);
}

/* Over every row the tables hold: the facts a shape must not contradict. Ids are 1-based over the tables laid end to end. */
static void invariants(void)
{
	uint32_t row, n = 0, entries = 0;
	unsigned bad = 0;

	for (row = 1; row < 0x10000u && kgenome_nucleo_name_of((uint16_t)row); row++) {
		uint8_t seen[KGENOME_DIAG_ROLE_COUNT];
		unsigned i, e, how;

		n++;
		memset(seen, 0, sizeof seen);
		for (i = 0; i < 8u; i++) {
			uint8_t r = kgenome_nucleo_row_role((uint16_t)row, i);

			if (r >= KGENOME_DIAG_ROLE_COUNT || (r && seen[r]++))
				bad++;
			if (kgenome_nucleo_row_field((uint16_t)row, i) && !r && kgenome_nucleo_entry_arg((uint16_t)row, NULL) != i)
				bad++;
		}
		e = kgenome_nucleo_entry_arg((uint16_t)row, &how);
		if (e != NO) {
			entries++;
			if (kgenome_nucleo_row_role((uint16_t)row, e) != TGT || !how)
				bad++;
		}
		for (i = 0; i < 2u; i++) {
			unsigned o = kgenome_nucleo_row_out((uint16_t)row, i);

			if (o != NO && o < 8u && kgenome_nucleo_row_role((uint16_t)row, o))
				bad++;
		}
		if (kgenome_nucleo_row_res((uint16_t)row) > KGENOME_NUCLEO_RES_NORET)
			bad++;
	}
	CK(bad == 0);
	CK(n > 1000u && entries >= 30u);
	/* the first id past the last row: no shape is read for it (the bound of the generated per-row array) */
	CK(kgenome_nucleo_row_role((uint16_t)row, 0) == 0 && kgenome_nucleo_row_res((uint16_t)row) == KGENOME_NUCLEO_RES_STATUS);
	CK(kgenome_nucleo_entry_arg((uint16_t)row, NULL) == NO && kgenome_nucleo_row_out((uint16_t)row, 0) == NO && !kgenome_nucleo_row_hands_on((uint16_t)row));
	CK(kgenome_nucleo_row_release((uint16_t)row) == NO && !kgenome_nucleo_row_field((uint16_t)row, 0));
}

int main(void)
{
	d1_closesocket();
	d2_protect();
	d3_ntstatus();
	d5_protect_ex();
	d6_createpipe();
	hand_constructors();
	x11_rows();
	rows_elf_1();
	elf_connect();
	openssl_elf();
	setid_value();
	doc_oracle();
	cap_unchanged();
	ordinals();
	invariants();
	printf("nucleo_rows: %d failure(s)\n", fails);
	return fails != 0;
}
