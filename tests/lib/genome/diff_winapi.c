/*
 * diff_winapi - every Windows API the interpreter models: its name, its argument count, its return
 * convention and what it does, in one table, and the proof that the table and the interpreter agree.
 *
 * A guest that resolves GetTickCount gets a stub address; the stub traps into winapi_do(), which switches on the
 * API's id. Three things can go wrong with that arrangement and none of them is visible from the guest's side
 * until a sample stops: a name in the table whose handler was never written (the call comes back as an
 * unhandled API), a handler whose argument count differs from the stub's `ret n` (a 32 bit guest's stack is off
 * by the difference), and a return value that is not what the API documents. This file closes all three:
 *
 *   TABLE     the emulator's list of APIs (kgenome_emu_win_api_*) and DOC below are the same set: every name
 *             has a row, every row a name, the argument counts agree, no name is listed twice
 *   HANDLER   each API is called, in a 32 bit and a 64 bit guest, with every argument zero. It must come back
 *             to its caller (ExitProcess and TerminateProcess end the run, RaiseException reaches the guest's
 *             dispatcher and, with no handler, is counted unhandled), it must not be unhandled otherwise, and in
 *             a 32 bit guest the stub must have removed exactly its own argument bytes (stdcall)
 *   RETURN    what comes back for those zero arguments is the row's value: a status, a BOOL, a handle, a count -
 *             or ANY where Windows leaves a NULL argument undefined (the cell of an Interlocked call is
 *             dereferenced) or the API returns nothing
 *   CONVENTION  a table of calls with real arguments, in both widths: strings in guest memory (ANSI and wide), the
 *             fifth to eighth argument on the stack above the 64 bit shadow space, pointer sized returns
 *
 * The rows say what the STUB does (the doc column), which is sometimes simpler than Windows on purpose; a row
 * that changes is a decision, and this is where it has to be made visible. Nothing here writes a file.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <phenotype/emu.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define CODE   0x400000ull
#define DATA   0x600000ull
#define STACK  0x7ff00000ull
#define IMAGE  0x140000000ull

static struct kgenome_emu *mk(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i, n = kgenome_emu_win_api_count();

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 1000000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_win_set_module(e, i, kgenome_emu_win_mod_base(i, bits));
	kgenome_emu_win_setup(e, bits == 32 ? 0x400000ull : IMAGE);
	kgenome_emu_win_set_heap(e, 0x1000000ull);
	/* the module images: one page of stubs each, as emu_unpack_pe_module.c writes them */
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_map(e, kgenome_emu_win_mod_base(i, bits) + KGENOME_EMU_WIN_STUB_RVA, NULL, 0,
				0x8000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	for (i = 0; i < n; i++) {
		uint64_t a = kgenome_emu_win_addr_of(e, kgenome_emu_win_api_name(i));
		uint8_t stub[16];
		unsigned argc = kgenome_emu_win_api_argc(i);
		uint32_t trap = kgenome_emu_win_api_trap(i);

		if (!a)
			continue;
		memset(stub, 0xcc, sizeof stub);
		stub[0] = 0xb8;
		memcpy(stub + 1, &trap, 4);
		if (bits == 32) {
			stub[5] = 0xcd; stub[6] = 0x80;
			if (argc) {
				uint16_t pop = (uint16_t)(argc * 4u);

				stub[7] = 0xc2;
				memcpy(stub + 8, &pop, 2);
			} else {
				stub[7] = 0xc3;
			}
		} else {
			stub[5] = 0x0f; stub[6] = 0x05; stub[7] = 0xc3;
		}
		kgenome_emu_write(e, a, stub, sizeof stub);
	}
	kgenome_emu_map(e, CODE, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

struct callres {
	uint64_t              ret;
	enum kgenome_emu_stop stop;
	int                   done;     /* came back to the HLT */
};

/* call API `name` with up to eight arguments */
static struct callres call(struct kgenome_emu *e, unsigned bits, const char *name, uint64_t a0, uint64_t a1,
			   uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7)
{
	struct callres r;
	uint64_t stub = kgenome_emu_win_addr_of(e, name);
	uint64_t args[8] = { a0, a1, a2, a3, a4, a5, a6, a7 };
	uint8_t code[256];
	unsigned n = 0, k, argc = 8;
	uint64_t rsp = STACK + 0x8000;

	memset(&r, 0, sizeof r);
	for (k = 0; k < kgenome_emu_win_api_count(); k++)
		if (!strcmp(kgenome_emu_win_api_name(k), name))
			argc = kgenome_emu_win_api_argc(k);
	CK(stub != 0, "the stub of %s exists", name);
	if (!stub)
		return r;
	if (bits == 32) {
		for (k = argc; k > 0; k--) {
			uint32_t v = (uint32_t)args[k - 1];

			code[n++] = 0x68;
			memcpy(code + n, &v, 4);
			n += 4;
		}
		code[n++] = 0xb8;
		{
			uint32_t s = (uint32_t)stub;

			memcpy(code + n, &s, 4);
			n += 4;
		}
		code[n++] = 0xff; code[n++] = 0xd0;           /* call eax */
		code[n++] = 0xf4;
	} else {
		/* the first four in registers, the rest in the caller's frame above a 32 byte shadow space */
		static const uint8_t mv[4][2] = { { 0x48, 0xb9 }, { 0x48, 0xba }, { 0x49, 0xb8 }, { 0x49, 0xb9 } };

		for (k = 0; k < 4; k++) {
			code[n++] = mv[k][0];
			code[n++] = mv[k][1];
			memcpy(code + n, &args[k], 8);
			n += 8;
		}
		for (k = 4; k < 8; k++)
			kgenome_emu_write(e, rsp + 0x20u + 8u * (k - 4u), &args[k], 8);
		code[n++] = 0x48; code[n++] = 0xb8;
		memcpy(code + n, &stub, 8);
		n += 8;
		code[n++] = 0xff; code[n++] = 0xd0;           /* call rax */
		code[n++] = 0xf4;
	}
	kgenome_emu_write(e, CODE, code, n);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, rsp);
	r.stop = kgenome_emu_run(e);
	r.done = kgenome_emu_get_rip(e) == CODE + n - 1u;
	r.ret = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
	if (bits == 32)
		r.ret &= 0xffffffffull;
	return r;
}


#define C0(e, b, nm)               call((e), (b), (nm), 0, 0, 0, 0, 0, 0, 0, 0)
#define C1(e, b, nm, x)            call((e), (b), (nm), (x), 0, 0, 0, 0, 0, 0, 0)
#define C2(e, b, nm, x, y)         call((e), (b), (nm), (x), (y), 0, 0, 0, 0, 0, 0)
#define C3(e, b, nm, x, y, z)      call((e), (b), (nm), (x), (y), (z), 0, 0, 0, 0, 0)

static void put(struct kgenome_emu *e, uint64_t va, const void *p, unsigned n)
{
	kgenome_emu_write(e, va, p, n);
}

static void puts_(struct kgenome_emu *e, uint64_t va, const char *s)
{
	put(e, va, s, (unsigned)strlen(s) + 1u);
}

static void putw16(struct kgenome_emu *e, uint64_t va, const char *s)
{
	unsigned i;

	for (i = 0;; i++) {
		uint16_t c = (uint8_t)s[i];

		put(e, va + 2u * i, &c, 2);
		if (!c)
			break;
	}
}

static uint64_t get(struct kgenome_emu *e, uint64_t va, unsigned n)
{
	uint64_t v = 0;

	if (!kgenome_emu_read(e, va, &v, n))
		return 0xdeadbeefdeadbeefull;
	return v;
}


static void gets_(struct kgenome_emu *e, uint64_t va, char *out, unsigned cap)
{
	unsigned i;

	for (i = 0; i + 1u < cap; i++) {
		uint64_t c = 0;

		if (!kgenome_emu_read(e, va + i, &c, 1) || !c)
			break;
		out[i] = (char)c;
	}
	out[i] = 0;
}

/* ---- the table ------------------------------------------------------------------------------ */

enum kind {
	K_VAL,      /* exactly `val` */
	K_NEG1,     /* all ones in the guest's width: (HANDLE)-1, INVALID_FILE_ATTRIBUTES, (SIZE_T)-1 */
	K_NEG2,     /* (HANDLE)-2: the current thread pseudo handle */
	K_IMAGE,    /* the image's own base */
	K_PTR,      /* some non-zero pointer */
	K_ANY,      /* not pinned: no return value, or a NULL argument Windows leaves undefined */
	K_EXIT,     /* ends the run */
	K_UNH       /* reaches the guest's exception dispatcher; unhandled when the guest has none */
};

struct doc {
	const char *name;
	unsigned    argc;
	enum kind   kind;
	uint64_t    val;
	const char *what;
};

static const struct doc DOC[] = {
	{ "GetModuleHandleA", 1, K_IMAGE, 0, "NULL names the calling process: the image base (the PE loader supplies it)" },
	{ "GetModuleHandleW", 1, K_IMAGE, 0, "as GetModuleHandleA, wide name" },
	{ "GetProcAddress", 2, K_VAL, 0x0, "NULL module or name: 0 (a name the table lacks gets a miss thunk, a module with exports its stub)" },
	{ "LoadLibraryA", 1, K_VAL, 0x0, "NULL name: 0; a modelled library its base, an unknown one a handle with no image, a sandbox tell is refused" },
	{ "LoadLibraryW", 1, K_VAL, 0x0, "as LoadLibraryA, wide name" },
	{ "VirtualAlloc", 4, K_VAL, 0x0, "size 0 fails: NULL; otherwise fresh zero pages from the Windows arena, never reclaimed" },
	{ "VirtualFree", 3, K_VAL, 0x1, "always TRUE: memory is not given back, what the run wrote is what the harvest reads" },
	{ "VirtualProtect", 4, K_VAL, 0x0, "FALSE for a range that is not mapped" },
	{ "ExitProcess", 1, K_EXIT, 0, "ends the run (stop EXIT); never returns" },
	{ "GetCurrentProcess", 0, K_NEG1, 0, "the pseudo handle (HANDLE)-1" },
	{ "IsDebuggerPresent", 0, K_VAL, 0x0, "FALSE, always: a debugger is what the environment hides" },
	{ "GetLastError", 0, K_VAL, 0x0, "the last error the guest or the environment set; 0 at start" },
	{ "SetLastError", 1, K_ANY, 0, "stores the code; no return value" },
	{ "GetVersion", 0, K_VAL, 0x4a65000a, "10.0 build 19045, major in the low byte (see the stub comment)" },
	{ "GetCurrentProcessId", 0, K_VAL, 0x1000, "a fixed plausible pid, 0x1000" },
	{ "GetTickCount", 0, K_VAL, 0x0, "(instructions executed >> 16): moves forward and only forward" },
	{ "AddVectoredExceptionHandler", 2, K_VAL, 0x0, "NULL handler: NULL; else the handler address is the handle" },
	{ "RemoveVectoredExceptionHandler", 1, K_VAL, 0x0, "a handle that is not registered: 0" },
	{ "GetProcessHeap", 0, K_VAL, 0x1000000, "the one heap, 0x1000000" },
	{ "HeapAlloc", 3, K_VAL, 0x0, "size 0 is refused: NULL; fresh zeroed page-granular block, recorded for HeapSize/HeapReAlloc" },
	{ "HeapFree", 3, K_VAL, 0x1, "TRUE; the block is marked freed, memory is not reused" },
	{ "HeapReAlloc", 4, K_VAL, 0x0, "a new block holding the old contents up to the smaller size; NULL for size 0" },
	{ "HeapSize", 3, K_NEG1, 0, "the allocated size of a live block, (SIZE_T)-1 for anything else" },
	{ "VirtualQuery", 3, K_VAL, 0x0, "NULL output buffer: 0 bytes; otherwise MEMORY_BASIC_INFORMATION for one committed RWX page" },
	{ "GetSystemInfo", 1, K_ANY, 0, "fills SYSTEM_INFO (AMD64, 4 KiB pages); no return value" },
	{ "Sleep", 1, K_ANY, 0, "returns at once; no return value" },
	{ "QueryPerformanceCounter", 1, K_VAL, 0x1, "TRUE" },
	{ "QueryPerformanceFrequency", 1, K_VAL, 0x1, "TRUE; a fixed frequency" },
	{ "GetSystemTimeAsFileTime", 1, K_ANY, 0, "fills the FILETIME; no return value" },
	{ "GetCurrentThreadId", 0, K_VAL, 0x2000, "a fixed plausible tid, 0x2000" },
	{ "GetCurrentThread", 0, K_NEG2, 0, "the pseudo handle (HANDLE)-2" },
	{ "TlsAlloc", 0, K_VAL, 0x0, "slot indices count up from 0; none past 64 (TLS_OUT_OF_INDEXES)" },
	{ "TlsGetValue", 1, K_VAL, 0x0, "the value stored, 0 for an unset slot" },
	{ "TlsSetValue", 2, K_VAL, 0x1, "TRUE" },
	{ "TlsFree", 1, K_VAL, 0x1, "TRUE" },
	{ "InitializeCriticalSection", 1, K_ANY, 0, "no-op: one thread; no return value" },
	{ "EnterCriticalSection", 1, K_ANY, 0, "no-op: one thread; no return value" },
	{ "LeaveCriticalSection", 1, K_ANY, 0, "no-op: one thread; no return value" },
	{ "DeleteCriticalSection", 1, K_ANY, 0, "no-op: one thread; no return value" },
	{ "FlushInstructionCache", 3, K_VAL, 0x1, "TRUE" },
	{ "GetStdHandle", 1, K_VAL, 0x10, "0x10 for every device" },
	{ "CloseHandle", 1, K_VAL, 0x1, "TRUE" },
	{ "SetUnhandledExceptionFilter", 1, K_VAL, 0x0, "stores the filter; returns the previous one (NULL at start)" },
	{ "GetModuleFileNameA", 3, K_VAL, 0x0, "a NULL buffer: 0; else the invented image path, truncated to the buffer and terminated" },
	{ "GetModuleFileNameW", 3, K_VAL, 0x0, "as GetModuleFileNameA, wide" },
	{ "GetCommandLineA", 0, K_PTR, 0, "a pointer to the invented command line" },
	{ "GetCommandLineW", 0, K_PTR, 0, "a pointer to the invented command line, wide" },
	{ "lstrlenA", 1, K_VAL, 0x0, "the length of the string; 0 for NULL" },
	{ "RtlAddFunctionTable", 3, K_VAL, 0x1, "TRUE" },
	{ "RtlAllocateHeap", 3, K_VAL, 0x0, "the same allocator as HeapAlloc" },
	{ "RtlFreeHeap", 3, K_VAL, 0x1, "the same as HeapFree" },
	{ "NtQueryInformationProcess", 5, K_VAL, 0xc0000003, "STATUS_INVALID_INFO_CLASS for a class the environment does not answer" },
	{ "FreeLibrary", 1, K_VAL, 0x1, "TRUE" },
	{ "LocalAlloc", 2, K_VAL, 0x0, "the same arena as HeapAlloc; 0 for size 0" },
	{ "LocalFree", 1, K_VAL, 0x0, "0 (NULL) is success" },
	{ "GlobalAlloc", 2, K_VAL, 0x0, "as LocalAlloc" },
	{ "GlobalFree", 1, K_VAL, 0x0, "0 (NULL) is success" },
	{ "lstrcmpA", 2, K_VAL, 0x0, "signed byte difference, 0 for equal" },
	{ "lstrcmpiA", 2, K_VAL, 0x0, "as lstrcmpA, case blind" },
	{ "lstrcpyA", 2, K_VAL, 0x0, "copies and returns the destination; 0 for an unreadable source" },
	{ "lstrcatA", 2, K_VAL, 0x0, "appends and returns the destination; 0 for an unreadable source" },
	{ "lstrlenW", 1, K_VAL, 0x0, "length in characters; 0 for NULL" },
	{ "MultiByteToWideChar", 6, K_VAL, 0x0, "characters written, or needed when the output size is 0; 0 with the last error set on failure" },
	{ "WideCharToMultiByte", 8, K_VAL, 0x0, "bytes written, or needed when the output size is 0; 0 with the last error set on failure" },
	{ "OutputDebugStringA", 1, K_ANY, 0, "ignored; no return value" },
	{ "SetErrorMode", 1, K_VAL, 0x0, "returns the previous mode, 0" },
	{ "GetStartupInfoA", 1, K_ANY, 0, "sets cb only; no return value" },
	{ "GetStartupInfoW", 1, K_ANY, 0, "sets cb only; no return value" },
	{ "GetSystemDirectoryA", 2, K_VAL, 0x14, "the length of the path plus one when the buffer cannot hold it (20 for C:\\Windows\\System32), else the length" },
	{ "GetWindowsDirectoryA", 2, K_VAL, 0xb, "the length of the path plus one when the buffer cannot hold it (11 for C:\\Windows), else the length" },
	{ "GetTempPathA", 2, K_VAL, 0x11, "the length of the invented path plus one when the buffer cannot hold it, else the length" },
	{ "GetFileAttributesA", 1, K_NEG1, 0, "INVALID_FILE_ATTRIBUTES: every file the guest names is absent" },
	{ "CreateFileA", 7, K_NEG1, 0, "INVALID_HANDLE_VALUE: no file system is modelled" },
	{ "ReadFile", 5, K_VAL, 0x0, "0: no file is ever open" },
	{ "WriteFile", 5, K_VAL, 0x0, "0: no file is ever open" },
	{ "SetFilePointer", 4, K_VAL, 0x0, "0: no file is ever open" },
	{ "GetFileSize", 2, K_NEG1, 0, "INVALID_FILE_SIZE for an unknown handle" },
	{ "CreateThread", 6, K_VAL, 0x0, "NULL: there is one instruction pointer, a thread reported started would never run" },
	{ "ResumeThread", 1, K_NEG1, 0, "(DWORD)-1: no thread exists" },
	{ "WaitForSingleObject", 2, K_VAL, 0x0, "WAIT_OBJECT_0" },
	{ "TerminateProcess", 2, K_EXIT, 0, "ends the run (stop EXIT)" },
	{ "RaiseException", 4, K_UNH, 0, "hands the exception to the guest dispatcher; with no handler it is reported unhandled" },
	{ "UnhandledExceptionFilter", 1, K_VAL, 0x1, "EXCEPTION_EXECUTE_HANDLER" },
	{ "InterlockedIncrement", 1, K_ANY, 0, "the incremented value (the cell is read and written in guest memory)" },
	{ "InterlockedDecrement", 1, K_ANY, 0, "the decremented value" },
	{ "NtProtectVirtualMemory", 5, K_VAL, 0x0, "STATUS_SUCCESS" },
	{ "NtAllocateVirtualMemory", 6, K_VAL, 0xc0000017, "STATUS_NO_MEMORY for a request the arena cannot place" },
	{ "RtlGetVersion", 1, K_VAL, 0xc000000d, "STATUS_INVALID_PARAMETER for a NULL structure" },
	{ "LdrLoadDll", 4, K_VAL, 0xc0000135, "STATUS_DLL_NOT_FOUND for a name that does not resolve to a library" },
	{ "LdrGetProcedureAddress", 4, K_VAL, 0xc0000139, "STATUS_ENTRYPOINT_NOT_FOUND for an unresolvable name" },
	{ "InitializeCriticalSectionAndSpinCount", 2, K_VAL, 0x1, "TRUE" },
	{ "IsProcessorFeaturePresent", 1, K_VAL, 0x0, "FALSE: the machine reports no optional feature" },
	{ "IsValidCodePage", 1, K_ANY, 0, "TRUE (every page is accepted)" },
	{ "IsBadReadPtr", 2, K_ANY, 0, "walks the range in guest memory: TRUE when a byte is not readable" },
	{ "IsBadWritePtr", 2, K_ANY, 0, "walks the range in guest memory: TRUE when a byte is not writable" },
	{ "InterlockedExchange", 2, K_ANY, 0, "the previous value of the cell" },
	{ "InterlockedCompareExchange", 3, K_ANY, 0, "the previous value of the cell" },
	{ "SetHandleCount", 1, K_VAL, 0x0, "0" },
	{ "SetStdHandle", 2, K_VAL, 0x1, "TRUE" },
	{ "SetEnvironmentVariableA", 2, K_ANY, 0, "TRUE" },
	{ "SetEnvironmentVariableW", 2, K_ANY, 0, "TRUE" },
	{ "SetConsoleCtrlHandler", 2, K_VAL, 0x1, "TRUE" },
	{ "FreeEnvironmentStringsA", 1, K_VAL, 0x1, "TRUE" },
	{ "FreeEnvironmentStringsW", 1, K_VAL, 0x1, "TRUE" },
	{ "FlushFileBuffers", 1, K_VAL, 0x1, "TRUE" },
	{ "FindClose", 1, K_VAL, 0x1, "TRUE" },
	{ "DecodePointer", 1, K_VAL, 0x0, "identity" },
	{ "EncodePointer", 1, K_VAL, 0x0, "identity" },
	{ "DeleteFileA", 1, K_VAL, 0x1, "TRUE" },
	{ "DisableThreadLibraryCalls", 1, K_VAL, 0x1, "TRUE" },
	{ "HeapCreate", 3, K_VAL, 0x1000000, "the one heap" },
	{ "HeapDestroy", 1, K_VAL, 0x1, "TRUE" },
	{ "GetCPInfo", 2, K_VAL, 0x0, "NULL structure: 0; else MaxCharSize 2, default character ?, no lead byte ranges" },
	{ "GetACP", 0, K_VAL, 0x4e4, "1252" },
	{ "GetOEMCP", 0, K_VAL, 0x1b5, "437" },
	{ "IsUserAnAdmin", 0, K_VAL, 0x0, "FALSE" },
	{ "SHGetFolderPathA", 5, K_VAL, 0x80004005, "E_FAIL: no shell folders are modelled" },
	{ "CoInitialize", 1, K_VAL, 0x0, "S_OK" },
	{ "CoUninitialize", 0, K_ANY, 0, "no return value" },
	{ "WSAStartup", 2, K_VAL, 0x0, "0 (success); the version 2.2 is written to WSADATA when the pointer is given" },
	{ "WSACleanup", 0, K_VAL, 0x0, "0 (success)" },
	{ "WSASocketA", 6, K_VAL, 0x100, "a fake socket handle, 0x100 and up" },
	{ "WSASocketW", 6, K_VAL, 0x100, "a fake socket handle, 0x100 and up" },
	{ "socket", 3, K_VAL, 0x100, "a fake socket handle, 0x100 and up" },
	{ "connect", 3, K_VAL, 0x0, "0 (success); nothing is connected" },
	{ "recv", 4, K_VAL, 0x0, "the length asked for; the first read of a socket answers a 4 byte size, 0x1000 (a stager reads it as a length prefix)" },
	{ "send", 4, K_VAL, 0x0, "the length asked for; nothing is sent" },
	{ "sendto", 6, K_VAL, 0x0, "as send" },
	{ "recvfrom", 6, K_VAL, 0x0, "as recv" },
	{ "closesocket", 1, K_VAL, 0x0, "0 (success)" },
	{ "bind", 3, K_VAL, 0x0, "0 (success)" },
	{ "listen", 2, K_VAL, 0x0, "0 (success)" },
	{ "accept", 3, K_VAL, 0x100, "a fake socket handle" },
	{ "shutdown", 2, K_VAL, 0x0, "0 (success)" },
	{ "setsockopt", 5, K_VAL, 0x0, "0 (success)" },
	{ "ioctlsocket", 3, K_VAL, 0x0, "0 (success)" },
};

#define NDOC (sizeof DOC / sizeof DOC[0])

static void t_table(void)
{
	unsigned n = kgenome_emu_win_api_count(), i, j;

	CK(n == NDOC, "the emulator models %u APIs and the table documents %zu", n, NDOC);
	for (i = 0; i < n; i++) {
		const char *nm = kgenome_emu_win_api_name(i);
		unsigned found = 0;

		for (j = 0; j < NDOC; j++)
			if (!strcmp(DOC[j].name, nm)) {
				found++;
				CK(DOC[j].argc == kgenome_emu_win_api_argc(i), "%s: the table says %u argument(s), the stub pops %u", nm,
				   DOC[j].argc, kgenome_emu_win_api_argc(i));
				CK(DOC[j].what && DOC[j].what[0], "%s has a documented semantic", nm);
			}
		CK(found == 1, "%s has exactly one row in the table (%u)", nm, found);
	}
	for (j = 0; j < NDOC; j++) {
		unsigned found = 0;

		for (i = 0; i < n; i++)
			found += !strcmp(DOC[j].name, kgenome_emu_win_api_name(i));
		CK(found == 1, "the row %s names an API of the emulator (%u)", DOC[j].name, found);
	}
}

static void t_handlers(unsigned bits)
{
	unsigned i;

	for (i = 0; i < NDOC; i++) {
		struct kgenome_emu *e = mk(bits);
		struct callres r;
		unsigned unh0;
		uint64_t neg1 = bits == 32 ? 0xffffffffull : ~0ull;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		unh0 = kgenome_emu_unhandled(e);
		r = call(e, bits, DOC[i].name, 0, 0, 0, 0, 0, 0, 0, 0);
		switch (DOC[i].kind) {
		case K_EXIT:
			CK(r.stop == KGENOME_EMU_STOP_EXIT && !r.done, "%s (%u bit): ends the run (stop %s)", DOC[i].name, bits,
			   kgenome_emu_stop_name(r.stop));
			break;
		case K_UNH:
			CK(r.done && kgenome_emu_unhandled(e) == unh0 + 1u, "%s (%u bit): an exception nobody handles is counted (%u)", DOC[i].name,
			   bits, kgenome_emu_unhandled(e) - unh0);
			break;
		default:
			CK(r.done, "%s (%u bit): comes back to its caller (stop %s)", DOC[i].name, bits, kgenome_emu_stop_name(r.stop));
			CK(kgenome_emu_unhandled(e) == unh0, "%s (%u bit): has a handler (unhandled count moved)", DOC[i].name, bits);
			CK(kgenome_emu_get_reg(e, KGENOME_EMU_RSP) == STACK + 0x8000, "%s (%u bit): the stack is where it was after the call (rsp %#llx)",
			   DOC[i].name, bits, (unsigned long long)kgenome_emu_get_reg(e, KGENOME_EMU_RSP));
			break;
		}
		switch (DOC[i].kind) {
		case K_VAL:
			CK(r.ret == DOC[i].val, "%s (%u bit): returns %#llx for zero arguments (%#llx)", DOC[i].name, bits,
			   (unsigned long long)DOC[i].val, (unsigned long long)r.ret);
			break;
		case K_NEG1:
			CK(r.ret == neg1, "%s (%u bit): returns -1 (%#llx)", DOC[i].name, bits, (unsigned long long)r.ret);
			break;
		case K_NEG2:
			CK(r.ret == neg1 - 1u, "%s (%u bit): returns -2 (%#llx)", DOC[i].name, bits, (unsigned long long)r.ret);
			break;
		case K_IMAGE:
			CK(r.ret == (bits == 32 ? 0x400000ull : IMAGE), "%s (%u bit): NULL is the image base (%#llx)", DOC[i].name, bits,
			   (unsigned long long)r.ret);
			break;
		case K_PTR:
			CK(r.ret != 0 && (bits == 64 || r.ret < 0x100000000ull), "%s (%u bit): a pointer (%#llx)", DOC[i].name, bits,
			   (unsigned long long)r.ret);
			break;
		default:
			break;
		}
		kgenome_emu_free(e);
	}
}

/* ---- calls with real arguments, in both widths ----------------------------------------------- */

static void t_convention(unsigned bits)
{
	struct kgenome_emu *e = mk(bits);
	struct callres r;
	char buf[64];
	uint64_t a, b;
	uint32_t cell = 5;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	puts_(e, DATA, "hello");
	putw16(e, DATA + 0x40, "wide");
	puts_(e, DATA + 0x80, "abc");
	puts_(e, DATA + 0xa0, "abd");
	put(e, DATA + 0x100, &cell, 4);
	/* strings, ANSI and wide */
	r = C1(e, bits, "lstrlenA", DATA);
	CK(r.ret == 5, "lstrlenA(\"hello\") = 5 (%llu)", (unsigned long long)r.ret);
	r = C1(e, bits, "lstrlenW", DATA + 0x40);
	CK(r.ret == 4, "lstrlenW(L\"wide\") = 4 (%llu)", (unsigned long long)r.ret);
	r = C2(e, bits, "lstrcmpA", DATA + 0x80, DATA + 0xa0);
	CK((int32_t)r.ret < 0, "lstrcmpA(\"abc\", \"abd\") is negative (%d)", (int32_t)r.ret);
	r = C2(e, bits, "lstrcmpA", DATA + 0xa0, DATA + 0x80);
	CK((int32_t)r.ret > 0, "lstrcmpA(\"abd\", \"abc\") is positive");
	r = C2(e, bits, "lstrcmpA", DATA + 0x80, DATA + 0x80);
	CK(r.ret == 0, "lstrcmpA of equal strings is 0");
	/* six and eight arguments: the last ones are on the stack, above the shadow space in a 64 bit guest */
	r = call(e, bits, "MultiByteToWideChar", 0, 0, DATA, (uint64_t)-1, DATA + 0x200, 16, 0, 0);
	CK(r.ret == 6 && get(e, DATA + 0x200, 2) == 'h' && get(e, DATA + 0x20a, 2) == 0, "MultiByteToWideChar(-1) counts and writes the terminator (%llu)",
	   (unsigned long long)r.ret);
	r = call(e, bits, "MultiByteToWideChar", 0, 0, DATA, (uint64_t)-1, 0, 0, 0, 0);
	CK(r.ret == 6, "MultiByteToWideChar with no output asks for the size (%llu)", (unsigned long long)r.ret);
	r = call(e, bits, "MultiByteToWideChar", 0, 0, DATA, 5, DATA + 0x240, 3, 0, 0);
	CK(r.ret == 0, "MultiByteToWideChar into too small a buffer is 0");
	r = C1(e, bits, "GetLastError", 0);
	CK(r.ret == 122, "and sets ERROR_INSUFFICIENT_BUFFER (%llu)", (unsigned long long)r.ret);
	{
		uint16_t w[3] = { 0x00e9, 0x20ac, 0 };

		put(e, DATA + 0x300, w, sizeof w);
		r = call(e, bits, "WideCharToMultiByte", 65001, 0, DATA + 0x300, (uint64_t)-1, DATA + 0x340, 16, 0, 0);
		CK(r.ret == 6 && get(e, DATA + 0x340, 1) == 0xc3 && get(e, DATA + 0x341, 1) == 0xa9 && get(e, DATA + 0x342, 1) == 0xe2,
		   "WideCharToMultiByte to UTF-8: U+00E9 U+20AC is c3 a9 e2 82 ac 00 (%llu)", (unsigned long long)r.ret);
		r = call(e, bits, "WideCharToMultiByte", 0, 0, DATA + 0x300, 2, DATA + 0x380, 16, 0, DATA + 0x3c0);
		CK(r.ret == 2 && get(e, DATA + 0x380, 1) == 0xe9 && get(e, DATA + 0x381, 1) == '?' && get(e, DATA + 0x3c0, 4) == 1,
		   "WideCharToMultiByte to an ANSI page: U+00E9 stays, U+20AC is the default character and UsedDefaultChar is set");
	}
	/* the heap */
	r = C1(e, bits, "GetProcessHeap", 0);
	a = r.ret;
	r = C3(e, bits, "HeapAlloc", a, 8, 100);
	b = r.ret;
	CK(b != 0 && !(b & 0xfff), "HeapAlloc returns a block (%#llx)", (unsigned long long)b);
	r = C3(e, bits, "HeapSize", a, 0, b);
	CK(r.ret == 100, "HeapSize of it is 100");
	/* the interlocked family reads and writes the cell the guest names */
	r = C1(e, bits, "InterlockedIncrement", DATA + 0x100);
	CK(r.ret == 6 && get(e, DATA + 0x100, 4) == 6, "InterlockedIncrement returns and stores the new value");
	r = C2(e, bits, "InterlockedExchange", DATA + 0x100, 9);
	CK(r.ret == 6 && get(e, DATA + 0x100, 4) == 9, "InterlockedExchange returns the old value and stores the new");
	r = C3(e, bits, "InterlockedCompareExchange", DATA + 0x100, 1, 9);
	CK(r.ret == 9 && get(e, DATA + 0x100, 4) == 1, "InterlockedCompareExchange stores when the comparand matches");
	r = C3(e, bits, "InterlockedCompareExchange", DATA + 0x100, 7, 9);
	CK(r.ret == 1 && get(e, DATA + 0x100, 4) == 1, "and leaves the cell when it does not");
	/* thread-local storage */
	r = C0(e, bits, "TlsAlloc");
	a = r.ret;
	C2(e, bits, "TlsSetValue", a, 0x1234);
	r = C1(e, bits, "TlsGetValue", a);
	CK(r.ret == 0x1234, "TlsGetValue returns what TlsSetValue stored");
	/* the invented image path */
	r = C3(e, bits, "GetModuleFileNameA", 0, DATA + 0x400, 64);
	gets_(e, DATA + 0x400, buf, sizeof buf);
	CK(r.ret == strlen(buf) && !strncmp(buf, "C:\\Windows\\", 11), "GetModuleFileNameA(NULL) returns its length (%s)", buf);
	/* a pointer-sized return is the whole pointer in a 64 bit guest and fits 32 bits in the other */
	r = call(e, bits, "VirtualAlloc", 0, 0x1000, 0x3000, 4, 0, 0, 0, 0);
	CK(r.ret != 0 && !(r.ret & 0xfff) && (bits == 64 || r.ret < 0x100000000ull), "VirtualAlloc returns a page aligned pointer of the guest's width (%#llx)",
	   (unsigned long long)r.ret);
	CK(kgenome_emu_write(e, r.ret + 0xfff, "z", 1), "and the whole page is writable");
	kgenome_emu_free(e);
}

int main(void)
{
	t_table();
	t_handlers(32);
	t_handlers(64);
	t_convention(32);
	t_convention(64);
	printf("diff_winapi: %zu API(s) x 2 guest widths\n", NDOC);
	if (fails) {
		printf("diff_winapi: FAILED (%d)\n", fails);
		return 1;
	}
	printf("diff_winapi: ok\n");
	return 0;
}
