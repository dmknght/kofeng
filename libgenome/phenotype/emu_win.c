/*
 * emu_win.c - the Windows environment: the API table, modules, the allocator, import resolution.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- the Windows environment ----------------------------------------------
 *
 * WHY THERE IS ONE AT ALL, GIVEN WHAT emu.h SAYS ABOUT SYSCALLS.
 *
 * The Linux environment above is short because a packer stub "wants memory and
 * then it wants to hand over". A Windows stub wants the same two things and
 * cannot ask for them the same way: there is no syscall it may use, so it asks
 * kernel32, and to ask kernel32 it must first find it. That is the whole of
 * what this provides - a kernel32 to find, and answers to the handful of calls
 * a stub makes once it has.
 *
 * WHAT SAID IT WAS WORTH BUILDING. Four Themida protected PEs, measured: each
 * ran between 22 and 48 million instructions of its own arithmetic and then
 * stopped, three of them fetching from an address inside their own .idata -
 * an import thunk the Windows loader fills before the entry point runs and
 * which nothing here had filled. Every one of the four imports exactly one
 * function, kernel32!GetModuleHandleA, which is a protector's way of saying
 * "give me the base and I will find the rest myself".
 *
 * SO THE EXPORT DIRECTORY IS THE POINT, not the import thunk. Filling the
 * thunk alone answers the first call and nothing after it; a loader that has
 * the base walks the exports by name. emu_unpack_pe_module.c builds an image with a real
 * export directory whose every entry points at a stub below.
 *
 * HOW A STUB REACHES HERE. Each exported function is eight bytes that load an
 * id and trap - `syscall` on 64 bit, `int 0x80` on 32 - so the dispatch this
 * file already has for Linux carries these too. The ids are checked BEFORE the
 * i386 translation and sit in a range no kernel uses, so an ELF guest cannot
 * reach them by accident and a Windows guest cannot reach a Linux syscall by
 * accident either.
 */

/*
 * THE NAMES AND THE ARGUMENT COUNTS, IN ONE PLACE BECAUSE TWO READERS NEED
 * THEM TO AGREE.
 *
 * This file dispatches on the id; emu_unpack_pe_module.c writes an export directory that
 * maps each NAME to the stub for that id, and writes the stub, which on i386
 * must end in `ret n` with n the argument count because Windows makes the
 * callee pop. A table in each place is a table that disagrees after the first
 * edit, so there is one and it is exported.
 */
static const struct {
	uint8_t     mod;        /* an index into win_mod below */
	const char *name;
	uint8_t     argc;
} win_api[] = {
	{ KGENOME_EMU_WIN_MOD_K32, "GetModuleHandleA",    1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetModuleHandleW",    1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetProcAddress",      2 },
	{ KGENOME_EMU_WIN_MOD_K32, "LoadLibraryA",        1 },
	{ KGENOME_EMU_WIN_MOD_K32, "LoadLibraryW",        1 },
	{ KGENOME_EMU_WIN_MOD_K32, "VirtualAlloc",        4 },
	{ KGENOME_EMU_WIN_MOD_K32, "VirtualFree",         3 },
	{ KGENOME_EMU_WIN_MOD_K32, "VirtualProtect",      4 },
	{ KGENOME_EMU_WIN_MOD_K32, "ExitProcess",         1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCurrentProcess",   0 },
	{ KGENOME_EMU_WIN_MOD_K32, "IsDebuggerPresent",   0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetLastError",        0 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetLastError",        1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetVersion",          0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCurrentProcessId", 0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetTickCount",        0 },
	{ KGENOME_EMU_WIN_MOD_K32, "AddVectoredExceptionHandler",    2 },
	{ KGENOME_EMU_WIN_MOD_K32, "RemoveVectoredExceptionHandler", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetProcessHeap",       0 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapAlloc",            3 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapFree",             3 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapReAlloc",          4 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapSize",             3 },
	{ KGENOME_EMU_WIN_MOD_K32, "VirtualQuery",         3 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetSystemInfo",        1 },
	{ KGENOME_EMU_WIN_MOD_K32, "Sleep",                1 },
	{ KGENOME_EMU_WIN_MOD_K32, "QueryPerformanceCounter",   1 },
	{ KGENOME_EMU_WIN_MOD_K32, "QueryPerformanceFrequency", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetSystemTimeAsFileTime",   1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCurrentThreadId",   0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCurrentThread",     0 },
	{ KGENOME_EMU_WIN_MOD_K32, "TlsAlloc",             0 },
	{ KGENOME_EMU_WIN_MOD_K32, "TlsGetValue",          1 },
	{ KGENOME_EMU_WIN_MOD_K32, "TlsSetValue",          2 },
	{ KGENOME_EMU_WIN_MOD_K32, "TlsFree",              1 },
	{ KGENOME_EMU_WIN_MOD_K32, "InitializeCriticalSection", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "EnterCriticalSection", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "LeaveCriticalSection", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "DeleteCriticalSection", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "FlushInstructionCache", 3 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetStdHandle",         1 },
	{ KGENOME_EMU_WIN_MOD_K32, "CloseHandle",          1 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetUnhandledExceptionFilter", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetModuleFileNameA",   3 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetModuleFileNameW",   3 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCommandLineA",      0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCommandLineW",      0 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrlenA",             1 },
	/*
	 * ntdll's, and RtlAddFunctionTable is the one that matters on amd64:
	 * a protector that generates code at run time registers an unwind
	 * table for it, and a call that goes nowhere is a call through a null
	 * pointer. Answering "done" is truthful here in the only sense that
	 * matters - there is no unwinder in this build for the table to feed.
	 */
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlAddFunctionTable",       3 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlAllocateHeap",           3 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlFreeHeap",               3 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "NtQueryInformationProcess", 5 },
	{ KGENOME_EMU_WIN_MOD_K32, "FreeLibrary",           1 },
	{ KGENOME_EMU_WIN_MOD_K32, "LocalAlloc",            2 },
	{ KGENOME_EMU_WIN_MOD_K32, "LocalFree",             1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GlobalAlloc",           2 },
	{ KGENOME_EMU_WIN_MOD_K32, "GlobalFree",            1 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrcmpA",              2 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrcmpiA",             2 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrcpyA",              2 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrcatA",              2 },
	{ KGENOME_EMU_WIN_MOD_K32, "lstrlenW",              1 },
	{ KGENOME_EMU_WIN_MOD_K32, "MultiByteToWideChar",   6 },
	{ KGENOME_EMU_WIN_MOD_K32, "WideCharToMultiByte",   8 },
	{ KGENOME_EMU_WIN_MOD_K32, "OutputDebugStringA",    1 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetErrorMode",          1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetStartupInfoA",       1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetStartupInfoW",       1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetSystemDirectoryA",   2 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetWindowsDirectoryA",  2 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetTempPathA",          2 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetFileAttributesA",    1 },
	{ KGENOME_EMU_WIN_MOD_K32, "CreateFileA",           7 },
	{ KGENOME_EMU_WIN_MOD_K32, "ReadFile",              5 },
	{ KGENOME_EMU_WIN_MOD_K32, "WriteFile",             5 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetFilePointer",        4 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetFileSize",           2 },
	{ KGENOME_EMU_WIN_MOD_K32, "CreateThread",          6 },
	{ KGENOME_EMU_WIN_MOD_K32, "ResumeThread",          1 },
	{ KGENOME_EMU_WIN_MOD_K32, "WaitForSingleObject",   2 },
	{ KGENOME_EMU_WIN_MOD_K32, "TerminateProcess",      2 },
	{ KGENOME_EMU_WIN_MOD_K32, "RaiseException",        4 },
	{ KGENOME_EMU_WIN_MOD_K32, "UnhandledExceptionFilter", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "InterlockedIncrement",  1 },
	{ KGENOME_EMU_WIN_MOD_K32, "InterlockedDecrement",  1 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "NtProtectVirtualMemory",   5 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "NtAllocateVirtualMemory",  6 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlGetVersion",            1 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "LdrLoadDll",               4 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "LdrGetProcedureAddress",   4 },
	{ KGENOME_EMU_WIN_MOD_K32, "InitializeCriticalSectionAndSpinCount", 2 },
	{ KGENOME_EMU_WIN_MOD_K32, "IsProcessorFeaturePresent", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "IsValidCodePage",         1 },
	{ KGENOME_EMU_WIN_MOD_K32, "IsBadReadPtr",            2 },
	{ KGENOME_EMU_WIN_MOD_K32, "IsBadWritePtr",           2 },
	{ KGENOME_EMU_WIN_MOD_K32, "InterlockedExchange",     2 },
	{ KGENOME_EMU_WIN_MOD_K32, "InterlockedCompareExchange", 3 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetHandleCount",          1 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetStdHandle",            2 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetEnvironmentVariableA", 2 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetEnvironmentVariableW", 2 },
	{ KGENOME_EMU_WIN_MOD_K32, "SetConsoleCtrlHandler",   2 },
	{ KGENOME_EMU_WIN_MOD_K32, "FreeEnvironmentStringsA", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "FreeEnvironmentStringsW", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "FlushFileBuffers",        1 },
	{ KGENOME_EMU_WIN_MOD_K32, "FindClose",               1 },
	{ KGENOME_EMU_WIN_MOD_K32, "DecodePointer",           1 },
	{ KGENOME_EMU_WIN_MOD_K32, "EncodePointer",           1 },
	{ KGENOME_EMU_WIN_MOD_K32, "DeleteFileA",             1 },
	{ KGENOME_EMU_WIN_MOD_K32, "DisableThreadLibraryCalls", 1 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapCreate",              3 },
	{ KGENOME_EMU_WIN_MOD_K32, "HeapDestroy",             1 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetCPInfo",               2 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetACP",                  0 },
	{ KGENOME_EMU_WIN_MOD_K32, "GetOEMCP",                0 },
	{ KGENOME_EMU_WIN_MOD_SHELL32, "IsUserAnAdmin",       0 },
	{ KGENOME_EMU_WIN_MOD_SHELL32, "SHGetFolderPathA",    5 },
	{ KGENOME_EMU_WIN_MOD_OLE32, "CoInitialize",          1 },
	{ KGENOME_EMU_WIN_MOD_OLE32, "CoUninitialize",        0 },
	{ KGENOME_EMU_WIN_MOD_WS2, "WSAStartup",              2 },
	{ KGENOME_EMU_WIN_MOD_WS2, "WSACleanup",              0 },
	{ KGENOME_EMU_WIN_MOD_WS2, "WSASocketA",              6 },
	{ KGENOME_EMU_WIN_MOD_WS2, "WSASocketW",              6 },
	{ KGENOME_EMU_WIN_MOD_WS2, "socket",                  3 },
	{ KGENOME_EMU_WIN_MOD_WS2, "connect",                 3 },
	{ KGENOME_EMU_WIN_MOD_WS2, "recv",                    4 },
	{ KGENOME_EMU_WIN_MOD_WS2, "send",                    4 },
	{ KGENOME_EMU_WIN_MOD_WS2, "sendto",                  6 },
	{ KGENOME_EMU_WIN_MOD_WS2, "recvfrom",                6 },
	{ KGENOME_EMU_WIN_MOD_WS2, "closesocket",             1 },
	{ KGENOME_EMU_WIN_MOD_WS2, "bind",                    3 },
	{ KGENOME_EMU_WIN_MOD_WS2, "listen",                  2 },
	{ KGENOME_EMU_WIN_MOD_WS2, "accept",                  3 },
	{ KGENOME_EMU_WIN_MOD_WS2, "shutdown",                2 },
	{ KGENOME_EMU_WIN_MOD_WS2, "setsockopt",              5 },
	{ KGENOME_EMU_WIN_MOD_WS2, "ioctlsocket",             3 },
	/* kernel32's AddVectoredExceptionHandler forwards to these on Windows; a resolver that walks ntdll
	 * for them finds them there. Same handlers, same arguments. */
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlAddVectoredExceptionHandler",    2 },
	{ KGENOME_EMU_WIN_MOD_NTDLL, "RtlRemoveVectoredExceptionHandler", 1 },
	{ KGENOME_EMU_WIN_MOD_MSCOREE, "_CorExeMain",         0 },
	{ KGENOME_EMU_WIN_MOD_MSCOREE, "_CorDllMain",         3 },

};

/*
 * THE MODULES, AND WHY THERE IS MORE THAN ONE.
 *
 * kernel32 alone was enough to get a protector started and not to keep it
 * going. Measured with KOF_WIN_TRACE on one of the Themida samples: it takes
 * the kernel32 base, and then asks for five more libraries in a row -
 * user32, advapi32, ntdll, shell32, shlwapi - is told no to every one, and
 * dereferences one of the zeros it was given. The fault it stopped on was
 * never an exception to be handled; it was a module that was not there.
 *
 * A MODULE IS AN IMAGE, not an entry in a list, for the reason build_k32_pe
 * gives: a resolver that has a base walks the export directory at it. Each one
 * therefore gets its own image and its own stubs INSIDE that image, so that an
 * address resolved from a module falls within that module's range - which a
 * careful resolver checks, and which a shared stub page would fail.
 *
 * An empty module is still worth having. It answers "yes, loaded, here it is",
 * which is what the guest is testing for, and a name it then fails to resolve
 * comes back zero from a directory that really does not list it - the same
 * answer the real library would give for a name that is not in it.
 */
static const struct {
	const char *name;
	uint64_t    base64, base32;
} win_mod[KGENOME_EMU_WIN_MOD_COUNT] = {
	{ "kernel32.dll", 0x0000000180000000ull, 0x76000000ull },
	{ "ntdll.dll",    0x0000000181000000ull, 0x77000000ull },
	{ "user32.dll",   0x0000000182000000ull, 0x75000000ull },
	{ "advapi32.dll", 0x0000000183000000ull, 0x74000000ull },
	{ "shell32.dll",  0x0000000184000000ull, 0x73000000ull },
	{ "shlwapi.dll",  0x0000000185000000ull, 0x72000000ull },
	{ "msvcrt.dll",   0x0000000186000000ull, 0x71000000ull },
	{ "ole32.dll",    0x0000000187000000ull, 0x70000000ull },
	{ "kernelbase.dll", 0x0000000188000000ull, 0x6f000000ull },
	{ "ws2_32.dll",   0x0000000189000000ull, 0x6e000000ull },
	{ "mscoree.dll",  0x000000018a000000ull, 0x6d000000ull }
};

_Static_assert(sizeof win_api / sizeof win_api[0] == (size_t)KGENOME_EMU_WIN_API__LAST,
	       "the Windows API table and its enum have drifted apart");

unsigned    kgenome_emu_win_api_count(void) { return KGENOME_EMU_WIN_API_COUNT; }
const char *kgenome_emu_win_api_name(unsigned i)
{
	return i < KGENOME_EMU_WIN_API_COUNT ? win_api[i].name : 0;
}
unsigned    kgenome_emu_win_api_argc(unsigned i)
{
	return i < KGENOME_EMU_WIN_API_COUNT ? win_api[i].argc : 0;
}
unsigned    kgenome_emu_win_api_mod(unsigned i)
{
	return i < KGENOME_EMU_WIN_API_COUNT ? win_api[i].mod : 0;
}
uint32_t    kgenome_emu_win_api_trap(unsigned i) { return KGENOME_EMU_WIN_API_BASE + i; }

unsigned    kgenome_emu_win_mod_count(void) { return KGENOME_EMU_WIN_MOD_COUNT; }
const char *kgenome_emu_win_mod_name(unsigned i)
{
	return i < KGENOME_EMU_WIN_MOD_COUNT ? win_mod[i].name : 0;
}
uint64_t    kgenome_emu_win_mod_base(unsigned i, unsigned bits)
{
	if (i >= KGENOME_EMU_WIN_MOD_COUNT)
		return 0;
	return bits == 32u ? win_mod[i].base32 : win_mod[i].base64;
}

/*
 * Where an export sits INSIDE its own module: the stubs of one module are
 * numbered from zero within it, so the n-th function of user32 is at user32's
 * stub base plus n, not at the global index.
 */
unsigned kgenome_emu_win_api_slot(unsigned i)
{
	unsigned k, slot = 0;

	if (i >= KGENOME_EMU_WIN_API_COUNT)
		return 0;
	for (k = 0; k < i; k++)
		if (win_api[k].mod == win_api[i].mod)
			slot++;
	return slot;
}

void kgenome_emu_win_setup(struct kgenome_emu *e, uint64_t image_base)
{
	if (!e)
		return;
	e->win_image_base = image_base;
}

void kgenome_emu_win_set_heap(struct kgenome_emu *e, uint64_t heap)
{
	if (!e)
		return;
	e->win_heap = heap;
}

void kgenome_emu_count_mod_reads(struct kgenome_emu *e, int on)
{
	if (!e)
		return;
	e->count_mod_reads = (uint8_t)(on != 0);
}

/* When the run first left the section it started in, and where it went. The
 * number says how much of a budget is spent reaching a stage a static unpacker
 * may already have produced. */
int kgenome_emu_itrace(struct kgenome_emu *e, unsigned n)
{
	if (!e)
		return 0;
	free(e->itr);
	e->itr = NULL;
	e->itr_cap = e->itr_n = 0;
	if (!n)
		return 1;
	if (n > KGENOME_EMU_ITRACE_MAX)
		n = KGENOME_EMU_ITRACE_MAX;
	e->itr = calloc(n, sizeof *e->itr);
	if (!e->itr) {
		KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_MEM, "instruction trace not allocated");
		return 0;
	}
	e->itr_cap = n;
	e->itr_frozen = 0;
	return 1;
}

void kgenome_emu_itrace_at(struct kgenome_emu *e, uint64_t rip)
{
	if (e)
		e->itr_at = rip;
}

void kgenome_emu_itrace_until(struct kgenome_emu *e, uint64_t insn)
{
	if (e)
		e->itr_until = insn;
}

/* Or at the first import this environment could not resolve, which is upstream
 * of every wrong value that follows it. */
void kgenome_emu_itrace_on_null(struct kgenome_emu *e, int on)
{
	if (e)
		e->itr_on_null = on;
}

unsigned kgenome_emu_itrace_count(const struct kgenome_emu *e)
{
	if (!e || !e->itr)
		return 0;
	return e->itr_n < e->itr_cap ? e->itr_n : e->itr_cap;
}

/* Oldest first, so a caller reading 0..count-1 reads them in the order they
 * ran - which is the only order in which "where did that value come from"
 * can be answered. */
int kgenome_emu_itrace_get(const struct kgenome_emu *e, unsigned k, uint64_t *rip,
		       const char **text, const uint64_t **gpr)
{
	unsigned have = kgenome_emu_itrace_count(e), at;

	if (!have || k >= have)
		return 0;
	at = e->itr_n <= e->itr_cap ? k
				    : (unsigned)((e->itr_n - have + k) %
						 e->itr_cap);
	if (rip)  *rip  = e->itr[at].rip;
	if (text) *text = e->itr[at].txt;
	if (gpr)  *gpr  = e->itr[at].gpr;
	return 1;
}

void kgenome_emu_first_hop(const struct kgenome_emu *e, uint64_t *insn, uint64_t *rip)
{
	if (insn) *insn = e ? e->hop_first_insn : 0;
	if (rip)  *rip  = e ? e->hop_first_rip : 0;
}

/* And the last one, which is where execution had got to when the run ended:
 * the address Unipacker's dump writes as the entry point. See THIRD-PARTY.md.
 * hop_count says how many stages there were, so one hop can be told from ten. */
void kgenome_emu_last_hop(const struct kgenome_emu *e, uint64_t *rip, uint32_t *count)
{
	if (rip)   *rip   = e ? e->hop_last_rip : 0;
	if (count) *count = e ? e->hop_count : 0;
}

uint64_t kgenome_emu_mod_reads(const struct kgenome_emu *e, unsigned i)
{
	return e && i < KGENOME_EMU_WIN_MOD_COUNT ? e->mod_reads[i] : 0;
}

void kgenome_emu_win_set_module(struct kgenome_emu *e, unsigned i, uint64_t base)
{
	if (!e)
		return;
	if (i < KGENOME_EMU_WIN_MOD_COUNT)
		e->win_mod_base[i] = base;
	if (i == KGENOME_EMU_WIN_MOD_K32)
		e->win_k32_base = base;
}

static int win_eq_nocase(const char *a, const char *b)
{
	for (; *a && *b; a++, b++) {
		char x = *a, y = *b;

		if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
		if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
		if (x != y)
			return 0;
	}
	return *a == *b;
}

/*
 * The address of an exported function by name, which is three things at once:
 * what GetProcAddress answers with, what an export directory has to point at,
 * and what an import thunk has to be filled with. Public for the third, since
 * filling the thunks is the loader's job and emu_unpack_pe_module.c is the loader here.
 */
uint64_t kgenome_emu_win_addr_of(struct kgenome_emu *e, const char *name)
{
	unsigned i;

	if (!e || !name)
		return 0;

	for (i = 0; i < KGENOME_EMU_WIN_API_COUNT; i++) {
		uint64_t base;

		if (!win_eq_nocase(win_api[i].name, name))
			continue;
		base = e->win_mod_base[win_api[i].mod];
		if (!base)
			return 0;       /* that module was not mapped */
		return base + KGENOME_EMU_WIN_STUB_RVA +
		       (uint64_t)kgenome_emu_win_api_slot(i) * KGENOME_EMU_WIN_STUB;
	}
	/*
	 * A NAME THE LIBRARIES LIST AND NOTHING MODELS has its stub after the modelled ones, in the order of
	 * emu_win_names.c (which holds no name win_api[] has): found by the same name, at the same address
	 * the export directory gives it. Case sensitive, as GetProcAddress is and the sorted list allows.
	 */
	{
		static const unsigned mods[] = {
			KGENOME_EMU_WIN_MOD_K32, KGENOME_EMU_WIN_MOD_NTDLL, KGENOME_EMU_WIN_MOD_USER32,
			KGENOME_EMU_WIN_MOD_ADVAPI32, KGENOME_EMU_WIN_MOD_SHELL32, KGENOME_EMU_WIN_MOD_SHLWAPI
		};
		unsigned m;

		for (m = 0; m < sizeof mods / sizeof mods[0]; m++) {
			const struct kgenome_emu_win_name *w = NULL;
			unsigned first = 0, lo = 0, hi = kgenome_emu_win_export_names(mods[m], &w, &first), k, nm = 0;

			while (lo < hi) {
				unsigned mid = lo + (hi - lo) / 2u;
				int c = strcmp(w[mid].name, name);

				if (!c) {
					uint64_t base = e->win_mod_base[mods[m]];

					if (!base)
						return 0;
					for (k = 0; k < KGENOME_EMU_WIN_API_COUNT; k++)
						nm += win_api[k].mod == mods[m];
					return base + KGENOME_EMU_WIN_STUB_RVA +
					       (uint64_t)(nm + mid) * KGENOME_EMU_WIN_STUB;
				}
				if (c < 0)
					lo = mid + 1u;
				else
					hi = mid;
			}
		}
	}
	return 0;
}

/*
 * AN EXPORT THIS ENVIRONMENT LACKS IS NOT AN EXPORT THAT DOES NOT EXIST.
 *
 * The libraries here carry eighty-odd of kernel32's fifteen hundred names, so
 * GetProcAddress answering 0 for the rest tells the guest that DeleteFileW is
 * missing from Windows - and a stub that checks its result takes its failure
 * path. Measured on the PE corpus with a static reference to score against:
 * UPX's import resolver aborts through ExitProcess at the first name outside
 * the table, ahead of the jump to the original entry point, so the run never
 * reaches the one transition an unpacker is waiting for.
 *
 * The answer for a plausible name the table lacks is therefore an address in
 * the unmapped null page, which the call0 policy in the interpreter already
 * turns into "return 0 and carry on" when somebody does call it. The resolver
 * stores it and moves on, which is all a resolver does with it.
 *
 * A plausible name only: identifier characters, 3 to 64 of them. A guest
 * probing with a name no library has will still be told so by the name check
 * failing here, but a garbage name made of identifier characters cannot be
 * told from a real one, so a stub whose anti-emulation test is exactly
 * "resolve a nonsense name and expect 0" is not defeated by this - it is
 * fooled, and that is a cost of the policy, stated rather than hidden.
 */
/* 16 bytes apart so two misses are two addresses, and inside the first page
 * so the null-call policy owns them. */
uint64_t kgenome_emu_win_miss_thunk(struct kgenome_emu *e)
{
	return 0x10u + 0x10u * (e->win_miss++ % 0xfeu);
}

/* KNOWN DEFECT S2-CTYPE-a (2026-10-24, R) [sev L]: kgenome_emu_win_resolve tests a guest name with isalpha/isalnum, which follow the host's locale (core's kof_is_alpha / kof_is_word_byte do not).
 * Trigger: a host that called setlocale() (the engine never does) and a guest import name with a byte >= 0x80. Effect: such a name is accepted as an import and given a miss thunk, or refused, by the host's locale.
 * Reproducer: none. Fix: kof_is_alpha(c) / kof_is_word_byte(c) from kofcore.h. */
uint64_t kgenome_emu_win_resolve(struct kgenome_emu *e, const char *name)
{
	uint64_t a;
	size_t i, n;

	if (!e || !name)
		return 0;
	a = kgenome_emu_win_addr_of(e, name);
	n = strlen(name);
	if (a)
		return a;
	if (n < 3u || n > 64u || !(isalpha((unsigned char)name[0]) || name[0] == '_'))
		return 0;
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)name[i]) && name[i] != '_' &&
		    name[i] != '@' && name[i] != '?' && name[i] != '$')
			return 0;
	return kgenome_emu_win_miss_thunk(e);
}

#define WIN_FAKE_BASE 0x7b000000ull
#define WIN_FAKE_STEP 0x10000ull

/*
 * A LIBRARY WE HAVE NO IMAGE FOR STILL EXISTS ON A REAL MACHINE.
 *
 * This used to fail the load, on the argument that a handle with nothing
 * behind it invites a guest to resolve a name against nothing and call what
 * comes back. kgenome_emu_win_resolve answers that: what comes back is a miss
 * thunk, and calling one returns 0. What failing the load did instead was end
 * the run - UPX's resolver, after the first library outside the table
 * (comctl32), stops there and calls ExitProcess before the jump to the
 * original entry point.
 *
 * NOT FOR A LIBRARY WHOSE ABSENCE IS THE POINT. An analysis environment is
 * recognised by what it has loaded, and a stub that asks for one of those
 * expects a failure; those names still fail.
 */
/*
 * A library name as the table of modelled libraries keys it: lower case, without the ".dll" a guest may leave
 * off or put on (the loader supplies it), so LoadLibrary("comctl32") and GetModuleHandle("COMCTL32.DLL") name
 * one library. Returns 0 for a name this table does not model (too short or long, odd characters).
 */
/* KNOWN DEFECT S2-CTYPE-b (2026-10-24, R) [sev L]: fake_key lower-cases and tests a library name with isalnum/tolower, which follow the host's locale.
 * Trigger: a host that called setlocale() (the engine never does) and a library name with a byte >= 0x80. Effect: the key differs between hosts, so a modelled library is found or missed by the locale.
 * Reproducer: none. Fix: kof_is_word_byte(c) and kof_lower_byte(c) from kofcore.h. */
static int fake_key(const char *name, char *low, size_t cap)
{
	size_t i, n = strlen(name);

	if (n < 3u || n >= cap)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)name[i];

		if (!isalnum(c) && c != '_' && c != '.' && c != '-')
			return 0;
		low[i] = (char)tolower(c);
	}
	low[n] = 0;
	if (n > 4u && !strcmp(low + n - 4u, ".dll"))
		low[n - 4u] = 0;
	return 1;
}

/* The handle a library of the modelled kind already has, or 0: what GetModuleHandle answers for a library
 * LoadLibrary made a handle for (it is "loaded" from then on). */
uint64_t kgenome_emu_win_fake_find(const struct kgenome_emu *e, const char *name)
{
	char low[32];
	uint32_t i;

	if (!fake_key(name, low, sizeof low))
		return 0;
	for (i = 0; i < e->n_win_fake; i++)
		if (!strcmp(e->win_fake[i], low))
			return WIN_FAKE_BASE + (uint64_t)i * WIN_FAKE_STEP;
	return 0;
}

uint64_t kgenome_emu_win_fake_lib(struct kgenome_emu *e, const char *name)
{
	static const char *const deny[] = {
		"sbiedll", "snxhk", "cmdvrt", "api_log", "dir_watch", "pstorec",
		"vmcheck", "wpespy", "dbghelp_wine", "vboxhook", "vboxmrxnp"
	};
	size_t i, n;
	char low[32];
	uint64_t h;

	if (!fake_key(name, low, sizeof low))
		return 0;
	n = strlen(low);
	for (i = 0; i < sizeof deny / sizeof deny[0]; i++)
		if (strstr(low, deny[i]))
			return 0;
	h = kgenome_emu_win_fake_find(e, name);
	if (h)
		return h;
	if (e->n_win_fake >= 16u) {
		/* the 17th distinct library a guest loads is told "absent", which ends a loader
		 * that expected it: the run is not the whole answer, and says so */
		KGENOME_EMU_REFUSED(e, KGENOME_EMU_HIT_LIB, "table of 16 modelled libraries is full");
		return 0;
	}
	memcpy(e->win_fake[e->n_win_fake], low, n + 1u);
	return WIN_FAKE_BASE + (uint64_t)e->n_win_fake++ * WIN_FAKE_STEP;
}

/*
 * The heap's block table (see `hblk` in struct kgenome_emu). Both arenas hand out ascending addresses, so a
 * new block always sorts last; a block that is not above the last one (a guest that mapped over it) is not
 * recorded and the call says so.
 */
int kgenome_emu_win_heap_note(struct kgenome_emu *e, uint64_t va, uint64_t size)
{
	if (!va)
		return 1;
	if (e->hblk_n && va <= e->hblk[e->hblk_n - 1u].va)
		return 0;
	if (e->hblk_n == e->hblk_cap) {
		uint32_t cap = e->hblk_cap ? e->hblk_cap * 2u : 64u;
		struct kgenome_emu_hblk *t = realloc(e->hblk, (size_t)cap * sizeof *t);

		if (!t)
			return 0;
		e->hblk = t;
		e->hblk_cap = cap;
	}
	e->hblk[e->hblk_n].va = va;
	e->hblk[e->hblk_n].size = size;
	e->hblk_n++;
	return 1;
}

struct kgenome_emu_hblk *kgenome_emu_win_heap_find(const struct kgenome_emu *e, uint64_t va)
{
	uint32_t lo = 0, hi = e->hblk_n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (e->hblk[mid].va == va)
			return &e->hblk[mid];
		if (e->hblk[mid].va < va)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return NULL;
}

int kgenome_emu_win_is_fake(const struct kgenome_emu *e, uint64_t h)
{
	return h >= WIN_FAKE_BASE &&
	       h < WIN_FAKE_BASE + (uint64_t)e->n_win_fake * WIN_FAKE_STEP &&
	       !((h - WIN_FAKE_BASE) % WIN_FAKE_STEP);
}

/*
 * A module handle by name, which is what GetModuleHandle and LoadLibrary both
 * come down to. `load` is LoadLibrary: it brings a module the process did not
 * start with (KGENOME_EMU_WIN_MOD_MSCOREE) in, and from then on both calls see
 * it; without it such a module is absent, which is what GetModuleHandle says
 * of a library nobody has loaded.
 */
static uint64_t mod_find(struct kgenome_emu *e, const char *name, int load)
{
	unsigned i;

	for (i = 0; i < KGENOME_EMU_WIN_MOD_COUNT; i++) {
		const char *n = win_mod[i].name;
		unsigned len = (unsigned)strlen(n);
		int hit = 0;

		if (win_eq_nocase(n, name))
			hit = 1;
		/* "kernel32" for "kernel32.dll": a guest may leave the suffix
		 * off and Windows supplies it. */
		else if (len > 4u && !strncmp(n + len - 4u, ".dll", 4u)) {
			char bare[64];

			if (len - 4u < sizeof bare) {
				memcpy(bare, n, len - 4u);
				bare[len - 4u] = 0;
				hit = win_eq_nocase(bare, name);
			}
		}
		if (!hit)
			continue;
		if (i >= KGENOME_EMU_WIN_MOD_RESIDENT) {
			uint32_t bit = 1u << (i - KGENOME_EMU_WIN_MOD_RESIDENT);

			if (!load && !(e->win_loaded & bit))
				return 0;
			if (load && e->win_mod_base[i])
				e->win_loaded |= bit;
		}
		return e->win_mod_base[i];
	}
	return 0;
}

uint64_t kgenome_emu_win_mod_of(struct kgenome_emu *e, const char *name)
{
	return mod_find(e, name, 0);
}

uint64_t kgenome_emu_win_mod_load(struct kgenome_emu *e, const char *name)
{
	return mod_find(e, name, 1);
}

/*
 * The calling conventions, and they are not the same one.
 *
 * amd64 Windows passes the first four in rcx, rdx, r8, r9 - a different set
 * from the System V order this file's Linux side reads. i386 Windows passes
 * them on the stack, and the CALLEE pops them, which is why the stubs end in
 * `ret n` rather than `ret` and why the argument count has to be known here as
 * well as there.
 */
uint64_t kgenome_emu_win_arg(struct kgenome_emu *e, unsigned i)
{
	static const unsigned r64[4] = {
		KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_R8, KGENOME_EMU_R9
	};
	uint64_t v = 0;

	if (e->bits == 32) {
		/* [esp] is the return address the stub's caller pushed. */
		if (!kgenome_emu_mem_rd(e, (e->gpr[KGENOME_EMU_RSP] + 4u + 4u * i) & 0xffffffffu,
			    &v, 4u))
			return 0;
		return v;
	}
	if (i < 4u)
		return e->gpr[r64[i]];
	if (!kgenome_emu_mem_rd(e, e->gpr[KGENOME_EMU_RSP] + 8u + 8u * i, &v, 8u))
		return 0;
	return v;
}

/* A NUL terminated guest string into a host buffer, bounded and always
 * terminated. A pointer that faults yields the empty string rather than a
 * failure: a stub asking for a module by a name it cannot read is asking for
 * nothing, and "not found" is the honest answer to that. */
void kgenome_emu_win_str(struct kgenome_emu *e, uint64_t va, char *out, unsigned cap,
		    int wide)
{
	unsigned i;

	for (i = 0; i + 1u < cap; i++) {
		uint64_t c = 0;

		if (!kgenome_emu_mem_rd(e, va + (wide ? 2u * i : i), &c, wide ? 2u : 1u))
			break;
		if (!c)
			break;
		out[i] = (char)(c & 0xffu);
	}
	out[i] = 0;
}


/*
 * Reserve guest memory, the way the Linux side's mmap does and from the same
 * arena - one allocator, so a guest that somehow used both could not be handed
 * the same page twice.
 */
/*
 * THE ARENA IS ITS OWN, AND THAT IS AN ANTI-EMULATION POINT RATHER THAN
 * TIDINESS.
 *
 * EMU_MMAP_BASE is 0x7f0000000000, which is where LINUX puts an mmap. Windows
 * does not: a VirtualAlloc comes back low, and a guest that stores the pointer,
 * or compares it against its own image base, or simply truncates it into a
 * 32-bit field it declared, learns something true about the machine it is on
 * and false about the machine it is meant to be on. A protector looking for
 * exactly that is the reason this number is not shared.
 */
#define EMU_WINALLOC_BASE 0x0000000030000000ull
/* The largest single reservation this will make. A guest with a real use for
 * more than this is not one a short interpreted run is going to finish. */
#define EMU_WINALLOC_MAX  (256ull << 20)

uint64_t kgenome_emu_win_alloc(struct kgenome_emu *e, uint64_t want, unsigned prot)
{
	uint64_t len;
	uint64_t at;

	/*
	 * THE SIZE IS A NUMBER THE GUEST CHOSE, so it is bounded before it is
	 * rounded. `want + PAGE - 1` wraps to a small value for a request near
	 * 2^64, which would then map a few pages and report success - and the
	 * guest would write far past them. The ceiling is the arena itself:
	 * nothing this interpreter runs has any use for a gigabyte, and a
	 * refusal is an answer a caller already has to handle.
	 */
	if (!want || want > EMU_WINALLOC_MAX)
		return 0;
	len = (want + KGENOME_EMU_PAGE - 1u) & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	if (!len)
		return 0;
	if (!e->winmap_next)
		e->winmap_next = EMU_WINALLOC_BASE;
	at = e->winmap_next;
	/* A guard page between mappings, so a guest that runs off the end of
	 * one faults here rather than scribbling on the next - the same reason
	 * the Linux mmap leaves one. */
	e->winmap_next += len + KGENOME_EMU_PAGE;
	if (!kgenome_emu_vma_add(e, at, len, 0, prot & 7u, 0))
		return 0;
	return at;
}

/*
 * The 32-bit arena, which cannot be the 64-bit one: EMU_MMAP_BASE is above
 * 4 GB, so a 32-bit guest storing the pointer truncates it and then writes to
 * an address nothing mapped. The same reasoning as STACK_TOP_32 in
 * emu_unpack_elf.c, and the same class of bug it was written for.
 */
#define EMU_MMAP_BASE_32 0x20000000ull

uint64_t kgenome_emu_win_alloc32(struct kgenome_emu *e, uint64_t want, unsigned prot)
{
	uint64_t len;
	uint64_t at;

	if (!want || want > EMU_WINALLOC_MAX)
		return 0;               /* see win_alloc on why this is first */
	len = (want + KGENOME_EMU_PAGE - 1u) & ~(uint64_t)(KGENOME_EMU_PAGE - 1u);
	if (!len)
		return 0;
	if (!e->mmap32_next)
		e->mmap32_next = EMU_MMAP_BASE_32;
	at = e->mmap32_next;
	e->mmap32_next += len + KGENOME_EMU_PAGE;
	if (at + len > 0xfffff000ull)
		return 0;
	if (!kgenome_emu_vma_add(e, at, len, 0, prot & 7u, 0))
		return 0;
	return at;
}

/*
 * PAGE_* to this emulator's three bits. Anything with an EXECUTE in it gets X,
 * anything writable gets W, and everything readable gets R - the distinctions
 * Windows draws that this does not (guard pages, write-combine, no-cache) are
 * about caching and faulting behaviour rather than about what the memory is.
 */
unsigned kgenome_emu_win_prot(uint64_t p)
{
	unsigned r = 0;

	switch (p & 0xffu) {
	case 0x01: r = 0; break;                                  /* NOACCESS */
	case 0x02: r = KGENOME_EMU_R; break;                          /* READONLY */
	case 0x04: r = KGENOME_EMU_R | KGENOME_EMU_W; break;              /* READWRITE */
	case 0x08: r = KGENOME_EMU_R | KGENOME_EMU_W; break;              /* WRITECOPY */
	case 0x10: r = KGENOME_EMU_X; break;                          /* EXECUTE */
	case 0x20: r = KGENOME_EMU_R | KGENOME_EMU_X; break;              /* E_READ */
	case 0x40: r = KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X; break;  /* E_RW */
	case 0x80: r = KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X; break;  /* E_WC */
	default:   r = KGENOME_EMU_R | KGENOME_EMU_W; break;
	}
	return r;
}



/*
 * A RETURN VALUE A MODULE DECLARED FOR AN API, in place of the one the switch
 * below computes. Declared data rather than a case in this file: the answer a
 * particular packer's anti-emulation test wants is that packer's fact, and it
 * belongs with the module that knows the packer. Only the VALUE is replaced -
 * the stub still pops its own arguments, and the call is still logged as a call
 * of that API, so what a program asked is not hidden by what it was told.
 */
int kgenome_emu_shim_api(struct kgenome_emu *e, const char *name, uint64_t ret)
{
	unsigned i, n = kgenome_emu_win_api_count();

	if (!e || !name)
		return 0;
	for (i = 0; i < n; i++)
		if (!strcmp(kgenome_emu_win_api_name(i), name))
			break;
	if (i == n)
		return 0;
	{
		uint32_t k;

		for (k = 0; k < e->n_shim; k++)
			if (e->shim[k].id == i) {
				e->shim[k].ret = ret;
				return 1;
			}
	}
	if (e->n_shim >= KGENOME_EMU_SHIM_MAX)
		return 0;
	e->shim[e->n_shim].id = i;
	e->shim[e->n_shim].ret = ret;
	e->n_shim++;
	return 1;
}
