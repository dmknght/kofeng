/*
 * emu_win_private.h - what the emulator's WINDOWS ENVIRONMENT shares between its files. NOT PART OF
 * THE SURFACE.
 *
 * The environment a PE guest calls into: the modelled API ids (one table, emu_win_names.c, and the
 * dispatch, emu_winapi.c), the modules and the miss thunks (emu_win.c), the heap and the exception
 * dispatcher (emu_win_exc.c). It is part of the emulator's core, not of an architecture's entry: the
 * Linux environment's syscall path (emu_sys.c) hands it the API traps, and the run loop
 * (emu_run_private.h) asks it whether a fault is a guest's to handle. Private to libgenome/phenotype/.
 */
#ifndef KGENOME_EMU_WIN_PRIVATE_H
#define KGENOME_EMU_WIN_PRIVATE_H

#include "emu_private.h"

/* ---- the Windows API ids, shared by the table and the dispatch ---- */

#define KGENOME_EMU_WIN_API_BASE   0x57494e00u      /* 'W','I','N',0 */

enum {
	KGENOME_EMU_WIN_GetModuleHandleA = 0,
	KGENOME_EMU_WIN_GetModuleHandleW,
	KGENOME_EMU_WIN_GetProcAddress,
	KGENOME_EMU_WIN_LoadLibraryA,
	KGENOME_EMU_WIN_LoadLibraryW,
	KGENOME_EMU_WIN_VirtualAlloc,
	KGENOME_EMU_WIN_VirtualFree,
	KGENOME_EMU_WIN_VirtualProtect,
	KGENOME_EMU_WIN_ExitProcess,
	KGENOME_EMU_WIN_GetCurrentProcess,
	KGENOME_EMU_WIN_IsDebuggerPresent,
	KGENOME_EMU_WIN_GetLastError,
	KGENOME_EMU_WIN_SetLastError,
	KGENOME_EMU_WIN_GetVersion,
	KGENOME_EMU_WIN_GetCurrentProcessId,
	KGENOME_EMU_WIN_GetTickCount,
	KGENOME_EMU_WIN_AddVectoredExceptionHandler,
	KGENOME_EMU_WIN_RemoveVectoredExceptionHandler,
	KGENOME_EMU_WIN_GetProcessHeap,
	KGENOME_EMU_WIN_HeapAlloc,
	KGENOME_EMU_WIN_HeapFree,
	KGENOME_EMU_WIN_HeapReAlloc,
	KGENOME_EMU_WIN_HeapSize,
	KGENOME_EMU_WIN_VirtualQuery,
	KGENOME_EMU_WIN_GetSystemInfo,
	KGENOME_EMU_WIN_Sleep,
	KGENOME_EMU_WIN_QueryPerformanceCounter,
	KGENOME_EMU_WIN_QueryPerformanceFrequency,
	KGENOME_EMU_WIN_GetSystemTimeAsFileTime,
	KGENOME_EMU_WIN_GetCurrentThreadId,
	KGENOME_EMU_WIN_GetCurrentThread,
	KGENOME_EMU_WIN_TlsAlloc,
	KGENOME_EMU_WIN_TlsGetValue,
	KGENOME_EMU_WIN_TlsSetValue,
	KGENOME_EMU_WIN_TlsFree,
	KGENOME_EMU_WIN_InitializeCriticalSection,
	KGENOME_EMU_WIN_EnterCriticalSection,
	KGENOME_EMU_WIN_LeaveCriticalSection,
	KGENOME_EMU_WIN_DeleteCriticalSection,
	KGENOME_EMU_WIN_FlushInstructionCache,
	KGENOME_EMU_WIN_GetStdHandle,
	KGENOME_EMU_WIN_CloseHandle,
	KGENOME_EMU_WIN_SetUnhandledExceptionFilter,
	KGENOME_EMU_WIN_GetModuleFileNameA,
	KGENOME_EMU_WIN_GetModuleFileNameW,
	KGENOME_EMU_WIN_GetCommandLineA,
	KGENOME_EMU_WIN_GetCommandLineW,
	KGENOME_EMU_WIN_lstrlenA,
	KGENOME_EMU_WIN_RtlAddFunctionTable,
	KGENOME_EMU_WIN_RtlAllocateHeap,
	KGENOME_EMU_WIN_RtlFreeHeap,
	KGENOME_EMU_WIN_NtQueryInformationProcess,
	KGENOME_EMU_WIN_FreeLibrary,
	KGENOME_EMU_WIN_LocalAlloc,
	KGENOME_EMU_WIN_LocalFree,
	KGENOME_EMU_WIN_GlobalAlloc,
	KGENOME_EMU_WIN_GlobalFree,
	KGENOME_EMU_WIN_lstrcmpA,
	KGENOME_EMU_WIN_lstrcmpiA,
	KGENOME_EMU_WIN_lstrcpyA,
	KGENOME_EMU_WIN_lstrcatA,
	KGENOME_EMU_WIN_lstrlenW,
	KGENOME_EMU_WIN_MultiByteToWideChar,
	KGENOME_EMU_WIN_WideCharToMultiByte,
	KGENOME_EMU_WIN_OutputDebugStringA,
	KGENOME_EMU_WIN_SetErrorMode,
	KGENOME_EMU_WIN_GetStartupInfoA,
	KGENOME_EMU_WIN_GetStartupInfoW,
	KGENOME_EMU_WIN_GetSystemDirectoryA,
	KGENOME_EMU_WIN_GetWindowsDirectoryA,
	KGENOME_EMU_WIN_GetTempPathA,
	KGENOME_EMU_WIN_GetFileAttributesA,
	KGENOME_EMU_WIN_CreateFileA,
	KGENOME_EMU_WIN_ReadFile,
	KGENOME_EMU_WIN_WriteFile,
	KGENOME_EMU_WIN_SetFilePointer,
	KGENOME_EMU_WIN_GetFileSize,
	KGENOME_EMU_WIN_CreateThread,
	KGENOME_EMU_WIN_ResumeThread,
	KGENOME_EMU_WIN_WaitForSingleObject,
	KGENOME_EMU_WIN_TerminateProcess,
	KGENOME_EMU_WIN_RaiseException,
	KGENOME_EMU_WIN_UnhandledExceptionFilter,
	KGENOME_EMU_WIN_InterlockedIncrement,
	KGENOME_EMU_WIN_InterlockedDecrement,
	KGENOME_EMU_WIN_NtProtectVirtualMemory,
	KGENOME_EMU_WIN_NtAllocateVirtualMemory,
	KGENOME_EMU_WIN_RtlGetVersion,
	KGENOME_EMU_WIN_LdrLoadDll,
	KGENOME_EMU_WIN_LdrGetProcedureAddress,
	KGENOME_EMU_WIN_InitializeCriticalSectionAndSpinCount,
	KGENOME_EMU_WIN_IsProcessorFeaturePresent,
	KGENOME_EMU_WIN_IsValidCodePage,
	KGENOME_EMU_WIN_IsBadReadPtr,
	KGENOME_EMU_WIN_IsBadWritePtr,
	KGENOME_EMU_WIN_InterlockedExchange,
	KGENOME_EMU_WIN_InterlockedCompareExchange,
	KGENOME_EMU_WIN_SetHandleCount,
	KGENOME_EMU_WIN_SetStdHandle,
	KGENOME_EMU_WIN_SetEnvironmentVariableA,
	KGENOME_EMU_WIN_SetEnvironmentVariableW,
	KGENOME_EMU_WIN_SetConsoleCtrlHandler,
	KGENOME_EMU_WIN_FreeEnvironmentStringsA,
	KGENOME_EMU_WIN_FreeEnvironmentStringsW,
	KGENOME_EMU_WIN_FlushFileBuffers,
	KGENOME_EMU_WIN_FindClose,
	KGENOME_EMU_WIN_DecodePointer,
	KGENOME_EMU_WIN_EncodePointer,
	KGENOME_EMU_WIN_DeleteFileA,
	KGENOME_EMU_WIN_DisableThreadLibraryCalls,
	KGENOME_EMU_WIN_HeapCreate,
	KGENOME_EMU_WIN_HeapDestroy,
	KGENOME_EMU_WIN_GetCPInfo,
	KGENOME_EMU_WIN_GetACP,
	KGENOME_EMU_WIN_GetOEMCP,
	KGENOME_EMU_WIN_IsUserAnAdmin,
	KGENOME_EMU_WIN_SHGetFolderPathA,
	KGENOME_EMU_WIN_CoInitialize,
	KGENOME_EMU_WIN_CoUninitialize,
	/* ws2_32. The environment is a SCRIPTED PEER - see winapi_do. */
	KGENOME_EMU_WIN_WSAStartup,
	KGENOME_EMU_WIN_WSACleanup,
	KGENOME_EMU_WIN_WSASocketA,
	KGENOME_EMU_WIN_WSASocketW,
	KGENOME_EMU_WIN_socket,
	KGENOME_EMU_WIN_connect,
	KGENOME_EMU_WIN_recv,
	KGENOME_EMU_WIN_send,
	KGENOME_EMU_WIN_sendto,
	KGENOME_EMU_WIN_recvfrom,
	KGENOME_EMU_WIN_closesocket,
	KGENOME_EMU_WIN_bind,
	KGENOME_EMU_WIN_listen,
	KGENOME_EMU_WIN_accept,
	KGENOME_EMU_WIN_shutdown,
	KGENOME_EMU_WIN_setsockopt,
	KGENOME_EMU_WIN_ioctlsocket,
	/* mscoree: the runtime's two entry points - see KGENOME_EMU_WIN_MOD_MSCOREE. */
	KGENOME_EMU_WIN_RtlAddVectoredExceptionHandler,
	KGENOME_EMU_WIN_RtlRemoveVectoredExceptionHandler,

	KGENOME_EMU_WIN_CorExeMain,
	KGENOME_EMU_WIN_CorDllMain,

	/*
	 * THE COUNT COMES FROM THE ENUM AND THE ENUM IS CHECKED AGAINST THE
	 * TABLE, because writing it by hand is how this broke.
	 *
	 * KGENOME_EMU_WIN_API_COUNT was a literal, the table grew by 34 entries and the
	 * literal was set to 53 for 52 of them, and the one-past read crashed
	 * the scanner in win_eq_nocase against a name pointer that was never
	 * written. The header already says of the table that "a table in each
	 * place is a table that disagrees after the first edit"; a hand
	 * written length is the same mistake one step smaller.
	 */
	KGENOME_EMU_WIN_API__LAST
};

#define KGENOME_EMU_WIN_API_COUNT ((unsigned)KGENOME_EMU_WIN_API__LAST)

uint64_t kgenome_emu_win_miss_thunk(struct kgenome_emu *e);
uint64_t kgenome_emu_win_fake_lib(struct kgenome_emu *e, const char *name);
uint64_t kgenome_emu_win_fake_find(const struct kgenome_emu *e, const char *name);
#define KGENOME_EMU_HBLK_FREED (~(uint64_t)0)
int kgenome_emu_win_heap_note(struct kgenome_emu *e, uint64_t va, uint64_t size);
struct kgenome_emu_hblk *kgenome_emu_win_heap_find(const struct kgenome_emu *e, uint64_t va);
int kgenome_emu_win_is_fake(const struct kgenome_emu *e, uint64_t h);
uint64_t kgenome_emu_win_mod_of(struct kgenome_emu *e, const char *name);
uint64_t kgenome_emu_win_mod_load(struct kgenome_emu *e, const char *name);

uint64_t kgenome_emu_win_arg(struct kgenome_emu *e, unsigned i);
void kgenome_emu_win_str(struct kgenome_emu *e, uint64_t va, char *out, unsigned cap,
		int wide);
uint64_t kgenome_emu_win_alloc(struct kgenome_emu *e, uint64_t want, unsigned prot);
uint64_t kgenome_emu_win_alloc32(struct kgenome_emu *e, uint64_t want, unsigned prot);
unsigned kgenome_emu_win_prot(uint64_t p);
uint64_t kgenome_emu_win_ret_magic(const struct kgenome_emu *e);
int kgenome_emu_win_exc_begin(struct kgenome_emu *e);
int kgenome_emu_win_exc_return(struct kgenome_emu *e);
void kgenome_emu_win_trace(struct kgenome_emu *e, const char *api, const char *arg,
		uint64_t ret);
void kgenome_emu_win_event_note(struct kgenome_emu *e, unsigned api, uint64_t ret);
uint64_t kgenome_emu_win_sock_new(struct kgenome_emu *e);
int kgenome_emu_win_sock_first_read(struct kgenome_emu *e, uint64_t s);
uint64_t kgenome_emu_winapi_do(struct kgenome_emu *e, unsigned id, int *stop_out);

#endif /* KGENOME_EMU_WIN_PRIVATE_H */
