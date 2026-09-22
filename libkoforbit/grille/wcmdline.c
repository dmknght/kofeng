/*
 * wcmdline.c - the command line of a process that has just started.
 *
 * WHY THIS IS NOT AN ETW FIELD
 *
 * Because Kernel-Process does not carry one. ProcessStart is event 1 version 4
 * with sixteen properties - pid, creation time, parent, session, token
 * elevation, mandatory label, image name, checksum, package identity - and the
 * arguments are not among them. That is not an oversight to work around at the
 * decode; the data is not in the event.
 *
 * So it is read out of the new process itself: PEB -> ProcessParameters ->
 * CommandLine. That makes this the only field in the whole collector that is
 * fetched rather than received, and it brings the two costs of fetching.
 *
 *
 * THE RACE, WHICH IS NOT AN EDGE CASE
 *
 * The process has to still exist. The processes whose arguments matter most are
 * exactly the ones that do not last - a stager runs for milliseconds, and a
 * LOLBin invocation is often shorter than the flush timer that delivered the
 * event announcing it. Losing is normal here, not exceptional.
 *
 * What matters is that losing is VISIBLE. An unread command line and an empty
 * one are different facts and only one of them is about the program, so a
 * failure sets KOFW_EF_CMDLINE_RACED rather than leaving an empty string that
 * reads as "started with no arguments".
 *
 *
 * WHY THE LAYOUT IS VALIDATED RATHER THAN TRUSTED
 *
 * PEB and RTL_USER_PROCESS_PARAMETERS are not in mingw-w64's headers and their
 * layout is not contractual. Offsets copied from a reference are the same kind
 * of guess as an event id copied from documentation, and they fail the same
 * silent way: a wrong offset yields a UNICODE_STRING-shaped pile of bytes, and
 * a pointer read from it produces a string that looks like a string.
 *
 * So every field read here is checked against what it must be if the layout is
 * right - a length that is even, non-zero, no larger than its own maximum and
 * within a sane bound, and a buffer pointer that is not null. Anything
 * inconsistent is reported as a failure. The collector would rather say it does
 * not know than hand a rule some bytes it found.
 */

#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "wcmdline.h"
/* wtext.h, not wevt_decode.h: the UTF-16 conversion lives with the other
 * plain-C text handling, which is the half with no Windows API in it. */
#include "wtext.h"

/*
 * The two structures, cut down to the members this reads and laid out with
 * explicit padding so the offsets are stated rather than inferred from a
 * compiler's packing rules.
 *
 * Native layout only: on a 64-bit host these are read out of the 64-bit PEB,
 * which Windows maintains for a WOW64 process as well as for a native one.
 */
/*
 * PROCESS_BASIC_INFORMATION, and the first member is ONE pointer.
 *
 * It was written as Reserved1[2], which put PebBaseAddress at offset 16 instead
 * of 8. Every read then took the AffinityMask as the PEB address, which is not
 * a mapped pointer, so ReadProcessMemory failed and every command line was
 * reported lost - measured, 0 read out of 17 including processes that lived for
 * a minute. A race loses some; that lost all of them, which is what said it was
 * not a race.
 *
 * The real layout (winternl.h): ExitStatus, PebBaseAddress, AffinityMask,
 * BasePriority, UniqueProcessId, InheritedFromUniqueProcessId - six members,
 * the first a status and the rest pointer-width.
 */
typedef struct {
	PVOID     Reserved1;        /* ExitStatus, padded to pointer width */
	PVOID     PebBaseAddress;
	PVOID     Reserved2[2];     /* AffinityMask, BasePriority */
	ULONG_PTR UniqueProcessId;
	PVOID     Reserved3;
} KOFW_PROCESS_BASIC_INFORMATION;

/*
 * LONG rather than NTSTATUS: mingw-w64 defines NTSTATUS only when one of the
 * DDK headers has been pulled in, and windows.h alone does not. It is a signed
 * 32-bit status either way, and this only ever compares it against zero.
 */
typedef LONG (WINAPI *pfn_nt_qip)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* Offset of ProcessParameters inside PEB, and of CommandLine inside
 * RTL_USER_PROCESS_PARAMETERS. Both native-width. Validated, never trusted -
 * see the header comment. */
#if defined(_WIN64)
#define PEB_PARAMS_OFF   0x20u
#define PARAMS_CMDLINE   0x70u
#else
#define PEB_PARAMS_OFF   0x10u
#define PARAMS_CMDLINE   0x40u
#endif

/* A command line longer than this is not one; it is a misread. Windows itself
 * caps a command line at 32767 characters. */
#define CMDLINE_MAX_BYTES 65534u

static pfn_nt_qip resolve_nt_qip(void)
{
	static pfn_nt_qip fn;
	static int tried;

	if (!tried) {
		HMODULE nt = GetModuleHandleW(L"ntdll.dll");

		tried = 1;
		if (nt)
			fn = (pfn_nt_qip)(void *)GetProcAddress(
				nt, "NtQueryInformationProcess");
	}
	return fn;
}

int kofw_cmdline_of(uint32_t pid, char *out, size_t cap)
{
	KOFW_PROCESS_BASIC_INFORMATION pbi;
	pfn_nt_qip  qip = resolve_nt_qip();
	HANDLE      h;
	ULONG       got = 0;
	SIZE_T      rd;
	char       *peb_params = NULL;
	USHORT      len = 0, maxlen = 0;
	void       *buf = NULL;
	uint16_t   *wide;
	int         rc = KOFW_CMDLINE_FAIL, cut = 0;

	if (!out || cap == 0)
		return KOFW_CMDLINE_FAIL;
	out[0] = '\0';
	if (!qip)
		return KOFW_CMDLINE_FAIL;

	/*
	 * QUERY_LIMITED_INFORMATION rather than QUERY_INFORMATION: it is the
	 * weaker right and it is enough for the PEB address, so this asks for
	 * less than it could. VM_READ is the one that cannot be avoided.
	 */
	h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
			FALSE, (DWORD)pid);
	if (!h)
		return KOFW_CMDLINE_FAIL;

	memset(&pbi, 0, sizeof pbi);
	/* The size is a ULONG in the signature and a size_t here; the tree
	 * builds with -Wconversion, so the narrowing is stated. */
	if (qip(h, 0 /* ProcessBasicInformation */, &pbi,
		(ULONG)sizeof pbi, &got) != 0 || !pbi.PebBaseAddress)
		goto done;

	if (!ReadProcessMemory(h, (char *)pbi.PebBaseAddress + PEB_PARAMS_OFF,
			       &peb_params, sizeof peb_params, &rd) ||
	    rd != sizeof peb_params || !peb_params)
		goto done;

	/*
	 * UNICODE_STRING is { USHORT Length; USHORT MaximumLength; PVOID
	 * Buffer; } - read the three parts separately so each can be checked
	 * before the next is believed.
	 */
	if (!ReadProcessMemory(h, peb_params + PARAMS_CMDLINE,
			       &len, sizeof len, &rd) || rd != sizeof len)
		goto done;
	if (!ReadProcessMemory(h, peb_params + PARAMS_CMDLINE + 2,
			       &maxlen, sizeof maxlen, &rd) || rd != sizeof maxlen)
		goto done;
	if (!ReadProcessMemory(h, peb_params + PARAMS_CMDLINE + 8,
			       &buf, sizeof buf, &rd) || rd != sizeof buf)
		goto done;

	/*
	 * THE VALIDATION. Every one of these is a property the layout
	 * guarantees, so a failure means the offsets above are wrong on this
	 * build - and reporting that is the whole point.
	 */
	if (!buf || len == 0 || (len & 1u) || len > maxlen ||
	    len > CMDLINE_MAX_BYTES)
		goto done;

	wide = malloc(len + 2u);
	if (!wide)
		goto done;
	if (ReadProcessMemory(h, buf, wide, len, &rd) && rd == len) {
		wide[len / 2u] = 0;
		kofw_utf16_to_utf8(wide, len / 2u, out, cap, &cut);
		rc = cut ? KOFW_CMDLINE_CUT : KOFW_CMDLINE_OK;
	}
	free(wide);

done:
	CloseHandle(h);
	return rc;
}
