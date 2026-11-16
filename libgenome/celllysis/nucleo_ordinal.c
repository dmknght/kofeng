/*
 * nucleo_ordinal.c - THE NAME OF AN IMPORT BY ORDINAL, for the libraries whose ordinals are part of their ABI.
 *
 * WHY. An import by ordinal has no name in the importing file, and every route that turns an import into a node matches a NAME
 * (kgenome_nucleo_cap_of_name), so it was skipped: measured on the APT set of 2026-11-15, whs32 imports 26 WS2_32 functions by
 * ordinal (socket 23 at 5 call sites, connect 4, send 19 at 8, recv 16 at 5) and only getaddrinfo, imported by name, was a node;
 * 6 of the 120 PE of the pe120 set import ws2_32/wsock32 by ordinal (fix_aptgap, LG-ORD).
 *
 * WHICH LIBRARIES. Only those whose ordinals the OS keeps fixed because programs import by them: the Windows Sockets 1.1 exports of
 * ws2_32 and wsock32. Any other library's ordinal is the build's own, and stays unnamed - a limit, not a guess. The two tables are
 * NOT one: ordinals 10, 11 and 12 are ioctlsocket, inet_addr, inet_ntoa in ws2_32 and inet_addr, inet_ntoa, ioctlsocket in wsock32.
 *
 * WHERE THE NUMBERS COME FROM. Wine's export specs, dlls/ws2_32/ws2_32.spec and dlls/wsock32/wsock32.spec (github.com/wine-mirror/wine,
 * master, read 2026-11-15); Microsoft's reference does not publish ordinals. The four the APT sample uses (23, 4, 19, 16) agree with
 * the sample's own calls (fix_aptgap, measured).
 * TODO(verify): not checked against the export table of a Microsoft-built ws2_32.dll / wsock32.dll (none on this machine).
 */
#include "nucleo_private.h"

#include <string.h>

#include <kofcore.h>

struct ordrow {
	uint16_t    ord;
	const char *name;
};

/* Ordinals 1..23, 51..57, 101..116, 151: the Windows Sockets 1.1 set, ascending. */
static const struct ordrow ws2_32[] = {
	{ 1, "accept" }, { 2, "bind" }, { 3, "closesocket" }, { 4, "connect" }, { 5, "getpeername" }, { 6, "getsockname" },
	{ 7, "getsockopt" }, { 8, "htonl" }, { 9, "htons" }, { 10, "ioctlsocket" }, { 11, "inet_addr" }, { 12, "inet_ntoa" },
	{ 13, "listen" }, { 14, "ntohl" }, { 15, "ntohs" }, { 16, "recv" }, { 17, "recvfrom" }, { 18, "select" }, { 19, "send" },
	{ 20, "sendto" }, { 21, "setsockopt" }, { 22, "shutdown" }, { 23, "socket" },
	{ 51, "gethostbyaddr" }, { 52, "gethostbyname" }, { 53, "getprotobyname" }, { 54, "getprotobynumber" },
	{ 55, "getservbyname" }, { 56, "getservbyport" }, { 57, "gethostname" },
	{ 101, "WSAAsyncSelect" }, { 102, "WSAAsyncGetHostByAddr" }, { 103, "WSAAsyncGetHostByName" },
	{ 104, "WSAAsyncGetProtoByNumber" }, { 105, "WSAAsyncGetProtoByName" }, { 106, "WSAAsyncGetServByPort" },
	{ 107, "WSAAsyncGetServByName" }, { 108, "WSACancelAsyncRequest" }, { 109, "WSASetBlockingHook" },
	{ 110, "WSAUnhookBlockingHook" }, { 111, "WSAGetLastError" }, { 112, "WSASetLastError" }, { 113, "WSACancelBlockingCall" },
	{ 114, "WSAIsBlocking" }, { 115, "WSAStartup" }, { 116, "WSACleanup" }, { 151, "__WSAFDIsSet" }
};

static const struct ordrow wsock32[] = {
	{ 1, "accept" }, { 2, "bind" }, { 3, "closesocket" }, { 4, "connect" }, { 5, "getpeername" }, { 6, "getsockname" },
	{ 7, "getsockopt" }, { 8, "htonl" }, { 9, "htons" }, { 10, "inet_addr" }, { 11, "inet_ntoa" }, { 12, "ioctlsocket" },
	{ 13, "listen" }, { 14, "ntohl" }, { 15, "ntohs" }, { 16, "recv" }, { 17, "recvfrom" }, { 18, "select" }, { 19, "send" },
	{ 20, "sendto" }, { 21, "setsockopt" }, { 22, "shutdown" }, { 23, "socket" },
	{ 51, "gethostbyaddr" }, { 52, "gethostbyname" }, { 53, "getprotobyname" }, { 54, "getprotobynumber" },
	{ 55, "getservbyname" }, { 56, "getservbyport" }, { 57, "gethostname" },
	{ 101, "WSAAsyncSelect" }, { 102, "WSAAsyncGetHostByAddr" }, { 103, "WSAAsyncGetHostByName" },
	{ 104, "WSAAsyncGetProtoByNumber" }, { 105, "WSAAsyncGetProtoByName" }, { 106, "WSAAsyncGetServByPort" },
	{ 107, "WSAAsyncGetServByName" }, { 108, "WSACancelAsyncRequest" }, { 109, "WSASetBlockingHook" },
	{ 110, "WSAUnhookBlockingHook" }, { 111, "WSAGetLastError" }, { 112, "WSASetLastError" }, { 113, "WSACancelBlockingCall" },
	{ 114, "WSAIsBlocking" }, { 115, "WSAStartup" }, { 116, "WSACleanup" }, { 151, "__WSAFDIsSet" }
};

/* `dll` is `base` in any case, with or without ".dll" (any case) after it. */
static int dll_is(const char *dll, const char *base)
{
	size_t n = strlen(base), i;

	for (i = 0; i < n; i++)
		if (!dll[i] || kof_lower_byte((uint8_t)dll[i]) != (uint8_t)base[i])
			return 0;
	if (!dll[n])
		return 1;
	return dll[n] == '.' && kof_lower_byte((uint8_t)dll[n + 1]) == 'd' && kof_lower_byte((uint8_t)dll[n + 2]) == 'l' &&
	       kof_lower_byte((uint8_t)dll[n + 3]) == 'l' && !dll[n + 4];
}

static const char *find(const struct ordrow *t, size_t n, uint32_t ord)
{
	size_t lo = 0, hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2u;

		if (t[mid].ord == ord)
			return t[mid].name;
		if (t[mid].ord < ord)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return NULL;
}

const char *kgenome_nucleo_ordinal_name(const char *dll, uint32_t ordinal)
{
	if (!dll)
		return NULL;
	if (dll_is(dll, "ws2_32"))
		return find(ws2_32, sizeof ws2_32 / sizeof ws2_32[0], ordinal);
	if (dll_is(dll, "wsock32"))
		return find(wsock32, sizeof wsock32 / sizeof wsock32[0], ordinal);
	return NULL;
}
