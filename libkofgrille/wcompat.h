/*
 * wcompat.h - what mingw-w64's headers do not declare, declared once.
 *
 * The toolchain this tree builds with on Windows is clang against mingw-w64's
 * SDK headers, and that SDK is incomplete in two places this library needs.
 * Nothing here is a workaround for a difference between compilers or a guess at
 * an undocumented interface: every value below is a fixed part of the ETW ABI,
 * published in the Windows SDK headers and unchanged since the API shipped.
 * They are written out because the header that should carry them does not, and
 * the alternative - requiring the Windows SDK alongside the MSYS2 toolchain -
 * would make this the only part of the tree that needs a second SDK.
 *
 * The rule for adding to this file: it takes DECLARATIONS ONLY, and only ones
 * that already exist somewhere official. The moment something here is a guess,
 * it belongs in the code that guesses it, with what was measured.
 */

#ifndef KOFGRILLE_WCOMPAT_H
#define KOFGRILLE_WCOMPAT_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

/*
 * The manifest's own type ids, from the SDK's _TDH_IN_TYPE.
 *
 * mingw-w64's tdh.h declares TRACE_EVENT_INFO and EVENT_PROPERTY_INFO but not
 * the enum whose values fill EVENT_PROPERTY_INFO.nonStructType.InType, so a
 * consumer can read the shape of an event and cannot say what is in it.
 *
 * BOOLEAN is 13 and occupies FOUR bytes on the wire, not one. That is ETW's
 * definition rather than C's, and a decoder that assumes otherwise shifts every
 * following field by three - which is why the sizes live beside these names in
 * wevt_decode.c rather than being inferred at the call.
 */
#ifndef TDH_INTYPE_NULL
#define TDH_INTYPE_NULL           0
#define TDH_INTYPE_UNICODESTRING  1
#define TDH_INTYPE_ANSISTRING     2
#define TDH_INTYPE_INT8           3
#define TDH_INTYPE_UINT8          4
#define TDH_INTYPE_INT16          5
#define TDH_INTYPE_UINT16         6
#define TDH_INTYPE_INT32          7
#define TDH_INTYPE_UINT32         8
#define TDH_INTYPE_INT64          9
#define TDH_INTYPE_UINT64        10
#define TDH_INTYPE_FLOAT         11
#define TDH_INTYPE_DOUBLE        12
#define TDH_INTYPE_BOOLEAN       13
#define TDH_INTYPE_BINARY        14
#define TDH_INTYPE_GUID          15
#define TDH_INTYPE_POINTER       16
#define TDH_INTYPE_FILETIME      17
#define TDH_INTYPE_SYSTEMTIME    18
#define TDH_INTYPE_SID           19
#define TDH_INTYPE_HEXINT32      20
#define TDH_INTYPE_HEXINT64      21
#endif

#ifndef TDHSTATUS
typedef ULONG TDHSTATUS;
#endif

/*
 * The event-id filter, which is the reason this file exists at all.
 *
 * Filtering by event id happens INSIDE the provider: an event this refuses is
 * never written to a buffer, never delivered and never decoded. It is the only
 * filtering in the whole pipeline that is genuinely free, and without these two
 * declarations there is no way to ask for it - the fallback is to accept every
 * event the keyword allows and throw most of them away after paying for them.
 */
#ifndef EVENT_FILTER_TYPE_EVENT_ID
#define EVENT_FILTER_TYPE_EVENT_ID 0x80000200
#endif

#ifndef _EVENT_FILTER_EVENT_ID_DEFINED
#define _EVENT_FILTER_EVENT_ID_DEFINED
typedef struct _EVENT_FILTER_EVENT_ID {
	BOOLEAN FilterIn;
	UCHAR   Reserved;
	USHORT  Count;
	USHORT  Events[ANYSIZE_ARRAY];
} EVENT_FILTER_EVENT_ID, *PEVENT_FILTER_EVENT_ID;
#endif

#endif /* KOFGRILLE_WCOMPAT_H */
