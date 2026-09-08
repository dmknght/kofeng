/*
 * wevt_decode.c - see wevt_decode.h for why TDH runs once and not per record.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include "wcompat.h"

#include "wevt_decode.h"
#include "wtext.h"

/*
 * THE ASSERTION kofgrille.h PROMISES.
 *
 * KOFW_REC_HEAD is how the text arena is sized, so if a field is ever added
 * above text[] without moving it, every string in every record silently starts
 * at the wrong offset - and a path read from the wrong offset still looks like
 * a path. The header said this was checked here. It was not, until now.
 */
_Static_assert(offsetof(struct kofw_evt, text) == KOFW_REC_HEAD,
	       "KOFW_REC_HEAD no longer matches the record layout");
_Static_assert(sizeof(struct kofw_evt) == KOFW_REC_SIZE,
	       "struct kofw_evt is not KOFW_REC_SIZE bytes");

const GUID KOFW_GUID_KERNEL_PROCESS = {
	0x22fb2cd6, 0x0e7b, 0x422b,
	{ 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 }
};

const GUID KOFW_GUID_KERNEL_NET = {
	0x7dd42a49, 0x5329, 0x4832,
	{ 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
};

/*
 * Microsoft-Windows-Kernel-Registry.
 *
 * NOT ESTABLISHED THE WAY THE OTHERS WERE, and that difference is why this
 * comment is longer than the constant. Check it before trusting a quiet run:
 *
 *     logman query providers Microsoft-Windows-Kernel-Registry
 *
 * EnableTraceEx2 SUCCEEDS for a provider GUID nothing publishes - the session
 * starts, the keyword is accepted, and not one event ever arrives. There is no
 * error anywhere in that sequence. A wrong GUID here does not look like a bug,
 * it looks like a machine that does not touch the registry, which no machine
 * is. `--schema` naming no `registry` shape at all is what that failure looks
 * like from the outside.
 */
const GUID KOFW_GUID_KERNEL_REGISTRY = {
	0x70eb4f03, 0xc1de, 0x4f73,
	{ 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd }
};

/*
 * Microsoft-Antimalware-Scan-Interface, {2A576B87-09A7-520E-C21A-4942F0271D67}.
 *
 * THE ONE PROVIDER HERE THAT IS NOT A KERNEL PROVIDER, and the difference
 * matters twice.
 *
 * What it reports is what an APPLICATION handed to AmsiScanBuffer - a
 * PowerShell command line after the shell has expanded it, a macro body, a
 * script block about to be executed. That is the only place in this whole
 * collector where the content of something is visible rather than the fact of
 * it: the file events say a script appeared, this says what the script SAYS.
 *
 * The cost of being a user-mode provider is that a process can silence it for
 * itself. Patching ntdll!EtwEventWrite in your own address space stops your own
 * AMSI submissions being reported, and so does not calling AmsiScanBuffer at
 * all - a payload that never touches a scripting host is simply not an AMSI
 * client. Neither is true of the kernel providers, which is why this is an
 * addition to them and not a replacement for any of them.
 */
const GUID KOFW_GUID_AMSI = {
	0x2a576b87, 0x09a7, 0x520e,
	{ 0xc2, 0x1a, 0x49, 0x42, 0xf0, 0x27, 0x1d, 0x67 }
};

const GUID KOFW_GUID_KERNEL_FILE = {
	0xedd08927, 0x9cc4, 0x4e65,
	{ 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 }
};

uint8_t kofw_provider_of(const GUID *g)
{
	if (!memcmp(g, &KOFW_GUID_KERNEL_PROCESS, sizeof *g))
		return KOFW_PROV_PROCESS;
	if (!memcmp(g, &KOFW_GUID_KERNEL_NET, sizeof *g))
		return KOFW_PROV_NET;
	if (!memcmp(g, &KOFW_GUID_KERNEL_FILE, sizeof *g))
		return KOFW_PROV_FILE;
	if (!memcmp(g, &KOFW_GUID_KERNEL_REGISTRY, sizeof *g))
		return KOFW_PROV_REGISTRY;
	if (!memcmp(g, &KOFW_GUID_AMSI, sizeof *g))
		return KOFW_PROV_AMSI;
	return KOFW_PROV_NONE;
}

#define EVID_PROCESS_START 1u
#define EVID_PROCESS_STOP  2u
#define EVID_IMAGE_LOAD    5u
#define EVID_IMAGE_UNLOAD  6u

/*
 * KERNEL-FILE'S IDS, AND HOW THEY WERE ESTABLISHED.
 *
 * Not copied from documentation, and not guessed. Each was watched into place:
 * a script performed one operation at a time, a second apart, under kofmontrace
 * with --raw, and the id that appeared at each step is the one written here.
 *
 *   30  a `copy` produced a new file      -> FileName, the new path
 *   27  a `ren` renamed it                -> FilePath, the path after
 *   26  a delete removed it               -> FilePath, the path removed
 *
 * The method matters more than the numbers, because the numbers may not survive
 * a Windows upgrade. Anything this table gets wrong shows up as an event typed
 * as the wrong thing rather than as an error, so when these are re-checked they
 * should be re-checked the same way: one operation, one second apart, and read
 * the ids off the ordered trace. An id that stops appearing is a table entry
 * that has gone stale, and an event that arrives as `raw` is one that was never
 * in the table at all.
 */
#define EVID_FILE_CREATE_NEW 30u
#define EVID_FILE_RENAME     27u
#define EVID_FILE_DELETE     26u

/* -------------------------------------------------------- learning a shape */

/* Compare a manifest property name against an ASCII literal. */
static int name_is(const wchar_t *w, const char *ascii)
{
	size_t i;

	for (i = 0; ascii[i]; i++) {
		if (w[i] != (wchar_t)(unsigned char)ascii[i])
			return 0;
	}
	return w[i] == 0;
}

/*
 * WHICH FIELD A PROPERTY FEEDS DEPENDS ON THE EVENT, not just on its name.
 *
 * "ImageName" is the clearest case and the reason this takes a type at all: in
 * a ProcessStart it names the SUBJECT - the program the pid is - and in an
 * ImageLoad it names the OBJECT, a module mapped into a process that is
 * something else entirely. One global name table would have quietly filed every
 * loaded DLL as the loading process's own identity.
 */
static uint8_t field_of(const wchar_t *name, uint16_t type, uint8_t prov)
{
	/*
	 * AMSI FIRST, AND ONLY `content` FEEDS THE OBJECT.
	 *
	 * The walk assigns fields in payload order and the last match wins, so
	 * every name mapped to OBJECT competes for the same slot. That is fine
	 * where the candidates are alternative spellings of one path. It is not
	 * fine here: an AMSI event carries the submitted buffer AND the names
	 * of the application and the content beside it, and whichever the
	 * provider happens to list last is what a reader would see. A trace
	 * showing "PowerShell" where the script was supposed to be is not an
	 * error anybody would notice as one.
	 *
	 * This is the same mistake StartAddr and Win32StartAddr made, caught in
	 * a second place. The general rule it argues for: names may only share
	 * a field when they are alternatives, never when they can co-occur.
	 */
	if (prov == KOFW_PROV_AMSI) {
		if (name_is(name, "content") || name_is(name, "Content"))
			return KOFW_FLD_OBJECT;
		if (name_is(name, "ProcessID") || name_is(name, "PID"))
			return KOFW_FLD_PID;
		/* appname and contentname are context and would otherwise
		 * overwrite the buffer. Visible in --schema; not carried. */
		return KOFW_FLD_SKIP;
	}

	/*
	 * TWO SPELLINGS OF THE SAME FIELD, and the second one cost a whole
	 * debugging session.
	 *
	 * Kernel-Process says "ProcessID". Kernel-Network says "PID". Without
	 * the second, a network event's subject fell back to the raising
	 * process from the event header - which for the network stack is not
	 * the application at all - so every connection was attributed to the
	 * wrong pid, and a trace scoped to one subtree therefore showed no
	 * network activity whatsoever. Nothing errored: the events arrived, they
	 * decoded, and they were filtered out as somebody else's.
	 */
	if (name_is(name, "ProcessID") || name_is(name, "PID"))
		return KOFW_FLD_PID;
	if (name_is(name, "ParentProcessID")) return KOFW_FLD_PPID;
	if (name_is(name, "CreateTime"))      return KOFW_FLD_CREATE_TIME;
	if (name_is(name, "SessionID"))       return KOFW_FLD_SESSION;
	if (name_is(name, "ExitCode"))        return KOFW_FLD_EXIT_CODE;

	/*
	 * Whatever this provider calls the path it acted on.
	 *
	 * FileName is Kernel-File's spelling. KeyName, ValueName and
	 * RelativeName are Kernel-Registry's, and having all three here is
	 * deliberate: which one carries the useful text differs by event, and
	 * the walk fills `object` from whichever it reaches. The others are
	 * here because a RAW event is worth rendering with its path rather
	 * than without - which is the whole of what makes a discovery run
	 * readable.
	 */
	if (name_is(name, "FileName") || name_is(name, "FilePath") ||
	    name_is(name, "OldFileName") || name_is(name, "NewFileName") ||
	    name_is(name, "KeyName") || name_is(name, "ValueName") ||
	    name_is(name, "RelativeName") || name_is(name, "KeyObject"))
		return KOFW_FLD_OBJECT;

	if (name_is(name, "daddr")) return KOFW_FLD_DADDR;
	if (name_is(name, "saddr")) return KOFW_FLD_SADDR;
	if (name_is(name, "dport")) return KOFW_FLD_DPORT;
	if (name_is(name, "sport")) return KOFW_FLD_SPORT;
	if (name_is(name, "size"))  return KOFW_FLD_SIZE;

	/*
	 * A THREAD'S ENTRY POINT, under whichever of these the manifest uses.
	 *
	 * This is the field the whole thread subscription is for: an entry
	 * point that is not inside any mapped image is what a reflectively
	 * loaded payload and a remote injection both look like, and it is the
	 * only in-box way to see either without a protected-process signature.
	 * ImageBase is here too, so a module load reports where it landed.
	 */
	/*
	 * ESTABLISHED, no longer assumed. Kernel-Process ThreadStart is event 3
	 * version 1 and carries BOTH `StartAddr` and `Win32StartAddr`, each a
	 * pointer. They are not interchangeable:
	 *
	 *   StartAddr        where the kernel begins the thread, which for
	 *                    every ordinary thread is the same ntdll stub.
	 *   Win32StartAddr   the routine the thread was actually created to
	 *                    run - the one a caller passed to CreateThread.
	 *
	 * Only the second answers "is this entry point inside a mapped image",
	 * because the first is inside ntdll for injected and innocent threads
	 * alike. Mapping both to one field made the answer depend on which the
	 * payload happened to list last, which is not a decision anybody made.
	 */
	if (name_is(name, "Win32StartAddr") || name_is(name, "StartAddress") ||
	    name_is(name, "ImageBase"))
		return KOFW_FLD_ADDR;

	/* ImageSize, so a module load describes a RANGE rather than a point.
	 * Without it there is a list of addresses and no way to ask whether a
	 * thread's entry point falls inside one. */
	/*
	 * HOW A WRITE NAMES ITS TARGET, which is not by path.
	 *
	 * FileIo Write carries FileObject and FileKey - kernel pointers - and
	 * no filename at all. The FILENAME keyword emits separate records that
	 * map one of those to a path, and wfilter.c keeps them; this is where
	 * the key itself is picked up so there is something to look up with.
	 *
	 * Both spellings, because which one is the stable identity differs by
	 * event: the name records key on FileKey and the write carries both.
	 * FileKey is preferred by being tested first.
	 */
	if (name_is(name, "FileKey") || name_is(name, "FileObject"))
		return KOFW_FLD_FILE_KEY;

	if (name_is(name, "ImageSize"))
		return KOFW_FLD_ADDR_SIZE;

	if (name_is(name, "ImageName")) {
		if (type == KOF_EVT_PROC_START || type == KOF_EVT_PROC_STOP)
			return KOFW_FLD_IMAGE;
		return KOFW_FLD_OBJECT;
	}
	return KOFW_FLD_SKIP;
}

/* What a (provider, id) pair means to this build, or KOF_EVT_RAW when nothing
 * yet. */
static uint16_t type_of(uint8_t prov, uint16_t id)
{
	if (prov == KOFW_PROV_PROCESS) {
		switch (id) {
		case EVID_PROCESS_START: return KOF_EVT_PROC_START;
		case EVID_PROCESS_STOP:  return KOF_EVT_PROC_STOP;
		case EVID_IMAGE_LOAD:    return KOF_EVT_IMAGE_LOAD;
		case EVID_IMAGE_UNLOAD:  return KOF_EVT_IMAGE_UNLOAD;
		default: break;
		}
	} else if (prov == KOFW_PROV_NET) {
		/*
		 * Established the same way as Kernel-File's: one HTTP fetch under
		 * kofmontrace --raw, and the ids read off in the order they arrived -
		 * 12 first, then 10, then 11, and 13 after the process had exited.
		 * 18 also appears between them and is NOT typed: a fourth id in that
		 * position is most likely the copy-to-user step rather than a
		 * separate receive, and typing it as one would double every byte
		 * count computed from this stream.
		 */
		switch (id) {
		case 12: return KOF_EVT_NET_CONNECT;
		case 10: return KOF_EVT_NET_SEND;
		case 11: return KOF_EVT_NET_RECV;
		case 13: return KOF_EVT_NET_DISCONNECT;
		default: break;
		}
	} else if (prov == KOFW_PROV_FILE) {
		switch (id) {
		case EVID_FILE_CREATE_NEW: return KOF_EVT_FILE_NEW;
		case EVID_FILE_RENAME:     return KOF_EVT_FILE_RENAME;
		case EVID_FILE_DELETE:     return KOF_EVT_FILE_DELETE;
		/*
		 * FileIo Write. Established from its shape rather than from a
		 * list: `--schema` describes id 16 version 1 as ByteOffset,
		 * Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags,
		 * ExtraFlags - a size against a file handle, which is a write
		 * and nothing else.
		 *
		 * Note what it does NOT carry: a path. The target is named by
		 * FileObject, a kernel pointer, and turning those back into
		 * paths needs the FileKey->FileName records that arrive as id
		 * 10 to be kept in a map. Until that exists these are typed but
		 * pathless, which is still better than untyped.
		 */
		case 16u:                  return KOF_EVT_FILE_WRITE;
		default: break;
		}
	} else if (prov == KOFW_PROV_REGISTRY) {
		/*
		 * EMPTY ON PURPOSE, AND THIS IS NOT A TODO LEFT LYING ABOUT.
		 *
		 * Kernel-Registry's ids have not been established on a real
		 * machine, and the two other providers in this file say in
		 * their own comments how that is done: one operation at a
		 * time, a second apart, under `kofmontrace --raw --schema`,
		 * reading the id off the ordered trace. Numbers copied from
		 * documentation are how a table ends up decoding CREATE as
		 * SETVALUE - which is silent, because an event typed as the
		 * wrong thing is still a typed event.
		 *
		 * Until then every registry record arrives as RAW carrying its
		 * provider, id, version and key path, which is exactly what a
		 * discovery run needs and is strictly more honest than a
		 * guess. Filling this switch in afterwards is three lines.
		 *
		 *   case <id>: return KOF_EVT_REG_CREATE;
		 *   case <id>: return KOF_EVT_REG_SET_VALUE;
		 *   case <id>: return KOF_EVT_REG_DELETE;
		 */
	} else if (prov == KOFW_PROV_AMSI) {
		/*
		 * ESTABLISHED, on this machine, the same way as every other id
		 * here: run a script under the tracer and read the id off the
		 * line. It is 1101 version 1, and it was arriving all along -
		 * it printed as `[? id 1101 v1]` because kofw_provider_name had
		 * no case for AMSI, so a working provider read as an unknown
		 * one. Both halves of that are now fixed.
		 */
		if (id == 1101u)
			return KOF_EVT_AMSI_SCAN;
		/*
		 * EMPTY FOR THE SAME REASON, WITH A DIFFERENT OBSTACLE.
		 *
		 * Registry's ids are unestablished because nobody has run the
		 * discovery yet. AMSI's are unestablished because this machine
		 * CANNOT run it: Get-MpComputerStatus reports
		 * RealTimeProtectionEnabled = False, and with real-time
		 * protection off the scripting hosts stop submitting buffers,
		 * so the provider is correctly enabled and correctly silent.
		 *
		 * That is worth writing down precisely because it looks
		 * identical to a wrong GUID from the outside. The wiring was
		 * checked another way instead: MpOav.dll is registered as an
		 * AMSI provider under HKLM\SOFTWARE\Microsoft\AMSI\Providers,
		 * amsi.dll is present, and EnableTraceEx2 accepted the GUID.
		 * What is missing is production, not plumbing.
		 *
		 * To finish this: on a machine with real-time protection on,
		 * run `kofwatchtower --amsi --schema`, execute a script, and read
		 * the id off the shape dump. The property names are already
		 * mapped in field_of, so `content` will land in `object` the
		 * moment the id is typed - and until then these arrive as RAW
		 * with the content already visible, which is most of the value.
		 */
	}
	return KOF_EVT_RAW;
}

/* What this event type is expected to carry, so what is left over after the
 * walk is an honest answer to "what is missing". */
static uint32_t wanted(uint16_t type)
{
	switch (type) {
	case KOF_EVT_PROC_START:
		return KOFW_F_PID | KOFW_F_PPID | KOFW_F_CREATE_TIME |
		       KOFW_F_SESSION | KOFW_F_IMAGE;
	case KOF_EVT_PROC_STOP:
		return KOFW_F_PID | KOFW_F_CREATE_TIME | KOFW_F_EXIT_CODE |
		       KOFW_F_IMAGE;
	case KOF_EVT_IMAGE_LOAD:
	case KOF_EVT_IMAGE_UNLOAD:
		return KOFW_F_PID | KOFW_F_OBJECT;
	case KOF_EVT_FILE_NEW:
	case KOF_EVT_FILE_RENAME:
	case KOF_EVT_FILE_DELETE:
	case KOF_EVT_FILE_WRITE:
	case KOF_EVT_REG_CREATE:
	case KOF_EVT_REG_SET_VALUE:
	case KOF_EVT_REG_DELETE:
		/* No pid here on purpose: Kernel-File's payload does not repeat
		 * it, and the process that acted is the one the kernel was
		 * running - which the header already gave. Asking for a field
		 * the provider never sends would flag every file event as
		 * damaged. */
		return KOFW_F_OBJECT;
	default:
		/* A RAW event is by definition one whose shape this build does
		 * not know, so there is nothing it can be said to be missing.
		 * Claiming otherwise would flag every discovery record as
		 * damaged. */
		return 0;
	}
}

/*
 * How many bytes this type occupies, or 0 when it has to be measured against
 * the payload itself.
 *
 * BOOLEAN is four bytes here and not one. That is ETW's definition rather than
 * C's, and getting it wrong shifts every following field by three bytes - which
 * is exactly the class of silent misread this whole file exists to avoid.
 */
static uint16_t fixed_size(uint16_t in_type, int ptr32)
{
	switch (in_type) {
	case TDH_INTYPE_INT8:
	case TDH_INTYPE_UINT8:       return 1;
	case TDH_INTYPE_INT16:
	case TDH_INTYPE_UINT16:      return 2;
	case TDH_INTYPE_INT32:
	case TDH_INTYPE_UINT32:
	case TDH_INTYPE_HEXINT32:
	case TDH_INTYPE_FLOAT:
	case TDH_INTYPE_BOOLEAN:     return 4;
	case TDH_INTYPE_INT64:
	case TDH_INTYPE_UINT64:
	case TDH_INTYPE_HEXINT64:
	case TDH_INTYPE_DOUBLE:
	case TDH_INTYPE_FILETIME:    return 8;
	case TDH_INTYPE_GUID:        return 16;
	case TDH_INTYPE_SYSTEMTIME:  return 16;
	case TDH_INTYPE_POINTER:     return ptr32 ? 4 : 8;
	default:                     return 0;
	}
}

/* (prov, id, ver) into a slot. Knuth's multiplicative hash over the packed
 * key, which is what the process table already uses for a pid - a collision
 * costs one probe and never a wrong answer, because the entry is believed only
 * when all three fields match. */
static uint32_t schema_slot(uint8_t prov, uint16_t id, uint8_t ver)
{
	uint32_t key = ((uint32_t)prov << 24) | ((uint32_t)id << 8) | ver;

	return (key * 2654435761u) & (KOFW_SCHEMA_HASH - 1u);
}

static struct kofw_schema *find(struct kofw_schema_cache *c, uint8_t prov,
				uint16_t id, uint8_t ver)
{
	uint32_t s = schema_slot(prov, id, ver);
	uint32_t i;

	for (i = 0; i < KOFW_SCHEMA_HASH; i++) {
		uint32_t at = (s + i) & (KOFW_SCHEMA_HASH - 1u);
		uint16_t ix = c->hash[at];
		struct kofw_schema *sc;

		/* Empty, and nothing was ever removed - so the key is absent
		 * rather than further along. */
		if (ix == 0)
			return NULL;

		sc = &c->s[ix - 1u];
		if (sc->prov == prov && sc->id == id && sc->ver == ver)
			return sc;
	}
	return NULL;
}

/* Publish a freshly learned shape into the index. */
static void schema_index(struct kofw_schema_cache *c, uint32_t which)
{
	const struct kofw_schema *sc = &c->s[which];
	uint32_t s = schema_slot(sc->prov, sc->id, sc->ver);
	uint32_t i;

	for (i = 0; i < KOFW_SCHEMA_HASH; i++) {
		uint32_t at = (s + i) & (KOFW_SCHEMA_HASH - 1u);

		if (c->hash[at] == 0) {
			c->hash[at] = (uint16_t)(which + 1u);
			return;
		}
	}
}

static struct kofw_schema *learn(struct kofw_schema_cache *c, uint8_t prov,
				 uint16_t type,
				 const EVENT_RECORD *rec)
{
	TRACE_EVENT_INFO   *info = NULL;
	struct kofw_schema *sc;
	ULONG   sz = 0;
	TDHSTATUS st;
	int     ptr32 = (rec->EventHeader.Flags &
			 EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
	uint16_t id  = rec->EventHeader.EventDescriptor.Id;
	uint8_t  ver = rec->EventHeader.EventDescriptor.Version;
	ULONG   i;

	/*
	 * TDH's prototype is not const-correct - TdhGetEventInformation takes a
	 * PEVENT_RECORD and does not write through it - so the const has to be
	 * dropped somewhere. Laundered through uintptr_t once, here, rather
	 * than cast away at each call site: the tree builds with -Wcast-qual and
	 * the point of that flag is to catch the casts that are NOT this one.
	 */
	PEVENT_RECORD mut = (PEVENT_RECORD)(uintptr_t)rec;

	if (c->n >= KOFW_SCHEMA_MAX) {
		c->cache_full++;
		return NULL;
	}

	st = TdhGetEventInformation(mut, 0, NULL, NULL, &sz);
	if (st != ERROR_INSUFFICIENT_BUFFER || sz == 0) {
		c->learn_failed++;
		return NULL;
	}
	info = malloc(sz);
	if (!info) {
		c->learn_failed++;
		return NULL;
	}
	st = TdhGetEventInformation(mut, 0, NULL, info, &sz);
	if (st != ERROR_SUCCESS) {
		free(info);
		c->learn_failed++;
		return NULL;
	}

	sc = &c->s[c->n];
	memset(sc, 0, sizeof *sc);
	sc->id   = id;
	sc->prov = prov;
	sc->ver = ver;

	for (i = 0; i < info->TopLevelPropertyCount; i++) {
		const EVENT_PROPERTY_INFO *pi = &info->EventPropertyInfoArray[i];
		const wchar_t *name;
		uint16_t in_type, fx;
		uint8_t  len_from;

		if (sc->n_prop >= KOFW_SCHEMA_MAX_PROP) {
			sc->truncated = 1;
			break;
		}

		/*
		 * A nested structure, or a length or count that is another
		 * property's VALUE, cannot be stepped over without interpreting
		 * the payload. The shape stops here rather than guessing - see
		 * the header for why a wrong offset is worse than a missing
		 * field.
		 */
		if (pi->Flags & (PropertyStruct | PropertyParamCount)) {
			sc->truncated = 1;
			break;
		}

		/*
		 * A LENGTH THAT IS ANOTHER PROPERTY'S VALUE - resolved rather
		 * than refused. See kofw_prop.len_from for what this unblocked.
		 *
		 * Accepted only when that property is already in the shape and
		 * is a fixed-size integer, so its offset is known before this
		 * one is reached and reading it is arithmetic rather than a
		 * guess. Anything else still stops the walk.
		 */
		len_from = 0;
		if (pi->Flags & PropertyParamLength) {
			USHORT li = pi->lengthPropertyIndex;

			if (li < sc->n_prop && sc->prop[li].fixed &&
			    sc->prop[li].fixed <= 4u &&
			    sc->prop[li].in_type != TDH_INTYPE_UNICODESTRING &&
			    sc->prop[li].in_type != TDH_INTYPE_ANSISTRING) {
				len_from = (uint8_t)(li + 1u);
			} else {
				sc->truncated = 1;
				break;
			}
		}

		in_type = pi->nonStructType.InType;
		fx      = fixed_size(in_type, ptr32);

		if (fx == 0) {
			/* A string with a declared length is still fixed; one
			 * without has to be measured per record. */
			if (in_type == TDH_INTYPE_UNICODESTRING && pi->length)
				fx = (uint16_t)(pi->length * 2u);
			else if (in_type == TDH_INTYPE_ANSISTRING && pi->length)
				fx = pi->length;
			else if (in_type == TDH_INTYPE_BINARY && pi->length)
				fx = pi->length;
			else if (in_type != TDH_INTYPE_UNICODESTRING &&
				 in_type != TDH_INTYPE_ANSISTRING &&
				 in_type != TDH_INTYPE_SID) {
				/* Something this build cannot size at all. */
				sc->truncated = 1;
				break;
			}
		}

		/* A fixed-count array of a fixed-size type is just a bigger
		 * fixed size; anything else in an array is not walkable. */
		if (pi->count > 1) {
			if (fx == 0 || pi->count > 0xffffu / fx) {
				sc->truncated = 1;
				break;
			}
			fx = (uint16_t)(fx * pi->count);
		}

		name = (const wchar_t *)((const char *)info + pi->NameOffset);

		sc->prop[sc->n_prop].in_type  = in_type;
		sc->prop[sc->n_prop].fixed    = fx;
		sc->prop[sc->n_prop].len_from = len_from;
		/* A length that comes from elsewhere is not a fixed size, and
		 * leaving `fixed` set would make the walk step by the wrong
		 * amount before ever consulting it. */
		if (len_from)
			sc->prop[sc->n_prop].fixed = 0;
		sc->prop[sc->n_prop].field   = pi->NameOffset
						       ? field_of(name, type, prov)
						       : KOFW_FLD_SKIP;
		if (pi->NameOffset) {
			char  *d = sc->prop[sc->n_prop].name;
			size_t k;
			for (k = 0; k + 1 < sizeof sc->prop[0].name && name[k];
			     k++)
				d[k] = (name[k] < 0x80) ? (char)name[k] : '?';
			d[k] = '\0';
		}
		sc->n_prop++;
	}

	free(info);

	sc->in_use = 1;
	schema_index(c, c->n);
	c->n++;
	return sc;
}

/* ------------------------------------------------------------- one payload */

static uint32_t rd_u32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, sizeof v);
	return v;
}

static uint64_t rd_u64(const uint8_t *p)
{
	uint64_t v;
	memcpy(&v, p, sizeof v);
	return v;
}

/*
 * How long the property at `p` is, given a shape that could not state it.
 * SIZE_MAX when it runs past the payload, which stops the walk.
 */
static size_t measure(uint16_t in_type, const uint8_t *p, size_t left)
{
	size_t i;

	switch (in_type) {
	case TDH_INTYPE_UNICODESTRING:
		for (i = 0; i + 1 < left; i += 2) {
			if (p[i] == 0 && p[i + 1] == 0)
				return i + 2;
		}
		/* Unterminated: the provider gave the rest of the payload as the
		 * string, which is legal and is how the last field often looks. */
		return left;

	case TDH_INTYPE_ANSISTRING:
		for (i = 0; i < left; i++) {
			if (p[i] == 0)
				return i + 1;
		}
		return left;

	case TDH_INTYPE_SID: {
		size_t sub;
		if (left < 8)
			return SIZE_MAX;
		sub = p[1];
		if (8u + sub * 4u > left)
			return SIZE_MAX;
		return 8u + sub * 4u;
	}

	default:
		return SIZE_MAX;
	}
}

int kofw_decode(struct kofw_schema_cache *c, const EVENT_RECORD *rec,
		struct kofw_evt *out)
{
	/* Not const: the shape's own hit counter is bumped below, and it is
	 * this thread's to bump - there is one producer by construction. */
	struct kofw_schema *sc;
	const uint8_t *base;
	size_t   off, total, tnext = 0;
	/* The longest string no named field claimed - see KOFW_FLD_SKIP in the
	 * walk below, and the use after it. */
	size_t   spare_off = 0, spare_len = 0;
	uint16_t spare_type = 0;
	uint16_t id, type;
	uint32_t want;
	size_t   prop_at[KOFW_SCHEMA_MAX_PROP];
	uint8_t  prov;
	uint8_t  i;

	prov = kofw_provider_of(&rec->EventHeader.ProviderId);
	if (prov == KOFW_PROV_NONE)
		return 0;

	id   = rec->EventHeader.EventDescriptor.Id;
	type = type_of(prov, id);

	sc = find(c, prov, id, rec->EventHeader.EventDescriptor.Version);
	if (!sc) {
		sc = learn(c, prov, type, rec);
		if (!sc)
			return 0;
	}
	/* One producer, one cache line this thread already owns - see the note
	 * on kofw_schema.hits for why a count and not just a list. */
	sc->hits++;

	memset(out, 0, sizeof *out);
	out->type        = type;
	out->provider    = prov;
	out->raw_id      = id;
	out->raw_version = rec->EventHeader.EventDescriptor.Version;
	out->stamp       = (uint64_t)rec->EventHeader.TimeStamp.QuadPart;
	out->tid         = rec->EventHeader.ThreadId;
	out->raiser_pid  = rec->EventHeader.ProcessId;
	out->cpu         = rec->BufferContext.ProcessorNumber;
	out->off_image   = KOF_TEXT_NONE;
	out->off_object  = KOF_TEXT_NONE;
	/*
	 * NONE, not the zero a memset leaves.
	 *
	 * Zero is a valid offset into text[], so a record that never had a
	 * command line read into it would answer kofw_evt_cmdline() with
	 * whatever sits at offset 0 - which is the image path. Every file,
	 * network and registry event would have reported the process image as
	 * its command line, and that reads like data.
	 */
	out->off_cmdline = KOF_TEXT_NONE;

	/*
	 * THE SUBJECT DEFAULTS TO WHOEVER RAISED THE EVENT.
	 *
	 * For a file event that is the whole answer - the process that made the
	 * file IS the one the kernel was running - and the payload does not
	 * repeat it. For a process event the payload overrides this below,
	 * because there the subject is the process being started or stopped and
	 * the raiser is somebody else.
	 */
	out->pid = rec->EventHeader.ProcessId;

	want = wanted(type);
	base = (const uint8_t *)rec->UserData;
	total = rec->UserDataLength;
	off   = 0;

	/*
	 * WHERE EACH PROPERTY LANDED, so a property whose length is another
	 * property's value can read that value. Only the fixed-size ones are
	 * ever consulted - see kofw_prop.len_from - and the walk is strictly
	 * forward, so the entry is always written before it is read.
	 */
	memset(prop_at, 0, sizeof prop_at);

	for (i = 0; i < sc->n_prop; i++) {
		const struct kofw_prop *pr = &sc->prop[i];
		size_t len = pr->fixed;

		if (off >= total)
			break;

		prop_at[i] = off;

		if (pr->len_from) {
			/* The length is the value of a property already
			 * walked. Read it at its recorded offset rather than
			 * re-deriving where it was. */
			const struct kofw_prop *lp = &sc->prop[pr->len_from - 1u];
			size_t lat = prop_at[pr->len_from - 1u];
			uint32_t v = 0;

			if (lat + lp->fixed > total)
				break;
			if (lp->fixed == 1u)
				v = base[lat];
			else if (lp->fixed == 2u)
				v = (uint32_t)base[lat] |
				    ((uint32_t)base[lat + 1u] << 8);
			else
				v = rd_u32(base + lat);
			len = v;
		} else if (len == 0) {
			len = measure(pr->in_type, base + off, total - off);
			if (len == SIZE_MAX)
				break;
		}
		if (len > total - off)
			break;

		switch (pr->field) {
		case KOFW_FLD_PID:
			if (len >= 4) {
				out->pid = rd_u32(base + off);
				want &= ~(uint32_t)KOFW_F_PID;
			}
			break;
		case KOFW_FLD_PPID:
			if (len >= 4) {
				out->ppid = rd_u32(base + off);
				want &= ~(uint32_t)KOFW_F_PPID;
			}
			break;
		case KOFW_FLD_SESSION:
			if (len >= 4) {
				out->session_id = rd_u32(base + off);
				want &= ~(uint32_t)KOFW_F_SESSION;
			}
			break;
		case KOFW_FLD_EXIT_CODE:
			if (len >= 4) {
				out->exit_code = rd_u32(base + off);
				want &= ~(uint32_t)KOFW_F_EXIT_CODE;
			}
			break;
		case KOFW_FLD_CREATE_TIME:
			if (len >= 8) {
				out->create_time = rd_u64(base + off);
				want &= ~(uint32_t)KOFW_F_CREATE_TIME;
			}
			break;
		case KOFW_FLD_DADDR:
			if (len >= 4)
				out->net_daddr = rd_u32(base + off);
			break;
		case KOFW_FLD_SADDR:
			if (len >= 4)
				out->net_saddr = rd_u32(base + off);
			break;
		case KOFW_FLD_DPORT:
			if (len >= 2)
				memcpy(&out->net_dport, base + off, 2);
			break;
		case KOFW_FLD_SPORT:
			if (len >= 2)
				memcpy(&out->net_sport, base + off, 2);
			break;
		case KOFW_FLD_SIZE:
			if (len >= 4)
				out->net_size = rd_u32(base + off);
			break;
		case KOFW_FLD_FILE_KEY:
			/* Into `addr`, which a file event never uses for
			 * anything else - a write has no entry point. The
			 * consumer thread resolves it to a path; see
			 * kofw_ftab_resolve. */
			if (!out->addr) {
				if (len >= 8)
					out->addr = rd_u64(base + off);
				else if (len >= 4)
					out->addr = rd_u32(base + off);
			}
			break;
		case KOFW_FLD_ADDR:
			/* 8 on a 64-bit payload, 4 on a 32-bit one - the shape
			 * already sized it as a POINTER, so take what is
			 * there rather than assuming the wider form. */
			if (len >= 8)
				out->addr = rd_u64(base + off);
			else if (len >= 4)
				out->addr = rd_u32(base + off);
			break;
		case KOFW_FLD_ADDR_SIZE:
			if (len >= 8)
				out->addr_size = rd_u64(base + off);
			else if (len >= 4)
				out->addr_size = rd_u32(base + off);
			break;

		/*
		 * A STRING NOBODY CLAIMED, remembered in case nothing does.
		 *
		 * An event whose property names this build has never seen -
		 * every provider on its first encounter - fills no string field
		 * and renders as a bare `[prov id v]` with nothing after it.
		 * That reads as "the event carried nothing", which is what AMSI
		 * looked like for a whole session while it was in fact carrying
		 * the script.
		 *
		 * So the longest unclaimed string is kept, and used below only
		 * if no named field took the object slot. Longest rather than
		 * first, because the payload that matters is the content and
		 * the ones beside it are labels: an application name and a
		 * content name are short, a submitted script block is not.
		 *
		 * A fallback, never an override. Anything this build actually
		 * recognises still wins.
		 */
		case KOFW_FLD_SKIP:
			if ((pr->in_type == TDH_INTYPE_UNICODESTRING ||
			     pr->in_type == TDH_INTYPE_ANSISTRING) &&
			    len > spare_len) {
				spare_off  = off;
				spare_len  = len;
				spare_type = pr->in_type;
			}
			break;

		case KOFW_FLD_IMAGE:
		case KOFW_FLD_OBJECT: {
			int    cut = 0;
			size_t room, n = 0;
			int    got = 1;

			/*
			 * Both strings share one arena and are appended in the
			 * order the payload happens to carry them, so the second
			 * gets whatever the first left. A path that has to be cut
			 * because of that is still flagged - a truncated path
			 * that looks whole is exactly what a later rule would
			 * match against and be wrong about.
			 */
			if (tnext + 1 >= sizeof out->text)
				break;
			room = sizeof out->text - tnext;

			if (pr->in_type == TDH_INTYPE_UNICODESTRING)
				n = kofw_utf16_to_utf8(
					(const uint16_t *)(const void *)
						(base + off),
					len / 2u, out->text + tnext, room,
					&cut);
			else if (pr->in_type == TDH_INTYPE_ANSISTRING)
				n = kofw_ansi_to_text(base + off, len,
						      out->text + tnext, room,
						      &cut);
			/*
			 * A BINARY BUFFER, which is what AMSI's `content` is.
			 *
			 * Not a string type, so it used to be skipped entirely
			 * - the second of the two reasons the one field that
			 * subscription exists for never appeared.
			 *
			 * WHICH ENCODING IS A HEURISTIC AND IS LABELLED AS
			 * ONE: a PowerShell script block arrives as UTF-16 and
			 * a macro body as bytes, and the provider does not say
			 * which. Two NUL high bytes in the first four is the
			 * test.
			 *
			 * AND IT IS NO LONGER CONVERTED AT ALL. Sanitising -
			 * high bytes to '?', control characters to '.' - was
			 * justified by the record being printed, and this
			 * record is not printed: it goes over a channel to
			 * kofwatchman, whose entire purpose is to SCAN what is
			 * in it. A lossy conversion here destroys the evidence
			 * before the half that needs it ever sees it, so the
			 * bytes are copied verbatim and content_len says how
			 * many. Whoever PRINTS one sanitises it there, which is
			 * where the terminal is.
			 */
			else if (pr->in_type == TDH_INTYPE_BINARY) {
				size_t take = len;

				if (take > room - 1u) {
					take = room - 1u;
					cut = 1;
				}
				memcpy(out->text + tnext, base + off, take);
				/*
				 * Length-delimited, but still NUL terminated
				 * after it: content_len is what a scanner
				 * reads, and the NUL is so that anything
				 * treating the arena as strings - a label, a
				 * panel row - cannot run off the end of it.
				 */
				out->text[tnext + take] = '\0';
				out->content_len = (uint16_t)take;
				n = take;
			}
			else
				got = 0;

			if (got) {
				if (pr->field == KOFW_FLD_IMAGE) {
					out->off_image = (uint16_t)tnext;
					want &= ~(uint32_t)KOFW_F_IMAGE;
				} else {
					out->off_object = (uint16_t)tnext;
					want &= ~(uint32_t)KOFW_F_OBJECT;
				}
				tnext += n + 1u;
				out->text_len = (uint16_t)tnext;
				if (cut)
					out->flags |= KOFW_EF_TRUNCATED;
			}
			break;
		}

		default:
			break;
		}

		off += len;
	}

	/*
	 * THE UNCLAIMED STRING, used only if nothing named took the slot.
	 *
	 * This is what makes a provider legible on its first encounter instead
	 * of on the second, after somebody has read a shape dump and added its
	 * property names. The record still says which provider and which id it
	 * came from, so the string is offered as "here is what it carried", not
	 * as a field this build understands.
	 */
	if (out->off_object == KOF_TEXT_NONE && spare_len &&
	    tnext + 1u < sizeof out->text) {
		size_t room = sizeof out->text - tnext, n = 0;
		int    cut = 0;

		if (spare_type == TDH_INTYPE_UNICODESTRING)
			n = kofw_utf16_to_utf8(
				(const uint16_t *)(const void *)
					(base + spare_off),
				spare_len / 2u, out->text + tnext, room, &cut);
		else
			n = kofw_ansi_to_text(base + spare_off, spare_len,
					      out->text + tnext, room, &cut);
		if (n) {
			out->off_object = (uint16_t)tnext;
			tnext += n + 1u;
			out->text_len = (uint16_t)tnext;
			if (cut)
				out->flags |= KOFW_EF_TRUNCATED;
		}
	}

	out->miss = want;
	if (want)
		out->flags |= KOFW_EF_PARTIAL;

	return 1;
}

/* --------------------------------------------------------- what was learned */

static const char *field_name(uint8_t f)
{
	switch (f) {
	case KOFW_FLD_PID:         return "-> pid";
	case KOFW_FLD_PPID:        return "-> ppid";
	case KOFW_FLD_CREATE_TIME: return "-> create_time";
	case KOFW_FLD_SESSION:     return "-> session";
	case KOFW_FLD_EXIT_CODE:   return "-> exit_code";
	case KOFW_FLD_ADDR:        return "-> addr";
	case KOFW_FLD_ADDR_SIZE:   return "-> addr_size";
	case KOFW_FLD_IMAGE:       return "-> image";
	case KOFW_FLD_OBJECT:      return "-> object";
	default:                   return "";
	}
}

size_t kofw_schema_describe(const struct kofw_schema_cache *c, char *buf,
			    size_t cap)
{
	size_t o = 0;
	uint32_t i;
	uint8_t  j;
	int      n;

	if (!c || !buf || cap == 0)
		return 0;
	buf[0] = '\0';

	/*
	 * SAID OUT LOUD, because an empty dump is an ANSWER and an empty dump
	 * that prints nothing looks like a broken flag.
	 *
	 * A shape is learned the first time a record of that (provider, id,
	 * version) reaches the decoder. So "no shape for the net provider" is
	 * not "the events were filtered" or "the ids are wrong" - it is "not
	 * one network record was ever delivered", which points at the session
	 * and the keyword rather than at anything downstream. That is a
	 * different bug with a different fix, and this line is what separates
	 * them.
	 */
	if (c->n == 0) {
		n = snprintf(buf + o, cap - o,
			     "no shapes learned: not one event reached the "
			     "decoder, so nothing was filtered - the session "
			     "or the keyword is what delivered nothing\n");
		return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
	}

	for (i = 0; i < c->n; i++) {
		const struct kofw_schema *s = &c->s[i];

		n = snprintf(buf + o, cap - o,
			     "%-8s event %-3u v%-2u %10llu record(s)  "
			     "%u properties%s\n",
			     kofw_provider_name(s->prov),
			     (unsigned)s->id, (unsigned)s->ver,
			     (unsigned long long)s->hits,
			     (unsigned)s->n_prop,
			     s->truncated ? "  [SHAPE TRUNCATED - the walk "
					    "stopped early, so everything "
					    "after the last line below is "
					    "unreachable]"
					  : "");
		if (n < 0 || (size_t)n >= cap - o)
			return o;
		o += (size_t)n;

		for (j = 0; j < s->n_prop; j++) {
			const struct kofw_prop *p = &s->prop[j];

			n = snprintf(buf + o, cap - o,
				     "    %-28s intype %-3u %-8s %s\n",
				     p->name[0] ? p->name : "(unnamed)",
				     (unsigned)p->in_type,
				     p->fixed ? "fixed" : "measured",
				     field_name(p->field));
			if (n < 0 || (size_t)n >= cap - o)
				return o;
			o += (size_t)n;
		}
	}

	if (c->learn_failed) {
		n = snprintf(buf + o, cap - o,
			     "%llu event(s) TDH would not describe at all\n",
			     (unsigned long long)c->learn_failed);
		if (n > 0 && (size_t)n < cap - o)
			o += (size_t)n;
	}

	/*
	 * Said in full rather than as a number, because it is the one line here
	 * that means the collector is no longer collecting everything it was
	 * asked for - and the shape it stopped at is the last one listed above,
	 * which is what somebody reading this needs in order to know what it
	 * ran out on.
	 */
	if (c->cache_full) {
		n = snprintf(buf + o, cap - o,
			     "SCHEMA CACHE FULL at %u shapes: %llu event(s) "
			     "were dropped whole because no slot was left to "
			     "learn them, and every further NEW (id, version) "
			     "will be too\n",
			     (unsigned)KOFW_SCHEMA_MAX,
			     (unsigned long long)c->cache_full);
		if (n > 0 && (size_t)n < cap - o)
			o += (size_t)n;
	}

	return o;
}
