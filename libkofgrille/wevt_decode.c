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
 * KOFW_EVT_HEAD is how the text arena is sized, so if a field is ever added
 * above text[] without moving it, every string in every record silently starts
 * at the wrong offset - and a path read from the wrong offset still looks like
 * a path. The header said this was checked here. It was not, until now.
 */
_Static_assert(offsetof(struct kofw_evt, text) == KOFW_EVT_HEAD,
	       "KOFW_EVT_HEAD no longer matches the record layout");
_Static_assert(sizeof(struct kofw_evt) == KOFW_EVT_SIZE,
	       "struct kofw_evt is not KOFW_EVT_SIZE bytes");

const GUID KOFW_GUID_KERNEL_PROCESS = {
	0x22fb2cd6, 0x0e7b, 0x422b,
	{ 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 }
};

const GUID KOFW_GUID_KERNEL_NET = {
	0x7dd42a49, 0x5329, 0x4832,
	{ 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
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
	return KOFW_PROV_NONE;
}

#define EVID_PROCESS_START 1u
#define EVID_PROCESS_STOP  2u
#define EVID_IMAGE_LOAD    5u

/*
 * KERNEL-FILE'S IDS, AND HOW THEY WERE ESTABLISHED.
 *
 * Not copied from documentation, and not guessed. Each was watched into place:
 * a script performed one operation at a time, a second apart, under kofwintrace
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
static uint8_t field_of(const wchar_t *name, uint16_t type)
{
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

	/* Whatever this provider calls the path it acted on. FileName is
	 * Kernel-File's spelling; the others are here because a RAW event is
	 * worth rendering with its path rather than without. */
	if (name_is(name, "FileName") || name_is(name, "FilePath") ||
	    name_is(name, "OldFileName") || name_is(name, "NewFileName"))
		return KOFW_FLD_OBJECT;

	if (name_is(name, "daddr")) return KOFW_FLD_DADDR;
	if (name_is(name, "saddr")) return KOFW_FLD_SADDR;
	if (name_is(name, "dport")) return KOFW_FLD_DPORT;
	if (name_is(name, "sport")) return KOFW_FLD_SPORT;
	if (name_is(name, "size"))  return KOFW_FLD_SIZE;

	if (name_is(name, "ImageName")) {
		if (type == KOFW_EVT_PROC_START || type == KOFW_EVT_PROC_STOP)
			return KOFW_FLD_IMAGE;
		return KOFW_FLD_OBJECT;
	}
	return KOFW_FLD_SKIP;
}

/* What a (provider, id) pair means to this build, or KOFW_EVT_RAW when nothing
 * yet. */
static uint16_t type_of(uint8_t prov, uint16_t id)
{
	if (prov == KOFW_PROV_PROCESS) {
		switch (id) {
		case EVID_PROCESS_START: return KOFW_EVT_PROC_START;
		case EVID_PROCESS_STOP:  return KOFW_EVT_PROC_STOP;
		case EVID_IMAGE_LOAD:    return KOFW_EVT_IMAGE_LOAD;
		default: break;
		}
	} else if (prov == KOFW_PROV_NET) {
		/*
		 * Established the same way as Kernel-File's: one HTTP fetch under
		 * kofwintrace --raw, and the ids read off in the order they arrived -
		 * 12 first, then 10, then 11, and 13 after the process had exited.
		 * 18 also appears between them and is NOT typed: a fourth id in that
		 * position is most likely the copy-to-user step rather than a
		 * separate receive, and typing it as one would double every byte
		 * count computed from this stream.
		 */
		switch (id) {
		case 12: return KOFW_EVT_NET_CONNECT;
		case 10: return KOFW_EVT_NET_SEND;
		case 11: return KOFW_EVT_NET_RECV;
		case 13: return KOFW_EVT_NET_DISCONNECT;
		default: break;
		}
	} else if (prov == KOFW_PROV_FILE) {
		switch (id) {
		case EVID_FILE_CREATE_NEW: return KOFW_EVT_FILE_NEW;
		case EVID_FILE_RENAME:     return KOFW_EVT_FILE_RENAME;
		case EVID_FILE_DELETE:     return KOFW_EVT_FILE_DELETE;
		default: break;
		}
	}
	return KOFW_EVT_RAW;
}

/* What this event type is expected to carry, so what is left over after the
 * walk is an honest answer to "what is missing". */
static uint32_t wanted(uint16_t type)
{
	switch (type) {
	case KOFW_EVT_PROC_START:
		return KOFW_F_PID | KOFW_F_PPID | KOFW_F_CREATE_TIME |
		       KOFW_F_SESSION | KOFW_F_IMAGE;
	case KOFW_EVT_PROC_STOP:
		return KOFW_F_PID | KOFW_F_CREATE_TIME | KOFW_F_EXIT_CODE |
		       KOFW_F_IMAGE;
	case KOFW_EVT_IMAGE_LOAD:
		return KOFW_F_PID | KOFW_F_OBJECT;
	case KOFW_EVT_FILE_NEW:
	case KOFW_EVT_FILE_RENAME:
	case KOFW_EVT_FILE_DELETE:
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

static struct kofw_schema *find(struct kofw_schema_cache *c, uint8_t prov,
				uint16_t id, uint8_t ver)
{
	uint32_t i;

	for (i = 0; i < c->n; i++) {
		if (c->s[i].in_use && c->s[i].prov == prov &&
		    c->s[i].id == id && c->s[i].ver == ver)
			return &c->s[i];
	}
	return NULL;
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
		if (pi->Flags & (PropertyStruct | PropertyParamLength |
				 PropertyParamCount)) {
			sc->truncated = 1;
			break;
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

		sc->prop[sc->n_prop].in_type = in_type;
		sc->prop[sc->n_prop].fixed   = fx;
		sc->prop[sc->n_prop].field   = pi->NameOffset
						       ? field_of(name, type)
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
	const struct kofw_schema *sc;
	const uint8_t *base;
	size_t   off, total, tnext = 0;
	uint16_t id, type;
	uint32_t want;
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

	memset(out, 0, sizeof *out);
	out->type        = type;
	out->provider    = prov;
	out->raw_id      = id;
	out->raw_version = rec->EventHeader.EventDescriptor.Version;
	out->stamp       = (uint64_t)rec->EventHeader.TimeStamp.QuadPart;
	out->tid         = rec->EventHeader.ThreadId;
	out->raiser_pid  = rec->EventHeader.ProcessId;
	out->cpu         = rec->BufferContext.ProcessorNumber;
	out->off_image   = KOFW_TEXT_NONE;
	out->off_object  = KOFW_TEXT_NONE;

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

	for (i = 0; i < sc->n_prop; i++) {
		const struct kofw_prop *pr = &sc->prop[i];
		size_t len = pr->fixed;

		if (off >= total)
			break;

		if (len == 0) {
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

	for (i = 0; i < c->n; i++) {
		const struct kofw_schema *s = &c->s[i];

		n = snprintf(buf + o, cap - o,
			     "event %u version %u: %u properties%s\n",
			     (unsigned)s->id, (unsigned)s->ver,
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
