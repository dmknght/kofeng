/*
 * wevt_decode.h - turning one provider's payload into a kofw_evt.
 *
 * WHY TDH IS USED ONCE AND THEN NOT AGAIN
 *
 * TdhGetEventInformation answers "what is in this event" by finding and parsing
 * the provider's manifest, and TdhFormatProperty then allocates and formats
 * each field into a string. Both are the documented way to read an ETW event
 * and both are far too slow to run per record: the manifest lookup is the
 * expensive part and the answer is the same every time.
 *
 * But the answer is only the same for a given (provider, event id, VERSION),
 * and the version is what a hand-written offset table gets wrong. Microsoft
 * revises these payloads between Windows builds - fields are appended, and
 * ProcessStart alone has shipped several versions - so a table that was correct
 * when it was written reads the wrong bytes on the next release, silently,
 * because a payload that is the wrong shape is still a payload.
 *
 * So: ask TDH once per (id, version) actually seen, keep the shape it
 * describes, and decode every later record by walking that shape. Correct
 * across builds because nothing is assumed, and cheap because the lookup
 * happens once.
 *
 *
 * WHAT HAPPENS WHEN THE SHAPE CANNOT BE WALKED
 *
 * A property whose size depends on another property's value, or a nested
 * structure, cannot be stepped over without interpreting it. Rather than guess
 * and read every following field from the wrong offset, the learned shape STOPS
 * at that property. Fields before it are decoded; fields after it are reported
 * absent through kofw_evt.miss.
 *
 * That is the whole reason `miss` exists. Reading garbage into a field that
 * looks plausible is the failure mode this design exists to prevent - it is
 * silent, it is downstream of everything, and it is indistinguishable from a
 * fact until somebody acts on it.
 */

#ifndef KOFGRILLE_WEVT_DECODE_H
#define KOFGRILLE_WEVT_DECODE_H

#include <windows.h>
#include <evntcons.h>

#include "kofgrille.h"

/* How many properties of one event are described. Kernel-Process's largest
 * payload is fifteen; past this the shape is truncated exactly as it is for an
 * unwalkable property, and the fields that fit are still decoded. */
#define KOFW_SCHEMA_MAX_PROP 32u

/* How many distinct (id, version) pairs are remembered. One provider with two
 * event ids needs a handful even across a Windows upgrade in flight. */
#define KOFW_SCHEMA_MAX 64u

/*
 * The providers, defined once and shared with the session that enables them.
 *
 * VERIFY THESE RATHER THAN TRUST THEM: `logman query providers <name>` prints
 * the GUID and the keyword table this build assumes. It matters because
 * EnableTraceEx2 SUCCEEDS for a provider GUID nothing publishes - the session
 * starts, the keyword is accepted, and no event ever arrives. A wrong GUID does
 * not look like an error, it looks like a quiet machine.
 */
extern const GUID KOFW_GUID_KERNEL_PROCESS;   /* Microsoft-Windows-Kernel-Process */
extern const GUID KOFW_GUID_KERNEL_FILE;      /* Microsoft-Windows-Kernel-File */
extern const GUID KOFW_GUID_KERNEL_NET;       /* Microsoft-Windows-Kernel-Network */

struct kofw_prop {
	uint16_t in_type;   /* TDH_INTYPE_* */
	uint16_t fixed;     /* size in bytes, or 0 when it must be measured */
	uint8_t  field;     /* enum kofw_field */

	/*
	 * The manifest's own name for this property, kept rather than discarded
	 * once it has been matched.
	 *
	 * It costs a few hundred bytes per event type, once, and it is the
	 * difference between "a field is missing" and "here is the shape that
	 * arrived and here is where the walk stopped". A truncated schema
	 * without names is not diagnosable at all - which was learned by having
	 * one.
	 */
	char     name[28];
};

struct kofw_schema {
	uint16_t id;
	uint8_t  prov;       /* enum kofw_provider */
	uint8_t  ver;
	uint8_t  in_use;
	uint8_t  truncated;  /* the shape stops early - see the header comment */
	uint8_t  n_prop;
	struct kofw_prop prop[KOFW_SCHEMA_MAX_PROP];
};

struct kofw_schema_cache {
	struct kofw_schema s[KOFW_SCHEMA_MAX];
	uint32_t n;
	uint64_t learn_failed;   /* TDH would not describe an event at all */

	/*
	 * Shapes that never got a slot because the cache was full.
	 *
	 * Counted apart from learn_failed because they say opposite things. A
	 * TDH failure is one event this build could not read; a full cache is a
	 * COLLECTOR that has stopped learning - every new (id, version) from
	 * here on is refused, permanently, and no later event of that shape is
	 * ever decoded. One is a record, the other is a state.
	 */
	uint64_t cache_full;
};

/* Which normalised field a property feeds. */
enum kofw_field {
	KOFW_FLD_SKIP = 0,
	KOFW_FLD_PID,
	KOFW_FLD_PPID,
	KOFW_FLD_CREATE_TIME,
	KOFW_FLD_SESSION,
	KOFW_FLD_EXIT_CODE,
	KOFW_FLD_IMAGE,
	KOFW_FLD_OBJECT,
	KOFW_FLD_DADDR,
	KOFW_FLD_SADDR,
	KOFW_FLD_DPORT,
	KOFW_FLD_SPORT,
	KOFW_FLD_SIZE
};

/*
 * Turn a provider GUID into an enum, or KOFW_PROV_NONE.
 *
 * Here rather than in the session because the DECODE is what has to branch on
 * it; the session only has to enable the thing.
 */
uint8_t kofw_provider_of(const GUID *);

/*
 * Fill `out` from `rec`, learning the shape if this is the first of its kind.
 *
 * Non-zero if the record was decoded into something worth keeping. Zero when
 * the event is not one this build wants, or when TDH would not describe it -
 * the caller counts the second case, which is why they are not distinguished
 * further here.
 */
int kofw_decode(struct kofw_schema_cache *, const EVENT_RECORD *rec,
		struct kofw_evt *out);

/* The string conversions live in wtext.h, which includes no Windows header -
 * see that file for why the boundary is where it is. */

/*
 * Render every shape learned so far as text. Returns bytes written, excluding
 * the NUL, and never writes past `cap`.
 *
 * Rendered here rather than handing the structs out, because the shapes are an
 * artefact of the decode and not something a caller should be able to act on -
 * what a caller needs is to be able to SEE them when a field it expected did
 * not arrive.
 */
size_t kofw_schema_describe(const struct kofw_schema_cache *, char *buf,
			    size_t cap);

#endif /* KOFGRILLE_WEVT_DECODE_H */
