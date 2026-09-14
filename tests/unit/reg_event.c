/*
 * reg_event.c - the registry decode, over hand-built ETW records.
 *
 * WHAT IT IS ACTUALLY TESTING, and why it can run at all.
 *
 * Kernel-Registry is a kernel provider: seeing one of its events for real needs
 * an elevated prompt, an ETW session and something writing to the registry, and
 * none of that belongs in a test run. But the part that breaks is not the
 * session - it is the DECODE, and the decode takes an EVENT_RECORD.
 *
 * So the records here are built by hand and handed straight to kofw_decode.
 * TdhGetEventInformation resolves a shape from the provider GUID and the event
 * id against the manifest Windows already has registered, so `learn` runs for
 * real against the real template - which means this exercises the schema cache,
 * the property walk, the length-from-another-property resolution that
 * CapturedData needs, and the field mapping, all without a trace.
 *
 * THE TEMPLATES THESE PAYLOADS ARE BUILT TO, read off the live manifest with
 *
 *     (Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Registry).Events
 *
 *   id 1  CreateKey     BaseObject KeyObject Status Disposition
 *                       BaseName RelativeName
 *   id 5  SetValueKey   KeyObject Status Type DataSize KeyName ValueName
 *                       CapturedDataSize CapturedData PreviousDataType
 *                       PreviousDataSize PreviousDataCapturedSize PreviousData
 *   id 6  DeleteValueKey  KeyObject Status KeyName ValueName
 *
 * IF A FUTURE WINDOWS CHANGES ONE, THIS TEST SAYS SO rather than the collector
 * going quiet in production - which is the failure mode wevt_etw.c already
 * records for a wrong keyword: the session delivers thousands of records and
 * none of them is the one anybody wanted.
 *
 * WHAT IT IS GUARDING, stated as the bug it was written for: KeyName and
 * ValueName both used to map to the object slot, the walk's last match won, and
 * every registry event in the product kept the value name and threw the key
 * path away. "Updater" instead of "...\CurrentVersion\Run\Updater" - which
 * matches no location rule, carries no ATT&CK technique, and reads like a
 * working collector.
 */

#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <evntrace.h>

#include "kofgrille.h"
#include "wevt_decode.h"
#include "wtext.h"
#include "kofevtfmt.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

/* ------------------------------------------------------- building a payload */

/*
 * A payload is built by appending, because that is what a provider does and
 * because the walk's whole job is to step fields whose sizes are only known in
 * order. Nothing here is aligned or padded: ETW payloads are packed, and a
 * builder that padded would produce records the real decoder never sees.
 */
struct pay {
	unsigned char b[1024];
	size_t        n;
};

static void p_bytes(struct pay *p, const void *src, size_t n)
{
	if (p->n + n > sizeof p->b)
		return;
	memcpy(p->b + p->n, src, n);
	p->n += n;
}

static void p_u16(struct pay *p, uint16_t v) { p_bytes(p, &v, sizeof v); }
static void p_u32(struct pay *p, uint32_t v) { p_bytes(p, &v, sizeof v); }
static void p_u64(struct pay *p, uint64_t v) { p_bytes(p, &v, sizeof v); }

/* A UTF-16LE string with its terminator, which is what win:UnicodeString is. */
static void p_wstr(struct pay *p, const char *ascii)
{
	size_t i;

	for (i = 0; ascii[i]; i++)
		p_u16(p, (uint16_t)(unsigned char)ascii[i]);
	p_u16(p, 0);
}

/*
 * Kernel-Registry's GUID, the same constant the decoder carries. Taken from
 * there rather than spelled again here: two copies of a GUID is the shape that
 * lets a test pass against a provider the product does not actually subscribe
 * to.
 */
static int decode_one(struct kofw_schema_cache *c, uint16_t id,
		      const struct pay *p, struct kofw_evt *out)
{
	EVENT_RECORD rec;

	memset(&rec, 0, sizeof rec);
	rec.EventHeader.Size  = (USHORT)sizeof rec.EventHeader;
	rec.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
	rec.EventHeader.ProviderId = KOFW_GUID_KERNEL_REGISTRY;
	rec.EventHeader.EventDescriptor.Id      = id;
	rec.EventHeader.EventDescriptor.Version = 0;
	rec.EventHeader.ProcessId = 4242;
	rec.EventHeader.ThreadId  = 77;
	rec.UserData       = (void *)(uintptr_t)p->b;
	rec.UserDataLength = (USHORT)p->n;

	return kofw_decode(c, &rec, out, NULL);
}

/* ----------------------------------------------------------------- the runs */

#define RUN_KEY \
	"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

/*
 * The command a Run value persists, as the bytes a REG_SZ actually holds:
 * UTF-16, which is why it cannot travel as a C string and why data_len exists.
 */
static const unsigned char cmd_utf16[] = {
	'C',0, ':',0, '\\',0, 'a',0, '.',0, 'e',0, 'x',0, 'e',0, 0,0
};

static void set_value(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct pay p;
	const char *obj;

	memset(&p, 0, sizeof p);
	p_u64(&p, 0xffff800012340000ull);        /* KeyObject */
	p_u32(&p, 0);                            /* Status */
	p_u32(&p, 1u);                           /* Type = REG_SZ */
	p_u32(&p, (uint32_t)sizeof cmd_utf16);   /* DataSize */
	p_wstr(&p, RUN_KEY);                     /* KeyName */
	p_wstr(&p, "Updater");                   /* ValueName */
	p_u16(&p, (uint16_t)sizeof cmd_utf16);   /* CapturedDataSize */
	p_bytes(&p, cmd_utf16, sizeof cmd_utf16);/* CapturedData */
	p_u32(&p, 0);                            /* PreviousDataType */
	p_u32(&p, 0);                            /* PreviousDataSize */
	p_u16(&p, 0);                            /* PreviousDataCapturedSize */

	if (!decode_one(c, 5u, &p, &e)) {
		fail("a SetValueKey record did not decode at all");
		return;
	}

	if (e.type != KOF_EVT_REG_SET_VALUE)
		fail("SetValueKey did not come out as the set verb");

	/*
	 * THE WHOLE POINT. Before the two names were separated this was
	 * "Updater" and the key was gone.
	 */
	obj = kofw_evt_object(&e);
	if (!obj || strcmp(obj, RUN_KEY "\\Updater") != 0)
		printf("  FAIL the path came out as \"%s\"\n", obj ? obj : "");
	failures += (!obj || strcmp(obj, RUN_KEY "\\Updater")) ? 1 : 0;

	/* The data, which used not to be carried at all. */
	if (e.data_len != sizeof cmd_utf16)
		fail("the captured data has the wrong length");
	else if (e.off_data == KOF_TEXT_NONE ||
		 memcmp(e.text + e.off_data, cmd_utf16, sizeof cmd_utf16))
		fail("the captured data is not the bytes that were written");

	if (e.reg_type != 1u)
		fail("the value type was not carried");
	if (e.reg_data_size != (uint32_t)sizeof cmd_utf16)
		fail("the value's full size was not carried");

	/*
	 * A COMPLETE RECORD IS NOT A PARTIAL ONE. KOFW_EF_PARTIAL is what a
	 * consumer reads to decide whether to trust a record, so a decode that
	 * worked and flagged itself damaged would have every registry event
	 * discarded downstream.
	 */
	if (e.flags & KOFW_EF_PARTIAL)
		fail("a complete SetValueKey record was flagged partial");
	if (e.flags & KOFW_EF_TRUNCATED)
		fail("a record that fits was flagged truncated");
}

/*
 * THE DEFAULT VALUE, which has no name and is a real target.
 *
 * A COM hijack writes the default value of an InprocServer32 key, so a path
 * that stopped at the key would name the technique and lose which value it
 * was. See KOFW_FLD_REG_VALUE.
 */
static void default_value(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct pay p;
	const char *obj;

	memset(&p, 0, sizeof p);
	p_u64(&p, 0xffff800012340000ull);
	p_u32(&p, 0);
	p_u32(&p, 1u);
	p_u32(&p, 4u);
	p_wstr(&p, RUN_KEY);
	p_wstr(&p, "");                          /* ValueName - the default */
	p_u16(&p, 0);
	p_u32(&p, 0);
	p_u32(&p, 0);
	p_u16(&p, 0);

	if (!decode_one(c, 5u, &p, &e)) {
		fail("a default-value record did not decode");
		return;
	}
	obj = kofw_evt_object(&e);
	if (!obj || strcmp(obj, RUN_KEY "\\(Default)") != 0) {
		printf("  FAIL the default value came out as \"%s\"\n",
		       obj ? obj : "");
		failures++;
	}
}

/*
 * CREATE, AND WHETHER IT ACTUALLY CREATED.
 *
 * Two records that differ only in Disposition, because one alone proves
 * nothing: a field that is always 1 and a field that is read correctly look
 * identical from one sample.
 */
static void create_key(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct pay p;
	const char *obj;
	unsigned k;

	for (k = 1u; k <= 2u; k++) {
		memset(&p, 0, sizeof p);
		p_u64(&p, 0xffff800011110000ull);  /* BaseObject */
		p_u64(&p, 0xffff800012340000ull);  /* KeyObject */
		p_u32(&p, 0);                      /* Status */
		p_u32(&p, k);                      /* Disposition */
		p_wstr(&p, "\\REGISTRY\\MACHINE\\SOFTWARE");   /* BaseName */
		p_wstr(&p, "Microsoft\\Windows");              /* RelativeName */

		if (!decode_one(c, 1u, &p, &e)) {
			fail("a CreateKey record did not decode");
			return;
		}
		if (e.type != KOF_EVT_REG_CREATE)
			fail("CreateKey did not come out as the create verb");

		obj = kofw_evt_object(&e);
		if (!obj || strcmp(obj,
			"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows")) {
			printf("  FAIL create path came out as \"%s\"\n",
			       obj ? obj : "");
			failures++;
		}
		if (e.reg_disp != (uint8_t)k)
			fail("the disposition was not carried");
	}
}

/*
 * AN ABSOLUTE SECOND NAME, which is how a key opened by full path arrives:
 * BaseName is empty and RelativeName is the whole thing. Joining those with a
 * separator would produce "\\REGISTRY\..." - a path that is not the one the
 * machine touched and that no location rule matches.
 */
static void absolute_relative(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct pay p;
	const char *obj;

	memset(&p, 0, sizeof p);
	p_u64(&p, 0);
	p_u64(&p, 0xffff800012340000ull);
	p_u32(&p, 0);
	p_u32(&p, 1u);
	p_wstr(&p, "");                        /* BaseName - opened absolute */
	p_wstr(&p, RUN_KEY);                   /* RelativeName */

	if (!decode_one(c, 1u, &p, &e)) {
		fail("an absolute CreateKey record did not decode");
		return;
	}
	obj = kofw_evt_object(&e);
	if (!obj || strcmp(obj, RUN_KEY) != 0) {
		printf("  FAIL absolute create came out as \"%s\"\n",
		       obj ? obj : "");
		failures++;
	}
}

/*
 * THE CLASSIFICATION IS THE REASON THE PATH HAD TO BE WHOLE.
 *
 * kof_classify_path already knew "\CurrentVersion\Run" is T1547.001 - the row
 * has been in the table the whole time. It could never fire, because the
 * object it was given was "Updater". This is the half of the fix that is
 * visible from outside the collector, so it is asserted here rather than left
 * to be noticed in a report.
 */
static void classifies(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct pay p;
	uint8_t  loc = 0;
	uint16_t att = 0;

	memset(&p, 0, sizeof p);
	p_u64(&p, 0xffff800012340000ull);
	p_u32(&p, 0);
	p_u32(&p, 1u);
	p_u32(&p, (uint32_t)sizeof cmd_utf16);
	p_wstr(&p, RUN_KEY);
	p_wstr(&p, "Updater");
	p_u16(&p, (uint16_t)sizeof cmd_utf16);
	p_bytes(&p, cmd_utf16, sizeof cmd_utf16);
	p_u32(&p, 0);
	p_u32(&p, 0);
	p_u16(&p, 0);

	if (!decode_one(c, 5u, &p, &e)) {
		fail("the classification record did not decode");
		return;
	}
	loc = kof_classify(kofw_evt_object(&e), &att);
	if (loc != KOF_LOC_AUTOSTART)
		fail("a Run value did not classify as autostart");
	if (att != KOF_ATT_RUN_KEY)
		fail("a Run value did not carry T1547.001");
}

/*
 * THE OTHER HALF OF THE JOURNEY: the collector's record becomes the neutral
 * one, and that is what a rule and a report actually see.
 *
 * Worth its own case because the conversion is where a second arena slot can
 * quietly go wrong. off_data and data_len are one fact in two fields, and the
 * clamping that keeps them agreeing with the bytes that were copied is exactly
 * the kind of code that is correct by inspection and wrong in practice.
 */
static void converts(struct kofw_schema_cache *c)
{
	struct kofw_evt e;
	struct kof_evt  k;
	const struct kof_evt_reg *r;
	struct pay p;

	memset(&p, 0, sizeof p);
	p_u64(&p, 0xffff800012340000ull);
	p_u32(&p, 0);
	p_u32(&p, 1u);
	p_u32(&p, (uint32_t)sizeof cmd_utf16);
	p_wstr(&p, RUN_KEY);
	p_wstr(&p, "Updater");
	p_u16(&p, (uint16_t)sizeof cmd_utf16);
	p_bytes(&p, cmd_utf16, sizeof cmd_utf16);
	p_u32(&p, 0);
	p_u32(&p, 0);
	p_u16(&p, 0);

	if (!decode_one(c, 5u, &p, &e)) {
		fail("the conversion record did not decode");
		return;
	}

	memset(&k, 0, sizeof k);
	kofw_evt_to_kof(&e, &k);

	if (k.verb != KOF_EVT_REG_SET_VALUE) {
		fail("the verb did not survive the conversion");
		return;
	}
	if (!kof_evt_object(&k) ||
	    strcmp(kof_evt_object(&k), RUN_KEY "\\Updater") != 0)
		fail("the path did not survive the conversion");

	/*
	 * A REGISTRY EVENT OWNS A PAYLOAD NOW. It used to be KOF_EK_NONE, so
	 * this accessor returning NULL is precisely the old behaviour and is
	 * what this asserts against.
	 */
	r = kof_evt_as_reg(&k);
	if (!r) {
		fail("a registry event still owns no payload");
		return;
	}
	if (r->type != 1u || r->data_size != (uint32_t)sizeof cmd_utf16)
		fail("the value type or size did not survive the conversion");

	if (k.off_data == KOF_TEXT_NONE || k.data_len != sizeof cmd_utf16 ||
	    memcmp(k.text + k.off_data, cmd_utf16, sizeof cmd_utf16))
		fail("the value data did not survive the conversion");

	/*
	 * AND IT HAS TO BE READABLE, because a field nothing renders is a field
	 * nobody will notice has stopped being filled. The type says UTF-16, so
	 * the line must show the command rather than a dot between every
	 * character.
	 */
	{
		char line[1024];
		struct kof_evt_tally tally;
		FILE *f = tmpfile();
		size_t n;

		memset(&tally, 0, sizeof tally);

		if (!f) {
			fail("no temp file to render into");
			return;
		}
		kof_evt_render(&k, 0.0, "test", f, &tally);
		rewind(f);
		n = fread(line, 1, sizeof line - 1u, f);
		line[n] = '\0';
		fclose(f);

		if (!strstr(line, "C:\\a.exe"))
			printf("  FAIL the rendered line does not show the "
			       "command: %s\n", line);
		failures += strstr(line, "C:\\a.exe") ? 0 : 1;
	}
}

int main(void)
{
	static struct kofw_schema_cache cache;

	printf("registry event:\n");
	memset(&cache, 0, sizeof cache);

	set_value(&cache);
	default_value(&cache);
	create_key(&cache);
	absolute_relative(&cache);
	classifies(&cache);
	converts(&cache);

	/*
	 * THE SHAPES HAD TO COME FROM SOMEWHERE. If TDH described none of them
	 * every assertion above would have been skipped by an early return and
	 * the test would have passed having tested nothing - which is the one
	 * way a test like this goes wrong silently.
	 */
	if (cache.n == 0) {
		printf("  FAIL no shape was ever learned - TDH described "
		       "nothing, so nothing above was exercised\n");
		failures++;
	}
	if (cache.learn_failed)
		printf("  note: %llu shape(s) TDH would not describe\n",
		       (unsigned long long)cache.learn_failed);

	if (failures) {
		printf("registry event: %d failure(s)\n", failures);
		return 1;
	}
	printf("  ok (%u shape(s) learned)\n", cache.n);
	return 0;
}
