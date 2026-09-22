/*
 * amsi_rule.c - the AMSI path, end to end, over synthetic submissions.
 *
 * WHAT IT IS ACTUALLY TESTING, which is not the rule.
 *
 * It is testing that a client which pulled a submission off a channel can hand
 * it to the engine and have a rule in a database decide about it, with no C in
 * between. Every link has to hold: the caller declares the format and the
 * content's extent through as_view, the parse validates that extent against the
 * buffer, the region resolver splits the object into the two halves amsi.h
 * promises, the target byte routes the object to modules that declared
 * KOF_EVT_AMSI and to no others, and the rule runs against one half only.
 *
 * A break anywhere in that comes back as SILENCE, which is why the negative
 * cases here are asserted as hard as the positive ones. A rule that fires on
 * everything passes any test that only checks that it fires, and the specific
 * way this path fails - regions that stop partitioning, so OBJDATA quietly
 * swallows the metadata - produces exactly that rule.
 *
 * TWO CALLER SHAPES, BECAUSE THERE ARE TWO CALLERS AND THEY DISAGREE.
 *
 * kofwatchman hands the engine a buffer holding ONLY the reassembled content -
 * kof_evt_join gathers the content, not the record - so its object starts at
 * the submission and there is no metadata in it at all. A viewer holding a
 * whole record has the head and the arena around the content, and its obj_off
 * is not zero. Both are legitimate and the parse has to be right for each, so
 * both are exercised; the second is what the two regions exist for.
 *
 * SYNTHETIC AND NOT OVER A LIVE SUBMISSION, deliberately. AMSI needs an ETW
 * session, an elevated prompt and something executing, so a test over a real
 * one would not run in a CI - and none of that is the part that breaks. The
 * shapes here are written down as bytes, including the exact UTF-16 a script
 * block arrives as, so the test runs on a host with no AMSI on it at all.
 *
 * NOTE THE PARSE READS NOTHING OF THE RECORD'S LAYOUT. The extents are handed
 * in, for the reason amsi_parse.h gives - the record belongs to libkoforbit and
 * the engine must not know its shape - so an object built here out of plain
 * bytes exercises the same code a real record does.
 */

#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/analyzer/parsers/events/amsi_parse.h"

#include <kofmod/kofsig.h>
#include <kofmod/amsi.h>

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

/* ------------------------------------------------------------ the articles */

/*
 * What `powershell -EncodedCommand <base64>` actually submits.
 *
 * NOT the base64. PowerShell decodes it before AMSI is called, so what arrives
 * is the plain text, in UTF-16 because a script block always is. Written here
 * as the bytes rather than the string so the test does not depend on the host's
 * wchar_t being two bytes or little endian - on a big-endian host L"..." would
 * be the wrong bytes and the rule would correctly not fire, which would read as
 * a broken engine.
 */
static const unsigned char enc_cmd[] = {
	'W',0, 'r',0, 'i',0, 't',0, 'e',0, '-',0, 'H',0, 'o',0, 's',0, 't',0,
	' ',0, '"',0, 'h',0, 'e',0, 'l',0, 'l',0, 'o',0, ' ',0, 'w',0, 'o',0,
	'r',0, 'l',0, 'd',0, '"',0
};

/*
 * What a script carries when it decodes a blob at RUNTIME - here the base64 is
 * in the submitted text, because the script itself holds it:
 *
 *     $s=[Convert]::FromBase64String('aGVsbG8gd29ybGQ=')
 *
 * The distinction between this and enc_cmd above is the one a rule author gets
 * wrong; see sig_amsi.c.
 */
static const unsigned char b64_script[] = {
	'$',0, 's',0, '=',0, '[',0, 'C',0, 'o',0, 'n',0, 'v',0, 'e',0, 'r',0,
	't',0, ']',0, ':',0, ':',0, 'F',0, 'r',0, 'o',0, 'm',0, 'B',0, 'a',0,
	's',0, 'e',0, '6',0, '4',0, 'S',0, 't',0, 'r',0, 'i',0, 'n',0, 'g',0,
	'(',0, '\'',0,
	'a',0, 'G',0, 'V',0, 's',0, 'b',0, 'G',0, '8',0, 'g',0, 'd',0, '2',0,
	'9',0, 'y',0, 'b',0, 'G',0, 'Q',0, '=',0,
	'\'',0, ')',0
};

/* A submission with nothing in it worth naming. */
static const unsigned char benign[] = {
	'G',0, 'e',0, 't',0, '-',0, 'D',0, 'a',0, 't',0, 'e',0
};

/* ------------------------------------------------------------- the scanning */

struct seen {
	char name[224];
	int  n, rc;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct seen *s = (struct seen *)user;

	(void)name; (void)bytes; (void)len;
	if (res && res->n) {
		if (!s->n)
			snprintf(s->name, sizeof s->name, "%s", res->v[0].name);
		s->n += (int)res->n;
	}
	return 0;
}

/*
 * Scan one object as a submission.
 *
 * `obj_off`/`obj_len` are declared through as_view, which is a PREFIX of
 * kof_amsi_view - see the field in kof_scan_option for why a declared input
 * travels that way rather than as a vocabulary of its own. Passing tell=0 omits
 * as_view entirely, which is what kofwatchman does and therefore has to work.
 */
static const char *scan_as_amsi(kof_scanner *sc, const void *obj, uint64_t n,
				int tell, uint64_t obj_off, uint64_t obj_len,
				struct seen *s)
{
	struct kof_scan_option opt;
	struct kof_amsi_view decl;

	memset(s, 0, sizeof *s);
	memset(&opt, 0, sizeof opt);
	opt.as_format = KOF_EVT_AMSI;   /* DECLARED - an event never sniffs */
	opt.all_matches = 1;
	if (tell) {
		memset(&decl, 0, sizeof decl);
		decl.obj_off = obj_off;
		decl.obj_len = obj_len;
		opt.as_view = &decl;
		opt.as_view_len = (uint32_t)sizeof decl;
	}
	s->rc = kof_scan_bytes(sc, obj, n, "event//1//AMSI_SCAN", &opt,
			       on_object, s);
	return s->name;
}

static int said(const char *got, const char *want)
{
	return strstr(got, want) != NULL;
}

/*
 * Build the shape a viewer holds: the collector's account, then the content,
 * then the rest of the arena. Returns the object's length and reports where the
 * content landed, because that is what a caller has to be able to say.
 */
static uint64_t build_record(unsigned char *out, uint64_t cap,
			     const char *meta_before, const void *content,
			     uint64_t content_len, const char *meta_after,
			     uint64_t *obj_off)
{
	uint64_t o = 0, n;

	n = strlen(meta_before);
	if (n + content_len + strlen(meta_after) > cap)
		return 0;
	memcpy(out, meta_before, n);
	o = n;
	*obj_off = o;
	memcpy(out + o, content, (size_t)content_len);
	o += content_len;
	n = strlen(meta_after);
	memcpy(out + o, meta_after, (size_t)n);
	return o + n;
}

/* ------------------------------------------------------- the partition test */

/*
 * THE CONTRACT amsi.h STATES, CHECKED RATHER THAN ASSUMED.
 *
 * OR-ing both regions must scan every byte exactly once. This is the property
 * the rest of the test depends on - a rule keyed to one half is only meaningful
 * if the halves are actually halves - so it is checked directly against the
 * resolver rather than inferred from which rules fired.
 *
 * METADATA is TWO ranges here and that is the whole subtlety: the content sits
 * in the middle, so "everything else" is what is in front of it and what is
 * behind it, and a resolver that returned one bounding range would put the
 * content back inside METADATA while still looking like it covered the object.
 */
static void partition(const unsigned char *obj, uint64_t n, uint64_t obj_off,
		      uint64_t obj_len, const char *what)
{
	struct kof_amsi_view v;
	struct kof_obj_ctx ctx;
	struct kof_range ext[8];
	unsigned char *hit;
	uint32_t got, i, k;
	uint64_t total = 0;

	memset(&v, 0, sizeof v);
	memset(&ctx, 0, sizeof ctx);
	v.obj_off = obj_off;
	v.obj_len = obj_len;
	if (!kof_amsi_parse(kof_buf_make(obj, n), &v, &ctx)) {
		fail("the parse refused an object it should have taken");
		return;
	}

	hit = calloc((size_t)n, 1);
	if (!hit)
		return;

	for (i = 0; i < 2; i++) {
		got = ctx.resolve_scan(&ctx, kof_amsi_regions[i], ext,
				       (uint32_t)(sizeof ext / sizeof ext[0]));
		for (k = 0; k < got; k++) {
			uint64_t b;

			if (ext[k].off + ext[k].len > n) {
				fail("a region reaches past the object");
				free(hit);
				return;
			}
			for (b = ext[k].off; b < ext[k].off + ext[k].len; b++) {
				if (hit[b]++)
					fail("two regions claim the same byte");
			}
			total += ext[k].len;
		}
	}

	if (total != n) {
		printf("  FAIL %s: regions cover %llu of %llu bytes\n", what,
		       (unsigned long long)total, (unsigned long long)n);
		failures++;
	}
	free(hit);
}

/* ---------------------------------------------------------------------- run */

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/test/databases-sigs";
	kof_engine  *eng;
	kof_scanner *sc;
	unsigned char rec[1024];
	struct seen s;
	uint64_t n, off;

	eng = kof_engine_open(db);
	if (!eng) {
		printf("amsi rule: cannot open %s\n", db);
		return 2;
	}
	sc = kof_scanner_new(eng);
	if (!sc) {
		kof_engine_close(eng);
		return 2;
	}

	printf("amsi rule:\n");

	/*
	 * 1. THE SHAPE kofwatchman ACTUALLY SENDS: content only, and no extent
	 *    declared at all. The parse takes an omitted length as "all of it",
	 *    which is the right reading for a buffer that IS the content - and
	 *    this is the case that must never regress, because it is the one in
	 *    production.
	 */
	if (!said(scan_as_amsi(sc, enc_cmd, sizeof enc_cmd, 0, 0, 0, &s),
		  "EncHello"))
		fail("a decoded -EncodedCommand did not match (watchman shape)");

	/*
	 * 2. THE SAME BYTES, EXTENT DECLARED. A caller that says what the
	 *    omitting caller left implicit must get the same answer; if these
	 *    two ever disagree, one of the callers is being told something
	 *    different about the same submission.
	 */
	if (!said(scan_as_amsi(sc, enc_cmd, sizeof enc_cmd, 1, 0,
			       sizeof enc_cmd, &s), "EncHello"))
		fail("the same submission did not match when declared");

	/* 3. The base64 in the script text, which is the OTHER shape. */
	if (!said(scan_as_amsi(sc, b64_script, sizeof b64_script, 0, 0, 0, &s),
		  "B64Hello"))
		fail("a base64 literal in a script block did not match");

	/*
	 * 4. THE WHOLE RECORD, content in the middle. This is the first case
	 *    where obj_off is not zero, so it is the first that proves the
	 *    declared extent is used at all rather than ignored.
	 */
	n = build_record(rec, sizeof rec,
			 "powershell.exe|C:\\Windows\\System32\\", b64_script,
			 sizeof b64_script, "|user", &off);
	if (!n)
		fail("the record would not build");
	else if (!said(scan_as_amsi(sc, rec, n, 1, off, sizeof b64_script, &s),
		       "B64Hello"))
		fail("content in the middle of a record did not match");

	/*
	 * 5. THE NEGATIVE THAT MATTERS MOST.
	 *
	 * The same marker, moved into the METADATA, with benign content. A rule
	 * keyed to OBJDATA must not see it. If this fires, the two regions have
	 * stopped partitioning and every content rule in the database has
	 * quietly become a rule about the collector's own strings - which is
	 * the false positive amsi.h opens with, and it would fire on the image
	 * name of every legitimate script host forever.
	 */
	n = build_record(rec, sizeof rec,
			 "powershell.exe|aGVsbG8gd29ybGQ=|", benign,
			 sizeof benign, "|user", &off);
	if (!n)
		fail("the record would not build");
	else {
		scan_as_amsi(sc, rec, n, 1, off, sizeof benign, &s);
		if (s.n)
			printf("  FAIL a metadata marker matched an OBJDATA "
			       "rule as \"%s\"\n", s.name);
		failures += s.n ? 1 : 0;
	}

	/*
	 * 6. THE OTHER HALF, SO THE TEST IS NOT ONE-SIDED. A rule keyed to
	 *    METADATA has to reach the metadata; a resolver that returned
	 *    nothing for it would pass case 5 for the wrong reason.
	 */
	n = build_record(rec, sizeof rec, "kofeng-amsi-meta-probe|", benign,
			 sizeof benign, "|user", &off);
	if (!n)
		fail("the record would not build");
	else if (!said(scan_as_amsi(sc, rec, n, 1, off, sizeof benign, &s),
		       "MetaProbe"))
		fail("a METADATA rule did not reach the metadata");

	/* 7. A submission with nothing in it names nothing. */
	scan_as_amsi(sc, benign, sizeof benign, 0, 0, 0, &s);
	if (s.n)
		fail("a benign submission was named");

	/*
	 * 8. A DECLARED EXTENT THAT IS NOT TRUE. Being told is not being right -
	 *    the parse says so and this is what checks it. An offset past the
	 *    end must be refused rather than resolved into ranges that are not
	 *    there; what must NOT happen is a crash or a match.
	 */
	scan_as_amsi(sc, benign, sizeof benign, 1, sizeof benign + 64u, 16, &s);
	if (s.n)
		fail("an out-of-range extent produced a match");

	/*
	 * 9. THE SUBTYPE AXIS, WHICH IS THE OTHER THING THAT ROUTES.
	 *
	 * A submission is either an executable or text a host was about to run,
	 * and a text rule offered the executable is a waste at best. The rule in
	 * sig_amsi.c gates on KOF_AMSI_COMMAND, so the SAME marker must match in
	 * one and not in the other - which is the only way to test a gate. One
	 * half alone would pass with the gate broken open or welded shut.
	 */
	{
		unsigned char img[0x54];
		static const char marker[] = "aGVsbG8gd29ybGQ=";

		memset(img, 0, sizeof img);
		memcpy(img + 0x44, marker, sizeof marker - 1);

		/* No header yet: this is COMMAND, and the marker is reachable. */
		if (!said(scan_as_amsi(sc, img, sizeof img, 0, 0, 0, &s),
			  "B64Hello"))
			fail("the marker did not match before the PE header "
			     "was put on it");

		/*
		 * The three reads declare_carried makes, and nothing else: MZ,
		 * the offset at 0x3c, and "PE\0\0" where it points. That is a
		 * submitted image as far as the parse is concerned, which is
		 * what this case needs it to be.
		 */
		img[0] = 'M'; img[1] = 'Z';
		img[0x3c] = 0x40;
		img[0x40] = 'P'; img[0x41] = 'E';

		scan_as_amsi(sc, img, sizeof img, 0, 0, 0, &s);
		if (s.n)
			printf("  FAIL a command rule ran against a submitted "
			       "image and said \"%s\"\n", s.name);
		failures += s.n ? 1 : 0;
	}

	/* 10. The partition itself, on both shapes. */
	partition(enc_cmd, sizeof enc_cmd, 0, sizeof enc_cmd, "content-only");
	n = build_record(rec, sizeof rec, "powershell.exe|", b64_script,
			 sizeof b64_script, "|user", &off);
	if (n)
		partition(rec, n, off, sizeof b64_script, "whole record");

	kof_scanner_free(sc);
	kof_engine_close(eng);

	if (failures) {
		printf("amsi rule: %d failure(s)\n", failures);
		return 1;
	}
	printf("  ok\n");
	return 0;
}
