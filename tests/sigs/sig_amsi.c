/*
 * sig_amsi.c - proves a rule can decide about a SUBMISSION rather than a file.
 *
 * WHY THE ARTICLE IS "hello world" AND NOT A REAL PAYLOAD.
 *
 * What is under test is the path, not the pattern: a collector declares an
 * event, the parse validates the extent it was handed, the region resolver
 * splits the object in two, and a rule keyed to one half runs against that half
 * and no other. Every link has to hold, and a break anywhere comes back as
 * silence. A benign marker makes the silence the only interesting outcome -
 * nothing here has to be quarantined, nothing trips the host's own AV, and the
 * test article can sit in a repository.
 *
 * THE TWO FORMS OF THE SAME COMMAND, WHICH IS THE POINT WORTH KNOWING.
 *
 *   powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvA...
 *
 * AMSI does NOT see that base64. PowerShell decodes -EncodedCommand before it
 * submits, so what arrives is the plain text `Write-Host "hello world"` in
 * UTF-16 - which is why enc_hello below is the rule that fires on that command
 * line, and why it is declared WIDE.
 *
 * A base64 blob reaches AMSI only when the SCRIPT ITSELF carries one:
 *
 *   $s=[Convert]::FromBase64String('aGVsbG8gd29ybGQ=')
 *
 * There the literal is in the submitted text, and b64_hello matches it. Both
 * are real shapes and they are not the same shape; a rule author who conflates
 * them writes one that never fires and cannot tell why.
 *
 * BOTH WIDTHS, BECAUSE THE PROVIDER DECIDES. A script block arrives as UTF-16
 * and a submission from a native provider may be bytes, so the base64 marker is
 * declared twice - see KOF_DEFINE_STR_WIDE for why that is a build-time
 * expansion and not a compare mode.
 */

#include <kofmod/kofsig.h>
#include <kofmod/amsi.h>

/* An event target, not a format - see KOF_TARGET_EVENT. Nothing here casts
 * ctx->file_header, so the view's shape is not this module's business. */
KOF_TARGET_EVENT(KOF_EVT_AMSI);
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "AmsiTest");

/*
 * THE TWO REGIONS, NAMED SEPARATELY ON PURPOSE.
 *
 * This is the distinction amsi.h opens with: a rule that matched a script host
 * without saying which half it meant would fire on the image name of every
 * legitimate one, forever. Keeping both here lets the test prove the halves are
 * actually separate rather than assume it.
 */
KOF_TARGET_RANGE(submitted, KOF_SCAN_AMSI_OBJ);
KOF_TARGET_RANGE(collected, KOF_SCAN_AMSI_META);

/* What a script carries when it decodes a blob at runtime. */
KOF_DEFINE_STR(b64_hello, "aGVsbG8gd29ybGQ=", KOF_CASE_EXACT,
	       KOF_WORD_SUBSTRING);
KOF_DEFINE_STR_WIDE(b64_hello_w, "aGVsbG8gd29ybGQ=", KOF_CASE_EXACT,
		    KOF_WORD_SUBSTRING);

/* What -EncodedCommand actually submits, which is the DECODED text. */
KOF_DEFINE_STR_WIDE(enc_hello, "Write-Host \"hello world\"", KOF_CASE_EXACT,
		    KOF_WORD_SUBSTRING);

/*
 * A marker that only ever appears in the collector's account of the submission.
 * Keyed to METADATA, so if the regions ever stop partitioning, the test sees
 * this fire on content or sees the content rules fire on this - either way the
 * break is visible rather than silent.
 */
KOF_DEFINE_STR(meta_probe, "kofeng-amsi-meta-probe", KOF_CASE_EXACT,
	       KOF_WORD_SUBSTRING);

KOF_DEFINE_SCAN
{
	/*
	 * THE SUBTYPE IS CHECKED BEFORE THE TEXT, and it is not decoration.
	 * A submitted executable is offered to this module too, and text rules
	 * against an image are a waste at best and a coincidence at worst -
	 * see enum kof_amsi_kind for why the axis exists.
	 */
	if (ctx->subtype == (uint8_t)KOF_AMSI_COMMAND) {
		if (kof_find_str(submitted, enc_hello))
			KOF_SCAN_INFECT("EncHello");
		if (kof_find_str(submitted, b64_hello_w) ||
		    kof_find_str(submitted, b64_hello))
			KOF_SCAN_INFECT("B64Hello");
	}

	if (kof_find_str(collected, meta_probe))
		KOF_SCAN_SUSPECT("MetaProbe");
}
