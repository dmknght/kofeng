/*
 * word_modes - what the three boundary modes actually do, on source code.
 *
 * WHY THIS EXISTS. A signature was written by hand in the viewer against a php
 * shell, generated correctly in every visible respect, and matched nothing:
 *
 *     KOF_DEFINE_STR(s0, "@eval(@gzuncompress(@", KOF_CASE_EXACT,
 *                    KOF_WORD_TOKEN);
 *
 * against
 *
 *     @eval(@gzuncompress(@x(@base64_decode($m[1]),$k)));
 *
 * Nothing in the source says why. The rule reads as correct, the marker is
 * plainly in the file, and the failure is silent - which is the one failure
 * mode this tree calls out everywhere else.
 *
 * The reason is KOF_WORD_TOKEN, and it is doing exactly what it is documented
 * to do: a match must be a WHOLE WHITESPACE DELIMITED RUN, and every non-space
 * neighbour - punctuation included - continues the run. The byte after the
 * marker is "x", so the match is not whole and is refused.
 *
 * That is not a bug in the matcher. It is a fact about the mode that is easy to
 * state and easy to get backwards, and the comment that used to sit over the
 * viewer's default had it backwards in writing: it claimed a marker "surrounded
 * by quotes, brackets or dollars is still whole". So the behaviour is pinned
 * here, on the real case, in both directions - what TOKEN refuses and what it
 * is for.
 */
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/core/kofcore.h"
#include "../../libkofeng/kofmatchers/kofmatch.h"
#include "../../libkofeng/kofdb/kofpack.h"

static int fails;

/* Is `pat` found anywhere in `hay` under these flags? */
static int found(const char *hay, const char *pat, uint8_t flags)
{
	struct kof_match_ctx m;
	uint64_t n = (uint64_t)strlen(hay);
	int r;

	memset(&m, 0, sizeof m);
	if (!kof_match_state_init(&m, 0, 0))
		return -1;
	kof_match_begin(&m, kof_buf_make((const uint8_t *)hay, n));
	r = kof_match_in(&m, 0, n, (const uint8_t *)pat,
			 (uint16_t)strlen(pat), KOF_STR_LITERAL, flags);
	kof_match_state_free(&m);
	return r;
}

static void want(const char *what, const char *hay, const char *pat,
		 uint8_t flags, int expect)
{
	int r = found(hay, pat, flags);

	if (r == expect)
		return;
	printf("  FAIL %-46s got %d, wanted %d\n", what, r, expect);
	fails++;
}

/* The line the rule was written against, verbatim. */
static const char weevely[] =
	"@ob_start();\n"
	"@eval(@gzuncompress(@x(@base64_decode($m[1]),$k)));\n"
	"$o=@ob_get_contents();\n";

/* What TOKEN was added for: "<%" is a whole marker in classic ASP and a prefix
 * of "<%@" in ASP.NET, and FULLWORD cannot tell them apart because "@" is not a
 * word byte. */
static const char asp_open[]  = "<% x = 1 %>\n";
static const char aspx_open[] = "<%@ Page Language=\"C#\" %>\n";

int main(void)
{
	/*
	 * THE CASE THAT FAILED. A fragment of a longer run is not a token, and
	 * TOKEN refuses it - correctly, and with nothing on screen to say so.
	 */
	want("fragment, TOKEN: refused", weevely, "@eval(@gzuncompress(@",
	     KOF_STR_TOKEN, 0);
	want("fragment, SUBSTRING: found", weevely, "@eval(@gzuncompress(@",
	     0, 1);
	/*
	 * AND FULLWORD REFUSES IT TOO - which was NOT the expectation when this
	 * test was written, and is the useful part of it.
	 *
	 * The guess was that "(" and "@" are not word bytes so FULLWORD would
	 * pass. The byte that decides is the one AFTER the marker, and that is
	 * "x": a word byte. The marker ends in the middle of an identifier.
	 *
	 * So neither boundary mode can match this, for two different reasons,
	 * and SUBSTRING is not a fallback here - it is the only correct answer.
	 * That is what makes "choose the mode from the neighbours" the right
	 * default rather than "prefer the narrow one": a marker cut out of the
	 * middle of source has no boundary to speak of, whichever rule is used
	 * to look for one.
	 */
	want("fragment, FULLWORD: refused too", weevely,
	     "@eval(@gzuncompress(@", KOF_STR_FULLWORD, 0);

	/*
	 * AND WHAT TOKEN IS FOR. The whole point of the mode: tell "<%" from
	 * "<%@", which FULLWORD cannot.
	 */
	want("<% in classic asp, TOKEN: found", asp_open, "<%",
	     KOF_STR_TOKEN, 1);
	want("<% in <%@, TOKEN: refused", aspx_open, "<%",
	     KOF_STR_TOKEN, 0);
	want("<% in <%@, FULLWORD: found (why TOKEN exists)", aspx_open, "<%",
	     KOF_STR_FULLWORD, 1);

	/*
	 * A MARKER THAT REALLY IS A WHOLE TOKEN keeps working under TOKEN -
	 * which is what makes it a free narrowing when the bytes either side
	 * are whitespace, and the reason the viewer still chooses it there.
	 */
	want("whole token, TOKEN: found", "@ob_start();\n$o=1;\n",
	     "@ob_start();", KOF_STR_TOKEN, 1);

	if (fails) {
		printf("word modes: %d check(s) failed\n", fails);
		return 1;
	}
	printf("word modes: both boundaries refuse a fragment, "
	       "token tells <%% from <%%@ - ok\n");
	return 0;
}
