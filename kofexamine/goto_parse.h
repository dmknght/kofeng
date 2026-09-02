/*
 * goto_parse.h - the offset a reader types into "Go to", as a number.
 *
 * A HEADER, and not four lines inside kofviewer.c, for one reason: it is the
 * part of that dialog that can be WRONG WITHOUT ANYONE SEEING IT. Every other
 * half of the feature announces its own failure - a jump to the wrong place is
 * on the screen, a refused offset says so on the status line - but a parser
 * that reads "10" as sixteen when the reader meant ten lands somewhere real and
 * plausible, and nothing about the screen says which base was used. So it is
 * pulled out where a test can call it directly: tests/unit/goto_parse.c is that
 * test, and it exists so the base rules below cannot drift without a build
 * failing.
 *
 * HEX BY DEFAULT. Every offset this tool prints is hex - the hex pane's gutter,
 * a finding's location, a marker's row - so a reader retyping one of those
 * means hex, and a decimal default would misread all of them silently. "0x" is
 * accepted and ignored. "0n" forces decimal: it is the one prefix that cannot
 * itself be a run of hex digits, which is what makes it unambiguous where a
 * bare "10" is not.
 */

#ifndef KOF_GOTO_PARSE_H
#define KOF_GOTO_PARSE_H

#include <stdint.h>

/* Not a number, or too large to be one. Spelled the way the engine spells a
 * broken offset so a caller testing it reads the same value everywhere. */
#ifndef KOF_GOTO_BAD
#define KOF_GOTO_BAD (~(uint64_t)0)
#endif

static uint64_t kof_goto_parse(const char *s)
{
	uint64_t n = 0;
	unsigned base = 16u;
	int any = 0;

	if (!s)
		return KOF_GOTO_BAD;
	while (*s == ' ' || *s == '\t')
		s++;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		s += 2;
	} else if (s[0] == '0' && (s[1] == 'n' || s[1] == 'N')) {
		s += 2;
		base = 10u;
	}
	for (; *s; s++) {
		unsigned d;

		if (*s >= '0' && *s <= '9')
			d = (unsigned)(*s - '0');
		else if (base == 16u && *s >= 'a' && *s <= 'f')
			d = (unsigned)(*s - 'a') + 10u;
		else if (base == 16u && *s >= 'A' && *s <= 'F')
			d = (unsigned)(*s - 'A') + 10u;
		else
			return KOF_GOTO_BAD;
		/*
		 * Refused rather than wrapped. A number too big for any file is
		 * a typo; wrapped, it becomes a small offset that exists, and
		 * the jump succeeds at a place the reader never asked for -
		 * which is the one failure this dialog must not have.
		 *
		 * The bound is checked BEFORE the multiply, on the value that
		 * would overflow, so nothing has wrapped by the time it is
		 * tested. KOF_GOTO_BAD is itself the largest uint64, so a
		 * literal "ffffffffffffffff" is refused too - it could not be a
		 * real offset and returning it would read as an error anyway.
		 */
		if (n > (KOF_GOTO_BAD - (uint64_t)d) / base)
			return KOF_GOTO_BAD;
		n = n * base + (uint64_t)d;
		any = 1;
	}
	if (!any || n == KOF_GOTO_BAD)
		return KOF_GOTO_BAD;
	return n;
}

#endif /* KOF_GOTO_PARSE_H */
