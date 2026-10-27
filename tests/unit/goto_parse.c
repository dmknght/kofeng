/*
 * goto_parse - the base rules of the viewer's "Go to" offset field.
 *
 * The dialog is not testable from here - it needs a terminal, a loaded file and
 * a tree - but the one part of it that can be wrong INVISIBLY is: a parser that
 * reads "10" as sixteen when ten was meant jumps somewhere real and plausible,
 * and nothing on the screen says which base it used. So the parser lives in a
 * header (kofexamine/goto_parse.h) and this asks it the questions a reader's
 * fingers ask.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../kofexamine/goto_parse.h"

static int fails;

static void eq(const char *in, uint64_t want, const char *why)
{
	uint64_t got = kof_goto_parse(in);

	if (got == want)
		return;
	printf("  FAIL %-28s \"%s\" -> ", why, in ? in : "(null)");
	if (got == KOF_GOTO_BAD)
		printf("refused");
	else
		printf("%llu", (unsigned long long)got);
	if (want == KOF_GOTO_BAD)
		printf(", wanted refused\n");
	else
		printf(", wanted %llu\n", (unsigned long long)want);
	fails++;
}

/* ---- hostile rows: what a person can type or paste into the field ------------ */

/* The oracle: the rules of goto_parse.h stated again with 128-bit arithmetic, which cannot wrap on the way. */
static uint64_t oracle(const char *s)
{
	unsigned __int128 n = 0;
	unsigned base = 16, digits = 0;

	while (*s == ' ' || *s == '\t')
		s++;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	else if (s[0] == '0' && (s[1] == 'n' || s[1] == 'N')) {
		s += 2;
		base = 10;
	}
	for (; *s; s++) {
		int d = -1;

		if (*s >= '0' && *s <= '9')
			d = *s - '0';
		else if (base == 16 && *s >= 'a' && *s <= 'f')
			d = *s - 'a' + 10;
		else if (base == 16 && *s >= 'A' && *s <= 'F')
			d = *s - 'A' + 10;
		if (d < 0 || d >= (int)base)
			return KOF_GOTO_BAD;
		n = n * base + (unsigned)d;
		if (n >= (unsigned __int128)KOF_GOTO_BAD)       /* the largest uint64 is refused too */
			return KOF_GOTO_BAD;
		digits++;
	}
	return digits ? (uint64_t)n : KOF_GOTO_BAD;
}

static void hostile(void)
{
	static const char alpha[] = { '0', '1', '9', 'a', 'F', 'x', 'n', 'X', ' ', 'g', '-', '\t' };
	enum { NA = sizeof alpha, MAXL = 5 };
	char buf[MAXL + 1];
	unsigned idx[MAXL];
	unsigned len, i, bad = 0;
	unsigned long total = 0;
	char *big;
	const size_t MB = 1u << 20;

	/* every string of up to five characters over a twelve-letter alphabet that holds both prefixes, both
	 * bases, a digit past 9, a sign, a blank and a tab: 270k strings against the oracle */
	for (len = 0; len <= MAXL; len++) {
		unsigned long count = 1, c;

		for (i = 0; i < len; i++)
			count *= NA;
		for (c = 0; c < count; c++) {
			unsigned long t = c;

			for (i = 0; i < len; i++) {
				idx[i] = (unsigned)(t % NA);
				t /= NA;
				buf[i] = alpha[idx[i]];
			}
			buf[len] = 0;
			total++;
			if (kof_goto_parse(buf) != oracle(buf) && bad++ < 5) {
				printf("  FAIL exhaustive \"%s\": got %llx, oracle %llx\n", buf,
				       (unsigned long long)kof_goto_parse(buf), (unsigned long long)oracle(buf));
				fails++;
			}
		}
	}
	if (total < 200000ul) {
		printf("  FAIL exhaustive sweep ran %lu strings\n", total);
		fails++;
	}

	/* edges named, because the sweep's alphabet is small */
	eq("0n18446744073709551614", 0xfffffffffffffffeull, "decimal, one below the refused value");
	eq("0n18446744073709551615", KOF_GOTO_BAD, "decimal, the refused value itself");
	eq("fffffffffffffffe0",      KOF_GOTO_BAD, "hex, one digit past the largest");
	eq("0x0x10",   KOF_GOTO_BAD, "a prefix twice");
	eq("0x 10",    KOF_GOTO_BAD, "a blank after the prefix");
	eq("10 ",      KOF_GOTO_BAD, "a trailing blank refuses the field");
	eq("1 0",      KOF_GOTO_BAD, "a blank inside");
	eq("\n10",     KOF_GOTO_BAD, "a newline is not a skipped blank");
	eq("0n0x10",   KOF_GOTO_BAD, "0x after 0n");
	eq("0x0n10",   KOF_GOTO_BAD, "0n after 0x");
	eq("\xc3\xa9", KOF_GOTO_BAD, "UTF-8 letter");
	eq("1\xff",    KOF_GOTO_BAD, "a byte outside UTF-8");
	eq("\xef\xbc\x91", KOF_GOTO_BAD, "a full-width one");
	eq("\xe2\x80\x8b" "10", KOF_GOTO_BAD, "a zero-width space before the digits");
	eq("0n000000000000000000000000000001", 1, "leading zeros do not overflow");

	/* one megabyte pasted: it must be decided, in time, and by the right rule */
	big = malloc(MB + 8u);
	if (!big) {
		printf("  FAIL out of memory\n");
		fails++;
		return;
	}
	memset(big, '0', MB);
	big[MB] = 0;
	eq(big, 0, "1 MB of zeros is zero");
	big[MB - 1] = '1';
	eq(big, 1, "1 MB of zeros then a one");
	memset(big, 'f', MB);
	eq(big, KOF_GOTO_BAD, "1 MB of f");
	memset(big, '9', MB);
	eq(big, KOF_GOTO_BAD, "1 MB of nines (hex)");
	memset(big, '7', MB);
	big[0] = ' ';
	big[1] = '0';
	big[2] = 'n';
	eq(big, KOF_GOTO_BAD, "1 MB of decimal digits");
	memset(big, 'g', MB);
	eq(big, KOF_GOTO_BAD, "1 MB of junk");
	memset(big, ' ', MB);
	eq(big, KOF_GOTO_BAD, "1 MB of blanks");
	free(big);
}

int main(void)
{
	/* HEX IS THE DEFAULT, because every offset this tool prints is hex. */
	eq("10",    0x10,  "bare digits are hex");
	eq("ff",    0xff,  "bare hex letters");
	eq("FF",    0xff,  "upper case too");
	eq("1a2b",  0x1a2b, "longer hex");
	eq("0",     0,     "zero is a real offset");

	/* The two prefixes. */
	eq("0x10",  0x10,  "0x is accepted and ignored");
	eq("0X10",  0x10,  "and in upper case");
	eq("0n10",  10,    "0n forces decimal");
	eq("0N10",  10,    "and in upper case");

	/* Whitespace a paste brings with it. */
	eq("  20",  0x20,  "leading blanks are skipped");
	eq("\t20",  0x20,  "including a tab");

	/* Junk is refused rather than partly read: a field that took "12g4"
	 * as 0x12 would jump somewhere the reader did not type. */
	eq("",      KOF_GOTO_BAD, "empty is not a number");
	eq(" ",     KOF_GOTO_BAD, "blanks alone are not either");
	eq("0x",    KOF_GOTO_BAD, "a prefix with no digits");
	eq("0n",    KOF_GOTO_BAD, "the same for 0n");
	eq("12g4",  KOF_GOTO_BAD, "trailing junk refuses the whole field");
	eq("g",     KOF_GOTO_BAD, "a letter past f is not a hex digit");
	eq("-1",    KOF_GOTO_BAD, "an offset has no sign");
	eq("0n1f",  KOF_GOTO_BAD, "hex letters are junk once 0n was said");
	eq(NULL,    KOF_GOTO_BAD, "no string at all");

	/* Refused rather than WRAPPED - a wrapped number lands on a real byte
	 * the reader never asked for, which is the failure worth testing. */
	eq("ffffffffffffffff",  KOF_GOTO_BAD, "the largest uint64 is refused");
	eq("10000000000000000", KOF_GOTO_BAD, "one past 64 bits of hex");
	eq("fffffffffffffffe",  0xfffffffffffffffeull, "one below it is fine");
	eq("0n18446744073709551616", KOF_GOTO_BAD, "past 64 bits in decimal");

	hostile();

	printf("goto parse: %s\n", fails ? "FAILED" : "ok");
	return fails ? 1 : 0;
}
