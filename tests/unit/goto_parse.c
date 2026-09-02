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

	printf("goto parse: %s\n", fails ? "FAILED" : "ok");
	return fails ? 1 : 0;
}
