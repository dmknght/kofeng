#define _GNU_SOURCE
/*
 * textual_fn_chr - the character a number names, in each language's own chr (kgenome_textual_chr, kgenome_textual_fn_run): php, perl, lua, vbscript's Chr and
 * ChrW, python's chr, javascript's String.fromCharCode and fromCodePoint.
 *
 * AGAINST THE REAL INTERPRETERS where there are some on the machine: python 3 for every code point (0..0x10FFFF, and the numbers just outside it) in the
 * flavours that read one - python's chr, javascript's units and vbscript's ChrW are the same character for 0..65535, and a surrogate is the one thing the
 * lib refuses where python makes a str; perl for the byte flavour (0..255 is the byte, 256 and above is a wide character: refused). php, node, lua and
 * wscript are not here: those flavours are checked against the arithmetic of the rule written beside it in this file, differently from the code under test,
 * and are [Unverified] against the interpreter.
 */

#include "textual_check.h"

static int run_chr(uint8_t flavour, const long *v, uint32_t n, uint8_t *out, uint32_t cap, uint32_t *w)
{
	struct kgenome_textual_fn f = { .op = KGENOME_TEXTUAL_DEC_CHR, .min_args = 1, .max_args = n > 1u ? 16u : 1u, .subject = KGENOME_TEXTUAL_FN_NONE,
					.param = { 0, KGENOME_TEXTUAL_FN_NONE }, .numeric = 1, .form = KGENOME_TEXTUAL_FN_FORM_PRINTABLE, .chr = flavour };
	struct kgenome_textual_arg a[16];
	char txt[16][24];
	uint32_t i;

	for (i = 0; i < n; i++) {
		snprintf(txt[i], sizeof txt[i], "%ld", v[i]);
		a[i].p = (const uint8_t *)txt[i];
		a[i].n = (uint32_t)strlen(txt[i]);
	}
	return kgenome_textual_fn_run(&f, a, n, NULL, NULL, out, cap, w);
}

/* The rule, written as arithmetic: what each flavour answers for one number, as bytes; 0 when it refuses. */
static uint32_t rule(uint8_t fl, long v, uint8_t *o)
{
	long cp = v;

	switch (fl) {
	case KGENOME_TEXTUAL_CHR_PHP:
		o[0] = (uint8_t)(((v % 256) + 256) % 256);
		return 1;
	case KGENOME_TEXTUAL_CHR_BYTE:
		if (v < 0 || v > 255)
			return 0;
		o[0] = (uint8_t)v;
		return 1;
	case KGENOME_TEXTUAL_CHR_ASCII:
		if (v < 0 || v > 127)
			return 0;
		o[0] = (uint8_t)v;
		return 1;
	case KGENOME_TEXTUAL_CHR_UTF16:
		cp = ((v % 65536) + 65536) % 65536;
		break;
	case KGENOME_TEXTUAL_CHR_UCS2:
		if (v < 0 || v > 65535)
			return 0;
		break;
	default:
		if (v < 0 || v > 0x10ffff)
			return 0;
	}
	if (cp >= 0xd800 && cp <= 0xdfff)
		return 0;
	if (cp < 0x80) {
		o[0] = (uint8_t)cp;
		return 1;
	}
	if (cp < 0x800) {
		o[0] = (uint8_t)(0xc0 | (cp >> 6));
		o[1] = (uint8_t)(0x80 | (cp & 63));
		return 2;
	}
	if (cp < 0x10000) {
		o[0] = (uint8_t)(0xe0 | (cp >> 12));
		o[1] = (uint8_t)(0x80 | ((cp >> 6) & 63));
		o[2] = (uint8_t)(0x80 | (cp & 63));
		return 3;
	}
	o[0] = (uint8_t)(0xf0 | (cp >> 18));
	o[1] = (uint8_t)(0x80 | ((cp >> 12) & 63));
	o[2] = (uint8_t)(0x80 | ((cp >> 6) & 63));
	o[3] = (uint8_t)(0x80 | (cp & 63));
	return 4;
}

static void check_rule(void)
{
	static const uint8_t fls[] = { KGENOME_TEXTUAL_CHR_PHP, KGENOME_TEXTUAL_CHR_BYTE, KGENOME_TEXTUAL_CHR_ASCII, KGENOME_TEXTUAL_CHR_UTF8,
				       KGENOME_TEXTUAL_CHR_UTF16, KGENOME_TEXTUAL_CHR_UCS2 };
	unsigned k;
	long v;

	for (k = 0; k < sizeof fls; k++) {
		/* every number around every boundary, and a stride through the rest */
		for (v = -70000; v <= 0x112000; v += (v > -300 && v < 70000) || (v > 0xfff00 && v < 0x110100) ? 1 : 997) {
			uint8_t got[8], want[8];
			uint32_t gw = 0, ww = rule(fls[k], v, want);
			int ok = run_chr(fls[k], &v, 1, got, sizeof got, &gw);

			if (ok != (ww != 0) || (ok && (gw != ww || memcmp(got, want, ww)))) {
				printf("  FAIL flavour %u, number %ld: got ok=%d len=%u, the rule says %u bytes\n", fls[k], v, ok, gw, ww);
				fails++;
				return;
			}
		}
	}
}

/* The numbers a language's own function takes, against the interpreter that has it: a stream of "<hex of utf-8>" or "-" per number. */
static void check_python(void)
{
	FILE *p = popen("python3 -I -c \"import sys\n"
			"for n in list(range(-2,0x110002)):\n"
			"    try:\n"
			"        s = chr(n).encode('utf-8')\n"
			"        print(s.hex())\n"
			"    except (ValueError, UnicodeEncodeError, OverflowError):\n"
			"        print('-')\n\" 2>&1", "r");
	char line[64];
	long v = -2;
	unsigned bad = 0;

	if (!p) {
		printf("  python3 not run\n");
		return;
	}
	while (fgets(line, sizeof line, p) && v <= 0x110001) {
		uint8_t got[8];
		uint32_t gw = 0, i;
		int ok = run_chr(KGENOME_TEXTUAL_CHR_UTF8, &v, 1, got, sizeof got, &gw);
		char hex[20];

		line[strcspn(line, "\n")] = 0;
		for (i = 0; i < gw; i++)
			snprintf(hex + 2u * i, 4, "%02x", got[i]);
		if (!ok)
			strcpy(hex, "-");
		if (strcmp(hex, line)) {
			if (bad++ < 3u)
				printf("  FAIL python chr(%ld) is [%s], the lib says [%s]\n", v, line, hex);
		}
		/* javascript's unit and vbscript's ChrW are python's character for 0..65535 */
		if (v >= 0 && v <= 65535) {
			uint32_t w2 = 0;
			uint8_t g2[8];
			int ok2 = run_chr(KGENOME_TEXTUAL_CHR_UCS2, &v, 1, g2, sizeof g2, &w2), ok3;
			uint32_t w3 = 0;
			uint8_t g3[8];

			ok3 = run_chr(KGENOME_TEXTUAL_CHR_UTF16, &v, 1, g3, sizeof g3, &w3);
			if (ok2 != ok || ok3 != ok || (ok && (w2 != gw || w3 != gw || memcmp(g2, got, gw) || memcmp(g3, got, gw)))) {
				if (bad++ < 3u)
					printf("  FAIL ChrW / fromCharCode(%ld) differ from chr\n", v);
			}
		}
		v++;
	}
	pclose(p);
	if (v != 0x110002) {
		printf("  FAIL python stopped at %ld\n", v);
		bad++;
	}
	if (bad)
		fails++;
	else
		printf("  python 3: chr of every number from -2 to 0x110001 read back, all equal\n");
}

/* perl: chr(n) for 0..255 is the byte; for 256 and above it is a wide character (the lib refuses); for a negative one it is U+FFFD. */
static void check_perl(void)
{
	FILE *p = popen("perl -e 'for my $n (-2..300) { my $c = chr($n); print ((length($c) == 1 && ord($c) < 256 && ord($c) == $n) ? sprintf(\"%02x\\n\", ord($c)) : \"-\\n\"); }' 2>&1", "r");
	char line[64];
	long v = -2;
	unsigned bad = 0;

	if (!p)
		return;
	while (fgets(line, sizeof line, p) && v <= 300) {
		uint8_t got[8];
		uint32_t gw = 0;
		int ok = run_chr(KGENOME_TEXTUAL_CHR_BYTE, &v, 1, got, sizeof got, &gw);
		char hex[8] = "-";

		line[strcspn(line, "\n")] = 0;
		if (ok)
			snprintf(hex, sizeof hex, "%02x", got[0]);
		if (strcmp(hex, line) && bad++ < 3u)
			printf("  FAIL perl chr(%ld) is [%s], the lib says [%s]\n", v, line, hex);
		v++;
	}
	pclose(p);
	if (bad || v != 301)
		fails++;
	else
		printf("  perl: chr of -2..300 read back, all equal\n");
}

/* several numbers are several characters (String.fromCharCode(104, 105), string.char(104, 105)), and one refused number refuses the call */
static void variadic(void)
{
	long v[4] = { 104, 105, 0x20ac, 33 };
	uint8_t o[32];
	uint32_t w = 0;

	CK(run_chr(KGENOME_TEXTUAL_CHR_UTF16, v, 4, o, sizeof o, &w) && w == 2u + 3u + 1u && !memcmp(o, "hi\xe2\x82\xac!", 6));
	CK(run_chr(KGENOME_TEXTUAL_CHR_BYTE, v, 2, o, sizeof o, &w) && w == 2u && !memcmp(o, "hi", 2));
	CK(!run_chr(KGENOME_TEXTUAL_CHR_BYTE, v, 4, o, sizeof o, &w));          /* 0x20ac is not a byte */
	v[1] = 0xd800;
	CK(!run_chr(KGENOME_TEXTUAL_CHR_UTF16, v, 4, o, sizeof o, &w));         /* a lone surrogate */
	/* the answer does not fit: refused, no write past the cap */
	v[0] = 0x10348;
	CK(!run_chr(KGENOME_TEXTUAL_CHR_UTF8, v, 1, o, 3, &w));
	CK(run_chr(KGENOME_TEXTUAL_CHR_UTF8, v, 1, o, 4, &w) && w == 4u);
	CK(!run_chr(KGENOME_TEXTUAL_CHR_BYTE, v, 1, o, 0, &w));
}

int main(void)
{
	check_rule();
	check_python();
	check_perl();
	variadic();
	printf("textual fn chr: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
