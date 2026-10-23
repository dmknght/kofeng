/*
 * script_dispatch - which reader a script is given, and that each reader still does its own job.
 *
 * A script kind is read by exactly one of two: the lib's lexer (php, shell, js, python, vbs, asp, aspx and jsp) or the table-driven pass
 * every other kind keeps until it has a lexer. A change to the router could break that quietly in
 * either direction - php sent down the old path, which would still make a view and a different one,
 * or a shell script sent into a lexer that does not know it - so this asserts it through the whole
 * scan, on known answers, and not through the router's own table:
 *
 *   MAPPING    every script kind: the eight above have a lexer and the rest do not; an unknown kind, and
 *              every value past the list, has none.
 *   PHP        a messy page becomes the lexer's form - comments gone, a trailing one too, brackets closed
 *              up, the brace joined, the markup untouched - and the view is ONE region, the whole of it.
 *   SHELL      a shell script becomes the lexer's form too: comments gone, a trailing one included, white
 *              space kept as one space (it is syntax there), a here-document and a string untouched.
 *   OTHERS     each other lexed kind gives its lexer's view and one region (a js file with a regular
 *              expression that holds a quote, a python file with an f-string, a vbs file with a "Rem", a jsp
 *              and an asp page with an island that holds "%>" in a comment).
 *   PERL       a perl file is lexed like the rest (every kind the engine names has a lexer now): comments gone, a trailing
 *              one included, a space kept where closing it up would change what perl reads.
 *   DECODE     a literal under a decoder is replaced by what it decodes to - base64, hex, url, rot13,
 *              reverse, raw deflate, zlib, gzip, and chains of them in the order php runs them - and
 *              a layer inside a layer is peeled and formed. A literal that is not the whole of the
 *              argument, or a call with no literal, is left as typed. A text nested past the bound
 *              stays encoded at the bound and the scan still ends.
 *
 * The images are built in memory and given to kscan_bytes.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/script.h"
#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"
#include <textual/textual.h>

static int failures;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

/* ---- what the scan hands back ----------------------------------------------- */

/* a check that says what it was about, with the same counter as CK */
#define CKF(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		failures++; \
	} \
} while (0)

static uint8_t kid[1u << 22];
static uint64_t kid_n, n_kids;
static uint32_t kid_regions, kid_mask, kid_off, kid_len;

static int on_object(const char *name, const void *bytes, uint64_t len, const struct kof_result *res,
		     void *user)
{
	(void)user;
	if (!strstr(name, "//"))
		return 0;
	if (n_kids++ == 0 && bytes && len <= sizeof kid) {
		memcpy(kid, bytes, (size_t)len);
		kid_n = len;
		kid_regions = res->n_region;
		kid_mask = res->n_region ? res->region[0].mask : 0;
		kid_off = res->n_region ? (uint32_t)res->region[0].off : 0;
		kid_len = res->n_region ? (uint32_t)res->region[0].len : 0;
	}
	return 0;
}

static kof_scanner *sc;

static void scan(const char *src, size_t n, int level)
{
	struct kof_scan_option opt;

	memset(&opt, 0, sizeof opt);
	opt.heur_level = (uint32_t)level;
	opt.max_produced_bytes = 64u << 20;
	opt.max_resident_bytes = 256u << 20;
	opt.max_object_bytes = 32u << 20;
	kid_n = n_kids = kid_regions = kid_mask = kid_off = kid_len = 0;
	kscan_bytes(sc, src, n, "t", &opt, on_object, NULL);
}

/* The view of `src` is exactly `want`, and it is the one child. */
static void view_raw(const char *src, const char *want)
{
	scan(src, strlen(src), 1);
	if (n_kids != 1 || kid_n != strlen(want) || memcmp(kid, want, kid_n)) {
		kid[kid_n < sizeof kid ? kid_n : sizeof kid - 1u] = 0;
		printf("  FAIL view of  %s\n       children %llu\n       got    %s\n       wanted %s\n", src,
		       (unsigned long long)n_kids, (char *)kid, want);
		failures++;
	}
}

/*
 * A view is made only where it says something the object did not and is not a scrap - a floor the
 * pass has had since before the lexer, 32 bytes - so the short inputs below end with a statement of
 * their own and the answer with its form.
 */
static void view(const char *src, const char *want)
{
	static char a[8192], b[8192];

	snprintf(a, sizeof a, "%s$keep = 1;\n", src);
	snprintf(b, sizeof b, "%s\n$keep=1;", want);
	view_raw(a, b);
}

/* ---- encoders, to build the inputs ------------------------------------------ */

static size_t b64(const uint8_t *p, size_t n, char *out)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, w = 0;

	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)p[i] << 16 | (i + 1 < n ? (uint32_t)p[i + 1] << 8 : 0) |
			     (i + 2 < n ? p[i + 2] : 0);

		out[w++] = t[v >> 18 & 63];
		out[w++] = t[v >> 12 & 63];
		out[w++] = i + 1 < n ? t[v >> 6 & 63] : '=';
		out[w++] = i + 2 < n ? t[v & 63] : '=';
	}
	out[w] = 0;
	return w;
}

/* A deflate stream of one stored block, with `pre` bytes in front and `post` behind it. */
static size_t stored(const uint8_t *p, size_t n, const uint8_t *pre, size_t np, uint8_t *out)
{
	size_t w = 0;

	memcpy(out, pre, np);
	w = np;
	out[w++] = 1;
	out[w++] = (uint8_t)n;
	out[w++] = (uint8_t)(n >> 8);
	out[w++] = (uint8_t)~n;
	out[w++] = (uint8_t)(~n >> 8);
	memcpy(out + w, p, n);
	return w + n;
}

#define PAYLOAD "echo 'hi';"
#define PAYLOAD_FORM "echo('hi');"

/* php source calling `fn` over the literal `lit`, with a line of padding so the view is worth making. */
static void call(char *out, const char *fn, const char *lit)
{
	sprintf(out, "<?php\n// padding padding padding\neval( %s( \"%s\" ) );\n", fn, lit);
}

static void decoders(void)
{
	static char src[4096], lit[2048], want[4096];
	uint8_t raw[512];
	const uint8_t *pay = (const uint8_t *)PAYLOAD;
	size_t n = strlen(PAYLOAD), k, m;

	/* base64 */
	b64(pay, n, lit);
	call(src, "base64_decode", lit);
	view(src, "<?php\neval(decoded_base64_decode(\"" PAYLOAD_FORM "\"));");
	/* and with the other spellings of the call: case, a leading backslash, the silence operator */
	call(src, "BASE64_Decode", lit);
	view(src, "<?php\neval(decoded_BASE64_Decode(\"" PAYLOAD_FORM "\"));");
	sprintf(src, "<?php\n// padding padding padding\neval(@\\base64_decode(\"%s\"));\n", lit);
	view(src, "<?php\neval(@\\decoded_base64_decode(\"" PAYLOAD_FORM "\"));");
	/* a second argument does not stop it, a second term in the first does */
	sprintf(src, "<?php\n// padding padding padding\neval(base64_decode(\"%s\", true));\n", lit);
	view(src, "<?php\neval(decoded_base64_decode(\"" PAYLOAD_FORM "\",true));");

	/* hex2bin, urldecode, str_rot13, strrev (these two carry the text itself, so it has no quote in it) */
	for (k = 0; k < n; k++)
		sprintf(lit + 2 * k, "%02x", pay[k]);
	call(src, "hex2bin", lit);
	view(src, "<?php\neval(decoded_hex2bin(\"" PAYLOAD_FORM "\"));");
	for (k = m = 0; k < n; k++)
		m += (size_t)sprintf(lit + m, "%%%02X", pay[k]);
	call(src, "urldecode", lit);
	view(src, "<?php\neval(decoded_urldecode(\"" PAYLOAD_FORM "\"));");
	{
		static const char plain[] = "echo 1;echo 2;echo 3;";
		size_t pn = strlen(plain);

		for (k = 0; k < pn; k++) {
			uint8_t c = (uint8_t)plain[k];

			lit[k] = (char)((c >= 'a' && c <= 'z') ? 'a' + (c - 'a' + 13) % 26 : c);
		}
		lit[pn] = 0;
		sprintf(src, "<?php\n// padding padding padding\neval(str_rot13('%s'));\n", lit);
		view(src, "<?php\neval(decoded_str_rot13('echo(1);echo(2);echo(3);'));");
		for (k = 0; k < pn; k++)
			lit[k] = plain[pn - 1 - k];
		lit[pn] = 0;
		sprintf(src, "<?php\n// padding padding padding\neval(strrev('%s'));\n", lit);
		view(src, "<?php\neval(decoded_strrev('echo(1);echo(2);echo(3);'));");
	}

	/* raw deflate, zlib and gzip, each behind base64 as a shell has them */
	m = stored(pay, n, (const uint8_t *)"", 0, raw);
	b64(raw, m, lit);
	call(src, "gzinflate", lit);
	sprintf(want, "<?php\neval(gzinflate('%s'));", lit);
	view(src, want);              /* a deflate stream is binary: base64 is not under it, so not decoded */
	sprintf(src, "<?php\n// padding padding padding\neval(gzinflate(base64_decode(\"%s\")));\n", lit);
	view(src, "<?php\neval(decoded_gzinflate(decoded_base64_decode(\"" PAYLOAD_FORM "\")));");
	m = stored(pay, n, (const uint8_t *)"\x78\x01", 2, raw);
	b64(raw, m, lit);
	sprintf(src, "<?php\n// padding padding padding\neval(gzuncompress(base64_decode(\"%s\")));\n", lit);
	view(src, "<?php\neval(decoded_gzuncompress(decoded_base64_decode(\"" PAYLOAD_FORM "\")));");
	m = stored(pay, n, (const uint8_t *)"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", 10, raw);
	b64(raw, m, lit);
	sprintf(src, "<?php\n// padding padding padding\neval(gzdecode(base64_decode(\"%s\")));\n", lit);
	view(src, "<?php\neval(decoded_gzdecode(decoded_base64_decode(\"" PAYLOAD_FORM "\")));");

	/* a chain runs innermost first: rot13 over base64 over reverse is not the same as the other way */
	{
		char inner[512], outer[512];
		size_t i;

		for (i = 0; i < n; i++)
			inner[i] = (char)pay[n - 1 - i];                 /* strrev */
		b64((const uint8_t *)inner, n, outer);                   /* base64 of the reversed text */
		sprintf(src, "<?php\n// padding padding padding\neval(strrev(base64_decode(\"%s\")));\n", outer);
		/* base64_decode first gives the reversed text, strrev then restores it */
		view(src, "<?php\neval(decoded_strrev(decoded_base64_decode(\"" PAYLOAD_FORM "\")));");
	}

	/* a layer inside a layer: the payload is php that decodes another, and both are peeled */
	{
		char mid[1024], midb[1024], midl[2048];

		b64(pay, n, lit);
		sprintf(mid, "eval( base64_decode( \"%s\" ) );", lit);
		b64((const uint8_t *)mid, strlen(mid), midb);
		sprintf(midl, "%s", midb);
		call(src, "base64_decode", midl);
		/* the view carries each layer's text where its literal was: the quotes inside are not escaped again */
		view(src, "<?php\neval(decoded_base64_decode(\"eval(decoded_base64_decode(\"" PAYLOAD_FORM "\"));\"));");
	}

	/* a payload that is a page keeps its tag and its markup */
	{
		const char *page = "<b> x </b><?php  echo  1 ; ?>\n";

		b64((const uint8_t *)page, strlen(page), lit);
		call(src, "base64_decode", lit);
		/* markup is markup: its spacing stays, the island in it is formed */
		view(src, "<?php\neval(decoded_base64_decode(\"<b> x </b><?php echo(1);\n?>\n\"));");
	}

	/* NOT decoded: no literal, a join, a call that is not a decoder, a literal that is not base64 */
	view("<?php\n// padding padding padding\neval(base64_decode($x));\n",
	     "<?php\neval(base64_decode($x));");
	view("<?php\n// padding padding padding\neval(base64_decode(\"YQ==\" . $y));\n",
	     "<?php\neval(base64_decode('YQ=='.$y));");
	view("<?php\n// padding padding padding\neval(md5(\"YQ==\"));\n", "<?php\neval(md5('YQ=='));");
	view("<?php\n// padding padding padding\neval(hex2bin('zz'));\n", "<?php\neval(hex2bin('zz'));");

	/*
	 * NESTED, every layer the base64 of the one inside, the innermost of the payload ITSELF encoded (a layer that wraps raw
	 * text in base64_decode decodes it to noise, and a check that the payload is NOT reached then holds at any depth). Twelve
	 * and thirty-two layers reach the payload; thirty-three do not: the text is cut at the bound, not lost, and the scan ends.
	 * The bound is SCRIPT_DEC_DEPTH of objctx_script_dec.c; a change to it is a change to the two numbers here.
	 */
	{
		static const unsigned depths[] = { 1, 12, 32, 33 };
		static char a[1u << 22], b[1u << 22], t[(1u << 22) + 256u];
		unsigned d, i;

		for (d = 0; d < sizeof depths / sizeof depths[0]; d++) {
			static char big[(1u << 22) + 256u];
			int reached;

			b64((const uint8_t *)PAYLOAD, strlen(PAYLOAD), a);
			for (i = 1; i < depths[d]; i++) {
				snprintf(t, sizeof t, "eval( base64_decode( \"%s\" ) );", a);
				b64((const uint8_t *)t, strlen(t), b);
				strcpy(a, b);
			}
			snprintf(big, sizeof big, "<?php\n// padding padding padding\neval(base64_decode(\"%s\"));\n", a);
			scan(big, strlen(big), 1);
			CKF(n_kids == 1, "%u layers: %llu objects", depths[d], (unsigned long long)n_kids);
			if (kid_n >= sizeof kid)
				continue;
			kid[kid_n] = 0;
			reached = strstr((char *)kid, PAYLOAD_FORM) != NULL;
			CKF(reached == (depths[d] <= 32u), "%u layers: the payload is %sreached", depths[d], reached ? "" : "not ");
			if (depths[d] > 32u)
				CK(strstr((char *)kid, "base64_decode(") != NULL);      /* the layer past the bound is kept as it was */
		}
	}
}

/*
 * WHAT A SCRIPT COMPUTES, WRITTEN WHERE IT WAS COMPUTED (deep, php): the right side of an assignment that is not one literal and that the
 * evaluator follows to a text is written in the view as the literal it comes to, so `$u = str_replace('T|', '', $a . $b)` shows the program
 * it builds, in place, with the pieces still there around it. The evaluator is the diagnose route's (one place that knows what a join and
 * str_replace come to) and the writer is the lib's; what is checked here is the engine's decision between them: that it is done, deep only,
 * not for what a decoder makes (the decode hook owns that and keeps the call), not for what is not a constant, and with every byte of the value
 * back (a quote or a backslash in it is escaped, so the literal's value is the text).
 */
static int view_level(const char *src, int level, const char *const must[], const char *const mustnot[])
{
	uint32_t i, bad = 0;

	scan(src, strlen(src), level);
	kid[kid_n < sizeof kid ? kid_n : sizeof kid - 1u] = 0;
	for (i = 0; must && must[i]; i++)
		if (n_kids != 1 || !strstr((char *)kid, must[i])) {
			printf("  FAIL level %d view of  %s\n       lacks   %s\n       view    %s\n", level, src, must[i], n_kids ? (char *)kid : "(none)");
			bad++;
		}
	for (i = 0; mustnot && mustnot[i]; i++)
		if (n_kids == 1 && strstr((char *)kid, mustnot[i])) {
			printf("  FAIL level %d view of  %s\n       has     %s\n       view    %s\n", level, src, mustnot[i], (char *)kid);
			bad++;
		}
	failures += (int)bad;
	return !bad;
}

static void computed_values(void)
{
	static const char pad[] = "<?php\n// padding padding padding padding padding padding padding padding\n";
	static char src[4096];
	static const char *const m1[] = { "$a='ab';", NULL }, *const n1[] = { "str_replace", NULL };
	static const char *const m2[] = { "$a='echo 1;';", NULL }, *const n2[] = { "str_replace(", NULL };
	static const char *const m3[] = { "$f='create_function';", NULL };
	static const char *const m4[] = { "$a='it\\'s \\\\ ok';", NULL };
	static const char *const m5[] = { "decoded_base64_decode(", NULL }, *const n5[] = { "$a='abcx'", NULL };
	static const char *const m6[] = { "str_replace(", NULL };

	/* a variable operand: the pieces are variables, the answer is not */
	snprintf(src, sizeof src, "%s$s = 'axb'; $a = str_replace('x', '', $s); echo $a;\n", pad);
	view_level(src, 2, m1, n1);
	/* the pieces joined by variables, and str_replace over the join (hoho's shape) */
	snprintf(src, sizeof src, "%s$p = 'ec#ho '; $q = '1;'; $a = str_replace('#', '', $p . $q); eval($a);\n", pad);
	view_level(src, 2, m2, n2);
	/* a function name built by str_replace, and a function named by it */
	snprintf(src, sizeof src, "%s$f = str_replace('k', '', 'create_funkction'); $f('', 'return 1;');\n", pad);
	view_level(src, 2, m3, NULL);
	/* a quote and a backslash in the value are escaped: the literal's value is the text */
	snprintf(src, sizeof src, "%s$a = str_replace('Z', '', \"it's Z\\\\ ok\"); echo $a;\n", pad);
	view_level(src, 2, m4, NULL);
	/* a decoder is the decode hook's: the call stays (renamed) and the decoded literal is shown by it, not written over a variable */
	snprintf(src, sizeof src, "%s$a = base64_decode('YWJj') . 'x'; echo $a;\n", pad);
	view_level(src, 2, m5, n5);
	/* not deep: nothing is written over - the evaluator is for the deep pass */
	snprintf(src, sizeof src, "%s$s = 'axb'; $a = str_replace('x', '', $s); echo $a;\n$keep = 1;\n", pad);
	view_level(src, 1, m6, NULL);
	/* not a constant: a request in it */
	snprintf(src, sizeof src, "%s$a = str_replace('x', '', 'a' . $_GET['b']); echo $a;\n$keep = 1;\n", pad);
	view_level(src, 2, m6, NULL);
}

/*
 * A deflate bomb: one fixed-huffman block that writes a letter and then copies it 258 bytes at a time,
 * twenty thousand times - about five megabytes out of thirty kilobytes in. The allowance an object
 * of that size has is eight times it, so the inflate stops there, the real beginning is the view's
 * and the scan ends.
 */
static size_t bomb(uint8_t *out, unsigned copies)
{
	size_t w = 0;
	unsigned bits = 0, i;
	uint32_t acc = 0;

#define PUT(val, n) do { \
		for (unsigned b_ = 0; b_ < (n); b_++) { \
			acc |= (uint32_t)(((val) >> b_) & 1u) << bits++; \
			if (bits == 8) { out[w++] = (uint8_t)acc; acc = 0; bits = 0; } \
		} \
	} while (0)
	/* header: BFINAL = 1, BTYPE = 01 (fixed) */
	PUT(1u, 1u);
	PUT(1u, 2u);
	/* literal 'A' (0x41): fixed codes 0..143 are 8 bits, 00110000 + value, most significant bit first */
	{
		uint32_t code = 0x30u + 0x41u, r = 0;

		for (i = 0; i < 8; i++)
			r |= ((code >> i) & 1u) << (7u - i);
		PUT(r, 8u);
	}
	for (i = 0; i < copies; i++) {
		uint32_t code = 0xc0u + (285u - 280u), r = 0, k;       /* length 258 */

		for (k = 0; k < 8; k++)
			r |= ((code >> k) & 1u) << (7u - k);
		PUT(r, 8u);
		PUT(0u, 5u);                                            /* distance 1 */
	}
	{
		uint32_t r = 0;                                         /* end of block: 0000000 */

		PUT(r, 7u);
	}
	if (bits)
		out[w++] = (uint8_t)acc;
#undef PUT
	return w;
}

static void bombs(void)
{
	static uint8_t raw[1u << 16];
	static char lit[1u << 17], src[(1u << 17) + 256u];
	size_t m = bomb(raw, 20000u);

	b64(raw, m, lit);
	sprintf(src, "<?php\n// padding padding padding\neval(gzinflate(base64_decode(\"%s\")));\n$keep = 1;\n", lit);
	scan(src, strlen(src), 1);
	CK(n_kids == 1);
	/* the view holds the beginning of what the stream makes: more than the file, and no more than its allowance (thirty-two times
	 * the file and sixty-four kilobytes) - never the five megabytes the stream would make */
	CKF(kid_n > strlen(src) && kid_n <= 33u * strlen(src) + 65536u + 4096u, "view %llu bytes of a %zu byte file", (unsigned long long)kid_n, strlen(src));
	CK(kid_n <= sizeof kid && memchr(kid, 'A', kid_n) != NULL);
	/* it still reads as the call it was */
	CK(kid_n >= 56u && memcmp(kid, "<?php\neval(decoded_gzinflate(decoded_base64_decode(\"AAAA", 56u) == 0);
}

/*
 * THE VALUE OF A LITERAL AND A PAYLOAD IN PIECES, through the scan: the payload "echo 'hi';" is base64 "ZWNobyAnaGknOw==",
 * written as one literal with a line break in it ("\n" is an escape, the two characters are not base64), or cut in two and
 * joined - with "." in php, "+" in javascript, side by side in python - or both. Each reads as the payload and is replaced by
 * what it decodes to.
 */
static void value_and_joins(void)
{
	view_raw("<?php\n// padding padding padding\neval( base64_decode( \"ZWNobyAnaGknOw==\\n\" ) );\n$keep = 1;\n",
		 "<?php\neval(decoded_base64_decode(\"echo('hi');\"));\n$keep=1;");
	view_raw("<?php\n// padding padding padding\neval( base64_decode( \"ZWNo\" . 'by' . \"AnaGkn\\x4f\\x77==\" ) );\n$keep = 1;\n",
		 "<?php\neval(decoded_base64_decode(\"echo('hi');\"));\n$keep=1;");
	/* a join with a name in it is not a payload and is written as typed (the way the form writes it with no decoder) */
	view_raw("<?php\n// padding padding padding\neval( base64_decode( \"ZWNo\" . $x ) );\n$keep = 1;\n",
		 "<?php\neval(base64_decode('ZWNo'.$x));\n$keep=1;");
	view_raw("#!/usr/bin/env node\n// padding padding padding\neval( atob( \"ZWNo\" + 'byAnaGknOw==' ) );\nvar keep = 1;\n",
		 "#!/usr/bin/env node\neval(decoded_atob(\"echo'hi';\"));\nvar keep=1;");
	view_raw("#!/usr/bin/env python\n# padding padding padding\nexec( base64.b64decode( \"ZWNo\" 'by' \"AnaGknOw==\" ) )\nkeep = 1\n",
		 "#!/usr/bin/env python\nexec(base64.decoded_b64decode(\"echo'hi';\"))\nkeep=1");
	/* a join no decoder reads is folded, and that alone makes a view: nothing was left to tidy in this one */
	view_raw("<?php\n$f = 'ev' . 'al'; $g = 'sys' . 'tem'; $keep = 1;\n",
		 "<?php\n$f='eval';$g='system';$keep=1;");
	/* a literal with something the program fills in has no value, so it is not offered */
	view_raw("<?php\n// padding padding padding\neval( base64_decode( \"ZWNo$x\" ) );\n$keep = 1;\n",
		 "<?php\neval(base64_decode(\"ZWNo$x\"));\n$keep=1;");
}

static void mapping(void)
{
	unsigned k;

	static const struct { unsigned kind, lang; } lexed[] = {
		{ KOF_SCRIPT_PHP, KGENOME_TEXTUAL_LANG_PHP }, { KOF_SCRIPT_SHELL, KGENOME_TEXTUAL_LANG_SH },
		{ KOF_SCRIPT_JS, KGENOME_TEXTUAL_LANG_JS }, { KOF_SCRIPT_PYTHON, KGENOME_TEXTUAL_LANG_PY },
		{ KOF_SCRIPT_VBS, KGENOME_TEXTUAL_LANG_VBS }, { KOF_SCRIPT_ASP, KGENOME_TEXTUAL_LANG_ASP },
		{ KOF_SCRIPT_ASPX, KGENOME_TEXTUAL_LANG_ASPX }, { KOF_SCRIPT_JSP, KGENOME_TEXTUAL_LANG_JSP },
		{ KOF_SCRIPT_PERL, KGENOME_TEXTUAL_LANG_PERL }, { KOF_SCRIPT_RUBY, KGENOME_TEXTUAL_LANG_RUBY },
		{ KOF_SCRIPT_LUA, KGENOME_TEXTUAL_LANG_LUA }, { KOF_SCRIPT_TCL, KGENOME_TEXTUAL_LANG_TCL },
		{ KOF_SCRIPT_BAT, KGENOME_TEXTUAL_LANG_BAT }, { KOF_SCRIPT_PSH, KGENOME_TEXTUAL_LANG_PSH },
		{ KOF_SCRIPT_CFM, KGENOME_TEXTUAL_LANG_CFM },
	};
	unsigned i, want;

	for (k = 0; k < KOF_SCRIPT_TYPE_COUNT; k++) {
		for (i = 0, want = KGENOME_TEXTUAL_LANG_NONE; i < sizeof lexed / sizeof lexed[0]; i++)
			if (lexed[i].kind == k)
				want = lexed[i].lang;
		CK(kof_script_textual_lang((uint8_t)k) == want);
	}
	CK(kof_script_textual_lang(KOF_SCRIPT_TYPE_COUNT) == KGENOME_TEXTUAL_LANG_NONE);
	CK(kof_script_textual_lang(255) == KGENOME_TEXTUAL_LANG_NONE);
}

static void php_view(void)
{
	/* comments gone (a trailing one too), brackets closed up, the brace joined, the markup untouched */
	view_raw("<html>\n<?php\n    // gone\n    if ( isset( $_POST['a'] ) )\n    {\n        eval( $_POST['a'] );  /* gone */\n    }\n?>\n<p>  x  </p>\n",
	     "<html>\n<?php\nif(isset($_POST['a'])){\neval($_POST['a']);\n}\n?>\n<p>  x  </p>\n");
	/* the whole view is one region: BODY, from the first byte to the last */
	CK(kid_regions == 0);
	/* a plain program is the same */
	view_raw("<?php\n\n\n   $a  =  1 ;   // one\n   $b = 2 ;\n   echo $a + $b ;\n   system( $_GET[ 'c' ] ) ;\n",
	     "<?php\n$a=1;\n$b=2;\necho($a+$b);\nsystem($_GET['c']);");
	CK(kid_regions == 0);
	/* a hex-escaped name is the name */
	view("<?php\n// padding padding padding padding\n$f = $_SERVER[\"\\x53\\x43\\x52\\x49\\x50\\x54\"];\n",
	     "<?php\n$f=$_SERVER['SCRIPT'];");
}

static void shell_view(void)
{
	/* white space is syntax, so one space is kept; the trailing comment goes, and so does the last break */
	view_raw("#!/bin/sh\n\n    if [ -f /etc/x ]; then\n        echo   hi   # say hi\n    fi\n    # a whole line\n",
		 "#!/bin/sh\nif [ -f /etc/x ]; then\necho hi\nfi");
	CK(kid_regions == 0);
	/* a here-document and the strings are what they were */
	view_raw("#!/bin/sh\n# padding padding padding\ncat  <<EOF   > /tmp/x\n   keep   this   # and this\nEOF\necho  \"a   b\"  'c   d'\n",
		 "#!/bin/sh\ncat <<EOF > /tmp/x\n   keep   this   # and this\nEOF\necho \"a   b\" 'c   d'");
}

static void lexed_views(void)
{
	/* the interpreter line stays (js and python call it a comment, the form keeps it) and the rest is formed */
	view_raw("#!/usr/bin/env node\n// padding padding padding\nvar  re = /[\"']+/g ,  s = `a${ b( \"}\" ) }c` ;   // t\n",
		 "#!/usr/bin/env node\nvar re=/[\"']+/g,s=`a${ b( \"}\" ) }c`;");
	CK(kid_regions == 0);
	view_raw("#!/usr/bin/env python\n\n    import os\n\n    os.system( f\"{ x['a'] } id\" )   # run it\n    # whole line\n    y = 1\n",
		 "#!/usr/bin/env python\nimport os\nos.system(f\"{ x['a'] } id\")\ny=1");
	CK(kid_regions == 0);
	/* an asp page: the first island is only a comment and goes whole - "%>" ends it, in a comment too - and the
	 * second is formed; the markup between and around them is untouched */
	view_raw("<%@ LANGUAGE=\"VBScript\" %>\n<html>\n<% ' a long note that is only a comment %> x\n<% Dim  a ' trailing\n  a = \"1 %\" & \"2\" %>\n<p> keep </p>\n",
		 "<%@ LANGUAGE=\"VBScript\" %>\n<html>\n x\n<%Dim a\na=\"1 %\"&\"2\"\n%>\n<p> keep </p>\n");
	CK(kid_regions == 0);
}

static void perl_view(void)
{
	view_raw("#!/usr/bin/perl\n\n    use strict;\n\n    print(  \"id\" ) ;   # run it\n    # whole line\n    my $x = 1;\n",
		 "#!/usr/bin/perl\nuse strict;\nprint(\"id\");\nmy $x=1;");
	/* a lexed language declares no region, as the others do */
	CK(kid_regions == 0);
}

int main(int argc, char **argv)
{
	const char *db = argc > 1 ? argv[1] : "build/release/databases";
	kof_engine *eng = keng_open(db);

	if (!eng) {
		printf("script dispatch: cannot open %s\n", db);
		return 2;
	}
	sc = kscan_new(eng);
	if (!sc) {
		keng_close(eng);
		return 2;
	}
	mapping();
	php_view();
	shell_view();
	lexed_views();
	perl_view();
	decoders();
	value_and_joins();
	bombs();
	computed_values();
	kscan_free(sc);
	keng_close(eng);
	printf("script dispatch: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
