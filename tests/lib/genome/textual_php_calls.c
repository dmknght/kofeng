/*
 * textual_php_calls - the form writes a php call on literals as the literal it evaluates to (str_replace('k','','ckrekatek'),
 * chr(115), substr('abcdef', -3), strtolower(trim(' ABC '))), and leaves every call that is not exactly that as it was typed.
 *
 * THE FUNCTIONS ARE NOT WHAT IS UNDER TEST. This links libkgenome.a alone, so the hook that runs str_replace and its kin is this
 * file's own (ref_apply, plain loops, written from php's documentation - [Unverified] against php: none is installed here); the engine's
 * hook is kuncoat's and is checked by tests/lib/uncoat/strfn.c. What is under test is everything between the text and the hook: which
 * calls are taken, which argument is which (the table), what a number is, how the answer is written as a literal, how it
 * joins with the literals around it, and what comes out when the call turns out not to be one.
 *
 * TWO KINDS OF CHECK.
 *
 * EXAMPLES, one per rule, each with the text it must come out as: the calls that fold (the spellings of the name, the white space and
 * comments between the tokens, a call in a call, a call in a join, an argument that is a join) and the ones that must not (a method, a
 * static call, a definition, `new`, a namespaced name, an argument that is a variable or an array or a literal that interpolates, an
 * octal number, hex, a float, an argument too many, a call the text ends inside, a control byte under chr, no hook, KEEP_JOINS).
 *
 * GENERATED, against a model written in the generator: random expression trees of literals (single quoted, double quoted with every
 * kind of escape), the calls of the table with random white space, comments, case, "\" and "@", and joins, each with the value the
 * generator computed as it built the text. For a tree that is one call or one literal the form must be exactly
 * `$x='<value>';` - and for a join of them the literals it leaves must hold that value in order. Then: the form of the form
 * is itself; a cap that is too tight for the fold does not stop the form or change a byte of meaning (status OK, and the output
 * run through the form again with room is the output that had the room the first time); and the count of calls is the number the
 * generator built.
 */

#include "textual_check.h"

/* ---- the reference hook: php's functions of bytes, as plain loops ----------------------------------------------------------- */

static int is_trim(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0 || c == 0x0b;
}

static int ref_apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out,
		     uint32_t cap, uint32_t *n_out)
{
	uint32_t i = 0, w = 0, k;
	int64_t from, cnt;

	(void)user;
	*n_out = 0;
	switch (c->op) {
	case KGENOME_TEXTUAL_DEC_REPLACE:
		while (i < len) {
			if (c->n1 && len - i >= c->n1 && !memcmp(in + i, c->s1, c->n1)) {
				if (c->n2 > cap - w)
					return 0;
				memcpy(out + w, c->s2, c->n2);
				w += c->n2;
				i += c->n1;
			} else {
				if (w >= cap)
					return 0;
				out[w++] = in[i++];
			}
		}
		break;
	case KGENOME_TEXTUAL_DEC_TRANSLATE:
		if (c->n1 != c->n2 || len > cap)
			return 0;
		for (; i < len; i++) {
			uint8_t b = in[i];

			for (k = c->n1; k-- > 0;)
				if (c->s1[k] == b) {
					b = c->s2[k];
					break;
				}
			out[w++] = b;
		}
		break;
	case KGENOME_TEXTUAL_DEC_SLICE:
		from = c->k1 < 0 ? (int64_t)len + c->k1 : c->k1;
		if (from < 0)
			from = 0;
		if (from > (int64_t)len)
			break;
		cnt = c->to_end ? (int64_t)len - from : c->k2;
		if (cnt < 0)
			cnt = (int64_t)len - from + cnt < 0 ? 0 : (int64_t)len - from + cnt;
		if (cnt > (int64_t)len - from)
			cnt = (int64_t)len - from;
		if ((uint64_t)cnt > cap)
			return 0;
		memcpy(out, in + from, (size_t)cnt);
		w = (uint32_t)cnt;
		break;
	case KGENOME_TEXTUAL_DEC_LOWER: case KGENOME_TEXTUAL_DEC_UPPER:
	case KGENOME_TEXTUAL_DEC_UCFIRST: case KGENOME_TEXTUAL_DEC_LCFIRST:
		if (len > cap)
			return 0;
		for (; i < len; i++) {
			uint8_t b = in[i];
			int up = c->op == KGENOME_TEXTUAL_DEC_UPPER || (c->op == KGENOME_TEXTUAL_DEC_UCFIRST && !i);
			int lo = c->op == KGENOME_TEXTUAL_DEC_LOWER || (c->op == KGENOME_TEXTUAL_DEC_LCFIRST && !i);

			if (up && b >= 'a' && b <= 'z')
				b = (uint8_t)(b - 32);
			if (lo && b >= 'A' && b <= 'Z')
				b = (uint8_t)(b + 32);
			out[w++] = b;
		}
		break;
	case KGENOME_TEXTUAL_DEC_TRIM: case KGENOME_TEXTUAL_DEC_LTRIM: case KGENOME_TEXTUAL_DEC_RTRIM: {
		uint32_t a = 0, z = len;

		if (c->op != KGENOME_TEXTUAL_DEC_RTRIM)
			while (a < z && is_trim(in[a]))
				a++;
		if (c->op != KGENOME_TEXTUAL_DEC_LTRIM)
			while (z > a && is_trim(in[z - 1u]))
				z--;
		if (z - a > cap)
			return 0;
		memcpy(out, in + a, z - a);
		w = z - a;
		break;
	}
	default:
		return 0;
	}
	*n_out = w;
	return 1;
}

/* ---- examples -------------------------------------------------------------------------------------------------------------- */

static uint8_t cbuf[1 << 16];

static struct kgenome_textual_form_res run_cap_n(const char *src, uint32_t n, uint32_t flags, kgenome_textual_apply_fn ap, uint64_t cap,
						 uint32_t *w, enum kgenome_textual_status *st)
{
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = n, .lang = KGENOME_TEXTUAL_LANG_PHP,
					       .flags = flags, .out = cbuf, .cap = cap, .apply = ap };
	struct kgenome_textual_form_res rs;

	*st = kgenome_textual_form(&rq, &rs);
	*w = rs.n_out;
	return rs;
}

static struct kgenome_textual_form_res run_cap(const char *src, uint32_t flags, kgenome_textual_apply_fn ap, uint64_t cap,
					       uint32_t *w, enum kgenome_textual_status *st)
{
	return run_cap_n(src, (uint32_t)strlen(src), flags, ap, cap, w, st);
}

/* The form of `src` as a fragment, with the hook, room to spare: must be `want` with `calls` calls rewritten. */
static void fold(const char *src, const char *want, uint32_t calls)
{
	enum kgenome_textual_status st;
	uint32_t w;
	struct kgenome_textual_form_res rs = run_cap(src, KGENOME_TEXTUAL_FRAGMENT, ref_apply, KGENOME_TEXTUAL_FORM_CAP(strlen(src)) + 4096u, &w, &st);

	if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w != strlen(want) || memcmp(cbuf, want, w) || rs.n_calls != calls) {
		cbuf[w < sizeof cbuf ? w : sizeof cbuf - 1u] = 0;
		printf("  FAIL fold of  %s\n       got    %s  (status %d, %u calls)\n       wanted %s  (%u calls)\n", src, cbuf, (int)st,
		       rs.n_calls, want, calls);
		fails++;
	}
	/* and the form of what came out is itself */
	if (w < sizeof cbuf / 2u) {
		static uint8_t again[sizeof cbuf];
		uint32_t w2;
		struct kgenome_textual_form_req rq = { .in = cbuf, .n = w, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = KGENOME_TEXTUAL_FRAGMENT,
						       .out = again, .cap = KGENOME_TEXTUAL_FORM_CAP(w) + 4096u, .apply = ref_apply };
		struct kgenome_textual_form_res r2;

		memcpy(again, cbuf, w);
		(void)kgenome_textual_form(&rq, &r2);
		w2 = r2.n_out;
		if (w2 != w || memcmp(again, cbuf, w)) {
			printf("  FAIL fold of %s is not its own form\n", src);
			fails++;
		}
	}
}

static void examples_fold(void)
{
	/* the call is its literal */
	fold("$f = str_replace('k', '', 'ckrekatek_fuknkkction');", "$f='create_function';", 1);
	fold("$c = chr(115);", "$c='s';", 1);
	fold("$c = substr('abcdef', -3);", "$c='def';", 1);
	fold("$c = substr('abcdef', 1, -2);", "$c='bcd';", 1);
	fold("$c = strtr('hello', 'el', 'ip');", "$c='hippo';", 1);
	fold("$c = ucfirst('word'); $d = lcfirst('WORD'); $e = strtoupper('w'); $f = strtolower('W');", "$c='Word';$d='wORD';$e='W';$f='w';", 4);
	fold("$c = trim('  q  ') . ltrim('  q ') . rtrim(' q  ');", "$c='qq  q';", 3);
	/* a name kept from a scan by a join of calls and literals is ONE literal */
	fold("$c = chr(115) . chr(121) . 'stem';", "$c='system';", 2);
	fold("$c = 'sys' . chr(116) . 'em';", "$c='system';", 1);
	fold("$c = strrev('a') . chr(65);", "$c=strrev('a').'A';", 1);
	/* calls in calls, and an argument that is a join */
	fold("$c = strtolower(trim(' ABC '));", "$c='abc';", 2);
	fold("$c = strtolower(trim(' ABC ') . 'D');", "$c='abcd';", 2);
	fold("$c = str_replace('a', '', 'ev' . 'a' . 'l' . 'a');", "$c='evl';", 1);
	fold("$c = substr(strtolower(chr(65) . chr(66) . 'CD'), 1, 2);", "$c='bc';", 4);
	/* any spelling of the name, white space and comments between the tokens, "\" and "@" */
	fold("$c = \\STR_Replace ( /* a */ 'k' , // b\n '' ,\n 'ckat' );", "$c='cat';", 1);
	fold("$c = @trim('  q ');", "$c=@'q';", 1);
	fold("$c = chr( 65 ) . chr(+66) . chr(-190);", "$c='ABB';", 3);
	fold("$c = substr('abc', '1');", "$c='bc';", 1);
	/* a literal as its value: both kinds of quote, and an answer holding the two bytes a single quote reads */
	fold("$c = str_replace('a', \"'\", 'xay');", "$c='x\\'y';", 1);
	fold("$c = str_replace('a', '\\\\', 'xay');", "$c='x\\\\y';", 1);
	fold("$c = trim(\"\\x41 \\n\");", "$c='A';", 1);
	fold("$c = strtoupper(\"a\\$b\");", "$c='A$B';", 1);
	fold("$c = trim('');", "$c='';", 1);
	fold("$c = substr('abc', 9);", "$c='';", 1);
	/* where it stands: an argument of a call that is not one, an array element, a return, an echo */
	fold("foo(trim(' a '), $x);", "foo('a',$x);", 1);
	fold("$a = [1, chr(65), 'b'];", "$a=[1,'A','b'];", 1);
	fold("return chr(65);", "return'A';", 1);
	fold("echo chr(65);", "echo('A');", 1);
	fold("echo 'x' . strtoupper('y'), 'z';", "echo('xY','z');", 1);
	/* the calls that are not one stay, and what is round them is formed as ever */
	fold("$c = str_replace('a', 'b', $x);", "$c=str_replace('a','b',$x);", 0);
	fold("$c = str_replace('a', 'b', 'x' . $y);", "$c=str_replace('a','b','x'.$y);", 0);
	fold("$c = str_replace('a', 'b', \"x$y\");", "$c=str_replace('a','b',\"x$y\");", 0);
	fold("$c = str_replace(array('a'), 'b', 'c');", "$c=str_replace(array('a'),'b','c');", 0);
	fold("$c = trim(' x ', 'y');", "$c=trim(' x ','y');", 0);
	fold("$c = substr('abc');", "$c=substr('abc');", 0);
	fold("$c = substr('abc', 1, 2, 3);", "$c=substr('abc',1,2,3);", 0);
	fold("$c = strtr('abc', 'ab', 'x');", "$c=strtr('abc','ab','x');", 0);       /* unequal lists: the hook refuses */
	fold("$c = chr(10) . chr(0) . chr(200);", "$c=chr(10).chr(0).chr(200);", 0);   /* a table of bytes is data */
	fold("$c = chr(010);", "$c=chr(010);", 0);                                    /* octal */
	fold("$c = chr(065) . substr('abcdefghijklmnop', 010);", "$c=chr(065).substr('abcdefghijklmnop',010);", 0);
	fold("$c = chr(65) . substr('abcdefghijklmnop', 0) . chr(0) . chr(-0);", "$c='A'.'abcdefghijklmnop'.chr(0).chr(-0);", 2);       /* a join that goes on into a call that stays is not one literal */
	fold("$c = chr(0x41);", "$c=chr(0x41);", 0);
	fold("$c = chr(65.5);", "$c=chr(65.5);", 0);
	fold("$c = chr(65 + 1);", "$c=chr(65+1);", 0);
	/* the line break before a call that is written as a literal stays: it is a statement's end */
	fold("$a = 1;\nchr(65);\n\n  chr(66);", "$a=1;\n'A';\n'B';", 2);
	fold("f(1,\n trim(' a '));", "f(1,\n'a');", 1);
	/* a call that turns out not to be one is written with the white space it had: a line break kept before the byte that ended it */
	fold("f(substr('a',\n $x));", "f(substr('a',\n$x));", 0);
	fold("f(trim('a'\n . $x));", "f(trim('a'\n.$x));", 0);
	fold("$c = chr('A');", "$c=chr('A');", 0);                                    /* not a number: the table's rule, the hook is not asked */
	fold("$c = chr();", "$c=chr();", 0);
	fold("$c = substr('abc', 1,);", "$c=substr('abc',1,);", 0);
	fold("$o->trim('x'); X::trim('y'); $z = $trim('w');", "$o->trim('x');X::trim('y');$z=$trim('w');", 0);
	fold("function trim($s) { return $s; } $n = new strtr('a', 'b', 'c');", "function trim($s){return$s;}$n=new strtr('a','b','c');", 0);
	fold("$c = ns\\trim(' q ');", "$c=ns\\trim(' q ');", 0);
	fold("$c = strtolower_(' Q ') . xtrim(' q ') . trim_(' q ');", "$c=strtolower_(' Q ').xtrim(' q ').trim_(' q ');", 0);
	fold("$c = trim(' a ' 'b');", "$c=trim(' a ''b');", 0);
	fold("$c = trim(<<<X\n a \nX\n);", "$c=trim(<<<X\n a \nX\n);", 0);
	fold("$c = trim(' a ' . 5);", "$c=trim(' a '.5);", 0);
	fold("$c = trim(5 . ' a ');", "$c=trim(5.' a ');", 0);
	/* a call the text ends inside, and one a tag or a comment that does not end interrupts */
	fold("$c = trim(' a '", "$c=trim(' a '", 0);
	fold("$c = trim(' a ' /* open", "$c=trim(' a '/* open", 0);
	/* and one that is a decoder's is the decoder's, with no hook here: left as typed */
	fold("$c = strrev('abc') . base64_decode('YWJj');", "$c=strrev('abc').base64_decode('YWJj');", 0);
}

/*
 * THE BYTE BEFORE A NAME. `Xtrim(' q ')` is a call of trim only when X does not continue a name: for every byte at all, the form agrees with
 * what a name is (letters, digits, "_", and every byte from 0x80). The bytes that mean something of their own in front of a name - a quote,
 * "#" and "/" that begin a literal or a comment, "$", "\\", "<" and "?" that are a variable, a namespace or a tag - are examples above.
 */
static void every_byte_before(void)
{
	static const char skip[] = "'\"`#/$\\<?";
	uint32_t x;

	for (x = 0; x < 256u; x++) {
		uint8_t src[40];
		uint32_t w, n = 0, name = (x >= '0' && x <= '9') || ((x | 32u) >= 'a' && (x | 32u) <= 'z') || x == '_' || x >= 0x80u;
		enum kgenome_textual_status st;
		struct kgenome_textual_form_res rs;
		static const char tail[] = "trim(' q '));";

		if (x && memchr(skip, (int)x, sizeof skip - 1u))
			continue;
		memcpy(src, "f(1", 3);
		n = 3;
		src[n++] = (uint8_t)x;
		memcpy(src + n, tail, sizeof tail - 1u);
		n += (uint32_t)sizeof tail - 1u;
		rs = run_cap_n((const char *)src, n, KGENOME_TEXTUAL_FRAGMENT, ref_apply, KGENOME_TEXTUAL_FORM_CAP(n) + 256u, &w, &st);
		if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || rs.n_calls != (name ? 0u : 1u)) {
			printf("  FAIL a call after the byte 0x%02x: %u calls, wanted %u\n", x, rs.n_calls, name ? 0u : 1u);
			fails++;
		}
	}
}

/* the calls in a text with markup and tags: the call is code, and a tag ends it */
static void examples_page(void)
{
	enum kgenome_textual_status st;
	uint32_t w;
	struct kgenome_textual_form_res rs;
	const char *a = "<b>x</b><?php $a = chr(65) . 'b'; ?><i>y</i><?php echo str_replace('x', 'y', 'xz');";
	const char *b = "<?php $a = trim(' q ?><?php 1; ";

	rs = run_cap(a, 0, ref_apply, KGENOME_TEXTUAL_FORM_CAP(strlen(a)) + 256u, &w, &st);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 2);
	CK(w == strlen("<b>x</b><?php $a='Ab';\n?><i>y</i><?php echo('yz');") && !memcmp(cbuf, "<b>x</b><?php $a='Ab';\n?><i>y</i><?php echo('yz');", w));
	/* a tag inside a call: written as typed */
	rs = run_cap(b, 0, ref_apply, KGENOME_TEXTUAL_FORM_CAP(strlen(b)) + 256u, &w, &st);
	CK(rs.n_calls == 0);
}

/*
 * ROOM. A call is written as its literal only when what that leaves still fits what the caller gave: the answer is held at the top of the
 * output until it is written, so a long one (str_replace that makes the text longer) in a buffer with no room beyond KGENOME_TEXTUAL_FORM_CAP
 * stays as typed, is counted, and the text is still all there. And what is held is given back: a script of three thousand folds in a
 * buffer with no room to spare folds them all, because none of them is still held when the next is read.
 */
static void examples_room(void)
{
	enum kgenome_textual_status st;
	uint32_t w, i;
	struct kgenome_textual_form_res rs;
	const char *x = "$a = str_replace('a', 'aaaaaaaaaaaaaaaa', 'aaaaaaaa');";
	uint32_t n = (uint32_t)strlen(x);
	const char *dq = "$a = str_replace('a', 'b', \"x$y\"); $b = trim(' x ', 'y'); $c = substr('abc');";
	char *many = malloc(14u * 3000u + 1u);
	uint8_t *out = malloc(KGENOME_TEXTUAL_FORM_CAP(14u * 3000u) + 64u);

	rs = run_cap(x, KGENOME_TEXTUAL_FRAGMENT, ref_apply, KGENOME_TEXTUAL_FORM_CAP(n), &w, &st);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 0 && rs.n_refused == 1 && w == strlen("$a=str_replace('a','aaaaaaaaaaaaaaaa','aaaaaaaa');"));
	rs = run_cap(x, KGENOME_TEXTUAL_FRAGMENT, ref_apply, KGENOME_TEXTUAL_FORM_CAP(n) + 1000u, &w, &st);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 1 && rs.n_refused == 0 && w == 3u + 130u + 1u && cbuf[3] == '\'' && cbuf[3 + 129] == '\'');
	/* one that is refused for what it holds (an interpolating literal) is counted; one that is not that call (a third argument, two few) is a call
	 * for the hook to refuse or the table to decline: counted when the stage took it, not when it never did */
	rs = run_cap(dq, KGENOME_TEXTUAL_FRAGMENT, ref_apply, KGENOME_TEXTUAL_FORM_CAP(strlen(dq)) + 64u, &w, &st);
	CK(rs.n_calls == 0 && rs.n_refused == 2);
	for (i = 0; i < 3000u; i++)
		memcpy(many + 14u * i, "$a = chr(65);\n", 14u);
	{
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)many, .n = 14u * 3000u, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = KGENOME_TEXTUAL_FRAGMENT,
						       .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP(14u * 3000u), .apply = ref_apply };

		st = kgenome_textual_form(&rq, &rs);
		CK(st == KGENOME_TEXTUAL_OK && rs.n_calls >= 2990u && rs.n_fn[KGENOME_TEXTUAL_DEC_CHR] == rs.n_calls);
	}
	/* answers longer than the calls: with no room to spare they are refused, the text is formed whole, and with room every one is folded */
	{
		static const char one[] = "$a = str_replace('a', 'bbbbbbbbbbbbbbbbbbbb', 'aaaaaaaaaaaaaaaaaaaa');\n";
		uint32_t gl = (uint32_t)strlen(one), gn = gl * 40u;
		char *grow = malloc(gn);
		uint8_t *g = malloc(KGENOME_TEXTUAL_FORM_CAP(gn) + 40u * 400u);
		struct kgenome_textual_form_req rq;

		for (i = 0; i < 40u; i++)
			memcpy(grow + gl * i, one, gl);
		rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)grow, .n = gn, .lang = KGENOME_TEXTUAL_LANG_PHP, .flags = KGENOME_TEXTUAL_FRAGMENT,
							.out = g, .cap = KGENOME_TEXTUAL_FORM_CAP(gn), .apply = ref_apply };
		st = kgenome_textual_form(&rq, &rs);
		CK(st == KGENOME_TEXTUAL_OK && rs.n_out <= KGENOME_TEXTUAL_FORM_CAP(gn));
		CK(rs.n_calls + rs.n_refused == 40u && rs.n_refused > 0u);
		rq.cap = KGENOME_TEXTUAL_FORM_CAP(gn) + 40u * 400u;
		st = kgenome_textual_form(&rq, &rs);
		if (rs.n_calls != 40u) printf("calls %u refused %u status %d\n", rs.n_calls, rs.n_refused, (int)st);
		CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 40u && rs.n_refused == 0u);
		free(grow);
		free(g);
	}
	free(many);
	free(out);
}

/* the hook's own absence, KEEP_JOINS, and the other languages are not touched */
static void examples_off(void)
{
	enum kgenome_textual_status st;
	uint32_t w;
	struct kgenome_textual_form_res rs;
	const char *s = "$c = chr(65) . trim(' b ');";

	rs = run_cap(s, KGENOME_TEXTUAL_FRAGMENT, NULL, KGENOME_TEXTUAL_FORM_CAP(strlen(s)), &w, &st);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 0 && w == strlen("$c=chr(65).trim(' b ');") && !memcmp(cbuf, "$c=chr(65).trim(' b ');", w));
	rs = run_cap(s, KGENOME_TEXTUAL_FRAGMENT | KGENOME_TEXTUAL_KEEP_JOINS, ref_apply, KGENOME_TEXTUAL_FORM_CAP(strlen(s)) + 64u, &w, &st);
	CK(st == KGENOME_TEXTUAL_OK && rs.n_calls == 0 && w == strlen("$c=chr(65).trim(' b ');") && !memcmp(cbuf, "$c=chr(65).trim(' b ');", w));
	{
		static uint8_t plain[64];
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)"x = chr(65) + trim(' a ')", .n = 26, .lang = KGENOME_TEXTUAL_LANG_JS,
						       .out = cbuf, .cap = 4096, .apply = ref_apply };
		struct kgenome_textual_form_res r2, r3;

		st = kgenome_textual_form(&rq, &r2);
		rq.out = plain;
		rq.apply = NULL;
		(void)kgenome_textual_form(&rq, &r3);
		/* a language whose table has no function the form rewrites is as it was, with a hook or without */
		CK(st == KGENOME_TEXTUAL_OK && r2.n_calls == 0 && r2.n_out == r3.n_out && !memcmp(cbuf, plain, r3.n_out));
	}
	/* a table is the language's: every function of it has the arguments its row says, and the form agrees with the evaluator's reading */
	{
		struct kgenome_textual_fn f;

		CK(kgenome_textual_fn_find(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)"CHR", 3, &f) && f.op == KGENOME_TEXTUAL_DEC_CHR &&
		   f.form == KGENOME_TEXTUAL_FN_FORM_PRINTABLE);
		CK(kgenome_textual_fn_find(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)"base64_decode", 13, &f) && f.form == KGENOME_TEXTUAL_FN_FORM_NEVER);
		CK(!kgenome_textual_fn_find(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)"chr", 3, &f));
	}
}

/* ---- the decode hook and the call stage together --------------------------------------------------------------------------- */

static int up_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len, const uint8_t **out,
		     uint32_t *out_len)
{
	static uint8_t buf[256];
	uint32_t i;

	(void)user;
	(void)chain;
	(void)n_chain;
	if (len > sizeof buf)
		return 0;
	for (i = 0; i < len; i++)
		buf[i] = in[i] >= 'a' && in[i] <= 'z' ? (uint8_t)(in[i] - 32) : in[i];
	*out = buf;
	*out_len = len;
	return 1;
}

static void examples_decode(void)
{
	struct kgenome_textual_form_req rq;
	struct kgenome_textual_form_res rs;
	static const struct { const char *src, *want; } c[] = {
		/* the literal a call made is what the decoder around it reads, and the decoder's call stays, renamed */
		{ "x(base64_decode(str_replace('!', '', 'ab!c')));", "x(decoded_base64_decode('ABC'));" },
		{ "x(base64_decode('ab' . chr(99)));", "x(decoded_base64_decode('ABC'));" },
		{ "x(strrev(trim(' ab ')));", "x(decoded_strrev('AB'));" },
		/* a decoder's literal inside a call on literals is not a literal the stage can read: the call is as typed */
		{ "x(trim(base64_decode('ab')));", "x(trim(decoded_base64_decode('AB')));" },
		{ "x(str_replace('A', 'b', base64_decode('ab')));", "x(str_replace('A','b',decoded_base64_decode('AB')));" },
	};
	uint32_t i;

	for (i = 0; i < sizeof c / sizeof c[0]; i++) {
		rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)c[i].src, .n = (uint32_t)strlen(c[i].src), .lang = KGENOME_TEXTUAL_LANG_PHP,
							.flags = KGENOME_TEXTUAL_FRAGMENT, .out = cbuf, .cap = 4096, .decode = up_decode, .apply = ref_apply };
		(void)kgenome_textual_form(&rq, &rs);
		if (rs.n_out != strlen(c[i].want) || memcmp(cbuf, c[i].want, rs.n_out)) {
			cbuf[rs.n_out] = 0;
			printf("  FAIL decode and fold of  %s\n       got    %s\n       wanted %s\n", c[i].src, cbuf, c[i].want);
			fails++;
		}
	}
}

/* ---- generated ------------------------------------------------------------------------------------------------------------- */

static uint64_t rs_ = 0x2545f4914f6cdd1du;

static uint32_t rnd(void)
{
	rs_ ^= rs_ << 13;
	rs_ ^= rs_ >> 7;
	rs_ ^= rs_ << 17;
	return (uint32_t)(rs_ >> 32);
}

#define VMAX 160u
struct ex {
	char     text[1400];
	uint32_t nt;
	uint8_t  val[VMAX];
	uint32_t nv;
	uint32_t calls;         /* calls in the text */
	int      call;          /* the whole text is one call */
	int      join;          /* the whole text is a join */
};

static void tput(struct ex *e, const char *s)
{
	uint32_t l = (uint32_t)strlen(s);

	memcpy(e->text + e->nt, s, l);
	e->nt += l;
}

/* the text of another expression: its length is nt, a NUL may be in it */
static void tputx(struct ex *e, const struct ex *o)
{
	memcpy(e->text + e->nt, o->text, o->nt);
	e->nt += o->nt;
}

/* one byte, whatever it is (NUL too) */
static void tput1(struct ex *e, uint8_t c)
{
	e->text[e->nt++] = (char)c;
}

/* white space and comments between two tokens that are not a name or a number: any of them */
static void gap(struct ex *e)
{
	static const char *const g[] = { "", "", "", " ", "  ", "\n", "\t", " /* c */ ", "/**/", " // c\n", "\r\n ", " # c\n" };

	tput(e, g[rnd() % (sizeof g / sizeof g[0])]);
}

/* a byte string of the alphabet that makes a literal hard to read */
static uint32_t gen_bytes(uint8_t *b, uint32_t max)
{
	static const uint8_t alpha[] = "abcxyzABC 019.,'\\\"\n\t_-";
	uint32_t n = rnd() % (max + 1u), i;

	for (i = 0; i < n; i++)
		b[i] = rnd() % 8u ? alpha[rnd() % (sizeof alpha - 1u)] : (uint8_t)(rnd() % 3u ? 'k' : (rnd() & 0xff));
	return n;
}

/* `v` as a php literal, single or double quoted (no "$" in a double: it would interpolate) */
static void enc_lit(struct ex *e, const uint8_t *v, uint32_t n)
{
	uint32_t i;
	char t[8];

	if (rnd() % 3u == 0) {
		tput(e, "\"");
		for (i = 0; i < n; i++) {
			uint8_t c = v[i];

			if (c == '"' || c == '\\') {
				t[0] = '\\';
				t[1] = (char)c;
				t[2] = 0;
			} else if (c == '\n' && rnd() & 1u) {
				strcpy(t, "\\n");
			} else if (c == '\t' && rnd() & 1u) {
				strcpy(t, "\\t");
			} else if (c < 0x20 || c >= 0x7f || c == '$' || c == '{') {
				snprintf(t, sizeof t, "\\x%02x", c);
			} else {
				t[0] = (char)c;
				t[1] = 0;
			}
			tput(e, t);
		}
		tput(e, "\"");
	} else {
		tput(e, "'");
		for (i = 0; i < n; i++) {
			if (v[i] == '\'' || v[i] == '\\')
				tput(e, "\\");
			tput1(e, v[i]);
		}
		tput(e, "'");
	}
}

static const char *const fname[] = { "str_replace", "strtr", "substr", "strtolower", "strtoupper", "ucfirst", "lcfirst", "trim", "ltrim", "rtrim", "chr" };

/* the name as typed: any case, maybe "\" in front */
static void gen_name(struct ex *e, const char *w)
{
	char t[32];
	uint32_t i, l = (uint32_t)strlen(w), k = 0;
	uint32_t pre = rnd() % 8u;

	if (pre == 1)
		t[k++] = '\\';
	for (i = 0; i < l; i++)
		t[k++] = rnd() & 1u && w[i] >= 'a' && w[i] <= 'z' ? (char)(w[i] - 32) : w[i];
	t[k] = 0;
	tput(e, t);
}

static void gen(struct ex *e, uint32_t depth);

/* A number as a call writes it: plain, signed, or a quoted numeral. */
static void num_arg(struct ex *e, int32_t v)
{
	char t[24];

	switch (rnd() % 5u) {
	case 0:
		snprintf(t, sizeof t, "'%d'", v);
		break;
	case 1:
		snprintf(t, sizeof t, v >= 0 ? "+%d" : "%d", v);
		break;
	default:
		snprintf(t, sizeof t, "%d", v);
		break;
	}
	tput(e, t);
}

static void comma(struct ex *e)
{
	gap(e);
	tput(e, ",");
	gap(e);
}

static void open_call(struct ex *e, const char *w)
{
	gap(e);
	gen_name(e, w);
	gap(e);
	tput(e, "(");
	gap(e);
}

/* one expression of at most `depth` levels: its text appended to `e`, its value set */
static void gen(struct ex *e, uint32_t depth)
{
	uint32_t kind = depth ? rnd() % 10u : 0u;
	struct kgenome_textual_call c;
	struct ex sub[3];
	uint32_t k;
	uint8_t tmp[VMAX * 3u];
	uint32_t got;

	memset(&c, 0, sizeof c);
	e->nt = 0;
	e->nv = 0;
	e->calls = 0;
	e->call = e->join = 0;
	if (kind <= 2u) {                                      /* a literal */
		e->nv = gen_bytes(e->val, 20);
		enc_lit(e, e->val, e->nv);
		return;
	}
	if (kind == 9u) {                                      /* a join of two or three */
		uint32_t n = 2u + rnd() % 2u;

		for (k = 0; k < n; k++) {
			gen(&sub[k], depth - 1u);
			if (k) {
				gap(e);
				tput(e, ".");
				gap(e);
			}
			tputx(e, &sub[k]);
			if (e->nv + sub[k].nv > VMAX) {
				/* too long for the model: keep the first pieces */
				e->join = 1;
				return;
			}
			memcpy(e->val + e->nv, sub[k].val, sub[k].nv);
			e->nv += sub[k].nv;
			e->calls += sub[k].calls;
		}
		e->join = 1;
		return;
	}
	/* a call of the table */
	k = rnd() % (sizeof fname / sizeof fname[0]);
	open_call(e, fname[k]);
	e->calls = 1;
	e->call = 1;
	if (!strcmp(fname[k], "chr")) {
		int32_t v = (int32_t)(0x20u + rnd() % 0x5fu);

		if (rnd() % 4u == 0)
			v += 256 * (int32_t)(rnd() % 4u);
		if (rnd() % 8u == 0)
			v -= 256 * (int32_t)(1u + rnd() % 3u);
		num_arg(e, v);
		e->val[0] = (uint8_t)(v & 0xff);
		e->nv = 1;
	} else if (!strcmp(fname[k], "str_replace")) {
		uint32_t i;

		for (i = 0; i < 3u; i++)
			gen(&sub[i], depth - 1u);
		for (i = 0; i < 3u; i++) {
			if (i)
				comma(e);
			tputx(e, &sub[i]);
			e->calls += sub[i].calls;
		}
		c.op = KGENOME_TEXTUAL_DEC_REPLACE;
		c.s1 = sub[0].val;
		c.n1 = sub[0].nv;
		c.s2 = sub[1].val;
		c.n2 = sub[1].nv;
		if (!ref_apply(NULL, &c, sub[2].val, sub[2].nv, tmp, sizeof tmp, &got) || got > VMAX) {
			/* an answer this model does not hold: use the subject itself */
			e->nt = 0;
			e->calls = 0;
			e->call = 0;
			e->nv = gen_bytes(e->val, 20);
			enc_lit(e, e->val, e->nv);
			return;
		}
		memcpy(e->val, tmp, got);
		e->nv = got;
	} else if (!strcmp(fname[k], "strtr")) {
		uint8_t from[8], to[8];
		uint32_t n = 1u + rnd() % 6u, i;

		gen(&sub[0], depth - 1u);
		for (i = 0; i < n; i++) {
			from[i] = (uint8_t)("abcxk 1'\\"[rnd() % 9u]);
			to[i] = (uint8_t)("xyzabQ9\"\n"[rnd() % 9u]);
		}
		tputx(e, &sub[0]);
		e->calls += sub[0].calls;
		comma(e);
		{
			struct ex t1 = { .nt = 0 }, t2 = { .nt = 0 };

			enc_lit(&t1, from, n);
			enc_lit(&t2, to, n);
			tputx(e, &t1);
			comma(e);
			tputx(e, &t2);
		}
		c.op = KGENOME_TEXTUAL_DEC_TRANSLATE;
		c.s1 = from;
		c.n1 = n;
		c.s2 = to;
		c.n2 = n;
		(void)ref_apply(NULL, &c, sub[0].val, sub[0].nv, tmp, sizeof tmp, &got);
		memcpy(e->val, tmp, got);
		e->nv = got;
	} else if (!strcmp(fname[k], "substr")) {
		int32_t from = (int32_t)(rnd() % 17u) - 8, len = (int32_t)(rnd() % 17u) - 8;
		int with_len = (int)(rnd() & 1u);

		gen(&sub[0], depth - 1u);
		tputx(e, &sub[0]);
		e->calls += sub[0].calls;
		comma(e);
		num_arg(e, from);
		if (with_len) {
			comma(e);
			num_arg(e, len);
		}
		c.op = KGENOME_TEXTUAL_DEC_SLICE;
		c.k1 = from;
		c.k2 = len;
		c.to_end = !with_len;
		(void)ref_apply(NULL, &c, sub[0].val, sub[0].nv, tmp, sizeof tmp, &got);
		memcpy(e->val, tmp, got);
		e->nv = got;
	} else {
		static const struct { const char *n; uint32_t op; } one[] = {
			{ "strtolower", KGENOME_TEXTUAL_DEC_LOWER }, { "strtoupper", KGENOME_TEXTUAL_DEC_UPPER }, { "ucfirst", KGENOME_TEXTUAL_DEC_UCFIRST },
			{ "lcfirst", KGENOME_TEXTUAL_DEC_LCFIRST }, { "trim", KGENOME_TEXTUAL_DEC_TRIM }, { "ltrim", KGENOME_TEXTUAL_DEC_LTRIM },
			{ "rtrim", KGENOME_TEXTUAL_DEC_RTRIM } };
		uint32_t i;

		for (i = 0; one[i].n && strcmp(one[i].n, fname[k]); i++)
			;
		gen(&sub[0], depth - 1u);
		tputx(e, &sub[0]);
		e->calls += sub[0].calls;
		c.op = one[i].op;
		(void)ref_apply(NULL, &c, sub[0].val, sub[0].nv, tmp, sizeof tmp, &got);
		memcpy(e->val, tmp, got);
		e->nv = got;
	}
	gap(e);
	tput(e, ")");
}

/* the generator may have discarded a call and kept literal text: `calls` is then the text's, which is what the form must report */

/* a single quoted literal of `v`, as the form writes it */
static uint32_t want_sq(uint8_t *o, const uint8_t *v, uint32_t n)
{
	uint32_t i, w = 0;

	o[w++] = '\'';
	for (i = 0; i < n; i++) {
		if (v[i] == '\\' || v[i] == '\'')
			o[w++] = '\\';
		o[w++] = v[i];
	}
	o[w++] = '\'';
	return w;
}

struct lits {
	uint8_t  val[4096];
	uint32_t n;
	uint32_t pieces;
	int      ok;
};

static int lits_sink(void *u, const struct kgenome_textual_span *s)
{
	struct lits *l = u;

	if (s->kind == KGENOME_TEXTUAL_STRING) {
		struct kgenome_textual_value_req vq = { .lang = KGENOME_TEXTUAL_LANG_PHP, .lit = cbuf + s->off, .len = s->len, .open_len = s->open_len,
							.close_len = s->close_len, .flags = (uint8_t)s->flags, .out = l->val + l->n, .cap = s->len };
		struct kgenome_textual_value_res vr;

		if (l->n + s->len > sizeof l->val || kgenome_textual_value(&vq, &vr) != KGENOME_TEXTUAL_OK)
			l->ok = 0;
		else
			l->n += vr.n_out;
		l->pieces++;
	}
	return 1;
}

/* Runs one generated expression `$x = <e>;` (with "@" in front when `at`): the properties above. */
static uint32_t one_case(const struct ex *e, uint32_t it, int at)
{
	static char src[1700];
	static uint8_t want[1024], out[4096], again[4096];
	struct kgenome_textual_form_res rs, r2;
	enum kgenome_textual_status st;
	uint32_t n, w, w2, wn, bad = 0, k;
	uint64_t caps[5];

	memcpy(src, "<?php $x = ", 11);
	n = 11;
	if (at)
		src[n++] = '@';
	memcpy(src + n, e->text, e->nt);
	n += e->nt;
	src[n++] = ';';
	src[n] = 0;
	rs = run_cap_n(src, n, 0, ref_apply, KGENOME_TEXTUAL_FORM_CAP(n) + 8192u, &w, &st);
	memcpy(out, cbuf, w);
	if (st != KGENOME_TEXTUAL_OK) {
		printf("  FAIL status %d: %s\n", (int)st, src);
		return 1;
	}
	/* the count: every call of the text, a call that the model discarded is not in the text */
	if (rs.n_calls != e->calls) {
		printf("  FAIL %u calls for %u built: %s\n   form %.*s\n", rs.n_calls, e->calls, src, (int)w, out);
		bad = 1;
	}
	if (!e->join) {
		/* one literal or one call: exactly the literal of the value */
		char head[] = "<?php $x=@";
		uint32_t hl = (uint32_t)sizeof head - (at ? 1u : 2u);       /* "<?php $x=" and the "@" when it was typed */

		wn = want_sq(want, e->val, e->nv);
		if (!e->call) {
			/* a literal is as the form always wrote it: only that its value is the value */
		} else if (out[hl] == '\n' ? (w != hl + 1u + wn + 1u || memcmp(out + hl + 1u, want, wn))     /* a comment that ends a line is a line break */
					   : (w != hl + wn + 1u || memcmp(out + hl, want, wn)) ||
			   memcmp(out, head, hl) || out[w - 1u] != ';') {
			printf("  FAIL a call is not its literal: %s\n   form %.*s\n", src, (int)w, out);
			bad = 1;
		}
	}
	{
		/* the literals the form leaves, read in order, are the value, with a "." and nothing else between them */
		struct lits *l = calloc(1, sizeof *l);
		struct kgenome_textual_lex_req lq = { .in = out, .n = w, .lang = KGENOME_TEXTUAL_LANG_PHP, .sink = lits_sink, .user = l };
		struct kgenome_textual_lex_res lr;

		memcpy(cbuf, out, w);
		l->ok = 1;
		lq.in = cbuf;
		(void)kgenome_textual_lex(&lq, &lr);
		if (!l->ok || l->n != e->nv || memcmp(l->val, e->val, e->nv)) {
			uint32_t q;

			printf("  FAIL the literals hold another value: %s\n   form %.*s\n   form's value ", src, (int)w, out);
			for (q = 0; q < l->n; q++)
				printf("%02x", l->val[q]);
			printf("\n   model's value ");
			for (q = 0; q < e->nv; q++)
				printf("%02x", e->val[q]);
			printf("\n");
			bad = 1;
		}
		free(l);
	}
	/* the form of the form is itself */
	{
		struct kgenome_textual_form_req rq = { .in = out, .n = w, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = again,
						       .cap = KGENOME_TEXTUAL_FORM_CAP(w) + 8192u, .apply = ref_apply };

		(void)kgenome_textual_form(&rq, &r2);
		w2 = r2.n_out;
		if (w2 != w || memcmp(out, again, w) || r2.n_calls) {
			printf("  FAIL not its own form: %s\n   form  %.*s\n   again %.*s\n", src, (int)w, out, (int)w2, again);
			bad = 1;
		}
	}
	/* a tight cap: no refusal of the text, and what comes out folds to what had room */
	if (it % 3u == 0) {
		caps[0] = KGENOME_TEXTUAL_FORM_CAP(n);
		caps[1] = caps[0] + 1u;
		caps[2] = caps[0] + 9u;
		caps[3] = caps[0] + 60u;
		caps[4] = caps[0] + 400u;
		for (k = 0; k < 5u; k++) {
			uint32_t wt;

			rs = run_cap_n(src, n, 0, ref_apply, caps[k], &wt, &st);
			if (st != KGENOME_TEXTUAL_OK || wt > caps[k]) {
				printf("  FAIL cap %llu: status %d, %u bytes: %s\n", (unsigned long long)caps[k], (int)st, wt, src);
				bad = 1;
				break;
			}
			{
				struct kgenome_textual_form_req rq = { .in = cbuf, .n = wt, .lang = KGENOME_TEXTUAL_LANG_PHP, .out = again,
								       .cap = KGENOME_TEXTUAL_FORM_CAP(wt) + 8192u, .apply = ref_apply };

				(void)kgenome_textual_form(&rq, &r2);
				if (r2.n_out != w || memcmp(again, out, w)) {
					printf("  FAIL cap %llu leaves what does not fold to the roomy form: %s\n   tight %.*s\n   roomy %.*s\n",
					       (unsigned long long)caps[k], src, (int)wt, cbuf, (int)w, out);
					bad = 1;
					break;
				}
			}
		}
	}
	return bad;
}

static void generated(void)
{
	static struct ex e;
	uint32_t it, bad = 0, folded = 0, joins = 0;

	for (it = 0; it < 30000u && bad < 3u; it++) {
		gen(&e, 1u + rnd() % 3u);
		e.text[e.nt] = 0;
		if (e.nt > 1000u || e.calls == 0)
			continue;
		folded++;
		joins += (uint32_t)e.join;
		bad += one_case(&e, it, e.call && rnd() % 6u == 0);
	}
	fails += (int)bad;
	printf("  generated: %u expressions with calls, %u of them joins\n", folded, joins);
	CK(folded > 5000u && joins > 500u);
}

int main(void)
{
	examples_fold();
	every_byte_before();
	examples_page();
	examples_room();
	examples_off();
	examples_decode();
	generated();
	if (fails) {
		printf("textual_php_calls: %d failed\n", fails);
		return 1;
	}
	printf("textual_php_calls: calls on literals - examples, generated expressions, caps, the decode hook - ok\n");
	return 0;
}
