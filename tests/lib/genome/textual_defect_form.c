/*
 * genome / textual_defect_form - L14, L15, L16 of the lexer audit and the non-idempotent forms they and their neighbours make. The form of a form is itself
 * (textual_check.h form_property_for says so on random text, and found none): these are the ones it could not find, because they need a particular byte or a
 * particular line, and each is a case where the form changed what the text SAYS, which is the worse half of what the audit reported.
 *
 *   L14  sh: a vertical tab and a form feed are WORD bytes in the shell (only space, tab, newline end a word), and the form took them for blanks: `echo a<VT># b; id`
 *        became `echo a # b; id`, the word `a<VT>#` a word and a comment, `id` turned into text; a line that begins with VT then "#" became a comment. Asserted by the
 *        cases, and by a SWEEP over the shell's alphabet (every text of up to 6 bytes of ` \t\n\v\f#;a<`): the code, string and heredoc bytes of the form are those of the
 *        text, white space apart, and the form of the form is the form.
 *   L15  sh: the line break after a heredoc whose closing line ends in a CR (CRLF files) was written as "\r": `EOF\r\r` + `id`, so the terminator line was "EOF\r\rid".
 *        The shell reads a CR as a blank and only "\n" as a line break; the byte the form writes after a literal that ends in a CR is "\r" only for the languages where a
 *        lone CR is a line break (python, vbscript).
 *   L16  perl: `print FH (...)` is printed to the handle FH, `print FH(...)` calls the function FH (perl -MO=Deparse says so: "print FH 1" and "print FH(1)"). The form closed
 *        the blank up. It keeps it after print, printf and say and a BAREWORD (`$fh (` and `$fh(` are the same to perl).
 *   hashbang  js, lua, ruby, powershell: "#!" at byte 0 is a line the lexer reads as the interpreter's, and the form can put "#!" at byte 0 that was not there - by dropping
 *        the blank in front of it (` #!x` -> `#!x`), or the blank between the two bytes in lua (`# !`, a length operator and a "!" ) - so the second pass reads a comment where
 *        the first read code. A "#!" that the form writes at the start of its output is kept apart from the start by one blank, which is the same rule in the next pass.
 *
 * Why the old tests missed them: (b) form_property_for runs random bytes from an alphabet WITHOUT a vertical tab, a form feed or a CR next to a heredoc terminator, and
 * 160 bytes at most, so a pair of bytes that matters (VT then "#") is a one in a million draw; and (c) the form cases compare strings the author typed with the
 * ordinary blanks. The audit's fuzz found 190 of about 5 million forms by luck; the sweeps below find them in a second because they do not draw, they list.
 *
 * usage: textual_defect_form
 */

#include "textual_check.h"

/* KGENOME_TEXTUAL_FORM_CAP is 64 bits wide; the buffers of this test are small */
#define CAP32(n) ((uint32_t)KGENOME_TEXTUAL_FORM_CAP(n))

static void showbytes(const uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		printf(p[i] >= 0x20 && p[i] < 0x7f && p[i] != '\\' ? "%c" : "\\x%02x", p[i]);
}

static uint32_t form_bytes(uint32_t lang, const uint8_t *in, uint32_t n, uint8_t *out, uint32_t cap)
{
	struct kgenome_textual_form_req rq = { .in = in, .n = n, .lang = lang, .out = out, .cap = cap };
	struct kgenome_textual_form_res rs;
	enum kgenome_textual_status st = kgenome_textual_form(&rq, &rs);

	return st == KGENOME_TEXTUAL_OK || st == KGENOME_TEXTUAL_OPEN ? rs.n_out : 0xffffffffu;
}

/* `src` (escapes: \v \f \r \n \t \0 not used) -> the form must be exactly `want`, and the form of that is itself */
static void form_is(uint32_t lang, const char *what, const uint8_t *in, uint32_t n, const uint8_t *want, uint32_t wn)
{
	static uint8_t o1[4096], o2[4096];
	uint32_t n1 = form_bytes(lang, in, n, o1, sizeof o1), n2;

	if (n1 != wn || memcmp(o1, want, wn)) {
		printf("  FAIL %s: form of [", what);
		showbytes(in, n);
		printf("] is [");
		showbytes(o1, n1 == 0xffffffffu ? 0 : n1);
		printf("], wanted [");
		showbytes(want, wn);
		printf("]\n");
		fails++;
		return;
	}
	n2 = form_bytes(lang, o1, n1, o2, sizeof o2);
	if (n2 != n1 || memcmp(o1, o2, n1)) {
		printf("  FAIL %s: the form of [", what);
		showbytes(o1, n1);
		printf("] is not itself\n");
		fails++;
	}
}

#define FORM_IS(lang, what, src, want) form_is(lang, what, (const uint8_t *)(src), (uint32_t)sizeof(src) - 1u, (const uint8_t *)(want), (uint32_t)sizeof(want) - 1u)

/* the bytes of `in` that are not white space to the shell: a space, a tab, a CR and a line break are; a vertical tab and a form feed are bytes of a word */
static uint32_t kept_bytes(const uint8_t *in, uint32_t n, uint8_t *out)
{
	uint32_t w = 0, i;

	for (i = 0; i < n; i++) {
		uint8_t c = in[i];

		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			continue;
		out[w++] = c;
	}
	return w;
}

/* every text of the alphabet up to `len` bytes: the form of the form is the form, and (`keep`) the form keeps every byte of the text that is not a space, a tab or a line break */
static void sweep(uint32_t lang, const char *name, const char *alpha, uint32_t len, int keep)
{
	uint32_t na = (uint32_t)strlen(alpha), l, k, idx[10], shown = 0;
	uint8_t b[10], o1[200], o2[200], k1[200], k2[200];
	uint64_t cases = 0, bad = 0;

	for (l = 1; l <= len; l++) {
		for (k = 0; k < l; k++)
			idx[k] = 0;
		for (;;) {
			uint32_t n1, n2;
			int ok = 1;

			for (k = 0; k < l; k++)
				b[k] = (uint8_t)alpha[idx[k]];
			n1 = form_bytes(lang, b, l, o1, CAP32(l));
			n2 = n1 == 0xffffffffu ? 0xffffffffu : form_bytes(lang, o1, n1, o2, CAP32(n1));
			cases++;
			if (n1 == 0xffffffffu || n2 != n1 || memcmp(o1, o2, n1))
				ok = 0;
			if (ok && keep) {
				uint32_t a = kept_bytes(b, l, k1), c = kept_bytes(o1, n1, k2), j, kk = 0;

				/* a comment is dropped by the form: only the texts with no comment character can be compared whole */
				for (j = 0; j < l; j++)
					kk += b[j] == '#';
				if (!kk && (a != c || memcmp(k1, k2, a)))
					ok = 0;
			}
			if (!ok) {
				bad++;
				if (shown < 4u) {
					printf("  FAIL %s sweep: [", name);
					showbytes(b, l);
					printf("] -> [");
					showbytes(o1, n1 == 0xffffffffu ? 0 : n1);
					printf("] -> [");
					showbytes(o2, n2 == 0xffffffffu ? 0 : n2);
					printf("]\n");
					shown++;
				}
			}
			for (k = 0; k < l && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == l)
				break;
		}
	}
	if (bad) {
		printf("  FAIL %s sweep: %llu of %llu texts\n", name, (unsigned long long)bad, (unsigned long long)cases);
		fails++;
	}
}

int main(void)
{
	/* L14 */
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 vt before #", "echo a\v# b; id\n", "echo a\v# b; id");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 ff before #", "echo a\f# b; id\n", "echo a\f# b; id");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 line begins vt #", "\v# x\nid\n", "\v# x\nid");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 ff only word", "echo \f\n", "echo \f");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 blanks around a vt word", "echo  \t a\v  b  ;\n", "echo a\v b ;");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L14 control: a real comment goes", "echo a # b\nid\n", "echo a\nid");
	/* L15 */
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L15 crlf heredoc", "cat <<EOF\r\nx\r\nEOF\r\nid\r\n", "cat <<EOF\nx\r\nEOF\r\nid");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L15 crlf heredoc strip", "cat <<-EOF\r\n\tx\r\n\tEOF\r\nid\r\n", "cat <<-EOF\n\tx\r\n\tEOF\r\nid");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L15 crlf heredoc quoted", "cat <<'EOF'\r\n$x\r\nEOF\r\nid\r\n", "cat <<'EOF'\n$x\r\nEOF\r\nid");
	FORM_IS(KGENOME_TEXTUAL_LANG_SH, "L15 two heredocs", "cat <<A <<B\r\na\r\nA\r\nb\r\nB\r\nid\r\n", "cat <<A <<B\na\r\nA\r\nb\r\nB\r\nid");
	/* L16 */
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 print FH (", "print FH (1);\n", "print FH (1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 blanks", "print  FH   (  1  )  ;\n", "print FH (1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 STDERR", "print STDERR (\"a\");\n", "print STDERR (\"a\");");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 printf", "printf FH (\"%s\", 1);\n", "printf FH (\"%s\", 1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 say", "say FH (1);\n", "say FH (1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 after =", "$x = print FH (1);\n", "$x=print FH (1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 control: the call keeps no blank", "print FH(1);\n", "print FH(1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 control: $fh and ( are one to perl", "print $fh (1);\n", "print $fh(1);");
	FORM_IS(KGENOME_TEXTUAL_LANG_PERL, "L16 control: if (", "if (1) { foo (1); }\n", "if(1){foo(1);}");
	/* hashbang */
	FORM_IS(KGENOME_TEXTUAL_LANG_JS, "hashbang js blank", " #!'\n", " #!'\n");
	FORM_IS(KGENOME_TEXTUAL_LANG_LUA, "hashbang lua gap", "# !\n", " #!");
	FORM_IS(KGENOME_TEXTUAL_LANG_LUA, "hashbang lua blank", " #!'\n", " #!'\n");
	FORM_IS(KGENOME_TEXTUAL_LANG_RUBY, "hashbang ruby cr", "#!\r\r\n<", "#!\n<");
	FORM_IS(KGENOME_TEXTUAL_LANG_PSH, "hashbang psh cr", "#!\r\"\n", "#!\n\"\n");

	sweep(KGENOME_TEXTUAL_LANG_SH, "sh", " \t\n\v\f#;a<", 6, 1);
	sweep(KGENOME_TEXTUAL_LANG_SH, "sh heredoc", "<EO\n\r\v F", 6, 0);
	sweep(KGENOME_TEXTUAL_LANG_JS, "js", "a \n\r\v#!'\"", 6, 0);
	sweep(KGENOME_TEXTUAL_LANG_LUA, "lua", "a \n\r\v#!-\"", 6, 0);
	sweep(KGENOME_TEXTUAL_LANG_RUBY, "ruby", "#!\r\n<a", 7, 0);
	sweep(KGENOME_TEXTUAL_LANG_PSH, "psh", "#!\r\n\"a", 7, 0);
	sweep(KGENOME_TEXTUAL_LANG_JSP, "jsp", "<%\"\r\v\n a", 6, 0);
	printf(fails ? "textual_defect_form: %d FAILED\n" : "textual_defect_form: ok\n", fails);
	return fails != 0;
}
