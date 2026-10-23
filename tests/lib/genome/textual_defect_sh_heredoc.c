#define _GNU_SOURCE
/*
 * genome / textual_defect_sh_heredoc - sh_lex.c heredoc_op skipped kgenome_textual_blank() between "<<" and the delimiter, and that set is space, tab, CR, VT and FF. The
 * shell's blanks are space and tab (bash: `cat <<VT EOF` waits for the line "VT EOF" - checked by running bash below), and the FORM has said so since L14: a VT or FF is a byte
 * of a word (`word_vt_ff`, textual_form.c), a CR a blank for CRLF files. So the lexer read `cat <<\vEOF` as a here-document closed by "EOF" while the shell reads one closed by
 * "\vEOF" - or never: every line after the operator was a string to the lexer and code to the shell (or the other way round), the same disagreement as L14.
 *
 * The rule is one function now, kgenome_textual_blank_in(c, word_vt_ff), asked by the form and by sh_lex.c; this test is the sweep over every byte placed between the operator
 * and the delimiter, with bash as the oracle for each byte the engine does not take on purpose (CR is a blank here, a word byte to bash: the CRLF rule of sh_lex.c's header).
 *
 * Why the old tests missed it: (b) the heredoc cases in textual_sh*.c and the L15 form cases put a space or nothing between "<<" and the word, and the L14 sweep alphabet
 * (` \t\n\v\f#;a<`) has no heredoc with a VT or FF in that place; (c) a test that compared the lexer with the form never compared either with a shell.
 *
 * usage: textual_defect_sh_heredoc
 */

#include "textual_check.h"
#include "../interp_oracle.h"

struct seen {
	uint32_t code_at_tail;    /* 1 when "echo CLOSED" is inside a CODE span */
	const uint8_t *in;
	uint32_t n;
};

static int tail_sink(void *u, const struct kgenome_textual_span *s)
{
	struct seen *z = u;
	static const char tail[] = "echo CLOSED";
	uint32_t at = z->n - 12u;      /* "echo CLOSED\n" is the last 12 bytes */

	if (s->kind == KGENOME_TEXTUAL_CODE && s->off <= at && at + (sizeof tail - 1u) <= (uint64_t)s->off + s->len)
		z->code_at_tail = 1;
	return 1;
}

/* does the lexer read the last line of `in` as code (the here-document is over) */
static int lexer_closed(const uint8_t *in, uint32_t n)
{
	struct seen z = { 0, in, n };
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = KGENOME_TEXTUAL_LANG_SH, .sink = tail_sink, .user = &z };
	struct kgenome_textual_lex_res rs;

	(void)kgenome_textual_lex(&rq, &rs);
	return (int)z.code_at_tail;
}

/* a byte the delimiter parse treats specially (a quote, a backslash, a meta character, "-", "<"), left out of the sweep: it is not about blanks */
static int special(unsigned b)
{
	return b == 0 || b == '\n' || b == '\'' || b == '"' || b == '\\' || b == '-' || b == '<' || b == ';' || b == '&' || b == '|' || b == '(' || b == ')' || b == '>';
}

int main(void)
{
	unsigned b, swept = 0, oracle = 0, bad = 0;
	static uint8_t t[64];

	/* the cases: the shell reads `<<VT EOF` as the delimiter "VT EOF", so the "EOF" line closes nothing and the last line is text */
	{
		struct { const char *what; const char *text; int closed; } C[] = {
			{ "vt before the word", "cat <<\vEOF\nx\nEOF\necho CLOSED\n", 0 },
			{ "ff before the word", "cat <<\fEOF\nx\nEOF\necho CLOSED\n", 0 },
			{ "vt, then the line that closes it", "cat <<\vEOF\nx\n\vEOF\necho CLOSED\n", 1 },
			{ "strip form, vt", "cat <<-\vEOF\nx\nEOF\necho CLOSED\n", 0 },
			{ "space then vt", "cat << \vEOF\nx\nEOF\necho CLOSED\n", 0 },
			{ "control: a space", "cat << EOF\nx\nEOF\necho CLOSED\n", 1 },
			{ "control: a tab", "cat <<\tEOF\nx\nEOF\necho CLOSED\n", 1 },
			{ "control: a crlf file's CR is a blank", "cat <<\rEOF\nx\nEOF\necho CLOSED\n", 1 },
			{ "control: no blank", "cat <<EOF\nx\nEOF\necho CLOSED\n", 1 },
		};
		unsigned k;

		for (k = 0; k < sizeof C / sizeof C[0]; k++) {
			uint32_t n = (uint32_t)strlen(C[k].text);

			if (lexer_closed((const uint8_t *)C[k].text, n) != C[k].closed) {
				printf("  FAIL %s: the lexer says the here-document is %s\n", C[k].what, C[k].closed ? "not closed" : "closed");
				fails++;
			}
		}
	}

	/* the sweep: every byte between the operator and the word. The model is the shell's, with the one deliberate exception (CR). */
	for (b = 1; b < 256u; b++) {
		uint32_t n;
		int want, got;

		if (special(b))
			continue;
		n = (uint32_t)snprintf((char *)t, sizeof t, "cat <<%cEOF\nx\nEOF\necho CLOSED\n", (int)b);
		want = b == ' ' || b == '\t' || b == '\r';
		got = lexer_closed(t, n);
		swept++;
		if (got != want) {
			printf("  FAIL sweep: byte 0x%02x between << and EOF: the lexer says %s, the shell's blanks say %s\n", b, got ? "closed" : "open", want ? "closed" : "open");
			bad++;
		}
		if (b != '\r') {   /* bash is the oracle for every byte the engine takes as the shell does */
			char scr[96], *out;

			snprintf(scr, sizeof scr, "cat <<%cEOF\nx\nEOF\necho CLOSED\n", (int)b);
			out = run_script(2, scr);
			if (out) {
				int bash_closed = strstr(out, "CLOSED") != NULL && strstr(out, "warning") == NULL;

				oracle++;
				if (bash_closed != want) {
					printf("  FAIL oracle: byte 0x%02x: bash says %s, the model says %s\n", b, bash_closed ? "closed" : "open", want ? "closed" : "open");
					bad++;
				}
				free(out);
			}
		}
	}
	if (bad)
		fails++;
	printf("textual_defect_sh_heredoc: %u bytes swept, %u run through bash (%s)%s\n", swept, oracle, oracle ? "bash present" : "bash absent: oracle skipped", fails ? " FAILED" : "");
	return fails != 0;
}
