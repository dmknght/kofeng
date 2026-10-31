/*
 * diag_text_vb_cont - where a vb statement ends in the graph row is where the LEXER says it does (REV-D4).
 *
 * The lexer decides a line continuation once, kgenome_textual_vb_cont: a "_" that is a whole word and the last thing on its line. The graph row
 * decided it again with a byte test (a one-byte token "_" before the break), so `a = b _ 'note` - where the lexer says "no continuation" (a comment
 * follows) - kept the statement open and the next line was read as part of it. One decision now.
 *
 * Old tests missed it: (b) no vbs text put a comment after a "_", and the continuation tests (textual_vbs.c) read the lexer's spans, not the graph.
 */
#include "diag_text_testlib.h"

static void sig_of(const struct kgenome_diag_scan *s, char *out, size_t cap)
{
	uint32_t i, k;
	size_t n = 0;

	out[0] = 0;
	for (i = 0; s && i < kgenome_diag_scan_count(s) && n + 80u < cap; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		n += (size_t)snprintf(out + n, cap - n, "%u:%u[", i, (unsigned)h->cap);
		for (k = 0; k < h->n_in; k++)
			n += (size_t)snprintf(out + n, cap - n, "%u/%u/%u ", (unsigned)h->in[k].from, (unsigned)h->in[k].role, (unsigned)h->in[k].kind);
		n += (size_t)snprintf(out + n, cap - n, "]");
	}
}

static void graph(const char *text, char *out, size_t cap)
{
	struct kgenome_diag_scan *s = scan_l(KGENOME_TEXTUAL_LANG_VBS, text);

	sig_of(s, out, cap);
	kgenome_diag_scan_free(s);
}

int main(void)
{
	char a[512], b[512];

	(void)rname;               /* shared helper of diag_text_testlib.h, not needed here */
	/* `Execute Request("x")` then a second Execute on the next line: the graph is two statements. */
	static const char plain[] = "Execute Request(\"x\")\r\nExecute a\r\n";
	static const char note[] = "Execute Request(\"x\") _ 'c\r\nExecute a\r\n";       /* "_" before a comment: the lexer says no continuation */
	static const char note2[] = "Execute _'c_b\r\nExecute a\n";
	static const char cont[] = "Execute Request(\"x\") _\r\n + \"\"\r\nExecute a\r\n";

	graph(plain, a, sizeof a);
	graph(note, b, sizeof b);
	CK(a[0] != 0, "the plain program makes nodes");
	CK(strcmp(a, b) == 0, "a '_' before a comment kept the statement open: [%s] against [%s]", b, a);
	{
		struct kgenome_diag_scan *s = scan_l(KGENOME_TEXTUAL_LANG_VBS, note2);

		/* the first Execute has no argument: the second one is the next statement, not its argument */
		CK(s && kgenome_diag_scan_count(s) == 2u && kgenome_diag_scan_at(s, 0)->n_in == 0u, "the next line was read as the argument of the first Execute");
		kgenome_diag_scan_free(s);
	}
	/* a real continuation still joins the next line */
	graph(cont, b, sizeof b);
	CK(b[0] != 0, "a real continuation still scans");
	if (fails) {
		printf("diag_text_vb_cont: %d failure(s)\n", fails);
		return 1;
	}
	printf("diag_text_vb_cont: ok\n");
	return 0;
}
