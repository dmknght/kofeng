/*
 * kx_dlgsel - the text a selection over a recorded page (kv_dlgsel.c) hands back: dlg_copy puts it on the clipboard and enc_sel_text
 * hands it to the Decoder's Declare (KXA-9: the two walked the selection separately and disagreed). The source is included; the rest
 * of the viewer is not linked (its functions are stubs here, never reached by a selection).
 *
 * A cell is a character and a character may be several bytes: dlg_bx[row][col] is the first byte of a column. A selection over
 * "h\xc3\xa9llo" (five cells, six bytes) must come back whole.
 */
#define _GNU_SOURCE
#include "../../kofexamine/kv_dlgsel.c"

static char g_sent[256];
static size_t g_sent_n;

/* Copy goes through the terminal in the viewer; here it is recorded. */
void copy_osc52(const char *bytes, size_t n)
{
	g_sent_n = n < sizeof g_sent ? n : sizeof g_sent;
	memcpy(g_sent, bytes, g_sent_n);
}

static struct view V;
static int fails, checks;

#define CK(cond, what) do { checks++; if (!(cond)) { printf("  FAIL %s\n", what); fails++; } } while (0)

/* one recorded row of `cells` characters, `bytes` bytes, with its cell starts */
static void row(int r, const char *text, const uint16_t *starts, int cells, int nbytes)
{
	int c;

	memcpy(V.dlg_line[r], text, (size_t)nbytes);
	for (c = 0; c <= cells; c++)
		V.dlg_bx[r][c] = starts[c];
	V.dlg_cols[r] = (uint16_t)cells;
	V.dlg_src[r] = r;
}

static void select_span(int r0, int c0, int r1, int c1)
{
	V.dlg_have = 1;
	V.dlg_ar = r0; V.dlg_ac = c0;
	V.dlg_br = r1; V.dlg_bc = c1;
}

int main(void)
{
	static const uint16_t wide[] = { 0, 1, 3, 4, 5, 6 };      /* h, e-acute (2 bytes), l, l, o */
	static const uint16_t plain[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	char out[64];
	size_t n;

	V.dlg_rows = 3;
	row(0, "h\xc3\xa9llo", wide, 5, 6);
	row(1, "ab   ", plain, 5, 5);                              /* trailing blanks are layout, not text */
	row(2, "xyz", plain, 3, 3);

	/* a multi-byte character: the selection comes back byte for byte */
	select_span(0, 0, 0, 4);
	n = enc_sel_text(&V, out, sizeof out);
	CK(n == 6 && !memcmp(out, "h\xc3\xa9llo", 6) && out[6] == 0, "enc_sel_text keeps every byte of a multi-byte character");
	dlg_copy(&V);
	CK(g_sent_n == 6 && !memcmp(g_sent, "h\xc3\xa9llo", 6), "dlg_copy keeps every byte of a multi-byte character");

	/* several rows: joined by newlines, trailing blanks dropped, and the two entry points agree */
	select_span(0, 0, 2, 2);
	n = enc_sel_text(&V, out, sizeof out);
	CK(n == 6 + 1 + 2 + 1 + 3 && !memcmp(out, "h\xc3\xa9llo\nab\nxyz", n), "enc_sel_text: rows joined by newlines, trailing blanks dropped");
	dlg_copy(&V);
	CK(g_sent_n == n && !memcmp(g_sent, out, n), "dlg_copy and enc_sel_text give the same text");

	/* a leading row with nothing in it still counts as a row (a newline is its separator), in both */
	V.dlg_cols[0] = 0;
	V.dlg_bx[0][0] = 0;
	select_span(0, 0, 1, 1);
	n = enc_sel_text(&V, out, sizeof out);
	dlg_copy(&V);
	CK(g_sent_n == n && !memcmp(g_sent, out, n), "an empty first row: the same text from both");

	/* the cap: never more than cap - 1 bytes and always terminated; no span: nothing, out untouched */
	row(0, "h\xc3\xa9llo", wide, 5, 6);
	select_span(0, 0, 0, 4);
	n = enc_sel_text(&V, out, 4);
	CK(n <= 3 && out[n] == 0, "a cap of 4 holds at most 3 bytes and a NUL");
	V.dlg_have = 0;
	out[0] = 'Q';
	CK(enc_sel_text(&V, out, sizeof out) == 0 && out[0] == 'Q', "no selection: 0, nothing written");

	printf("%d check(s), %d failed\n", checks, fails);
	return fails ? 1 : 0;
}
