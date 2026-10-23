/*
 * genome / textual_defect_cmd_progress - L2 and L9 of the lexer audit: the COMMAND reader (kgenome_textual_cmd_read) of the shell and of tcl.
 *
 * L2. A word whose quote, brace or group does not close made the reader return `end == from` with no words. The engine's loop (diag_text_cmdval.c collect, and its
 * three siblings) then steps one byte and reads again, and every one of those reads walks to the end of the text looking for the closer: quadratic, over 20 s at
 * 100-300 KB, times 16 for each doubling. The contract asserted here is the loop's own, and it is a STEP count, not a time: a call with from < limit always advances
 * (from < end <= limit), and a text of unclosed openers is read in a bounded number of calls however long it is - the unclosed word runs to the end of the text, as the
 * shell and tcl read it, and the command says so (`open`).
 *
 * L9. tcl: a comment that ends in a backslash stepped over the byte after it and answered `end` one past the limit, so the caller's next read started past the text.
 *
 * Why the old tests missed them: (b) textual_cmd.c reads every PREFIX of its cases (a guard at the cut) but only checks that no event lies past the cut - not that the
 * reader MOVED, and not how many calls a text takes; a quote that does not close was only ever the last byte of a short case. L9: (a) a comment whose last byte is a
 * backslash is in no case at all.
 *
 * usage: textual_defect_cmd_progress
 */

#include "textual_check.h"

/* The engine's loop: read commands from 0 to the end the way collect() does (pos = end > pos ? end : pos + 1), counting the calls and the calls that did not move. */
static void drive(uint32_t lang, const uint8_t *in, uint32_t n, uint32_t *calls_out, uint32_t *stuck_out, uint32_t *wild_out)
{
	struct kgenome_textual_cmd c;
	uint32_t pos = 0, calls = 0, stuck = 0, wild = 0;

	memset(&c, 0, sizeof c);
	while (pos < n && kgenome_textual_cmd_read(lang, in, pos, n, &c)) {
		uint32_t k;

		calls++;
		if (c.end > n)
			wild++;
		if (c.end <= pos)
			stuck++;
		for (k = 0; k < c.n && k < KGENOME_TEXTUAL_CMD_WORDS; k++)
			if (c.w[k].off < pos || (uint64_t)c.w[k].off + c.w[k].len > (c.end > n ? n : c.end))
				wild++;
		pos = c.end > pos ? c.end : pos + 1u;
		if (calls > n + 8u)
			break;
	}
	*calls_out = calls;
	*stuck_out = stuck;
	*wild_out = wild;
}

static void show(const uint8_t *b, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n && i < 24u; i++)
		printf(b[i] >= 0x20 && b[i] < 0x7f && b[i] != '\\' ? "%c" : "\\x%02x", b[i]);
}

/* `unit` written `rep` times: an unclosed opener over and over. The old reader made `rep` calls, each walking to the end. */
static void unclosed_run(uint32_t lang, const char *name, const char *unit, uint32_t rep)
{
	size_t u = strlen(unit);
	uint32_t n = (uint32_t)(u * rep), i, calls, stuck, wild;
	uint8_t *b = malloc(n);

	if (!b)
		abort();
	for (i = 0; i < rep; i++)
		memcpy(b + u * i, unit, u);
	drive(lang, b, n, &calls, &stuck, &wild);
	if (calls > 16u || stuck || wild) {
		printf("  FAIL %s: `%s` x %u: %u calls (bound 16), %u that did not move, %u outside the text\n", name, unit, rep, calls, stuck, wild);
		fails++;
	}
	free(b);
}

/* Every text of the alphabet up to `len` bytes, read from every start: the reader moves, stays inside the text and keeps its words inside the command. */
static void exhaustive(uint32_t lang, const char *name, const char *alpha, uint32_t len)
{
	uint32_t na = (uint32_t)strlen(alpha), l, k, idx[8], shown = 0;
	uint8_t b[8];
	uint64_t cases = 0, bad = 0;

	for (l = 1; l <= len; l++) {
		for (k = 0; k < l; k++)
			idx[k] = 0;
		for (;;) {
			uint32_t from;

			for (k = 0; k < l; k++)
				b[k] = (uint8_t)alpha[idx[k]];
			for (from = 0; from < l; from++) {
				struct kgenome_textual_cmd c;

				memset(&c, 0, sizeof c);
				cases++;
				if (!kgenome_textual_cmd_read(lang, b, from, l, &c) || c.end <= from || c.end > l) {
					bad++;
					if (shown < 3u) {
						printf("  FAIL %s: [", name);
						show(b, l);
						printf("] from %u: end %u (text %u bytes)\n", from, c.end, l);
						shown++;
					}
					break;
				}
			}
			for (k = 0; k < l && ++idx[k] == na; k++)
				idx[k] = 0;
			if (k == l)
				break;
		}
	}
	if (bad) {
		printf("  FAIL %s: %llu of %llu reads did not advance inside the text\n", name, (unsigned long long)bad, (unsigned long long)cases);
		fails++;
	}
}

int main(void)
{
	static const char *const sh_unclosed[] = { "\"", "'", "$(", "${", "`", "\"$(", "$(\"", "\"${", "$('", "echo \"", "x=\"" };
	static const char *const tcl_unclosed[] = { "{", "[", "\"", "\"[", "[{", "set a \"", "puts {", "a [b " };
	static const char *const bat_unclosed[] = { "\"", "echo \"", "set \"x=" };
	uint32_t k;

	for (k = 0; k < sizeof sh_unclosed / sizeof sh_unclosed[0]; k++) {
		unclosed_run(KGENOME_TEXTUAL_LANG_SH, "sh", sh_unclosed[k], 4000);
		unclosed_run(KGENOME_TEXTUAL_LANG_SH, "sh x20", sh_unclosed[k], 20000);
	}
	for (k = 0; k < sizeof tcl_unclosed / sizeof tcl_unclosed[0]; k++)
		unclosed_run(KGENOME_TEXTUAL_LANG_TCL, "tcl", tcl_unclosed[k], 4000);
	for (k = 0; k < sizeof bat_unclosed / sizeof bat_unclosed[0]; k++)
		unclosed_run(KGENOME_TEXTUAL_LANG_BAT, "bat", bat_unclosed[k], 4000);

	exhaustive(KGENOME_TEXTUAL_LANG_SH, "sh", "a \"'$(){}`\\\n;<#", 5);
	exhaustive(KGENOME_TEXTUAL_LANG_TCL, "tcl", "a \"{}[]$\\\n;#", 5);
	exhaustive(KGENOME_TEXTUAL_LANG_BAT, "bat", "a \"^%&|<>(\n:@r", 5);

	/* an unclosed word is REPORTED: `open`, and the command runs to the end of the text; a closed one is not */
	{
		static const struct { uint32_t lang; const char *text; int open; } o[] = {
			{ KGENOME_TEXTUAL_LANG_SH, "echo \"abc", 1 }, { KGENOME_TEXTUAL_LANG_SH, "echo 'abc", 1 }, { KGENOME_TEXTUAL_LANG_SH, "echo $(id", 1 },
			{ KGENOME_TEXTUAL_LANG_SH, "echo ${x", 1 }, { KGENOME_TEXTUAL_LANG_SH, "cat < \"x", 1 }, { KGENOME_TEXTUAL_LANG_SH, "echo \"abc\" 'd'; id", 0 },
			{ KGENOME_TEXTUAL_LANG_TCL, "puts {abc", 1 }, { KGENOME_TEXTUAL_LANG_TCL, "puts [abc", 1 }, { KGENOME_TEXTUAL_LANG_TCL, "puts \"abc", 1 },
			{ KGENOME_TEXTUAL_LANG_TCL, "puts {abc}; id", 0 },
		};
		uint32_t i;

		for (i = 0; i < sizeof o / sizeof o[0]; i++) {
			struct kgenome_textual_cmd c;
			uint32_t n = (uint32_t)strlen(o[i].text);

			memset(&c, 0, sizeof c);
			CK(kgenome_textual_cmd_read(o[i].lang, (const uint8_t *)o[i].text, 0, n, &c) == 1);
			if (c.open != o[i].open || (o[i].open && c.end != n) || (!o[i].open && c.end >= n)) {
				printf("  FAIL [%s]: open %u (want %d), end %u of %u\n", o[i].text, c.open, o[i].open, c.end, n);
				fails++;
			}
		}
	}
	/* a command with more words than the record holds says `many`, and the words it has are the first ones: 31, 32, 33 and 40 words */
	{
		uint32_t nw, w;

		for (nw = 31; nw <= 40u; nw += (nw < 33u ? 1u : 7u)) {
			uint8_t text[256];
			uint32_t n = 0;
			struct kgenome_textual_cmd c;

			for (w = 0; w < nw; w++) {
				text[n++] = 'a';
				text[n++] = ' ';
			}
			memset(&c, 0, sizeof c);
			CK(kgenome_textual_cmd_read(KGENOME_TEXTUAL_LANG_SH, text, 0, n, &c) == 1);
			CK(c.n == (nw < KGENOME_TEXTUAL_CMD_WORDS ? nw : KGENOME_TEXTUAL_CMD_WORDS));
			CK(c.many == (nw > KGENOME_TEXTUAL_CMD_WORDS));
			CK(c.end == n && !c.open);
		}
	}
	/* L9: the comment that ends in a backslash. The repro is two bytes. */
	{
		static const char *const t[] = { "#\\", "# a \\", "#\\\\\\", "a;#\\", "\n#\\" };
		uint32_t i;

		for (i = 0; i < sizeof t / sizeof t[0]; i++) {
			struct kgenome_textual_cmd c;
			uint32_t n = (uint32_t)strlen(t[i]), from;

			for (from = 0; from < n; from++) {
				memset(&c, 0, sizeof c);
				kgenome_textual_cmd_read(KGENOME_TEXTUAL_LANG_TCL, (const uint8_t *)t[i], from, n, &c);
				if (c.end > n) {
					printf("  FAIL tcl L9: [%s] from %u: end %u past the text (%u bytes)\n", t[i], from, c.end, n);
					fails++;
				}
			}
		}
	}
	if (fails)
		printf("textual_defect_cmd_progress: %d FAILED\n", fails);
	else
		printf("textual_defect_cmd_progress: ok\n");
	return fails != 0;
}
