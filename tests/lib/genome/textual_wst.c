/*
 * genome / textual_wst - what the command readers (sh, batch, tcl) share in textual_private.h and textual.h: kgenome_textual_range_is (one spelling of "is this range the word"),
 * kgenome_textual_name_start / kof_is_word_byte (a name's bytes), kgenome_textual_blank (white space in a line), and the word reader's state with its one way to hand a literal piece
 * to a sink (kgenome_textual_wst_lit). References are written here from the sentences in the headers.
 *
 * usage: textual_wst
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <kofcore.h>
#include <textual/textual.h>
#include <textual/textual_private.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

struct got {
	int calls, refuse_at;
	uint32_t total;
	uint8_t first;
};

static int sink_lit(void *user, const uint8_t *p, uint32_t n)
{
	struct got *g = user;

	g->calls++;
	g->total += n;
	g->first = p[0];
	return g->refuse_at && g->calls >= g->refuse_at ? 0 : 1;
}

int main(void)
{
	unsigned c;
	static const uint8_t text[] = "xx set yy setx se";
	struct kgenome_textual_range r;
	struct got g = { 0, 0, 0, 0 };
	struct kgenome_textual_word_sink sk = { .user = &g, .lit = sink_lit };
	struct kgenome_textual_wst s;
	const uint8_t piece[4] = { 'a', 'b', 'c', 'd' };

	for (c = 0; c < 256; c++) {
		int letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

		CK(!!kgenome_textual_name_start((uint8_t)c) == (letter || c == '_'));
		CK(!!kgenome_textual_blank((uint8_t)c) == (c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'));
	}
	/* range_is: the exact word, not a prefix, not a longer word, not the next bytes; an empty range is no word; the empty word is only an empty range */
	r.off = 3; r.len = 3;
	CK(kgenome_textual_range_is(text, r, "set"));
	CK(!kgenome_textual_range_is(text, r, "se"));
	CK(!kgenome_textual_range_is(text, r, "setx"));
	CK(!kgenome_textual_range_is(text, r, "Set"));
	CK(!kgenome_textual_range_is(text, r, ""));
	r.off = 10; r.len = 4;
	CK(kgenome_textual_range_is(text, r, "setx"));
	CK(!kgenome_textual_range_is(text, r, "set "));
	r.off = 15; r.len = 2;
	CK(kgenome_textual_range_is(text, r, "se"));
	r.off = 0; r.len = 0;
	CK(kgenome_textual_range_is(text, r, ""));
	CK(!kgenome_textual_range_is(text, r, "x"));
	/* wst_lit: a piece goes to the sink; an empty piece does not; no sink is no call and no refusal; a refusal is remembered and stops the rest */
	memset(&s, 0, sizeof s);
	s.sk = &sk;
	s.ok = 1;
	kgenome_textual_wst_lit(&s, piece, 0);
	CK(g.calls == 0 && s.ok);
	kgenome_textual_wst_lit(&s, piece, 4);
	CK(g.calls == 1 && g.total == 4u && g.first == 'a' && s.ok);
	kgenome_textual_wst_lit(&s, piece + 2, 2);
	CK(g.calls == 2 && g.total == 6u && g.first == 'c' && s.ok);
	g.refuse_at = 3;
	kgenome_textual_wst_lit(&s, piece, 1);
	CK(g.calls == 3 && !s.ok);
	kgenome_textual_wst_lit(&s, piece, 1);          /* after a refusal the sink is not asked again */
	CK(g.calls == 3 && !s.ok);
	s.ok = 1;
	s.sk = NULL;
	kgenome_textual_wst_lit(&s, piece, 1);
	CK(g.calls == 3 && s.ok);
	printf("genome textual_wst: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
