/*
 * textual_islands - kgenome_textual_islands: where the code is in a text that mixes markup and code, as the lexer reads it.
 *
 * KNOWN ANSWERS for php and the three page languages (asp, aspx, jsp): the tags, a "?>" or "%>" that does not close (in a string, a block comment, a
 * heredoc, an interpolation), one that does (a line comment ends at it, a page's "%>" ends the island inside a string too, which is the page rule), a
 * directive and a comment of the page that are no island, a server <script> element, __halt_compiler, an island that is not closed, a fragment.
 *
 * A GENERATED CORPUS for php, checked against offsets that come from how the text was BUILT and not from the lexer: markup, then "<?php", then pieces
 * of code each of which holds a "?>" the language does not read as one (a single quoted string, a double quoted one with an interpolation, a block
 * comment, a heredoc, a nowdoc, `#[` and a line comment that ends first), then the real "?>". The expected island is [open, after the closing "?>"), and
 * the last island of some texts is left open to the end.
 */

#include "textual_check.h"

struct got {
	struct kgenome_textual_island v[16];
	unsigned n, stop_at;
};

static int take(void *u, const struct kgenome_textual_island *is)
{
	struct got *g = u;

	if (g->n < 16u)
		g->v[g->n] = *is;
	g->n++;
	return !g->stop_at || g->n < g->stop_at;
}

static enum kgenome_textual_status islands(uint32_t lang, uint32_t flags, const char *src, uint32_t n, struct got *g)
{
	struct kgenome_textual_islands_req rq = { .in = (const uint8_t *)src, .n = n, .lang = lang, .flags = flags, .sink = take, .user = g };

	memset(g, 0, sizeof *g);
	return kgenome_textual_islands(&rq);
}

/* The expected island: where it opens, the tag's own bytes, where the close begins, its own bytes, closed. */
struct want {
	uint32_t off, open_len, end_tag, close_len;
	uint8_t  closed;
};

static void known(uint32_t lang, uint32_t flags, const char *src, unsigned n_want, const struct want *w)
{
	struct got g;
	unsigned i;
	int same;

	islands(lang, flags, src, (uint32_t)strlen(src), &g);
	same = g.n == n_want;
	for (i = 0; same && i < n_want; i++)
		same = g.v[i].off == w[i].off && g.v[i].open_len == w[i].open_len && g.v[i].end_tag == w[i].end_tag &&
		       g.v[i].close_len == w[i].close_len && g.v[i].closed == w[i].closed;
	if (!same) {
		printf("  FAIL islands of  %s\n       got %u:", src, g.n);
		for (i = 0; i < g.n && i < 4u; i++)
			printf(" {%u,%u,%u,%u,%u}", g.v[i].off, g.v[i].open_len, g.v[i].end_tag, g.v[i].close_len, g.v[i].closed);
		printf("\n       wanted %u:", n_want);
		for (i = 0; i < n_want; i++)
			printf(" {%u,%u,%u,%u,%u}", w[i].off, w[i].open_len, w[i].end_tag, w[i].close_len, w[i].closed);
		printf("\n");
		fails++;
	}
}

#define PHP KGENOME_TEXTUAL_LANG_PHP

static void php_known(void)
{
	static const struct want one[] = { { 6, 5, 20, 2, 1 } }, eq[] = { { 0, 3, 7, 2, 1 } }, bare[] = { { 0, 2, 6, 2, 1 } };
	static const struct want s1[] = { { 0, 5, 14, 2, 1 } }, s2[] = { { 0, 5, 11, 2, 1 } };
	static const struct want two[] = { { 0, 5, 9, 2, 1 }, { 15, 5, 24, 2, 1 } }, open1[] = { { 0, 5, 13, 0, 0 } };
	static const struct want halt[] = { { 0, 5, 24, 0, 0 } }, frag[] = { { 0, 0, 8, 2, 1 } };

	known(PHP, 0, "<html><?php echo 1; ?>x", 1, one);                    /* the tag is "<?php", its white space is not its own */
	known(PHP, 0, "<?= $a ?>", 1, eq);
	known(PHP, 0, "<? $a ?>", 1, bare);
	known(PHP, 0, "<?xml version=\"1.0\"?>", 0, NULL);                   /* markup: no white space after "<?" */
	known(PHP, 0, "<?php?>", 0, NULL);                                   /* no white space after "<?php": not the tag, nor a short one */
	known(PHP, 0, "<?php $s = '?>'; ?>", 1, (const struct want[]){ { 0, 5, 17, 2, 1 } });
	known(PHP, 0, "<?php $s = \"?>\"; ?>", 1, (const struct want[]){ { 0, 5, 17, 2, 1 } });
	known(PHP, 0, "<?php /* ?> */ x ?>", 1, (const struct want[]){ { 0, 5, 17, 2, 1 } });
	known(PHP, 0, "<?php // c ?> x", 1, s2);                             /* a line comment ends at the "?>": php leaves the comment there */
	known(PHP, 0, "<?php # c ?> x", 1, (const struct want[]){ { 0, 5, 10, 2, 1 } });
	known(PHP, 0, "<?php $x = \"{$a['?>']}\"; ?>", 1, (const struct want[]){ { 0, 5, 25, 2, 1 } });
	known(PHP, 0, "<?php $x = <<<E\n?>\nE;\n?>", 1, (const struct want[]){ { 0, 5, 22, 2, 1 } });
	known(PHP, 0, "<?php $x = <<<'E'\n?>\nE;\n?>", 1, (const struct want[]){ { 0, 5, 24, 2, 1 } });
	known(PHP, 0, "<?php #[A] $x; ?>", 1, (const struct want[]){ { 0, 5, 15, 2, 1 } });
	known(PHP, 0, "<?php a ?>b<?php c ?>", 1 + 1u, (const struct want[]){ { 0, 5, 8, 2, 1 }, { 11, 5, 19, 2, 1 } });
	known(PHP, 0, "<?php echo 1;", 1, (const struct want[]){ { 0, 5, 13, 0, 0 } });    /* not closed: ends at the end of the text */
	known(PHP, 0, "<?php __halt_compiler(); data ?>", 1, halt);          /* what follows is data, not code: the island ends where the code did */
	known(PHP, 0, "<?php a ?>x<?php b", 2, (const struct want[]){ { 0, 5, 8, 2, 1 }, { 11, 5, 18, 0, 0 } });
	known(PHP, KGENOME_TEXTUAL_FRAGMENT, "$a = 1; ?> x", 1, frag);        /* a fragment is code from its first byte: no opening tag */
	(void)s1; (void)two; (void)open1;
	/* no tag, no island; a language with none */
	known(PHP, 0, "just markup", 0, NULL);
	known(PHP, 0, "", 0, NULL);
	known(KGENOME_TEXTUAL_LANG_SH, 0, "echo '<?php x ?>'", 0, NULL);
	known(KGENOME_TEXTUAL_LANG_PY, 0, "x = '<% a %>'", 0, NULL);
}

static void page_known(void)
{
	static const struct want a1[] = { { 0, 2, 9, 2, 1 } }, a3[] = { { 0, 3, 6, 2, 1 } }, s1[] = { { 0, 2, 8, 2, 1 } };

	for (unsigned k = 0; k < 3u; k++) {
		uint32_t lang = k == 0 ? KGENOME_TEXTUAL_LANG_ASP : k == 1 ? KGENOME_TEXTUAL_LANG_ASPX : KGENOME_TEXTUAL_LANG_JSP;

		known(lang, 0, "<% x = 1 %>", 1, a1);
		known(lang, 0, "<%= x %>", 1, a3);
		known(lang, 0, "<%@ Page Language=\"C#\" %><% x %>", 1, (const struct want[]){ { 25, 2, 30, 2, 1 } });   /* a directive is the page's, not code */
		known(lang, 0, "<% s = \"%>\" %>", 1, s1);          /* the page ends an island at the first "%>" there is, a string or not */
		known(lang, 0, "<% x", 1, (const struct want[]){ { 0, 2, 4, 0, 0 } });
		known(lang, 0, "<% a %>b<% c %>", 2, (const struct want[]){ { 0, 2, 5, 2, 1 }, { 8, 2, 13, 2, 1 } });
		known(lang, 0, "plain <b>markup</b>", 0, NULL);
	}
	/* a comment of the page is not an island (aspx and jsp) */
	known(KGENOME_TEXTUAL_LANG_ASPX, 0, "<%-- <% a %> --%><% b %>", 1, (const struct want[]){ { 17, 2, 22, 2, 1 } });
	known(KGENOME_TEXTUAL_LANG_JSP, 0, "<%-- <% a %> --%><% b %>", 1, (const struct want[]){ { 17, 2, 22, 2, 1 } });
	/* a server script element: its tag is the opening tag, "</script>" the closing one; one with no runat is the browser's */
	known(KGENOME_TEXTUAL_LANG_ASPX, 0, "<script runat=\"server\">int x;</script>", 1,
	      (const struct want[]){ { 0, 23, 29, 9, 1 } });
	known(KGENOME_TEXTUAL_LANG_ASPX, 0, "<script>client();</script>", 0, NULL);
}

static void stop_and_status(void)
{
	struct got g;
	enum kgenome_textual_status st;
	struct kgenome_textual_islands_req rq = { .lang = 9999u };

	/* the sink answers 0 after the first: one delivered, the status says so */
	st = islands(PHP, 0, "<?php a ?>x<?php b ?>y<?php c ?>", 33u > 32u ? 32u : 32u, &g);
	CK(st == KGENOME_TEXTUAL_OK && g.n == 3u);
	{
		struct kgenome_textual_islands_req r2 = { .in = (const uint8_t *)"<?php a ?>x<?php b ?>", .n = 21u, .lang = PHP, .sink = take, .user = &g };

		memset(&g, 0, sizeof g);
		g.stop_at = 1;
		st = kgenome_textual_islands(&r2);
		CK(st == KGENOME_TEXTUAL_REFUSED && g.n == 1u);
	}
	rq.in = (const uint8_t *)"x";
	rq.n = 1;
	rq.sink = take;
	rq.user = &g;
	CK(kgenome_textual_islands(&rq) == KGENOME_TEXTUAL_NO_LANG);
}

/* ---- generated php: offsets from the construction --------------------------------------------- */

static uint32_t rs = 0x2545f491u;

static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 17;
	rs ^= rs << 5;
	return rs;
}

struct buf {
	char b[2048];
	uint32_t n;
};

static void bput(struct buf *b, const char *s)
{
	uint32_t l = (uint32_t)strlen(s);

	memcpy(b->b + b->n, s, l);
	b->n += l;
}

/* A piece of php code that holds a "?>" which is not a close, or none. */
static void code_piece(struct buf *b)
{
	static const char *const p[] = {
		"$a = 1;\n", "echo $x . 'y';", "$s = 'a ?> b';", "$s = \"c ?> d\";", "/* e ?> f */", "$h = <<<EOT\nm ?> n\nEOT;\n",
		"$h = <<<'EOT'\nm ?> n\nEOT;\n", "#[Attr('?>')]\n", "$s = \"{$a['?>']} z\";", "$q = 'it\\'s ?> ok';", "foo(1, 2);", "\n\t  ",
		"$r = \"\\\"?>\";", "// a note without the tag\n", "if ($a) { $b = 'x'; }", "$h = <<<\"EOT\"\n$a ?>\nEOT;\n"
	};

	bput(b, p[rnd() % (sizeof p / sizeof p[0])]);
}

static void generated(void)
{
	unsigned it;

	for (it = 0; it < 30000u; it++) {
		static struct buf b;
		struct want w[6];
		unsigned n_isl = rnd() % 5u, i, k, pieces;
		int open_last = n_isl && rnd() % 6u == 0u;
		struct got g;
		int ok;

		b.n = 0;
		for (i = 0; i < n_isl; i++) {
			static const char *const open[] = { "<?php ", "<?php\n", "<?php\t", "<?= ", "<? ", "<?PHP " };
			static const uint32_t olen[] = { 5, 5, 5, 3, 2, 5 };
			unsigned ot = rnd() % 6u;

			bput(&b, rnd() % 2u ? "<html>\n<?x? > " : "text ? > <b> ");
			w[i].off = b.n;
			bput(&b, open[ot]);
			w[i].open_len = olen[ot];
			pieces = rnd() % 5u;
			for (k = 0; k < pieces; k++)
				code_piece(&b);
			w[i].end_tag = b.n;
			if (open_last && i + 1u == n_isl) {
				w[i].close_len = 0;
				w[i].closed = 0;
				break;
			}
			bput(&b, "?>");
			w[i].close_len = 2;
			w[i].closed = 1;
			bput(&b, rnd() % 2u ? "\n" : "tail");
		}
		/* an unclosed island runs to the end of the text, with the white space after its tag and the code */
		if (n_isl && open_last)
			w[n_isl - 1u].end_tag = b.n;
		islands(PHP, 0, b.b, b.n, &g);
		ok = g.n == n_isl;
		for (i = 0; ok && i < n_isl; i++)
			ok = g.v[i].off == w[i].off && g.v[i].open_len == w[i].open_len && g.v[i].end_tag == w[i].end_tag &&
			     g.v[i].close_len == w[i].close_len && g.v[i].closed == w[i].closed;
		if (!ok) {
			b.b[b.n] = 0;
			printf("  FAIL generated %u: %u islands, wanted %u:\n%s\n", it, g.n, n_isl, b.b);
			for (i = 0; i < n_isl; i++)
				printf("   want {%u,%u,%u,%u,%u}\n", w[i].off, w[i].open_len, w[i].end_tag, w[i].close_len, w[i].closed);
			for (i = 0; i < g.n && i < 6u; i++)
				printf("   got  {%u,%u,%u,%u,%u}\n", g.v[i].off, g.v[i].open_len, g.v[i].end_tag, g.v[i].close_len, g.v[i].closed);
			fails++;
			return;
		}
	}
}

int main(void)
{
	php_known();
	page_known();
	stop_and_status();
	generated();
	printf("textual islands: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
