/*
 * diag_text_langs - the TEXT route for the languages that write a call as `name(args)`: javascript, python, perl, ruby, lua, java (jsp) and c#/vb.net
 * (aspx), each read through its PROFILE ROW (libgenome/phenotype/diag_text_lang_<name>.c) by the one walk that reads php.
 *
 * What is pinned is the graph and nothing about a verdict, as in diag_text.c: for each text, WHICH of these facts hold between its nodes -
 * a request that reaches a command / an eval, a decode that reaches an eval / a created function, a request that names the callee (data-call) or
 * the class (data-load), an eval whose name the program built - and, as much, which do NOT. Each row says its facts as a mask and the whole mask
 * is compared, so a fact that appears where the row does not list it fails as surely as one that is missing. The texts are written the way the
 * language is written (and one in every few the way a minifier or a person in a hurry writes it), one behaviour each.
 *
 * Also pinned: the one list of languages the route serves and the target each reads; that the row's `fold` is the table's; that a name that does
 * not fit the lookup buffer is refused and not cut; and that a language with no row has no nodes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>
#include <phenotype/diag_text_private.h>
#include <celllysis/nucleo.h>
#include <textual/textual.h>

#include "diag_text_graph.h"
#include "diag_text_testlib.h"

enum {
	F_REQ_EXEC = 1u << 0,   /* a request value reaches a command */
	F_REQ_EVAL = 1u << 1,   /* ... reaches an eval */
	F_DEC_EVAL = 1u << 2,   /* a decode's result reaches an eval */
	F_REQ_CALL = 1u << 3,   /* the request is the TARGET of a call by a value (data-call) */
	F_DEC_CREATE = 1u << 4, /* a decode's result reaches the text that becomes a function */
	F_REQ_LOAD = 1u << 5,   /* a request reaches the name of a class or module that is loaded */
	F_BUILT_EVAL = 1u << 6, /* an eval whose name the program built */
	F_ANY_EVAL = 1u << 7,   /* there is an eval node at all */
	F_REQ_DEC = 1u << 8,    /* a request reaches a decoder */
	F_REQ_FILE = 1u << 9,   /* a request reaches the delete of a file */
	F_BUILT_EXEC = 1u << 10,/* a command whose name the program built */
	F_CREATE_CALL = 1u << 11 /* the function made out of text is called (through a variable, or at once) */
};

struct row {
	uint32_t    lang;
	const char *src;
	unsigned    want;
};

static unsigned facts(const struct kgenome_diag_scan *s)
{
	unsigned f = 0;

	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) ? F_REQ_EXEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_EVAL, 0xff) ? F_REQ_EVAL : 0u;
	f |= linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EVAL, 0xff) ? F_DEC_EVAL : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET) ? F_REQ_CALL : 0u;
	f |= linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_CREATE, 0xff) ? F_DEC_CREATE : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNLOAD, 0xff) ? F_REQ_LOAD : 0u;
	f |= built_node(s, KGENOME_NUCLEO_EVAL) ? F_BUILT_EVAL : 0u;
	f |= count(s, KGENOME_NUCLEO_EVAL) ? F_ANY_EVAL : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DECODE, 0xff) ? F_REQ_DEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_FILE_DELETE, 0xff) ? F_REQ_FILE : 0u;
	f |= built_node(s, KGENOME_NUCLEO_EXEC_IMAGE) ? F_BUILT_EXEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_CREATE, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET) ? F_CREATE_CALL : 0u;
	return f;
}

#define PY KGENOME_TEXTUAL_LANG_PY
#define JS KGENOME_TEXTUAL_LANG_JS
#define PL KGENOME_TEXTUAL_LANG_PERL
#define RB KGENOME_TEXTUAL_LANG_RUBY
#define LU KGENOME_TEXTUAL_LANG_LUA
#define JSP KGENOME_TEXTUAL_LANG_JSP
#define AX KGENOME_TEXTUAL_LANG_ASPX

static const struct row rows[] = {
	/* ================= python: indentation is the block, the line break the statement ================= */
	{ PY, "import os\nfrom flask import request\ncmd = request.args.get('c')\nos.system(cmd)\n", F_REQ_EXEC },
	/* a name in a function written inside a function that declared it `global`: the alias is the OUTER scope's, not the inner one's, so the lookup climbs past it to the top level (alias_find, diag_text_vars.c: declared() asks for an alias to ITSELF) */
	{ PY, "import os\nx = request.args['a']\ndef outer():\n    global x\n    def inner():\n        os.system(x)\n    inner()\n", F_REQ_EXEC },
	{ PY, "x = base64.b64decode(request.form['p'])\nexec(x)\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ PY, "eval(request.args['code'])\n", F_REQ_EVAL | F_ANY_EVAL },
	/* the request names the callee: a variable called, and the globals indexed by it */
	{ PY, "f = request.args.get('f')\nf(1)\n", F_REQ_CALL },
	{ PY, "n = request.form['m']\nglobals()[n](1)\n", F_REQ_CALL },
	/* a name the program built, handed to the globals: an eval it does not write */
	{ PY, "n = 'ev' + 'al'\nglobals()[n](x)\n", F_BUILT_EVAL | F_ANY_EVAL },
	{ PY, "n = 'ev' 'al'\nglobals()[n](x)\n", F_BUILT_EVAL | F_ANY_EVAL },
	/* the module an import names by a literal is the module: __import__('os').system is os.system */
	{ PY, "__import__('os').system(request.args['c'])\n", F_REQ_EXEC },
	{ PY, "m = __import__(request.args['m'])\nn = __import__('os')\n", F_REQ_LOAD },
	{ PY, "import importlib\nimportlib.import_module(request.args['m'])\n", F_REQ_LOAD },
	{ PY, "import subprocess\nsubprocess.call(request.args['c'], shell=True)\n", F_REQ_EXEC },
	/* a keyword argument is not an assignment: the request reaches the call through it */
	{ PY, "import subprocess\nsubprocess.Popen(shell=True, args=request.args['c'])\n", F_REQ_EXEC },
	{ PY, "os.system(\n    request.args['c']\n)\n", F_REQ_EXEC },
	{ PY, "os.system(request.args['c'] + \\\n  ' -l')\n", F_REQ_EXEC },
	{ PY, "s = socket.socket()\ns.connect((request.args['h'], 80))\n", 0 },
	/* NOT: a name only mentioned, a value that never reached the call, two functions that share a variable name */
	{ PY, "# os.system(request.args['c'])\nprint(\"os.system(request.args['c'])\")\n", 0 },
	{ PY, "cmd = request.args.get('c')\nos.system('ls')\n", 0 },
	{ PY, "def a():\n    cmd = request.args.get('c')\n    return len(cmd)\n\ndef b():\n    cmd = 'ls'\n    os.system(cmd)\n", 0 },
	{ PY, "cmd = request.args.get('c')\nn = len(cmd)\nos.system(str(n))\n", 0 },
	{ PY, "f = lambda s: s\nx = base64.b64decode(y)\nz = f(x)\nprint(z)\n", 0 },
	/* a decode in one statement and an eval of something else in the next: the line break ends the first */
	{ PY, "d = base64.b64decode(blob)\neval(code)\n", F_ANY_EVAL },
	{ PY, "import os\nos.system(cmd)\nprint(request.args.get('c'))\n", 0 },

	/* ================= javascript: node, the browser; the automatic semicolon; closures ================= */
	{ JS, "const cp = require('child_process');\napp.get('/x', function (req, res) {\n  var cmd = req.query.c\n  cp.exec(cmd)\n})\n", F_REQ_EXEC },
	{ JS, "require('child_process').execSync(req.body.cmd);\n", F_REQ_EXEC },
	{ JS, "var child_process = require('child_process')\nchild_process.exec(req.query.c)\n", F_REQ_EXEC },
	{ JS, "eval(req.query.code);\n", F_REQ_EVAL | F_ANY_EVAL },
	{ JS, "var d = atob(req.body.p)\neval(d)\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ JS, "eval(unescape(x));\n", F_DEC_EVAL | F_ANY_EVAL },
	/* text made a function and called: at once, through a variable, and not called */
	{ JS, "new Function(atob(x))();\n", F_DEC_CREATE | F_CREATE_CALL },
	{ JS, "var f = new Function(atob(x));\nf();\n", F_DEC_CREATE | F_CREATE_CALL },
	{ JS, "var f = new Function(atob(x));\nconsole.log(f);\n", F_DEC_CREATE },
	/* a module named by the request: the row no program can write; one named by a literal is no node */
	{ JS, "require(req.query.m);\nrequire('fs');\n", F_REQ_LOAD },
	{ JS, "var m = 'child_' + 'process';\nrequire('fs');\nrequire(m);\n", 0 },
	{ JS, "var f = req.query.f\nwindow[f](1)\n", F_REQ_CALL },
	{ JS, "var f = req.query.f;\nf(1);\n", F_REQ_CALL },
	{ JS, "window[req.query.f](1);\n", F_REQ_CALL },
	{ JS, "var n = 'ev' + 'al';\nwindow[n](d);\n", F_BUILT_EVAL | F_ANY_EVAL },
	{ JS, "var n = ['ev', 'al'];\nvar m = 'e' + 'val';\nthis[m](x);\n", F_BUILT_EVAL | F_ANY_EVAL },
	/* the request in an arrow function's expression body, and one in a callback of a call */
	{ JS, "app.post('/x', (req, res) => eval(req.body.c));\n", F_REQ_EVAL | F_ANY_EVAL },
	{ JS, "app.get('/', function (req, res) {\n  var d = atob(req.query.p)\n  var q = 1\n  eval(d)\n})\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	/* a callback inside the brackets of a call: its statements end at their lines, which the brackets around it must not hide */
	{ JS, "app.get('/', function (req, res) {\n  var n = 'ev' + 'al'\n  window[n](d)\n})\n", F_BUILT_EVAL | F_ANY_EVAL },
	/* NOT: names in comments and strings; the decode ended at the line; a parameter that is not the outer variable; a function-valued variable */
	{ JS, "// eval(req.query.code)\nvar s = 'eval(req.query.code)';\n", 0 },
	{ JS, "var d = atob(x)\nfoo(1)\neval(y)\n", F_ANY_EVAL },
	{ JS, "var t = req.query.x;\nfunction a(t) { eval(t) }\n", F_ANY_EVAL },
	{ JS, "var t = req.query.x;\nvar a = (t) => eval(t);\nvar b = t => { eval(t) };\n", F_ANY_EVAL },
	{ JS, "var f = function (s) { return atob(s) }\nf(x)\n", 0 },
	{ JS, "var f = function (s) { return req.query.f }\nf(1)\n", 0 },
	{ JS, "var a = req.query.c\nfunction run() { var a = 'ls'; cp.exec(a) }\n", 0 },
	/* a method of an object that is not the module: no row for it */
	{ JS, "var re = /x/; re.exec(req.query.c);\nobj.exec(req.query.c);\n", 0 },
	{ JS, "x.foo(\n  req.query.c\n)\nvar y = 1\n", 0 },

	/* ================= perl: `$ENV{KEY}` is a member, `eval {}` is a block ================= */
	{ PL, "my $c = $ENV{'QUERY_STRING'};\nsystem($c);\n", F_REQ_EXEC },
	{ PL, "my $c = $ENV{QUERY_STRING};\nexec($c);\n", F_REQ_EXEC },
	{ PL, "my $code = decode_base64($ENV{HTTP_COOKIE});\neval($code);\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ PL, "eval(MIME::Base64::decode_base64($x));\n", F_DEC_EVAL | F_ANY_EVAL },
	/* pinned: the block form of eval is no eval of text, and the string form with a bracket is */
	{ PL, "eval { die \"x\" };\nsystem(\"ls\");\n", 0 },
	{ PL, "my $r = eval { decode_base64($x) };\nprint $r;\n", 0 },
	{ PL, "my $c = $ENV{QUERY_STRING};\neval { system(\"ls\") };\n", 0 },
	{ PL, "my $c = shift;\neval($c);\n", F_ANY_EVAL },
	/* NOT: a variable of another sub; a request key that is not one */
	{ PL, "sub a { my $c = $ENV{QUERY_STRING}; return length($c); }\nsub b { my $c = 'ls'; system($c); }\n", 0 },
	{ PL, "my $c = $ENV{HOME};\nsystem($c);\n", 0 },
	{ PL, "# system($ENV{QUERY_STRING});\nprint 'system($ENV{QUERY_STRING})';\n", 0 },

	/* ================= ruby: `end` closes a block; the modifier `if` opens none ================= */
	{ RB, "cmd = params[:c]\nsystem(cmd)\n", F_REQ_EXEC },
	{ RB, "Kernel.exec(request.params['z'])\n", F_REQ_EXEC },
	{ RB, "eval(Base64.decode64(params[:p]))\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ RB, "x = Base64.decode64(params[:p])\neval(x)\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ RB, "send(params[:m], 1)\n", F_REQ_CALL },
	{ RB, "require(params[:m])\nrequire('json')\n", F_REQ_LOAD },
	{ RB, "m = params[:m]\nsend(m, 1)\n", F_REQ_CALL },
	/* the modifier if does not open a block: the statement after it is still the same method */
	{ RB, "def run\n  cmd = params[:c] if x\n  system(cmd)\nend\n", F_REQ_EXEC },
	/* NOT: two methods, a value that never arrived, a name in a comment */
	{ RB, "def a\n  c = params[:c]\n  c.size\nend\ndef b\n  c = 'ls'\n  system(c)\nend\n", 0 },
	{ RB, "cmd = params[:c]\nsystem('ls')\n", 0 },
	{ RB, "# system(params[:c])\nputs 'system(params[:c])'\n", 0 },
	{ RB, "@cmd = params[:c]\nsystem(cmd)\n", 0 },
	/* a modifier if opens no block: the request is in def a only, whose `end` is the one after it */
	{ RB, "def a\n  c = params[:c] if x\nend\nc = 'ls'\nsystem(c)\n", 0 },

	/* ================= lua: `end` closes, `local` is a keyword, ".." joins ================= */
	{ LU, "local c = ngx.var.arg_c\nos.execute(c)\n", F_REQ_EXEC },
	{ LU, "io.popen(luci.http.formvalue('c'))\n", F_REQ_EXEC },
	/* ".." joins: the name after it is a variable and not a member of the one before */
	{ LU, "local c = ngx.var.arg_c\nos.execute('ls ' .. c)\n", F_REQ_EXEC },
	{ LU, "local p = ngx.req.get_uri_args()\nlocal code = mime.unb64(p.x)\nloadstring(code)()\n", F_DEC_CREATE | F_REQ_DEC | F_CREATE_CALL },
	{ LU, "local f = loadstring(mime.unb64(x))\nf()\n", F_DEC_CREATE | F_CREATE_CALL },
	{ LU, "local f = loadstring(mime.unb64(x))\nprint(f)\n", F_DEC_CREATE },
	{ LU, "require(ngx.var.arg_m)\nrequire('socket')\n", F_REQ_LOAD },
	{ LU, "local p = ngx.req.get_uri_args()\n_G[p.f](1)\n", F_REQ_CALL },
	{ LU, "local n = 'os.exe' .. 'cute'\n_G[n](x)\n", F_BUILT_EXEC },
	{ LU, "local n = 'os.' .. 'execute'\nlocal m = n .. 'x'\nprint(m)\n", 0 },
	/* NOT: two functions, and a value of an earlier statement that the next one does not use */
	{ LU, "function a()\n  local c = ngx.var.arg_c\n  return #c\nend\nfunction b()\n  local c = 'ls'\n  os.execute(c)\nend\n", 0 },
	{ LU, "local c = ngx.var.arg_c\nlocal d = 'ls'\nos.execute(d)\n", 0 },
	{ LU, "-- os.execute(ngx.var.arg_c)\nlocal s = \"os.execute(ngx.var.arg_c)\"\n", 0 },

	/* ================= java, as a jsp page runs it ================= */
	{ JSP, "<%\nString c = request.getParameter(\"c\");\nRuntime.getRuntime().exec(c);\n%>\n", F_REQ_EXEC },
	{ JSP, "<% java.lang.Runtime.getRuntime().exec(request.getParameter(\"x\")); %>\n", F_REQ_EXEC },
	{ JSP, "<% new ProcessBuilder(\"sh\", \"-c\", request.getParameter(\"c\")).start(); %>\n", F_REQ_EXEC },
	{ JSP, "<% String[] a = { \"sh\", request.getParameter(\"c\") }; Runtime.getRuntime().exec(a); %>\n", F_REQ_EXEC },
	{ JSP, "<% Class c = Class.forName(request.getParameter(\"k\")); %>\n", F_REQ_LOAD },
	{ JSP, "<% ScriptEngine e = m.getEngineByName(\"js\");\ne.eval(new String(Base64.getDecoder().decode(request.getParameter(\"p\")))); %>\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
	{ JSP, "<% File f = new File(request.getParameter(\"f\")); f.delete(); %>\n", F_REQ_FILE },
	/* NOT: the request printed and a fixed command run; two methods that share a name; a comment */
	{ JSP, "<% String c = request.getParameter(\"c\"); out.println(c); Runtime.getRuntime().exec(\"ls\"); %>\n", 0 },
	{ JSP, "<%! void a() { String c = request.getParameter(\"c\"); }\nvoid b() { String c = \"ls\"; Runtime.getRuntime().exec(c); } %>\n", 0 },
	{ JSP, "<% // Runtime.getRuntime().exec(request.getParameter(\"c\"));\nString s = \"Runtime.getRuntime().exec(request.getParameter)\"; %>\n", 0 },
	{ JSP, "<% String c = request.getParameter(\"c\"); %>\nsome markup\n<% Runtime.getRuntime().exec(d); %>\n", 0 },

	/* ================= c# and vb.net, as asp.net runs them ================= */
	{ AX, "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nvoid Page_Load(object s, EventArgs e) {\n  string c = Request.Form[\"c\"];\n  Process.Start(c);\n}\n</script>\n", F_REQ_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { System.Diagnostics.Process.Start(Request.QueryString[\"c\"]); }\n</script>\n", F_REQ_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { var p = new Process(); p.Start(Request.Form[\"c\"]); }\n</script>\n", F_REQ_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { Assembly.Load(Convert.FromBase64String(Request.Form[\"p\"])); }\n</script>\n", F_REQ_DEC },
	/* vb.net: the call has a bracket, the statement ends with the line, names do not care about case */
	/* a number is not the request: int.Parse, Convert.ToInt32 and CInt are the table's CLEAN rows, which the lookup could not match (a capitalised name in a language that folds: S2-4) */
	{ AX, "<%@ Page Language=\"C#\" %>\n<% var c = int.Parse(Request.Form[\"c\"]);\nProcess.Start(c); %>\n", 0 },
	{ AX, "<%@ Page Language=\"C#\" %>\n<% var c = Convert.ToInt32(Request.Form[\"c\"]);\nProcess.Start(c); %>\n", 0 },
	{ AX, "<%@ Page Language=\"VB\" %>\n<% c = CInt(Request.Form(\"c\"))\nprocess.start(c)\n%>\n", 0 },
	{ AX, "<%@ Page Language=\"C#\" %>\n<% var c = int.Parse(Request.Form[\"c\"]) + Request.Form[\"d\"];\nProcess.Start(c); %>\n", F_REQ_EXEC },
	{ AX, "<%@ Page Language=\"VB\" %>\n<% c = Request.Form(\"c\")\nprocess.start(c)\n%>\n", F_REQ_EXEC },
	{ AX, "<% x = convert.frombase64string(Request.Form(\"p\"))\n%>\n", F_REQ_DEC },
	/* NOT */
	{ AX, "<script runat=\"server\">\nvoid f() { string c = Request.Form[\"c\"]; Response.Write(c); Process.Start(\"calc\"); }\n</script>\n", 0 },
	{ AX, "<script runat=\"server\">\nvoid a() { string c = Request.Form[\"c\"]; }\nvoid b() { string c = \"calc\"; Process.Start(c); }\n</script>\n", 0 },
	{ AX, "<script runat=\"server\">\n// Process.Start(Request.Form[\"c\"]);\nvoid f() { string s = \"Process.Start(Request.Form)\"; }\n</script>\n", 0 },
};

static void rows_run(void)
{
	size_t i;

	for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
		struct kgenome_diag_scan *s = scan_l(rows[i].lang, rows[i].src);
		unsigned got;

		CK(s != NULL, "scan of: %s", rows[i].src);
		if (!s)
			continue;
		got = facts(s);
		CK(got == rows[i].want, "facts %#x, wanted %#x in: %s", got, rows[i].want, rows[i].src);
		kgenome_diag_scan_free(s);
	}
}

/* ---- the one list: what is served, against which table, and that the row agrees with the table ---- */

static void served(void)
{
	static const struct { uint32_t lang; unsigned target; } yes[] = {
		{ KGENOME_TEXTUAL_LANG_PHP, KGENOME_NUCLEO_T_PHP }, { JS, KGENOME_NUCLEO_T_JS }, { PY, KGENOME_NUCLEO_T_PY },
		{ PL, KGENOME_NUCLEO_T_PERL }, { RB, KGENOME_NUCLEO_T_RUBY }, { LU, KGENOME_NUCLEO_T_LUA }, { JSP, KGENOME_NUCLEO_T_JAVA },
		{ AX, KGENOME_NUCLEO_T_DOTNET },
		/* the statement-call languages (diag_text_stmt.c, diag_text_cmd.c): see tests/lib/genome/diag_text_stmt.c for what each reads */
		{ KGENOME_TEXTUAL_LANG_SH, KGENOME_NUCLEO_T_SH }, { KGENOME_TEXTUAL_LANG_BAT, KGENOME_NUCLEO_T_BAT },
		{ KGENOME_TEXTUAL_LANG_PSH, KGENOME_NUCLEO_T_PSH }, { KGENOME_TEXTUAL_LANG_TCL, KGENOME_NUCLEO_T_TCL },
		{ KGENOME_TEXTUAL_LANG_VBS, KGENOME_NUCLEO_T_VBS }, { KGENOME_TEXTUAL_LANG_ASP, KGENOME_NUCLEO_T_VBS },
		{ KGENOME_TEXTUAL_LANG_CFM, KGENOME_NUCLEO_T_CFML },
	};
	static const uint32_t no[] = { KGENOME_TEXTUAL_LANG_NONE, KGENOME_TEXTUAL_LANG_COUNT, 9999u };
	size_t i;

	for (i = 0; i < sizeof yes / sizeof yes[0]; i++) {
		CK(kgenome_diag_text_serves(yes[i].lang), "language %u is served", yes[i].lang);
		CK(kgenome_diag_text_target(yes[i].lang) == yes[i].target, "language %u reads target %u", yes[i].lang, yes[i].target);
	}
	for (i = 0; i < sizeof no / sizeof no[0]; i++) {
		struct kgenome_diag_scan *s = scan_l(no[i], "eval(base64_decode('x')); system($_GET['c']);");

		CK(!kgenome_diag_text_serves(no[i]) && kgenome_diag_text_target(no[i]) == 0, "language %u is not served", no[i]);
		CK(!s || kgenome_diag_scan_count(s) == 0, "a language with no row: no nodes (%u)", no[i]);
		if (s)
			kgenome_diag_scan_free(s);
	}
	/* only php reads the normalised view; the others read the script (see the row's reads_view) */
	CK(kgenome_diag_text_reads_view(KGENOME_TEXTUAL_LANG_PHP) && !kgenome_diag_text_reads_view(PY) && !kgenome_diag_text_reads_view(JS), "views");
}

/* The row's `fold` is the table's: a name in the other case is a row of a table that folds and no row of one that does not. */
static void folds(void)
{
	static const uint32_t all[] = { KGENOME_TEXTUAL_LANG_PHP, JS, PY, PL, RB, LU, JSP, AX };
	size_t i;

	for (i = 0; i < sizeof all / sizeof all[0]; i++) {
		const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(all[i]);
		const char *probe = l->target == KGENOME_NUCLEO_T_DOTNET ? "Process.Start" : l->target == KGENOME_NUCLEO_T_JAVA ? "Runtime.exec"
				  : l->target == KGENOME_NUCLEO_T_PERL || l->target == KGENOME_NUCLEO_T_RUBY ? "system" : "eval";
		char up[64];
		size_t k;

		if (l->target == KGENOME_NUCLEO_T_LUA)
			probe = "os.execute";
		if (l->target == KGENOME_NUCLEO_T_PY)
			probe = "os.system";
		for (k = 0; probe[k]; k++)
			up[k] = (char)(probe[k] >= 'a' && probe[k] <= 'z' ? probe[k] - 32 : probe[k]);
		up[k] = 0;
		CK(kgenome_nucleo_cap_of_name(l->target, probe) != KGENOME_NUCLEO_NONE, "%s is a row of target %u", probe, l->target);
		CK((kgenome_nucleo_cap_of_name(l->target, up) != KGENOME_NUCLEO_NONE) == (l->fold != 0), "row fold of target %u is the table's", l->target);
	}
}

/*
 * A NAME THAT DOES NOT FIT IS REFUSED. The chain is read into a buffer of KGENOME_DTX_NAME bytes; a longer one has no row (the longest is 46) and
 * is not looked up, which is not the same as looking up its first 63 bytes - the call below with a short receiver is a node, the same call behind
 * a receiver too long to hold is not.
 */
static void refused(void)
{
	char src[256];
	struct kgenome_diag_scan *s;
	int i;

	s = scan_l(PY, "import os\nos.system(x)\n");
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 1, "the short name is a node");
	if (s)
		kgenome_diag_scan_free(s);
	memset(src, 0, sizeof src);
	strcpy(src, "a");
	for (i = 0; i < 60; i++)
		strcat(src, "a");
	strcat(src, ".os.system(x)\n");
	s = scan_l(PY, src);
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "a receiver too long to hold: refused, not cut to os.system");
	if (s)
		kgenome_diag_scan_free(s);
	/* java and .NET drop a namespace in front, one piece at a time: a name that fits without it fits; one that does not fit at all is refused */
	s = scan_l(JSP, "<% java.lang.Runtime.getRuntime().exec(request.getParameter(\"x\")); %>\n");
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 1, "a qualified name is found without its package");
	if (s)
		kgenome_diag_scan_free(s);
	strcpy(src, "<% ");
	for (i = 0; i < 12; i++)
		strcat(src, "pkgname.");
	strcat(src, "Runtime.getRuntime().exec(x); %>\n");
	s = scan_l(JSP, src);
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "a package path too long for the buffer: refused");
	if (s)
		kgenome_diag_scan_free(s);
}

/* ---- the names a script "imports": each once, as the table spells it (the engine's gate reads these) ---- */

struct names { char v[16][48]; int n; };

static void collect(void *u, const char *name, uint32_t len)
{
	struct names *m = u;

	if (m->n < 16 && len < 48) {
		memcpy(m->v[m->n], name, len);
		m->v[m->n++][len] = 0;
	}
}

static int has(const struct names *m, const char *w)
{
	int i;

	for (i = 0; i < m->n; i++)
		if (!strcmp(m->v[i], w))
			return 1;
	return 0;
}

static void names(void)
{
	struct names nm;
	const char *js = "var cp = require('child_process');\ncp.exec(a);\nchild_process.exec(b);\neval(c);\n";
	const char *ax = "<script runat=\"server\">\nvoid f() { process.START(x); System.Diagnostics.Process.Start(y); }\n</script>\n";

	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)js, strlen(js), JS, NULL, collect, &nm);
	CK(nm.n == 2 && has(&nm, "child_process.exec") && has(&nm, "eval"), "js names: %d", nm.n);
	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)ax, strlen(ax), AX, NULL, collect, &nm);
	CK(nm.n == 1 && has(&nm, "Process.Start"), "aspx names, the table's spelling and once: %d", nm.n);
	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)js, strlen(js), 9999u, NULL, collect, &nm);
	CK(nm.n == 0, "a language with no row has no names");
}

/* ---- names and spacing nobody would write by hand: the variable's name is any name ---- */

static void random_names(void)
{
	static const struct { uint32_t lang; const char *fmt; unsigned want; } T[] = {
		{ PY, "@1 = request.args.get('x')\nos.system(@1)\n", F_REQ_EXEC },
		{ PY, "@1 = base64.b64decode(request.form['x'])\n@2 = @1\nexec(@2)\n", F_DEC_EVAL | F_REQ_DEC | F_ANY_EVAL },
		{ JS, "var @1 = req.query.c\nvar @2 = @1\nchild_process.exec(@2)\n", F_REQ_EXEC },
		{ JS, "const @1 = require('child_process');\n@1.exec(req.body.c);\n", F_REQ_EXEC },
		{ RB, "@1 = params[:c]\nsystem(@1)\n", F_REQ_EXEC },
		{ LU, "local @1 = ngx.var.arg_c\nos.execute(@1)\n", F_REQ_EXEC },
		{ PL, "my $@1 = $ENV{QUERY_STRING};\nsystem($@1);\n", F_REQ_EXEC },
		{ JSP, "<% String @1 = request.getParameter(\"c\"); Runtime.getRuntime().exec(@1); %>\n", F_REQ_EXEC },
		{ AX, "<script runat=\"server\">\nvoid f() { string @1 = Request.Form[\"c\"]; Process.Start(@1); }\n</script>\n", F_REQ_EXEC },
	};
	size_t t;
	unsigned it;

	for (it = 0; it < 60u; it++) {
		for (t = 0; t < sizeof T / sizeof T[0]; t++) {
			char n1[16], n2[16], src[512], *o = src;
			const char *p;
			struct kgenome_diag_scan *s;

			rname(n1);
			rname(n2);
			for (p = T[t].fmt; *p && o < src + sizeof src - 20; p++) {
				if (*p == '@' && (p[1] == '1' || p[1] == '2')) {
					const char *nm = p[1] == '1' ? n1 : n2;

					o += sprintf(o, "%s", nm);
					p++;
				} else {
					*o++ = *p;
				}
			}
			*o = 0;
			s = scan_l(T[t].lang, src);
			CK(s && facts(s) == T[t].want, "random names %s %s: facts %#x, wanted %#x in: %s", n1, n2, s ? facts(s) : 0u, T[t].want, src);
			if (s)
				kgenome_diag_scan_free(s);
		}
	}
}

/*
 * THE MEMO OF LOOKUPS keeps a name's answer by the name's hash, and a name that lands on another's slot must not read its answer. The names below
 * are found, here, to share eval's slot (the memo's own hash: FNV-1a over the bytes, 2048 slots): the text calls eval and then a function of
 * each of them, and only the first is an eval.
 */
static void memo_collision(void)
{
	char a[5], src[256];
	uint32_t want = 0u, h = 2166136261u, k, found = 0;
	int i, j, l, m;
	struct kgenome_diag_scan *s;

	for (k = 0; k < 4u; k++)
		h = (h ^ (uint8_t)"eval"[k]) * 16777619u;
	want = h & (KGENOME_DTX_CAPC - 1u);
	a[4] = 0;
	for (i = 0; i < 26 && found < 3u; i++)
		for (j = 0; j < 26 && found < 3u; j++)
			for (l = 0; l < 26 && found < 3u; l++)
				for (m = 0; m < 26 && found < 3u; m++) {
					a[0] = (char)('a' + i);
					a[1] = (char)('a' + j);
					a[2] = (char)('a' + l);
					a[3] = (char)('a' + m);
					h = 2166136261u;
					for (k = 0; k < 4u; k++)
						h = (h ^ (uint8_t)a[k]) * 16777619u;
					if ((h & (KGENOME_DTX_CAPC - 1u)) != want || !strcmp(a, "eval"))
						continue;
					snprintf(src, sizeof src, "eval(x);\n%s(y);\n", a);
					s = scan_l(JS, src);
					CK(s && count(s, KGENOME_NUCLEO_EVAL) == 1, "%s shares eval's slot and is no eval: %d eval nodes", a, s ? count(s, KGENOME_NUCLEO_EVAL) : -1);
					if (s)
						kgenome_diag_scan_free(s);
					found++;
				}
	CK(found == 3u, "three names share eval's slot");
}

/*
 * THE END OF AN ISLAND ENDS A STATEMENT (a page's <% %>): vb.net writes none, and a value assigned in one island must not run on into the call that
 * is the next island's first token - the evaluator is handed the right side of the assignment, and `"ev" & "al" Process.Start(x)` is no expression.
 * The constants told are the right sides the evaluator followed to a text.
 */
struct told { char v[8][32]; int n; };

static void on_const(void *u, uint64_t off, uint64_t len, const uint8_t *value, uint32_t n)
{
	struct told *t = u;

	(void)off; (void)len;
	if (t->n < 8 && n < 32) {
		memcpy(t->v[t->n], value, n);
		t->v[t->n++][n] = 0;
	}
}

static void islands_and_lines(void)
{
	static const struct { uint32_t lang; const char *src; const char *want; } T[] = {
		{ AX, "<%@ Page Language=\"VB\" %>\n<% n = \"ev\" & \"al\" %>\n<p>markup</p>\n<% Process.Start(x) %>\n", "eval" },
		{ AX, "<%@ Page Language=\"VB\" %>\n<% n = \"ev\" & \"al\"\nProcess.Start(x)\n%>\n", "eval" },
		{ PY, "n = 'ev' + 'al'\nprint(n)\n", "eval" },
		{ LU, "local n = 'ev' .. 'al'\nprint(n)\n", "eval" },
		{ RB, "n = 'ev' + 'al'\nputs n\n", "eval" },
		{ JS, "var n = 'ev' + 'al'\nconsole.log(n)\n", "eval" },
	};
	size_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		struct told t = { .n = 0 };
		struct kgenome_diag_text_req rq = { .base = (const uint8_t *)T[i].src, .size = strlen(T[i].src), .lang = T[i].lang, .on_const = on_const,
						    .const_user = &t };

		kgenome_diag_scan_free(kgenome_diag_scan_text(&rq));
		CK(t.n == 1 && !strcmp(t.v[0], T[i].want), "the constant %s is told (%d told) in: %s", T[i].want, t.n, T[i].src);
	}
}

/* ---- the variable table never moves a variable: many assignments, one of them written across the growth ---- */

static void many_variables(void)
{
	static char big[1 << 16];
	size_t n = 0;
	int i;
	struct kgenome_diag_scan *s;

	n += (size_t)snprintf(big + n, sizeof big - n, "var c0 = req.query.c;\n");
	for (i = 1; i < 700; i++)
		n += (size_t)snprintf(big + n, sizeof big - n, "var c%d = c%d;\n", i, i - 1);
	n += (size_t)snprintf(big + n, sizeof big - n, "child_process.exec(c699);\n");
	s = scan_l(JS, big);
	CK(s && (facts(s) & F_REQ_EXEC), "a request through 700 variables, the table growing under the assignment being read");
	if (s)
		kgenome_diag_scan_free(s);
}

int main(void)
{
	rows_run();
	served();
	folds();
	refused();
	names();
	random_names();
	memo_collision();
	islands_and_lines();
	many_variables();
	printf("diag text langs: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
