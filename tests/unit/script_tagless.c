/*
 * script_tagless - the three Windows scripting languages that carry no tag.
 *
 * WHAT THIS IS DEFENDING. php announces itself with "<?php" and a server page
 * with "<%"; VBScript, JScript and PowerShell announce nothing at all. Before
 * this existed the sniff knew shebangs, which are Linux, and server-page
 * markers, which are webshells - so a bare .vbs, .js or .ps1 came back
 * UNRECOGNISED while the engine already had KOF_SCRIPT_VBS, _JS and _PSH to
 * name them with. Measured: all three.
 *
 * THE TWO FAILURES WORTH A TEST, and neither one announces itself:
 *
 *   claims nothing     the file is scanned as raw bytes, no region partition,
 *                      and no rule scoped to a script can run on it
 *   claims the wrong   a .js reading `new ActiveXObject("WScript.Shell")` was
 *   language           called VBScript, because both reach the same scripting
 *                      host and only the constructor differs
 *
 * So this asserts the KIND and not merely that something was claimed.
 *
 * AND IT ASSERTS WHAT MUST NOT BE CLAIMED. Several PowerShell approved verbs
 * are ordinary English words - open, use, set, copy, find - so a case-blind
 * "Verb-Noun" rule claimed documentation on "open-n..." and "use-s...".
 * Measured over 189 config and documentation files from this machine: three
 * false claims before the capitalisation test, none after. The prose cases
 * below are that measurement kept.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/analyzer/parsers/scripts/script_parse.h"

static int failures;

static void expect(const char *what, const char *text, int claimed,
		   uint8_t kind)
{
	kof_buf b = kof_buf_make((const uint8_t *)text, strlen(text));
	struct kof_script_info info;
	struct kof_obj_ctx ctx;
	int got;

	memset(&info, 0, sizeof info);
	memset(&ctx, 0, sizeof ctx);

	got = kof_script_sniff(b);
	if (got != claimed) {
		printf("  FAIL %-28s sniff %s, wanted %s\n", what,
		       got ? "claimed" : "refused",
		       claimed ? "claimed" : "refused");
		failures++;
		return;
	}
	if (!claimed)
		return;
	if (!kof_script_parse(b, &info, &ctx)) {
		printf("  FAIL %-28s the sniff claimed it and the parse "
		       "refused\n", what);
		failures++;
		return;
	}
	if (info.kind != kind) {
		printf("  FAIL %-28s kind %u, wanted %u\n", what,
		       (unsigned)info.kind, (unsigned)kind);
		failures++;
	}
}

int main(void);
int main(void)
{
	/* ---- claimed, and as the right language ---- */

	expect("vbs by End Function",
	       "Function F()\r\n  F = 1\r\nEnd Function\r\n",
	       1, KOF_SCRIPT_VBS);
	expect("vbs by CreateObject",
	       "Set o = CreateObject(\"WScript.Shell\")\r\no.Run \"calc\"\r\n",
	       1, KOF_SCRIPT_VBS);
	/*
	 * THE SHARED MARKER, AND WHY THE ORDER OF THE TESTS IS THE ANSWER.
	 * Both languages drive WScript.Shell, so "wscript." cannot decide -
	 * but ActiveXObject is JScript's constructor and CreateObject is
	 * VBScript's. Asking for the unambiguous one first is what stops this
	 * being called VBScript.
	 */
	expect("js by ActiveXObject",
	       "var o = new ActiveXObject(\"WScript.Shell\");\r\n"
	       "o.Run(\"calc\");\r\n",
	       1, KOF_SCRIPT_JS);
	expect("js by console.log",
	       "function f(x) { console.log(x); }\r\nf(1);\r\n",
	       1, KOF_SCRIPT_JS);
	expect("psh by a cmdlet",
	       "# a comment\r\nSet-Alias Foo Bar\r\n",
	       1, KOF_SCRIPT_PSH);
	expect("psh by a module cmdlet",
	       "function X {\r\n  Add-Type -TypeDefinition $src\r\n}\r\n",
	       1, KOF_SCRIPT_PSH);
	/* A script that defines functions and calls no cmdlet at all - two of
	 * the shipped scripts this rule was measured against are this shape. */
	expect("psh by an operator",
	       "function F($a)\r\n{\r\n  if($a -eq $null) { return }\r\n}\r\n",
	       1, KOF_SCRIPT_PSH);
	/*
	 * AND AN OPERATOR POSIX `test` DOES NOT HAVE, INSIDE BRACKETS.
	 *
	 * shell_test_operator exists because `[ "$n" -lt 10 ]` is shell, not
	 * PowerShell. It was applied to every space-initial operator in the
	 * table, including eight - "-match", "-like", "-replace", "-join",
	 * "-split", "-contains", "-notmatch", "-notlike" - that no shell
	 * spells at all. Bracketed, they were discarded as shell evidence and
	 * the file came back unrecognised. Only the six `test` really shares
	 * are ambiguous; this pins the other direction.
	 */
	/*
	 * AND A TAG THAT NAMES NO LANGUAGE UNNAMES NOTHING.
	 *
	 * A bare "<%" opens a page in one of three languages and
	 * kof_svr_find_tag says so by answering KOF_SCRIPT_ANY. Accepted over
	 * a shebang, that answer replaced "Shell" with "cannot tell" - which
	 * is how six gzexe wrappers in the corpora, "#!/bin/sh" followed by
	 * tens of kilobytes of gzip that happens to contain the two bytes,
	 * stopped being shell scripts. The bytes are not in a string or a
	 * comment, so no code test rescues this; the shebang has to win.
	 */
	expect("a nameless tag cannot unname a shebang",
	       "#!/bin/sh\necho hi\n<% foo %>\necho bye\n",
	       1, KOF_SCRIPT_SHELL);
	expect("psh by an operator no shell has",
	       "$x = @($list)\r\nif ([string]$x -match 'abc') { $y = 1 }\r\n",
	       1, KOF_SCRIPT_PSH);
	expect("psh by an encoded switch",
	       "powershell -EncodedCommand SQBFAFgA\r\n",
	       1, KOF_SCRIPT_PSH);

	/* ---- a document nobody serves: its <script> body is its code ---- */

	/*
	 * AN HTA IS AN HTML FILE WHOSE PURPOSE IS TO RUN ONE SCRIPT, and a WSF
	 * is xml around the same thing. Both came back unrecognised before the
	 * markup family existed. The language comes from the element, so the
	 * second of these is VBScript and the first is not.
	 */
	expect("hta by a script element",
	       "<html><head><HTA:APPLICATION ID=\"x\"></head>"
	       "<script>new ActiveXObject(\"WScript.Shell\").Run(\"calc\")"
	       "</script></html>",
	       1, KOF_SCRIPT_JS);
	expect("wsf names its language",
	       "<job><script language=\"VBScript\">"
	       "CreateObject(\"WScript.Shell\").Run \"calc\""
	       "</script></job>",
	       1, KOF_SCRIPT_VBS);
	/*
	 * A SERVER PAGE IS STILL A SERVER PAGE. Its client-side javascript is
	 * markup the server copies out - svrpage_parse.c says so where it
	 * skips a <script> without runat - so the server tag has to win. This
	 * is the precedence, asserted rather than assumed.
	 */
	expect("php wins over a script element",
	       "<?php echo 1; ?><html><script>alert(1)</script></html>",
	       1, KOF_SCRIPT_PHP);

	/*
	 * ---- line one, when the bang was left out ----
	 *
	 * `#/usr/bin/perl` execs nowhere and the file still runs, because it
	 * is run as `perl file`. Two samples in the corpora are written that
	 * way and neither was claimed as a script at all.
	 */
	expect("a shebang missing its bang",
	       "#/usr/bin/perl\nuse Socket;\nmy $x = 1;\nprint $x;\n",
	       1, KOF_SCRIPT_PERL);
	/*
	 * AND THE REAL THING NEEDS NO KNOWN INTERPRETER. `#!/usr/bin/awk` is a
	 * script in a language with no subtype here; it is claimed, and its
	 * kind is honestly "cannot say".
	 */
	expect("a shebang naming no known kind",
	       "#!/usr/bin/awk -f\nBEGIN { x = 1 }\n{ print $1 }\n",
	       1, KOF_SCRIPT_ANY);

	/* ---- refused, and these are the measured false claims ---- */
	/*
	 * `#` OPENS A COMMENT IN EVERY LANGUAGE HERE, so the missing-bang form
	 * is only read when the word behind it is an interpreter the table
	 * knows - and only when the slash touches the `#`. A C source opening
	 * `#/*` and a comment with a path in it are both this shape and
	 * neither is a script.
	 */
	expect("a C source opening a comment",
	       "#/*\n * a comment\n */\nint main(void){return 0;}\n",
	       0, KOF_SCRIPT_ANY);
	expect("a comment that mentions a path",
	       "# /usr/bin/perl is needed\nsome prose here\nmore of it\n",
	       0, KOF_SCRIPT_ANY);

	/*
	 * A PAGE **ABOUT** SCRIPT IS NOT ONE. An opening tag with no closing
	 * tag is what documentation and an html escape in prose produce, so
	 * the pair is what says something is meant to run.
	 */
	expect("prose mentioning the tag",
	       "To add behaviour, place your code inside a &lt;script&gt; "
	       "element. The <script tag must be closed.\r\n",
	       0, 0);

	expect("prose with a verb compound",
	       "The connector uses an open-necked design, and you should use-"
	       "specific settings for the HTTP-Proxy documented above.\r\n",
	       0, 0);
	expect("a stylesheet offset",
	       "div.box { offset-x: 3px; margin-top: 1em; }\r\n",
	       0, 0);
	/*
	 * A LICENCE HEADER IS NOT A SCRIPT, and one of the shipped .ps1 files
	 * is nothing else. Refusing it is correct: the engine claims a format
	 * from CONTENT, and there is nothing in this content that says
	 * PowerShell. Naming it from the extension would be the guess this
	 * whole file avoids.
	 */
	expect("a comment-only script",
	       "# Copyright (c) Example Corporation. All rights reserved.\r\n"
	       "# THIS CODE IS PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND.\r\n",
	       0, 0);

	if (failures) {
		printf("script tagless: %d check(s) failed\n", failures);
		return 1;
	}
	printf("script tagless: vbs, jscript and powershell claimed by shape, "
	       "prose and stylesheets refused - ok\n");
	return 0;
}
