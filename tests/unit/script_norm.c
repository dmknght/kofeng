/*
 * script_norm - the form pass, on the cases it exists for and the ones that
 * would break it.
 *
 * The pass puts a script into one form so a marker survives how it was typed.
 * Everything it does is safe only OUTSIDE string literals, and the interesting
 * half of this file is the inside: a "#" in a URL is not a comment, "a   b" in
 * a string is not "a b", and getting either wrong corrupts the very bytes a
 * signature is taken from.
 *
 * Expectations are written from the rule, not from the code. That is the point
 * of writing them down: the last two times a rule here was checked against a
 * real string it turned out the code did something else.
 */
#include <stdio.h>
#include <string.h>

#include <kofmod/script.h>

#include "../../libkofeng/core/kofcore.h"
#include "../../libkofeng/kofparsers/scripts/script_norm.h"

static int fails;

static void bad2(const char *why)
{
	printf("  FAIL %s\n", why);
	fails++;
}

static void eq(uint8_t kind, const char *in, const char *want,
	       uint32_t what, const char *why)
{
	const struct kof_lex *lx = kof_lex_for(kind);
	uint8_t out[512];
	uint32_t n = (uint32_t)strlen(in);
	uint32_t w = kof_script_norm(lx, (const uint8_t *)in, n, out,
				     (uint32_t)sizeof out, what);

	if (w == strlen(want) && !memcmp(out, want, w))
		return;
	printf("  FAIL %-42s\n        in   \"%s\"\n        got  \"%.*s\"\n"
	       "        want \"%s\"\n", why, in, (int)w, (char *)out, want);
	fails++;
}

/* Answers 0 - nothing was done and the caller keeps the input. */
static void refused(uint8_t kind, const char *in, const char *why)
{
	const struct kof_lex *lx = kof_lex_for(kind);
	uint8_t out[512];
	uint32_t w = kof_script_norm(lx, (const uint8_t *)in,
				     (uint32_t)strlen(in), out,
				     (uint32_t)sizeof out, KOF_NORM_ALL);

	if (!w)
		return;
	printf("  FAIL %-42s got %u bytes, wanted 0\n", why, w);
	fails++;
}

int main(void)
{
	/* ---- what it is for ---- */

	eq(KOF_SCRIPT_PHP,
	   "    $x = 1;\n",
	   "$x=1;\n", KOF_NORM_ALL,
	   "indent goes, spaces close up");

	eq(KOF_SCRIPT_PHP,
	   "$a = 1;\n\n\n$b = 2;\n",
	   "$a=1;\n$b=2;\n", KOF_NORM_ALL,
	   "blank lines go");

	eq(KOF_SCRIPT_PHP,
	   "// a remark\n$a = 1;\n",
	   "$a=1;\n", KOF_NORM_ALL,
	   "a comment-only line goes");

	eq(KOF_SCRIPT_PHP,
	   "/* a\n   block */\n$a = 1;\n",
	   "$a=1;\n", KOF_NORM_ALL,
	   "a block comment over two lines goes");

	/*
	 * ALLMAN AND K&R ARE THE SAME CODE, and this is what makes one marker
	 * match both - worth more than the indent rule it sits beside.
	 */
	/* "return$t" because a word byte beside a non-word byte closes up, and
	 * php parses it - the rule is applied here as it is everywhere else
	 * rather than excepted for reading comfort. */
	eq(KOF_SCRIPT_PHP,
	   "function x($t)\n{\nreturn $t;\n}\n",
	   "function x($t){\nreturn$t;\n}\n", KOF_NORM_ALL,
	   "a lone brace joins the line above");

	/*
	 * BUT NOT ONTO A LINE THAT ENDS IN A COMMENT, or the brace is inside it
	 * and the block it opened is gone. Found in a real shell, where it put
	 * every brace after it one level out.
	 */
	eq(KOF_SCRIPT_PHP,
	   "function Zip($s) // Thanks to Alix Axel\n{\nreturn 1;\n}\n",
	   "function Zip($s)// Thanks to Alix Axel\n{\nreturn 1;\n}\n",
	   KOF_NORM_ALL,
	   "a brace does not join into a comment");

	/*
	 * "<<" IS A HEREDOC ONLY WITH A LABEL AFTER IT.
	 *
	 * A refusal is total - the extent keeps the bytes it was typed with -
	 * so reading an ascii banner as a heredoc costs a whole file its form.
	 * Measured: 5 of 76 php shells in the corpus contain "<<<" and no
	 * heredoc anywhere, 914 KB of them.
	 */
	eq(KOF_SCRIPT_PHP,
	   "/* >>>>> banner <<<<<<<<<< */\n$a = 1;\n",
	   "$a=1;\n", KOF_NORM_ALL,
	   "a row of angle brackets is not a heredoc");

	/* And "<<2" is the right answer, not "<< 2": "<" and "2" do not spell a
	 * longer token, so they close up like every other such pair. */
	eq(KOF_SCRIPT_PHP,
	   "$a = $b << 2;\n",
	   "$a=$b<<2;\n", KOF_NORM_ALL,
	   "a left shift is not a heredoc either");

	/* ---- what must NOT be touched ---- */

	/*
	 * THE CASE THE WHOLE STATE MACHINE EXISTS FOR. Strip from "//" to the
	 * end of the line and this becomes `$u="http:` - a broken line, and the
	 * marker somebody wanted is gone with it.
	 */
	eq(KOF_SCRIPT_JS,
	   "var u = \"http://evil.example/x\";\n",
	   "var u=\"http://evil.example/x\";\n", KOF_NORM_ALL,
	   "// inside a string is not a comment");

	eq(KOF_SCRIPT_PHP,
	   "$s = \"a   b\";\n",
	   "$s=\"a   b\";\n", KOF_NORM_ALL,
	   "spaces inside a string are values");

	eq(KOF_SCRIPT_PHP,
	   "$c = \"curl http://x/a#frag\";\n",
	   "$c=\"curl http://x/a#frag\";\n", KOF_NORM_ALL,
	   "# inside a string is not a comment");

	eq(KOF_SCRIPT_PHP,
	   "$q = \"he said \\\"hi\\\"\";\n",
	   "$q=\"he said \\\"hi\\\"\";\n", KOF_NORM_ALL,
	   "an escaped quote does not close the string");

	/* ---- closing two tokens into one ---- */

	eq(KOF_SCRIPT_PHP,
	   "@eval (@x($a));\n",
	   "@eval(@x($a));\n", KOF_NORM_ALL,
	   "eval ( closes up: word then non-word");

	eq(KOF_SCRIPT_PHP,
	   "function  x($t)\n",
	   "function x($t)\n", KOF_NORM_ALL,
	   "two words keep one space, or they glue");

	/*
	 * "$a + +$b" IS NOT "$a++$b" and "$a / /re/" is not a comment. Both
	 * sides non-word, so the space stays.
	 */
	/* The space before the first "+" closes up like any other word/non-word
	 * pair; only the "+ +" keeps one, which is the whole point. */
	eq(KOF_SCRIPT_PHP,
	   "$c = $a + +$b;\n",
	   "$c=$a+ +$b;\n", KOF_NORM_ALL,
	   "two operators keep one space between them");

	/* ---- the language actually matters ---- */

	/*
	 * SHELL CLOSES NOTHING UP. "ls -la" and "ls-la" are different commands
	 * and they have the same shape as "eval (" - a word byte, a space, a
	 * non-word byte. Only the table tells them apart.
	 */
	eq(KOF_SCRIPT_SHELL,
	   "ls   -la /tmp\n",
	   "ls -la /tmp\n", KOF_NORM_ALL,
	   "shell collapses but never closes up");

	eq(KOF_SCRIPT_SHELL,
	   "  echo hi\n",
	   "echo hi\n", KOF_NORM_ALL,
	   "shell still loses its indent");

	/*
	 * AND A BACKSLASH IN SHELL '...' IS A BACKSLASH. Read as an escape it
	 * would swallow the closing quote and take the rest of the file into a
	 * string that never ends.
	 */
	eq(KOF_SCRIPT_SHELL,
	   "a='x\\' ; echo  b\n",
	   "a='x\\' ; echo b\n", KOF_NORM_ALL,
	   "sh: backslash in '...' is not an escape");

	/*
	 * ---- A STRING THAT CROSSES A LINE ----
	 *
	 * Legal php, and the ordinary way a pure shell emits its page: html
	 * echoed from one literal. The pass used to assert this could not
	 * happen - has_multiline looks for heredoc and backtick openers and a
	 * plain quote is neither - and threw the string state away at every
	 * newline, so the second line of such a string was walked AS CODE.
	 *
	 * Every rule then did the wrong thing to a VALUE, and one of them did
	 * it destructively: a line reading "// x" inside the string was deleted
	 * as a comment-only line. The bytes of a file disappearing is the one
	 * outcome worth never producing, so all four are pinned here.
	 */
	eq(KOF_SCRIPT_PHP,
	   "$p = \"<b>\n  // not a comment\n\n  a   b\n</b>\";\n$x = 1;\n",
	   "$p=\"<b>\n  // not a comment\n\n  a   b\n</b>\";\n$x=1;\n",
	   KOF_NORM_ALL,
	   "a string crossing a line is all value");

	/* And the code AFTER it is still code - the state has to come back, or
	 * the rest of the file is copied as though it were a string. */
	eq(KOF_SCRIPT_PHP,
	   "$p = \"a\nb\";  if ( $x )  { }\n",
	   "$p=\"a\nb\";if($x){}\n", KOF_NORM_ALL,
	   "and the code after it is formed again");

	/*
	 * ---- CLASSIC ASP IS VBSCRIPT, AND VBSCRIPT IS NOT C ----
	 *
	 * Two bytes the "<%" family disagreed about, both found on one real
	 * shell (cmdasp.asp) and both inverting the pass for the rest of the
	 * file once they fired.
	 *
	 *   "'"  opens a COMMENT in VBScript and a character literal in C# and
	 *        Java. Read as a quote, every comment in an asp file opened a
	 *        string that never closed.
	 *   "\"   is not an escape at all. "C:\" is a whole string; read as an
	 *        escaped quote it swallows the closing one and runs on.
	 *
	 * What either one produces is the same and is the worst possible shape:
	 * code read as value and value read as code, so the spacing rules run
	 * over the INSIDE of strings and stop running over the code.
	 */
	eq(KOF_SCRIPT_ASP,
	   "  ' a remark with a man's apostrophe\n"
	   "  szTempFile = \"C:\\\" & oFileSys.GetTempName( )\n"
	   "  Call oScript.Run (\"cmd.exe /c \" & szCMD, 0, True)\n",
	   "szTempFile=\"C:\\\"&oFileSys.GetTempName()\n"
	   "Call oScript.Run(\"cmd.exe /c \"&szCMD,0,True)\n",
	   KOF_NORM_ALL,
	   "vbs: ' is a comment and \\ is not an escape");

	/* And the same bytes in a JSP island are C: there "'" IS a literal. */
	eq(KOF_SCRIPT_JSP,
	   "  char c = 'x';  int n = 1;\n",
	   "char c='x';int n=1;\n", KOF_NORM_ALL,
	   "jsp: ' is a character literal");

	/* ---- when it refuses ---- */

	refused(KOF_SCRIPT_ANY, "$a = 1;\n",
		"no table for the kind: nothing is guessed");

	refused(KOF_SCRIPT_PHP, "$x = <<<EOT\n  data\nEOT;\n",
		"a heredoc anywhere: the whole input is left alone");

	refused(KOF_SCRIPT_JS, "var s = `a\n  b`;\n",
		"a backtick anywhere: the whole input is left alone");

	/* ---- the folding pass ---- */

	/*
	 * THE MEASUREMENT THIS WAS BUILT FOR.
	 *
	 * Two builds of one generator share no byte string: the separator, the
	 * variable names, where the cuts fall and the order the pieces are
	 * joined in are all different. These two are that shape, cut down from
	 * weevely's cleartext obfuscator - one uses "T|" and the other "+T",
	 * and neither the names nor the cuts line up.
	 *
	 * If folding works they reduce to THE SAME BYTES, and one marker on
	 * those bytes covers both builds and every other build of the same
	 * generator. If it does not, no static signature can cover more than
	 * one of them and the whole pass is not worth its cost.
	 */
	{
		static const char b1[] =
			"<?php\n"
			"$p='T|functiT|on x($t,$k){$c=T|strlen($k);';\n"
			"$v='$k=\"4e4d6c33\";T|$kh=\"2b6fe62a63af\";';\n"
			"$U=str_replace('T|','',$v.$p);\n";
		static const char b2[] =
			"<?php\n"
			"$Y='$k=\"4e4d+T6c33\";$kh=\"2b6+Tfe62a63af\";';\n"
			"$P='func+Ttion x($t,$k){$c+T=strlen($k);';\n"
			"$u=str_replace('+T','',$Y.$P);\n";
		const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
		uint8_t o1[512], o2[512];
		uint32_t n1 = kof_script_fold(lx, (const uint8_t *)b1,
					      (uint32_t)strlen(b1), o1,
					      (uint32_t)sizeof o1);
		uint32_t n2 = kof_script_fold(lx, (const uint8_t *)b2,
					      (uint32_t)strlen(b2), o2,
					      (uint32_t)sizeof o2);

		if (!n1 || !n2) {
			printf("  FAIL folding produced nothing (%u, %u)\n",
			       n1, n2);
			fails++;
		} else if (n1 != n2 || memcmp(o1, o2, n1) != 0) {
			printf("  FAIL two builds did not reduce to one form\n"
			       "        b1 -> \"%.*s\"\n"
			       "        b2 -> \"%.*s\"\n",
			       (int)n1, (char *)o1, (int)n2, (char *)o2);
			fails++;
		} else {
			printf("  two poly builds reduce to one %u byte form: "
			       "\"%.*s\"\n", n1, (int)n1, (char *)o1);
		}
	}

	/* An escaped literal decodes - the "phar://" case, written as octal and
	 * hex so the seven bytes never appear. */
	{
		static const char esc[] =
			"<?php $a=\"\\160\\x68\\141\\x72\\72\\57\\57\";\n";
		const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
		uint8_t o[64];
		uint32_t n = kof_script_fold(lx, (const uint8_t *)esc,
					     (uint32_t)strlen(esc), o,
					     (uint32_t)sizeof o);

		if (n != 7u || memcmp(o, "phar://", 7u) != 0) {
			printf("  FAIL escapes: got %u \"%.*s\", wanted "
			       "\"phar://\"\n", n, (int)n, (char *)o);
			fails++;
		}
	}

	/*
	 * NOTHING IS RUN AND NOTHING FROM OUTSIDE IS FOLLOWED. A value that
	 * comes from the request is not a constant, and a pass that treated one
	 * as if it were would be inventing bytes that were never in the file.
	 */
	{
		static const char live[] =
			"<?php $a=$_POST['x']; $b='lit'.$a;\n";
		const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_PHP);
		uint8_t o[64];
		uint32_t n = kof_script_fold(lx, (const uint8_t *)live,
					     (uint32_t)strlen(live), o,
					     (uint32_t)sizeof o);

		if (n && memcmp(o, "lit", n < 3u ? n : 3u) == 0 && n > 3u) {
			printf("  FAIL a runtime value was folded as if it "
			       "were constant\n");
			fails++;
		}
	}

	/* A language with no sigil declines rather than guessing which bare
	 * name is a variable - see var_sigil. */
	{
		const struct kof_lex *lx = kof_lex_for(KOF_SCRIPT_JS);
		uint8_t o[64];

		if (kof_script_fold(lx, (const uint8_t *)"var a='x'+'y';",
				    14u, o, (uint32_t)sizeof o))
			bad2("js folded without a sigil to go on");
	}

	/*
	 * THE THREE KINDS THAT HAD NO ROW AT ALL.
	 *
	 * kof_lex_for answered NULL for Lua, Tcl and ColdFusion, and a NULL row
	 * means the form pass declines the object: those files were recognised
	 * as scripts and then never formed, so a marker taken from one carried
	 * whatever spacing and comments the author happened to type.
	 */
	eq(KOF_SCRIPT_TCL, "# a note\n    set x 1\n    exec /bin/sh -c $x\n",
	   "set x 1\nexec /bin/sh -c $x\n", KOF_NORM_ALL,
	   "tcl: the comment and the indent go, the words stay apart");
	eq(KOF_SCRIPT_CFM,
	   "<cfscript>\n  // a note\n  x = \"cmd\" & \".exe\";\n</cfscript>\n",
	   "<cfscript>\nx=\"cmd\"&\".exe\";\n</cfscript>\n", KOF_NORM_ALL,
	   "coldfusion: its script dialect forms like the C family");
	eq(KOF_SCRIPT_LUA, "-- a note\nlocal s = 'cmd'\nos.execute( s )\n",
	   "local s='cmd'\nos.execute(s)\n", KOF_NORM_ALL,
	   "lua: comment out, spacing closed");
	/*
	 * AND LUA'S LONG BRACKET IS REFUSED RATHER THAN FORMED - see lex_lua.
	 * "[[" opens a multi-line STRING, the pass has no handling for one, and
	 * closing up the spacing inside a literal is the corruption this whole
	 * pass is forbidden to commit. The block comment shares the bracket, so
	 * it refuses too: a file that is not formed, never a literal that no
	 * longer matches.
	 */
	refused(KOF_SCRIPT_LUA, "local t = [[ a long string ]]\n",
		"lua: a long string is not formed");
	refused(KOF_SCRIPT_LUA, "--[[ a block note ]]\nlocal s = 1\n",
		"lua: a block comment shares the long bracket");

	if (fails) {
		printf("script norm: %d check(s) failed\n", fails);
		return 1;
	}
	printf("script norm: form, strings, multi-line values, operators, "
	       "shell, lua/tcl/cfm, refusals, folding - ok\n");
	return 0;
}
