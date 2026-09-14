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

	/* ---- when it refuses ---- */

	refused(KOF_SCRIPT_ANY, "$a = 1;\n",
		"no table for the kind: nothing is guessed");

	refused(KOF_SCRIPT_PHP, "$x = <<<EOT\n  data\nEOT;\n",
		"a heredoc anywhere: the whole input is left alone");

	refused(KOF_SCRIPT_JS, "var s = `a\n  b`;\n",
		"a backtick anywhere: the whole input is left alone");

	if (fails) {
		printf("script norm: %d check(s) failed\n", fails);
		return 1;
	}
	printf("script norm: form, strings, operators, shell, refusals - ok\n");
	return 0;
}
