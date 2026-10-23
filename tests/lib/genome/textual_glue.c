/*
 * textual_glue - the pairs of bytes closing up white space would turn into something else, in php (php_glue), where the rule is "an operator byte
 * followed by itself, or the pair opens a comment or a tag".
 *
 * A NUL is not an operator. php's row asked strchr(set, a), which answers yes for a == 0 (it finds the set's terminator), so alone among the rows it
 * kept a space between two NULs; kgenome_textual_glue_twice says no, like every other row. "$a=1; <NUL> <NUL> $b" is `$a=1;<NUL><NUL>$b`: closing two NULs
 * up makes no longer token, and the space was an accident of a library call. Measured over 52,199 php files and the engine's children of the 71 of
 * the list: no file has a NUL between two tokens, so nothing real changed.
 */

#include "textual_check.h"

static void both(const char *src, const char *want)
{
	form_lang(KGENOME_TEXTUAL_LANG_PHP, src, want);
}

int main(void)
{
	static const char ops[] = "+-*%=!<>&|.:?^~$";
	char src[64], want[64];
	unsigned i;

	/* the NUL pair: no space, in php as in the other rows */
	{
		static const char in[] = "<?php $a=1; \0 \0 $b=2;";
		static const char out[] = "<?php $a=1;\0\0$b=2;";
		uint32_t n;

		CK(form_of(in, sizeof in - 1u, fbuf, sizeof fbuf, &n) == KGENOME_TEXTUAL_OK);
		CK(n == sizeof out - 1u && !memcmp(fbuf, out, n));
		/* a NUL and another byte */
		{
			static const char in2[] = "<?php $a=1; \0 + $b=2;";
			static const char out2[] = "<?php $a=1;\0+$b=2;";

			CK(form_of(in2, sizeof in2 - 1u, fbuf, sizeof fbuf, &n) == KGENOME_TEXTUAL_OK && n == sizeof out2 - 1u && !memcmp(fbuf, out2, n));
		}
	}
	/* every operator byte twice keeps its space (closing up would make ++, --, .. and so on); an operator and another byte close up */
	for (i = 0; ops[i]; i++) {
		snprintf(src, sizeof src, "<?php $a %c %c$b;", ops[i], ops[i]);
		snprintf(want, sizeof want, "<?php $a%c %c$b;", ops[i], ops[i]);
		both(src, want);
		snprintf(src, sizeof src, "<?php $a %c ( $b;", ops[i]);
		snprintf(want, sizeof want, "<?php $a%c($b;", ops[i]);
		if (ops[i] != '$')
			both(src, want);
	}
	/* the comment openers and the tag */
	both("<?php $a / /*c*/ 2;", "<?php $a/2;");
	both("<?php $a = $b / / 2;", "<?php $a=$b/ /2;");
	both("<?php $a = $b ? > 2;", "<?php $a=$b? >2;");
	printf("textual glue: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
