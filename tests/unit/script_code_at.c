#define _GNU_SOURCE
/*
 * script_code_at - kof_script_is_code_at: is byte `at` of a script CODE, outside every string and every comment, as the lib's lexer reads the kind.
 *
 * The sniff asks it to tell a file that IS php from one that TALKS ABOUT php: a "<?php" in a python comment, in a shell string or in a lua block
 * comment is not code. It replaced kof_lex_is_code_at, which read the comment openers and quotes of script_norm.c's rows - a second reader of the same
 * rules the lexer reads - and what that one's tests pinned is here: the cases of normalizer_script_form.c (php line comment, python comment, lua block
 * comment, php block comment and string, an unterminated quote, the null and out-of-range answers), and then every language the lib lexes, each with
 * a byte in code, in a string, in a comment and - where the language has one - in a heredoc or a long string.
 *
 * Each case is a text and two lists of NEEDLES (the first byte of each is asked): the ones that must be code and the ones that must not. The
 * delimiters are not asked: a string's quote and a comment's opener are the lexer's STRING and COMMENT spans, where the table put the opener in code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kofmod/script.h>
#include "../../libkofeng/analyzers/parsers/scripts/script_route.h"

static unsigned ok_n, bad_n;

#define CK(cond, ...) do { \
	if (cond) { \
		ok_n++; \
	} else { \
		bad_n++; \
		printf("  FAIL %s:%d  %s  ", __FILE__, __LINE__, #cond); \
		printf(__VA_ARGS__); \
		printf("\n"); \
	} \
} while (0)

struct tc {
	uint8_t     kind;
	const char *text;
	const char *code[4];    /* needles: must be code */
	const char *data[4];    /* needles: must not */
};

static const struct tc cases[] = {
	{ KOF_SCRIPT_PHP, "$a = 1; // eval( here\n$b = 2;", { "$a", "$b", "\n$b" }, { "eval" } },
	{ KOF_SCRIPT_PHP, "$a = 1; /* eval( */ $b = \"eval(\";", { "$a", "$b" }, { "eval( */", "eval(\";" } },
	{ KOF_SCRIPT_PHP, "$a = 'x'; # eval(\n$b = <<<EOT\nsystem(1)\nEOT;\n$c = 3;", { "$a", "$c", "$b", "system" }, { "eval" } },        /* a heredoc body is code to the sniff, as it was */
	{ KOF_SCRIPT_PHP, "$a = \"x\\\" eval(\"; $b = 1;", { "$a", "$b" }, { "eval" } },
	{ KOF_SCRIPT_PYTHON, "x = 1  # <?php here\ny = 2", { "x = 1", "y = 2" }, { "<?php" } },
	{ KOF_SCRIPT_PYTHON, "x = '<?php a' + \"<?php b\"\nz = 1", { "x =", "z = 1" }, { "<?php a", "<?php b" } },
	{ KOF_SCRIPT_PYTHON, "s = '''<?php\ncode()\n'''\nt = 2", { "t = 2", "s =" }, { "<?php\ncode", "code()" } },
	{ KOF_SCRIPT_PYTHON, "s = f'{x} <?php {y}'\nt = 2", { "t = 2" }, { "<?php" } },
	{ KOF_SCRIPT_LUA, "x = 1 --[[ eval( ]] y = 2", { "x = 1", "y = 2" }, { "eval" } },
	{ KOF_SCRIPT_LUA, "x = [[ <?php\nz ]] y = 2 -- note <?php\nw = 1", { "x =", "y = 2", "w = 1" }, { "<?php\nz", "note", "<?php\nw" } },
	{ KOF_SCRIPT_SHELL, "echo hi # <?php a\necho 'b <?php c' \"d <?php e\"\n", { "echo hi", "echo 'b" }, { "<?php a", "<?php c", "<?php e" } },
	{ KOF_SCRIPT_SHELL, "cat <<EOF\n<?php heredoc\nEOF\necho done", { "echo done", "cat", "<?php heredoc" }, { NULL } },     /* script_islands.c: "sh that heredocs php -> php" */
	{ KOF_SCRIPT_SHELL, "echo a#b $((1<<2)) c", { "a#b", "c" }, { NULL } },
	{ KOF_SCRIPT_PERL, "$x = 1; # <?php a\n$y = 'b <?php c';\n$z = 3;", { "$x", "$z" }, { "<?php a", "<?php c" } },
	{ KOF_SCRIPT_PERL, "print <<EOT;\n<?php here\nEOT\n$w = 1;", { "$w", "print", "<?php here" }, { NULL } },
	{ KOF_SCRIPT_RUBY, "x = 1 # <?php a\ny = \"b <?php c\"\nz = 2", { "x = 1", "z = 2" }, { "<?php a", "<?php c" } },
	{ KOF_SCRIPT_JS, "var a = 1; // <?php a\nvar b = '<?php b'; /* <?php c */ var c = 3;", { "var a", "var c" }, { "<?php a", "<?php b", "<?php c" } },
	{ KOF_SCRIPT_JS, "var s = `x <?php ${y} z`; var t = 1;", { "var t" }, { "<?php" } },
	{ KOF_SCRIPT_TCL, "set a 1\n# <?php a\nset b \"<?php b\"\nset c {<?php c}", { "set a", "set b" }, { "<?php a", "<?php b", "<?php c" } },
	{ KOF_SCRIPT_PSH, "$a = 1 # <?php a\n$b = '<?php b' + \"<?php c\"\n<# <?php d #> $e = 2", { "$a", "$e" }, { "<?php a", "<?php b", "<?php c", "<?php d" } },
	{ KOF_SCRIPT_VBS, "x = 1 ' <?php a\ny = \"<?php b\"\nRem <?php c\nz = 2", { "x = 1", "z = 2" }, { "<?php a", "<?php b", "<?php c" } },
	{ KOF_SCRIPT_BAT, "echo a\nREM <?php a\necho \"<?php b\"\n:: <?php c\necho z", { "echo a", "echo z" }, { "<?php a", "<?php b", "<?php c" } },
	{ KOF_SCRIPT_ASP, "<% x = 1 ' <?php a\ny = \"<?php b\" %>", { "x = 1" }, { "<?php a", "<?php b" } },
	{ KOF_SCRIPT_JSP, "<% int a = 1; // <?php a\nString b = \"<?php b\"; /* <?php c */ %>", { "int a" }, { "<?php a", "<?php b", "<?php c" } },
};

/* An unterminated one-line string ends at its line (python's, lua's, javascript's): the rest of the file is not a string. DIFFERENCE for php, whose double
 * quoted string runs over lines and ends at the end of the text, as php reads it: the table this replaced ended every quote at the newline, php's too. */
static const struct tc line_end = { KOF_SCRIPT_PYTHON, "s = 'abc\n<?php x", { "<?php x" }, { "abc" } };
static const struct tc php_open = { KOF_SCRIPT_PHP, "echo \"abc\n<?php x", { "echo" }, { "<?php x", "abc" } };

static void run(const struct tc *t)
{
	const uint8_t *p = (const uint8_t *)t->text;
	uint32_t n = (uint32_t)strlen(t->text);
	unsigned i;

	for (i = 0; i < 4u && t->code[i]; i++) {
		const char *q = strstr(t->text, t->code[i]);

		CK(q != NULL, "needle [%s] is not in [%s]", t->code[i], t->text);
		if (q)
			CK(kof_script_is_code_at(t->kind, p, n, (uint32_t)(q - t->text)), "kind %u: [%s] is code in [%s]", t->kind, t->code[i], t->text);
	}
	for (i = 0; i < 4u && t->data[i]; i++) {
		const char *q = strstr(t->text, t->data[i]);

		CK(q != NULL, "needle [%s] is not in [%s]", t->data[i], t->text);
		if (q)
			CK(!kof_script_is_code_at(t->kind, p, n, (uint32_t)(q - t->text)), "kind %u: [%s] is not code in [%s]", t->kind, t->data[i], t->text);
	}
}

int main(void)
{
	unsigned i;
	static const char src[] = "$a = 1; /* eval( */ $b = \"eval(\";";

	for (i = 0; i < sizeof cases / sizeof cases[0]; i++)
		run(&cases[i]);
	run(&line_end);
	run(&php_open);
	/* the answers that are not about a byte: no lexer for the kind, no text, a byte past the end */
	CK(kof_script_is_code_at(KOF_SCRIPT_ANY, (const uint8_t *)src, (uint32_t)strlen(src), 10), "a kind with no lexer says code");
	CK(kof_script_is_code_at(250, (const uint8_t *)src, (uint32_t)strlen(src), 10), "an unknown kind says code");
	CK(kof_script_is_code_at(KOF_SCRIPT_PHP, NULL, 10, 5), "no text says code");
	CK(kof_script_is_code_at(KOF_SCRIPT_PHP, (const uint8_t *)src, 4, 99), "a byte past the end says code");
	CK(kof_script_is_code_at(KOF_SCRIPT_PHP, (const uint8_t *)src, (uint32_t)strlen(src), (uint32_t)strlen(src)), "the byte at the end says code");
	/* every byte of every case, whatever it is, is answered (no read past the text: the text is exactly `n` bytes of a heap block) */
	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		size_t n = strlen(cases[i].text), k;
		uint8_t *h = malloc(n);

		memcpy(h, cases[i].text, n);
		for (k = 0; k < n; k++)
			(void)kof_script_is_code_at(cases[i].kind, h, (uint32_t)n, (uint32_t)k);
		free(h);
	}
	printf("script_code_at: %u checks, %u failed\n", ok_n + bad_n, bad_n);
	return bad_n != 0;
}
