/*
 * genome / script_funcs_bat - the batch subroutine strategy (celllysis/script_funcs_bat.c) from CONSTRUCTED text only, linked
 * against libkgenome.a alone.
 *
 * WHAT IS ASSERTED: as in script_funcs_py.c (the kit is script_funcs_kit.h): exact (off, len,
 * name_off, name_len) and END_OPEN per entry, the properties of any answer, and the same entries under CRLF and behind a BOM (no
 * lone-CR run: cmd and the batch lexer end a line at "\n" only, a CR is a blank).
 *
 * WHY THE OLD TESTS MISSED IT: every group is (a) - the strategy was a stub (NO_TABLE). The groups that decide where a subroutine
 * ends (a return inside a parenthesised block or after IF is not the end, one after "&" is; a label nobody calls is part of the
 * subroutine it is in) are also (b): each is the boundary between a conditional and an unconditional return.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_BAT
#define SF_STRAT kgenome_script_funcs_bat
#define SF_CR    0      /* a lone CR is a blank to cmd */

#include "script_funcs_kit.h"

/* ---- Batch -------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("called label to goto :eof", ":main\ncall :sub1 a\ngoto :eof\n:sub1\necho %1\ngoto :eof\n",
		{ "\n:sub1", "goto :eof", "sub1", 0 });
	SF_NONE("a goto target is not a subroutine", ":loop\necho x\ngoto loop\n");
	SF_CASE("exit /b", "call :f\nexit /b\n:f\necho f\nexit /b 0\n", { "\n:f", "exit /b 0", "f", 0 });
	SF_CASE("case, goto eof without the colon", "CALL :Sub\n:SUB\nEcho\nGOTO EOF\n", { "\n:SUB", "GOTO EOF", "SUB", 0 });
	SF_CASE("label with text after it, indented", "call :f x\n  :f extra\necho\nexit /B\n", { ":f extra", "exit /B", "f", 0 });
	SF_CASE("label at offset 0 called later", ":f\necho\ngoto :eof\ncall :f\n", { ":f", "goto :eof", "f", 0 });
	SF_CASE("call inside a block and after if", "if x (call :a) else call :b\n:a\ngoto :eof\n:b\ngoto :eof\n",
		{ "\n:a", "goto :eof", "a", 0 }, { "\n:b", "goto :eof", "b", 0 });
	SF_CASE("@call", "@call :f\n:f\n@goto :eof\n", { "\n:f", "@goto :eof", "f", 0 });
}

static void ends(void)
{
	SF_CASE("a return inside a block is not the end", "call :f\n:f\nif x (\n  exit /b\n)\necho y\ngoto :eof\n",
		{ "\n:f", "y\ngoto :eof", "f", 0 });
	SF_CASE("a return after if on its line is not the end", "call :f\n:f\nif errorlevel 1 goto :eof\necho y\nexit /b\n",
		{ "\n:f", "y\nexit /b", "f", 0 });
	SF_CASE("a return after & on an if line is the if's", "call :f\n:f\nif x echo a & goto :eof\necho y\nexit /b\n",
		{ "\n:f", "y\nexit /b", "f", 0 });
	SF_CASE("a return after && is not the end", "call :f\n:f\nx && exit /b\necho y\nexit /b\n", { "\n:f", "y\nexit /b", "f", 0 });
	SF_CASE("a return in a pipe is not the end", "call :f\n:f\nx | exit /b\necho y\nexit /b\n", { "\n:f", "y\nexit /b", "f", 0 });
	SF_CASE("a return after || is not the end", "call :f\n:f\nx || exit /b\necho y\nexit /b\n", { "\n:f", "y\nexit /b", "f", 0 });
	SF_CASE("a return after & is", "call :f\n:f\necho a & goto :eof\necho never\n", { "\n:f", "goto :eof", "f", 0 });
	SF_CASE("the next called label ends it", "call :a\ncall :b\n:a\necho a\n\n:b\necho b\ngoto :eof\n",
		{ "\n:a", "echo a", "a", 0 }, { "\n:b", "goto :eof", "b", 0 });
	SF_CASE("a label nobody calls is inside", "call :f\n:f\n:inner\necho x\ngoto inner\ngoto :eof\n", { "\n:f", "goto :eof", "f", 0 });
	SF_CASE("goto other is not a return", "call :f\n:f\ngoto other\n:other\nexit /b\n", { "\n:f", "exit /b", "f", 0 });
	SF_CASE("goto :eofx and exit /bx are not returns", "call :f\n:f\ngoto :eofx\nexit /bx\nexit /b\n", { "\n:f", "/bx\nexit /b", "f", 0 });
	SF_CASE("unterminated at the end", "call :f\n:f\necho x\n", { "\n:f", NULL, "f", 1 });
	SF_CASE("return on the last line without a break", "call :f\n:f\nexit /b", { "\n:f", "exit /b", "f", 0 });
}

static void literals(void)
{
	SF_NONE(":: and rem are comments", "call :c\n:: c\nrem :c\n");
	SF_NONE(":eof is not a subroutine", "call :eof\n:eof\necho\n");
	SF_NONE("call in a comment or a string", "rem call :x\necho \"call :x\"\n:: call :x\n:x\necho\n");
	SF_NONE("a word that holds call", "recall :x\ncalls :x\n:x\necho\n");
}

static void hostile(void)
{
	sf_hostile("100000 called subroutines", "", ":L\ncall :L\ngoto :eof\n", 100000u, 100000u);
	sf_hostile("100000 labels nobody calls", "", ":L\necho\n", 100000u, 0u);
	sf_hostile("100000 calls, one label", ":L\n", "call :L\n", 100000u, 1u);
	sf_hostile("100000 open blocks", "call :L\n:L\n", "(\nexit /b\n", 100000u, 1u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	ends();
	literals();
	hostile();
	if (hk_fails) {
		printf("script_funcs_bat: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_bat: ok\n");
	return 0;
}
