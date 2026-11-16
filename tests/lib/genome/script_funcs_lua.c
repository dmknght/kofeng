/*
 * genome / script_funcs_lua - the Lua function strategy (celllysis/script_funcs_lua.c) from CONSTRUCTED text only, linked
 * against libkgenome.a alone.
 *
 * WHAT IS ASSERTED: as in script_funcs_py.c (the kit is script_funcs_kit.h): exact (off, len,
 * name_off, name_len) and END_OPEN per entry, the properties of any answer, and the same entries under CRLF, lone CR and behind a
 * BOM (lua's lexer: "\n", "\r", "\r\n" and "\n\r" are line breaks; no rule here depends on them).
 *
 * WHY THE OLD TESTS MISSED IT: every group is (a) - the strategy was a stub (NO_TABLE) and no Lua function was ever read. The
 * counting group (the "do" of while/for counted once, repeat closed by until, elseif/else/then opening nothing) and the keyword-
 * inside-a-name group are also (b): each is the one byte or word that tells two counts apart.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_LUA
#define SF_STRAT kgenome_script_funcs_lua
#define SF_CR    1

#include "script_funcs_kit.h"

/* ---- Lua ---------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("global", "function f(a)\n  return a\nend\nf(1)\n", { "function f", "end", "f", 0 });
	SF_CASE("local", "local function g()\nend\n", { "local", "end", "g", 0 });
	SF_CASE("local, blanks and a break between", "local \t\n function g()\nend\n", { "local", "end", "g", 0 });
	SF_CASE("field and method", "function a.b:c(x)\nend\nfunction M.new() end\n",
		{ "function a", "end", "a.b:c", 0 }, { "function M", "end", "M.new", 0 });
	SF_CASE("anonymous, outermost", "local f = function(x)\n  return x\nend\n", { "function", "end", "", 0 });
	SF_CASE("two anonymous in one call", "foo(function() end, function(a) return a end)\n",
		{ "function", "end", "", 0 }, { "function", "end", "", 0 });
	SF_CASE("at the end without a break", "x = 1 function f() end", { "function", "end", "f", 0 });
	SF_CASE("local is the declaration's only when it is directly in front",
		"local x = 1 function f() end\n", { "function", "end", "f", 0 });
}

static void counting(void)
{
	SF_CASE("every block kind",
		"function f()\n  if a then\n    b()\n  elseif c then\n  else\n  end\n  while x do\n  end\n  for i=1,3 do\n  end\n"
		"  for k,v in pairs(t) do end\n  repeat\n    y()\n  until z\n  do\n    local q = 1\n  end\n  local h = function() end\nend\nafter()\n",
		{ "function f", "function() end\nend", "f", 0 });
	SF_CASE("repeat holds a function", "function f()\n repeat local g = function() end until g\nend\n",
		{ "function f", "until g\nend", "f", 0 });
	SF_CASE("nested named and anonymous are the outer's",
		"function o()\n  local function i() end\n  return function() return i end\nend\nfunction p() end\n",
		{ "function o", "i end\nend", "o", 0 }, { "function p", "end", "p", 0 });
	SF_CASE("words that hold keywords", "function f()\n  local done, ending, todo, endx = 1\n  doit()\n  if_ = 2\nend\n",
		{ "function f", "= 2\nend", "f", 0 });
	SF_NONE("names that hold function", "function_list = {}\nmyfunction = 1\nendfunction = 2\n");
	/* a loop whose "do" never came does not keep its "do" pending past its own end */
	SF_CASE("a while closed without do", "while x end\nfunction g() do end end\n", { "function g", "end end", "g", 0 });
	SF_CASE("goto and labels", "function f()\n  goto continue\n  ::continue::\nend\n", { "function f", "::\nend", "f", 0 });
}

static void literals(void)
{
	SF_NONE("strings and comments",
		"s = 'function x() end'\n-- function y() end\n--[[ function z()\nend ]]\nt = [[function w() end]]\nu = [==[ end ]==]\nv = \"end\"\n");
	SF_CASE("keywords in strings inside a function",
		"function f()\n  local s = \"end\"\n  local t = [[\nend\n]]\n  -- end\n  --[==[ end ]==]\nend\n",
		{ "function f", "]==]\nend", "f", 0 });
}

static void open_ends(void)
{
	SF_CASE("unterminated block", "function f()\n  if x then\n", { "function f", NULL, "f", 1 });
	SF_CASE("unterminated header", "function g(", { "function g", NULL, "g", 1 });
	SF_CASE("closed then open", "function a() end\nlocal function b()\n  while x do\n", { "function a", "end", "a", 0 },
		{ "local", NULL, "b", 1 });
	SF_CASE("repeat never closed", "function f()\n repeat\n  x()\nend\n", { "function f", NULL, "f", 1 });
}

static void hostile(void)
{
	sf_hostile("100000 functions", "", "function f() end\n", 100000u, 100000u);
	sf_hostile("100000 nested anonymous functions", "", "function()\n", 100000u, 1u);
	sf_hostile("100000 do blocks in one function", "function f()\n", "do\n", 100000u, 1u);
	sf_hostile("100000 stray end", "", "end\n", 100000u, 0u);
	sf_hostile("100000 local without function", "", "local ", 100000u, 0u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	counting();
	literals();
	open_ends();
	hostile();
	if (hk_fails) {
		printf("script_funcs_lua: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_lua: ok\n");
	return 0;
}
